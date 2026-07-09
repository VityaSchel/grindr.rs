use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::sleep;
use wreq::websocket::{Message, WebSocket};

use crate::auth::{AuthState, Session};
use crate::error::GrindrError;
use crate::headers::GrindrHeaders;
use crate::rest::InnerClient;

const WS_URL: &str = "wss://grindr.mobi/v1/ws";

const WS_BROADCAST_CAPACITY: usize = 256;

/// A command to send over the websocket.
///
/// The client adds the session token; you set `type`, `ref_id`, and `payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsCommand {
    /// Command type, e.g. `"chat.v1.message"`.
    pub r#type: String,
    /// Your id for this command, echoed back in the reply.
    pub ref_id: String,
    /// The command payload.
    pub payload: Value,
}

/// An event received over the websocket.
#[derive(Debug, Clone)]
pub struct WsEvent {
    /// The event's `type` field.
    pub event_type: String,
    /// The full event JSON, including the `type` field.
    pub payload: Value,
}

/// Whether the websocket is connected.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum WsConnectionState {
    /// Not connected (logged out, reconnecting, or backing off).
    #[default]
    Disconnected,
    /// Connected and ready to send and receive.
    Connected,
}

pub(crate) struct WsChannels {
    pub event_tx: broadcast::Sender<WsEvent>,
    pub state_tx: watch::Sender<WsConnectionState>,
}

pub(crate) fn make_channels() -> (WsChannels, WsHandles) {
    let (event_tx, _) = broadcast::channel(WS_BROADCAST_CAPACITY);
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (state_tx, state_rx) = watch::channel(WsConnectionState::Disconnected);

    let channels = WsChannels {
        event_tx: event_tx.clone(),
        state_tx,
    };
    let handles = WsHandles {
        cmd_tx,
        cmd_rx,
        state_rx,
    };
    (channels, handles)
}

pub(crate) struct WsHandles {
    pub cmd_tx: mpsc::Sender<WsCommand>,
    pub cmd_rx: mpsc::Receiver<WsCommand>,
    pub state_rx: watch::Receiver<WsConnectionState>,
}

pub(crate) fn spawn_ws_task(
    inner: Arc<InnerClient>,
    auth: Arc<AuthState>,
    channels: WsChannels,
    mut cmd_rx: mpsc::Receiver<WsCommand>,
) {
    tokio::spawn(async move {
        let mut session_rx = auth.session_tx.subscribe();
        let mut backoff = Duration::from_secs(1);

        loop {
            loop {
                if auth.session.read().await.is_some() {
                    break;
                }
                if session_rx.changed().await.is_err() {
                    return;
                }
            }

            match connect_and_run(&inner, &auth, &channels, &mut cmd_rx, &mut session_rx).await {
                Ok(()) => {
                    let _ = channels.state_tx.send(WsConnectionState::Disconnected);
                    backoff = Duration::from_secs(1);
                }
                Err(GrindrError::Auth(_)) => {
                    tracing::warn!("[ws] auth error, waiting for next login");
                    let _ = channels.state_tx.send(WsConnectionState::Disconnected);
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    tracing::warn!("[ws] connection error: {e}; retrying in {backoff:?}");
                    let _ = channels.state_tx.send(WsConnectionState::Disconnected);

                    if auth.session.read().await.is_none() {
                        backoff = Duration::from_secs(1);
                        continue;
                    }
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    });
}

async fn connect_and_run(
    inner: &InnerClient,
    auth: &AuthState,
    channels: &WsChannels,
    cmd_rx: &mut mpsc::Receiver<WsCommand>,
    session_rx: &mut watch::Receiver<Option<Session>>,
) -> Result<(), GrindrError> {
    let authorization = crate::auth::authorization_header(inner, auth)
        .await
        .ok_or_else(|| GrindrError::Auth("not logged in".to_owned()))?;

    let fp = inner.fingerprint().await;
    let headers = GrindrHeaders::build(
        &fp.device,
        &fp.user_agent,
        Some(&authorization),
        Some("[FREE]"),
    )?;

    let mut builder = fp.ws_http.websocket(WS_URL);
    for (name, value) in &headers.items {
        builder = builder.header(name.clone(), value.clone());
    }

    let response = builder
        .send()
        .await
        .map_err(|e| GrindrError::Http(format!("WS connect failed: {e}")))?;

    let mut ws = response
        .into_websocket()
        .await
        .map_err(|e| GrindrError::Http(format!("WS upgrade failed: {e}")))?;

    let _ = channels.state_tx.send(WsConnectionState::Connected);

    run_message_loop(&mut ws, cmd_rx, auth, session_rx, &channels.event_tx).await
}

async fn session_token(auth: &AuthState) -> Option<String> {
    auth.session
        .read()
        .await
        .as_ref()
        .map(|s| s.session_id.clone())
}

async fn run_message_loop(
    ws: &mut WebSocket,
    cmd_rx: &mut mpsc::Receiver<WsCommand>,
    auth: &AuthState,
    session_rx: &mut watch::Receiver<Option<Session>>,
    event_tx: &broadcast::Sender<WsEvent>,
) -> Result<(), GrindrError> {
    if session_token(auth).await.is_none() {
        return Ok(());
    }

    loop {
        tokio::select! {
            changed = session_rx.changed() => {
                let logged_out = changed.is_err() || session_rx.borrow_and_update().is_none();
                if logged_out {
                    return Ok(());
                }
            }
            msg = ws.next() => match msg {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(payload) = serde_json::from_str::<Value>(text.as_str()) {
                        if let Some(event_type) = payload["type"].as_str() {

                            let _ = event_tx.send(WsEvent {
                                event_type: event_type.to_owned(),
                                payload,
                            });
                        }
                    }
                }
                Some(Ok(Message::Ping(data))) => {
                    ws.send(Message::Pong(data))
                        .await
                        .map_err(|e| GrindrError::Http(e.to_string()))?;
                }
                Some(Ok(Message::Close(_))) | None => {
                    return Err(GrindrError::Http("WS connection closed by server".to_owned()));
                }
                Some(Err(e)) => {
                    return Err(GrindrError::Http(e.to_string()));
                }
                Some(Ok(_)) => {}
            },
            cmd = cmd_rx.recv() => match cmd {
                Some(cmd) => {
                    let Some(token) = session_token(auth).await else {
                        return Ok(());
                    };
                    let json = serde_json::json!({
                        "type": cmd.r#type,
                        "ref":  cmd.ref_id,
                        "token": token,
                        "payload": cmd.payload,
                    });
                    ws.send(Message::text(json.to_string()))
                        .await
                        .map_err(|e| GrindrError::Http(e.to_string()))?;
                }
                None => return Ok(()),
            }
        }
    }
}
