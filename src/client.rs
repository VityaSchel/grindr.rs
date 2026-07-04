use std::sync::{Arc, Mutex, Once};

use bytes::Bytes;
use tokio::sync::{broadcast, mpsc, watch, Notify};
use wreq::{
    Client, EmulationProvider, Http2Config, Method, PseudoOrder, SettingsOrder, SslCurve,
    TlsConfig, TlsVersion,
};

use crate::auth::{AuthEvent, AuthState, LoginResult, Session};
use crate::device::DeviceInfo;
use crate::error::GrindrError;
use crate::headers::build_user_agent;
use crate::rest::{Fingerprint, InnerClient, RawResponse, RequestBody};
use crate::ws::{make_channels, WsChannels, WsCommand, WsConnectionState, WsEvent};

/// References <https://opengrind.org/grindr-api/security-headers#cipher-suites>
const MODERN_TLS_CIPHERS: &str = concat!(
    "TLS_AES_128_GCM_SHA256",
    ":TLS_AES_256_GCM_SHA384",
    ":TLS_CHACHA20_POLY1305_SHA256",
    ":TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    ":TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ":TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ":TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    ":TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    ":TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    ":TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    ":TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    ":TLS_RSA_WITH_AES_128_GCM_SHA256",
    ":TLS_RSA_WITH_AES_256_GCM_SHA384",
    ":TLS_RSA_WITH_AES_128_CBC_SHA",
    ":TLS_RSA_WITH_AES_256_CBC_SHA",
);

/// References <https://opengrind.org/grindr-api/security-headers#extensions>
const SIGALGS: &str = concat!(
    "ecdsa_secp256r1_sha256",
    ":rsa_pss_rsae_sha256",
    ":rsa_pkcs1_sha256",
    ":ecdsa_secp384r1_sha384",
    ":rsa_pss_rsae_sha384",
    ":rsa_pkcs1_sha384",
    ":rsa_pss_rsae_sha512",
    ":rsa_pkcs1_sha512",
    ":rsa_pkcs1_sha1",
);

const CURVES: &[SslCurve] = &[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1];

/// References <https://opengrind.org/grindr-api/security-headers#pseudoheaders>
const PSEUDO_ORDER: [PseudoOrder; 4] = [
    PseudoOrder::Method,
    PseudoOrder::Path,
    PseudoOrder::Authority,
    PseudoOrder::Scheme,
];

/// References <https://opengrind.org/grindr-api/security-headers#frames>
const SETTINGS_ORDER: [SettingsOrder; 8] = [
    SettingsOrder::InitialWindowSize,
    SettingsOrder::HeaderTableSize,
    SettingsOrder::EnablePush,
    SettingsOrder::MaxConcurrentStreams,
    SettingsOrder::MaxFrameSize,
    SettingsOrder::MaxHeaderListSize,
    SettingsOrder::UnknownSetting8,
    SettingsOrder::UnknownSetting9,
];

const OKHTTP_WINDOW_SIZE: u32 = 16 * 1024 * 1024;

fn okhttp_tls_config() -> TlsConfig {
    TlsConfig::builder()
        .enable_ocsp_stapling(true)
        .pre_shared_key(true)
        .curves(CURVES)
        .sigalgs_list(SIGALGS)
        .cipher_list(MODERN_TLS_CIPHERS)
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .build()
}

fn okhttp_http2_config() -> Http2Config {
    Http2Config::builder()
        .initial_stream_window_size(OKHTTP_WINDOW_SIZE)
        .initial_connection_window_size(OKHTTP_WINDOW_SIZE)
        .headers_pseudo_order(PSEUDO_ORDER)
        .settings_order(SETTINGS_ORDER)
        .build()
}

fn grindr_emulation() -> EmulationProvider {
    EmulationProvider::builder()
        .tls_config(okhttp_tls_config())
        .http2_config(okhttp_http2_config())
        .default_headers(None)
        .build()
}

/// The [`EmulationProvider`] that gives a `wreq` client the same TLS and HTTP/2
/// fingerprint as the Android app.
///
/// Use it to build your own `wreq::Client` with the same fingerprint (see the
/// `fingerprint_check` example).
pub fn probe_emulation() -> EmulationProvider {
    grindr_emulation()
}

/// Shared `wreq` setup: the emulation profile plus gzip-only encoding.
fn grindr_client_builder() -> wreq::ClientBuilder {
    Client::builder()
        .emulation(grindr_emulation())
        .gzip(true)
        .no_deflate()
        .no_brotli()
        .no_zstd()
}

fn build_http_client() -> Result<Client, GrindrError> {
    grindr_client_builder().build().map_err(Into::into)
}

fn build_ws_client() -> Result<Client, GrindrError> {
    // Websocket endpoint is http/1.1
    grindr_client_builder()
        .http1_only()
        .build()
        .map_err(Into::into)
}

/// Builds the transport shared by [`GrindrClient::new`] and [`GrindrClient::rotate_device`].
fn build_fingerprint(device: DeviceInfo) -> Result<Arc<Fingerprint>, GrindrError> {
    let user_agent = build_user_agent(&device, "Free");
    let http = build_http_client()?;
    let ws_http = build_ws_client()?;
    Ok(Arc::new(Fingerprint {
        http,
        ws_http,
        device,
        user_agent,
    }))
}

/// Everything needed to start the background websocket task.
struct WsSpawn {
    inner: Arc<InnerClient>,
    auth: Arc<AuthState>,
    channels: WsChannels,
    cmd_rx: mpsc::Receiver<WsCommand>,
    logout_notify: Arc<Notify>,
}

/// An async client for the Grindr API.
///
/// Cheap to [`Clone`] — clones share the connection pool, session, and the
/// background websocket task. Build one with [`new`](Self::new), log in with
/// [`login`](Self::login) or [`google_sign_in`](Self::google_sign_in), then make
/// requests with [`request_authenticated_raw`](Self::request_authenticated_raw).
///
/// The realtime websocket is opt-in: REST works on its own and never opens a
/// socket. Call [`connect`](Self::connect) when you want realtime, then read
/// events from [`ws_receiver`](Self::ws_receiver). The background task is shared
/// across clones and started at most once.
///
/// The client owns no Tokio runtime. [`new`](Self::new) is sync and can be
/// called from non-async code; the websocket task attaches to the caller's
/// runtime the first time [`connect`](Self::connect) is called.
#[derive(Clone)]
pub struct GrindrClient {
    inner: Arc<InnerClient>,
    auth: Arc<AuthState>,
    session_rx: watch::Receiver<Option<Session>>,
    ws_event_tx: broadcast::Sender<WsEvent>,
    ws_cmd_tx: mpsc::Sender<WsCommand>,
    ws_state_rx: watch::Receiver<WsConnectionState>,
    logout_notify: Arc<Notify>,
    ws_started: Arc<Once>,
    ws_spawn: Arc<Mutex<Option<WsSpawn>>>,
}

impl GrindrClient {
    /// Creates a client for a [`DeviceInfo`], optionally resuming a saved
    /// [`Session`].
    ///
    /// Pass `None` to start logged out, or a saved session to resume without
    /// logging in again. This is sync and needs no runtime, and it never opens
    /// the websocket — call [`connect`](Self::connect) for that.
    pub fn new(device: DeviceInfo, session: Option<Session>) -> Result<Self, GrindrError> {
        let fingerprint = build_fingerprint(device)?;

        let inner = Arc::new(InnerClient {
            fingerprint: tokio::sync::RwLock::new(fingerprint),
        });

        let (auth_state, session_rx) = AuthState::new(session);
        let auth = Arc::new(auth_state);

        let (ws_channels, ws_handles) = make_channels();
        let logout_notify = Arc::new(Notify::new());

        let ws_event_tx = ws_channels.event_tx.clone();
        let ws_cmd_tx = ws_handles.cmd_tx;
        let ws_state_rx = ws_handles.state_rx;

        let ws_spawn = WsSpawn {
            inner: Arc::clone(&inner),
            auth: Arc::clone(&auth),
            channels: ws_channels,
            cmd_rx: ws_handles.cmd_rx,
            logout_notify: Arc::clone(&logout_notify),
        };

        Ok(Self {
            inner,
            auth,
            session_rx,
            ws_event_tx,
            ws_cmd_tx,
            ws_state_rx,
            logout_notify,
            ws_started: Arc::new(Once::new()),
            ws_spawn: Arc::new(Mutex::new(Some(ws_spawn))),
        })
    }

    /// Spawns the background websocket task once, on the current Tokio
    /// runtime. Cheap to call repeatedly, only the first call does any work.
    ///
    /// Only reached through [`connect`](Self::connect), so it always runs inside
    /// an async context and the task attaches to the caller's runtime.
    fn ensure_ws_task(&self) {
        self.ws_started.call_once(|| {
            // Only this closure runs (once), so the parts are always present.
            if let Some(parts) = self.ws_spawn.lock().unwrap().take() {
                crate::ws::spawn_ws_task(
                    parts.inner,
                    parts.auth,
                    parts.channels,
                    parts.cmd_rx,
                    parts.logout_notify,
                );
            }
        });
    }

    /// Subscribes to [`AuthEvent`]s sent when a background token refresh fails
    /// (e.g. the session was revoked).
    pub fn auth_event_receiver(&self) -> broadcast::Receiver<AuthEvent> {
        self.auth.auth_event_tx.subscribe()
    }

    /// Watches the current [`Session`].
    ///
    /// It changes on login, refresh, and logout — read it here to save the
    /// session to disk.
    pub fn session_receiver(&self) -> watch::Receiver<Option<Session>> {
        self.session_rx.clone()
    }

    /// Watches the websocket [`WsConnectionState`].
    pub fn connection_state(&self) -> watch::Receiver<WsConnectionState> {
        self.ws_state_rx.clone()
    }

    /// Subscribes to incoming [`WsEvent`]s (messages, taps, presence). You only
    /// get events sent after you subscribe.
    pub fn ws_receiver(&self) -> broadcast::Receiver<WsEvent> {
        self.ws_event_tx.subscribe()
    }

    /// A sender for [`WsCommand`]s over the websocket.
    pub fn ws_sender(&self) -> mpsc::Sender<WsCommand> {
        self.ws_cmd_tx.clone()
    }

    /// Opts in to the realtime websocket, starting the shared background task if
    /// it isn't running yet.
    ///
    /// The websocket is never started automatically. REST calls like
    /// [`request_authenticated_raw`](Self::request_authenticated_raw) work
    /// without it. Call this once (from any clone) when you want realtime events
    /// from [`ws_receiver`](Self::ws_receiver); the task connects as soon as
    /// there's a session and reconnects on its own. Calling it again does
    /// nothing.
    pub async fn connect(&self) {
        self.ensure_ws_task();
    }

    /// Logs in with email and password and stores the session.
    pub async fn login(&self, email: &str, password: &str) -> Result<LoginResult, GrindrError> {
        crate::auth::login_email(&self.inner, &self.auth, email, password).await
    }

    /// Signs in with a Google OAuth access token and stores the session.
    pub async fn google_sign_in(
        &self,
        google_access_token: &str,
    ) -> Result<LoginResult, GrindrError> {
        crate::auth::google_sign_in(&self.inner, &self.auth, google_access_token).await
    }

    /// Forces a token refresh.
    ///
    /// This happens automatically before the token expires, so you rarely need
    /// to call it yourself.
    pub async fn refresh_token(&self) -> Result<LoginResult, GrindrError> {
        crate::auth::refresh_token(&self.inner, &self.auth).await
    }

    /// Clears the session and closes the websocket.
    pub async fn logout(&self) {
        self.auth.clear_session().await;
        self.logout_notify.notify_waiters();
    }

    /// Makes an authenticated request and returns the raw status and body.
    ///
    /// `path` is added to the API base URL and must start with `/` (e.g.
    /// `/v3/me/profile`), otherwise you get [`GrindrError::InvalidRequest`]. The
    /// session token is added for you, refreshing first if it's about to expire.
    /// The body comes back as-is for you to deserialize.
    ///
    /// This crate doesn't ship response types. See the API reference at
    /// <https://opengrind.org/grindr-api/> and the dev tool at
    /// <https://git.opengrind.org/open-grind/grindr-api-dev-tool>.
    pub async fn request_authenticated_raw(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<RawResponse, GrindrError> {
        self.inner
            .request_authenticated(&self.auth, method, path, body.map(RequestBody::Json))
            .await
    }

    /// Like [`request_authenticated_raw`](Self::request_authenticated_raw), but
    /// sends a raw binary body with the given `Content-Type` instead of JSON —
    /// for endpoints like `POST /v5/chat/media/upload` that take the file bytes
    /// as the body.
    ///
    /// `body` accepts anything convertible to [`Bytes`]; a `Vec<u8>` converts
    /// without copying. Non-success statuses come back as a normal
    /// [`RawResponse`]; map them with [`GrindrError::from_response`] to get the
    /// same errors the crate's typed methods return.
    pub async fn request_authenticated_bytes(
        &self,
        method: Method,
        path: &str,
        content_type: &str,
        body: impl Into<Bytes>,
    ) -> Result<RawResponse, GrindrError> {
        self.inner
            .request_authenticated(
                &self.auth,
                method,
                path,
                Some(RequestBody::Raw {
                    content_type: content_type.to_owned(),
                    bytes: body.into(),
                }),
            )
            .await
    }

    /// Replaces the device identity (and its clients) while keeping the session.
    /// Returns the old device.
    pub async fn rotate_device(&self, device: DeviceInfo) -> Result<DeviceInfo, GrindrError> {
        let new_fp = build_fingerprint(device)?;
        let old_fp = {
            let mut guard = self.inner.fingerprint.write().await;
            std::mem::replace(&mut *guard, new_fp)
        };
        Ok(old_fp.device.clone())
    }

    /// The device identity currently in use.
    pub async fn current_device(&self) -> DeviceInfo {
        self.inner.fingerprint().await.device.clone()
    }

    /// Whether the server has first-party reCAPTCHA enabled. No auth needed.
    pub async fn recaptcha_first_party_enabled(&self) -> Result<bool, GrindrError> {
        crate::auth::recaptcha_first_party_enabled(&self.inner).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_does_not_require_a_runtime() {
        // The constructor is synchronous and must not panic when called outside
        // of any Tokio runtime.
        let client = GrindrClient::new(DeviceInfo::generate(), None).unwrap();
        assert!(!client.ws_started.is_completed());
    }

    #[tokio::test]
    async fn rest_calls_do_not_start_the_ws_task() {
        let client = GrindrClient::new(DeviceInfo::generate(), None).unwrap();

        let err = client
            .request_authenticated_raw(Method::GET, "/v3/me/profile", None)
            .await
            .unwrap_err();

        assert!(matches!(err, GrindrError::Auth(_)));
        assert!(!client.ws_started.is_completed());
    }

    #[tokio::test]
    async fn bytes_requests_require_a_session_and_validate_the_path() {
        let client = GrindrClient::new(DeviceInfo::generate(), None).unwrap();

        let err = client
            .request_authenticated_bytes(
                Method::POST,
                "/v5/chat/media/upload?takenOnGrindr=false",
                "image/jpeg",
                vec![0xFF, 0xD8],
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GrindrError::Auth(_)));

        let err = client
            .request_authenticated_bytes(Method::POST, "evil.com/x", "image/jpeg", Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(err, GrindrError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn connect_starts_the_ws_task() {
        // Resuming a session and only calling connect() (no request) must still
        // bring the background task up.
        let client = GrindrClient::new(DeviceInfo::generate(), None).unwrap();
        assert!(!client.ws_started.is_completed());
        client.connect().await;
        assert!(client.ws_started.is_completed());
    }

    #[tokio::test]
    async fn dropping_client_in_async_context_does_not_panic() {
        // Regression guard: the old owned-runtime design panicked when the last
        // clone was dropped inside an async context.
        let client = GrindrClient::new(DeviceInfo::generate(), None).unwrap();
        let clone = client.clone();
        drop(client);
        drop(clone);
    }
}
