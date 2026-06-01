use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch, Mutex, RwLock};

use crate::error::GrindrError;
use crate::rest::InnerClient;

/// How a [`Session`] was obtained.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SessionKind {
    /// Email + password login.
    #[default]
    Email,
    /// Google third-party sign-in.
    Google,
}

/// An authenticated session.
///
/// A `Session` has credentials (`session_id` and `auth_token`) and
/// is `Serialize`/`Deserialize` so it can be persisted between runs and handed
/// back to [`GrindrClient::new`](crate::GrindrClient::new). It's a secret:
/// store it somewhere only the user can read and delete after sign out.
/// Its [`fmt::Debug`] implementation redacts the credential fields so they are
/// not leaked through logs.
#[derive(Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct Session {
    /// Account email (or third-party display id for non-email logins).
    pub email: String,
    /// Unix timestamp (seconds) at which `session_id` expires.
    pub expires_at: u64,
    /// The account's profile id.
    pub profile_id: String,
    /// Short-lived bearer token (a JWT) sent in the `Authorization` header.
    pub session_id: String,
    /// Long-lived token used to mint a fresh `session_id` on refresh.
    pub auth_token: String,
    /// How this session was created.
    #[serde(default)]
    pub kind: SessionKind,
    /// Vendor-scoped user id for third-party logins, if any.
    #[serde(default)]
    pub third_party_user_id: Option<String>,
}

impl fmt::Debug for Session {
    /// Redacts `session_id` and `auth_token` so the bearer credentials never
    /// show up in logs via `{:?}`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("email", &self.email)
            .field("expires_at", &self.expires_at)
            .field("profile_id", &self.profile_id)
            .field("session_id", &"<redacted>")
            .field("auth_token", &"<redacted>")
            .field("kind", &self.kind)
            .field("third_party_user_id", &self.third_party_user_id)
            .finish()
    }
}

/// The outcome of a successful login or token refresh.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct LoginResult {
    /// The authenticated account's profile id.
    pub profile_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionResponse {
    pub profile_id: String,
    pub session_id: String,
    pub auth_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginRequest {
    pub email: String,
    pub password: String,
    pub token: Option<String>,
    pub geohash: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshRequest {
    pub email: String,
    pub auth_token: String,
    pub token: Option<String>,
    pub geohash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    exp: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThirdPartySignInRequest<'a> {
    third_party_vendor: u8,
    third_party_token: &'a str,
    geohash: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ThirdPartyAuthResponse {
    #[allow(dead_code)]
    registered: bool,
    authentication_response: Option<ThirdPartySession>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ThirdPartySession {
    profile_id: String,
    session_id: String,
    auth_token: String,
    third_party_user_id: String,
    #[serde(default)]
    third_party_user_id_to_show: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AssignmentsResponse {
    #[serde(default)]
    assignments: Vec<Assignment>,
}

#[derive(Debug, Deserialize)]
struct Assignment {
    key: String,
    value: String,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reads the `exp` claim out of a server-issued session JWT.
///
/// The signature is not verified because the token is minted by the
/// Grindr server, the client does not hold the signing key, and the decoded
/// value is only used to decide when to refresh — not for a trust
/// or authorization decision.
fn decode_session_jwt(token: &str) -> Result<JwtClaims, GrindrError> {
    jsonwebtoken::dangerous::insecure_decode::<JwtClaims>(token)
        .map(|d| d.claims)
        .map_err(|e| GrindrError::Auth(format!("JWT decode failed: {e}")))
}

pub(crate) trait AuthRequest: Serialize {
    fn email(&self) -> &str;
}

impl AuthRequest for LoginRequest {
    fn email(&self) -> &str {
        &self.email
    }
}

impl AuthRequest for RefreshRequest {
    fn email(&self) -> &str {
        &self.email
    }
}

/// Emitted on the channel returned by
/// [`GrindrClient::auth_event_receiver`](crate::GrindrClient::auth_event_receiver)
/// when a background token refresh fails.
#[derive(Debug, Clone)]
pub struct AuthEvent {
    /// Human-readable description of the failure.
    pub message: String,
    /// `true` if the failure was a `401` and the session has been cleared,
    /// meaning the user must log in again.
    pub unauthorized: bool,
}

pub(crate) struct AuthState {
    pub session: RwLock<Option<Session>>,
    pub refresh_lock: Mutex<()>,
    pub session_tx: watch::Sender<Option<Session>>,
    pub auth_event_tx: broadcast::Sender<AuthEvent>,
}

impl AuthState {
    pub fn new(initial: Option<Session>) -> (Self, watch::Receiver<Option<Session>>) {
        let (tx, rx) = watch::channel(initial.clone());
        let (auth_event_tx, _) = broadcast::channel(16);
        let state = Self {
            session: RwLock::new(initial),
            refresh_lock: Mutex::new(()),
            session_tx: tx,
            auth_event_tx,
        };
        (state, rx)
    }

    pub async fn set_session(&self, session: Session) {
        *self.session.write().await = Some(session.clone());
        let _ = self.session_tx.send(Some(session));
    }

    pub async fn clear_session(&self) {
        *self.session.write().await = None;
        let _ = self.session_tx.send(None);
    }
}

pub(crate) async fn create_session(
    inner: &InnerClient,
    body: &impl AuthRequest,
    kind: SessionKind,
    third_party_user_id: Option<String>,
) -> Result<Session, GrindrError> {
    let resp: SessionResponse = inner
        .request_no_auth(wreq::Method::POST, "/v8/sessions", Some(body))
        .await?;

    let claims = decode_session_jwt(&resp.session_id)?;

    Ok(Session {
        email: body.email().to_owned(),
        profile_id: resp.profile_id,
        session_id: resp.session_id,
        auth_token: resp.auth_token,
        expires_at: claims.exp,
        kind,
        third_party_user_id,
    })
}

pub(crate) async fn login_email(
    inner: &InnerClient,
    auth: &AuthState,
    email: &str,
    password: &str,
) -> Result<LoginResult, GrindrError> {
    let body = LoginRequest {
        email: email.to_owned(),
        password: password.to_owned(),
        token: None,
        geohash: None,
    };
    let session = create_session(inner, &body, SessionKind::Email, None).await?;
    let profile_id = session.profile_id.clone();
    auth.set_session(session).await;
    Ok(LoginResult { profile_id })
}

pub(crate) async fn google_sign_in(
    inner: &InnerClient,
    auth: &AuthState,
    google_access_token: &str,
) -> Result<LoginResult, GrindrError> {
    let body = ThirdPartySignInRequest {
        third_party_vendor: 2,
        third_party_token: google_access_token,
        geohash: None,
    };
    let parsed: ThirdPartyAuthResponse = inner
        .request_no_auth(wreq::Method::POST, "/v8/sessions/thirdparty", Some(&body))
        .await?;
    let tp = parsed
        .authentication_response
        .ok_or_else(|| GrindrError::Auth("account not registered".to_owned()))?;
    let claims = decode_session_jwt(&tp.session_id)?;
    let display_email = tp
        .third_party_user_id_to_show
        .clone()
        .unwrap_or_else(|| tp.third_party_user_id.clone());

    let session = Session {
        email: display_email,
        profile_id: tp.profile_id.clone(),
        session_id: tp.session_id,
        auth_token: tp.auth_token,
        expires_at: claims.exp,
        kind: SessionKind::Google,
        third_party_user_id: Some(tp.third_party_user_id),
    };
    let profile_id = session.profile_id.clone();
    auth.set_session(session).await;
    Ok(LoginResult { profile_id })
}

pub(crate) async fn refresh_token(
    inner: &InnerClient,
    auth: &AuthState,
) -> Result<LoginResult, GrindrError> {
    let (email, auth_token) = {
        let guard = auth.session.read().await;
        let s = guard
            .as_ref()
            .ok_or_else(|| GrindrError::Auth("not logged in".to_owned()))?;
        (s.email.clone(), s.auth_token.clone())
    };

    let body = RefreshRequest {
        email,
        auth_token,
        token: None,
        geohash: None,
    };
    let session = create_session(inner, &body, SessionKind::Email, None).await?;
    let profile_id = session.profile_id.clone();
    auth.set_session(session).await;
    Ok(LoginResult { profile_id })
}

pub(crate) async fn recaptcha_first_party_enabled(
    inner: &InnerClient,
) -> Result<bool, GrindrError> {
    let resp: AssignmentsResponse = inner
        .request_no_auth::<(), _>(wreq::Method::GET, "/public/v1/assignments", None)
        .await?;
    Ok(resp
        .assignments
        .iter()
        .any(|a| a.key == "recaptcha_first_party" && a.value == "on"))
}

pub(crate) async fn authorization_header(inner: &InnerClient, auth: &AuthState) -> Option<String> {
    let expires_at = auth.session.read().await.as_ref()?.expires_at;

    const REFRESH_BUFFER_SECS: u64 = 60;

    if expires_at < now_unix() + REFRESH_BUFFER_SECS {
        let _guard = auth.refresh_lock.lock().await;

        let still_expired = match auth.session.read().await.as_ref() {
            Some(s) => s.expires_at < now_unix() + REFRESH_BUFFER_SECS,
            None => return None,
        };

        if still_expired {
            if let Err(e) = refresh_token(inner, auth).await {
                tracing::warn!("token refresh failed: {e}");
                let unauthorized = matches!(e, GrindrError::Unauthorized { .. });
                if unauthorized {
                    auth.clear_session().await;
                }
                if unauthorized || auth.session.read().await.is_some() {
                    let _ = auth.auth_event_tx.send(AuthEvent {
                        message: e.to_string(),
                        unauthorized,
                    });
                }
            }
        }
    }

    auth.session
        .read()
        .await
        .as_ref()
        .map(|s| format!("Grindr3 {}", s.session_id))
}
