use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch, Mutex, RwLock};

use crate::error::{BanInfo, GrindrError};
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
	/// Account restriction from the session JWT, if any. The session is valid.
	#[serde(default)]
	pub restriction: Option<Restriction>,
}

/// An account restriction carried in the session JWT.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Restriction {
	/// Age verification is required.
	AgeVerification {
		/// Region whose rules apply.
		region: VerificationRegion,
		/// Raw `restrictionReason` value.
		reason: String,
	},
	/// A time-limited ban.
	TimedBan(BanDetails),
	/// Rejected by the anti-fraud vendor.
	TrustVendorRejected,
	/// A value this version does not model.
	Other(String),
}

/// Region for a [`Restriction::AgeVerification`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VerificationRegion {
	/// United Kingdom.
	Uk,
	/// Brazil.
	Br,
	/// Australia.
	Au,
	/// A region this version does not model.
	Other,
}

/// A timed ban's details, from the JWT `banDetails` claim.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BanDetails {
	/// Unix seconds when the ban expires.
	pub expiry_time: Option<i64>,
	/// Ban reason.
	pub reason: Option<String>,
	/// Ban sub-reason.
	pub sub_reason: Option<String>,
	/// Whether the ban was automated.
	#[serde(default)]
	pub is_automated: bool,
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
			.field("restriction", &self.restriction)
			.finish()
	}
}

/// The outcome of a successful login or token refresh.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct LoginResult {
	/// The authenticated account's profile id.
	pub profile_id: String,
	/// Account restriction, if any. A session was still established.
	pub restriction: Option<Restriction>,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThirdPartyRefreshRequest<'a> {
	third_party_user_id: &'a str,
	auth_token: &'a str,
	geohash: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JwtClaims {
	exp: u64,
	#[serde(default)]
	restriction: Option<String>,
	#[serde(default)]
	restriction_reason: Option<String>,
	#[serde(default)]
	ban_details: Option<BanDetails>,
}

fn restriction_from_claims(claims: &JwtClaims) -> Option<Restriction> {
	let restriction = claims.restriction.as_deref()?;
	Some(match restriction {
		"AGE_RESTRICTED" => Restriction::AgeVerification {
			region: region_from_reason(claims.restriction_reason.as_deref()),
			reason: claims.restriction_reason.clone().unwrap_or_default(),
		},
		"TIMED_BAN" => Restriction::TimedBan(
			claims.ban_details.clone().unwrap_or_default(),
		),
		"TRUST_VENDOR_REJECTED" => Restriction::TrustVendorRejected,
		other => Restriction::Other(other.to_owned()),
	})
}

fn region_from_reason(reason: Option<&str>) -> VerificationRegion {
	match reason {
		Some("UK_VERIFICATION_REQUIRED") => VerificationRegion::Uk,
		Some("BR_VERIFICATION_REQUIRED") => VerificationRegion::Br,
		Some("AU_VERIFICATION_REQUIRED") => VerificationRegion::Au,
		_ => VerificationRegion::Other,
	}
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

/// Emitted on [`GrindrClient::auth_event_receiver`](crate::GrindrClient::auth_event_receiver)
/// when a background token refresh changes the auth state.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuthEvent {
	/// Session cleared (`401`); log in again.
	LoggedOut,
	/// The account is banned; session cleared.
	Banned(BanInfo),
	/// A transient refresh failure; the session is kept.
	RefreshFailed {
		/// What went wrong.
		message: String,
	},
}

pub(crate) struct AuthState {
	pub session: RwLock<Option<Session>>,
	pub logout_epoch: AtomicU64,
	pub refresh_lock: Mutex<()>,
	pub session_tx: watch::Sender<Option<Session>>,
	pub auth_event_tx: broadcast::Sender<AuthEvent>,
}

impl AuthState {
	pub fn new(
		initial: Option<Session>,
	) -> (Self, watch::Receiver<Option<Session>>) {
		let (tx, rx) = watch::channel(initial.clone());
		let (auth_event_tx, _) = broadcast::channel(16);
		let state = Self {
			session: RwLock::new(initial),
			logout_epoch: AtomicU64::new(0),
			refresh_lock: Mutex::new(()),
			session_tx: tx,
			auth_event_tx,
		};
		(state, rx)
	}

	pub fn epoch(&self) -> u64 {
		self.logout_epoch.load(Ordering::SeqCst)
	}

	pub async fn set_session_if_current(
		&self,
		session: Session,
		epoch: u64,
	) -> bool {
		let mut guard = self.session.write().await;
		if self.epoch() != epoch {
			return false;
		}
		*guard = Some(session.clone());
		let _ = self.session_tx.send(Some(session));
		true
	}

	pub async fn clear_session(&self) {
		let mut guard = self.session.write().await;
		self.logout_epoch.fetch_add(1, Ordering::SeqCst);
		*guard = None;
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
		restriction: restriction_from_claims(&claims),
	})
}

pub(crate) async fn login_email(
	inner: &InnerClient,
	auth: &AuthState,
	email: &str,
	password: &str,
	geohash: Option<&str>,
) -> Result<LoginResult, GrindrError> {
	let body = LoginRequest {
		email: email.to_owned(),
		password: password.to_owned(),
		token: None,
		geohash: geohash.map(str::to_owned),
	};
	let epoch = auth.epoch();
	let session =
		create_session(inner, &body, SessionKind::Email, None).await?;
	let profile_id = session.profile_id.clone();
	let restriction = session.restriction.clone();
	if !auth.set_session_if_current(session, epoch).await {
		return Err(GrindrError::SessionCleared);
	}
	Ok(LoginResult {
		profile_id,
		restriction,
	})
}

pub(crate) async fn google_sign_in(
	inner: &InnerClient,
	auth: &AuthState,
	google_access_token: &str,
	geohash: Option<&str>,
) -> Result<LoginResult, GrindrError> {
	let epoch = auth.epoch();
	let body = ThirdPartySignInRequest {
		third_party_vendor: 2,
		third_party_token: google_access_token,
		geohash,
	};
	let parsed: ThirdPartyAuthResponse = inner
		.request_no_auth(
			wreq::Method::POST,
			"/v8/sessions/thirdparty",
			Some(&body),
		)
		.await?;
	let tp = parsed.authentication_response.ok_or_else(|| {
		GrindrError::Auth("account not registered".to_owned())
	})?;
	let fallback_email = tp.third_party_user_id.clone();
	let session = session_from_third_party(tp, fallback_email)?;
	let profile_id = session.profile_id.clone();
	let restriction = session.restriction.clone();
	if !auth.set_session_if_current(session, epoch).await {
		return Err(GrindrError::SessionCleared);
	}
	Ok(LoginResult {
		profile_id,
		restriction,
	})
}

fn session_from_third_party(
	tp: ThirdPartySession,
	fallback_email: String,
) -> Result<Session, GrindrError> {
	let claims = decode_session_jwt(&tp.session_id)?;
	Ok(Session {
		email: tp.third_party_user_id_to_show.unwrap_or(fallback_email),
		profile_id: tp.profile_id,
		session_id: tp.session_id,
		auth_token: tp.auth_token,
		expires_at: claims.exp,
		kind: SessionKind::Google,
		third_party_user_id: Some(tp.third_party_user_id),
		restriction: restriction_from_claims(&claims),
	})
}

async fn refresh_third_party_session(
	inner: &InnerClient,
	third_party_user_id: &str,
	auth_token: &str,
	fallback_email: String,
	geohash: Option<&str>,
) -> Result<Session, GrindrError> {
	let body = ThirdPartyRefreshRequest {
		third_party_user_id,
		auth_token,
		geohash,
	};
	let parsed: ThirdPartyAuthResponse = inner
		.request_no_auth(
			wreq::Method::POST,
			"/v8/sessions/thirdparty",
			Some(&body),
		)
		.await?;
	let tp = parsed.authentication_response.ok_or_else(|| {
		GrindrError::Auth("third-party session refresh rejected".to_owned())
	})?;
	session_from_third_party(tp, fallback_email)
}

pub(crate) async fn refresh_token(
	inner: &InnerClient,
	auth: &AuthState,
	geohash: Option<&str>,
) -> Result<LoginResult, GrindrError> {
	let (kind, email, auth_token, third_party_user_id, epoch) = {
		let guard = auth.session.read().await;
		let s = guard
			.as_ref()
			.ok_or_else(|| GrindrError::Auth("not logged in".to_owned()))?;
		(
			s.kind.clone(),
			s.email.clone(),
			s.auth_token.clone(),
			s.third_party_user_id.clone(),
			auth.epoch(),
		)
	};

	let session = match kind {
		SessionKind::Email => {
			let body = RefreshRequest {
				email,
				auth_token,
				token: None,
				geohash: geohash.map(str::to_owned),
			};
			create_session(inner, &body, SessionKind::Email, None).await?
		}
		SessionKind::Google => {
			let third_party_user_id = third_party_user_id.ok_or_else(|| {
				GrindrError::Auth(
					"google session missing third-party user id".to_owned(),
				)
			})?;
			refresh_third_party_session(
				inner,
				&third_party_user_id,
				&auth_token,
				email,
				geohash,
			)
			.await?
		}
	};

	let profile_id = session.profile_id.clone();
	let restriction = session.restriction.clone();
	if !auth.set_session_if_current(session, epoch).await {
		return Err(GrindrError::SessionCleared);
	}
	Ok(LoginResult {
		profile_id,
		restriction,
	})
}

async fn emit_refresh_failure(auth: &AuthState, error: GrindrError) {
	let event = match error {
		GrindrError::Unauthorized { .. } => {
			auth.clear_session().await;
			AuthEvent::LoggedOut
		}
		GrindrError::Banned(info) => {
			auth.clear_session().await;
			AuthEvent::Banned(info)
		}
		other => {
			if auth.session.read().await.is_none() {
				return;
			}
			AuthEvent::RefreshFailed {
				message: other.to_string(),
			}
		}
	};
	let _ = auth.auth_event_tx.send(event);
}

/// Refresh after an authenticated request returned `401`.
pub(crate) async fn refresh_after_unauthorized(
	inner: &InnerClient,
	auth: &AuthState,
	rejected_session_id: &str,
) -> bool {
	let _guard = auth.refresh_lock.lock().await;

	match auth.session.read().await.as_ref() {
		None => return false,
		Some(s) if s.session_id != rejected_session_id => return true,
		Some(_) => {}
	}

	match refresh_token(inner, auth, None).await {
		Ok(_) => true,
		Err(e) => {
			tracing::warn!("reactive token refresh failed: {e}");
			emit_refresh_failure(auth, e).await;
			false
		}
	}
}

pub(crate) async fn recaptcha_first_party_enabled(
	inner: &InnerClient,
) -> Result<bool, GrindrError> {
	let resp: AssignmentsResponse = inner
		.request_no_auth::<(), _>(
			wreq::Method::GET,
			"/public/v1/assignments",
			None,
		)
		.await?;
	Ok(resp
		.assignments
		.iter()
		.any(|a| a.key == "recaptcha_first_party" && a.value == "on"))
}

pub(crate) async fn authorization_header(
	inner: &InnerClient,
	auth: &AuthState,
) -> Option<String> {
	let expires_at = auth.session.read().await.as_ref()?.expires_at;

	const REFRESH_BUFFER_SECS: u64 = 60;

	if expires_at < now_unix() + REFRESH_BUFFER_SECS {
		let _guard = auth.refresh_lock.lock().await;

		let still_expired = match auth.session.read().await.as_ref() {
			Some(s) => s.expires_at < now_unix() + REFRESH_BUFFER_SECS,
			None => return None,
		};

		if still_expired {
			if let Err(e) = refresh_token(inner, auth, None).await {
				tracing::warn!("token refresh failed: {e}");
				emit_refresh_failure(auth, e).await;
			}
		}
	}

	auth.session
		.read()
		.await
		.as_ref()
		.map(|s| format!("Grindr3 {}", s.session_id))
}

#[cfg(test)]
mod tests {
	use super::*;

	// Header {"alg":"HS256","typ":"JWT"} . payload {"exp":9999999999} . sig
	const JWT: &str =
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig";

	fn session_named(email: &str) -> Session {
		Session {
			email: email.to_owned(),
			expires_at: 9_999_999_999,
			profile_id: "42".to_owned(),
			session_id: JWT.to_owned(),
			auth_token: "auth-tok".to_owned(),
			kind: SessionKind::Email,
			third_party_user_id: None,
			restriction: None,
		}
	}

	#[tokio::test]
	async fn a_session_minted_before_a_sign_out_is_refused() {
		let (auth, mut rx) = AuthState::new(Some(session_named("old@x")));
		let epoch = auth.epoch();

		auth.clear_session().await;

		assert!(
			!auth.set_session_if_current(session_named("old@x"), epoch).await,
			"a refresh in flight across sign-out must not resurrect the account"
		);
		assert!(auth.session.read().await.is_none());
		assert!(
			rx.borrow_and_update().is_none(),
			"the watch must not be left holding a stale session for the app to persist"
		);
	}

	#[tokio::test]
	async fn a_session_minted_after_a_sign_out_is_accepted() {
		let (auth, _rx) = AuthState::new(Some(session_named("old@x")));
		auth.clear_session().await;

		let epoch = auth.epoch();
		assert!(
			auth.set_session_if_current(session_named("new@x"), epoch)
				.await,
			"signing in again after a sign-out must work"
		);
		assert_eq!(auth.session.read().await.as_ref().unwrap().email, "new@x");
	}

	fn third_party_session(show: Option<&str>) -> ThirdPartySession {
		ThirdPartySession {
			profile_id: "42".to_owned(),
			session_id: JWT.to_owned(),
			auth_token: "auth-tok".to_owned(),
			third_party_user_id: "vendor-uid".to_owned(),
			third_party_user_id_to_show: show.map(str::to_owned),
		}
	}

	#[test]
	fn third_party_refresh_body_uses_grindr_wire_keys() {
		let body = ThirdPartyRefreshRequest {
			third_party_user_id: "vendor-uid",
			auth_token: "auth-tok",
			geohash: None,
		};
		let json: serde_json::Value = serde_json::to_value(&body).unwrap();
		assert_eq!(json["thirdPartyUserId"], "vendor-uid");
		assert_eq!(json["authToken"], "auth-tok");
		assert!(json.get("email").is_none());
		assert!(json["geohash"].is_null());
	}

	#[test]
	fn sign_in_bodies_carry_geohash_when_set() {
		let login = serde_json::to_value(LoginRequest {
			email: "user@example.com".to_owned(),
			password: "pw".to_owned(),
			token: None,
			geohash: Some("9q8yyk8yuv".to_owned()),
		})
		.unwrap();
		assert_eq!(login["geohash"], "9q8yyk8yuv");

		let refresh = serde_json::to_value(RefreshRequest {
			email: "user@example.com".to_owned(),
			auth_token: "auth-tok".to_owned(),
			token: None,
			geohash: Some("9q8yyk8yuv".to_owned()),
		})
		.unwrap();
		assert_eq!(refresh["geohash"], "9q8yyk8yuv");

		let google = serde_json::to_value(ThirdPartySignInRequest {
			third_party_vendor: 2,
			third_party_token: "ya29.token",
			geohash: Some("9q8yyk8yuv"),
		})
		.unwrap();
		assert_eq!(google["geohash"], "9q8yyk8yuv");
	}

	#[test]
	fn sign_in_bodies_omit_geohash_when_none() {
		let login = serde_json::to_value(LoginRequest {
			email: "user@example.com".to_owned(),
			password: "pw".to_owned(),
			token: None,
			geohash: None,
		})
		.unwrap();
		assert!(login["geohash"].is_null());
	}

	#[test]
	fn session_from_third_party_preserves_google_identity() {
		let session = session_from_third_party(
			third_party_session(Some("me@example.com")),
			"fallback@example.com".to_owned(),
		)
		.unwrap();

		assert_eq!(session.kind, SessionKind::Google);
		assert_eq!(session.third_party_user_id.as_deref(), Some("vendor-uid"));
		assert_eq!(session.auth_token, "auth-tok");
		assert_eq!(session.email, "me@example.com");
	}

	#[test]
	fn session_from_third_party_falls_back_when_no_display_id() {
		let session = session_from_third_party(
			third_party_session(None),
			"fallback@example.com".to_owned(),
		)
		.unwrap();
		assert_eq!(session.email, "fallback@example.com");
	}

	#[test]
	fn age_restricted_claims_map_to_age_verification() {
		let claims = JwtClaims {
			exp: 0,
			restriction: Some("AGE_RESTRICTED".to_owned()),
			restriction_reason: Some("UK_VERIFICATION_REQUIRED".to_owned()),
			ban_details: None,
		};
		assert_eq!(
			restriction_from_claims(&claims),
			Some(Restriction::AgeVerification {
				region: VerificationRegion::Uk,
				reason: "UK_VERIFICATION_REQUIRED".to_owned(),
			})
		);
	}

	#[test]
	fn unrestricted_claims_map_to_none() {
		let claims = JwtClaims {
			exp: 0,
			restriction: None,
			restriction_reason: None,
			ban_details: None,
		};
		assert_eq!(restriction_from_claims(&claims), None);
	}
}
