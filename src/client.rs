use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{broadcast, mpsc, watch};
use wreq::{
	header::HeaderName, Client, EmulationProvider, Http1Config, Http2Config,
	Method, PseudoOrder, SettingsOrder, SslCurve, TlsConfig, TlsVersion,
};

use crate::auth::{AuthEvent, AuthState, LoginResult, Session};
use crate::device::DeviceInfo;
use crate::error::GrindrError;
use crate::headers::build_user_agent;
use crate::media::{MediaRequest, MediaResponse};
use crate::rest::{Fingerprint, InnerClient, RawResponse, RequestBody};
use crate::signing::{
	DeviceSigningKey, MediaUploadResponse, UploadProfileImageResponse,
};
use crate::ws::{
	make_channels, WsChannels, WsCommand, WsConnectionState, WsEvent,
};

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

const CURVES: &[SslCurve] =
	&[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1];

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

const OKHTTP_FIRST_STREAM_ID: u32 = 3;

const OKHTTP_POOL_IDLE: Duration = Duration::from_secs(5 * 60);
const OKHTTP_MAX_IDLE_CONNECTIONS: usize = 5;

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
		.initial_stream_id(OKHTTP_FIRST_STREAM_ID)
		.initial_stream_window_size(OKHTTP_WINDOW_SIZE)
		.initial_connection_window_size(OKHTTP_WINDOW_SIZE)
		.headers_pseudo_order(PSEUDO_ORDER)
		.settings_order(SETTINGS_ORDER)
		.build()
}

static OKHTTP_WS_HEADER_ORDER: [HeaderName; 14] = [
	HeaderName::from_static("authorization"),
	HeaderName::from_static("l-time-zone"),
	HeaderName::from_static("l-grindr-roles"),
	HeaderName::from_static("l-device-info"),
	HeaderName::from_static("accept"),
	HeaderName::from_static("user-agent"),
	HeaderName::from_static("l-locale"),
	HeaderName::from_static("accept-language"),
	HeaderName::from_static("upgrade"),
	HeaderName::from_static("connection"),
	HeaderName::from_static("sec-websocket-key"),
	HeaderName::from_static("sec-websocket-version"),
	HeaderName::from_static("sec-websocket-extensions"),
	HeaderName::from_static("accept-encoding"),
];

fn grindr_ws_emulation() -> EmulationProvider {
	EmulationProvider::builder()
		.tls_config(okhttp_tls_config())
		.http1_config(Http1Config::builder().title_case_headers(true).build())
		.headers_order(&OKHTTP_WS_HEADER_ORDER[..])
		.default_headers(None)
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

/// okhttp's defaults
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(35);
pub(crate) const UPLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Shared `wreq` setup: the emulation profile plus gzip-only encoding.
fn grindr_client_builder() -> wreq::ClientBuilder {
	Client::builder()
		.emulation(grindr_emulation())
		.gzip(true)
		.no_deflate()
		.no_brotli()
		.no_zstd()
		.connect_timeout(CONNECT_TIMEOUT)
		.pool_idle_timeout(OKHTTP_POOL_IDLE)
		.pool_max_idle_per_host(OKHTTP_MAX_IDLE_CONNECTIONS)
		.tcp_keepalive(None)
}

fn build_http_client() -> Result<Client, GrindrError> {
	grindr_client_builder()
		.read_timeout(READ_TIMEOUT)
		.build()
		.map_err(Into::into)
}

fn build_ws_client() -> Result<Client, GrindrError> {
	// Websocket endpoint is http/1.1
	grindr_client_builder()
		.emulation(grindr_ws_emulation())
		.http1_only()
		.build()
		.map_err(Into::into)
}

/// Builds the transport shared by [`GrindrClient::new`] and [`GrindrClient::rotate_device`].
fn build_fingerprint(
	device: DeviceInfo,
) -> Result<Arc<Fingerprint>, GrindrError> {
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

fn parse_json<T: serde::de::DeserializeOwned>(
	resp: RawResponse,
) -> Result<T, GrindrError> {
	if !(200..300).contains(&resp.status) {
		return Err(GrindrError::from_response(resp.status, &resp.body));
	}
	serde_json::from_slice(&resp.body)
		.map_err(|e| GrindrError::Http(e.to_string()))
}

/// Everything needed to start the background websocket task.
struct WsSpawn {
	inner: Arc<InnerClient>,
	auth: Arc<AuthState>,
	channels: WsChannels,
	cmd_rx: mpsc::Receiver<WsCommand>,
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
	signing_key_rx: watch::Receiver<Option<DeviceSigningKey>>,
	ws_event_tx: broadcast::Sender<WsEvent>,
	ws_cmd_tx: mpsc::Sender<WsCommand>,
	ws_state_rx: watch::Receiver<WsConnectionState>,
	ws_started: Arc<Once>,
	ws_spawn: Arc<Mutex<Option<WsSpawn>>>,
}

impl GrindrClient {
	/// Creates a client for a [`DeviceInfo`], optionally resuming an account
	/// from saved [`Credentials`](crate::Credentials).
	///
	/// Pass `None` to start logged out, or `Session { credentials, token: None }`
	/// to resume without logging in again. This is sync and needs no runtime, and
	/// it never opens the websocket — call [`connect`](Self::connect) for that.
	pub fn new(
		device: DeviceInfo,
		session: Option<Session>,
	) -> Result<Self, GrindrError> {
		let fingerprint = build_fingerprint(device)?;

		let (signing_key_tx, signing_key_rx) = watch::channel(None);
		let inner = Arc::new(InnerClient {
			fingerprint: tokio::sync::RwLock::new(fingerprint),
			signing: tokio::sync::Mutex::new(None),
			signing_key_tx,
			server_offset_ms: std::sync::atomic::AtomicI64::new(0),
		});

		let (auth_state, session_rx) = AuthState::new(session);
		let auth = Arc::new(auth_state);

		let (ws_channels, ws_handles) = make_channels();

		let ws_event_tx = ws_channels.event_tx.clone();
		let ws_cmd_tx = ws_handles.cmd_tx;
		let ws_state_rx = ws_handles.state_rx;

		let ws_spawn = WsSpawn {
			inner: Arc::clone(&inner),
			auth: Arc::clone(&auth),
			channels: ws_channels,
			cmd_rx: ws_handles.cmd_rx,
		};

		Ok(Self {
			inner,
			auth,
			session_rx,
			signing_key_rx,
			ws_event_tx,
			ws_cmd_tx,
			ws_state_rx,
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
	/// It changes on login, refresh, and logout — read it here to persist its
	/// [`credentials`](crate::Session::credentials) to disk.
	pub fn session_receiver(&self) -> watch::Receiver<Option<Session>> {
		self.session_rx.clone()
	}

	/// Watches the current [`DeviceSigningKey`] (used to sign media uploads).
	///
	/// It changes when a key is registered on first upload (save it in secure
	/// storage alongside the session) and clears on [`logout`](Self::logout) /
	/// [`rotate_device`](Self::rotate_device). Restore a saved one with
	/// [`restore_signing_key`](Self::restore_signing_key) to avoid re-registering.
	pub fn signing_key_receiver(
		&self,
	) -> watch::Receiver<Option<DeviceSigningKey>> {
		self.signing_key_rx.clone()
	}

	/// Restores a persisted [`DeviceSigningKey`] so uploads reuse it instead of
	/// registering a fresh key.
	///
	/// Returns whether it was taken: a key that can't be decoded, or that was
	/// saved for a different account than the current session, is refused.
	#[must_use]
	pub async fn restore_signing_key(&self, key: DeviceSigningKey) -> bool {
		self.inner.restore_signing_key(&self.auth, key).await
	}

	/// Watches the websocket [`WsConnectionState`].
	pub fn connection_state(&self) -> watch::Receiver<WsConnectionState> {
		self.ws_state_rx.clone()
	}

	/// Marks the client active or idle; clients start active. Set `false` while
	/// the host app is backgrounded.
	///
	/// Idle, the websocket disconnects and stops reconnecting and a failed
	/// refresh raises no [`RefreshFailed`](crate::AuthEvent::RefreshFailed),
	/// terminal events and REST calls are unaffected. Returning to active
	/// reconnects at once.
	pub fn set_active(&self, active: bool) {
		self.auth.set_active(active);
	}

	/// Whether the client is [active](Self::set_active).
	pub fn is_active(&self) -> bool {
		self.auth.is_active()
	}

	/// Drops the connection pool and TLS session cache, keeping the device
	/// identity, the session, and the signing key. Worth calling on resume:
	/// sockets that idled through a suspend are often dead with neither end
	/// having noticed, stalling the first request that inherits one.
	pub async fn reset_transport(&self) -> Result<(), GrindrError> {
		let device = self.inner.fingerprint().await.device.clone();
		let fingerprint = build_fingerprint(device)?;
		*self.inner.fingerprint.write().await = fingerprint;
		Ok(())
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
	pub async fn login(
		&self,
		email: &str,
		password: &str,
	) -> Result<LoginResult, GrindrError> {
		self.login_with_geohash(email, password, None).await
	}

	/// Like [`login`](Self::login), but tags the sign-in request with a
	/// `geohash` so the server records that approximate location for the new
	/// session. Only this initial request carries it; later background refreshes
	/// do not. Pass `None` to omit it.
	pub async fn login_with_geohash(
		&self,
		email: &str,
		password: &str,
		geohash: Option<&str>,
	) -> Result<LoginResult, GrindrError> {
		crate::auth::login_email(
			&self.inner,
			&self.auth,
			email,
			password,
			geohash,
		)
		.await
	}

	/// Signs in with a Google OAuth access token and stores the session.
	pub async fn google_sign_in(
		&self,
		google_access_token: &str,
	) -> Result<LoginResult, GrindrError> {
		self.google_sign_in_with_geohash(google_access_token, None)
			.await
	}

	/// Like [`google_sign_in`](Self::google_sign_in), but tags the sign-in
	/// request with a `geohash`. Only this initial request carries it. Pass
	/// `None` to omit it.
	pub async fn google_sign_in_with_geohash(
		&self,
		google_access_token: &str,
		geohash: Option<&str>,
	) -> Result<LoginResult, GrindrError> {
		crate::auth::google_sign_in(
			&self.inner,
			&self.auth,
			google_access_token,
			geohash,
		)
		.await
	}

	/// Forces a token refresh.
	///
	/// This happens automatically before the token expires, so you rarely need
	/// to call it yourself.
	pub async fn refresh_token(&self) -> Result<LoginResult, GrindrError> {
		self.refresh_token_with_geohash(None).await
	}

	/// Like [`refresh_token`](Self::refresh_token), but tags the refresh request
	/// with a `geohash`. Useful to seed the location of a session resumed from a
	/// saved `auth_token` on its first request. Automatic background refreshes
	/// never carry a geohash. Pass `None` to omit it.
	pub async fn refresh_token_with_geohash(
		&self,
		geohash: Option<&str>,
	) -> Result<LoginResult, GrindrError> {
		crate::auth::refresh_token(&self.inner, &self.auth, geohash).await
	}

	/// Clears the session and closes the websocket, without reconnecting while
	/// logged out. Keeps the device identity and transport — use
	/// [`sign_out_rotating`](Self::sign_out_rotating) to also rotate those.
	pub async fn logout(&self) {
		self.auth.clear_session().await;
		self.inner.clear_signing().await;
	}

	/// Makes an authenticated request and returns the raw status and body.
	///
	/// `path` is added to the API base URL and must start with `/` (e.g.
	/// `/v3/me/profile`), otherwise you get [`GrindrError::InvalidRequest`]. The
	/// session token is added for you, refreshing first if it's about to expire.
	/// The body comes back as-is for you to deserialize, including non-success
	/// statuses; map those with [`GrindrError::from_response`]. An edge
	/// interstitial (a `403` that isn't JSON, or a Cloudflare challenge) turns
	/// into [`GrindrError::Blocked`] instead.
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
			.request_authenticated(
				&self.auth,
				method,
				path,
				body.map(RequestBody::Json),
			)
			.await
	}

	/// Makes an unauthenticated request and returns the raw status and body, for
	/// the endpoints that take no session (sign-in, `/v3/bootstrap`, feature
	/// probes).
	///
	/// Same transport and path rules as
	/// [`request_authenticated_raw`](Self::request_authenticated_raw), without
	/// the `Authorization` and `L-Grindr-Roles` headers.
	pub async fn request_no_auth_raw(
		&self,
		method: Method,
		path: &str,
		body: Option<serde_json::Value>,
	) -> Result<RawResponse, GrindrError> {
		self.inner
			.request_no_auth_raw(method, path, body.map(RequestBody::Json))
			.await
	}

	/// Like [`request_authenticated_raw`](Self::request_authenticated_raw), but
	/// sends a raw binary body with the given `Content-Type` instead of JSON —
	/// for endpoints like `POST /v6/chat/media/upload` that take the file bytes
	/// as the body.
	///
	/// `body` accepts anything convertible to [`Bytes`]; a `Vec<u8>` converts
	/// without copying. Non-success statuses come back as a normal
	/// [`RawResponse`]; map them with [`GrindrError::from_response`] to get the
	/// same errors the crate's typed methods return. An edge interstitial turns
	/// into [`GrindrError::Blocked`].
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

	/// Sends a device-key-signed request with a raw binary body, for the upload
	/// endpoints that require it (`/v5/media/upload`, `/v6/chat/media/upload`).
	///
	/// On first use it registers an ephemeral P-256 key for the session; the key
	/// is dropped on [`logout`](Self::logout) and [`rotate_device`](Self::rotate_device).
	/// Prefer [`upload_profile_image`](Self::upload_profile_image) /
	/// [`upload_chat_media`](Self::upload_chat_media) unless you need another path.
	pub async fn request_signed_bytes(
		&self,
		method: Method,
		path: &str,
		content_type: &str,
		body: impl Into<Bytes>,
	) -> Result<RawResponse, GrindrError> {
		self.inner
			.request_signed(&self.auth, method, path, content_type, body.into())
			.await
	}

	/// Uploads a profile image via signed `POST /v5/media/upload`.
	///
	/// `thumb_coords` is an optional `"x,y,w,h"` crop; `taken_on_grindr` marks
	/// images captured in-app.
	pub async fn upload_profile_image(
		&self,
		jpeg: impl Into<Bytes>,
		thumb_coords: Option<&str>,
		taken_on_grindr: bool,
	) -> Result<UploadProfileImageResponse, GrindrError> {
		let mut path =
			format!("/v5/media/upload?takenOnGrindr={taken_on_grindr}");
		if let Some(coords) = thumb_coords {
			path.push_str("&thumbCoords=");
			path.push_str(coords);
		}
		let resp = self
			.request_signed_bytes(Method::POST, &path, "image/jpeg", jpeg)
			.await?;
		parse_json(resp)
	}

	/// Uploads chat media via unsigned `POST /v5/chat/media/upload`.
	pub async fn upload_chat_media_unsigned(
		&self,
		bytes: impl Into<Bytes>,
		content_type: &str,
	) -> Result<MediaUploadResponse, GrindrError> {
		let resp = self
			.request_authenticated_bytes(
				Method::POST,
				"/v5/chat/media/upload?takenOnGrindr=false",
				content_type,
				bytes,
			)
			.await?;
		parse_json(resp)
	}

	/// Uploads chat media via signed `POST /v6/chat/media/upload`.
	pub async fn upload_chat_media(
		&self,
		bytes: impl Into<Bytes>,
		content_type: &str,
		length: Option<i64>,
		looping: Option<bool>,
		taken_on_grindr: bool,
	) -> Result<MediaUploadResponse, GrindrError> {
		let mut path =
			format!("/v6/chat/media/upload?takenOnGrindr={taken_on_grindr}");
		if let Some(length) = length {
			path.push_str(&format!("&length={length}"));
		}
		if let Some(looping) = looping {
			path.push_str(&format!("&looping={looping}"));
		}
		let resp = self
			.request_signed_bytes(Method::POST, &path, content_type, bytes)
			.await?;
		parse_json(resp)
	}

	/// Fetches a CDN file on the transport the API uses, with the headers the
	/// app's image loader sends.
	///
	/// Only `https` on `cdns.grindr.com` or `*.cloudfront.net` is accepted,
	/// redirects included; anything else is [`GrindrError::InvalidRequest`]
	/// before a socket is opened. A non-success status comes back as an
	/// ordinary [`MediaResponse`].
	pub async fn fetch_media(
		&self,
		request: MediaRequest<'_>,
	) -> Result<MediaResponse, GrindrError> {
		self.inner.fetch_media(request).await
	}

	/// Replaces the device identity and the underlying HTTP/TLS transport while
	/// keeping the session, and returns the old device. Building new `wreq`
	/// clients also drops the connection pool and TLS session-resumption cache,
	/// so nothing from the old device carries over to later requests.
	pub async fn rotate_device(
		&self,
		device: DeviceInfo,
	) -> Result<DeviceInfo, GrindrError> {
		let new_fp = build_fingerprint(device)?;
		let old_fp = {
			let mut guard = self.inner.fingerprint.write().await;
			std::mem::replace(&mut *guard, new_fp)
		};
		self.inner.clear_signing().await;
		Ok(old_fp.device.clone())
	}

	/// [`logout`](Self::logout) then [`rotate_device`](Self::rotate_device):
	/// clears the session and rotates the device identity and transport so the
	/// next login cannot be correlated with this one. Pass a fresh
	/// [`DeviceInfo`] to persist and reuse until the next sign-out; returns the
	/// old device.
	pub async fn sign_out_rotating(
		&self,
		device: DeviceInfo,
	) -> Result<DeviceInfo, GrindrError> {
		self.logout().await;
		self.rotate_device(device).await
	}

	/// The device identity currently in use.
	pub async fn current_device(&self) -> DeviceInfo {
		self.inner.fingerprint().await.device.clone()
	}

	/// Whether the server has first-party reCAPTCHA enabled. No auth needed.
	pub async fn recaptcha_first_party_enabled(
		&self,
	) -> Result<bool, GrindrError> {
		crate::auth::recaptcha_first_party_enabled(&self.inner).await
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::auth::{Credentials, SessionToken};

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
	async fn a_session_without_a_token_is_never_sent_as_an_empty_bearer() {
		let device = DeviceInfo::generate();
		let device_id = device.device_id.clone();
		crate::testserver::queue_session_replies(
			&device_id,
			[("503 Service Unavailable", "{}".to_owned())],
		);
		let client =
			GrindrClient::new(device, Some(resumed("a@b.c", "auth-tok")))
				.unwrap();

		let err = client
			.request_authenticated_raw(Method::GET, "/v3/me/profile", None)
			.await
			.unwrap_err();
		assert!(matches!(err, GrindrError::Auth(_)), "got {err:?}");

		let requests = crate::testserver::requests_from(&device_id);
		assert!(
			requests.iter().all(|r| r.path != "/v3/me/profile"),
			"the authenticated call must never leave without a token"
		);
	}

	#[tokio::test]
	async fn no_auth_requests_need_no_session_but_validate_the_path() {
		let client = GrindrClient::new(DeviceInfo::generate(), None).unwrap();

		let err = client
			.request_no_auth_raw(Method::GET, "evil.com/x", None)
			.await
			.unwrap_err();
		assert!(matches!(err, GrindrError::InvalidRequest(_)));
		assert!(!client.ws_started.is_completed());
	}

	#[tokio::test]
	async fn bytes_requests_require_a_session_and_validate_the_path() {
		let client = GrindrClient::new(DeviceInfo::generate(), None).unwrap();

		let err = client
			.request_authenticated_bytes(
				Method::POST,
				"/v6/chat/media/upload?takenOnGrindr=false",
				"image/jpeg",
				vec![0xFF, 0xD8],
			)
			.await
			.unwrap_err();
		assert!(matches!(err, GrindrError::Auth(_)));

		let err = client
			.request_authenticated_bytes(
				Method::POST,
				"evil.com/x",
				"image/jpeg",
				Vec::new(),
			)
			.await
			.unwrap_err();
		assert!(matches!(err, GrindrError::InvalidRequest(_)));
	}

	#[tokio::test]
	async fn a_token_resumed_session_refreshes_before_its_first_request() {
		let device = DeviceInfo::generate();
		let device_id = device.device_id.clone();
		let client =
			GrindrClient::new(device, Some(resumed("a@b.c", "stored-tok")))
				.unwrap();

		let resp = client
			.request_authenticated_raw(Method::GET, "/v3/bootstrap", None)
			.await
			.unwrap();
		assert_eq!(resp.status, 200);

		let requests = crate::testserver::requests_from(&device_id);
		assert_eq!(
			requests[0].path, "/v8/sessions",
			"the refresh must precede the call it authorizes"
		);
		assert_eq!(requests[1].path, "/v3/bootstrap");

		let refreshed = client.session_receiver().borrow().clone().unwrap();
		assert_eq!(
			refreshed.credentials.profile_id.as_deref(),
			Some(crate::testserver::REFRESHED_PROFILE_ID)
		);
		let bearer = format!("Grindr3 {}", refreshed.token.unwrap().session_id);
		assert_eq!(requests[1].header("authorization"), Some(bearer.as_str()));
	}

	#[tokio::test]
	async fn a_failing_refresh_is_reported_once_then_retracted_on_recovery() {
		let device = DeviceInfo::generate();
		let device_id = device.device_id.clone();
		crate::testserver::queue_session_replies(
			&device_id,
			[("503 Service Unavailable", "{}".to_owned())],
		);
		let client =
			GrindrClient::new(device, Some(expired_session())).unwrap();
		let mut events = client.auth_event_receiver();

		client
			.request_authenticated_raw(Method::GET, "/v3/bootstrap", None)
			.await
			.unwrap();

		let event = events.try_recv().unwrap();
		let AuthEvent::RefreshFailed { kind, .. } = event else {
			panic!("expected a RefreshFailed, got {event:?}");
		};
		assert_eq!(kind, crate::auth::RefreshFailureKind::Server);

		client.refresh_token().await.unwrap();
		assert!(matches!(events.try_recv(), Ok(AuthEvent::RefreshRecovered)));
	}

	#[tokio::test]
	async fn a_burst_of_calls_on_a_dead_network_refreshes_once() {
		let device = DeviceInfo::generate();
		let device_id = device.device_id.clone();
		crate::testserver::queue_session_replies(
			&device_id,
			std::iter::repeat_n(
				("503 Service Unavailable", "{}".to_owned()),
				8,
			),
		);
		let client =
			GrindrClient::new(device, Some(expired_session())).unwrap();

		let calls = (0..8).map(|_| {
			let client = client.clone();
			async move {
				let _ = client
					.request_authenticated_raw(
						Method::GET,
						"/v3/bootstrap",
						None,
					)
					.await;
			}
		});
		futures_util::future::join_all(calls).await;

		let refreshes = crate::testserver::requests_from(&device_id)
			.iter()
			.filter(|r| r.path == "/v8/sessions")
			.count();
		assert_eq!(
			refreshes, 1,
			"the cooldown must collapse the waiters queued behind the first \
			 failed refresh, not let each one retry"
		);
	}

	#[tokio::test]
	async fn an_idle_client_reports_nothing_but_still_serves_rest_calls() {
		let device = DeviceInfo::generate();
		let device_id = device.device_id.clone();
		crate::testserver::queue_session_replies(
			&device_id,
			[("503 Service Unavailable", "{}".to_owned())],
		);
		let client =
			GrindrClient::new(device, Some(expired_session())).unwrap();
		let mut events = client.auth_event_receiver();
		client.set_active(false);

		client
			.request_authenticated_raw(Method::GET, "/v3/bootstrap", None)
			.await
			.unwrap();

		assert!(
			events.try_recv().is_err(),
			"a backgrounded app must not raise a failure the user cannot act on"
		);
		assert!(!client.is_active());
		client.set_active(true);
		assert!(client.is_active());
	}

	#[tokio::test]
	async fn reset_transport_keeps_the_device_and_the_session() {
		let device = DeviceInfo::generate();
		let client =
			GrindrClient::new(device.clone(), Some(fake_session())).unwrap();

		client.reset_transport().await.unwrap();

		assert_eq!(client.current_device().await.device_id, device.device_id);
		assert!(client.session_receiver().borrow().is_some());
	}

	#[tokio::test]
	async fn an_unsigned_chat_upload_registers_no_key_and_signs_nothing() {
		let device = DeviceInfo::generate();
		let device_id = device.device_id.clone();
		let client =
			GrindrClient::new(device, Some(resumed("a@b.c", "stored-tok")))
				.unwrap();

		let uploaded = client
			.upload_chat_media_unsigned(vec![0xFF, 0xD8], "image/jpeg")
			.await
			.unwrap();

		assert_eq!(uploaded.media_id, 7);
		assert_eq!(uploaded.url, "https://cdn/x.jpg");
		assert_eq!(uploaded.media_hash, "h");

		let requests = crate::testserver::requests_from(&device_id);
		let paths: Vec<&str> =
			requests.iter().map(|r| r.path.as_str()).collect();
		assert_eq!(
			paths,
			["/v8/sessions", "/v5/chat/media/upload?takenOnGrindr=false"],
			"the unsigned path must not touch the device-key endpoints"
		);

		let upload = requests.last().unwrap();
		assert_eq!(upload.method, "POST");
		assert_eq!(upload.header("content-type"), Some("image/jpeg"));
		assert_eq!(upload.header("x-key-id"), None);
		assert_eq!(upload.header("x-sig"), None);
	}

	#[tokio::test]
	async fn a_token_resumed_upload_binds_the_key_to_the_refreshed_profile_id()
	{
		use base64::engine::general_purpose::URL_SAFE_NO_PAD;
		use base64::Engine;
		use p256::ecdsa::{signature::Verifier, DerSignature, VerifyingKey};
		use spki::DecodePublicKey;

		let device = DeviceInfo::generate();
		let device_id = device.device_id.clone();
		let client =
			GrindrClient::new(device, Some(resumed("a@b.c", "stored-tok")))
				.unwrap();

		client
			.upload_profile_image(vec![0xFF, 0xD8], None, false)
			.await
			.unwrap();

		let requests = crate::testserver::requests_from(&device_id);
		let paths: Vec<&str> =
			requests.iter().map(|r| r.path.as_str()).collect();
		assert_eq!(
			paths,
			[
				"/v8/sessions",
				"/v1/verification/device-keys/challenge",
				"/v1/verification/device-keys",
				"/v5/media/upload?takenOnGrindr=false",
			],
			"the refresh must land before the key is generated"
		);

		assert_eq!(requests[2].method, "POST");
		let registration: serde_json::Value =
			serde_json::from_str(&requests[2].body).unwrap();
		let public_key = registration["publicKey"].as_str().unwrap();
		let key_id = registration["keyId"].as_str().unwrap();
		let signature = registration["registrationSignature"].as_str().unwrap();

		let verifying = VerifyingKey::from(
			p256::PublicKey::from_public_key_der(
				&URL_SAFE_NO_PAD.decode(public_key).unwrap(),
			)
			.unwrap(),
		);
		let der = URL_SAFE_NO_PAD.decode(signature).unwrap();
		let signature = DerSignature::try_from(der.as_slice()).unwrap();
		let signed_for = |user_id: &str| {
			format!(
				"{user_id}|{key_id}|{public_key}|{device_id}|{}",
				crate::testserver::CHALLENGE
			)
		};

		assert!(
			verifying
				.verify(
					signed_for(crate::testserver::REFRESHED_PROFILE_ID)
						.as_bytes(),
					&signature
				)
				.is_ok(),
			"the key must bind to the refreshed profile id"
		);
		assert!(
			verifying
				.verify(signed_for("").as_bytes(), &signature)
				.is_err(),
			"the key must not bind to the blank pre-refresh profile id"
		);
	}

	#[tokio::test]
	async fn no_auth_requests_carry_no_credentials_even_with_a_session() {
		let device = DeviceInfo::generate();
		let device_id = device.device_id.clone();
		let client = GrindrClient::new(device, Some(fake_session())).unwrap();

		let resp = client
			.request_no_auth_raw(Method::GET, "/v3/bootstrap", None)
			.await
			.unwrap();
		assert_eq!(resp.status, 200);
		assert_eq!(resp.body, br#"{"ok":true}"#);

		let requests = crate::testserver::requests_from(&device_id);
		let bootstrap = &requests[0];
		assert_eq!(bootstrap.method, "GET");
		assert_eq!(bootstrap.path, "/v3/bootstrap");
		assert_eq!(bootstrap.header("authorization"), None);
		assert_eq!(bootstrap.header("l-grindr-roles"), None);
		assert!(bootstrap.header("l-device-info").is_some());
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

	fn resumed(email: &str, auth_token: &str) -> Session {
		Session {
			credentials: Credentials {
				email: email.to_owned(),
				profile_id: None,
				auth_token: auth_token.to_owned(),
				kind: crate::auth::SessionKind::Email,
				third_party_user_id: None,
			},
			token: None,
		}
	}

	fn expired_session() -> Session {
		Session {
			token: Some(SessionToken {
				session_id: "stale-sid".to_owned(),
				expires_at: 0,
				restriction: None,
			}),
			..fake_session()
		}
	}

	fn fake_session() -> Session {
		Session {
			credentials: Credentials {
				email: "user@example.com".to_owned(),
				profile_id: Some("1".to_owned()),
				auth_token: "atok".to_owned(),
				kind: crate::auth::SessionKind::Email,
				third_party_user_id: None,
			},
			token: Some(SessionToken {
				session_id: "sid".to_owned(),
				expires_at: u64::MAX,
				restriction: None,
			}),
		}
	}

	#[tokio::test]
	async fn rotate_device_swaps_identity_and_returns_old() {
		let old = DeviceInfo::generate();
		let client = GrindrClient::new(old.clone(), None).unwrap();

		let returned =
			client.rotate_device(DeviceInfo::generate()).await.unwrap();
		assert_eq!(returned.device_id, old.device_id);
		assert_ne!(client.current_device().await.device_id, old.device_id);
	}

	#[tokio::test]
	async fn sign_out_rotating_clears_session_and_rotates_device() {
		let old = DeviceInfo::generate();
		let client =
			GrindrClient::new(old.clone(), Some(fake_session())).unwrap();
		assert!(client.session_receiver().borrow().is_some());

		let returned = client
			.sign_out_rotating(DeviceInfo::generate())
			.await
			.unwrap();

		assert_eq!(returned.device_id, old.device_id);
		assert_ne!(client.current_device().await.device_id, old.device_id);
		assert!(client.session_receiver().borrow().is_none());
	}
}
