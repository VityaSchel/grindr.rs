use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::watch;
use wreq::header::HeaderMap;
use wreq::{Client, Method, RequestBuilder};

use crate::auth::AuthState;
use crate::device::DeviceInfo;
use crate::error::{BanInfo, BanKind, GrindrError};
use crate::headers::GrindrHeaders;
use crate::signing::{
	signing_reject, DeviceKey, DeviceSigningKey, SigningReject,
};

#[cfg(not(test))]
pub(crate) fn base_url() -> &'static str {
	"https://grindr.mobi"
}

#[cfg(test)]
pub(crate) fn base_url() -> &'static str {
	crate::testserver::base_url()
}

/// Guards against a `path` that would change the effective host once
/// concatenated onto [`base_url`].
///
/// `format!("{}{path}", base_url())` keeps the request on `grindr.mobi` only
/// when `path` starts with `/`.
fn validate_path(path: &str) -> Result<(), GrindrError> {
	if path.starts_with('/') {
		Ok(())
	} else {
		Err(GrindrError::InvalidRequest(format!(
			"request path must begin with '/', got {path:?}"
		)))
	}
}

/// A raw API response: the HTTP status and the unparsed body bytes.
///
/// Returned by
/// [`GrindrClient::request_authenticated_raw`](crate::GrindrClient::request_authenticated_raw)
/// and
/// [`GrindrClient::request_authenticated_bytes`](crate::GrindrClient::request_authenticated_bytes)
/// so callers can deserialize the body into whatever type the endpoint returns.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RawResponse {
	/// HTTP status code.
	pub status: u16,
	/// Raw, unparsed response body.
	pub body: Vec<u8>,
}

pub struct Fingerprint {
	/// ALPN: `["h2", "http/1.1"]`
	pub http: Client,
	/// ALPN: `["http/1.1"]`
	pub ws_http: Client,
	pub device: DeviceInfo,
	pub user_agent: String,
}

/// Payload of an authenticated request.
///
/// Kept by reference across the internal 401-refresh retry, so the raw variant
/// holds [`Bytes`] (cloning is a refcount bump, not a copy).
pub(crate) enum RequestBody {
	Json(serde_json::Value),
	Raw { content_type: String, bytes: Bytes },
}

pub(crate) struct InnerClient {
	pub fingerprint: tokio::sync::RwLock<Arc<Fingerprint>>,
	pub signing: tokio::sync::Mutex<Option<DeviceKey>>,
	pub signing_key_tx: watch::Sender<Option<DeviceSigningKey>>,
	pub server_offset_ms: AtomicI64,
}

fn local_now_ms() -> i64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_millis() as i64)
		.unwrap_or(0)
}

impl InnerClient {
	pub async fn fingerprint(&self) -> Arc<Fingerprint> {
		Arc::clone(&*self.fingerprint.read().await)
	}

	pub async fn clear_signing(&self) {
		self.signing.lock().await.take();
		let _ = self.signing_key_tx.send(None);
	}

	pub async fn restore_signing_key(
		&self,
		auth: &AuthState,
		key: DeviceSigningKey,
	) -> bool {
		let known_user_id =
			session_user_id(auth).await.ok().filter(|id| !id.is_empty());
		if known_user_id.is_some_and(|id| id != key.user_id()) {
			return false;
		}
		match DeviceKey::from_stored(&key) {
			Some(device_key) => {
				*self.signing.lock().await = Some(device_key);
				let _ = self.signing_key_tx.send(Some(key));
				true
			}
			None => false,
		}
	}

	/// Tracks the local↔server clock skew from a response's `Date` header, so
	/// signed uploads carry an `X-Timestamp` the server accepts (the app corrects
	/// this reactively on a `timestamp_drift` rejection; seeding from `Date`
	/// avoids that round-trip).
	fn note_server_date(&self, headers: &HeaderMap) {
		let server_ms = headers
			.get("date")
			.and_then(|v| v.to_str().ok())
			.and_then(|d| httpdate::parse_http_date(d).ok())
			.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
			.map(|d| d.as_millis() as i64);
		if let Some(server_ms) = server_ms {
			self.server_offset_ms
				.store(server_ms - local_now_ms(), Ordering::Relaxed);
		}
	}

	fn synced_now_ms(&self) -> u64 {
		(local_now_ms() + self.server_offset_ms.load(Ordering::Relaxed)).max(0)
			as u64
	}

	fn apply_headers(
		mut req: RequestBuilder,
		items: &[(wreq::header::HeaderName, wreq::header::HeaderValue)],
	) -> RequestBuilder {
		for (name, value) in items {
			req = req.header(name.clone(), value.clone());
		}
		req
	}

	fn apply_body(
		req: RequestBuilder,
		body: Option<&RequestBody>,
	) -> RequestBuilder {
		match body {
			Some(RequestBody::Json(b)) => req.json(b),
			Some(RequestBody::Raw {
				content_type,
				bytes,
			}) => req.header("content-type", content_type).body(bytes.clone()),
			None => req,
		}
	}

	pub async fn request_no_auth<TReq, TResp>(
		&self,
		method: Method,
		path: &str,
		body: Option<&TReq>,
	) -> Result<TResp, GrindrError>
	where
		TReq: Serialize + ?Sized,
		TResp: DeserializeOwned,
	{
		validate_path(path)?;
		let fp = self.fingerprint().await;
		let headers =
			GrindrHeaders::build(&fp.device, &fp.user_agent, None, None)?;

		let mut req = Self::apply_headers(
			fp.http.request(method, format!("{}{path}", base_url())),
			&headers.items,
		);
		if let Some(b) = body {
			req = req.json(b);
		}

		let resp = req.send().await?;
		self.note_server_date(resp.headers());
		if !resp.status().is_success() {
			let status = resp.status().as_u16();
			let bytes = resp.bytes().await.unwrap_or_default();
			return Err(parse_api_error(&bytes, status));
		}
		resp.json::<TResp>().await.map_err(Into::into)
	}

	pub async fn request_no_auth_raw(
		&self,
		method: Method,
		path: &str,
		body: Option<RequestBody>,
	) -> Result<RawResponse, GrindrError> {
		validate_path(path)?;

		let fp = self.fingerprint().await;
		let headers =
			GrindrHeaders::build(&fp.device, &fp.user_agent, None, None)?;

		let req = Self::apply_body(
			Self::apply_headers(
				fp.http.request(method, format!("{}{path}", base_url())),
				&headers.items,
			),
			body.as_ref(),
		);

		let resp = req.send().await?;
		self.note_server_date(resp.headers());
		let status = resp.status().as_u16();
		let body_bytes = resp.bytes().await?.to_vec();
		raw_or_blocked(status, body_bytes)
	}

	pub async fn request_authenticated(
		&self,
		auth: &AuthState,
		method: Method,
		path: &str,
		body: Option<RequestBody>,
	) -> Result<RawResponse, GrindrError> {
		validate_path(path)?;

		let mut retried = false;
		loop {
			let authorization = crate::auth::authorization_header(self, auth)
				.await
				.ok_or_else(|| GrindrError::Auth("not logged in".to_owned()))?;
			let session_id = auth
				.session
				.read()
				.await
				.as_ref()
				.map(|s| s.session_id.clone());

			let fp = self.fingerprint().await;
			let headers = GrindrHeaders::build(
				&fp.device,
				&fp.user_agent,
				Some(&authorization),
				Some("[FREE]"),
			)?;

			let req = Self::apply_body(
				Self::apply_headers(
					fp.http.request(
						method.clone(),
						format!("{}{path}", base_url()),
					),
					&headers.items,
				),
				body.as_ref(),
			);

			let resp = req.send().await?;
			self.note_server_date(resp.headers());
			let status = resp.status().as_u16();
			let body_bytes = resp.bytes().await?.to_vec();

			if status == 401 && !retried {
				retried = true;
				if let Some(stale) = session_id {
					if crate::auth::refresh_after_unauthorized(
						self, auth, &stale,
					)
					.await
					{
						continue;
					}
				}
			}

			return raw_or_blocked(status, body_bytes);
		}
	}

	async fn authed_json<T: DeserializeOwned>(
		&self,
		auth: &AuthState,
		method: Method,
		path: &str,
		body: Option<serde_json::Value>,
	) -> Result<T, GrindrError> {
		let resp = self
			.request_authenticated(
				auth,
				method,
				path,
				body.map(RequestBody::Json),
			)
			.await?;
		if !(200..300).contains(&resp.status) {
			return Err(parse_api_error(&resp.body, resp.status));
		}
		serde_json::from_slice(&resp.body)
			.map_err(|e| GrindrError::Http(e.to_string()))
	}

	/// Refreshes first, so the blank profile id a token-resumed session starts
	/// with is filled in before a key binds to it.
	async fn signing_user_id(
		&self,
		auth: &AuthState,
	) -> Result<String, GrindrError> {
		crate::auth::authorization_header(self, auth)
			.await
			.ok_or_else(|| GrindrError::Auth("not logged in".to_owned()))?;
		match session_user_id(auth).await? {
			id if id.is_empty() => Err(GrindrError::Auth(
				"session has no profile id to bind a device key to".to_owned(),
			)),
			id => Ok(id),
		}
	}

	async fn ensure_device_key(
		&self,
		auth: &AuthState,
	) -> Result<(), GrindrError> {
		let user_id = self.signing_user_id(auth).await?;
		let mut guard = self.signing.lock().await;
		if guard.as_ref().is_some_and(|k| k.user_id() == user_id) {
			return Ok(());
		}

		let android_id = self.fingerprint().await.device.device_id.clone();
		let key = DeviceKey::generate(user_id);

		let challenge: crate::signing::ChallengeResponse = self
			.authed_json(
				auth,
				Method::POST,
				"/v1/verification/device-keys/challenge",
				None,
			)
			.await?;

		let registration_signature =
			key.registration_signature(&android_id, &challenge.challenge);
		let body = serde_json::to_value(crate::signing::RegisterKeyRequest {
			public_key: key.public_key(),
			key_id: key.key_id(),
			registration_signature: &registration_signature,
		})
		.map_err(|e| GrindrError::Http(e.to_string()))?;

		let resp = self
			.request_authenticated(
				auth,
				Method::POST,
				"/v1/verification/device-keys",
				Some(RequestBody::Json(body)),
			)
			.await?;
		if !(200..300).contains(&resp.status) {
			return Err(parse_api_error(&resp.body, resp.status));
		}

		let exported = key.export();
		*guard = Some(key);
		let _ = self.signing_key_tx.send(Some(exported));
		Ok(())
	}

	pub async fn request_signed(
		&self,
		auth: &AuthState,
		method: Method,
		path: &str,
		content_type: &str,
		body: Bytes,
	) -> Result<RawResponse, GrindrError> {
		validate_path(path)?;
		self.ensure_device_key(auth).await?;

		let mut refreshed = false;
		let mut resigned = false;
		loop {
			let authorization = crate::auth::authorization_header(self, auth)
				.await
				.ok_or_else(|| GrindrError::Auth("not logged in".to_owned()))?;
			let session_id = auth
				.session
				.read()
				.await
				.as_ref()
				.map(|s| s.session_id.clone());

			let fp = self.fingerprint().await;
			let android_id = fp.device.device_id.clone();
			let timestamp = self.synced_now_ms();
			let signature = {
				let guard = self.signing.lock().await;
				guard
					.as_ref()
					.ok_or_else(|| {
						GrindrError::Auth(
							"device key not registered".to_owned(),
						)
					})?
					.upload_headers(&android_id, &body, timestamp)
			};

			let headers = GrindrHeaders::build(
				&fp.device,
				&fp.user_agent,
				Some(&authorization),
				Some("[FREE]"),
			)?;
			let req = Self::apply_headers(
				fp.http
					.request(method.clone(), format!("{}{path}", base_url())),
				&headers.items,
			)
			.header("x-key-id", &signature.key_id)
			.header("x-sig", &signature.signature)
			.header("x-timestamp", signature.timestamp.to_string())
			.header("x-nonce", &signature.nonce)
			.header("content-type", content_type)
			.body(body.clone());

			let resp = req.send().await?;
			self.note_server_date(resp.headers());
			let status = resp.status().as_u16();
			let body_bytes = resp.bytes().await?.to_vec();

			if status == 401 && !refreshed {
				refreshed = true;
				if let Some(stale) = session_id {
					if crate::auth::refresh_after_unauthorized(
						self, auth, &stale,
					)
					.await
					{
						continue;
					}
				}
			}

			if !(200..300).contains(&status) {
				match signing_reject(&body_bytes) {
					Some(SigningReject::Retryable) if !resigned => {
						resigned = true;
						continue;
					}
					Some(SigningReject::Fatal) => self.clear_signing().await,
					_ => {}
				}
			}

			return raw_or_blocked(status, body_bytes);
		}
	}
}

async fn session_user_id(auth: &AuthState) -> Result<String, GrindrError> {
	auth.session
		.read()
		.await
		.as_ref()
		.map(|s| s.profile_id.clone())
		.ok_or_else(|| GrindrError::Auth("not logged in".to_owned()))
}

const MAX_ERROR_BODY: usize = 1024;

/// A `403` whose body isn't JSON: a Cloudflare block page, a WAF custom
/// response, or an intercepting proxy answered instead of the API. Scoped to
/// `403` — an HTML `502` is a plain upstream failure, not a block.
pub(crate) fn is_edge_block(status: u16, body: &[u8]) -> bool {
	if status != 403 {
		return false;
	}
	let body = body.trim_ascii();
	!body.is_empty()
		&& serde_json::from_slice::<serde_json::Value>(body).is_err()
}

/// Cloudflare's "Just a moment..." browser challenge.
pub(crate) fn is_cloudflare_challenge(status: u16, body: &[u8]) -> bool {
	if (200..300).contains(&status) {
		return false;
	}
	let text = String::from_utf8_lossy(body);
	text.contains("_cf_chl_opt")
		|| text.contains("/cdn-cgi/challenge-platform/")
}

pub(crate) fn is_edge_interstitial(status: u16, body: &[u8]) -> bool {
	is_edge_block(status, body) || is_cloudflare_challenge(status, body)
}

fn raw_or_blocked(
	status: u16,
	body: Vec<u8>,
) -> Result<RawResponse, GrindrError> {
	if is_edge_interstitial(status, &body) {
		return Err(GrindrError::Blocked);
	}
	Ok(RawResponse { status, body })
}

pub(crate) fn parse_api_error(bytes: &[u8], http_status: u16) -> GrindrError {
	if is_edge_interstitial(http_status, bytes) {
		return GrindrError::Blocked;
	}

	let (code, message) = extract_api_error(bytes, http_status);

	if let Some(kind) = BanKind::from_code(code) {
		return GrindrError::Banned(ban_info(kind, code, message, bytes));
	}

	match http_status {
		401 => GrindrError::Unauthorized { code, message },
		429 => GrindrError::RateLimited,
		_ => GrindrError::Api { code, message },
	}
}

fn ban_info(
	kind: BanKind,
	code: i32,
	message: String,
	bytes: &[u8],
) -> BanInfo {
	let json = serde_json::from_slice::<serde_json::Value>(bytes).ok();
	let field = |key: &str| json.as_ref().and_then(|j| j.get(key));
	BanInfo {
		kind,
		code,
		message,
		reason: field("reason").and_then(|v| v.as_str()).map(str::to_owned),
		sub_reason: field("banSubReason")
			.and_then(|v| v.as_str())
			.map(str::to_owned),
		automated: field("isBanAutomated").and_then(|v| v.as_bool()),
	}
}

fn extract_api_error(bytes: &[u8], http_status: u16) -> (i32, String) {
	if let Ok(json) = serde_json::from_slice::<serde_json::Value>(bytes) {
		let code = json
			.get("code")
			.and_then(|c| c.as_i64())
			.map(|c| c as i32)
			.unwrap_or(http_status as i32);
		if let Some(msg) = json.get("message").and_then(|m| m.as_str()) {
			return (code, msg.to_owned());
		}
	}
	let text = String::from_utf8_lossy(bytes);
	let truncated = if text.len() > MAX_ERROR_BODY {
		let mut end = MAX_ERROR_BODY;
		while end > 0 && !text.is_char_boundary(end) {
			end -= 1;
		}
		format!("{}...", &text[..end])
	} else {
		text.into_owned()
	};
	let message = if truncated.is_empty() {
		"unknown error".to_owned()
	} else {
		truncated
	};
	(http_status as i32, message)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::auth::Session;
	use crate::GrindrClient;

	fn session_for(profile_id: &str) -> Session {
		let mut session = Session::from_auth_token("a@b.c", "auth-tok");
		session.profile_id = profile_id.to_owned();
		session
	}

	fn client_signed_in_as(profile_id: &str) -> GrindrClient {
		GrindrClient::new(DeviceInfo::generate(), Some(session_for(profile_id)))
			.unwrap()
	}

	async fn restored_key_user_id(client: &GrindrClient) -> Option<String> {
		client
			.signing_key_receiver()
			.borrow()
			.as_ref()
			.map(|k| k.user_id().to_owned())
	}

	#[tokio::test]
	async fn a_signing_key_from_another_account_is_refused() {
		let client = client_signed_in_as("42");
		let foreign = DeviceKey::generate("99".to_owned()).export();

		assert!(!client.restore_signing_key(foreign).await);
		assert!(
			restored_key_user_id(&client).await.is_none(),
			"a refused key must not reach the signing slot or the watch"
		);
	}

	#[tokio::test]
	async fn a_signing_key_is_restored_for_its_own_account() {
		let client = client_signed_in_as("42");
		let own = DeviceKey::generate("42".to_owned()).export();

		assert!(client.restore_signing_key(own).await);
		assert_eq!(restored_key_user_id(&client).await.as_deref(), Some("42"));
	}

	#[tokio::test]
	async fn a_token_resumed_session_accepts_a_key_before_its_first_refresh() {
		let client = client_signed_in_as("");
		let key = DeviceKey::generate("42".to_owned()).export();

		assert!(client.restore_signing_key(key).await);
	}

	#[test]
	fn accepts_absolute_paths() {
		assert!(validate_path("/v3/me/profile").is_ok());
		assert!(validate_path("/").is_ok());
	}

	#[test]
	fn rejects_host_repointing_paths() {
		for bad in ["@evil.com/x", "https://evil.com", "evil.com", ""] {
			assert!(
				matches!(
					validate_path(bad),
					Err(GrindrError::InvalidRequest(_))
				),
				"expected {bad:?} to be rejected"
			);
		}
	}

	#[test]
	fn from_response_parses_api_code_and_message() {
		let err = GrindrError::from_response(
			400,
			br#"{"code":4,"message":"Media not allowed"}"#,
		);
		assert!(
			matches!(err, GrindrError::Api { code: 4, ref message } if message == "Media not allowed"),
			"got {err:?}"
		);
	}

	#[test]
	fn from_response_maps_401_to_unauthorized() {
		let err = GrindrError::from_response(401, b"{}");
		assert!(matches!(err, GrindrError::Unauthorized { code: 401, .. }));
	}

	#[test]
	fn from_response_maps_429_to_rate_limited() {
		let err = GrindrError::from_response(429, b"{}");
		assert!(matches!(err, GrindrError::RateLimited));
	}

	#[test]
	fn from_response_classifies_ban_with_body_fields() {
		let err = GrindrError::from_response(
            403,
            br#"{"code":27,"message":"Profile is banned","banSubReason":"DRUG_SALES","isBanAutomated":true}"#,
        );
		let GrindrError::Banned(info) = err else {
			panic!("expected Banned, got {err:?}");
		};
		assert_eq!(info.kind, BanKind::Profile);
		assert_eq!(info.code, 27);
		assert_eq!(info.sub_reason.as_deref(), Some("DRUG_SALES"));
		assert_eq!(info.automated, Some(true));
	}

	#[test]
	fn from_response_maps_device_ban_code() {
		let err = GrindrError::from_response(
			403,
			br#"{"code":28,"message":"ACCOUNT_BANNED"}"#,
		);
		assert!(
			matches!(err, GrindrError::Banned(info) if info.kind == BanKind::Device)
		);
	}

	const CLOUDFLARE_BLOCK_PAGE: &[u8] = br#"<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head><body><h1>Sorry, you have been blocked</h1><p>You are unable to access grindr.mobi</p></body></html>"#;

	#[test]
	fn from_response_maps_cloudflare_block_to_blocked() {
		let err = GrindrError::from_response(403, CLOUDFLARE_BLOCK_PAGE);
		assert!(matches!(err, GrindrError::Blocked), "got {err:?}");
	}

	/// A WAF custom response: a block that carries none of the markers the
	/// classic interstitial does.
	const WAF_CUSTOM_BLOCK_PAGE: &[u8] =
		br#"<!DOCTYPE html><html><head><title>Access denied</title></head><body><h1>Request rejected</h1><p>Error code 1020</p></body></html>"#;

	#[test]
	fn edge_block_catches_any_non_json_403() {
		for page in [
			CLOUDFLARE_BLOCK_PAGE,
			CLOUDFLARE_CHALLENGE_PAGE,
			WAF_CUSTOM_BLOCK_PAGE,
			b"<title>Attention Required! | Cloudflare</title>",
			b"Forbidden",
		] {
			assert!(is_edge_block(403, page), "expected a block for {page:?}");
			assert!(matches!(
				GrindrError::from_response(403, page),
				GrindrError::Blocked
			));
		}
	}

	#[test]
	fn edge_block_leaves_api_answered_403s_alone() {
		for body in [
			&br#"{"code":28,"message":"ACCOUNT_BANNED"}"#[..],
			&br#"{"type":"urn:gr:err:unauthorized_action","status":403}"#[..],
			b"",
			b"   ",
		] {
			assert!(!is_edge_block(403, body), "unexpected block for {body:?}");
		}
	}

	#[test]
	fn edge_block_is_scoped_to_403() {
		for status in [400, 401, 429, 500, 502, 503] {
			assert!(
				!is_edge_block(status, WAF_CUSTOM_BLOCK_PAGE),
				"expected {status} to stay an upstream failure"
			);
		}
		assert!(!is_edge_block(200, WAF_CUSTOM_BLOCK_PAGE));
	}

	const CLOUDFLARE_CHALLENGE_PAGE: &[u8] = br#"<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title><meta http-equiv="refresh" content="360"></head><body><div class="main-wrapper" role="main"><noscript><span id="challenge-error-text">Enable JavaScript and cookies to continue</span></noscript></div><script nonce="UWPAt20YJwDjVxfZvpSJVX">(function(){window._cf_chl_opt = {cRay: 'a1fbdcf40dd6851a',cType: 'interactive',cZone: 'grindr.mobi'};var a = document.createElement('script');a.src = '/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=a1fbdcf40dd6851a';document.getElementsByTagName('head')[0].appendChild(a);}());</script></body></html>"#;

	#[test]
	fn from_response_maps_cloudflare_challenge_to_blocked() {
		let err = GrindrError::from_response(403, CLOUDFLARE_CHALLENGE_PAGE);
		assert!(matches!(err, GrindrError::Blocked), "got {err:?}");
	}

	#[test]
	fn challenge_is_detected_on_every_status_cloudflare_uses() {
		for status in [403, 429, 503] {
			assert!(
				is_cloudflare_challenge(status, CLOUDFLARE_CHALLENGE_PAGE),
				"expected {status} challenge to be detected"
			);
			assert!(matches!(
				GrindrError::from_response(status, CLOUDFLARE_CHALLENGE_PAGE),
				GrindrError::Blocked
			));
		}
	}

	#[test]
	fn either_challenge_marker_alone_is_conclusive() {
		assert!(is_cloudflare_challenge(
			403,
			b"<html><script>window._cf_chl_opt = {};</script></html>"
		));
		assert!(is_cloudflare_challenge(
			403,
			b"<html><script src='/cdn-cgi/challenge-platform/h/b/x'></script></html>"
		));
		// The title alone is localized, so it is deliberately not a marker
		assert!(!is_cloudflare_challenge(
			403,
			b"<html><head><title>Just a moment...</title></head></html>"
		));
	}

	#[test]
	fn challenge_check_skips_successful_responses() {
		assert!(!is_cloudflare_challenge(200, CLOUDFLARE_CHALLENGE_PAGE));
		assert!(!is_cloudflare_challenge(204, CLOUDFLARE_CHALLENGE_PAGE));
		assert!(is_cloudflare_challenge(403, CLOUDFLARE_CHALLENGE_PAGE));
	}

	#[test]
	fn challenge_check_leaves_grindr_error_bodies_alone() {
		for body in [
			&br#"{"code":28,"message":"ACCOUNT_BANNED"}"#[..],
			&br#"{"code":4,"message":"Media not allowed"}"#[..],
			b"Bad Gateway",
			b"",
		] {
			assert!(!is_cloudflare_challenge(403, body));
			assert!(!is_cloudflare_challenge(429, body));
		}
		assert!(matches!(
			GrindrError::from_response(429, b"{}"),
			GrindrError::RateLimited
		));
	}

	#[test]
	fn raw_or_blocked_rejects_every_interstitial() {
		for page in [
			CLOUDFLARE_BLOCK_PAGE,
			CLOUDFLARE_CHALLENGE_PAGE,
			WAF_CUSTOM_BLOCK_PAGE,
		] {
			let err = raw_or_blocked(403, page.to_vec()).unwrap_err();
			assert!(matches!(err, GrindrError::Blocked), "got {err:?}");
		}
		let ok = raw_or_blocked(403, b"{\"code\":4}".to_vec()).unwrap();
		assert_eq!(ok.status, 403);
	}

	#[test]
	fn cloudflare_check_precedes_ban_classification() {
		let err = GrindrError::from_response(
			403,
			br#"{"code":27,"message":"Profile is banned"}"#,
		);
		assert!(matches!(err, GrindrError::Banned(_)), "got {err:?}");
	}

	#[test]
	fn from_response_falls_back_to_raw_body() {
		let err = GrindrError::from_response(502, b"Bad Gateway");
		assert!(
			matches!(err, GrindrError::Api { code: 502, ref message } if message == "Bad Gateway"),
			"got {err:?}"
		);

		let err = GrindrError::from_response(500, b"");
		assert!(
			matches!(err, GrindrError::Api { code: 500, ref message } if message == "unknown error"),
			"got {err:?}"
		);
	}

	#[test]
	fn from_response_truncates_long_bodies_on_char_boundaries() {
		// 3-byte chars with MAX_ERROR_BODY % 3 == 1 put the cut mid-character,
		// so this only passes if the boundary backoff steps back a byte.
		let body = "€".repeat(400);
		let err = GrindrError::from_response(500, body.as_bytes());
		let GrindrError::Api { message, .. } = err else {
			panic!("expected Api error");
		};
		let prefix = message.strip_suffix("...").expect("truncation suffix");
		assert_eq!(prefix.len(), MAX_ERROR_BODY - 1);
		assert!(prefix.chars().all(|c| c == '€'));
	}
}
