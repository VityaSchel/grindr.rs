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
use crate::signing::{signing_reject, DeviceKey, DeviceSigningKey, SigningReject};

pub(crate) const BASE_URL: &str = "https://grindr.mobi";

/// Guards against a `path` that would change the effective host once
/// concatenated onto [`BASE_URL`].
///
/// `format!("{BASE_URL}{path}")` keeps the request on `grindr.mobi` only when
/// `path` starts with `/`.
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

    pub async fn restore_signing_key(&self, key: DeviceSigningKey) {
        if let Some(device_key) = DeviceKey::from_stored(&key) {
            *self.signing.lock().await = Some(device_key);
            let _ = self.signing_key_tx.send(Some(key));
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
        (local_now_ms() + self.server_offset_ms.load(Ordering::Relaxed)).max(0) as u64
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
        let headers = GrindrHeaders::build(&fp.device, &fp.user_agent, None, None)?;

        let mut req = Self::apply_headers(
            fp.http.request(method, format!("{BASE_URL}{path}")),
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

            let mut req = Self::apply_headers(
                fp.http.request(method.clone(), format!("{BASE_URL}{path}")),
                &headers.items,
            );
            match &body {
                Some(RequestBody::Json(b)) => req = req.json(b),
                Some(RequestBody::Raw {
                    content_type,
                    bytes,
                }) => req = req.header("content-type", content_type).body(bytes.clone()),
                None => {}
            }

            let resp = req.send().await?;
            self.note_server_date(resp.headers());
            let status = resp.status().as_u16();
            let body_bytes = resp.bytes().await?.to_vec();

            if status == 401 && !retried {
                retried = true;
                if let Some(stale) = session_id {
                    if crate::auth::refresh_after_unauthorized(self, auth, &stale).await {
                        continue;
                    }
                }
            }

            return Ok(RawResponse {
                status,
                body: body_bytes,
            });
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
            .request_authenticated(auth, method, path, body.map(RequestBody::Json))
            .await?;
        if !(200..300).contains(&resp.status) {
            return Err(parse_api_error(&resp.body, resp.status));
        }
        serde_json::from_slice(&resp.body).map_err(|e| GrindrError::Http(e.to_string()))
    }

    async fn ensure_device_key(&self, auth: &AuthState) -> Result<(), GrindrError> {
        let user_id = session_user_id(auth).await?;
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
                    .ok_or_else(|| GrindrError::Auth("device key not registered".to_owned()))?
                    .upload_headers(&android_id, &body, timestamp)
            };

            let headers = GrindrHeaders::build(
                &fp.device,
                &fp.user_agent,
                Some(&authorization),
                Some("[FREE]"),
            )?;
            let req = Self::apply_headers(
                fp.http.request(method.clone(), format!("{BASE_URL}{path}")),
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
                    if crate::auth::refresh_after_unauthorized(self, auth, &stale).await {
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

            return Ok(RawResponse {
                status,
                body: body_bytes,
            });
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

pub(crate) fn parse_api_error(bytes: &[u8], http_status: u16) -> GrindrError {
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

fn ban_info(kind: BanKind, code: i32, message: String, bytes: &[u8]) -> BanInfo {
    let json = serde_json::from_slice::<serde_json::Value>(bytes).ok();
    let field = |key: &str| json.as_ref().and_then(|j| j.get(key));
    BanInfo {
        kind,
        code,
        message,
        reason: field("reason").and_then(|v| v.as_str()).map(str::to_owned),
        sub_reason: field("banSubReason").and_then(|v| v.as_str()).map(str::to_owned),
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

    #[test]
    fn accepts_absolute_paths() {
        assert!(validate_path("/v3/me/profile").is_ok());
        assert!(validate_path("/").is_ok());
    }

    #[test]
    fn rejects_host_repointing_paths() {
        for bad in ["@evil.com/x", "https://evil.com", "evil.com", ""] {
            assert!(
                matches!(validate_path(bad), Err(GrindrError::InvalidRequest(_))),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn from_response_parses_api_code_and_message() {
        let err = GrindrError::from_response(400, br#"{"code":4,"message":"Media not allowed"}"#);
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
        let err = GrindrError::from_response(403, br#"{"code":28,"message":"ACCOUNT_BANNED"}"#);
        assert!(matches!(err, GrindrError::Banned(info) if info.kind == BanKind::Device));
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
