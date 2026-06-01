use std::sync::Arc;

use serde::{de::DeserializeOwned, Serialize};
use wreq::{Client, Method, RequestBuilder};

use crate::auth::AuthState;
use crate::device::DeviceInfo;
use crate::error::GrindrError;
use crate::headers::GrindrHeaders;

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

pub(crate) struct InnerClient {
    pub fingerprint: tokio::sync::RwLock<Arc<Fingerprint>>,
}

impl InnerClient {
    pub async fn fingerprint(&self) -> Arc<Fingerprint> {
        Arc::clone(&*self.fingerprint.read().await)
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
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let bytes = resp.bytes().await.unwrap_or_default();
            return Err(parse_api_error(&bytes, status));
        }
        resp.json::<TResp>().await.map_err(Into::into)
    }

    pub async fn request_authenticated_raw(
        &self,
        auth: &AuthState,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<RawResponse, GrindrError> {
        validate_path(path)?;
        let authorization = crate::auth::authorization_header(self, auth)
            .await
            .ok_or_else(|| GrindrError::Auth("not logged in".to_owned()))?;

        let fp = self.fingerprint().await;
        let headers = GrindrHeaders::build(
            &fp.device,
            &fp.user_agent,
            Some(&authorization),
            Some("[FREE]"),
        )?;

        let mut req = Self::apply_headers(
            fp.http.request(method, format!("{BASE_URL}{path}")),
            &headers.items,
        );
        if let Some(b) = body {
            req = req.json(&b);
        }

        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let body_bytes = resp.bytes().await?.to_vec();
        Ok(RawResponse {
            status,
            body: body_bytes,
        })
    }
}

const MAX_ERROR_BODY: usize = 1024;

pub(crate) fn parse_api_error(bytes: &[u8], http_status: u16) -> GrindrError {
    let (code, message) = extract_api_error(bytes, http_status);
    if http_status == 401 {
        GrindrError::Unauthorized { code, message }
    } else {
        GrindrError::Api { code, message }
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
}
