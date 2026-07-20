use thiserror::Error;

/// Errors returned by this crate.
///
/// The enum is `#[non_exhaustive]`; match with a wildcard arm so that future
/// variants do not break your build.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GrindrError {
    /// Transport-level failure (connection, TLS, malformed header value).
    #[error("HTTP error: {0}")]
    Http(String),

    /// Authentication problem that is not a server `401` (e.g. not logged in,
    /// JWT could not be decoded, or a third-party account is not registered).
    #[error("auth error: {0}")]
    Auth(String),

    /// The API returned a non-success status. `code` is the Grindr error code
    /// from the body, or the HTTP status if there isn't one.
    #[error("API error {code}: {message}")]
    Api {
        /// Grindr error code, or the HTTP status if absent.
        code: i32,
        /// Message from the response body.
        message: String,
    },

    /// The API returned `401`. If this happens during a token refresh, the
    /// session is cleared for you.
    #[error("unauthorized ({code}): {message}")]
    Unauthorized {
        /// Grindr error code, or `401` if absent.
        code: i32,
        /// Message from the response body.
        message: String,
    },

    /// Login or refresh was refused because the account, device, or network is
    /// banned.
    #[error("banned: {0}")]
    Banned(BanInfo),

    /// The API returned `429`.
    #[error("rate limited")]
    RateLimited,

    /// Cloudflare blocked the request before it reached Grindr: a `403` with
    /// the "Sorry, you have been blocked" page, usually because it didn't like
    /// the TLS/HTTP fingerprint. Retrying the same request won't get past it.
    #[error("blocked by Cloudflare")]
    Blocked,

    /// A request argument was malformed, e.g. a path that does not begin with
    /// `/` and could therefore repoint the request to a different host.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

/// What a [`GrindrError::Banned`] applies to, from the error code in the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BanKind {
    /// Code 27.
    Profile,
    /// Code 28. Often spurious: a bad security fingerprint blocks the request,
    /// not the account.
    Device,
    /// Code 31 (`SUSPICIOUS_NETWORK`).
    Network,
    /// Codes 35 and 36 (underage).
    Underage,
}

impl BanKind {
    pub(crate) fn from_code(code: i32) -> Option<Self> {
        Some(match code {
            27 => Self::Profile,
            28 => Self::Device,
            31 => Self::Network,
            35 | 36 => Self::Underage,
            _ => return None,
        })
    }
}

/// Details of a ban from the login/refresh response body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BanInfo {
    /// What the ban applies to.
    pub kind: BanKind,
    /// Grindr error code.
    pub code: i32,
    /// Message from the body.
    pub message: String,
    /// Body `reason`, if present.
    pub reason: Option<String>,
    /// Body `banSubReason`, if present.
    pub sub_reason: Option<String>,
    /// Body `isBanAutomated`, if present.
    pub automated: Option<bool>,
}

impl std::fmt::Display for BanInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} (code {}): {}", self.kind, self.code, self.message)
    }
}

impl GrindrError {
    /// Builds the error for a non-success [`RawResponse`](crate::RawResponse),
    /// the same way the crate's typed methods do: [`Api`](Self::Api) (or
    /// [`Unauthorized`](Self::Unauthorized) for a `401`) with the Grindr
    /// `{code, message}` parsed from the body, falling back to the HTTP status
    /// and the truncated raw body.
    pub fn from_response(status: u16, body: &[u8]) -> Self {
        crate::rest::parse_api_error(body, status)
    }
}

impl From<wreq::Error> for GrindrError {
    fn from(e: wreq::Error) -> Self {
        GrindrError::Http(e.to_string())
    }
}
