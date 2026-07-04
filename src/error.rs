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

    /// A request argument was malformed, e.g. a path that does not begin with
    /// `/` and could therefore repoint the request to a different host.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
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
