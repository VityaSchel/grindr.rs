use std::fmt;

use thiserror::Error;

/// Who answered instead of the API, for a [`GrindrError::Blocked`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
	/// A Cloudflare block page or "Just a moment..." browser challenge.
	Cloudflare,
	/// An interstitial block.
	Edge,
}

impl fmt::Display for BlockKind {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			BlockKind::Cloudflare => write!(f, "Cloudflare"),
			BlockKind::Edge => write!(f, "network edge"),
		}
	}
}

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

	/// An edge in front of Grindr answered instead of the API: a Cloudflare
	/// block page, a "Just a moment..." browser challenge, a WAF custom
	/// response, or an intercepting proxy — usually because Cloudflare didn't
	/// like the TLS/HTTP fingerprint. Recognized by shape: a `403` whose body
	/// isn't JSON, or a challenge marker on any non-success status.
	///
	/// Often transient: retrying the same request sometimes gets through, so
	/// this is worth a backoff-and-retry rather than treating it as terminal.
	/// If it persists, rotate the device identity with
	/// [`rotate_device`](crate::GrindrClient::rotate_device).
	#[error("blocked before reaching the API ({0})")]
	Blocked(BlockKind),

	/// A request argument was malformed, e.g. a path that does not begin with
	/// `/` and could therefore repoint the request to a different host.
	#[error("invalid request: {0}")]
	InvalidRequest(String),

	/// Signed out while this request was in flight
	#[error("session was cleared while the request was in flight")]
	SessionCleared,

	/// A media body is larger than `MediaRequest::max_bytes` and was not buffered.
	#[error("media body exceeds {max_bytes} bytes")]
	MediaTooLarge {
		/// The ceiling the request set.
		max_bytes: usize,
	},
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
	/// and a capped body excerpt — markup is summarized, never quoted.
	pub fn from_response(status: u16, body: &[u8]) -> Self {
		crate::rest::parse_api_error(body, status)
	}
}

impl From<wreq::Error> for GrindrError {
	fn from(e: wreq::Error) -> Self {
		GrindrError::Http(e.to_string())
	}
}
