use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use wreq::redirect::Policy;
use wreq::{Method, Url};

use crate::error::GrindrError;
use crate::headers::GrindrHeaders;
use crate::rest::InnerClient;

mod stream;
#[cfg(test)]
mod tests;

pub use stream::{MediaStream, StreamRequest};

pub(crate) const MEDIA_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_REDIRECTS: usize = 5;

/// Which of the app's two HTTP stacks a fetch imitates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MediaFetcher {
	/// The image loader, used for photos and chat images.
	#[default]
	ImageLoader,
	/// `android.media.MediaPlayer`, used for album video.
	MediaPlayer,
}

/// Argument of [`GrindrClient::fetch_media`](crate::GrindrClient::fetch_media).
#[derive(Debug, Clone, Copy)]
pub struct MediaRequest<'a> {
	/// Absolute `https` url on a Grindr CDN.
	pub url: &'a str,
	/// `Range` header value, forwarded verbatim.
	pub range: Option<&'a str>,
	/// Body size ceiling. A larger response fails instead of being buffered.
	pub max_bytes: usize,
	/// Which header set to send.
	pub fetcher: MediaFetcher,
}

/// Result of [`GrindrClient::fetch_media`](crate::GrindrClient::fetch_media).
#[derive(Debug, Clone)]
pub struct MediaResponse {
	/// HTTP status.
	pub status: u16,
	/// `Content-Type` header.
	pub content_type: Option<String>,
	/// `Content-Range` header.
	pub content_range: Option<String>,
	/// `Accept-Ranges` header.
	pub accept_ranges: Option<String>,
	/// Decompressed body. Size it from `len()`, not `Content-Length`.
	pub body: Bytes,
}

fn is_media_host(url: &Url) -> bool {
	if url.scheme() != "https" {
		return false;
	}
	url.host_str().is_some_and(|host| {
		host == "cdns.grindr.com" || host.ends_with(".cloudfront.net")
	})
}

#[cfg(not(test))]
fn is_allowed(url: &Url) -> bool {
	is_media_host(url)
}

#[cfg(test)]
fn is_allowed(url: &Url) -> bool {
	is_media_host(url)
		|| url.as_str().starts_with(crate::testserver::base_url())
}

fn header(response: &wreq::Response, name: &str) -> Option<String> {
	response
		.headers()
		.get(name)
		.and_then(|value| value.to_str().ok())
		.map(str::to_owned)
}

struct Target<'a> {
	url: &'a str,
	range: Option<&'a str>,
	fetcher: MediaFetcher,
}

impl InnerClient {
	async fn media_request(
		&self,
		target: Target<'_>,
	) -> Result<wreq::RequestBuilder, GrindrError> {
		let url = Url::parse(target.url).map_err(|e| {
			GrindrError::InvalidRequest(format!(
				"media url {:?}: {e}",
				target.url
			))
		})?;
		if !is_allowed(&url) {
			return Err(GrindrError::InvalidRequest(format!(
				"media url is not on a Grindr CDN: {:?}",
				target.url
			)));
		}

		let fp = self.fingerprint().await;
		let headers = match target.fetcher {
			MediaFetcher::ImageLoader => {
				GrindrHeaders::build_media(&fp.user_agent, target.range)?
			}
			MediaFetcher::MediaPlayer => {
				GrindrHeaders::build_platform_media(&fp.device, target.range)?
			}
		};

		let mut request = fp.http.request(Method::GET, url);
		for (name, value) in headers.items {
			request = request.header(name, value);
		}
		Ok(request.redirect(Policy::custom(|attempt| {
			if attempt.previous().len() > MAX_REDIRECTS
				|| !is_allowed(attempt.url())
			{
				attempt.stop()
			} else {
				attempt.follow()
			}
		})))
	}

	pub(crate) async fn fetch_media(
		&self,
		request: MediaRequest<'_>,
	) -> Result<MediaResponse, GrindrError> {
		let mut response = self
			.media_request(Target {
				url: request.url,
				range: request.range,
				fetcher: request.fetcher,
			})
			.await?
			.timeout(self.timeouts.media)
			.send()
			.await?;

		let status = response.status().as_u16();
		let content_type = header(&response, "content-type");
		let content_range = header(&response, "content-range");
		let accept_ranges = header(&response, "accept-ranges");

		if response
			.content_length()
			.is_some_and(|len| len > request.max_bytes as u64)
		{
			return Err(GrindrError::MediaTooLarge {
				max_bytes: request.max_bytes,
			});
		}

		let mut body = BytesMut::new();
		while let Some(chunk) = response.chunk().await? {
			if body.len() + chunk.len() > request.max_bytes {
				return Err(GrindrError::MediaTooLarge {
					max_bytes: request.max_bytes,
				});
			}
			body.put(chunk);
		}

		Ok(MediaResponse {
			status,
			content_type,
			content_range,
			accept_ranges,
			body: body.freeze(),
		})
	}
}
