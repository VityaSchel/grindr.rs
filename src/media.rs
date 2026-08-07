use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use wreq::redirect::Policy;
use wreq::{Method, Url};

use crate::error::GrindrError;
use crate::headers::GrindrHeaders;
use crate::rest::InnerClient;

const MEDIA_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_REDIRECTS: usize = 5;

/// Argument of [`GrindrClient::fetch_media`](crate::GrindrClient::fetch_media).
#[derive(Debug, Clone, Copy)]
pub struct MediaRequest<'a> {
	/// Absolute `https` url on a Grindr CDN.
	pub url: &'a str,
	/// `Range` header value, forwarded verbatim.
	pub range: Option<&'a str>,
	/// Body size ceiling. A larger response fails instead of being buffered.
	pub max_bytes: usize,
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

impl InnerClient {
	pub(crate) async fn fetch_media(
		&self,
		request: MediaRequest<'_>,
	) -> Result<MediaResponse, GrindrError> {
		let url = Url::parse(request.url).map_err(|e| {
			GrindrError::InvalidRequest(format!(
				"media url {:?}: {e}",
				request.url
			))
		})?;
		if !is_allowed(&url) {
			return Err(GrindrError::InvalidRequest(format!(
				"media url is not on a Grindr CDN: {:?}",
				request.url
			)));
		}

		let fp = self.fingerprint().await;
		let headers =
			GrindrHeaders::build_media(&fp.user_agent, request.range)?;

		let mut req = fp.http.request(Method::GET, url);
		for (name, value) in headers.items {
			req = req.header(name, value);
		}
		let mut response = req
			.timeout(MEDIA_TIMEOUT)
			.redirect(Policy::custom(|attempt| {
				if attempt.previous().len() > MAX_REDIRECTS
					|| !is_allowed(attempt.url())
				{
					attempt.stop()
				} else {
					attempt.follow()
				}
			}))
			.send()
			.await?;

		let status = response.status().as_u16();
		let content_type = header(&response, "content-type");
		let content_range = header(&response, "content-range");
		let accept_ranges = header(&response, "accept-ranges");

		let mut body = BytesMut::new();
		while let Some(chunk) = response.chunk().await? {
			if body.len() + chunk.len() > request.max_bytes {
				return Err(GrindrError::Http(format!(
					"media body exceeds {} bytes",
					request.max_bytes
				)));
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::auth::{Session, SessionKind};
	use crate::device::DeviceInfo;
	use crate::testserver::{self, MEDIA_PREFIX};
	use crate::GrindrClient;

	fn parsed(url: &str) -> Url {
		Url::parse(url).unwrap()
	}

	fn signed_in_client() -> GrindrClient {
		let session = Session {
			email: "user@example.com".to_owned(),
			expires_at: u64::MAX,
			profile_id: "1".to_owned(),
			session_id: "sid".to_owned(),
			auth_token: "atok".to_owned(),
			kind: SessionKind::Email,
			third_party_user_id: None,
			restriction: None,
		};
		GrindrClient::new(DeviceInfo::generate(), Some(session)).unwrap()
	}

	fn media_url(length: usize) -> String {
		format!("{}{MEDIA_PREFIX}{length}", testserver::base_url())
	}

	fn request(url: &str) -> MediaRequest<'_> {
		MediaRequest {
			url,
			range: None,
			max_bytes: 1024 * 1024,
		}
	}

	fn header_names(headers: &GrindrHeaders) -> Vec<&str> {
		headers
			.items
			.iter()
			.map(|(name, _)| name.as_str())
			.collect()
	}

	fn header_value<'a>(
		headers: &'a GrindrHeaders,
		name: &str,
	) -> Option<&'a str> {
		headers
			.items
			.iter()
			.find(|(header, _)| header.as_str() == name)
			.and_then(|(_, value)| value.to_str().ok())
	}

	#[test]
	fn media_headers_are_an_image_accept_the_app_ua_and_gzip() {
		let headers = GrindrHeaders::build_media("grindr3/ua", None).unwrap();

		assert_eq!(
			header_names(&headers),
			&["accept", "user-agent", "accept-encoding"]
		);
		assert_eq!(
			header_value(&headers, "accept"),
			Some("image/webp,image/*;q=0.8")
		);
		assert_eq!(header_value(&headers, "user-agent"), Some("grindr3/ua"));
	}

	#[test]
	fn a_ranged_media_request_swaps_gzip_for_the_range() {
		let headers =
			GrindrHeaders::build_media("grindr3/ua", Some("bytes=10-19"))
				.unwrap();

		assert_eq!(header_names(&headers), &["accept", "user-agent", "range"]);
		assert_eq!(header_value(&headers, "range"), Some("bytes=10-19"));
	}

	#[test]
	fn media_headers_carry_none_of_the_api_headers() {
		let device = DeviceInfo::generate();
		let api = GrindrHeaders::build(
			&device,
			"ua",
			Some("Grindr3 tok"),
			Some("[FREE]"),
		)
		.unwrap();
		let media = GrindrHeaders::build_media("ua", None).unwrap();

		for name in header_names(&api) {
			if matches!(name, "accept" | "user-agent" | "accept-encoding") {
				continue;
			}
			assert!(
				!header_names(&media).contains(&name),
				"{name} must not reach a CDN"
			);
		}
		assert_eq!(header_value(&api, "accept"), Some("application/json"));
	}

	#[test]
	fn admits_the_two_cdn_families() {
		assert!(is_media_host(&parsed(
			"https://cdns.grindr.com/images/thumb/320x320/abc"
		)));
		assert!(is_media_host(&parsed(
			"https://d3lyqctnm3b6pb.cloudfront.net/x.jpg?Signature=y"
		)));
		assert!(
			is_media_host(&parsed("https://d2wxe7lth7kp8g.cloudfront.net/x")),
			"the signed-media distribution rotates, so it is matched by suffix"
		);
	}

	#[test]
	fn refuses_everything_else() {
		for url in [
			"http://cdns.grindr.com/x",
			"https://cdns.grindr.com.evil.test/x",
			"https://evilcdns.grindr.com/x",
			"https://evilcloudfront.net/x",
			"https://cloudfront.net.evil.test/x",
			"https://d123.cloudfront.net.evil.test/x",
			"https://grindr.mobi/v3/me/profile",
			"https://tile.openstreetmap.org/1/2/3.png",
			"file:///etc/passwd",
		] {
			assert!(!is_media_host(&parsed(url)), "{url} must be refused");
		}
	}

	#[test]
	fn the_bare_cdn_apex_is_not_a_distribution() {
		assert!(!is_media_host(&parsed("https://cloudfront.net/x")));
	}

	#[tokio::test]
	async fn a_media_fetch_carries_no_credentials_even_with_a_session() {
		let url = media_url(11);

		let response =
			signed_in_client().fetch_media(request(&url)).await.unwrap();

		assert_eq!(response.status, 200);
		assert_eq!(response.content_type.as_deref(), Some("image/jpeg"));
		assert_eq!(response.body.len(), 11);

		let recorded = testserver::requests_to(&format!("{MEDIA_PREFIX}11"));
		let fetch = recorded.first().expect("the media request was made");
		assert_eq!(fetch.method, "GET");
		for name in [
			"authorization",
			"l-device-info",
			"l-grindr-roles",
			"l-time-zone",
			"l-locale",
			"accept-language",
			"cookie",
		] {
			assert_eq!(fetch.header(name), None, "{name} must not reach a CDN");
		}
		assert_eq!(fetch.header("accept"), Some("image/webp,image/*;q=0.8"));
		assert_eq!(fetch.header("accept-encoding"), Some("gzip"));
	}

	#[tokio::test]
	async fn a_range_is_forwarded_and_its_206_comes_back_whole() {
		let url = media_url(64);

		let response = signed_in_client()
			.fetch_media(MediaRequest {
				range: Some("bytes=10-19"),
				..request(&url)
			})
			.await
			.unwrap();

		assert_eq!(response.status, 206);
		assert_eq!(response.content_range.as_deref(), Some("bytes 10-19/64"));
		assert_eq!(response.accept_ranges.as_deref(), Some("bytes"));
		assert_eq!(response.body.as_ref(), &(10u8..=19).collect::<Vec<u8>>());

		let recorded = testserver::requests_to(&format!("{MEDIA_PREFIX}64"));
		let fetch = recorded.first().expect("the media request was made");
		assert_eq!(fetch.header("range"), Some("bytes=10-19"));
		assert_eq!(fetch.header("accept-encoding"), None);
	}

	#[tokio::test]
	async fn a_body_over_the_ceiling_fails_instead_of_buffering() {
		let url = media_url(4096);

		let err = signed_in_client()
			.fetch_media(MediaRequest {
				max_bytes: 512,
				..request(&url)
			})
			.await
			.unwrap_err();

		assert!(matches!(err, GrindrError::Http(_)), "got {err:?}");
	}

	#[tokio::test]
	async fn a_redirect_is_followed_only_while_it_stays_on_a_cdn() {
		let allowed = format!(
			"{}{MEDIA_PREFIX}redirect?to={}",
			testserver::base_url(),
			media_url(8)
		);
		let response = signed_in_client()
			.fetch_media(request(&allowed))
			.await
			.unwrap();
		assert_eq!(response.status, 200);
		assert_eq!(response.body.len(), 8);

		let elsewhere = format!(
			"{}{MEDIA_PREFIX}redirect?to=https://evil.test/x.jpg",
			testserver::base_url()
		);
		let response = signed_in_client()
			.fetch_media(request(&elsewhere))
			.await
			.unwrap();
		assert_eq!(
			response.status, 302,
			"the redirect must be handed back, not followed"
		);
		assert!(response.body.is_empty());
	}

	#[tokio::test]
	async fn a_url_off_the_cdns_never_reaches_the_network() {
		for url in [
			"https://evil.test/x.jpg",
			"http://cdns.grindr.com/x.jpg",
			"https://grindr.mobi/v3/me/profile",
			"not a url",
		] {
			let err = signed_in_client()
				.fetch_media(request(url))
				.await
				.unwrap_err();
			assert!(
				matches!(err, GrindrError::InvalidRequest(_)),
				"{url} gave {err:?}"
			);
		}
	}
}
