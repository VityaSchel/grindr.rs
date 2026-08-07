//! In-process stand-in for the Grindr API, so the client's whole request path
//! can be exercised without touching the network.
//!
//! One server is shared by every test. Tests stay independent by filtering
//! [`requests_from`] on their own generated device id.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, OnceLock};

/// Header `{"alg":"HS256","typ":"JWT"}` . payload `{"exp":9999999999}` . sig
const JWT: &str =
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig";

pub(crate) const REFRESHED_PROFILE_ID: &str = "42";

pub(crate) const CHALLENGE: &str = "chal-123";

#[derive(Clone)]
pub(crate) struct Recorded {
	pub method: String,
	pub path: String,
	pub headers: Vec<(String, String)>,
	pub body: String,
}

impl Recorded {
	pub fn header(&self, name: &str) -> Option<&str> {
		self.headers
			.iter()
			.find(|(n, _)| n == name)
			.map(|(_, v)| v.as_str())
	}
}

fn recordings() -> &'static Mutex<Vec<Recorded>> {
	static RECORDINGS: OnceLock<Mutex<Vec<Recorded>>> = OnceLock::new();
	RECORDINGS.get_or_init(Mutex::default)
}

/// Requests to one exact path, for callers with no `l-device-info` to filter on.
pub(crate) fn requests_to(path: &str) -> Vec<Recorded> {
	recordings()
		.lock()
		.unwrap()
		.iter()
		.filter(|r| r.path == path)
		.cloned()
		.collect()
}

/// Requests made by one device, in the order the server saw them.
pub(crate) fn requests_from(device_id: &str) -> Vec<Recorded> {
	recordings()
		.lock()
		.unwrap()
		.iter()
		.filter(|r| {
			r.header("l-device-info")
				.is_some_and(|v| v.starts_with(device_id))
		})
		.cloned()
		.collect()
}

pub(crate) fn base_url() -> &'static str {
	static BASE: OnceLock<String> = OnceLock::new();
	BASE.get_or_init(|| {
		let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
		let addr = listener.local_addr().expect("local addr");
		std::thread::spawn(move || {
			for stream in listener.incoming().flatten() {
				std::thread::spawn(move || serve(stream));
			}
		});
		format!("http://{addr}")
	})
}

fn serve(mut stream: TcpStream) {
	let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

	let mut request_line = String::new();
	if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
		return;
	}
	let mut parts = request_line.split_whitespace();
	let method = parts.next().unwrap_or_default().to_owned();
	let path = parts.next().unwrap_or_default().to_owned();

	let mut headers: Vec<(String, String)> = Vec::new();
	loop {
		let mut line = String::new();
		if reader.read_line(&mut line).unwrap_or(0) == 0 {
			break;
		}
		let line = line.trim_end();
		if line.is_empty() {
			break;
		}
		if let Some((name, value)) = line.split_once(':') {
			headers.push((
				name.trim().to_ascii_lowercase(),
				value.trim().to_owned(),
			));
		}
	}

	let length: usize = headers
		.iter()
		.find(|(n, _)| n == "content-length")
		.and_then(|(_, v)| v.parse().ok())
		.unwrap_or(0);
	let mut body = vec![0u8; length];
	if length > 0 && reader.read_exact(&mut body).is_err() {
		return;
	}

	let reply = match path.strip_prefix(MEDIA_PREFIX) {
		Some(rest) => media_reply(rest, &headers),
		None => {
			let (status, payload) = respond(&path);
			Reply {
				status,
				content_type: "application/json",
				extra: Vec::new(),
				body: payload.into_bytes(),
			}
		}
	};
	recordings().lock().unwrap().push(Recorded {
		method,
		path,
		headers,
		body: String::from_utf8_lossy(&body).into_owned(),
	});

	let mut head = format!(
		"HTTP/1.1 {}\r\ncontent-type: {}\r\ncontent-length: {}\r\n\
		 connection: close\r\n",
		reply.status,
		reply.content_type,
		reply.body.len()
	);
	for (name, value) in &reply.extra {
		head.push_str(&format!("{name}: {value}\r\n"));
	}
	head.push_str("\r\n");
	let _ = stream.write_all(head.as_bytes());
	let _ = stream.write_all(&reply.body);
	let _ = stream.flush();
}

struct Reply {
	status: &'static str,
	content_type: &'static str,
	extra: Vec<(&'static str, String)>,
	body: Vec<u8>,
}

/// `/media/<len>` serves that many bytes and honors `Range`;
/// `/media/redirect?to=<url>` answers a `302`.
pub(crate) const MEDIA_PREFIX: &str = "/media/";

fn media_reply(rest: &str, headers: &[(String, String)]) -> Reply {
	if let Some(query) = rest.strip_prefix("redirect?to=") {
		return Reply {
			status: "302 Found",
			content_type: "text/plain",
			extra: vec![("location", query.to_owned())],
			body: Vec::new(),
		};
	}

	let length: usize = rest
		.split('?')
		.next()
		.unwrap_or(rest)
		.parse()
		.unwrap_or_default();
	let full: Vec<u8> = (0..length).map(|i| i as u8).collect();

	let range = headers
		.iter()
		.find(|(name, _)| name == "range")
		.and_then(|(_, value)| value.strip_prefix("bytes="))
		.and_then(|value| value.split_once('-'));
	let Some((start, end)) = range else {
		return Reply {
			status: "200 OK",
			content_type: "image/jpeg",
			extra: vec![("accept-ranges", "bytes".to_owned())],
			body: full,
		};
	};

	let start: usize = start.parse().unwrap_or_default();
	let end: usize = end.parse().unwrap_or(length.saturating_sub(1));
	let slice =
		full[start.min(length)..=end.min(length.saturating_sub(1))].to_vec();
	Reply {
		status: "206 Partial Content",
		content_type: "video/mp4",
		extra: vec![
			("accept-ranges", "bytes".to_owned()),
			("content-range", format!("bytes {start}-{end}/{length}")),
		],
		body: slice,
	}
}

fn respond(path: &str) -> (&'static str, String) {
	match path.split('?').next().unwrap_or(path) {
		"/v8/sessions" => (
			"200 OK",
			format!(
				r#"{{"profileId":"{REFRESHED_PROFILE_ID}","sessionId":"{JWT}","authToken":"refreshed-tok"}}"#
			),
		),
		"/v1/verification/device-keys/challenge" => {
			("200 OK", format!(r#"{{"challenge":"{CHALLENGE}"}}"#))
		}
		"/v1/verification/device-keys" => ("200 OK", "{}".to_owned()),
		"/v5/media/upload" => (
			"200 OK",
			r#"{"hash":"media-hash","imageSizes":[]}"#.to_owned(),
		),
		"/v5/chat/media/upload" => (
			"200 OK",
			r#"{"mediaId":7,"url":"https://cdn/x.jpg","mediaHash":"h"}"#
				.to_owned(),
		),
		"/v3/bootstrap" => ("200 OK", r#"{"ok":true}"#.to_owned()),
		_ => (
			"404 Not Found",
			r#"{"code":404,"message":"no route"}"#.to_owned(),
		),
	}
}
