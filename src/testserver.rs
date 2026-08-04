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

	let (status, payload) = respond(&path);
	recordings().lock().unwrap().push(Recorded {
		method,
		path,
		headers,
		body: String::from_utf8_lossy(&body).into_owned(),
	});

	let _ = write!(
		stream,
		"HTTP/1.1 {status}\r\ncontent-type: application/json\r\n\
		 content-length: {}\r\nconnection: close\r\n\r\n{payload}",
		payload.len()
	);
	let _ = stream.flush();
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
		"/v3/bootstrap" => ("200 OK", r#"{"ok":true}"#.to_owned()),
		_ => (
			"404 Not Found",
			r#"{"code":404,"message":"no route"}"#.to_owned(),
		),
	}
}
