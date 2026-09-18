use std::time::{Duration, Instant};

use super::tests::{counting, drain, dripping, request};
use super::UNANSWERED;
use crate::client::Timeouts;
use crate::media::tests::client_with;
use crate::testserver::{self, HOLD_BEFORE_CLOSING, STALLED_PATH};
use crate::GrindrError;

#[tokio::test]
async fn the_header_deadline_fires_when_the_headers_stall() {
	let deadline = Duration::from_millis(300);
	let client = client_with(Timeouts {
		media: deadline,
		..Timeouts::default()
	});
	let url = format!("{}{STALLED_PATH}", testserver::base_url());
	let started = Instant::now();

	let err = client.stream_media(request(&url)).await.unwrap_err();

	assert!(
		matches!(&err, GrindrError::Http(message) if message == UNANSWERED),
		"got {err:?}"
	);
	assert!(started.elapsed() >= deadline);
	assert!(started.elapsed() < HOLD_BEFORE_CLOSING);
}

#[tokio::test]
async fn a_mid_body_stall_longer_than_the_read_timeout_errors() {
	let client = client_with(Timeouts {
		read: Duration::from_millis(200),
		..Timeouts::default()
	});
	let pause = Duration::from_millis(800);
	let url = dripping(40, pause);

	let mut stream = client.stream_media(request(&url)).await.unwrap();
	let first = stream.chunk().await.unwrap().expect("a first chunk");
	let stalled = Instant::now();
	let err = stream.chunk().await.unwrap_err();

	assert!(!first.is_empty());
	assert!(
		matches!(&err, GrindrError::Http(message) if message.contains("timed out")),
		"got {err:?}"
	);
	assert!(
		stalled.elapsed() < pause,
		"the server resumed before the error"
	);
}

#[tokio::test]
async fn a_slow_but_alive_body_outlives_the_read_timeout() {
	let read = Duration::from_millis(500);
	let client = client_with(Timeouts {
		read,
		..Timeouts::default()
	});
	let url = dripping(72, Duration::from_millis(100));
	let started = Instant::now();

	let mut stream = client.stream_media(request(&url)).await.unwrap();
	let body = drain(&mut stream)
		.await
		.expect("a moving body never times out");

	assert_eq!(body, counting(72));
	assert!(
		started.elapsed() > read,
		"the body ended within the read timeout"
	);
}
