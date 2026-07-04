# grindr.rs

<img src="./contrib/logo.svg" align="right" />

Unofficial async Rust client for the Grindr API, powering [Open Grind](https://opengrind.org) client.

> [!Important]
> This is an **unofficial library**, not affiliated with or endorsed by Grindr.
> It is provided for research and interoperability.
> Automating access may violate Grindr's Terms of Service. You are responsible for how you use it.

## Features

- Async, clonable client built on [`tokio`](https://tokio.rs) and [`wreq`](https://crates.io/crates/wreq)
- Fingerprint matching Grindr's official Android APK's network lib: TLS (JA3/JA4), HTTP/2 (frames, pseudoheaders), required headers
- Session handling — tokens are refreshed automatically
- Background WebSocket with automatic reconnect and states callback
- Device identities spoofing — store DeviceInfo along session token to decrease the chance of triggering Cloudflare block pages

This crate is a transport: it handles authentication, fingerprinting, connection, but does not ship typed models for every endpoint. You choose the path and deserialize the body yourself.

## Installation

```toml
[dependencies]
grindr = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "sync"] }
serde_json = "1"
```

### Versioning

This crate's version is `<lib version>+<Grindr APK version>`. For example, `0.1.0+26.9.1.163471` is library `0.1.0` targeting APK `26.9.1.163471`. The `+<apk>` suffix is [SemVer build metadata](https://semver.org/#spec-item-10): informational only, and ignored by Cargo when resolving versions. Retargeting the APK is treated as a breaking change, so it bumps the minor, requiring manual upgrade. The targeted version is also exposed as `grindr::APP_VERSION`.

## Quick start

```rust
use grindr::{DeviceInfo, GrindrClient, Method};

#[tokio::main]
async fn main() -> Result<(), grindr::GrindrError> {
    let device = DeviceInfo::generate();
    let client = GrindrClient::new(device, None)?;

    let me = client.login("m@example.com", "yourpassword").await?;
    println!("logged in as profile {}", me.profile_id);

    // URL must start with `/`
    // Session token is added automatically
    // API reference: <https://opengrind.org/grindr-api/>
    // Dev tool: <https://git.opengrind.org/open-grind/grindr-api-dev-tool>
    let resp = client
        .request_authenticated_raw(Method::GET, "/v3/me/profile", None)
        .await?;
    println!("status {}", resp.status);
    let profile: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    println!("{profile:#?}");

    Ok(())
}
```

## Sessions & device identity

```rust
// Load `device` and `saved` from disk
let client = GrindrClient::new(device, saved)?;

// Persist session whenever it changes
let mut sessions = client.session_receiver();
tokio::spawn(async move {
    while sessions.changed().await.is_ok() {
        // Option<Session>
        let current = sessions.borrow().clone();
        // Serialize to disk and store securely
        save_session(&current);
    }
});
```

## WebSocket

The realtime WebSocket is opt-in, REST works without it. Call `client.connect().await` once to start the shared background socket, which then connects as soon as a session exists. Subscribe to events and send commands:

```rust
use grindr::WsCommand;

// Subscribe to events
let mut events = client.ws_receiver();
tokio::spawn(async move {
    while let Ok(event) = events.recv().await {
        println!("event {}: {}", event.event_type, event.payload);
    }
});

// Send a command
client
    .ws_sender()
    .send(WsCommand {
        r#type: "chat.v1.typing".to_owned(),
        ref_id: "1".to_owned(),
        payload: serde_json::json!({ "conversationId": "abc" }),
    })
    .await
    .ok();
```

The background task is never started for you. `client.connect().await` is the only thing that starts it, and it's idempotent and shared across clones. Until you call it, no socket is opened and `ws_receiver()` produces nothing. Watch the connection with `GrindrClient::connection_state`, and observe failed background token refreshes via `GrindrClient::auth_event_receiver`.

## API reference

Full generated docs: <https://docs.rs/grindr>.

### `GrindrClient`

| Method                                                                 | Description                                                                    |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `new(device, session) -> Result<Self>`                                 | Create a client, optionally resuming a stored `Session`                        |
| `login(email, password) -> Result<LoginResult>`                        | Email + password login                                                         |
| `google_sign_in(access_token) -> Result<LoginResult>`                  | Google OAuth sign-in                                                           |
| `refresh_token() -> Result<LoginResult>`                               | Force token refresh                                                            |
| `logout()`                                                             | Clear the session and disconnect the websocket                                 |
| `request_authenticated_raw(method, path, body) -> Result<RawResponse>` | Authenticated API call returning the raw status + body                         |
| `request_authenticated_bytes(method, path, content_type, body) -> Result<RawResponse>` | Like `request_authenticated_raw`, but with a raw binary body (e.g. media uploads) |
| `rotate_device(device) -> Result<DeviceInfo>`                          | Set the device identity in place, keeping the session; returns old device info |
| `current_device() -> DeviceInfo`                                       | Get the device identity currently in use                                       |
| `recaptcha_first_party_enabled() -> Result<bool>`                      | Check whether first-party reCAPTCHA is enabled                                 |
| `session_receiver() -> watch::Receiver<Option<Session>>`               | Watch the current session (updates on login/refresh/logout)                    |
| `connection_state() -> watch::Receiver<WsConnectionState>`             | Watch the websocket connection state                                           |
| `ws_receiver() -> broadcast::Receiver<WsEvent>`                        | Subscribe to websocket events                                                  |
| `ws_sender() -> mpsc::Sender<WsCommand>`                               | Get websocket sender for commands                                              |
| `connect()`                                                            | Opt in to the realtime websocket and start the shared background task          |
| `auth_event_receiver() -> broadcast::Receiver<AuthEvent>`              | Subscribe to background token refresh failures                                 |

### Types

- `DeviceInfo` — device identity, build with `DeviceInfo::generate()` or `DeviceInfo::default()`
- `Session` — session token and other secrets
- `SessionKind` — `Email` or `Google`
- `LoginResult` — `{ profile_id }`, returned by the auth methods
- `RawResponse` — `{ status: u16, body: Vec<u8> }`
- `WsCommand` — websocket command `{ type, ref_id, payload }`
- `WsEvent` — websocket event `{ event_type, payload }`
- `WsConnectionState` — `Connected` / `Disconnected`
- `AuthEvent` — `{ message, unauthorized }` from background refreshes
- `GrindrError` — the crate error type (`Http`, `Auth`, `Api`, `Unauthorized`, `InvalidRequest`); `GrindrError::from_response(status, body)` maps a non-success `RawResponse` the same way the typed methods do
- `Method` — re-exported `wreq::Method` for `request_authenticated_raw`
- `Bytes` — re-exported `bytes::Bytes` for `request_authenticated_bytes`

### Low-level helpers

For building your own `wreq::Client` with an identical fingerprint:

- `probe_emulation() -> wreq::EmulationProvider` — tls/http2 emulation profile
- `build_user_agent(device, tier) -> String` — `User-Agent` value
- `build_device_info_header(device) -> String` — `L-Device-Info` value
- `GrindrHeaders::build(device, ua, authorization, roles)` — full and correctly ordered headers list

## Examples

Observe TLS session resumption:

```sh
cargo run --example warm_probe
```

Assert the emulated fingerprint:

```sh
cargo run --example fingerprint_check
```

The `fingerprint_check` example verifies JA3/JA4, the Akamai http/2 fingerprint and header ordering against [tls.peet.ws](https://tls.peet.ws). Pass `--all` flag to check both http/2 and http/1.1 (websocket) clients.

## Minimum supported Rust version

Rust **1.80**.

## License

[MIT](./LICENSE)
