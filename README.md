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
- Device identities spoofing — store DeviceInfo along session token to decrease the chance of triggering Cloudflare block and challenge pages

This crate is a transport: it handles authentication, fingerprinting, connection, but does not ship typed models for every endpoint. You choose the path and deserialize the body yourself.

## Installation

```toml
[dependencies]
grindr = "0.10"
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
        r#type: "chat.v1.typing_status".to_owned(),
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

All methods are `async` except `new`, `signing_key_receiver`, `session_receiver`, `auth_event_receiver`, `connection_state`, `ws_receiver` and `ws_sender`.

#### Setup and device identity

| Method                                            | Description                                                                            |
| ------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `new(device, session) -> Result<Self>`            | Create a client, optionally resuming a stored `Session`. Sync, needs no runtime        |
| `current_device() -> DeviceInfo`                  | The device identity currently in use                                                   |
| `rotate_device(device) -> Result<DeviceInfo>`     | Swap the device identity and transport, keeping the session; returns the old device    |
| `sign_out_rotating(device) -> Result<DeviceInfo>` | `logout()` then `rotate_device()`, so the next login can't be correlated with this one |

#### Authentication

| Method                                                                      | Description                                                     |
| --------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `login(email, password) -> Result<LoginResult>`                             | Email + password login                                          |
| `login_with_geohash(email, password, geohash) -> Result<LoginResult>`       | Like `login`, tagging the sign-in with an approximate location  |
| `google_sign_in(access_token) -> Result<LoginResult>`                       | Google OAuth sign-in                                            |
| `google_sign_in_with_geohash(access_token, geohash) -> Result<LoginResult>` | Like `google_sign_in`, with a geohash                           |
| `refresh_token() -> Result<LoginResult>`                                    | Force a token refresh (happens automatically otherwise)         |
| `refresh_token_with_geohash(geohash) -> Result<LoginResult>`                | Like `refresh_token`, with a geohash                            |
| `logout()`                                                                  | Clear the session and signing key, and close the websocket      |
| `recaptcha_first_party_enabled() -> Result<bool>`                           | Whether the server has first-party reCAPTCHA on. No auth needed |

Only the initial request carries a `geohash`; automatic background refreshes never do.

#### Requests

| Method                                                                                 | Description                                                             |
| -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `request_authenticated_raw(method, path, body) -> Result<RawResponse>`                 | Authenticated JSON call returning the raw status + body                 |
| `request_authenticated_bytes(method, path, content_type, body) -> Result<RawResponse>` | Same, with a raw binary body                                            |
| `request_signed_bytes(method, path, content_type, body) -> Result<RawResponse>`        | Same, plus device-key signing — for upload paths that require it        |
| `request_no_auth_raw(method, path, body) -> Result<RawResponse>`                       | Unauthenticated call on the same transport — sign-in, bootstrap, probes |

`path` must start with `/`, otherwise you get `GrindrError::InvalidRequest`.

`requires_device_signature(path)` tells you which paths need `request_signed_bytes` rather than `request_authenticated_bytes`.

#### Media uploads

Signed uploads register an ephemeral P-256 device key on first use. Persist it to avoid re-registering.

| Method                                                                                                    | Description                                                                          |
| --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `upload_profile_image(jpeg, thumb_coords, taken_on_grindr) -> Result<UploadProfileImageResponse>`         | Signed `POST /v5/media/upload`                                                       |
| `upload_chat_media(bytes, content_type, length, looping, taken_on_grindr) -> Result<MediaUploadResponse>` | Signed `POST /v6/chat/media/upload`                                                  |
| `upload_chat_media_unsigned(bytes, content_type) -> Result<MediaUploadResponse>`                          | Unsigned `POST /v5/chat/media/upload`, for media the user did not capture in the app |
| `restore_signing_key(key) -> bool`                                                                        | Restore a persisted `DeviceSigningKey`; refused if it belongs to another account     |
| `signing_key_receiver() -> watch::Receiver<Option<DeviceSigningKey>>`                                     | Watch the signing key so you can save it                                             |

#### Realtime websocket

| Method                                                     | Description                                                  |
| ---------------------------------------------------------- | ------------------------------------------------------------ |
| `connect()`                                                | Opt in to the websocket and start the shared background task |
| `ws_receiver() -> broadcast::Receiver<WsEvent>`            | Subscribe to websocket events                                |
| `ws_sender() -> mpsc::Sender<WsCommand>`                   | Sender for websocket commands                                |
| `connection_state() -> watch::Receiver<WsConnectionState>` | Watch the websocket connection state                         |

#### Watching session state

| Method                                                    | Description                                                 |
| --------------------------------------------------------- | ----------------------------------------------------------- |
| `session_receiver() -> watch::Receiver<Option<Session>>`  | Watch the current session (updates on login/refresh/logout) |
| `auth_event_receiver() -> broadcast::Receiver<AuthEvent>` | Subscribe to background token refresh failures              |

### Types

Everything under **Identity and session** and **Requests and errors** — except `RawResponse` — is `#[non_exhaustive]`, so match those enums with a wildcard arm. The **Uploads** and **Websocket** types are ordinary.

**Identity and session**

- `DeviceInfo` — device identity, build with `DeviceInfo::generate()` or `DeviceInfo::default()`
- `Session` — session token and other secrets. `Debug` redacts the credentials. `Session::from_auth_token(email, auth_token)` resumes an email account from a stored long-lived token
- `SessionKind` — `Email` or `Google`
- `LoginResult` — `{ profile_id, restriction }`, returned by the auth methods
- `Restriction` — account restriction from the session JWT, the session is still valid: `AgeVerification { region, reason }` / `TimedBan(BanDetails)` / `TrustVendorRejected` / `Other(String)`
- `VerificationRegion` — `Uk` / `Br` / `Au` / `Other`
- `BanDetails` — `{ expiry_time, reason, sub_reason, is_automated }`

**Requests and errors**

Every request carries its own timeout — 35 s, matching the app's okhttp `callTimeout`, and 120 s when the body is bytes, so an upload is not cut off by what is meant to be a timeout. There is no need to wrap calls in one of your own.

- `RawResponse` — `{ status: u16, body: Vec<u8> }`
- `GrindrError` — the crate error type (`Http`, `Auth`, `Api`, `Unauthorized`, `Banned`, `RateLimited`, `Blocked(BlockKind)`, `InvalidRequest`, `SessionCleared`); `GrindrError::from_response(status, body)` maps a non-success `RawResponse` the same way the typed methods do
- `BlockKind` — `Cloudflare` for Cloudflare block page or "Just a moment..." challenge, `Edge` for anything else
- `BanInfo` — `{ kind, code, message, reason, sub_reason, automated }`
- `BanKind` — `Profile` / `Device` / `Network` / `Underage`
- `AuthEvent` — `LoggedOut` / `Banned(BanInfo)` / `RefreshFailed { message }` from background refreshes

**Uploads**

- `DeviceSigningKey` — persistable P-256 upload signing key, scoped to one account and device. `Debug` redacts the key
- `UploadProfileImageResponse` — `{ hash, image_sizes }`
- `UploadedProfileImage` — `{ media_hash, full_url, state, thumbnail, size }`
- `MediaUploadResponse` — `{ media_id, url, media_hash }`

**Websocket**

- `WsCommand` — websocket command `{ type, ref_id, payload }`
- `WsEvent` — websocket event `{ event_type, payload }`
- `WsConnectionState` — `Connected` / `Disconnected`

The socket pings every 10 s like the app does, and refuses inbound frames and messages over 1 MiB.

**Re-exports**

- `Method` — re-exported `wreq::Method` for `request_authenticated_raw`
- `Bytes` — re-exported `bytes::Bytes` for `request_authenticated_bytes`

### Low-level helpers

For building your own `wreq::Client` with an identical fingerprint:

- `probe_emulation() -> wreq::EmulationProvider` — tls/http2 emulation profile
- `build_user_agent(device, tier) -> String` — `User-Agent` value
- `build_device_info_header(device) -> String` — `L-Device-Info` value
- `GrindrHeaders::build(device, ua, authorization, roles)` — full and correctly ordered headers list
- `requires_device_signature(path) -> bool` — whether an upload path needs the device signature headers
- `APP_VERSION` — the Grindr APK version this crate emulates

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

Rust **1.88**.

## License

[MIT](./LICENSE)
