# Windows app (`windows-app/`)

The PC side of Device Connect. The phone dials in; this side listens, proves who
is calling, and then answers only what the user has approved.

- No accounts, no cloud, no analytics, no telemetry, no crash reporters.
- The PC never dials a phone and never opens a port the user did not ask it to
  open. Nothing listens when the app is closed.
- Nothing is unlocked before the user compares the six-digit code on both
  screens.

---

## Modules

| Module | Type | Purpose |
| --- | --- | --- |
| `core/` | Rust library (`dc-client`) | The PC's identity, pairing window, trust stores and connection handling. No UI, and one Windows API call site (the Credential Manager). |
| `src-tauri/` | Tauri 2 app | Shell and React/TypeScript UI. **Phase 3b; not in the repository yet.** |

`core` is deliberately not a Tauri module. Keeping the connection handling in a
plain library means it builds and tests with nothing but `cargo test`, and the
shell is left with the two jobs only a shell can do: asking Windows for the facts
a window needs (the adapter to advertise, the real OS version) and asking the
user. The one Windows API that is not a UI concern - the Credential Manager, where
the long-term key lives - is inside `core`, so the key never has to pass through
JavaScript to be stored.

---

## Layout

```
windows-app/
  Cargo.toml            Workspace. members = ["core"] (and "src-tauri" in Phase 3b)
  core/
    Cargo.toml          dc-client
    src/lib.rs          Module list, re-exports, unix_now()/unix_now_ms()
    src/identity.rs     X25519 key pair; the device id is derived from the key
    src/pairing.rs      One pairing window: QR payload, nonce, prologue, expiry
    src/store.rs        SecretStore trait + FileSecretStore, atomic writes
    src/credman.rs      The PC key in the Windows Credential Manager (cfg(windows))
    src/trust.rs        TrustStore trait + the JSON list of pinned phones
    src/limit.rs        Per-address attempt bucket and listener lockout (section 3)
    src/session.rs      Listener, accept(), PendingSession, ActiveSession
    src/hex.rs          Lowercase hex, for ids
    tests/loopback.rs   Both protocol ends over a real TCP socket
```

The core reads exactly two things about the host: the machine name from
`COMPUTERNAME` (via `HostInfo::desktop()`) and Rust's own target-OS constant. A
richer Windows version string, the adapter list, and the credential store are
the shell's job, because only the shell can ask Windows. Inventing a version
string in the core would put a wrong claim on the wire (see `identity.rs`).

---

## What it contains

- **Identity.** An X25519 key pair, generated on first run and stored. The
  device id is *derived* - the first 8 bytes of SHA-256 of the public key, in
  hex - so a key and the id shown next to it can never disagree, and rotating the
  key cannot leave a stale id behind. `Identity`'s `Debug` prints the id and
  never the key.
- **Pairing window** (`PairingOffer`). A QR payload with a fresh nonce and a
  120-second expiry, or a manual-mode `host:port`. It also owns the Noise
  prologue, because the prologue is what binds a connection to the window.
- **Trust store.** The JSON list of pinned phones, written through a temp file
  and a rename. Entries whose `id` disagrees with their key are refused on load,
  and so is a file written by a newer version - an empty trust list would unpair
  every phone at once.
- **Session.** `Listener` -> `accept()` -> `PendingSession` -> `confirm()` ->
  `ActiveSession`, with the `hello` exchange, the confirmation code, request
  replies and `security.unpair` in both directions. `accept()` returns an
  `Arrival`, so a refused connection is a normal outcome rather than an error.
- **Heartbeat** (section 2.8). A `ping` is answered with a `pong` the moment the
  session reads one, and a `pong` is consumed, so no caller of `ActiveSession`
  ever sees a heartbeat frame or has to remember to answer one. The PC can send
  its own `ping`; pacing them and closing a silent link is the serving loop's job,
  which is not built yet - see `docs/windows.md`, "Heartbeat".
- **Rate limit and lockout** (section 3). Ten handshake attempts a minute per
  source address, and a listener-wide lock once one address sends more than five
  `hello`s that never become a pairing. It is decided before a byte is decrypted,
  which is what makes refusing cheap and also why the phone is only ever told by
  the socket closing; `docs/windows.md` has the numbers and the trade-offs.
- **Secrets.** The long-term key goes through `default_secret_store()`, which on
  Windows is the per-user Credential Manager - the key is never a file. That
  hides it from backups and from a second account on the machine, not from
  another program running as the same user; `docs/windows.md` says exactly what
  it does and does not stop.

Details, status and open gaps: **`docs/windows.md`**.

---

## Build and test

```powershell
Set-Location windows-app
$env:CARGO_TARGET_DIR = "D:\Albarr\tmp\cargo"   # optional: keeps target/ out of the repo
cargo test
```

Built and run with cargo/rustc 1.95.0. Nothing outside Rust is needed yet:
`cargo tauri` is only required from Phase 3b, when the shell is added.
