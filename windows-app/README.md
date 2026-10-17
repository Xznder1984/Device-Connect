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
| `core/` | Rust library (`dc-client`) | The PC's identity, pairing window, trust store and connection handling. No UI, no Windows APIs. |
| `src-tauri/` | Tauri 2 app | Shell and React/TypeScript UI. **Phase 3b; not in the repository yet.** |

`core` is deliberately not a Tauri module. Keeping the connection handling in a
plain library means it builds and tests with nothing but `cargo test`, and the
shell is left with the two jobs only a shell can do: asking Windows for facts
(the adapter to advertise, the real OS version, the Credential Manager) and
asking the user.

---

## Layout

```
windows-app/
  Cargo.toml            Workspace. members = ["core"] (and "src-tauri" in Phase 3b)
  core/
    Cargo.toml          dc-client
    src/lib.rs          Module list, re-exports, unix_now()
    src/identity.rs     X25519 key pair; the device id is derived from the key
    src/pairing.rs      One pairing window: QR payload, nonce, prologue, expiry
    src/store.rs        SecretStore trait + FileSecretStore, atomic writes
    src/trust.rs        TrustStore trait + the JSON list of pinned phones
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
  replies and `security.unpair` in both directions.

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
