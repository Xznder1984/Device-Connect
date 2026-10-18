# Device Connect

Control *your own* Android phone from *your own* Windows PC over your local
network - and, later, expose the same capabilities to Claude Code and OpenCode
through an MCP server.

- No accounts, no cloud, no analytics, no telemetry, no crash reporters.
- The phone dials, the PC listens. Nothing listens when the Windows app is
  closed, and the PC never reaches out to a phone on its own.
- Nothing is unlocked until the user compares the same six digits on both
  screens and confirms on both. Capabilities are off by default and are enforced
  on the phone, where the user can revoke them.
- Message bodies, clipboard contents, keys and tokens are never logged and never
  written to disk.

`docs/protocol.md` is the normative wire format; `docs/architecture.md` explains
the design and its threat model.

---

## Status

This is an honest snapshot. Anything marked Pending is **not shipped** and is not
claimed to work anywhere in this repository.

| Component | State |
| --- | --- |
| `protocol/` | **Implemented, tested.** Framing, the record layer, QR pairing payloads (nonce + expiry), six-digit confirmation codes, the Noise XX known-answer test, JSON Schemas and the golden vectors, with conformance suites in Rust and TypeScript here and a Kotlin/JVM one in `android-app/protocol/`, all reading the same vectors. |
| `android-app/` | Implemented through Phase 2c: `:protocol` (46 tests) and the app - pairing by QR, by typed `ip:port` or by mDNS, device identity sealed in the Keystore, the peer trust store, the foreground service, the consent screen and the clipboard capability. Screen capture, input injection, notifications, SMS, calls, contacts and files are **Pending**. |
| `windows-app/` | Phase 3a + 3b in part: `dc-client`, the responder core - identity whose key lives in the per-user **Windows Credential Manager**, pairing window, trust store, and the session (27 unit + 9 end-to-end tests, all green). The Tauri shell and the React UI are **Pending** (Phase 3b), as are the handshake rate limit and the heartbeat. |
| `mcp-server/` | **Not started.** |
| `website/` | **Not started.** |

The two apps have not yet been run against each other. Both sides are verified
against the shared protocol and its golden vectors, which is what makes that
worthwhile, but the first live phone-to-PC connection is Phase 4. Every
component's own document says so in its own words rather than leaving it implied.

## Repository layout

```
protocol/     the wire format. docs/protocol.md is normative; this tree holds
              the JSON Schemas, the golden vectors, and the Rust and TypeScript
              conformance suites (the Kotlin one is android-app/protocol)
android-app/  the phone. Kotlin, Jetpack Compose, pure-JVM :protocol module
windows-app/  the PC. Rust core now, Tauri 2 shell with a React/TypeScript UI
              in Phase 3b
docs/         architecture and threat model, the protocol spec, and one status
              document per component (android.md, windows.md)
```

## Building and testing

Every component builds on its own. Nothing here needs a phone, a PC or an
emulator attached to run the test suites.

Protocol, in Rust:

```powershell
Set-Location protocol/rust
cargo test          # 17 unit tests + 9 tests against the golden vectors
```

Protocol, in TypeScript (no build step: Node runs the `.ts` files directly via
its type stripping; checked on Node v22.20.0):

```powershell
Set-Location protocol/conformance/ts
npm install         # ajv, for the schema checks
npm test            # 10 tests: framing, QR, confirmation codes, schemas
```

Android (JDK 17+ and the Android SDK; `:protocol` alone needs only a JDK):

```powershell
Set-Location android-app
gradle :protocol:test :app:assembleDebug --console=plain
```

Windows:

```powershell
Set-Location windows-app
cargo test          # 27 unit tests + 9 tests over a real loopback socket
```

On a machine with little space on `C:`, point the caches elsewhere first:
`CARGO_TARGET_DIR`, `GRADLE_USER_HOME` and `ANDROID_HOME` are all respected;
this repository was developed with them on `D:`.

## Security posture

The short version, because it is the reason the project exists:

- **Consent is structural.** A phone whose key is not already pinned is not
  refused and not trusted - it gets a `PendingSession`, which answers nothing at
  all until the user compares the six-digit code on both screens and confirms on
  both. Capabilities are off by default, enforced on the phone, and revocable.
- **The phone dials; the PC listens.** Neither opens a port the user did not ask
  for, and the PC never initiates.
- **Contents are never written down.** Message bodies, clipboard contents, keys
  and tokens do not appear in any log, error or crash report, and there is no
  analytics or telemetry to send them to.
- **No custom cryptography.** Noise XX over X25519 / ChaChaPoly / SHA256, with
  the implementations (`snow` in Rust, a vendored MIT Java implementation on
  Android) chosen rather than written here.
- **Keys go to the platform store.** The phone's key is sealed in the Android
  Keystore; the PC's is an entry in the per-user Windows Credential Manager, not
  a file. Neither store separates programs running as the same user, and neither
  is described as if it did.

What is *not* protected yet is listed with the rest: the per-IP handshake rate
limit is designed but not implemented, and the PC has no heartbeat. Both are in
`docs/windows.md` and in `docs/architecture.md` section 6, which is the honest
list of limitations.

## License

MIT - see `LICENSE`. Third-party components and their licenses are listed in
`THIRD-PARTY-NOTICES.md`, including the vendored MIT Noise implementation on the
Android side. Nothing in the tree is copyleft-only.
