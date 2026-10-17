# Device Connect - Architecture

Status: Phase 3a (Windows core), living document. Every phase updates this file
when reality differs from the plan.

Device Connect lets one person control their own Android phone from their own
Windows PC over a local network or Bluetooth, and exposes the same capabilities
to Claude Code and OpenCode through an MCP server. There are no accounts, no
servers, and no cloud: everything travels directly between the user's two
devices, encrypted end to end.

## 1. Components

```
Device-Connect/
  protocol/       Shared protocol: framing spec, JSON Schemas, test vectors,
                  cross-platform conformance tests. The contract every other
                  component implements.
  android-app/    Kotlin + Jetpack Compose app. Captures the screen
                  (MediaProjection + hardware H.264), injects input through an
                  Accessibility Service, mirrors notifications, reads/sends SMS
                  (permission-gated), handles calls, clipboard, contacts, files,
                  and runs an optional ADB-based "Full Control" mode.
  windows-app/    Tauri 2 app. Rust core (transport, crypto, protocol, local
                  control interface) + React/TypeScript UI with hardware H.264
                  decode via WebCodecs in WebView2.
  mcp-server/     TypeScript MCP server (stdio) + Claude Code plugin/skill +
                  OpenCode MCP configuration. Talks to the Windows app through a
                  named pipe.
  website/        Static marketing/docs site. No trackers, no cookies.
  docs/           architecture.md (design, threat model, limitations),
                  protocol.md, and one status document per component.
  scripts/        PowerShell build and test scripts.
```

The tree above is the **target** layout. What exists in the repository today:
`protocol/` (spec, schemas, golden vectors, and matching Rust, Kotlin and
TypeScript implementations), `android-app/` (the phone, through pairing and the
control channel; see `docs/android.md`) and `windows-app/core/` (`dc-client`, the
PC's responder core). The Tauri shell, `mcp-server/`, `website/` and `scripts/`
are not written yet, and no capability is claimed that the code does not
implement - each area's own document carries its status table.

The macOS, Linux and iOS apps planned for later are **not** in this repository
yet. The protocol in `protocol/` is deliberately platform-neutral (no Android
or Windows types appear in the schema), so those apps can be added as new
`platform/<name>/` folders without changing the wire format. See
`protocol/README.md` for the extension rules.

## 2. Transport design

### 2.1 Layers

```
+--------------------------------------------------------------+
| Channels: control | video | notifications | messages | calls  |
|           clipboard | files | status | heartbeat              |
+--------------------------------------------------------------+
| Frame: u32be body_len | u8 channel | u8 type | u16be flags    |
|        | u32be seq | payload                                  |
+--------------------------------------------------------------+
| Noise_XX_25519_ChaChaPoly_SHA256 (encrypted, authenticated)   |
+--------------------------------------------------------------+
| Stream transport: TCP (Wi-Fi) or RFCOMM (Bluetooth Classic)   |
+--------------------------------------------------------------+
```

Full normative detail lives in `docs/protocol.md` and the machine-readable
schema in `protocol/schema/`.

### 2.2 Transports, in order of preference

1. **Wi-Fi / LAN (TCP).** Both devices on the same network, a VPN, or a
   phone/PC hotspot. The PC listens on a TCP port; the phone finds it by
   mDNS (`_deviceconnect._tcp`), by scanning the pairing QR code, or by a
   manually typed `ip:port`. This also works over a VPN because it is plain
   TCP with application-layer encryption.
2. **Bluetooth Classic (RFCOMM)** for control-plane channels (input,
   notifications, SMS, calls, clipboard) plus a best-effort low-frame-rate
   screen stream. BLE is used only for discovery and to wake the phone's
   service before the RFCOMM link is opened. Measured throughput numbers are to
   go into a `docs/measurements.md` that does not exist yet; the UI never
   promises more than measured, and nothing is claimed before it is measured.
3. **Wi-Fi Direct / hotspot**: no new code path. Both are just IP networks;
   the phone hotspot case uses the same TCP transport with manual IP entry
   when mDNS is unavailable.

The active transport is chosen automatically by measured latency and link type
(TCP beats RFCOMM when both are up). Both sides reconnect with exponential
backoff; if the Wi-Fi link drops, the app falls back to RFCOMM if available and
switches back automatically when Wi-Fi returns. The UI always shows which
transport is live.

### 2.3 Pairing and mutual authentication

1. The PC shows a QR code (valid 2 minutes) containing a one-time random
   128-bit nonce, the PC's mDNS name, the listening port, and the protocol
   version.
2. The phone scans it and opens a TCP connection. Both sides run a **Noise XX**
   handshake (X25519, ChaChaPoly, SHA256) with the QR nonce in the prologue, so
   a photographed or replayed QR is useless.
3. Both sides display the same 6-digit confirmation code derived from the two
   long-term static public keys. The user confirms on both devices. This stops
   a man in the middle on the local network.
4. Each side stores the peer's static public key (Android Keystore on the
   phone; on the PC a file store for now - Windows Credential Manager is
   Phase 3b, see `docs/windows.md`). Future connections authenticate against
   these pinned keys and skip the QR. Note that v1 keeps the full Noise XX
   handshake on reconnect; it only skips the QR step, not the handshake, so
   there is no shortened pattern to get wrong.

**Why Noise instead of TLS 1.3:** TLS needs certificates. Self-signed X.509
generation and lifecycle on Android is fragile (BouncyCastle is a hidden API
since API 28) and pinning adds no value for a two-device pairing where the
static keys are exchanged in person via QR. Noise XX gives mutual
authentication, forward secrecy and identity hiding before pairing, is a
standard reviewed construction, and has maintained implementations on both
platforms (`snow` in Rust, Signal's `noise-java` in Kotlin). No custom crypto.

### 2.4 Sensitive-action policy

Every state-changing request from the PC (and always from the MCP server
unless the user opts in on the phone) can require a confirmation prompt on the
phone: sending SMS, deleting anything, installing apps, file transfer outside
the shared folder, and unpairing. Toggles live on the phone's permission
screen and are enforced on the phone, not the PC.

## 3. Local control interface (MCP)

The Windows app exposes a named pipe `\\.\pipe\device-connect-<install-id>`
with a DACL limited to the current Windows user. The first message must carry
a per-install token read from `%APPDATA%\DeviceConnect\control-token`, a file
created with a user-only ACL. Requests are newline-delimited JSON-RPC with
strict schemas, per-client rate limiting, and a log that never contains
message text, contacts, keys or tokens.

## 4. Threat model

### 4.1 Adversaries considered

| Adversary | Mitigation | Residual risk |
|---|---|---|
| Other devices on the same LAN/Wi-Fi | Noise XX with pinned keys; unpaired clients are refused before any data flows | None known for the protocol itself |
| Active MITM during first pairing | QR one-time nonce + 6-digit code confirmed on both screens | Shoulder-surfing the QR within its 2-minute life |
| Malware on the PC or phone | OS sandbox; the phone's key is Keystore-sealed | A compromised OS can read the screen; out of scope. The PC key is a plain file under the user profile until Phase 3b |
| Thief of the phone | Unpair + remote wipe commands from the PC; keys non-exportable | Device unlocked before remote unpair arrives |
| Over-curious MCP/AI client | Phone-side confirmation for sensitive actions, per-capability toggles, user can disable confirmations | User who disables all confirmations trusts their AI client fully |
| Network attacker flooding handshakes | Designed: per-IP token bucket + exponential lockout, shown in the UI. **Not implemented** (see 6) | DoS of the pairing screen for the lockout window; today an attacker can force unlimited handshakes |

### 4.2 Explicit non-goals

- Hiding the app, its notification, or its launcher icon. All are visible and
  required.
- Bypassing FLAG_SECURE, DRM, or any OS security control.
- Remote access when devices are not on the same network/VPN/Bluetooth range.
- Protecting against an attacker with root/admin on either device.
- Anonymity or metadata protection: the peer sees device name, battery state,
  and app list by design.

## 5. Data collected

Nothing leaves the devices. No accounts, no analytics, no telemetry, no crash
reporters. Data that is read (SMS, notifications, contacts, call log, files,
clipboard) is only read while the corresponding capability toggle is on, only
used for the feature the user invoked, and never written to disk logs. App
logs contain event names, sizes, durations and error codes only - never
message bodies, contact names, keys or tokens.

## 6. Known limitations (honest list)

- **RCS and third-party chats** (WhatsApp, Telegram, ...) cannot be read
  directly. Replying works only through the mirrored notification's inline
  reply action, which the OS routes through the original app.
- **Call audio cannot be routed to the PC.** Android has no API to redirect
  cellular call audio to another device. Calls can be seen, answered, rejected
  and started; audio stays on the phone.
- **FLAG_SECURE content is never captured** (banking apps, DRM, password
  fields). This is deliberate and cannot be overridden without violating the
  platform's security model.
- **MediaProjection consent**: Android requires the system screen-capture
  dialog every time capture starts. The app cannot (and will not) suppress it.
- **Accessibility input has gaps**: some system screens, games, and apps with
  FLAG_SECURE do not accept injected input. Text selection handles are not
  accessible; long-press coordinates are.
- **Wireless debugging (Full Control mode)** needs Android 11+, developer
  options, and re-pairing after every reboot because the port and session
  change. It is optional, off by default, and explained in-app.
- **Battery optimizers** on aggressive OEM skins (notably Xiaomi, Huawei,
  Oppo) may still kill the foreground service. The app guides the user through
  the exemption request but cannot force it.
- **Bluetooth throughput** is unmeasured. There is no RFCOMM transport in the
  code yet on either side, so no number exists and none is quoted; a
  `docs/measurements.md` will record the real figures if and when the transport
  is written. The screen mirror over Bluetooth is planned as best-effort and low
  frame rate.
- **No iOS support yet.** The protocol is platform-neutral; there is no iOS
  client, and none is planned for v1.
- **Doze/sleep**: when the phone sleeps deeply with Wi-Fi off, the PC cannot
  wake it over IP. Bluetooth wake-up covers only devices in range with BLE on.
- **The PC is a responder only in v1.** It listens and answers; it never dials a
  phone and never initiates a session. This is deliberate (one dial direction,
  one place to get wrong), not an oversight, and the protocol allows the
  opposite direction without a version change.
- **Windows: the PC key is a plain file, not in Credential Manager.** `dc-client`
  ships a `FileSecretStore` behind a `SecretStore` trait; the Credential Manager
  implementation is Phase 3b. Until then the key inherits only the ACLs of the
  user's profile directory. `docs/windows.md` has the detail.
- **Windows: no handshake rate limit yet.** The per-IP token bucket and lockout
  in section 4.1 are designed but not implemented, so anything on the network can
  make the PC run handshakes as fast as it can send them.
- **Windows: no mDNS advertisement yet.** The phone can browse for
  `_deviceconnect._tcp`; the PC does not announce it until the Phase 3b shell
  exists, so pairing today is a typed `ip:port` or a QR.

## 7. Build and cache locations

This machine has limited space on C:, so all build caches are pointed at D::
`ANDROID_HOME=D:\Android\Sdk`, `GRADLE_USER_HOME=D:\Albarr\cache\gradle`,
`CARGO_TARGET_DIR=D:\Albarr\cache\cargo-target`, npm cache
`D:\Albarr\cache\npm`. These are all environment variables the tools respect, so
nothing in the repository hard-codes a local path. The `scripts/bootstrap.ps1`
that would set them on a fresh machine is **not written yet**; the commands in
each component's README work without it.
