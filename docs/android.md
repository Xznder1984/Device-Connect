# Android app (`android-app/`)

The phone side of Device Connect. It lets one person control *their own* phone
from *their own* Windows PC — nothing else.

- No root, no exploits, no custom system images.
- No accounts, no cloud, no analytics, no telemetry, no crash reporters.
- Every capability is opt-in on the phone and can be revoked instantly.

---

## Modules

| Module | Type | Purpose |
| --- | --- | --- |
| `:protocol` | plain Kotlin/JVM library | Wire format: framing, QR payloads, confirmation codes, Noise XX handshake, typed JSON messages. Shares the golden vectors with the Rust and TypeScript implementations. |
| `:app` | Android application | UI, foreground service, network transport, capability switches, and — in later phases — screen capture and the remaining system capabilities. |

`:protocol` is deliberately *not* an Android module. Keeping it on plain JVM
means its conformance tests run on any machine with a JDK and can be executed
without an emulator. `:app` depends on it for the wire format.

---

## Connection model

The protocol allows either side to listen and dial, with a tie-break for the
case where both do (`docs/protocol.md` section 2.1):

> Either side may listen and dial. If both listen, the peer with the
> lexicographically larger `id` keeps its listener and the other dials.

where `id` is the first 8 bytes (16 hex characters) of SHA-256 of the static
public key.

**This phone always dials, and never accepts an inbound connection.** That is a
deliberate v1 decision: the phone is the resource being controlled, so it should
not be reachable by strangers on the network. Because it never listens, it also
never advertises an mDNS record — advertising a service nothing is listening on
would make the phone look connectable when it is not. The PC is the listener.

The phone finds the PC three ways:

1. **QR** — the PC shows `dc1:` + base64url(JSON) for 120 s; the phone scans it
   and dials `h:p` with the QR nonce bound into the Noise prologue
   (`0x00` mode).
2. **mDNS** — the phone looks for the PC's `_deviceconnect._tcp.local` record
   (TXT `pv=1`, `id=<hex8>`, `role=pc`) and dials whatever address it resolves.
   Only records whose `role` is `pc` are offered.
3. **Manual** — the user types `ip:port` on the phone (Noise prologue mode
   `0x01`, no QR nonce).

All three converge on the same Noise `Noise_XX_25519_ChaChaPoly_SHA256`
handshake, so a wrong prologue on either side aborts immediately. There is no
custom cryptography anywhere: `:protocol` uses the MIT-licensed
`rweather/noise-java` library (vendored, see `THIRD-PARTY-NOTICES.md`).

A dial does not always reach a handshake. Protocol section 3 has the PC refuse a
connection before the handshake when the source address is over its attempt
budget or while its listener is locked, and there is no frame for that: the
socket simply closes. On this side that is indistinguishable from a PC that is
not listening at all, and telling the user which one it was is Pending (see
Status).

### Why the phone does not listen

Supporting inbound connections would mean holding a listening socket open, which
is exactly the property people distrust in remote-control software. Keeping the
phone dial-only means:

- there is no listening port to find or attack when the user is not pairing;
- a session can only ever start because the person holding the phone started it;
- the attack surface stays in the PC app, which is not the device holding
  personal data.

A future version can add a listener for reconnection convenience, but it would
need to keep the same rule: nothing listens unless a session is actively
expected.

---

## Permissions

These are the permissions actually declared in `AndroidManifest.xml` today. The
camera and notifications are requested at runtime; the rest are install-time
normal-level permissions.

| Permission | Why it exists | When it is used |
| --- | --- | --- |
| `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE` | Direct device-to-device TCP | Only while pairing or a session is active |
| `CHANGE_WIFI_MULTICAST_STATE` | Lets mDNS answers through the Wi-Fi multicast filter during a scan | Only while the "find on this network" screen is open |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_CONNECTED_DEVICE` | Keeps the connection alive while the phone is locked | While connected |
| `POST_NOTIFICATIONS` | Shows the mandatory "Device Connect is active" notification | Requested on first launch |
| `CAMERA` | Reads the pairing QR code the PC displays | Requested the first time the user chooses "Scan the QR code"; frames are decoded on-device and never stored or sent |

`CAMERA` is paired with `<uses-feature android:name="android.hardware.camera.any"
android:required="false" />`, so devices without a camera still install the app
and can pair by mDNS or by typing the address.

### Local network access

The app **targets API 36**. At that target level, local network access is
implicitly granted by `INTERNET`, and the Android platform documentation
explicitly says *not* to declare or request the new `ACCESS_LOCAL_NETWORK`
permission yet. When `targetSdk` is raised to 37, this manifest must add
`<uses-permission android:name="android.permission.ACCESS_LOCAL_NETWORK" />`
and the app must request it at runtime before scanning or connecting.

Nothing extra is declared for this today, on purpose: declaring it early would
be wrong for the current target SDK.

### Not yet declared (planned)

These are **not** in the manifest yet, because the features they belong to are
not implemented. They are listed so the intent is on record, and each will be
added only together with its feature, its in-app disclosure and its own user
switch:

- `MEDIA_PROJECTION` (runtime) — screen capture. The system consent sheet is
  mandatory and cannot be bypassed.
- `SYSTEM_ALERT_WINDOW` (runtime) — optional overlay, only for an in-app
  activity indicator, and only if the user turns it on.

### Capabilities that are implemented

One capability is shipped. It is off until the user turns it on in the app
(*What your PC can use*), and the switch is enforced on the phone, per request:

- **Clipboard** — `ClipboardManager`, text only, over the clipboard channel
  (`clipboard.get` / `clipboard.set`). There is no clipboard watcher and no
  background listener, so a clip leaves the phone only inside a reply to an
  explicit request, and it is never written to a log. Android 10 and later only
  let the *focused* app read the clipboard, so a read that arrives while the app
  is not on screen is refused with `NOT_FOUND` instead of being answered with an
  empty string: "cannot see it" and "it is empty" are different facts, and the PC
  has to be able to tell them apart. Transfers are capped at 128 KiB
  (`ClipboardSync.MAX_TEXT_BYTES`); the schema allows 1 MiB, but JSON escaping can
  turn one character into six, and the smaller cap is what guarantees the reply
  always fits in a single frame.

### Capabilities that are not implemented yet

Each needs a runtime permission or user-granted system access, declared only
together with its own feature, in-app disclosure and switch:

- **Input control** — an `AccessibilityService`. This is the only official API
  for injecting touch/gesture events. It must be enabled by the user in system
  settings, cannot be enabled by the app, and is disclosed before enabling.
- **Notifications** — a `NotificationListenerService`, which requires the user
  to grant notification access in system settings.
- **Files** — the Storage Access Framework (SAF), so the user picks exactly the
  directories that are shared; no broad storage permission.

No switch is offered for a capability that is not implemented, and `caps.set`
refuses one with `INVALID_ARGS` rather than storing it. `hello` advertises exactly
the implemented capabilities that are switched on, so the PC never believes it
may do something the phone would then refuse.

---

## Consent model

1. **Persistent notification.** A foreground-service notification is visible for
   the whole life of a session and states which stage it is at (connecting,
   confirming the code, connected). It cannot be swiped away, and its only
   action is Disconnect. When screen capture lands in a later phase it will use
   the same notification, switching to a "screen capture active" state.
2. **In-app indicator.** The home screen always states whether anything is
   allowed and shows the connection state; the connected screen repeats it. The
   switch list itself is reachable from both and needs no connection to use.
3. **Screen capture uses the system dialog.** `MediaProjection` requires the
   Android system consent sheet every time; the app cannot capture silently in
   the background.
4. **Sensitive actions confirm on the phone.** By default, sending SMS,
   deleting data, installing apps and file transfers require an on-phone
   confirmation dialog showing the exact action before the PC is allowed to
   proceed. This is configurable.
5. **Instant revoke.** The Disconnect action on the notification, or the button
   on the connected screen, drops the session immediately and clears the active
   state. `security.unpair` deletes the pinned peer key.

---

## Personal data

The app has no backend and no accounts. It stores only the minimum a pairing
needs, and nothing about the *content* of a session:

| Thing | Stored? | Where |
| --- | --- | --- |
| Local static keypair | Yes | Private key sealed with AES-GCM under a Keystore master key; only the ciphertext is in app-private `SharedPreferences` |
| Pinned peer public key | Yes | Sealed the same way as the local key; deleted on unpair |
| Peer display name | Yes | The name the PC reports about itself. Sealed with the pinned key, because it can be personal (for example a person's name). Deleted on unpair |
| Last connected address (`host:port`) | Yes | Plain `SharedPreferences`, so "Reconnect" works without re-pairing. Contains no personal data and is deleted on unpair |
| Capability switches | Yes | `SharedPreferences` (plain booleans) |
| Camera frames | **Never** | Decoded in memory for QR scanning; not written to disk and not sent anywhere |
| Confirmation code | **Never at rest** | Derived in memory and shown on screen for as long as the confirmation screen is open |
| Messages, contacts, call logs, file contents, notification text | **Never at rest** | Read only to answer a live request from the paired PC |
| Logs | Never contain message text, contacts, keys, tokens or QR nonces | Event name, size and error code only |
| Analytics / crash reporting | None exists | — |

The Android Keystore master key is hardware-backed where the device supports it,
so a copy of the app's private storage is useless on another device. Backups are
disabled (`allowBackup=false`) so nothing can be copied by a cloud backup or
device transfer.

---

## Distribution and Play Store policy limits

This project is distributed as **signed APKs from GitHub Releases** to its
single owner. The relevant Play policy limits, stated plainly:

- **SMS/messaging**: reading SMS and sending SMS from the device are restricted
  APIs. An app using them generally cannot be distributed on Play, and Play's
  own policies favour default-handler status for very narrow use cases.
- **Accessibility**: using an `AccessibilityService` for non-accessibility
  purposes (like input injection) is outside what Play permits for normal
  apps.
- **Notification listener**: allowed, but Play requires disclosure of exactly
  which data is read.
- **MediaProjection / screen capture**: allowed, but the system consent dialog
  is mandatory and background capture is not allowed.

Because the primary distribution channel is sideloading to the owner's own
device, these features are implemented and clearly disclosed in-app rather than
removed. **This document does not claim that the app complies with any specific
Play policy, and it must not be used as a compliance claim.** If a feature is
added that needs Play distribution, revisit it then.

Sideloaded APKs need a release keystore that is *never* committed (see
`.gitignore` and the "Signing material and secrets" section).

---

## Build and test

```powershell
$env:ANDROID_HOME = "D:\Android\Sdk"
$env:GRADLE_USER_HOME = "D:\GradleCache"
cd D:\Albarr\Projects\Device-Connect\android-app

# Protocol conformance tests - no device needed
gradle :protocol:test

# Debug APK (no keystore needed)
gradle :app:assembleDebug
```

Requirements: JDK 17 or 21, Gradle 9.7, Android SDK Platform 37.0 (the app
*compiles* against 37 because current androidx requires it, and *targets* 36),
and Build Tools 36.0.0.

## Status

Anything marked Pending is **not shipped** and is not claimed to work. Anything
marked Implemented has been compiled and, where it is testable without hardware,
run; end-to-end verification against a live PC is Phase 4.

| Area | State |
| --- | --- |
| `:protocol` conformance (framing, QR, confirm, Noise KAT, typed messages, record layer, command/capability map) | Implemented, tested (46 tests) |
| `:app` shell, theme, home/consent screen, launcher | Implemented, builds |
| Foreground service + mandatory notification (waiting / confirming / connected) | Implemented |
| Device identity (Keystore-sealed X25519) and peer trust store | Implemented |
| Pairing: scan the PC's QR code (CameraX + ZXing, on-device) | Implemented |
| Pairing: type `ip:port` manually | Implemented |
| Pairing: find the PC over mDNS | Implemented |
| Pairing: compare the six-digit confirmation code before pinning | Implemented |
| Transport (TCP dial, Noise XX handshake, record layer, `hello`/`hello_ack`) | Implemented, **not yet run against a live PC** |
| Control command dispatch (`status.get`, `caps.set`, `security.unpair`, `clipboard.get`, `clipboard.set`) | Implemented |
| Capability switches in the phone UI, enforced per request | Implemented (clipboard is the only capability this build implements) |
| Heartbeat / dead-link detection and reconnect backoff | Pending on the phone: nothing here sends a `ping`, answers one, or backs off before reconnecting. The PC half exists (`docs/windows.md`, "Heartbeat") |
| Screen capture (MediaProjection + H.264) | Pending |
| Input control (Accessibility) | Pending |
| Notification listener, SMS, files | Pending |
| Warning that the PC has locked its listener (protocol section 3) | Pending: a locked PC refuses before the handshake, so the phone sees only a closed socket and has nothing to show on screen |
