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
| `:app` | Android application | UI, foreground service, network transport, screen capture, and every system capability. |

`:protocol` is deliberately *not* an Android module. Keeping it on plain JVM
means its conformance tests run on any machine with a JDK and can be executed
without an emulator. `:app` depends on it for the wire format.

---

## Connection model

Both sides may listen and dial, so there is no fixed "server" role. The tie-break
rule from `docs/protocol.md` section 2.1 is:

> Either side may listen and dial. If both listen, the peer with the
> lexicographically larger `id` keeps its listener and the other dials.

where `id` is the first 8 bytes (16 hex characters) of SHA-256 of the static
public key.

The phone discovers the PC three ways, in this order:

1. **QR** — the PC shows `dc1:` + base64url(JSON) for 120 s; the phone scans it
   and dials `h:p` with the QR nonce bound into the Noise prologue.
2. **mDNS** — the phone advertises `_deviceconnect._tcp.local` with TXT
   `pv=1`, `id=<hex8>`, `role=phone` and discovers the PC's equivalent record.
3. **Manual** — the user types `ip:port` on the phone (Noise prologue mode
   `0x01`, no QR nonce).

All three converge on the same Noise `Noise_XX_25519_ChaChaPoly_SHA256`
handshake with prologue `"device-connect/v1"`, so a wrong prologue on either
side aborts immediately. There is no custom cryptography anywhere: `:protocol`
uses the MIT-licensed `rweather/noise-java` library (vendored, see
`THIRD-PARTY-NOTICES.md`).

---

## Permissions

Every permission is declared with a reason the user can read in the app itself.

| Permission | Why it exists | When it is used |
| --- | --- | --- |
| `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE` | Direct device-to-device TCP and mDNS discovery | Only while pairing or a session is active |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_CONNECTED_DEVICE` | Keeps the connection alive while the phone is locked | While connected |
| `POST_NOTIFICATIONS` | Shows the mandatory "Device Connect is active" notification | On first launch |
| `MEDIA_PROJECTION` (runtime) | Screen capture | Only for the duration of a session the user started |
| `SYSTEM_ALERT_WINDOW` (runtime) | Optional overlay, used only for the in-app activity indicator | Only if the user turns it on |

Later phases add the following capabilities, each behind its own switch:

- **Input control** — an `AccessibilityService`. This is the only official API
  for injecting touch/gesture events. It must be enabled by the user in system
  settings, cannot be enabled by the app, and is disclosed before enabling.
- **Notifications** — a `NotificationListenerService`, which requires the user
  to grant notification access in system settings.
- **Clipboard** — `ClipboardManager`, read only while the app is in the
  foreground or the user has opted in to background reads.
- **Files** — the Storage Access Framework (SAF), so the user picks exactly the
  directories that are shared; no broad storage permission.

---

## Consent model

1. **Persistent notification.** Whenever a session is connected *or* screen
   capture is running, a foreground-service notification is visible and states
   which capability is active. It cannot be hidden.
2. **In-app indicator.** The main screen always shows connection state and which
   capabilities are enabled.
3. **Screen capture uses the system dialog.** `MediaProjection` requires the
   Android system consent sheet every time; the app cannot capture silently in
   the background.
4. **Sensitive actions confirm on the phone.** By default, sending SMS,
   deleting data, installing apps and file transfers require an on-phone
   confirmation dialog showing the exact action before the PC is allowed to
   proceed. This is configurable.
5. **Instant revoke.** "Disconnect now" drops the session, stops capture,
   clears the active state and shows it in the notification. `security.unpair`
   deletes the pinned peer key.

---

## Personal data

The app stores **no** personal data and has no backend:

| Thing | Stored? | Where |
| --- | --- | --- |
| Local static keypair | Yes | Android Keystore (hardware-backed where available) |
| Pinned peer public key | Yes | Keystore/SharedPreferences, cleared on unpair |
| Capability switches | Yes | SharedPreferences |
| Messages, contacts, call logs, file contents, notification text | **Never at rest** | Read only to answer a live request from the paired PC |
| Logs | Never contain message text, contacts, keys, tokens or QR nonces | Event name, size and error code only |
| Analytics / crash reporting | None exists | — |

Backups are disabled (`allowBackup=false`) so nothing in the app can be copied
by a cloud backup or device transfer.

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

| Area | State |
| --- | --- |
| `:protocol` conformance (framing, QR, confirm, Noise KAT, typed messages) | Implemented, tested |
| `:app` shell, theme, consent screen, launcher | Implemented, builds |
| Foreground service + mandatory notification | Pending |
| Transport (mDNS, TCP, Noise handshake, session) | Pending |
| Control command dispatch | Pending |
| Screen capture (MediaProjection + H.264) | Pending |
| Input control (Accessibility) | Pending |
| Notification listener, SMS, clipboard, files | Pending |

Anything marked Pending is not shipped and is not claimed to work.
