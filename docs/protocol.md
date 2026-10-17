# Device Connect Protocol v1 - Normative Specification

Status: stable for v1. Machine-readable schema: `protocol/schema/`.
Golden test vectors every implementation must pass: `protocol/test-vectors/`.

Keywords MUST, SHOULD, MAY are used as in RFC 2119.

## 1. Design goals

- One encrypted, authenticated, multiplexed byte stream per connection.
- Platform-neutral: no Android, Windows, or browser-specific types on the wire.
- Length-prefixed framing so partial reads never desynchronize the stream.
- Forward-compatible: unknown channels and command names MUST be ignored with
  an `UNSUPPORTED` error response (for requests) or dropped (for events), never
  a disconnect.

## 2. Connection establishment

### 2.1 Transports

| Transport | Discovery | Dial direction | Notes |
|---|---|---|---|
| Wi-Fi TCP | mDNS `_deviceconnect._tcp.local` TXT `pv=1`, `id=<hex8>`, `role=pc|phone`; or QR; or manual `ip:port` | Either side may listen and dial. If both listen, the peer with the lexicographically larger `id` keeps its listener and the other dials. | Works over VPN and hotspots (plain TCP) |
| Bluetooth Classic RFCOMM | BLE GATT server on the phone advertises service data `0xDC 0x01 <rfcomm-mac-bytes?>`, SDP service name `deviceconnect` | PC dials the phone's RFCOMM socket | Control channels + best-effort screen mirror |

A connection is `initiator` (dialer) and `responder` (listener). The Noise
pattern is symmetric (XX), so either role works for either device.

### 2.2 Cryptographic handshake (pairing and every connection)

Immediately after the TCP/RFCOMM stream is up, both sides run
**Noise_XX_25519_ChaChaPoly_SHA256** (Noise Protocol Framework, rev 34):

- Pattern: `XX` (mutual auth, both static keys transmitted inside the handshake)
- Prologue: ASCII `device-connect/v1` + `0x00` + 1 mode byte:
  `0x00` = QR mode (followed by the 16-byte QR nonce), `0x01` = manual mode.
  Prologue binding prevents QR replay.
- Initiator and responder may each be the PC or the phone.
- After the 3-message handshake both sides hold a transport pair
  (ChaChaPoly-Poly1305, 64-bit nonce counter, in-order, as defined by Noise).

There is no session resumption in v1: every connection runs the full XX
handshake (1 round trip). Re-keying is not used; a ChaChaPoly counter space of
2^64 messages cannot be exhausted in a session's lifetime, and sessions end on
disconnect.

#### 2.2.1 Record layer

Every message on the stream, including the handshake itself, is length-prefixed
so a peer always knows where a message ends. All lengths are `u32be` and cover
only the bytes that follow them.

- **Handshake messages** (the three Noise XX messages): `u32be len` + message.
  `len` MUST be <= 65536. The XX pattern stays well under 1 KiB, so anything
  near the cap is a malformed or hostile peer and the connection is closed.
- **Transport records** (everything after `split()`): `u32be len` +
  ciphertext, where `len` is the encrypted size of exactly one frame, that is
  the plaintext frame length plus the 16-byte Poly1305 tag. A plaintext frame is
  `4 + body_len` bytes, so `len` MUST be <= 4 + 1_048_576 + 16 = 1_048_596.

A zero-length record is invalid on both paths and closes the connection.

The length prefix sits *outside* the AEAD, so tampering with it makes the tag
check fail and the connection closes; it can never desynchronize a peer into
accepting different plaintext. There is no padding and no coalescing in v1:
one frame is one record.

Immediately after the handshake, the **initiator** sends on the control
channel (plaintext framing, encrypted by Noise):

```json
{"pv":1,"t":"hello","device":{"id":"16-hex-chars","name":"Pixel 8","model":"Pixel 8","os":"Android 16"},"caps":["screen_view","input_control"]}
```

The responder answers:

```json
{"pv":1,"t":"hello_ack","device":{"id":"...","name":"PC","model":"","os":"Windows 11"},"caps":["screen_view"],"paired":true}
```

`pv` mismatch on `hello` MUST abort the connection with an error frame
(`code: UNSUPPORTED`) before any other traffic. `paired` tells the dialer
whether its static key was already pinned; if `false`, the UI MUST show the
pairing confirmation flow (section 3) before any channel traffic is used.

### 2.3 Frame format (all channels)

All integers big-endian.

> After the handshake this structure is the Noise *plaintext*. On the wire it is
> wrapped by the record layer of section 2.2.1 (`u32be len` + ciphertext), so the
> `body_len` field below is not readable until the record has been decrypted.

```
offset  size  field
0       4     body_len   u32   length of body, 8 .. 1_048_576 inclusive
4       1     channel    u8    see 2.4
5       1     mtype      u8    see 2.5
6       2     flags      u16   bit0 JSON_PAYLOAD, bit1-2 reserved, MUST be 0
8       4     seq        u32   per-channel sequence, starts 0, increments 1
12      ...   payload    bytes body_len - 8
```

Implementations MUST reject `body_len < 8` and `body_len > 1_048_576` by
closing the connection. Video access units larger than the limit MUST be
fragmented by the sender (mtype 0x03, section 2.6).

### 2.4 Channels

| id | name | payload |
|---|---|---|
| 0x01 | control | JSON commands (session, security, screen, input, apps, wait) |
| 0x02 | video | H.264 (see 2.6) |
| 0x03 | notifications | JSON commands + events |
| 0x04 | messages | JSON commands + events (SMS) |
| 0x05 | calls | JSON commands + events |
| 0x06 | clipboard | JSON commands + events |
| 0x07 | files | JSON commands + binary data frames |
| 0x08 | status | JSON commands + events |
| 0x09 | heartbeat | JSON ping/pong |

Unknown channel ids MUST be ignored (the frame is skipped by `body_len`).

### 2.5 Message types (uniform envelope)

| mtype | meaning | payload |
|---|---|---|
| 0x01 | request | JSON `{"id":<1..2^31-1>,"cmd":"<ns.name>","args":{...}}` |
| 0x02 | response | JSON `{"id":<same>,"ok":true,"result":{...}}` or `{"id":<same>,"ok":false,"error":{"code":"...","message":"...","actionId?"}}` |
| 0x03 | event | JSON `{"evt":"<ns.name>","data":{...}}` |
| 0x04 | error (unsolicited) | JSON `{"code":"...","message":"..."}` |

- `id` is chosen by the requester, unique per channel, MUST NOT be 0.
- Binary channels (video, files data) use mtype 0x10-0x1F as defined per
  channel; those frames have no JSON flag set.
- Requests SHOULD complete within 10 s or return `BUSY`.

### 2.6 Video channel (0x02)

Screen video is H.264 in Annex B format from Android's MediaProjection ->
MediaCodec hardware encoder.

- mtype 0x01 `config` (JSON): `{"codec":"h264","profile":"baseline"|"main"|"high","level":"...","width":<int>,"height":<int>,"sps":"<base64>","pps":"<base64>"}`
- mtype 0x02 `access_unit` (binary): `[u64be timestamp_ms][one Annex B access unit, ≤ 256 KiB]`
- mtype 0x03 `access_unit_fragment` (binary): `[u64be timestamp_ms][u32be fragment_index][u32be fragment_count][bytes]`
  Fragments of one timestamp MUST be reassembled in index order; a new
  timestamp or a keyframe abandons an incomplete set.
- Keyframes are flagged by the presence of an access unit starting with an IDR
  NAL (type 5) or SPS/PPS prefix. Receivers MUST NOT decode inter frames
  before the first config + keyframe after connect.

The PC requests fps/bitrate/resolution via `screen.start`/`screen.configure`
(control channel); the phone MAY clamp values to device capability and MUST
report the actual values in the config frame.

### 2.7 Files channel (0x07)

JSON commands negotiate transfers; data uses binary frames:

- mtype 0x10 `data`: `[u32be transfer_id][u64be offset][≤65536 bytes]`
- Transfers are sequential per direction; `transfer_id` allocated by the
  sender of `files.push`/agreed in `files.pull` response.
- SHA-256 of the full file travels in the negotiation JSON; the receiver MUST
  verify and report `INVALID_ARGS`/hash mismatch on failure.
- Paths on the phone are restricted to: `Download/`, `DCIM/`, `Pictures/`,
  `Documents/` trees (scoped storage), unless the user granted all-files
  access, in which case absolute paths under external storage are allowed.
  The UI MUST show every completed transfer.

### 2.8 Heartbeat (0x09)

Both sides send mtype 0x01 `{"t":"ping","ts":<ms>}` every 5 s and answer
mtype 0x02 `{"t":"pong","ts":<echo>}`. No frame for 15 s = dead link: the
connection MUST be closed and reconnection started with exponential backoff
(0.5 s, doubling to 30 s max, forever until success or user disconnect).

## 3. Pairing, trust and confirmation code

1. PC generates QR: `dc1:` + base64url(JSON `{"v":1,"n":<16 random bytes b64url>,"p":<port>,"h":"<host or ip>","exp":<unix sec>,"name":"<pc name>"}`), shown for 120 s.
2. Phone scans, connects, runs Noise XX with mode byte `0x00` + nonce in prologue.
3. Both sides derive the confirmation code from the two static public keys:

   `code = base10(be32(SHA256("dc-confirm-v1" || min(pkA,pkB) || max(pkA,pkB))[0..3])) mod 1000000`, zero-padded to 6 digits
   (min/max bytewise lexicographic order).

4. The user compares the two codes and taps Confirm on **both** devices.
   Only then are the peer keys pinned (phone: Android Keystore-wrapped;
   PC: Windows Credential Manager). A mismatch means active MITM: user MUST
   abort; nothing is stored.
5. Manual mode (`0x01`): user types `ip:port` on the phone; flow is otherwise
   identical minus the QR nonce.

Failed-attempt lockout on the listener: token bucket 10 handshake
attempts/min per IP. More than 5 attempts that reach `hello` without a
completed pairing within 10 minutes locks the listener for 5 minutes
(doubling per further violation). The PC UI shows the countdown; the phone
shows a warning notification while locked.

Unpair (`security.unpair`, phone-confirmed by default) deletes the pinned key
on both sides and drops the connection. `security.rotate` regenerates the
local static keypair, deletes the pinned peer key and forces a fresh pairing.

## 4. Capabilities and sensitive actions

Capabilities, toggled on the phone, enforced on the phone:

`screen_view`, `input_control`, `notifications`, `messages`, `calls`,
`contacts`, `files`, `clipboard`.

A request using a disabled capability returns
`{"code":"CAPABILITY_DISABLED"}`. Capabilities default to off except
`status` (implicit, device name/battery/transport only).

Which capability a command needs is fixed, not left to each implementation: the
phone refuses a command whose capability is off, so a disagreement here is either
a security hole (a command runs with its switch off) or a permanently broken
command (it can never run). The mapping is:

| Commands | Capability |
| --- | --- |
| `clipboard.*` | `clipboard` |
| `screen.*` | `screen_view` |
| `input.*` | `input_control` |
| `notifications.*` | `notifications` |
| `sms.*` | `messages` |
| `calls.*` | `calls` |
| `files.*` | `files` |
| `app.*`, `screentext.*`, `wait.*` | deliberately unassigned (see below) |
| `status.*`, `caps.*`, `security.*` | none — must always be reachable |

`status.*`, `caps.*` and `security.*` need no capability: turning a capability
off must never lock the user out of turning it back on, and the phone must always
be able to say what it is.

`app.*`, `screentext.*` and `wait.*` are served by the same accessibility service
as `input.*`, but they read on-screen content instead of injecting events, so
whether they belong to `input_control`, `screen_view`, or both is left open until
that layer is specified. Clients MUST NOT assume either yet.

`contacts` is declared above but has no commands in v1.

A phone MUST refuse a capability it does not implement, rather than storing it,
advertising it in `hello`, and then failing every command that uses it. The reply
to `caps.set` is the effective map over every capability the phone implements, so
a client can tell "not supported here" from "supported but switched off" instead
of guessing from absences.

Sensitive commands MUST additionally return
`{"code":"CONFIRM_REQUIRED","actionId":"..."}` when the phone's confirmation
setting (default ON) demands it, and only execute after the user accepts on
the phone. The eventual result arrives as a normal response to the original
`id` (the socket stays open), or the caller may `files.cancel`/abandon.
Sensitive set (defaults): `sms.send`, `calls.dial`, `files.push` outside
`Download/`, `files.pull` outside shared dirs, `security.unpair`,
`security.rotate`, `app.install`. The phone can set each of these to
always / only-first-time / never confirm.

## 5. Commands and events (by channel)

### control (0x01)

| cmd | args | result |
|---|---|---|
| `screen.start` | `{width?,height?,fps?,bitrate?}` | `{width,height,fps,bitrate}` (actual) |
| `screen.stop` | `{}` | `{}` |
| `screen.configure` | `{width?,height?,fps?,bitrate?}` | same as start |
| `input.tap` | `{x,y}` px in current screen coords | `{}` |
| `input.longpress` | `{x,y,durMs?}` | `{}` |
| `input.swipe` | `{x1,y1,x2,y2,durMs?}` | `{}` |
| `input.scroll` | `{x,y,dx,dy}` | `{}` |
| `input.text` | `{text}` | `{}` |
| `input.key` | `{key}` one of `back,home,recents,power,volume_up,volume_down,enter,tab,escape,delete,space,arrow_up,arrow_down,arrow_left,arrow_right` | `{}` |
| `app.open` | `{package}` | `{}` |
| `app.list` | `{}` | `{apps:[{package,label,system:bool}]}` |
| `screentext.get` | `{}` | `{text, tree:[{id,bounds:[l,t,r,b],cls,text?,desc?,clickable?}]}` |
| `wait.screen` | `{timeoutMs}` | `{changed:bool,hash}` - resolves when UI tree hash changes or timeout |
| `security.unpair` | `{}` | `{}` (phone-confirmed) |
| `security.rotate` | `{}` | `{}` (phone-confirmed) |
| `caps.set` | `{caps:{<cap>:bool}}` | `{caps:{...}}` (phone-side only setter; PC may request) |

### notifications (0x03)

`notifications.list` -> `{items:[{key,app,title,text,postTime,actions:[{id,title}]}]}`,
`notifications.reply {key,actionId?,text}`, `notifications.dismiss {key}`;
events `notification.posted`, `notification.removed` with the same item shape.
Replies are routed through the original app's reply action (RCS/third-party
chats are reachable only this way).

### messages (0x04)

`sms.list {limit?,beforeId?}` -> `{items:[{id,address,name?,body,sent:bool,read:bool,time}]}`,
`sms.thread {address,limit?}` -> same, `sms.send {to,text}` (confirmable);
event `sms.received {id,address,body,time}`. MMS is not supported in v1.

### calls (0x05)

`calls.list {limit?}` -> `{items:[{id,number,name?,type,duration,time}]}`,
`calls.answer {id}`, `calls.reject {id}`, `calls.dial {number}` (confirmable);
events `call.incoming {id,number,name?}`, `call.state {id,state,duration?}`.
Call audio stays on the phone (platform limitation).

### clipboard (0x06)

`clipboard.get` -> `{text}`, `clipboard.set {text}` (≤ 1 MiB), event
`clipboard.changed {}` (content only on request, not pushed).

### files (0x07)

`files.push {path,size,sha256}` -> `{transferId}` (then data frames),
`files.pull {path}` -> `{transferId,size,sha256}` (then data frames),
`files.cancel {transferId}`, event `file.progress {transferId,bytes,total}`.

### status (0x08)

`status.get` -> `{battery:{pct,charging},screenOn,transport,uptimeMs,network:{type},storage:{freeBytes}}`;
event `status.changed` with the same shape, sent on meaningful change
(battery ±2%, screen on/off, transport switch).

### heartbeat (0x09)

`{"t":"ping"}` / `{"t":"pong"}` as in 2.8.

## 6. Error codes

`UNAUTHORIZED, NOT_PAIRED, CAPABILITY_DISABLED, CONFIRM_REQUIRED,
RATE_LIMITED, LOCKED_OUT, INVALID_ARGS, NOT_FOUND, BUSY, UNSUPPORTED,
TRANSPORT_ERROR, INTERNAL`. Any other code MUST be treated as `INTERNAL`.

## 7. Logging rules (all implementations)

Logs and analytics (there are none) MUST never contain: message bodies,
contact names/numbers, notification text, clipboard content, file names or
contents, keys, tokens, QR nonces, confirmation codes. Event name, size,
duration, error code and channel id are allowed.

## 8. Versioning and future platforms

`pv` is a single integer, incremented on any breaking change (framing,
handshake, command semantics). Additive, backwards-compatible changes (new
commands, new optional args, new channels) do NOT increment `pv`; receivers
ignore what they do not know. The QR prefix `dc1:` embeds the version, so a
future `dc2:` QR is visually distinct. macOS/Linux/iOS clients implement this
document plus `protocol/schema/` unchanged; only discovery (mDNS is
cross-platform), transport and the crypto library bindings are
platform-specific. See `protocol/README.md`.
