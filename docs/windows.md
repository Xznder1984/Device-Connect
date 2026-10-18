# Windows app internals (`windows-app/`)

The PC side of Device Connect: the listener, the Noise responder, the trust
store and the consent gate. The module layout and build commands are in
`windows-app/README.md`; this file is the status, the connection model, and the
honest list of what is not built.

---

## Status

Anything marked Pending is **not shipped** and is not claimed to work. Anything
marked Implemented has been compiled and run on Windows.

| Area | State |
| --- | --- |
| `dc-client`: 27 unit tests + 9 end-to-end tests over a real loopback socket | Implemented, `cargo test` green |
| PC identity: X25519 key, id derived from the key (never chosen) | Implemented |
| Pairing window: QR payload, fresh nonce, expiry, manual-mode address | Implemented |
| Noise XX as responder, `hello`/`hello_ack`, version refusal | Implemented |
| Trust list: pin, refresh name, unpin, corrupt-entry and future-version refusal | Implemented |
| Confirmation code derived from both static keys | Implemented |
| `PendingSession` -> `confirm()` / `reject()`; nothing answered before that | Implemented |
| Requests on the control channel, refusals as answers, unknown command handling | Implemented |
| `security.unpair` in both directions | Implemented |
| Session listener + QR pairing listener + mDNS advertisement | Pending (Phase 3b; see "The prologue fixes the mode") |
| Tauri shell and React UI | Pending |
| Heartbeat / dead-link detection (`ping`/`pong`) | Pending on both sides; the reply timeout is the only detection today |
| Listener rate limit and lockout (section 3.4) | Pending |
| Windows Credential Manager for the long-term key | Implemented (`CredManSecretStore`; the file store stays for headless runs and tests) |
| Windows Firewall allowance | Not yet exercised; the shell will be the first thing that binds a listener |

`dc-client` speaks the clipboard-only vocabulary the phone implements today
(`docs/android.md`). The other capability families in `docs/protocol.md`
section 4 have no PC-side code and no PC-side UI, so nothing pretends to offer
them.

---

## Connection model

`docs/protocol.md` section 2.1 lets either side listen, with a tie-break if both
do. In v1 the phone always dials and the PC always listens (`docs/android.md`,
"Connection model"), so:

- `Listener::bind(port)` is the only socket the PC ever opens. Port 0 asks
  Windows for a free port, and that port is what the QR payload carries.
- The PC is the Noise **responder**. The phone sends `hello` first, so the
  responder never speaks into a connection before the caller has.
- `accept()` returns a `PendingSession`, and the caller owns it. Running a
  listener loop or accepting more than one phone at a time is the shell's
  business, not this library's.

### The prologue fixes the mode, so each mode needs its own listener

Both sides mix the same prologue into the handshake before the first message
(section 2.2). It is `"device-connect/v1\0"` plus `0x00` and the QR nonce, or
plus `0x01` alone for manual and mDNS mode. Because it is fixed before anything
is read, one listening socket can serve exactly one of the two.

The phone already works this way: `qrPrologue(nonce)` when the user scanned a
code, `manualPrologue()` for a typed address, mDNS, or a reconnect
(`android-app/app/src/main/kotlin/dev/deviceconnect/app/service/Session.kt`). The
PC therefore runs two listeners in Phase 3b:

| Listener | Prologue | Serves | Port |
| --- | --- | --- | --- |
| Session | `0x01` | Pinned phones reconnecting, typed addresses | Stable; shown in the app and in the mDNS record |
| Pairing window | `0x00` + nonce | The QR the user just scanned | A second port, carried in the QR's `p` field |

Splitting them is what keeps a pinned phone able to reconnect while a new phone
is being paired. `SessionConfig::with_offer(&offer)` is what binds a connection
to a window's mode; the library does not decide which listener to run.

### The pairing window

`PairingOffer` is one window, in one of two modes:

- `PairingOffer::qr(port, host, name)` mints a fresh 16-byte nonce and renders
  `dc1:<base64url JSON>` with `v`, `n`, `p`, `h`, `exp` and `name`. The nonce is
  the point of the window: a QR photographed during an earlier window cannot be
  replayed against a later one, because the prologue it is bound to no longer
  matches. `exp` (120 s) lets the phone refuse a stale payload on its own.
- `PairingOffer::manual(port, host, name)` has no nonce and the bare `0x01`
  prologue. `address()` returns the `host:port` the user types on the phone.

Expiry is a caller-side check (`offer.is_expired(now)`), not something the
library enforces behind the caller's back: opening and closing the window is the
app's business, and closing the listener is what actually ends it.

### Consent, in order

```text
TcpStream --accept()--> PendingSession --confirm()--> ActiveSession
                                    \--reject()---> closed, nothing stored
```

1. Handshake and `hello`. A `pv` this build does not speak gets an unsolicited
   `UNSUPPORTED` error frame and then the connection is dropped, before any other
   traffic (section 2.2). A peer we cannot talk to is never shown a code.
2. `hello_ack` carries the PC's own `caps` (empty: this build offers no PC-side
   capability) and `paired`.
3. `PendingSession` knows the phone's key, name, model, OS, advertised
   capabilities and the six-digit code, and answers **nothing**. The key the user
   is about to trust came out of the handshake, so a name on the screen cannot be
   hung on someone else's key.
4. `confirm()` pins the key; `reject()` closes the socket. `paired_at` is written
   once: a reconnecting phone refreshes its stored name and never moves the
   timestamp that records the user's decision.
5. Requests flow on the control channel. A refusal (`ok: false` plus
   `CAPABILITY_DISABLED`) is an **answer**, not an error: the phone behaved
   correctly, and the session stays usable. `SessionError::Refused` is only for
   an unsolicited error frame, which ends the connection.

`security.unpair` is the revocation path in both directions, and it is acted on
before it is answered: the key is deleted from the trust list first, then the
reply is written, then the session ends (`SessionError::Unpaired`). The phone's
`CommandHandlers.unpair` does the same thing in the same order, so a reply that
never arrives cannot leave either side still paired. An inbound command that is
not `security.unpair` is refused as a response to *that* request
(`UNSUPPORTED`), which keeps a pending request from being held hostage by it.

---

## One Windows detail that is easy to get wrong

A read timeout has to be set on the handle that reads. On Windows a socket from
`TcpStream::try_clone` does not carry `SO_RCVTIMEO` with it, and every read here
goes through the clone that `WireStream` owns. Measured on the development
machine:

| Timeout set on | Read performed by | Result |
| --- | --- | --- |
| the original stream | the clone | waited 998 ms for a peer that lived 1000 ms, then reported end of stream |
| the clone | the clone | gave up after 162 ms with `TimedOut` |

The first row is the dangerous one: the timeout silently does nothing, and a
phone that has gone away looks like an app that has hung. `Connection::set_read_timeout`
therefore always goes through `wire.reader`, and the test phone in
`tests/loopback.rs` does the same.

Treating a timed-out read as terminal follows from the same place: the read may
have consumed part of a record, so a retry would splice two records together.
`SessionError::Timeout` means the caller must drop the session, not retry it.

---

## Secrets

| What | Where |
| --- | --- |
| PC long-term key | Windows Credential Manager, entry `Device Connect:pc-identity-v1` (`CredManSecretStore`) |
| Pinned phones | `%APPDATA%\Device Connect\trusted-phones.json` (`FileTrustStore`) |

The shell calls `default_secret_store()`, which on Windows is the Credential
Manager. `FileSecretStore` (`%LOCALAPPDATA%\Device Connect\secrets`) is still
there and is what the tests and any headless run use.

What the Credential Manager buys, precisely: the key is encrypted at rest with
the user's DPAPI keys, it is not a file that a backup, a sync client or a
`dir /s` can pick up, and the user can see and delete it in the Windows UI. What
it does **not** buy: any separation between programs. Any process running as the
same user can `CredReadW` the same target name, so it does not stop malware that
is already running as that user. It raises the cost of a stolen disk, a roamed
profile or a second account on the machine. That is the whole claim.

Two API limits are handled rather than run into. An entry holds at most 2560
bytes, which the code checks by name and size instead of passing to the API and
getting a bare failure. And the API needs a logon session, so a service or a task
running as another account is reported as `ERROR_NO_SUCH_LOGON_SESSION` rather
than mistaken for "no key yet"; `CredManSecretStore::probe()` can check that at
startup, before the PC tries to save the key that makes it itself.

One migration note, from the earlier file-only state: an existing
`%LOCALAPPDATA%\Device Connect\secrets\pc-identity-v1.bin` is **not** imported.
The Credential Manager starts empty, so the PC would generate a second identity
and every phone that pinned the first one would refuse it. Nothing shipped that
wrote that file - it is what tests and headless runs used - but if it is there,
delete it rather than leave two identities around.

The trust list stays a file on purpose: it holds public keys, not secrets.

Both stores write through a temporary file and a rename, so a crash leaves the
previous contents rather than a truncated key or an emptied trust list. Secret
names are stripped to `[A-Za-z0-9_-]`, so no name can escape the directory.

An unconfirmed pairing writes nothing anywhere: no key is pinned, no file is
touched.

---

## Tests

Two kinds:

- **Unit tests** in `windows-app/core/src/*.rs`: pure functions, the two file
  stores against a temporary directory, and the Credential Manager store against
  the real vault under names only that test uses. They cover key derivation and
  the id, the trust list refusing a hand-edited entry or a future file version,
  the pairing window's nonce and prologue, store-name sanitising, and for the
  vault: round trip, replace, delete (twice), the 2560-byte boundary on both
  sides, a name that cannot be represented, and that the default store really is
  the Credential Manager.
- **`windows-app/core/tests/loopback.rs`**: both sides of a real TCP connection
  on 127.0.0.1, with a phone written directly against `dc-protocol` rather than
  out of `dc-client` helpers. Sharing the session code would only prove that the
  code agrees with itself; going through the shared codec instead exercises the
  bytes that would cross a network. It also derives the phone's public key
  without `dc-client`, so "the PC saw the right key" is checked across two paths
  through the same curve rather than inside one.

The nine end-to-end cases:

1. a new phone is offered a code and is pinned only by `confirm()`;
2. a disabled capability comes back as a refusal, and the session stays usable;
3. a pinned phone reconnects with `paired: true` and its `paired_at` does not move;
4. `reject()` leaves the trust list empty and the phone sees the close;
5. a missing reply ends in `Timeout` instead of hanging;
6. a `pv` mismatch gets `UNSUPPORTED` plus `ProtocolMismatch`;
7. unpair from the PC deletes the key and closes;
8. unpair from the phone is acted on before it is answered;
9. an unknown command is refused while the pending request still gets its answer.

What these do **not** cover: the Android app itself. The phone here is a test
double that speaks the same implementation and the same golden vectors, which is
why it is worth having, but a run against a live device is Phase 4.

---

## Pending

Each of these is a real gap, not a stub with a friendly name:

1. **Listener rate limit and lockout.** Section 3.4 asks for a token bucket of 10
   handshake attempts per minute per IP, and for locking out a peer that reaches
   `hello` more than 5 times in 10 minutes without completing a pairing. Neither
   exists, so anything on the network can make this PC run handshakes as fast as
   it can send them. That matters on a network the user does not control.
2. **Heartbeat.** `ping`/`pong` on channel `0x09` is not implemented on either
   side, so a link that dies without a FIN is only noticed when a request next
   times out.
3. **Tauri shell, React UI, session listener, QR pairing listener, mDNS
   advertisement.** Until mDNS advertises, the phone's "find the PC" path has
   nothing to find, and the only ways to pair are a typed `ip:port` or a QR whose
   port the shell has to bind.
4. **Windows Firewall.** The first bind will raise a firewall prompt; allowing it
   for the private network is what lets the phone in. Untested here because no
   shell binds yet.
