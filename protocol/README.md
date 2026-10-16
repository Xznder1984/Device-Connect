# Device Connect Protocol (shared specification)

This directory is the single source of truth for the wire protocol between
the Windows app, the Android app, and any future macOS/Linux/iOS client.

| Path | Contents |
|---|---|
| `schema/` | JSON Schemas (draft 2020-12) for every message on the wire |
| `test-vectors/` | Golden vectors: framing, QR payloads, confirmation codes, Noise handshake KAT, schema fixtures |
| `rust/` | Reference codec crate `dc-protocol` (used by the Windows app), includes generator for the Noise/confirm vectors |
| `conformance/ts/` | TypeScript conformance tests (framing, QR, schema) run with `node --test` |

The Kotlin implementation lives in `android-app/protocol/` (module
`dc-protocol`) and runs the same vectors from this directory. The Rust
implementation runs them from `protocol/rust/tests/`.

## Implementing the protocol

1. Read `docs/protocol.md` (normative).
2. Validate your messages against `schema/*.schema.json`.
3. Run the golden vectors: your codec must produce and accept every "valid"
   vector byte-for-byte and reject every "invalid" vector with the stated
   reason.

## Adding a new platform (macOS, Linux, iOS, ...)

The protocol is platform-neutral by design. A new client needs only:

- a TCP socket (all platforms) and optionally RFCOMM/BLE (where available),
- an mDNS implementation for `_deviceconnect._tcp.local.`,
- a Noise XX (25519/ChaChaPoly/SHA256) library,
- the schemas in `schema/` and the vectors in `test-vectors/`.

No changes to this directory are required. Put the new client in
`platform/<name>/` (existing apps stay in `android-app/`, `windows-app/`).
Breaking changes increment the protocol version `pv` and the QR prefix
(`dc1:` -> `dc2:`); additive changes do not bump `pv` and receivers must
ignore unknown commands and channels.

## Stability rules

- `pv` 1 is frozen: no breaking edits to framing, handshake or command
  semantics. Corrections that clarify without changing bytes are allowed.
- New commands/fields/channels are added in separate schema files or as
  additive `oneOf` entries, never by reusing an existing name differently.
- The test vectors are append-only; a broken vector means an
  implementation bug, not a vector bug.
