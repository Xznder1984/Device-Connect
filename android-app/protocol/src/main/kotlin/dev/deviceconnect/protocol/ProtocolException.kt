package dev.deviceconnect.protocol

/**
 * A protocol-level failure with a stable machine code.
 *
 * The [code] values are the ones the golden vectors in
 * `protocol/test-vectors/` assert against, and they match the Rust crate's
 * error variants (`protocol/rust`). Keep them in sync across platforms.
 */
class ProtocolException(val code: String) : Exception(code)
