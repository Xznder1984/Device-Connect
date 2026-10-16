package dev.deviceconnect.protocol

/**
 * Error codes carried by failed responses (docs/protocol.md section 5.2).
 *
 * The set is closed and mirrors `envelope.schema.json#/$defs/errorCode` and the
 * Rust `ErrorCode` enum. Adding a value requires updating the schema, the Rust
 * enum, this list, and the TypeScript conformance suite together.
 */
enum class ErrorCode(val wire: String) {
    UNAUTHORIZED("UNAUTHORIZED"),
    NOT_PAIRED("NOT_PAIRED"),
    CAPABILITY_DISABLED("CAPABILITY_DISABLED"),
    CONFIRM_REQUIRED("CONFIRM_REQUIRED"),
    RATE_LIMITED("RATE_LIMITED"),
    LOCKED_OUT("LOCKED_OUT"),
    INVALID_ARGS("INVALID_ARGS"),
    NOT_FOUND("NOT_FOUND"),
    BUSY("BUSY"),
    UNSUPPORTED("UNSUPPORTED"),
    TRANSPORT_ERROR("TRANSPORT_ERROR"),
    INTERNAL("INTERNAL");

    companion object {
        fun fromWire(value: String): ErrorCode? = entries.firstOrNull { it.wire == value }
    }
}
