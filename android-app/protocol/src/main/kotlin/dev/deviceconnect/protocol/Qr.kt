package dev.deviceconnect.protocol

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Pairing QR payload (docs/protocol.md section 3.1).
 *
 * Text form: `dc1:` + base64url(utf8(JSON)) without padding.
 *
 * Field order here is significant: it is the serialization order and the
 * golden vectors compare the exact encoded string.
 */
data class QrPayload(
    val v: Int,
    val n: String,
    val p: Int,
    val h: String? = null,
    val exp: Long,
    val name: String? = null,
)

/** Thrown with a stable [ProtocolException.code] describing the QR failure. */
typealias QrException = ProtocolException

object Qr {
    const val PREFIX = "dc1:"
    const val VALIDITY_SECS = 120L
    const val NONCE_LEN = 16

    /** 16 nonce bytes encode to 22 base64url characters. */
    const val NONCE_CHARS = 22

    private val gson: Gson = GsonBuilder().create()
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun encode(payload: QrPayload): String {
        val json = gson.toJson(payload).toByteArray(StandardCharsets.UTF_8)
        return PREFIX + encoder.encodeToString(json)
    }

    /**
     * Decode and structurally validate a scanned string.
     *
     * Expiry is not checked here: callers use [isExpired] so "expired" can be
     * reported distinctly from "malformed". Codes: `BadPrefix`, `BadBase64`,
     * `BadJson`, `BadField`.
     */
    fun decode(text: String): QrPayload {
        val trimmed = text.trim()
        if (!trimmed.startsWith(PREFIX)) throw ProtocolException("BadPrefix")
        val body = trimmed.substring(PREFIX.length)
        val json = try {
            String(decoder.decode(body), StandardCharsets.UTF_8)
        } catch (_: IllegalArgumentException) {
            throw ProtocolException("BadBase64")
        }
        val payload = try {
            gson.fromJson(json, QrPayload::class.java) ?: throw ProtocolException("BadField")
        } catch (e: ProtocolException) {
            throw e
        } catch (_: Exception) {
            throw ProtocolException("BadJson")
        }
        if (payload.v != 1) throw ProtocolException("BadField")
        if (payload.p < 1 || payload.p > 65535) throw ProtocolException("BadField")
        if (payload.n.length != NONCE_CHARS) throw ProtocolException("BadField")
        if (nonceBytes(payload).size != NONCE_LEN) throw ProtocolException("BadField")
        return payload
    }

    /** The nonce as raw bytes; feeds the Noise prologue. */
    fun nonceBytes(payload: QrPayload): ByteArray {
        val raw = try {
            decoder.decode(payload.n)
        } catch (_: IllegalArgumentException) {
            throw ProtocolException("BadField")
        }
        if (raw.size != NONCE_LEN) throw ProtocolException("BadField")
        return raw
    }

    /** True when the payload is expired at [nowSecs] on the local clock. */
    fun isExpired(payload: QrPayload, nowSecs: Long): Boolean = nowSecs > payload.exp
}
