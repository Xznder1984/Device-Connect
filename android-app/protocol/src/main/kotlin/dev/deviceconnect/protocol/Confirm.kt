package dev.deviceconnect.protocol

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Pairing confirmation code (docs/protocol.md section 3.3).
 *
 * ```
 * code = base10(be32(SHA256("dc-confirm-v1" || min(pkA,pkB) || max(pkA,pkB))[0..4])) mod 1_000_000
 * ```
 *
 * Both sides compare the same code out-of-band; it commits to both static
 * public keys, so a man-in-the-middle that swapped keys produces different
 * codes on each device.
 */
object Confirm {
    private val LABEL = "dc-confirm-v1".toByteArray(StandardCharsets.UTF_8)

    /** Derive the six-digit code. Order of the two keys does not matter. */
    fun code(pkA: ByteArray, pkB: ByteArray): String {
        val aBefore = compareBytes(pkA, pkB) <= 0
        val lo = if (aBefore) pkA else pkB
        val hi = if (aBefore) pkB else pkA
        val md = MessageDigest.getInstance("SHA-256")
        md.update(LABEL)
        md.update(lo)
        md.update(hi)
        val digest = md.digest()
        val be = ((digest[0].toInt() and 0xFF) shl 24) or
            ((digest[1].toInt() and 0xFF) shl 16) or
            ((digest[2].toInt() and 0xFF) shl 8) or
            (digest[3].toInt() and 0xFF)
        val value = (be.toLong() and 0xFFFFFFFFL) % 1_000_000L
        return value.toString().padStart(6, '0')
    }

    /** Bytewise comparison, shorter array sorts first on a common prefix. */
    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        val len = minOf(a.size, b.size)
        for (i in 0 until len) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }
}
