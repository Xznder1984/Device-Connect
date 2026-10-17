package dev.deviceconnect.app.net

import android.content.Context
import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * The one PC this phone has been paired with (v1 pairs a single peer, which is
 * all "control my own phone" needs; a future version can hold a set keyed by id).
 *
 * Everything here is sealed with [KeystoreCrypto] before it touches disk. The
 * peer's display name comes from the PC, so it can be personal ("Alice's
 * laptop"); sealing it keeps it out of reach of a backup dump, and nothing in
 * this class is ever logged.
 *
 * Pinning happens only after the user compares the six-digit confirmation code
 * on both devices and taps Confirm (docs/protocol.md section 3.4), so this type
 * never decides trust by itself.
 */
class TrustStore(context: Context) {

    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * A pinned peer. [publicKey] is the peer's 32-byte static X25519 key, the
     * exact bytes the Noise handshake must reproduce.
     */
    class Peer(
        val id: String,
        val name: String,
        val publicKey: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Peer && id == other.id && name == other.name &&
                publicKey.contentEquals(other.publicKey)

        override fun hashCode(): Int =
            (id.hashCode() * 31 + name.hashCode()) * 31 + publicKey.contentHashCode()

        override fun toString(): String = "Peer(id=$id, name=$name)"
    }

    /** The pinned peer, or null when this device has not been paired yet. */
    fun pinned(): Peer? {
        val stored = prefs.getString(KEY_PEER, null) ?: return null
        return runCatching {
            val raw = KeystoreCrypto.open(Base64.decode(stored, Base64.NO_WRAP))
            decode(raw)
        }.getOrNull()
    }

    /** Remember [peer] as the trusted PC. Overwrites any previous pairing. */
    fun pin(peer: Peer) {
        val sealed = KeystoreCrypto.seal(encode(peer))
        prefs.edit().putString(KEY_PEER, Base64.encodeToString(sealed, Base64.NO_WRAP)).apply()
    }

    /** Forget the pinned peer. This is the phone side of `security.unpair`. */
    fun clear() {
        prefs.edit().remove(KEY_PEER).apply()
    }

    private fun encode(peer: Peer): ByteArray {
        val id = peer.id.toByteArray(Charsets.UTF_8)
        val name = peer.name.toByteArray(Charsets.UTF_8)
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            d.writeByte(FORMAT_VERSION)
            d.writeInt(id.size)
            d.write(id)
            d.writeInt(name.size)
            d.write(name)
            d.writeInt(peer.publicKey.size)
            d.write(peer.publicKey)
        }
        return out.toByteArray()
    }

    private fun decode(raw: ByteArray): Peer {
        DataInputStream(ByteArrayInputStream(raw)).use { d ->
            val version = d.readUnsignedByte()
            require(version == FORMAT_VERSION) { "unsupported trust record version" }
            val id = String(ByteArray(readCheckedLength(d)).also { d.readFully(it) }, Charsets.UTF_8)
            val name = String(ByteArray(readCheckedLength(d)).also { d.readFully(it) }, Charsets.UTF_8)
            val key = ByteArray(readCheckedLength(d)).also { d.readFully(it) }
            require(key.size == PUBLIC_KEY_BYTES) { "bad peer public key length" }
            return Peer(id, name, key)
        }
    }

    /** Guard against a corrupt record asking for a multi-megabyte allocation. */
    private fun readCheckedLength(d: DataInputStream): Int {
        val len = d.readInt()
        require(len in 0..MAX_FIELD_BYTES) { "corrupt trust record" }
        return len
    }

    private companion object {
        const val PREFS = "deviceconnect.trust"
        const val KEY_PEER = "peer"
        const val FORMAT_VERSION = 1
        const val PUBLIC_KEY_BYTES = 32
        const val MAX_FIELD_BYTES = 256
    }
}
