package dev.deviceconnect.app.net

import android.content.Context
import android.util.Base64
import com.southernstorm.noise.crypto.Curve25519
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Device identity: a static X25519 keypair generated on first use and stored
 * encrypted under an Android Keystore master key (docs/protocol.md section 3).
 *
 * The private key never leaves the device in plaintext. [KeystoreCrypto] seals
 * it with a hardware-backed key, so a copy of the app's private storage is
 * useless on another device.
 */
class Identity private constructor(
    val privateKey: ByteArray,
    val publicKey: ByteArray,
) {
    /** First 8 bytes of SHA-256 of the static public key, as 16 lowercase hex. */
    val deviceId: String
        get() = deviceIdFromPublicKey(publicKey)

    companion object {
        private const val PREFS_NAME = "deviceconnect.identity"
        private const val KEY_PRIVATE = "privateKey"
        private const val KEY_PUBLIC = "publicKey"

        fun getOrCreate(context: Context): Identity {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val storedPrivate = prefs.getString(KEY_PRIVATE, null)
            val storedPublic = prefs.getString(KEY_PUBLIC, null)

            if (storedPrivate != null && storedPublic != null) {
                val restored = runCatching {
                    val privateKey = KeystoreCrypto.open(Base64.decode(storedPrivate, Base64.NO_WRAP))
                    val publicKey = Base64.decode(storedPublic, Base64.NO_WRAP)
                    if (publicKey.size != PUBLIC_KEY_BYTES) error("bad stored public key length")
                    Identity(privateKey, publicKey)
                }.getOrNull()
                // A Keystore entry can disappear (backup/restore, app data
                // cleared partially). Regenerating is the only safe recovery:
                // the peer simply pairs again.
                if (restored != null) return restored
            }

            return generate(context, prefs)
        }

        private fun generate(
            context: Context,
            prefs: android.content.SharedPreferences,
        ): Identity {
            val privateKey = ByteArray(PUBLIC_KEY_BYTES)
            SecureRandom().nextBytes(privateKey)
            val publicKey = ByteArray(PUBLIC_KEY_BYTES)
            Curve25519.eval(publicKey, 0, privateKey, null)

            val sealed = KeystoreCrypto.seal(privateKey)
            prefs.edit()
                .putString(KEY_PRIVATE, Base64.encodeToString(sealed, Base64.NO_WRAP))
                .putString(KEY_PUBLIC, Base64.encodeToString(publicKey, Base64.NO_WRAP))
                .apply()

            return Identity(privateKey, publicKey)
        }

        fun deviceIdFromPublicKey(publicKey: ByteArray): String {
            val hash = MessageDigest.getInstance("SHA-256").digest(publicKey)
            return hash.take(8).joinToString("") { "%02x".format(it) }
        }

        private const val PUBLIC_KEY_BYTES = 32
    }
}
