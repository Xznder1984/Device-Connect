package dev.deviceconnect.app.net

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.southernstorm.noise.crypto.Curve25519
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Device identity: a static X25519 keypair generated on first use and stored
 * encrypted under an Android Keystore master key (docs/protocol.md section 3).
 *
 * The private key never leaves the device in plaintext. The Android Keystore
 * master key is hardware-backed where available, so the encrypted private key
 * is useless if copied to another device.
 */
class Identity private constructor(
    val privateKey: ByteArray,
    val publicKey: ByteArray,
) {
    /** First 8 bytes of SHA-256 of the static public key, as 16 lowercase hex. */
    val deviceId: String
        get() = deviceIdFromPublicKey(publicKey)

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEYSTORE_ALIAS = "deviceconnect.identity"
        private const val PREFS_NAME = "deviceconnect.identity"
        private const val KEY_PRIVATE = "privateKey"
        private const val KEY_PUBLIC = "publicKey"
        private const val GCM_TAG_BITS = 128
        private const val GCM_IV_BYTES = 12

        fun getOrCreate(context: Context): Identity {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val storedPrivate = prefs.getString(KEY_PRIVATE, null)
            val storedPublic = prefs.getString(KEY_PUBLIC, null)

            if (storedPrivate != null && storedPublic != null) {
                val privateKey = decryptKeystore(Base64.decode(storedPrivate, Base64.NO_WRAP))
                val publicKey = Base64.decode(storedPublic, Base64.NO_WRAP)
                return Identity(privateKey, publicKey)
            }

            val privateKey = ByteArray(32)
            SecureRandom().nextBytes(privateKey)
            val publicKey = ByteArray(32)
            Curve25519.eval(publicKey, 0, privateKey, null)

            val encrypted = encryptKeystore(privateKey)
            prefs.edit()
                .putString(KEY_PRIVATE, Base64.encodeToString(encrypted, Base64.NO_WRAP))
                .putString(KEY_PUBLIC, Base64.encodeToString(publicKey, Base64.NO_WRAP))
                .apply()

            return Identity(privateKey, publicKey)
        }

        fun deviceIdFromPublicKey(publicKey: ByteArray): String {
            val hash = MessageDigest.getInstance("SHA-256").digest(publicKey)
            return hash.take(8).joinToString("") { "%02x".format(it) }
        }

        private fun getOrCreateMasterKey(): SecretKey {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            (keyStore.getKey(KEYSTORE_ALIAS, null) as? SecretKey)?.let { return it }

            val generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE,
            )
            generator.init(
                KeyGenParameterSpec.Builder(
                    KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
            return generator.generateKey()
        }

        private fun encryptKeystore(plaintext: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateMasterKey())
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext)
            return iv + ciphertext
        }

        private fun decryptKeystore(data: ByteArray): ByteArray {
            val iv = data.sliceArray(0 until GCM_IV_BYTES)
            val ciphertext = data.sliceArray(GCM_IV_BYTES until data.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateMasterKey(),
                GCMParameterSpec(GCM_TAG_BITS, iv),
            )
            return cipher.doFinal(ciphertext)
        }
    }
}
