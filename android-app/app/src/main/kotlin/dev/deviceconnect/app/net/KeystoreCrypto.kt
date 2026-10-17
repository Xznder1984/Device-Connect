package dev.deviceconnect.app.net

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-GCM sealing under a single Android Keystore master key.
 *
 * Two things live behind this: the device's static Noise private key
 * ([Identity]) and the pinned peer public key plus its display name
 * ([TrustStore]). Both are secrets of the pairing, and neither may be readable
 * if the app's private storage is copied off the device, so both are sealed with
 * a key that the Keystore will not export.
 *
 * The master key is hardware-backed where the device supports it. The output
 * layout is `iv || ciphertext || tag`; the Android Keystore always uses a 12-byte
 * GCM IV, but this code reads the IV length from the produced data rather than
 * assuming it, so a future Keystore change cannot silently break decryption.
 */
object KeystoreCrypto {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "deviceconnect.master"
    private const val GCM_TAG_BITS = 128
    private const val IV_BYTES = 12

    /** Encrypt [plaintext] into `iv || ciphertext`. */
    fun seal(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, masterKey())
        val iv = cipher.iv
        return iv + cipher.doFinal(plaintext)
    }

    /**
     * Decrypt data produced by [seal].
     *
     * @throws javax.crypto.AEADBadTagException if the data was tampered with or
     *   was sealed under a different master key (for example, after the user
     *   clears app data and the Keystore entry is regenerated).
     */
    fun open(data: ByteArray): ByteArray {
        require(data.size > IV_BYTES) { "sealed data too short" }
        val iv = data.copyOfRange(0, IV_BYTES)
        val ciphertext = data.copyOfRange(IV_BYTES, data.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, masterKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    private fun masterKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private const val TRANSFORMATION = "AES/GCM/NoPadding"
}
