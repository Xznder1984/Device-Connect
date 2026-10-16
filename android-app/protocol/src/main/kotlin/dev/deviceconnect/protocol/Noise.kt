package dev.deviceconnect.protocol

import com.southernstorm.noise.protocol.CipherState
import com.southernstorm.noise.protocol.CipherStatePair
import com.southernstorm.noise.protocol.HandshakeState

/**
 * Noise transport helpers (docs/protocol.md section 2.2).
 *
 * The handshake is `Noise_XX_25519_ChaChaPoly_SHA256`, implemented by the
 * vendored MIT-licensed `rweather/noise-java` library. There is no custom
 * cryptography here: the prologue, parameter string and key handling follow the
 * spec exactly, and are checked against the golden vectors in
 * `protocol/test-vectors/noise-kat.json`.
 */
object Noise {
    /** The only handshake pattern and parameter set this protocol uses. */
    const val PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_SHA256"

    /** Generous upper bound for one handshake message (xx stays well under this). */
    const val MAX_MESSAGE = 4096

    /**
     * Build a handshake state that has already mixed in the prologue and its
     * own static key, so the caller can drive [HandshakeState.writeMessage] /
     * [HandshakeState.readMessage] directly.
     *
     * @param role [HandshakeState.INITIATOR] or [HandshakeState.RESPONDER].
     * @param prologue Prologue bytes; see `prologue()` in the Rust crate.
     * @param staticPrivate This side's 32-byte static private key.
     * @param fixedEphemeralPrivate TEST ONLY: pins the ephemeral key so the
     *   handshake transcript is reproducible. Never supply this in real code;
     *   ephemerals must be random.
     */
    fun handshake(
        role: Int,
        prologue: ByteArray,
        staticPrivate: ByteArray,
        fixedEphemeralPrivate: ByteArray? = null,
    ): HandshakeState {
        val state = HandshakeState(PROTOCOL_NAME, role)
        state.setPrologue(prologue, 0, prologue.size)
        state.getLocalKeyPair().setPrivateKey(staticPrivate, 0)
        if (fixedEphemeralPrivate != null) {
            val fixed = state.getFixedEphemeralKey()
                ?: throw ProtocolException("NoEphemeralInPattern")
            fixed.setPrivateKey(fixedEphemeralPrivate, 0)
        }
        state.start()
        return state
    }

    /** Write the next handshake message carrying [payload]. */
    fun write(state: HandshakeState, payload: ByteArray): ByteArray {
        val buf = ByteArray(MAX_MESSAGE)
        val n = state.writeMessage(buf, 0, payload, 0, payload.size)
        if (n < 0) throw ProtocolException("MessageTooLarge")
        return buf.copyOf(n)
    }

    /** Read the next handshake message, returning its payload. */
    fun read(state: HandshakeState, message: ByteArray): ByteArray {
        val payload = ByteArray(MAX_MESSAGE)
        val n = state.readMessage(message, 0, message.size, payload, 0)
        if (n < 0) throw ProtocolException("Incomplete")
        return payload.copyOf(n)
    }

    /** The peer's static public key, once the handshake has completed. */
    fun remoteStatic(state: HandshakeState): ByteArray {
        val remote = state.getRemotePublicKey() ?: throw ProtocolException("RemoteUnknown")
        val out = ByteArray(remote.getPublicKeyLength())
        remote.getPublicKey(out, 0)
        return out
    }

    /** Convert a completed handshake into directional transport ciphers. */
    fun transport(state: HandshakeState): NoiseTransport {
        val pair: CipherStatePair = state.split()
        return NoiseTransport(pair.getSender(), pair.getReceiver(), remoteStatic(state))
    }
}

/**
 * Bidirectional Noise transport session.
 *
 * [sender] encrypts what this side emits and [receiver] decrypts what the peer
 * emits. Each direction has its own key and strictly increasing nonce, so the
 * same plaintext never encrypts to the same bytes.
 */
class NoiseTransport(
    private val sender: CipherState,
    private val receiver: CipherState,
    val remoteStatic: ByteArray,
) {
    fun encrypt(plaintext: ByteArray): ByteArray {
        val out = ByteArray(plaintext.size + sender.getMACLength())
        val n = try {
            sender.encryptWithAd(null, plaintext, 0, out, 0, plaintext.size)
        } catch (e: Exception) {
            throw ProtocolException("TransportError")
        }
        if (n < 0) throw ProtocolException("TransportError")
        return if (n == out.size) out else out.copyOf(n)
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        if (ciphertext.size < receiver.getMACLength()) throw ProtocolException("TransportError")
        val out = ByteArray(ciphertext.size)
        val n = try {
            receiver.decryptWithAd(null, ciphertext, 0, out, 0, ciphertext.size)
        } catch (e: Exception) {
            // A failing tag means tampering or a desynchronized nonce; never
            // return partial data.
            throw ProtocolException("TransportError")
        }
        if (n < 0) throw ProtocolException("TransportError")
        return if (n == out.size) out else out.copyOf(n)
    }

    fun destroy() {
        sender.destroy()
        receiver.destroy()
    }
}
