package dev.deviceconnect.protocol

import com.southernstorm.noise.protocol.HandshakeState
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Conformance against `protocol/test-vectors/noise-kat.json`.
 *
 * The vectors were produced by the Rust `snow` implementation with fixed keys,
 * so if noise-java reproduces them byte for byte then both platforms build the
 * identical transcript. Fixed ephemerals exist for testing only; production
 * handshakes use random ephemerals (also exercised below).
 */
internal class NoiseKatTest {

    private val kat = TestVectors.load("noise-kat.json")
    private val prologue = TestVectors.hex(kat.get("prologueHex").asString)
    private val transportText = "ping-from-initiator".toByteArray(Charsets.UTF_8)

    private fun startHandshake(role: Int, staticKey: String, ephemeralKey: String?): HandshakeState =
        Noise.handshake(
            role = role,
            prologue = prologue,
            staticPrivate = TestVectors.hex(kat.get(staticKey).asString),
            fixedEphemeralPrivate = ephemeralKey?.let { TestVectors.hex(kat.get(it).asString) },
        )

    private fun fixedPair(): Pair<HandshakeState, HandshakeState> = Pair(
        startHandshake(HandshakeState.INITIATOR, "initiatorStaticPrivHex", "initiatorEphPrivHex"),
        startHandshake(HandshakeState.RESPONDER, "responderStaticPrivHex", "responderEphPrivHex"),
    )

    /**
     * Drive the three-message XX handshake.
     *
     * `-> e` / `<- e, ee, s, es` / `-> s, se`. Payloads are empty, so each
     * message's trailing AEAD tag is still present.
     *
     * @return (message 1, message 2, message 3)
     */
    private fun driveHandshake(
        initiator: HandshakeState,
        responder: HandshakeState,
    ): Triple<ByteArray, ByteArray, ByteArray> {
        val msg1 = Noise.write(initiator, ByteArray(0))
        Noise.read(responder, msg1)

        val msg2 = Noise.write(responder, ByteArray(0))
        Noise.read(initiator, msg2)

        val msg3 = Noise.write(initiator, ByteArray(0))
        Noise.read(responder, msg3)

        return Triple(msg1, msg2, msg3)
    }

    @Test
    fun expectedProtocolAndPrologue() {
        assertEquals(
            kat.get("params").asString,
            Noise.PROTOCOL_NAME,
            "the parameter string must match the other platforms",
        )

        // "device-connect/v1" + NUL + mode byte 0x00 (QR present) + 16-byte QR nonce.
        assertEquals(35, prologue.size, "prologue length")
        assertEquals(
            "6465766963652d636f6e6e6563742f7631",
            TestVectors.unhex(prologue.copyOfRange(0, 17)),
            "prologue label",
        )
        assertEquals(0, prologue[17].toInt(), "label NUL terminator")
        assertEquals(0, prologue[18].toInt(), "QR-present mode byte")

        val qrNonce = TestVectors.load("qr.json")
            .getAsJsonArray("valid")[0].asJsonObject.get("nonceHex").asString
        assertEquals(
            qrNonce,
            TestVectors.unhex(prologue.copyOfRange(19, prologue.size)),
            "the nonce encoded in the QR is mixed into the prologue",
        )
    }

    @Test
    fun handshakeMessagesMatchTheVector() {
        val (initiator, responder) = fixedPair()
        val (msg1, msg2, msg3) = driveHandshake(initiator, responder)

        assertEquals(kat.get("msg1Hex").asString, TestVectors.unhex(msg1), "message 1")
        assertEquals(32, msg1.size, "message 1 carries one ephemeral public key")
        assertEquals(kat.get("msg2Hex").asString, TestVectors.unhex(msg2), "message 2")
        assertEquals(kat.get("msg3Hex").asString, TestVectors.unhex(msg3), "message 3")

        assertEquals(HandshakeState.SPLIT, initiator.getAction(), "initiator finished")
        assertEquals(HandshakeState.SPLIT, responder.getAction(), "responder finished")
    }

    @Test
    fun bothSidesLearnThePinnedStaticPublicKeys() {
        val (initiator, responder) = fixedPair()
        driveHandshake(initiator, responder)

        assertArrayEquals(
            TestVectors.hex(kat.get("responderStaticPubHex").asString),
            Noise.remoteStatic(initiator),
            "initiator pins the responder's static public key",
        )
        assertArrayEquals(
            TestVectors.hex(kat.get("initiatorStaticPubHex").asString),
            Noise.remoteStatic(responder),
            "responder pins the initiator's static public key",
        )
        // Pairing compares the peer's *public* key; the private bytes must not
        // show up here at all.
        val peerStatic = Noise.remoteStatic(initiator)
        assertFalse(
            peerStatic.contentEquals(TestVectors.hex(kat.get("responderStaticPrivHex").asString)),
            "the learned key must be the public key, not the peer's private bytes",
        )
    }

    @Test
    fun transportCiphersMatchTheVector() {
        val (initiator, responder) = fixedPair()
        driveHandshake(initiator, responder)

        val initiatorTransport = Noise.transport(initiator)
        val responderTransport = Noise.transport(responder)

        val transports = TestVectors.array(kat, "transports")
        assertEquals(2, transports.size())

        for (element in transports) {
            val vector = element.asJsonObject
            val cipher = TestVectors.hex(vector.get("cipherHex").asString)
            val plaintext = vector.get("plain").asString.toByteArray(Charsets.UTF_8)

            if (vector.get("from").asString == "initiator") {
                assertArrayEquals(cipher, initiatorTransport.encrypt(plaintext), "initiator ciphertext")
                assertArrayEquals(plaintext, responderTransport.decrypt(cipher), "responder decrypts it")
            } else {
                assertArrayEquals(cipher, responderTransport.encrypt(plaintext), "responder ciphertext")
                assertArrayEquals(plaintext, initiatorTransport.decrypt(cipher), "initiator decrypts it")
            }
        }

        // Nonces must advance: the same plaintext never repeats on the wire.
        val first = initiatorTransport.encrypt(transportText)
        val second = initiatorTransport.encrypt(transportText)
        assertTrue(
            !first.contentEquals(second),
            "nonce must advance so identical plaintext does not repeat",
        )
    }

    @Test
    fun tamperedCiphertextIsRejected() {
        val (initiator, responder) = fixedPair()
        driveHandshake(initiator, responder)
        val initiatorTransport = Noise.transport(initiator)
        val responderTransport = Noise.transport(responder)

        val cipher = initiatorTransport.encrypt(transportText)
        cipher[0] = (cipher[0] + 1).toByte()

        val error = runCatching { responderTransport.decrypt(cipher) }.exceptionOrNull()
        assertTrue(error is ProtocolException, "a flipped byte must fail the tag check, got $error")
        assertEquals("TransportError", (error as ProtocolException).code)
    }

    @Test
    fun randomEphemeralHandshakeCompletes() {
        // The real code path: ephemerals are random, so the transcript differs
        // from the vector, but both sides must still agree on keys and data.
        val initiator = startHandshake(HandshakeState.INITIATOR, "initiatorStaticPrivHex", null)
        val responder = startHandshake(HandshakeState.RESPONDER, "responderStaticPrivHex", null)
        driveHandshake(initiator, responder)

        assertEquals(HandshakeState.SPLIT, initiator.getAction())
        assertEquals(HandshakeState.SPLIT, responder.getAction())

        val initiatorTransport = Noise.transport(initiator)
        val responderTransport = Noise.transport(responder)

        val cipher = initiatorTransport.encrypt(transportText)
        assertArrayEquals(transportText, responderTransport.decrypt(cipher))
        val reply = responderTransport.encrypt("pong".toByteArray())
        assertArrayEquals("pong".toByteArray(), initiatorTransport.decrypt(reply))

        // Static keys are exchanged on every handshake, vector or not.
        assertArrayEquals(
            TestVectors.hex(kat.get("responderStaticPubHex").asString),
            Noise.remoteStatic(initiator),
        )
        assertArrayEquals(
            TestVectors.hex(kat.get("initiatorStaticPubHex").asString),
            Noise.remoteStatic(responder),
        )
    }
}
