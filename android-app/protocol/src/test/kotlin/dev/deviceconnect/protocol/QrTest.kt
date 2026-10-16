package dev.deviceconnect.protocol

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/** Conformance against `protocol/test-vectors/qr.json`. */
internal class QrTest {

    @Test
    fun validVectorsRoundTrip() {
        val vectors = TestVectors.load("qr.json")
        // The valid vectors are positional, so label failures by index.
        TestVectors.array(vectors, "valid").forEachIndexed { index, element ->
            val vector = element.asJsonObject
            val name = "valid qr[$index]"
            val encoded = vector.get("encoded").asString
            val json = vector.getAsJsonObject("json")

            val payload = Qr.decode(encoded)

            // Field-by-field so a key that vanished or changed name is caught.
            assertEquals(json.get("v").asInt, payload.v, "$name v")
            assertEquals(json.get("n").asString, payload.n, "$name n")
            assertEquals(json.get("p").asInt, payload.p, "$name p")
            assertEquals(
                if (json.has("h")) json.get("h").asString else null,
                payload.h,
                "$name h",
            )
            assertEquals(json.get("exp").asLong, payload.exp, "$name exp")
            assertEquals(
                if (json.has("name")) json.get("name").asString else null,
                payload.name,
                "$name name",
            )

            // Re-encoding must be byte-identical: the scanner shows this exact string.
            assertEquals(encoded, Qr.encode(payload), "$name re-encode")

            assertEquals(
                vector.get("nonceHex").asString,
                TestVectors.unhex(Qr.nonceBytes(payload)),
                "$name nonce",
            )

            assertTrue(Qr.isExpired(payload, vector.get("expiredAt").asLong), "$name expiry")
            assertFalse(Qr.isExpired(payload, payload.exp - 1), "$name still valid one second early")
        }
    }

    @Test
    fun invalidVectorsAreRejected() {
        val vectors = TestVectors.load("qr.json")
        val invalid = TestVectors.array(vectors, "invalid")
        assertTrue(invalid.size() >= 4)

        for (element in invalid) {
            val vector = element.asJsonObject
            val name = vector.get("name").asString
            val expected = vector.get("error").asString
            val text = vector.get("text").asString

            if (expected == "Expired") {
                // Expiry is reported separately from "malformed": decoding must
                // still succeed so the phone can say *why* it refused.
                val payload = Qr.decode(text)
                assertTrue(Qr.isExpired(payload, payload.exp + 1), "$name should be expired")
                continue
            }

            val error = assertThrows<ProtocolException>(name) { Qr.decode(text) }
            assertEquals(expected, error.code, name)
        }
    }

    @Test
    fun payloadRoundTripsAndExpiryTracksValidityWindow() {
        val payload = QrPayload(
            v = 1,
            n = QrCanned.NONCE_BASE64URL,
            p = 47321,
            h = "desk-pc.local",
            exp = 1_700_000_000L + Qr.VALIDITY_SECS,
            name = "Desk PC",
        )
        val decoded = Qr.decode(Qr.encode(payload))
        assertEquals(payload, decoded)

        val now = 1_700_000_000L
        assertFalse(Qr.isExpired(decoded, now), "not expired at creation")
        assertTrue(Qr.isExpired(decoded, payload.exp + 1), "expired one second past exp")
    }

    @Test
    fun mismatchedVersionsAreRejected() {
        // v != 1 is a full, well-formed payload that still must be refused.
        val encoded = Qr.encode(QrPayload(v = 2, n = QrCanned.NONCE_BASE64URL, p = 47321, exp = 1L))
        val error = assertThrows<ProtocolException> { Qr.decode(encoded) }
        assertEquals("BadField", error.code)
    }

    @Test
    fun badNonceLengthIsRejected() {
        val encoded = Qr.encode(QrPayload(v = 1, n = "short", p = 47321, exp = 1L))
        val error = assertThrows<ProtocolException> { Qr.decode(encoded) }
        assertEquals("BadField", error.code)
    }

    @Test
    fun portZeroIsRejected() {
        val encoded = Qr.encode(QrPayload(v = 1, n = QrCanned.NONCE_BASE64URL, p = 0, exp = 1L))
        val error = assertThrows<ProtocolException> { Qr.decode(encoded) }
        assertEquals("BadField", error.code)
    }
}

private object QrCanned {
    /** 16 zero bytes as base64url, the length the schema requires. */
    const val NONCE_BASE64URL = "AAAAAAAAAAAAAAAAAAAAAA"
}
