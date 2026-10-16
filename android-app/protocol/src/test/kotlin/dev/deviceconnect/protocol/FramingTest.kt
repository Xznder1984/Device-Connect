package dev.deviceconnect.protocol

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/** Conformance against `protocol/test-vectors/frames.json`. */
internal class FramingTest {

    private fun decodeOne(bytes: ByteArray): Frame {
        val result = Framing.decode(bytes)
        assertTrue(result is Framing.DecodeResult.Decoded, "expected a complete frame")
        return (result as Framing.DecodeResult.Decoded).frame
    }

    @Test
    fun validVectorsDecode() {
        val valid = TestVectors.array(TestVectors.load("frames.json"), "valid")
        assertTrue(valid.size() >= 6, "expected several valid frame vectors, got ${valid.size()}")

        for (element in valid) {
            val vector = element.asJsonObject
            val name = vector.get("name").asString
            val expect = vector.getAsJsonObject("expect")

            val frame = decodeOne(TestVectors.hex(vector.get("hex").asString))

            assertEquals(expect.get("channel").asInt, frame.channel, "$name channel")
            assertEquals(expect.get("mtype").asInt, frame.mtype, "$name mtype")
            assertEquals(expect.get("flags").asInt, frame.flags, "$name flags")
            assertEquals(expect.get("seq").asLong, frame.seq, "$name seq")

            if (expect.has("payloadHex")) {
                assertEquals(
                    expect.get("payloadHex").asString,
                    TestVectors.unhex(frame.payload),
                    "$name payload bytes",
                )
            }
            if (expect.has("payloadJson")) {
                assertEquals(
                    expect.get("payloadJson"),
                    TestVectors.parseJson(frame.payload),
                    "$name payload JSON",
                )
            }
            // Re-encoding must reproduce the exact wire bytes.
            assertEquals(
                vector.get("hex").asString,
                TestVectors.unhex(Framing.encode(frame)),
                "$name re-encode",
            )
        }
    }

    @Test
    fun invalidVectorsAreRejected() {
        val invalid = TestVectors.array(TestVectors.load("frames.json"), "invalid")
        assertTrue(invalid.size() >= 3)

        for (element in invalid) {
            val vector = element.asJsonObject
            val name = vector.get("name").asString
            val expected = vector.get("error").asString
            val bytes = TestVectors.hex(vector.get("hex").asString)
            val error = assertThrows<ProtocolException>(name) { Framing.decode(bytes) }
            assertEquals(expected, error.code, name)
        }
    }

    @Test
    fun streamReassemblyAcrossChunkBoundaries() {
        val valid = TestVectors.array(TestVectors.load("frames.json"), "valid")
        val bytes = TestVectors.hex(valid[2].asJsonObject.get("hex").asString)
        val expectedSeq = valid[2].asJsonObject.getAsJsonObject("expect").get("seq").asLong

        // The same frame must be reconstructed regardless of where the bytes
        // happen to be split by the transport.
        for (split in listOf(1, 3, 11, bytes.size - 1)) {
            assertTrue(split in 1 until bytes.size, "split $split out of range")

            val decoder = FrameDecoder()
            decoder.feed(bytes.copyOfRange(0, split))
            val first = decoder.next()

            decoder.feed(bytes.copyOfRange(split, bytes.size))
            val frame = first ?: decoder.next()

            assertNotNull(frame, "frame should complete after split $split")
            assertEquals(expectedSeq, frame!!.seq, "seq after split $split")
            assertNull(decoder.next(), "no extra frame after split $split")
            assertEquals(0, decoder.buffered, "buffer drained after split $split")
        }
    }

    @Test
    fun jsonFlagSetOnJsonPayloads() {
        val valid = TestVectors.array(TestVectors.load("frames.json"), "valid")
        for (element in valid) {
            val vector = element.asJsonObject
            if (!vector.getAsJsonObject("expect").has("payloadJson")) continue
            val frame = decodeOne(TestVectors.hex(vector.get("hex").asString))
            assertTrue(
                (frame.flags and Framing.FLAG_JSON) != 0,
                "${vector.get("name").asString} must set the JSON flag",
            )
        }
    }

    @Test
    fun emptyPayloadRoundTrips() {
        val frame = Frame(8, MType.EVENT, 0, 0, ByteArray(0))
        val encoded = Framing.encode(frame)
        assertEquals(Framing.MIN_BODY_LEN + Framing.FRAME_HEADER_LEN, encoded.size)
        assertEquals(frame, decodeOne(encoded))
    }

    @Test
    fun fileDataPayloadParsesAndReserializes() {
        val valid = TestVectors.array(TestVectors.load("frames.json"), "valid")
        val vector = valid.first { it.asJsonObject.get("name").asString == "file_data_chunk" }.asJsonObject
        val payload = TestVectors.hex(vector.getAsJsonObject("expect").get("payloadHex").asString)

        val data = FileData.decode(payload)
        assertEquals(9, data.transferId, "transfer id")
        assertEquals(18_446_744_073_709_551L, data.offset, "offset must be usable past 2^53")
        assertArrayEquals("DATA_CHUNK".toByteArray(), data.chunk, "chunk contents")
        assertArrayEquals(payload, data.encode(), "re-encode")
    }

    @Test
    fun videoAccessUnitPayloadParses() {
        val valid = TestVectors.array(TestVectors.load("frames.json"), "valid")
        val vector = valid.first { it.asJsonObject.get("name").asString == "video_access_unit" }.asJsonObject
        val payload = TestVectors.hex(vector.getAsJsonObject("expect").get("payloadHex").asString)

        val au = VideoAccessUnit.decode(payload)
        assertEquals(1_700_000_000_999L, au.timestampMs, "timestamp")
        assertEquals(8, au.data.size, "annex b tail")
        assertArrayEquals(payload, au.encode(), "re-encode")
    }

    @Test
    fun decoderBuffersPartialHeaders() {
        val decoder = FrameDecoder()
        decoder.feed(byteArrayOf(0x00, 0x00))
        assertNull(decoder.next(), "two bytes cannot contain a header")
        assertEquals(2, decoder.buffered)
    }
}
