package dev.deviceconnect.protocol

import com.google.gson.JsonElement
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Round-trips the shared typed-message vectors (`typed-messages.json`) through
 * the Kotlin message types.
 *
 * The vectors are generated from the Rust types and asserted against every
 * implementation, so this test is what keeps the phone's idea of a
 * `notification.posted` payload identical to the PC's.
 */
class MessageTest {

    private fun <T> roundTrip(element: JsonElement, clazz: Class<T>): Pair<T, JsonElement> {
        val parsed = Wire.gson.fromJson(element, clazz)
        return parsed to Wire.gson.toJsonTree(parsed)
    }

    @Test
    fun requestsParseAndRoundTrip() {
        val vectors = TestVectors.load("typed-messages.json")
        val requests = TestVectors.array(vectors, "requests")
        assertTrue(requests.size() >= 30, "expected the full request sample set")

        for (element in requests) {
            val original = element.asJsonObject
            val expectedId = original.get("id").asLong
            val expectedCmd = original.get("cmd").asString

            val (request, reserialized) = roundTrip(element, Request::class.java)
            assertEquals(expectedId, request.id, "id for ${expectedCmd}")
            assertEquals(expectedCmd, request.cmd, "cmd")

            // Re-encoding must reproduce the same id, cmd and args (deep equality).
            assertEquals(expectedId, reserialized.asJsonObject.get("id").asLong, "id for $expectedCmd")
            assertEquals(expectedCmd, reserialized.asJsonObject.get("cmd").asString, "cmd for $expectedCmd")
            if (original.has("args")) {
                assertEquals(
                    original.get("args"),
                    reserialized.asJsonObject.get("args"),
                    "args for $expectedCmd",
                )
            }
        }
    }

    @Test
    fun responsesParseAndRoundTrip() {
        val vectors = TestVectors.load("typed-messages.json")
        val responses = TestVectors.array(vectors, "responses")
        assertTrue(responses.size() >= 4, "expected the response sample set")

        for (element in responses) {
            val (response, reserialized) = roundTrip(element, Response::class.java)
            val original = element.asJsonObject
            assertEquals(original.get("id").asLong, response.id)
            assertEquals(original.get("ok").asBoolean, response.ok)

            val out = reserialized.asJsonObject
            if (response.ok) {
                assertNotNull(response.result, "ok response carries a result")
                assertNull(out.get("error"), "ok response omits error")
                assertEquals(original.get("result"), out.get("result"))
            } else {
                val error = response.error
                assertNotNull(error, "failed response carries an error")
                requireNotNull(error)
                assertEquals(original.getAsJsonObject("error").get("code").asString, error.code)
                assertEquals(original.getAsJsonObject("error").get("message").asString, error.message)
                assertNull(out.get("result"), "failed response omits result")
                if (original.getAsJsonObject("error").has("actionId")) {
                    assertEquals(
                        original.getAsJsonObject("error").get("actionId").asString,
                        error.actionId,
                    )
                }
            }
        }
    }

    @Test
    fun errorCodesAreRecognised() {
        val known = Wire.gson.fromJson(
            """{"id":1,"ok":false,"error":{"code":"CAPABILITY_DISABLED","message":"x"}}""",
            Response::class.java,
        )
        assertEquals(ErrorCode.CAPABILITY_DISABLED, known.error?.errorCode())

        // A future peer may send a code this build does not know; it must not crash
        // and the raw string must survive a round trip.
        val future = Wire.gson.fromJson(
            """{"id":2,"ok":false,"error":{"code":"SOMETHING_NEW","message":"y"}}""",
            Response::class.java,
        )
        assertEquals("SOMETHING_NEW", future.error?.code)
        assertNull(future.error?.errorCode())
    }

    @Test
    fun eventsParseIntoTheirTypedData() {
        val vectors = TestVectors.load("typed-messages.json")
        val events = TestVectors.array(vectors, "events")

        var seen = 0
        for (element in events) {
            val event = Wire.gson.fromJson(element, Event::class.java)
            val data = event.data
            val reserialized: JsonElement = when (event.evt) {
                "notification.posted" -> {
                    val item = Wire.gson.fromJson(data, NotificationItem::class.java)
                    assertEquals(1700000000000L, item.postTime)
                    assertEquals("Chat", item.appLabel)
                    assertEquals(2, item.actions?.size)
                    assertTrue(item.actions!![0].replyable == true)
                    assertTrue(item.actions!![1].replyable == null)
                    Wire.gson.toJsonTree(item)
                }

                "sms.received" -> {
                    val sms = Wire.gson.fromJson(data, SmsMessage::class.java)
                    assertEquals(91L, sms.id)
                    assertEquals("+15550100", sms.address)
                    assertEquals(false, sms.sent)
                    assertEquals(false, sms.read)
                    Wire.gson.toJsonTree(sms)
                }

                "call.incoming" -> {
                    val call = Wire.gson.fromJson(data, CallRecord::class.java)
                    assertEquals(CallType.INCOMING, call.kind)
                    assertEquals("+15550123", call.number)
                    Wire.gson.toJsonTree(call)
                }

                "status.changed" -> {
                    val status = Wire.gson.fromJson(data, StatusInfo::class.java)
                    assertEquals(80, status.battery.pct)
                    assertTrue(status.battery.charging)
                    assertEquals(TransportKind.WIFI, status.transport)
                    assertEquals(NetworkKind.WIFI, status.network?.kind)
                    assertEquals(12_000_000_000L, status.storage?.freeBytes)
                    assertTrue(status.screenOn)
                    Wire.gson.toJsonTree(status)
                }

                "file.progress" -> {
                    val progress = Wire.gson.fromJson(data, FileProgress::class.java)
                    assertEquals(1, progress.transferId)
                    assertEquals(65536L, progress.bytes)
                    assertEquals(1048576L, progress.total)
                    Wire.gson.toJsonTree(progress)
                }

                else -> error("unexpected event in vectors: ${event.evt}")
            }

            assertEquals(data, reserialized, "typed data for ${event.evt}")
            seen++
        }
        assertEquals(5, seen, "all five event vectors covered")
    }

    @Test
    fun keyCodesMapToTheirWireNames() {
        assertEquals("volume_up", KeyCode.VOLUME_UP.wire)
        assertEquals(KeyCode.ARROW_LEFT, KeyCode.fromWire("arrow_left"))
        assertNull(KeyCode.fromWire("nope"))

        // KeyCode is serialized through its annotated wire name.
        val json = Wire.gson.toJson(mapOf("key" to KeyCode.HOME))
        assertEquals("""{"key":"home"}""", json)
    }

    @Test
    fun sessionHandshakeShapesMatchTheSchema() {
        val device = DeviceInfo(id = "0123456789abcdef", name = "Pixel", model = "Pixel 9", os = "android")
        val hello = SessionHello(pv = 1, device = device, caps = listOf(Capability.SCREEN_VIEW, Capability.INPUT_CONTROL))
        val helloJson = Wire.gson.toJsonTree(hello).asJsonObject
        assertEquals(1, helloJson.get("pv").asInt)
        assertEquals("hello", helloJson.get("t").asString)
        assertEquals("0123456789abcdef", helloJson.getAsJsonObject("device").get("id").asString)
        assertEquals(2, helloJson.getAsJsonArray("caps").size())
        // model is optional and present here
        assertEquals("Pixel 9", helloJson.getAsJsonObject("device").get("model").asString)

        val ack = SessionHelloAck(
            pv = 1,
            device = DeviceInfo(id = "fedcba9876543210", name = "PC", os = "windows"),
            caps = listOf(Capability.SCREEN_VIEW),
            paired = true,
        )
        val ackJson = Wire.gson.toJsonTree(ack).asJsonObject
        assertEquals("hello_ack", ackJson.get("t").asString)
        assertTrue(ackJson.get("paired").asBoolean)
        // A Windows PC has no model; the field must be omitted, not null.
        assertNull(ackJson.getAsJsonObject("device").get("model"))
    }

    @Test
    fun heartbeatRoundTrips() {
        val ping = Heartbeat(HeartbeatKind.PING, 1700000000000L)
        assertEquals("""{"t":"ping","ts":1700000000000}""", Wire.gson.toJson(ping))
        val pong = Heartbeat(HeartbeatKind.PONG, 1700000000000L)
        assertEquals("""{"t":"pong","ts":1700000000000}""", Wire.gson.toJson(pong))
    }

    @Test
    fun framesCarryJsonMessages() {
        val request = Request(id = 7, cmd = "status.get", args = null)
        val frame = Wire.requestFrame(Channel.CONTROL, seq = 42, request = request)
        assertEquals(Channel.CONTROL, frame.channel)
        assertEquals(MType.REQUEST, frame.mtype)
        assertEquals(Framing.FLAG_JSON, frame.flags)
        assertEquals(42L, frame.seq)

        // Decode the frame bytes back into an identical request.
        val decoded = Framing.decode(Framing.encode(frame))
        assertTrue(decoded is Framing.DecodeResult.Decoded)
        val parsed = Wire.asRequest((decoded as Framing.DecodeResult.Decoded).frame)
        assertEquals(request.id, parsed.id)
        assertEquals(request.cmd, parsed.cmd)
        assertNull(parsed.args)

        val event = Event("status.changed", Wire.gson.toJsonTree(StatusInfo(
            battery = BatteryStatus(50, false),
            screenOn = true,
            transport = TransportKind.WIFI,
        )))
        val eventFrame = Wire.eventFrame(Channel.STATUS, seq = 1, event = event)
        assertEquals(MType.EVENT, eventFrame.mtype)
        assertEquals("status.changed", Wire.asEvent(eventFrame).evt)
    }
}
