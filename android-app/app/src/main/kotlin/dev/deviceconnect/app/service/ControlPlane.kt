package dev.deviceconnect.app.service

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import dev.deviceconnect.protocol.Channel
import dev.deviceconnect.protocol.DeviceInfo
import dev.deviceconnect.protocol.ErrorCode
import dev.deviceconnect.protocol.ErrorBody
import dev.deviceconnect.protocol.Frame
import dev.deviceconnect.protocol.Framing
import dev.deviceconnect.protocol.MType
import dev.deviceconnect.protocol.Request
import dev.deviceconnect.protocol.Response
import dev.deviceconnect.protocol.SessionHello
import dev.deviceconnect.protocol.SessionHelloAck
import dev.deviceconnect.protocol.Wire
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap

/**
 * The control channel (docs/protocol.md section 2.2 and 5).
 *
 * Responsibilities, in order of appearance on the wire:
 *  1. send `hello` as the first frame after the handshake,
 *  2. accept `hello_ack` and report whether the peer was already paired,
 *  3. dispatch every later request to a registered handler,
 *  4. answer anything unrecognised or failing with a well-formed error frame.
 *
 * Nothing here decides whether a capability *should* be used; that is the job
 * of the handlers, which check the user's switches and the confirmation policy.
 * The control plane only routes and keeps the envelope correct.
 */
class ControlPlane(
    private val device: DeviceInfo,
    private val emit: (Frame) -> Unit,
) {
    /** Handlers keyed by their exact `cmd` string. */
    private val handlers = ConcurrentHashMap<String, (Request) -> Response>()

    /** Per-channel sequence: starts 0, increments 1 (section 2.3). */
    private var seq = 0L

    private var helloSent = false

    /** Invoked when hello_ack arrives. The caller reads [peerPaired] from it. */
    var onHelloAck: ((SessionHelloAck) -> Unit)? = null

    /** Invoked when the peer refuses our protocol version. The caller closes. */
    var onProtocolMismatch: (() -> Unit)? = null

    /** Invoked for responses to requests this side issued. */
    var onResponse: ((Response) -> Unit)? = null

    @Volatile
    var peerPaired: Boolean? = null
        private set

    @Volatile
    var peerDeviceId: String? = null
        private set

    fun register(cmd: String, handler: (Request) -> Response) {
        handlers[cmd] = handler
    }

    private fun nextSeq(): Long {
        val current = seq
        seq += 1
        return current
    }

    /** First frame on the control channel. MUST precede all other traffic. */
    fun sendHello(caps: List<String>) {
        if (helloSent) return
        helloSent = true
        val payload = Wire.gson.toJson(SessionHello(pv = PV, device = device, caps = caps))
        emit(jsonFrame(MType.REQUEST, payload))
    }

    private fun jsonFrame(mtype: Int, json: String): Frame =
        jsonFrame(mtype, json.toByteArray(StandardCharsets.UTF_8))

    private fun jsonFrame(mtype: Int, payload: ByteArray): Frame =
        Frame(Channel.CONTROL, mtype, Framing.FLAG_JSON, nextSeq(), payload)

    /**
     * Answer [id] with [json], unless it cannot fit in one frame.
     *
     * A handler can legitimately produce a large result (clipboard text is the
     * first). `Framing` refuses anything over `MAX_BODY_LEN`, and that refusal
     * would be thrown from `emit` and swallowed by the reader loop, leaving the
     * peer waiting for a reply that never arrives. Saying "too large" instead
     * preserves the rule that every request gets exactly one answer (section 7).
     */
    private fun emitResponse(id: Long, json: String) {
        val payload = json.toByteArray(StandardCharsets.UTF_8)
        if (payload.size > MAX_JSON_PAYLOAD) {
            sendError(id, ErrorCode.INVALID_ARGS, "response too large")
            return
        }
        emit(jsonFrame(MType.RESPONSE, payload))
    }

    /**
     * Feed one control-channel frame in. Frames on other channels are ignored
     * here rather than rejected, so a future caller can multiplex.
     */
    fun onFrame(frame: Frame) {
        if (frame.channel != Channel.CONTROL) return

        val payload = String(frame.payload, StandardCharsets.UTF_8)
        val element = runCatching { JsonParser.parseString(payload) }.getOrNull() ?: run {
            sendError(null, ErrorCode.INVALID_ARGS, "unparseable control payload")
            return
        }

        if (!element.isJsonObject) {
            sendError(null, ErrorCode.INVALID_ARGS, "control payload must be an object")
            return
        }
        val obj = element.asJsonObject

        when {
            // Session negotiation: flat shape, discriminated by "t" (section 2.2).
            obj.has("t") -> handleSession(obj)

            // Ordinary response to something this side asked for.
            obj.has("ok") && obj.has("id") -> handleResponse(obj)

            // Ordinary request from the peer.
            obj.has("cmd") && obj.has("id") -> handleRequest(obj)

            else -> sendError(
                obj.get("id")?.takeIf { it.isJsonPrimitive }?.asLong,
                ErrorCode.INVALID_ARGS,
                "unrecognised control message",
            )
        }
    }

    private fun handleSession(obj: JsonObject) {
        when (obj.get("t")?.asString) {
            // The peer is the initiator in this build, so we expect hello_ack.
            // Answering a stray hello is harmless and keeps both roles working.
            "hello" -> {
                val ack = SessionHelloAck(
                    pv = PV,
                    device = device,
                    caps = emptyList(),
                    paired = false,
                )
                emit(jsonFrame(MType.RESPONSE, Wire.gson.toJson(ack)))
            }

            "hello_ack" -> {
                val ack = runCatching { Wire.gson.fromJson(obj, SessionHelloAck::class.java) }.getOrNull()
                if (ack == null || ack.pv != PV) {
                    // pv mismatch MUST abort before any other traffic (section 2.2).
                    sendError(null, ErrorCode.UNSUPPORTED, "protocol version $PV required")
                    onProtocolMismatch?.invoke()
                    return
                }
                peerPaired = ack.paired
                peerDeviceId = ack.device.id
                onHelloAck?.invoke(ack)
            }

            else -> sendError(null, ErrorCode.INVALID_ARGS, "unknown session message")
        }
    }

    private fun handleRequest(obj: JsonObject) {
        val request = runCatching { Wire.gson.fromJson(obj, Request::class.java) }.getOrNull()
        if (request == null) {
            sendError(null, ErrorCode.INVALID_ARGS, "bad request")
            return
        }

        val handler = handlers[request.cmd]
        if (handler == null) {
            sendError(request.id, ErrorCode.UNSUPPORTED, "unsupported command")
            return
        }

        val response = try {
            handler(request)
        } catch (e: Exception) {
            // Never leak exception text: it could carry device detail. The code
            // alone is what the peer needs (section 7: logs carry no content).
            Response.err(request.id, ErrorBody.of(ErrorCode.INTERNAL, "handler failed"))
        }
        emitResponse(request.id, Wire.gson.toJson(response))
    }

    private fun handleResponse(obj: JsonObject) {
        val response = runCatching { Wire.gson.fromJson(obj, Response::class.java) }.getOrNull() ?: return
        onResponse?.invoke(response)
    }

    private fun sendError(id: Long?, code: ErrorCode, message: String) {
        val body = ErrorBody.of(code, message)
        val json = if (id == null) {
            Wire.gson.toJson(body)
        } else {
            Wire.gson.toJson(Response.err(id, body))
        }
        emit(jsonFrame(if (id == null) MType.ERROR else MType.RESPONSE, json))
    }

    companion object {
        const val PV = 1

        /**
         * Largest JSON payload one frame can carry: the body limit minus the
         * fixed frame header that precedes the payload (section 2.3).
         */
        const val MAX_JSON_PAYLOAD = Framing.MAX_BODY_LEN - Framing.MIN_BODY_LEN
    }
}
