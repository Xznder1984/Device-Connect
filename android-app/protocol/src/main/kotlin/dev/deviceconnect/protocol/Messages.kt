package dev.deviceconnect.protocol

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonElement
import com.google.gson.annotations.SerializedName
import java.nio.charset.StandardCharsets

/**
 * Typed JSON messages for the control plane (docs/protocol.md sections 2.5-2.8
 * and 5).
 *
 * The JSON Schemas in `protocol/schema/` are the contract; these classes mirror
 * them so the phone and the PC agree on field names. Field names on the wire are
 * camelCase, enum values are snake_case, and absent optional fields are omitted
 * (Gson skips nulls by default, matching the `optional`/omit semantics in the
 * schemas and the Rust `skip_serializing_if` attributes).
 */
object Wire {
    /**
     * One shared Gson. Default configuration: no nulls written, field names used
     * verbatim (so Kotlin property names are the wire names), enums driven by
     * `@SerializedName`.
     */
    @JvmField
    val gson: Gson = GsonBuilder().create()

    fun jsonFrame(channel: Int, mtype: Int, seq: Long, json: String): Frame =
        Frame(channel, mtype, Framing.FLAG_JSON, seq, json.toByteArray(StandardCharsets.UTF_8))

    fun requestFrame(channel: Int, seq: Long, request: Request): Frame =
        jsonFrame(channel, MType.REQUEST, seq, gson.toJson(request))

    fun responseFrame(channel: Int, seq: Long, response: Response): Frame =
        jsonFrame(channel, MType.RESPONSE, seq, gson.toJson(response))

    fun eventFrame(channel: Int, seq: Long, event: Event): Frame =
        jsonFrame(channel, MType.EVENT, seq, gson.toJson(event))

    fun errorFrame(channel: Int, seq: Long, error: ErrorBody): Frame =
        jsonFrame(channel, MType.ERROR, seq, gson.toJson(error))

    fun asRequest(frame: Frame): Request =
        gson.fromJson(String(frame.payload, StandardCharsets.UTF_8), Request::class.java)

    fun asResponse(frame: Frame): Response =
        gson.fromJson(String(frame.payload, StandardCharsets.UTF_8), Response::class.java)

    fun asEvent(frame: Frame): Event =
        gson.fromJson(String(frame.payload, StandardCharsets.UTF_8), Event::class.java)

    fun asError(frame: Frame): ErrorBody =
        gson.fromJson(String(frame.payload, StandardCharsets.UTF_8), ErrorBody::class.java)
}

/** Channel numbers (docs/protocol.md section 2.4). */
object Channel {
    const val CONTROL = 0x01
    const val VIDEO = 0x02
    const val NOTIFICATIONS = 0x03
    const val MESSAGES = 0x04
    const val CALLS = 0x05
    const val CLIPBOARD = 0x06
    const val FILES = 0x07
    const val STATUS = 0x08
    const val HEARTBEAT = 0x09
}

/** Capability identifiers (snake_case, docs/protocol.md section 5). */
object Capability {
    const val SCREEN_VIEW = "screen_view"
    const val INPUT_CONTROL = "input_control"
    const val NOTIFICATIONS = "notifications"
    const val MESSAGES = "messages"
    const val CALLS = "calls"
    const val CONTACTS = "contacts"
    const val FILES = "files"
    const val CLIPBOARD = "clipboard"
}

// ---------- generic envelope ----------

/** `{"id":<1..2^31-1>,"cmd":"<ns.name>","args":{...}}` */
data class Request(
    val id: Long,
    val cmd: String,
    val args: JsonElement? = null,
)

/**
 * The error object inside a failed response (and the body of an unsolicited
 * error frame). [code] is a [ErrorCode] wire string; unknown values are kept so
 * a newer peer cannot crash this one.
 */
data class ErrorBody(
    val code: String,
    val message: String,
    val actionId: String? = null,
) {
    fun errorCode(): ErrorCode? = ErrorCode.fromWire(code)

    companion object {
        fun of(code: ErrorCode, message: String, actionId: String? = null): ErrorBody =
            ErrorBody(code.wire, message, actionId)
    }
}

/** `{"id":<same>,"ok":true,"result":{...}}` or `{"id":<same>,"ok":false,"error":{...}}` */
data class Response(
    val id: Long,
    val ok: Boolean,
    val result: JsonElement? = null,
    val error: ErrorBody? = null,
) {
    companion object {
        fun ok(id: Long, result: JsonElement? = null): Response =
            Response(id, ok = true, result = result, error = null)

        fun err(id: Long, error: ErrorBody): Response =
            Response(id, ok = false, result = null, error = error)
    }
}

/** `{"evt":"<ns.name>","data":{...}}` */
data class Event(
    val evt: String,
    val data: JsonElement,
)

// ---------- session negotiation (control channel) ----------

data class DeviceInfo(
    /** 16 hex characters: first 8 bytes of SHA-256 of the static public key. */
    val id: String,
    val name: String,
    val model: String? = null,
    val os: String,
)

/** First control message after the handshake, from the phone to the PC. */
data class SessionHello(
    val pv: Int,
    val t: String = "hello",
    val device: DeviceInfo,
    val caps: List<String>,
)

/** The PC's answer, confirming protocol version, capabilities and pairing. */
data class SessionHelloAck(
    val pv: Int,
    val t: String = "hello_ack",
    val device: DeviceInfo,
    val caps: List<String>,
    val paired: Boolean,
)

// ---------- enums ----------

enum class KeyCode(val wire: String) {
    @SerializedName("back")
    BACK("back"),

    @SerializedName("home")
    HOME("home"),

    @SerializedName("recents")
    RECENTS("recents"),

    @SerializedName("power")
    POWER("power"),

    @SerializedName("volume_up")
    VOLUME_UP("volume_up"),

    @SerializedName("volume_down")
    VOLUME_DOWN("volume_down"),

    @SerializedName("enter")
    ENTER("enter"),

    @SerializedName("tab")
    TAB("tab"),

    @SerializedName("escape")
    ESCAPE("escape"),

    @SerializedName("delete")
    DELETE("delete"),

    @SerializedName("space")
    SPACE("space"),

    @SerializedName("arrow_up")
    ARROW_UP("arrow_up"),

    @SerializedName("arrow_down")
    ARROW_DOWN("arrow_down"),

    @SerializedName("arrow_left")
    ARROW_LEFT("arrow_left"),

    @SerializedName("arrow_right")
    ARROW_RIGHT("arrow_right"),
    ;

    companion object {
        fun fromWire(value: String): KeyCode? = entries.firstOrNull { it.wire == value }
    }
}

enum class CallType {
    @SerializedName("incoming")
    INCOMING,

    @SerializedName("outgoing")
    OUTGOING,

    @SerializedName("missed")
    MISSED,

    @SerializedName("rejected")
    REJECTED,

    @SerializedName("blocked")
    BLOCKED,
}

enum class TransportKind {
    @SerializedName("wifi")
    WIFI,

    @SerializedName("bluetooth")
    BLUETOOTH,

    @SerializedName("vpn")
    VPN,
}

enum class NetworkKind {
    @SerializedName("wifi")
    WIFI,

    @SerializedName("ethernet")
    ETHERNET,

    @SerializedName("cellular")
    CELLULAR,

    @SerializedName("none")
    NONE,

    @SerializedName("bluetooth")
    BLUETOOTH,
}

enum class HeartbeatKind {
    @SerializedName("ping")
    PING,

    @SerializedName("pong")
    PONG,
}

// ---------- notifications channel (0x03) ----------

data class NotificationAction(
    val id: String,
    val title: String,
    val replyable: Boolean? = null,
)

data class NotificationItem(
    /** Stable key: rank|package|id|tag|uid. */
    val key: String,
    val app: String,
    val appLabel: String? = null,
    val title: String,
    val text: String? = null,
    val postTime: Long,
    val actions: List<NotificationAction>? = null,
)

// ---------- messages channel (0x04) ----------

data class SmsMessage(
    val id: Long,
    val address: String,
    val name: String? = null,
    val body: String,
    val sent: Boolean,
    val read: Boolean? = null,
    val time: Long,
)

// ---------- calls channel (0x05) ----------

data class CallRecord(
    val id: String,
    val number: String,
    val name: String? = null,
    @SerializedName("type")
    val kind: CallType,
    val duration: Long? = null,
    val time: Long,
)

// ---------- status channel (0x08) ----------

data class BatteryStatus(
    val pct: Int,
    val charging: Boolean,
)

data class NetworkStatus(
    @SerializedName("type")
    val kind: NetworkKind,
)

data class StorageStatus(
    val freeBytes: Long,
)

data class StatusInfo(
    val battery: BatteryStatus,
    val screenOn: Boolean,
    val transport: TransportKind,
    val uptimeMs: Long? = null,
    val network: NetworkStatus? = null,
    val storage: StorageStatus? = null,
)

// ---------- files channel (0x07) ----------

data class FileProgress(
    val transferId: Int,
    val bytes: Long,
    val total: Long,
)

// ---------- heartbeat channel (0x09) ----------

data class Heartbeat(
    val t: HeartbeatKind,
    val ts: Long,
)

// ---------- video channel (0x02), config message ----------

data class VideoConfig(
    val codec: String = "h264",
    val profile: String? = null,
    val level: String? = null,
    val width: Int,
    val height: Int,
    /** Base64 access-unit parameter set. */
    val sps: String,
    /** Base64 picture parameter set. */
    val pps: String,
)
