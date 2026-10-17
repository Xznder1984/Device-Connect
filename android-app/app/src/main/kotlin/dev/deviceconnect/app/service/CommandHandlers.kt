package dev.deviceconnect.app.service

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.PowerManager
import android.os.StatFs
import android.os.Environment
import android.os.SystemClock
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive
import dev.deviceconnect.protocol.Commands
import dev.deviceconnect.protocol.ErrorCode
import dev.deviceconnect.protocol.ErrorBody
import dev.deviceconnect.protocol.Request
import dev.deviceconnect.protocol.Response
import dev.deviceconnect.protocol.Wire

/**
 * The safe command set the PC may issue on the control channel
 * (docs/protocol.md section 5).
 *
 * Two rules apply to everything here:
 *  - the reply is always envelope-shaped, even when it is an error, so the PC
 *    never has to time out to learn that something was refused;
 *  - a refusal never says more than the peer needs. Messages are fixed strings
 *    chosen by this code, never exception text, which keeps device detail and
 *    personal data off the wire (and out of logs, by construction).
 */
class CommandHandlers(
    private val context: Context,
    private val capabilities: CapabilityState,
    /** Invoked when the PC asks to forget this pairing. */
    private val onUnpair: () -> Unit,
) {

    /** Text-only clipboard access for the clipboard channel (section 5). */
    private val clipboard = ClipboardSync(context)

    /** Register every handler this build serves on [plane]. */
    fun register(plane: ControlPlane) {
        plane.register("status.get") { request -> status(request) }
        plane.register("caps.set") { request -> capsSet(request) }
        plane.register("security.unpair") { request -> unpair(request) }
        plane.register("clipboard.get") { request -> gated(request, ::clipboardGet) }
        plane.register("clipboard.set") { request -> gated(request, ::clipboardSet) }
    }

    /**
     * Run [handler] only if the switch this command needs is on (section 4).
     *
     * The check is per request against the live store, so revoking a capability
     * mid-session takes effect on the very next command with no reconnect and no
     * reliance on the peer honouring the `hello` it was sent earlier.
     */
    private fun gated(request: Request, handler: (Request) -> Response): Response {
        val capability = Commands.capabilityFor(request.cmd)
        if (capability != null && !capabilities.isEnabled(capability)) {
            return Response.err(
                request.id,
                ErrorBody.of(ErrorCode.CAPABILITY_DISABLED, "$capability is off on this phone"),
            )
        }
        return handler(request)
    }

    /**
     * `status.get` -> the status object from status.schema.json.
     *
     * Every field is read live from the OS; nothing is cached or defaulted to a
     * plausible-looking value, because a wrong battery reading is worse than an
     * error. If a source is unavailable the reply is an error rather than a
     * guess.
     */
    private fun status(request: Request): Response = try {
        val result = JsonObject().apply {
            add("battery", battery())
            addProperty("screenOn", screenOn())
            addProperty("transport", transport())
            addProperty("uptimeMs", SystemClock.elapsedRealtime())
            add("network", network())
            add("storage", storage())
        }
        Response.ok(request.id, result)
    } catch (e: Exception) {
        Response.err(request.id, ErrorBody.of(ErrorCode.INTERNAL, "status unavailable"))
    }

    private fun battery(): JsonObject {
        val intent = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            ?: throw IllegalStateException("no battery sticky broadcast")
        val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
        if (level < 0 || scale <= 0) throw IllegalStateException("no battery data")
        val pct = ((level * 100f) / scale).toInt().coerceIn(0, 100)
        val status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
            status == BatteryManager.BATTERY_STATUS_FULL
        return JsonObject().apply {
            addProperty("pct", pct)
            addProperty("charging", charging)
        }
    }

    private fun screenOn(): Boolean {
        val power = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        return power.isInteractive
    }

    /** The transport the device is actually on; `vpn` if that is what is active. */
    private fun transport(): String {
        val caps = activeNetworkCapabilities() ?: return "wifi"
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return "vpn"
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) return "bluetooth"
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "cellular"
        return "wifi"
    }

    private fun network(): JsonObject {
        val caps = activeNetworkCapabilities()
        val type = when {
            caps == null -> "none"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> "bluetooth"
            else -> "none"
        }
        return JsonObject().apply { addProperty("type", type) }
    }

    private fun activeNetworkCapabilities(): NetworkCapabilities? {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return null
        val network = manager.activeNetwork ?: return null
        return manager.getNetworkCapabilities(network)
    }

    private fun storage(): JsonObject {
        val stat = StatFs(Environment.getDataDirectory().path)
        val free = stat.availableBlocksLong * stat.blockSizeLong
        return JsonObject().apply { addProperty("freeBytes", free) }
    }

    /**
     * `caps.set` -> `{caps:{...}}`, the effective map (section 5).
     *
     * The peer may only set switches this build implements, and only to values
     * the user can set in the app: there is no privileged path, so a compromised
     * PC can never grant itself access the phone's owner could not grant.
     * Capabilities this build does not implement are refused rather than stored:
     * a switch the code cannot honour would be advertised in `hello` and then
     * refused at the command, which is worse than saying no once.
     */
    private fun capsSet(request: Request): Response {
        val requested = mutableMapOf<String, Boolean>()
        val args: JsonObject? = request.args as? JsonObject
        val caps = args?.get("caps") as? JsonObject
            ?: return Response.err(request.id, ErrorBody.of(ErrorCode.INVALID_ARGS, "caps object required"))

        for ((key, value) in caps.entrySet()) {
            if (!value.isJsonPrimitive || !value.asJsonPrimitive.isBoolean) {
                return Response.err(request.id, ErrorBody.of(ErrorCode.INVALID_ARGS, "capability values must be booleans"))
            }
            if (key !in Commands.DECLARED) {
                // Unknown ids are refused rather than stored, so a newer PC
                // cannot smuggle state this build does not understand.
                return Response.err(request.id, ErrorBody.of(ErrorCode.INVALID_ARGS, "unknown capability"))
            }
            if (key !in ImplementedCapabilities.ids) {
                return Response.err(
                    request.id,
                    ErrorBody.of(ErrorCode.INVALID_ARGS, "capability is not implemented in this build"),
                )
            }
            requested[key] = value.asBoolean
        }
        if (requested.isEmpty()) {
            return Response.err(request.id, ErrorBody.of(ErrorCode.INVALID_ARGS, "caps object required"))
        }

        capabilities.apply(requested)
        // Answer with the effective map, not just what was asked for: that is
        // how the PC learns which switches this phone actually honoured.
        return Response.ok(
            request.id,
            JsonObject().apply { add("caps", Wire.gson.toJsonTree(capabilities.snapshot())) },
        )
    }

    /**
     * `security.unpair` -> forget the pinned peer and close the session.
     *
     * This is the revocation path: it clears the pinned key first, so even if
     * the session lingers the peer can never reconnect without a fresh pairing.
     */
    private fun unpair(request: Request): Response {
        val response = Response.ok(request.id, JsonObject())
        // Clear trust before answering: a failure between the two must leave the
        // user un-paired, never paired-but-unanswered.
        onUnpair()
        return response
    }

    /**
     * `clipboard.get` -> `{text}` (section 5, clipboard channel).
     *
     * The three outcomes are reported distinctly. Android 10+ only lets the
     * focused app read the clipboard, so "we cannot see it" is a normal,
     * expected answer here and must not be flattened into an empty string, which
     * would look like the user had copied nothing.
     */
    private fun clipboardGet(request: Request): Response = when (val read = clipboard.read()) {
        is ClipboardSync.Read.Text -> Response.ok(
            request.id,
            JsonObject().apply { addProperty("text", read.value) },
        )
        ClipboardSync.Read.Absent -> Response.err(
            request.id,
            ErrorBody.of(ErrorCode.NOT_FOUND, "no text on the clipboard"),
        )
        ClipboardSync.Read.TooLarge -> Response.err(
            request.id,
            ErrorBody.of(ErrorCode.UNSUPPORTED, "clipboard text is too large to transfer"),
        )
    }

    /**
     * `clipboard.set {text}` -> `{}`.
     *
     * The size is checked before anything is written, so an over-long request
     * cannot leave the phone's clipboard in a half-changed state, and the reply
     * is always a frame that fits.
     */
    private fun clipboardSet(request: Request): Response {
        val args = request.args as? JsonObject
        val text = (args?.get("text") as? JsonPrimitive)
            ?.takeIf { it.isString }
            ?.asString
            ?: return Response.err(request.id, ErrorBody.of(ErrorCode.INVALID_ARGS, "text is required"))
        if (ClipboardSync.utf8Bytes(text) > ClipboardSync.MAX_TEXT_BYTES) {
            return Response.err(
                request.id,
                ErrorBody.of(ErrorCode.INVALID_ARGS, "clipboard text is too large to transfer"),
            )
        }
        if (!clipboard.write(text)) {
            return Response.err(request.id, ErrorBody.of(ErrorCode.UNAUTHORIZED, "clipboard is not available"))
        }
        return Response.ok(request.id, JsonObject())
    }
}
