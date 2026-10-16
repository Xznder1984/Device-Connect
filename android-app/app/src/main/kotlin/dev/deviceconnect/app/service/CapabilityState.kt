package dev.deviceconnect.app.service

import android.content.Context
import java.util.concurrent.ConcurrentHashMap

/**
 * Which capabilities the user has switched on.
 *
 * Every capability starts **off**; the app asks before anything is enabled and
 * `caps.set` is the only path that turns one on. The state is persisted so a
 * restart does not silently re-grant what the user revoked.
 *
 * The PC can also send `caps.set`, but only to values the user is allowed to
 * grant here: this store is the single source of truth the handlers consult,
 * so a peer cannot enable something the phone has not agreed to.
 */
class CapabilityState(context: Context) {

    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** capability id -> enabled. Missing means "off". */
    private val values = ConcurrentHashMap<String, Boolean>()

    init {
        // Rehydrate from disk. Anything unrecognised is kept so a downgrade does
        // not crash, but it is never treated as granted by the handlers below.
        for (key in prefs.all.keys) {
            values[key] = prefs.getBoolean(key, false)
        }
    }

    fun isEnabled(capability: String): Boolean = values[capability] == true

    fun set(capability: String, enabled: Boolean) {
        values[capability] = enabled
        prefs.edit().putBoolean(capability, enabled).apply()
    }

    /** Apply a whole `caps.set` map. Returns the ids that actually changed. */
    fun apply(requested: Map<String, Boolean>): List<String> {
        val changed = mutableListOf<String>()
        for ((capability, enabled) in requested) {
            if (isEnabled(capability) != enabled) {
                set(capability, enabled)
                changed += capability
            }
        }
        return changed
    }

    /** Capabilities to advertise in `hello`. Only ever a subset of the known set. */
    fun enabled(): List<String> = values.filterValues { it }.keys.sorted()

    private companion object {
        const val PREFS = "deviceconnect.capabilities"
    }
}
