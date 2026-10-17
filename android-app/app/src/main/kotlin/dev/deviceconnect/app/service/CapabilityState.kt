package dev.deviceconnect.app.service

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap

/**
 * Which capabilities the user has switched on.
 *
 * Every capability starts **off**, and the state is persisted so a restart does
 * not silently re-grant what the user revoked.
 *
 * There is exactly one instance per process, obtained with [get]. That is not an
 * optimisation: the service enforces these switches and the UI displays them, so
 * two instances would mean the user could flip a toggle the handlers never look
 * at. One store, consulted by both, is the whole point.
 *
 * Only capabilities in [ImplementedCapabilities] can be on. The store therefore
 * cannot report a switch this build does not enforce, which is what makes the
 * capability list in `hello` trustworthy.
 */
class CapabilityState private constructor(context: Context) {

    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** capability id -> enabled. Missing, or not implemented, means "off". */
    private val values = ConcurrentHashMap<String, Boolean>()

    private val _enabledIds = MutableStateFlow<Set<String>>(emptySet())

    /** Ids currently switched on, for the UI to observe. */
    val enabledIds: StateFlow<Set<String>> = _enabledIds.asStateFlow()

    init {
        val editor = prefs.edit()
        for ((key, stored) in prefs.all) {
            if (key in ImplementedCapabilities.ids && stored == true) {
                values[key] = true
            } else {
                // Delete rather than merely ignore. A value written by a build
                // that implemented a different set must not sit on disk waiting
                // to be re-read as consent this build never asked the user for.
                editor.remove(key)
            }
        }
        editor.apply()
        publish()
    }

    fun isEnabled(capability: String): Boolean = values[capability] == true

    /** Turn a capability on or off. Unimplemented ids are ignored. */
    fun set(capability: String, enabled: Boolean) {
        if (capability !in ImplementedCapabilities.ids) return
        values[capability] = enabled
        prefs.edit().putBoolean(capability, enabled).apply()
        publish()
    }

    /** Apply a whole `caps.set` map. Returns the ids that actually changed. */
    fun apply(requested: Map<String, Boolean>): List<String> {
        val changed = mutableListOf<String>()
        for ((capability, enabled) in requested) {
            if (capability !in ImplementedCapabilities.ids) continue
            if (isEnabled(capability) != enabled) changed += capability
            set(capability, enabled)
        }
        return changed
    }

    /**
     * The capability map to advertise in `hello` or return from `caps.set`.
     *
     * Every implemented capability appears, off or on, so the peer can tell what
     * this build supports instead of guessing from absences.
     */
    fun snapshot(): Map<String, Boolean> = ImplementedCapabilities.ids.sorted().associateWith(::isEnabled)

    /** Enabled capability ids. Always a subset of [snapshot]'s true entries. */
    fun enabled(): List<String> = snapshot().filterValues { it }.keys.toList()

    private fun publish() {
        _enabledIds.value = snapshot().filterValues { it }.keys.toSortedSet()
    }

    companion object {
        private const val PREFS = "deviceconnect.capabilities"

        @Volatile
        private var instance: CapabilityState? = null

        /** The single process-wide store, created on first use. */
        fun get(context: Context): CapabilityState =
            instance ?: synchronized(this) {
                instance ?: CapabilityState(context.applicationContext).also { instance = it }
            }
    }
}
