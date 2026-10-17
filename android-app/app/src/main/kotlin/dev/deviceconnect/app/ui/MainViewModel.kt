package dev.deviceconnect.app.ui

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.IBinder
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.deviceconnect.app.net.Identity
import dev.deviceconnect.app.net.TrustStore
import dev.deviceconnect.app.discovery.Discovery
import dev.deviceconnect.app.service.ConnectionService
import dev.deviceconnect.app.service.LinkState
import dev.deviceconnect.app.service.Session
import dev.deviceconnect.protocol.Qr
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** Which screen is showing. Deliberately flat: there are only a handful. */
sealed interface Screen {
    data object Home : Screen
    data object PairingOptions : Screen
    data object Scan : Screen
    data object Manual : Screen
    data object Discovered : Screen
    data object Confirm : Screen
    data object Connected : Screen
}

/**
 * Holds everything the UI needs and owns the pairing/connection decisions.
 *
 * The session itself lives in [ConnectionService] so it survives the Activity;
 * this class only mirrors its state and drives it. All dialling happens through
 * the service, never here, so there is exactly one place that can start a
 * handshake.
 */
class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val appContext: Context = app.applicationContext

    private val identity = Identity.getOrCreate(appContext)
    private val trust = TrustStore(appContext)

    /** mDNS scanning; only runs while the "found on network" screen is open. */
    val discovery = Discovery(appContext)

    private val _link = MutableStateFlow<LinkState>(LinkState.Idle)
    val link: StateFlow<LinkState> = _link.asStateFlow()

    private val _screen = MutableStateFlow<Screen>(Screen.Home)
    val screen: StateFlow<Screen> = _screen.asStateFlow()

    private val _discovered = MutableStateFlow<List<Discovery.Peer>>(emptyList())
    val discovered: StateFlow<List<Discovery.Peer>> = _discovered.asStateFlow()

    private val _notice = MutableStateFlow<String?>(null)
    val notice: StateFlow<String?> = _notice.asStateFlow()

    private val _pairedPeerName = MutableStateFlow<String?>(null)
    val pairedPeerName: StateFlow<String?> = _pairedPeerName.asStateFlow()

    /** 16 hex characters; shown on the PC so the user can tell devices apart. */
    val deviceId: String = identity.deviceId

    val deviceName: String = Build.MODEL?.takeIf { it.isNotBlank() } ?: "Android phone"

    private var service: ConnectionService? = null
    private var bound = false
    private var stateJob: Job? = null
    private var pendingConnect: (() -> Unit)? = null

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val local = binder as? ConnectionService.LocalBinder ?: return
            val svc = local.service()
            service = svc
            bound = true
            observe(svc)
            pendingConnect?.invoke()
            pendingConnect = null
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            // The service stops itself once a session ends, so this is routine.
            bound = false
            service = null
        }
    }

    init {
        _pairedPeerName.value = trust.pinned()?.name
        bind()
    }

    // ---------- navigation ----------

    fun openPairingOptions() {
        _screen.value = Screen.PairingOptions
    }

    fun openManualEntry() {
        _screen.value = Screen.Manual
    }

    fun openScanner() {
        _screen.value = Screen.Scan
    }

    fun openDiscovery() {
        _discovered.value = emptyList()
        _screen.value = Screen.Discovered
        discovery.start(
            onChanged = { peers -> _discovered.value = peers },
            onError = { message -> _notice.value = message },
        )
    }

    fun back() {
        discovery.stop()
        _screen.value = when (_link.value) {
            is LinkState.AwaitingConfirmation -> Screen.Confirm
            is LinkState.Connected -> Screen.Connected
            else -> Screen.Home
        }
    }

    fun dismissNotice() {
        _notice.value = null
    }

    // ---------- connecting ----------

    /** Feed a string decoded from the PC's QR code. */
    fun onQrText(text: String) {
        val payload = runCatching { Qr.decode(text) }.getOrNull()
        if (payload == null) {
            _notice.value = "That is not a Device Connect QR code"
            return
        }
        val nowSecs = System.currentTimeMillis() / 1_000
        if (Qr.isExpired(payload, nowSecs)) {
            _notice.value = "That code has expired. Ask your PC to show a new one."
            return
        }
        val host = payload.h?.takeIf { it.isNotBlank() }
        if (host == null) {
            _notice.value = "That code did not include the PC's address"
            return
        }
        val nonce = runCatching { Qr.nonceBytes(payload) }.getOrNull() ?: run {
            _notice.value = "That code is malformed"
            return
        }
        connect(host, payload.p, Session.qrPrologue(nonce))
    }

    /** Connect to a `host:port` typed by the user (manual pairing, section 3.5). */
    fun connectManual(input: String) {
        val target = parseTarget(input)
        if (target == null) {
            _notice.value = "Enter the address as ip:port, for example 192.168.1.20:47810"
            return
        }
        connect(target.first, target.second, Session.manualPrologue())
    }

    /** Connect to a PC found by mDNS (section 2.1). */
    fun connectTo(peer: Discovery.Peer) {
        connect(peer.host, peer.port, Session.manualPrologue())
    }

    /** Reuse the address of the last successful session. */
    fun reconnect() {
        val target = service?.lastTarget()
        if (target == null) {
            _notice.value = "Enter your PC's address to connect"
            _screen.value = Screen.Manual
            return
        }
        connect(target.first, target.second, Session.manualPrologue())
    }

    private fun connect(host: String, port: Int, prologue: ByteArray) {
        discovery.stop()
        val attempt = {
            service?.connect(host, port, prologue)
                ?: run { _notice.value = "Connection service is not ready yet" }
        }
        // The service must be *started*, not just bound, so the session keeps
        // running when the screen locks or the app is backgrounded.
        startService()
        if (service != null) attempt() else pendingConnect = attempt
    }

    // ---------- pairing decisions ----------

    /** Codes matched: pin the peer and continue. */
    fun confirmPairing() {
        service?.confirmPairing()
    }

    /** Codes differ: treat as a possible man-in-the-middle and drop it. */
    fun rejectPairing() {
        service?.rejectPairing()
    }

    fun disconnect() {
        discovery.stop()
        service?.disconnect()
    }

    /** Forget the paired PC (section 3: `security.unpair`). */
    fun forgetPeer() {
        service?.forgetPeer()
        _pairedPeerName.value = null
        _notice.value = "This phone is no longer paired"
    }

    // ---------- internals ----------

    private fun bind() {
        if (bound) return
        val intent = Intent(appContext, ConnectionService::class.java)
        bound = appContext.bindService(intent, connection, Context.BIND_AUTO_CREATE)
    }

    private fun startService() {
        ContextCompat.startForegroundService(
            appContext,
            Intent(appContext, ConnectionService::class.java),
        )
    }

    private fun observe(svc: ConnectionService) {
        stateJob?.cancel()
        stateJob = viewModelScope.launch {
            svc.state.collect { state ->
                _link.value = state
                when (state) {
                    is LinkState.AwaitingConfirmation -> _screen.value = Screen.Confirm
                    is LinkState.Connected -> {
                        _pairedPeerName.value = state.peerName
                        _screen.value = Screen.Connected
                    }
                    is LinkState.Failed -> {
                        _notice.value = state.message
                        _screen.value = Screen.Home
                    }
                    LinkState.Idle -> {
                        if (_screen.value == Screen.Connected || _screen.value == Screen.Confirm) {
                            _screen.value = Screen.Home
                        }
                    }
                    is LinkState.Connecting -> Unit
                }
            }
        }
    }

    override fun onCleared() {
        discovery.stop()
        stateJob?.cancel()
        if (bound) {
            runCatching { appContext.unbindService(connection) }
            bound = false
        }
        super.onCleared()
    }

    private companion object {
        /**
         * Accepts `host:port` and `[ipv6]:port`. Returns null when the input is
         * not a usable address, so the caller can say what the format is.
         */
        fun parseTarget(input: String): Pair<String, Int>? {
            val trimmed = input.trim()
            val colon = trimmed.lastIndexOf(':')
            if (colon <= 0) return null
            val host = trimmed.substring(0, colon).trim().removePrefix("[").removeSuffix("]")
            val port = trimmed.substring(colon + 1).trim().toIntOrNull() ?: return null
            if (host.isEmpty() || port !in 1..65535) return null
            return host to port
        }
    }
}
