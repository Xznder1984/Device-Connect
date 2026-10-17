package dev.deviceconnect.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Binder
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import dev.deviceconnect.app.MainActivity
import dev.deviceconnect.app.R
import dev.deviceconnect.app.net.Identity
import dev.deviceconnect.app.net.TrustStore
import dev.deviceconnect.protocol.Confirm
import dev.deviceconnect.protocol.DeviceInfo
import dev.deviceconnect.protocol.SessionHelloAck
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
/**
 * Foreground service that owns the active Device Connect session.
 *
 * Ownership lives here rather than in the Activity so that the session survives
 * the screen being turned off or the app being swiped away, which is the whole
 * point of controlling the phone from elsewhere.
 *
 * The notification is the consent surface required by the project: while a
 * session exists the tray says exactly what stage it is at, the notification
 * cannot be swiped away, and its only action is Disconnect.
 */
class ConnectionService : Service() {

    /** What the notification currently claims. Mirrors [LinkState] in one word. */
    enum class State {
        WAITING,
        CONFIRMING,
        CONNECTED,
    }

    inner class LocalBinder : Binder() {
        fun service(): ConnectionService = this@ConnectionService
    }

    private val binder = LocalBinder()

    private lateinit var identity: Identity
    private lateinit var capabilities: CapabilityState
    private lateinit var trust: TrustStore

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _state = MutableStateFlow<LinkState>(LinkState.Idle)
    val state: StateFlow<LinkState> = _state.asStateFlow()

    /** The session, once [connect] has been called and before it ends. */
    @Volatile
    private var session: Session? = null

    /** A handshake that finished but whose peer key is not pinned yet. */
    @Volatile
    private var pendingPeer: TrustStore.Peer? = null

    override fun onCreate() {
        super.onCreate()
        identity = Identity.getOrCreate(this)
        capabilities = CapabilityState.get(this)
        trust = TrustStore(this)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                disconnect()
                return START_NOT_STICKY
            }
            else -> {
                // Only raise the idle notification. If a connect() is already
                // in flight it has set its own state, and overwriting it here
                // would flash "waiting" over "confirm pairing".
                if (_state.value is LinkState.Idle) startForegroundCompat(State.WAITING)
            }
        }
        // Never restarted silently: a session must always be re-established by
        // the user, which keeps the consent step in the loop.
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        destroyed = true
        scope.cancel()
        val current = session
        session = null
        current?.close()
        super.onDestroy()
    }

    // ---------- session lifecycle ----------

    /**
     * Dial [host]:[port] and run the handshake. [prologue] is the QR-mode or
     * manual-mode prologue (docs/protocol.md section 2.2); the caller builds it
     * because only it saw the QR nonce.
     */
    fun connect(host: String, port: Int, prologue: ByteArray) {
        if (session != null) return

        _state.value = LinkState.Connecting("$host:$port")
        startForegroundCompat(State.WAITING)
        lastRequestedHost = host
        lastRequestedPort = port

        val pinned = trust.pinned()
        val newSession = Session(
            identity = identity,
            role = Session.ROLE_INITIATOR,
            prologue = prologue,
            pinnedPeer = pinned?.publicKey,
            device = deviceInfo(),
            enabledCaps = capabilities.enabled(),
            installHandlers = { plane -> installCommandHandlers(plane) },
            onConnected = { remoteStatic, ack -> onHandshakeComplete(remoteStatic, ack) },
            onDisconnected = { message -> onSessionEnded(message) },
        )
        session = newSession

        scope.launch {
            try {
                newSession.connect(host, port)
            } catch (_: Exception) {
                // Dial, DNS or socket setup failed before the reader thread
                // started, so onDisconnected will not fire on its own.
                onSessionEnded("Could not reach that PC")
            }
        }
    }

    /** End the current session and remove the notification. */
    fun disconnect() {
        val current = session
        session = null
        pendingPeer = null
        if (current != null) {
            // close() reports through onDisconnected, which finishes the state
            // transition and stops the service.
            current.close()
        } else {
            finish(LinkState.Idle)
        }
    }

    /**
     * The user compared the confirmation code on both devices and it matched
     * (docs/protocol.md section 3.4). This is the only place a peer key is
     * pinned, and it is only reachable from a tap on the phone.
     */
    fun confirmPairing() {
        val peer = pendingPeer ?: return
        trust.pin(peer)
        pendingPeer = null
        startForegroundCompat(State.CONNECTED)
        _state.value = LinkState.Connected(peer.name, peer.id)
    }

    /**
     * The user says the codes do not match, or declined. Treat it as an active
     * man-in-the-middle attempt: pin nothing and drop the connection.
     */
    fun rejectPairing() {
        pendingPeer = null
        disconnect()
    }

    /** True when this phone already holds a pinned peer key. */
    fun isPaired(): Boolean = trust.pinned() != null

    /** The pinned peer's display name, for the "reconnect" affordance. */
    fun pairedPeerName(): String? = trust.pinned()?.name

    /** The PC's the pane remembers, so "Connect" can redial without re-pairing. */
    fun lastTarget(): Pair<String, Int>? {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        val host = prefs.getString(KEY_LAST_HOST, null) ?: return null
        val port = prefs.getInt(KEY_LAST_PORT, 0)
        return if (port in 1..65535) host to port else null
    }

    /** Forget the pinned peer without needing a live connection. */
    fun forgetPeer() {
        trust.clear()
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        prefs.edit().remove(KEY_LAST_HOST).remove(KEY_LAST_PORT).apply()
    }

    private fun installCommandHandlers(plane: ControlPlane) {
        val handlers = CommandHandlers(
            context = this,
            capabilities = capabilities,
            onUnpair = {
                // Revocation must win even if the connection lingers: clear
                // trust first, then drop the link.
                forgetPeer()
                disconnect()
            },
        )
        handlers.register(plane)
    }

    private fun onHandshakeComplete(remoteStatic: ByteArray, ack: SessionHelloAck) {
        rememberTarget()
        val pinned = trust.pinned()
        if (pinned == null) {
            // First pairing: show the code and wait for a human to confirm.
            startForegroundCompat(State.CONFIRMING)
            pendingPeer = TrustStore.Peer(
                id = ack.device.id,
                name = ack.device.name,
                publicKey = remoteStatic,
            )
            _state.value = LinkState.AwaitingConfirmation(
                peerName = ack.device.name,
                peerId = ack.device.id,
                code = Confirm.code(identity.publicKey, remoteStatic),
            )
            return
        }

        // A pinned peer that does not match never reaches here: the handshake
        // itself fails with RemoteUnknown (see Session.messageFor).
        startForegroundCompat(State.CONNECTED)
        _state.value = LinkState.Connected(pinned.name, pinned.id)
    }

    private fun onSessionEnded(message: String) {
        if (destroyed) return
        session = null
        pendingPeer = null
        finish(if (message == DISCONNECTED) LinkState.Idle else LinkState.Failed(message))
    }

    private fun finish(state: LinkState) {
        _state.value = state
        stopForegroundCompat()
        stopSelf()
    }

    /** How this phone introduces itself in `hello` (docs/protocol.md section 2.2). */
    private fun deviceInfo(): DeviceInfo = DeviceInfo(
        id = identity.deviceId,
        name = Build.MODEL?.takeIf { it.isNotBlank() } ?: "Android phone",
        model = Build.MODEL,
        os = "Android ${Build.VERSION.RELEASE}",
    )

    private fun rememberTarget() {
        val host = lastRequestedHost ?: return
        val port = lastRequestedPort
        if (port <= 0) return
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
            .putString(KEY_LAST_HOST, host)
            .putInt(KEY_LAST_PORT, port)
            .apply()
    }

    // ---------- notification ----------

    private fun startForegroundCompat(state: State) {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, buildNotification(state), type)
    }

    private fun stopForegroundCompat() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notif_channel_connection),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.notif_channel_connection_desc)
            setShowBadge(false)
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(state: State): Notification {
        val (title, text) = when (state) {
            State.WAITING -> getString(R.string.notif_waiting_title) to
                getString(R.string.notif_waiting_text)
            State.CONFIRMING -> getString(R.string.notif_confirm_title) to
                getString(R.string.notif_confirm_text)
            State.CONNECTED -> getString(R.string.notif_connected_title) to
                getString(R.string.notif_connected_text)
        }

        val disconnectPending = PendingIntent.getService(
            this,
            0,
            Intent(this, ConnectionService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val contentPending = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(contentPending)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .addAction(
                R.drawable.ic_notification,
                getString(R.string.action_disconnect),
                disconnectPending,
            )
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "deviceconnect.connection"
        private const val NOTIFICATION_ID = 1
        private const val PREFS = "deviceconnect.lasttarget"
        private const val KEY_LAST_HOST = "host"
        private const val KEY_LAST_PORT = "port"

        /** Value [Session] reports for a clean, user-initiated close. */
        const val DISCONNECTED = "Disconnected"

        const val ACTION_DISCONNECT = "dev.deviceconnect.app.DISCONNECT"

        /** Bring the service up in the foreground without a session yet. */
        fun start(context: Context) {
            context.startForegroundService(Intent(context, ConnectionService::class.java))
        }
    }

    // The host/port of the attempt in flight, kept only to remember it on success.
    @Volatile
    private var lastRequestedHost: String? = null

    @Volatile
    private var lastRequestedPort: Int = 0

    /** Set during onDestroy so late callbacks cannot touch a dying service. */
    @Volatile
    private var destroyed = false
}
