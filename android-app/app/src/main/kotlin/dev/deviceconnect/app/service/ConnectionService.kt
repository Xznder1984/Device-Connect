package dev.deviceconnect.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import dev.deviceconnect.app.MainActivity
import dev.deviceconnect.app.R

/**
 * Foreground service that hosts an active Device Connect session.
 *
 * The notification is the consent surface required by the project: while a
 * session is connected (and later, while the screen is being captured) the
 * system tray shows exactly that, and it cannot be dismissed without ending the
 * session. The only way out of the notification is the Disconnect action, which
 * is always present.
 */
class ConnectionService : Service() {

    /** What the notification currently claims. Kept in sync with the session. */
    enum class State {
        WAITING,
        CONNECTED,
        SCREEN_CAPTURE,
    }

    @Volatile
    var state: State = State.WAITING
        private set

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                setConnected(false)
                stopForegroundCompat()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForegroundCompat(State.WAITING)
            }
        }
        // Never be restarted silently: a session must always be re-established
        // by the user, which keeps the consent step in the loop.
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /** Flip the notification between "waiting" and "connected to your PC". */
    fun setConnected(connected: Boolean) {
        startForegroundCompat(if (connected) State.CONNECTED else State.WAITING)
    }

    /** Announce that screen capture is running, which the notification must show. */
    fun setScreenCapturing(capturing: Boolean) {
        startForegroundCompat(if (capturing) State.SCREEN_CAPTURE else State.CONNECTED)
    }

    private fun startForegroundCompat(state: State) {
        this.state = state
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
            State.CONNECTED -> getString(R.string.notif_connected_title) to
                getString(R.string.notif_connected_text)
            State.SCREEN_CAPTURE -> getString(R.string.notif_capture_title) to
                getString(R.string.notif_capture_text)
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
        const val ACTION_DISCONNECT = "dev.deviceconnect.app.DISCONNECT"

        fun start(context: Context) {
            val intent = Intent(context, ConnectionService::class.java)
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, ConnectionService::class.java)
                .setAction(ACTION_DISCONNECT)
            context.startService(intent)
        }
    }
}
