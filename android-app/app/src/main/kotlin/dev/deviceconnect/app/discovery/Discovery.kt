package dev.deviceconnect.app.discovery

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Finds PCs advertising `_deviceconnect._tcp` on the local network
 * (docs/protocol.md section 2.1).
 *
 * The phone is the dialer in every mode, so this class only discovers; it never
 * advertises a service, because the phone does not accept inbound connections in
 * v1. Advertising a service that nothing listens on would make the phone look
 * connectable when it is not, so that is deliberately left out.
 *
 * Two practical details:
 *  - mDNS answers are often multicast and the Wi-Fi stack filters them unless a
 *    `MulticastLock` is held, so one is taken for the lifetime of a scan;
 *  - `NsdManager.resolveService` fails if several resolves run at once on some
 *    devices, so found services are queued and resolved one at a time.
 */
class Discovery(context: Context) {

    /** A PC that answered and resolved to a usable address. */
    class Peer(
        val name: String,
        val host: String,
        val port: Int,
        val id: String?,
        val role: String?,
    ) {
        /** Stable key for de-duplication while scanning. */
        val key: String get() = "$host:$port"

        override fun equals(other: Any?): Boolean =
            other is Peer && name == other.name && host == other.host &&
                port == other.port && id == other.id && role == other.role

        override fun hashCode(): Int = key.hashCode()
    }

    private val appContext = context.applicationContext
    private val nsd: NsdManager? =
        appContext.getSystemService(Context.NSD_SERVICE) as? NsdManager

    private val running = AtomicBoolean(false)
    private val found = ConcurrentHashMap<String, Peer>()

    private val resolveQueue = LinkedBlockingQueue<NsdServiceInfo>()
    private var resolverThread: Thread? = null
    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private var multicastLock: WifiManager.MulticastLock? = null

    private var onChanged: ((List<Peer>) -> Unit)? = null
    private var onError: ((String) -> Unit)? = null

    /**
     * Begin scanning. [onChanged] is called on every change with the full,
     * sorted list; it may be called from a binder thread, so callers must be
     * thread-safe (a `StateFlow` update is).
     */
    fun start(onChanged: (List<Peer>) -> Unit, onError: (String) -> Unit) {
        if (!running.compareAndSet(false, true)) return
        this.onChanged = onChanged
        this.onError = onError
        found.clear()

        val manager = nsd
        if (manager == null) {
            running.set(false)
            onError("Network discovery is unavailable on this device")
            return
        }

        acquireMulticastLock()
        startResolver(manager)

        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) = Unit

            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                // Resolution is the only way to learn host, port and TXT, and it
                // is serialized through the queue.
                resolveQueue.offer(serviceInfo)
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                val name = serviceInfo.serviceName ?: return
                found.remove(name)
                publish()
            }

            override fun onDiscoveryStopped(serviceType: String) = Unit

            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                fail("Could not start network discovery (code $errorCode)")
            }

            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit
        }
        discoveryListener = listener

        runCatching { manager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener) }
            .onFailure { fail("Could not start network discovery") }
    }

    /** Stop scanning and release the multicast lock. Safe to call twice. */
    fun stop() {
        if (!running.compareAndSet(true, false)) return
        val manager = nsd
        val listener = discoveryListener
        if (manager != null && listener != null) {
            runCatching { manager.stopServiceDiscovery(listener) }
        }
        discoveryListener = null
        resolveQueue.clear()
        resolverThread?.interrupt()
        resolverThread = null
        releaseMulticastLock()
    }

    private fun startResolver(manager: NsdManager) {
        resolverThread = Thread({
            while (running.get()) {
                val info = try {
                    resolveQueue.take()
                } catch (_: InterruptedException) {
                    return@Thread
                }
                resolveOne(manager, info)
            }
        }, "dc-mdns-resolve").also {
            it.isDaemon = true
            it.start()
        }
    }

    private fun resolveOne(manager: NsdManager, info: NsdServiceInfo) {
        // Resolve callbacks arrive on a binder thread; resolveOne returns before
        // the peer is known, which is why the queue drains serially.
        @Suppress("DEPRECATION")
        manager.resolveService(
            info,
            object : NsdManager.ResolveListener {
                override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) = Unit

                override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                    if (!running.get()) return
                    val host = serviceInfo.host?.hostAddress
                        ?: serviceInfo.host?.hostName
                        ?: return
                    val port = serviceInfo.port
                    if (port <= 0) return

                    val attributes = serviceInfo.attributes ?: emptyMap()
                    val role = attribute(attributes, "role")
                    // Only PCs are dialable in v1; a `phone` record would be a
                    // peer that expects us to listen, which this build does not do.
                    if (role != null && role != "pc") return

                    val id = attribute(attributes, "id")
                    val name = attribute(attributes, "name")
                        ?: serviceInfo.serviceName?.substringBefore('.')
                        ?: host

                    val peer = Peer(name = name, host = host, port = port, id = id, role = role)
                    found[serviceInfo.serviceName ?: peer.key] = peer
                    publish()
                }
            },
        )
    }

    private fun attribute(attributes: Map<String, ByteArray>, key: String): String? =
        attributes[key]?.let { String(it, Charsets.UTF_8) }?.takeIf { it.isNotEmpty() }

    private fun publish() {
        val list = found.values.sortedBy { it.name.lowercase() }
        onChanged?.invoke(list)
    }

    private fun fail(message: String) {
        if (!running.compareAndSet(true, false)) return
        releaseMulticastLock()
        onError?.invoke(message)
    }

    private fun acquireMulticastLock() {
        val wifi = appContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return
        multicastLock = runCatching {
            wifi.createMulticastLock(MULTICAST_LOCK_TAG).apply {
                setReferenceCounted(false)
                acquire()
            }
        }.getOrNull()
    }

    private fun releaseMulticastLock() {
        runCatching { multicastLock?.release() }
        multicastLock = null
    }

    companion object {
        const val SERVICE_TYPE = "_deviceconnect._tcp"
        private const val MULTICAST_LOCK_TAG = "deviceconnect.mdns"
    }
}
