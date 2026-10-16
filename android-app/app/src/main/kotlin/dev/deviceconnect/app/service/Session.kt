package dev.deviceconnect.app.service

import com.southernstorm.noise.protocol.HandshakeState
import dev.deviceconnect.app.net.Identity
import dev.deviceconnect.protocol.Channel
import dev.deviceconnect.protocol.DeviceInfo
import dev.deviceconnect.protocol.ErrorCode
import dev.deviceconnect.protocol.ErrorBody
import dev.deviceconnect.protocol.Frame
import dev.deviceconnect.protocol.Framing
import dev.deviceconnect.protocol.HandshakeRunner
import dev.deviceconnect.protocol.MType
import dev.deviceconnect.protocol.ProtocolException
import dev.deviceconnect.protocol.Response
import dev.deviceconnect.protocol.SecureTransport
import dev.deviceconnect.protocol.Wire
import dev.deviceconnect.protocol.WireStream
import java.io.Closeable
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * One live connection to a PC: socket, Noise handshake, record layer and the
 * control plane that speaks on top of them (docs/protocol.md section 2 and 5).
 *
 * The phone is the dialer in QR and manual mode, so it is the initiator; the
 * role is a parameter so the same class can host the listener side later. This
 * class holds no Android types, which is what lets it be exercised against a
 * loopback socket in a plain JVM test.
 */
class Session(
    private val identity: Identity,
    private val role: Int,
    /** Noise prologue: 0x00 + 16-byte QR nonce, or bare 0x01 (section 2.2). */
    private val prologue: ByteArray,
    /** Pinned peer static key, or null on first pairing. */
    private val pinnedPeer: ByteArray?,
    private val device: DeviceInfo,
    /**
     * Capabilities the user has actually switched on, advertised in `hello`.
     * Read at connect time: the user can revoke a capability afterwards, and
     * that is enforced per-request by the handler, not by the hello.
     */
    private val enabledCaps: List<String>,
    /** Called once the handshake and hello exchange are done. */
    private val onConnected: (remoteStatic: ByteArray, paired: Boolean) -> Unit,
    /** Called when the connection ends for any reason. [message] is safe to show. */
    private val onDisconnected: (message: String) -> Unit,
) : Closeable {

    private val running = AtomicBoolean(false)
    private var socket: Socket? = null
    private var transport: SecureTransport? = null

    @Volatile
    var control: ControlPlane? = null
        private set

    @Volatile
    var remoteStatic: ByteArray? = null
        private set

    private var readThread: Thread? = null

    /**
     * Dial [host]:[port], then run the handshake and read loop on a background
     * thread. Returns as soon as the socket is connected; [onConnected] is the
     * single point where the session becomes usable.
     */
    fun connect(host: String, port: Int, timeoutMs: Int = 8_000) {
        if (!running.compareAndSet(false, true)) return

        val s = Socket()
        socket = s
        s.connect(InetSocketAddress(host, port), timeoutMs)
        s.tcpNoDelay = true

        val wire = WireStream(s.getInputStream(), s.getOutputStream())

        readThread = Thread({
            try {
                // The handshake runs here, not on the caller: it must consume
                // the peer's messages, and doing it on the caller would race
                // the first frame the PC sends right after splitting.
                val noise = HandshakeRunner.run(
                    wire = wire,
                    role = role,
                    prologue = prologue,
                    staticPrivate = identity.privateKey,
                    expectedRemoteStatic = pinnedPeer,
                )
                val secure = SecureTransport(wire, noise)
                transport = secure
                remoteStatic = secure.remoteStatic

                val plane = ControlPlane(device) { frame -> secure.sendFrame(frame) }
                control = plane

                plane.onHelloAck = { ack ->
                    onConnected(secure.remoteStatic, ack.paired)
                }
                plane.onProtocolMismatch = {
                    // Section 2.2: a pv mismatch aborts before other traffic.
                    fail("Peer requires a newer protocol version")
                }

                plane.sendHello(enabledCaps)
                readLoop(plane, secure)
            } catch (e: ProtocolException) {
                fail(messageFor(e))
            } catch (_: Exception) {
                fail("Connection lost")
            }
        }, "dc-session").also {
            it.isDaemon = true
            it.start()
        }
    }

    private fun readLoop(plane: ControlPlane, secure: SecureTransport) {
        while (running.get()) {
            val frame = try {
                secure.readFrame()
            } catch (_: ProtocolException) {
                fail("Connection closed")
                return
            }

            if (frame.mtype == MType.REQUEST && frame.channel != Channel.CONTROL) {
                // Requests on a channel this build does not serve get a proper
                // envelope-shaped error, so the PC sees a real answer rather
                // than a timeout (section 7).
                val reply = Response.err(
                    frame.seq.toLong(),
                    ErrorBody.of(ErrorCode.CAPABILITY_DISABLED, "channel not enabled on this device"),
                )
                try {
                    secure.sendFrame(
                        Frame(
                            frame.channel,
                            MType.RESPONSE,
                            Framing.FLAG_JSON,
                            frame.seq,
                            Wire.gson.toJson(reply).toByteArray(Charsets.UTF_8),
                        ),
                    )
                } catch (_: Exception) {
                    fail("Connection lost")
                    return
                }
                continue
            }

            try {
                plane.onFrame(frame)
            } catch (_: Exception) {
                // A malformed control message must not kill the session; the
                // plane answers with INVALID_ARGS itself where it can.
            }
        }
    }

    private fun fail(message: String) {
        if (!running.compareAndSet(true, false)) return
        closeQuietly()
        onDisconnected(message)
    }

    private fun messageFor(e: ProtocolException): String = when (e.message) {
        "RemoteUnknown" -> "This PC is not the device you paired with"
        "Incomplete" -> "Connection closed"
        "TransportError" -> "Connection integrity check failed"
        else -> "Connection failed"
    }

    private fun closeQuietly() {
        runCatching { transport?.close() }
        runCatching { socket?.close() }
        transport = null
        socket = null
    }

    override fun close() {
        if (!running.compareAndSet(true, false)) return
        closeQuietly()
        onDisconnected("Disconnected")
    }

    /** Block until the reader thread ends, for orderly shutdown. */
    fun join(timeoutMs: Long = 2_000) {
        runCatching { readThread?.join(timeoutMs) }
    }

    companion object {
        /** Role constant, so callers need not import the Noise class. */
        const val ROLE_INITIATOR = HandshakeState.INITIATOR
        const val ROLE_RESPONDER = HandshakeState.RESPONDER

        /** Prologue for manual and mDNS modes: version byte 0x01, no QR nonce. */
        fun manualPrologue(): ByteArray = byteArrayOf(0x01)

        /** Prologue for QR mode: 0x00 followed by the 16-byte QR nonce. */
        fun qrPrologue(nonce: ByteArray): ByteArray {
            require(nonce.size == 16) { "QR nonce must be 16 bytes" }
            return byteArrayOf(0x00) + nonce
        }
    }
}
