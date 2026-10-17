package dev.deviceconnect.protocol

import com.southernstorm.noise.protocol.HandshakeState
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

/**
 * The wire record layer (docs/protocol.md section 2.2.1).
 *
 * Every message on the stream, handshake or transport, is a `u32be` length
 * followed by exactly that many bytes. The length sits *outside* the AEAD, so
 * tampering with it can only make the tag check fail and close the connection;
 * it can never desynchronize a peer into accepting different plaintext.
 */
object Records {
    const val LENGTH_BYTES = 4

    /**
     * Largest `len` a handshake message may declare, in bytes, per section
     * 2.2.1. XX stays well under 1 KiB, so anything near this cap is a
     * malformed or hostile peer and the connection is closed.
     */
    const val MAX_HANDSHAKE_RECORD = 65536

    /**
     * Largest `len` an encrypted frame record may declare: the plaintext frame
     * (`LENGTH_BYTES + MAX_BODY_LEN`) plus the 16-byte Poly1305 tag, which is
     * the `4 + 1_048_576 + 16` bound stated in section 2.2.1.
     */
    const val MAX_TRANSPORT_RECORD = LENGTH_BYTES + Framing.MAX_BODY_LEN + 16

    /**
     * Prefix [payload] with its length.
     *
     * [max] is the largest `len` section 2.2.1 permits, that is the size of the
     * record *after* its 4-byte prefix. The cap is checked against the declared
     * length before any allocation, so a hostile peer cannot make the receiver
     * reserve a megabyte it never sent.
     */
    fun encode(payload: ByteArray, max: Int = MAX_TRANSPORT_RECORD): ByteArray {
        if (payload.isEmpty()) throw ProtocolException("Incomplete")
        if (payload.size > max) throw ProtocolException("BodyTooLarge")
        val out = ByteArray(LENGTH_BYTES + payload.size)
        out[0] = (payload.size ushr 24).toByte()
        out[1] = (payload.size ushr 16).toByte()
        out[2] = (payload.size ushr 8).toByte()
        out[3] = payload.size.toByte()
        payload.copyInto(out, LENGTH_BYTES)
        return out
    }

    /**
     * Incremental decoder for callers that feed bytes rather than read a stream.
     *
     * Because [decode] returns the bytes it consumed, a caller can feed one read
     * at a time; this is what the record tests use to prove partial records are
     * handled.
     */
    sealed interface DecodeResult {
        class Decoded(val payload: ByteArray, val bytesConsumed: Int) : DecodeResult
        data object NeedMore : DecodeResult
    }

    fun decode(buf: ByteArray, max: Int = MAX_TRANSPORT_RECORD): DecodeResult {
        if (buf.size < LENGTH_BYTES) return DecodeResult.NeedMore
        val len = ((buf[0].toInt() and 0xFF) shl 24) or
            ((buf[1].toInt() and 0xFF) shl 16) or
            ((buf[2].toInt() and 0xFF) shl 8) or
            (buf[3].toInt() and 0xFF)
        if (len <= 0) throw ProtocolException("BodyTooSmall")
        if (len > max) throw ProtocolException("BodyTooLarge")
        val total = LENGTH_BYTES + len
        if (buf.size < total) return DecodeResult.NeedMore
        return DecodeResult.Decoded(buf.copyOfRange(LENGTH_BYTES, total), total)
    }

    /** Write one record and flush it. */
    fun write(output: OutputStream, payload: ByteArray, max: Int = MAX_TRANSPORT_RECORD) {
        output.write(encode(payload, max))
        output.flush()
    }

    /**
     * Read exactly one record.
     *
     * @throws ProtocolException `Incomplete` on a truncated record or one that
     *   ends the stream, `BodyTooSmall` on a zero length, `BodyTooLarge` above
     *   [max].
     */
    fun read(input: DataInputStream, max: Int = MAX_TRANSPORT_RECORD): ByteArray {
        val len = try {
            input.readInt()
        } catch (e: EOFException) {
            throw ProtocolException("Incomplete")
        }
        if (len <= 0) throw ProtocolException("BodyTooSmall")
        if (len > max) throw ProtocolException("BodyTooLarge")
        val payload = ByteArray(len)
        try {
            input.readFully(payload)
        } catch (e: EOFException) {
            throw ProtocolException("Incomplete")
        }
        return payload
    }
}

/**
 * Buffered, big-endian reader and writer shared by the handshake and the
 * session.
 *
 * This exists because `BufferedInputStream` reads ahead. If the handshake and
 * the session each wrapped the socket in their own buffer, the handshake's
 * buffer would swallow the leading bytes of the first transport record and the
 * session would hang waiting for bytes that were already consumed. Creating the
 * buffer once and reusing it across both phases is what makes the transition
 * safe, so this type is the unit callers hold instead of raw streams.
 */
class WireStream(
    input: InputStream,
    output: OutputStream,
) {
    val input: DataInputStream = DataInputStream(BufferedInputStream(input, 64 * 1024))
    val output: DataOutputStream = DataOutputStream(BufferedOutputStream(output, 64 * 1024))
}

/**
 * Drives the Noise XX handshake over a stream and returns the transport pair.
 *
 * Both sides may be initiator or responder (docs/protocol.md section 2.1), so
 * the role is a parameter rather than baked in. The caller owns [wire] and must
 * hand the same instance to [SecureTransport] afterwards; that shared instance
 * is what prevents the read-ahead loss described on [WireStream].
 */
object HandshakeRunner {
    fun run(
        wire: WireStream,
        role: Int,
        prologue: ByteArray,
        staticPrivate: ByteArray,
        expectedRemoteStatic: ByteArray? = null,
        fixedEphemeralPrivate: ByteArray? = null,
    ): NoiseTransport {
        val state = Noise.handshake(role, prologue, staticPrivate, fixedEphemeralPrivate)

        // The transport must be split *before* the handshake state is destroyed.
        // split() derives the transport keys from the handshake's symmetric
        // state, and HandshakeState.destroy() clears that state
        // (SymmetricState.destroy() nulls its cipher), after which split()
        // throws a NullPointerException. The pair split() returns is built from
        // forked CipherState objects, so it outlives the handshake state.
        val transport = try {
            if (role == HandshakeState.INITIATOR) {
                Records.write(wire.output, Noise.write(state, ByteArray(0)), Records.MAX_HANDSHAKE_RECORD)
                Noise.read(state, Records.read(wire.input, Records.MAX_HANDSHAKE_RECORD))
                Records.write(wire.output, Noise.write(state, ByteArray(0)), Records.MAX_HANDSHAKE_RECORD)
            } else {
                Noise.read(state, Records.read(wire.input, Records.MAX_HANDSHAKE_RECORD))
                Records.write(wire.output, Noise.write(state, ByteArray(0)), Records.MAX_HANDSHAKE_RECORD)
                Noise.read(state, Records.read(wire.input, Records.MAX_HANDSHAKE_RECORD))
            }
            if (state.getAction() != HandshakeState.SPLIT) {
                throw ProtocolException("HandshakeIncomplete")
            }
            Noise.transport(state)
        } finally {
            state.destroy()
        }

        if (expectedRemoteStatic != null && !transport.remoteStatic.contentEquals(expectedRemoteStatic)) {
            transport.destroy()
            throw ProtocolException("RemoteUnknown")
        }
        return transport
    }
}

/**
 * Encrypted frame transport: the frame codec, the Noise transport and the
 * record layer, wired together so callers only see [Frame]s.
 *
 * One frame is one record. Reads are strictly sequential, which is what Noise's
 * in-order nonces require; writes are serialized so two threads can never
 * interleave a single record.
 */
class SecureTransport(
    private val wire: WireStream,
    private val transport: NoiseTransport,
) {
    private val writeLock = Any()

    /** The peer's static public key, from the completed handshake. */
    val remoteStatic: ByteArray get() = transport.remoteStatic

    fun sendFrame(frame: Frame) {
        val ciphertext = transport.encrypt(Framing.encode(frame))
        synchronized(writeLock) { Records.write(wire.output, ciphertext) }
    }

    /**
     * Read and decrypt the next frame.
     *
     * @throws ProtocolException on a malformed record, a failed tag check, or
     *   end of stream. Any of these means the connection is unusable.
     */
    fun readFrame(): Frame {
        val plaintext = transport.decrypt(Records.read(wire.input))
        return when (val result = Framing.decode(plaintext)) {
            is Framing.DecodeResult.Decoded -> result.frame
            Framing.DecodeResult.NeedMore -> throw ProtocolException("Incomplete")
        }
    }

    fun close() {
        runCatching { transport.destroy() }
        runCatching { wire.input.close() }
        runCatching { wire.output.close() }
    }
}
