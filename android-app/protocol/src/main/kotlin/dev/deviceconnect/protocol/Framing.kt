package dev.deviceconnect.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * A single protocol frame (docs/protocol.md section 2.3).
 *
 * Wire layout, all big-endian:
 * ```
 * u32 body_len   (length of everything after this field; >= 8)
 * u8  channel
 * u8  mtype
 * u16 flags
 * u32 seq
 * ... payload (body_len - 8 bytes)
 * ```
 */
class Frame(
    val channel: Int,
    val mtype: Int,
    val flags: Int,
    val seq: Long,
    val payload: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Frame) return false
        return channel == other.channel &&
            mtype == other.mtype &&
            flags == other.flags &&
            seq == other.seq &&
            payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = channel
        result = 31 * result + mtype
        result = 31 * result + flags
        result = 31 * result + seq.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }

    override fun toString(): String =
        "Frame(channel=$channel, mtype=$mtype, flags=$flags, seq=$seq, payload=${payload.size}B)"

    companion object {
        /** Human-readable hex for logs and test failures. Never log payload content. */
        fun describe(frame: Frame): String =
            "ch=0x%02x mtype=0x%02x flags=0x%04x seq=%d len=%d"
                .format(frame.channel, frame.mtype, frame.flags, frame.seq, frame.payload.size)
    }
}

/** Message type bytes. Their meaning depends on the channel. */
object MType {
    const val REQUEST = 0x01
    const val RESPONSE = 0x02
    const val EVENT = 0x03
    const val ERROR = 0x04

    /** Files channel: binary chunk (mtype 0x10). */
    const val FILE_DATA = 0x10

    /** Video channel: codec config, access unit, access unit fragment. */
    const val VIDEO_CONFIG = 0x01
    const val VIDEO_AU = 0x02
    const val VIDEO_AU_FRAGMENT = 0x03
}

/** Frame codec. Mirrors `protocol/rust/src/framing.rs` and the TypeScript port. */
object Framing {
    const val FRAME_HEADER_LEN = 4
    const val MIN_BODY_LEN = 8
    const val MAX_BODY_LEN = 1_048_576
    const val FLAG_JSON = 0x0001

    sealed interface DecodeResult {
        /** A complete frame plus how many bytes it consumed. */
        class Decoded(val frame: Frame, val bytesConsumed: Int) : DecodeResult

        /** Not enough bytes buffered yet; feed more and retry. */
        data object NeedMore : DecodeResult
    }

    fun encode(frame: Frame): ByteArray {
        if (frame.payload.size > MAX_BODY_LEN - MIN_BODY_LEN) throw ProtocolException("BodyTooLarge")
        val bodyLen = MIN_BODY_LEN + frame.payload.size
        val buf = ByteBuffer.allocate(FRAME_HEADER_LEN + bodyLen).order(ByteOrder.BIG_ENDIAN)
        buf.putInt(bodyLen)
        buf.put(frame.channel.toByte())
        buf.put(frame.mtype.toByte())
        buf.putShort(frame.flags.toShort())
        buf.putInt(frame.seq.toInt())
        buf.put(frame.payload)
        return buf.array()
    }

    /**
     * Decode one frame from the start of [buf].
     *
     * @throws ProtocolException `BodyTooSmall` when the declared body is below the
     *   minimum, `BodyTooLarge` when it exceeds the maximum.
     */
    fun decode(buf: ByteArray): DecodeResult {
        if (buf.size < FRAME_HEADER_LEN) return DecodeResult.NeedMore
        val bb = ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN)
        // Read the length as unsigned: 0xffffffff must report BodyTooLarge, not a
        // negative value that would look smaller than the minimum.
        val bodyLen = bb.getInt(0).toLong() and 0xFFFFFFFFL
        if (bodyLen < MIN_BODY_LEN) throw ProtocolException("BodyTooSmall")
        if (bodyLen > MAX_BODY_LEN) throw ProtocolException("BodyTooLarge")
        val total = (FRAME_HEADER_LEN + bodyLen).toInt()
        if (buf.size < total) return DecodeResult.NeedMore
        val frame = Frame(
            channel = buf[4].toInt() and 0xFF,
            mtype = buf[5].toInt() and 0xFF,
            flags = bb.getShort(6).toInt() and 0xFFFF,
            seq = bb.getInt(8).toLong() and 0xFFFFFFFFL,
            payload = buf.copyOfRange(12, total),
        )
        return DecodeResult.Decoded(frame, total)
    }
}

/**
 * Incremental decoder for a byte stream.
 *
 * Never assumes message boundaries line up with transport reads.
 */
class FrameDecoder {
    private var buf = ByteArray(0)

    val buffered: Int get() = buf.size

    fun feed(bytes: ByteArray) {
        if (bytes.isEmpty()) return
        val merged = ByteArray(buf.size + bytes.size)
        System.arraycopy(buf, 0, merged, 0, buf.size)
        System.arraycopy(bytes, 0, merged, buf.size, bytes.size)
        buf = merged
    }

    /**
     * @return the next complete frame, or null when more bytes are needed.
     * @throws ProtocolException on a malformed frame header.
     */
    fun next(): Frame? {
        return when (val result = Framing.decode(buf)) {
            is Framing.DecodeResult.Decoded -> {
                buf = buf.copyOfRange(result.bytesConsumed, buf.size)
                result.frame
            }

            Framing.DecodeResult.NeedMore -> null
        }
    }
}

/**
 * Files channel binary payload: u32 transfer id, u64 offset, then the chunk.
 * The offset is a `Long` used as unsigned; it can exceed 2^53.
 */
class FileData(val transferId: Int, val offset: Long, val chunk: ByteArray) {
    init {
        require(chunk.size <= MAX_FILE_CHUNK) { "chunk exceeds $MAX_FILE_CHUNK bytes" }
    }

    fun encode(): ByteArray {
        val out = ByteBuffer.allocate(12 + chunk.size).order(ByteOrder.BIG_ENDIAN)
        out.putInt(transferId)
        out.putLong(offset)
        out.put(chunk)
        return out.array()
    }

    companion object {
        const val MAX_FILE_CHUNK = 65536

        fun decode(payload: ByteArray): FileData {
            if (payload.size < 12) throw ProtocolException("Incomplete")
            val bb = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
            val transferId = bb.getInt(0)
            val offset = bb.getLong(4)
            val chunk = payload.copyOfRange(12, payload.size)
            if (chunk.size > MAX_FILE_CHUNK) throw ProtocolException("BodyTooLarge")
            return FileData(transferId, offset, chunk)
        }
    }
}

/** Video channel access unit: u64 timestamp in milliseconds, then Annex B bytes. */
class VideoAccessUnit(val timestampMs: Long, val data: ByteArray) {
    fun encode(): ByteArray {
        val out = ByteBuffer.allocate(8 + data.size).order(ByteOrder.BIG_ENDIAN)
        out.putLong(timestampMs)
        out.put(data)
        return out.array()
    }

    companion object {
        fun decode(payload: ByteArray): VideoAccessUnit {
            if (payload.size < 8) throw ProtocolException("Incomplete")
            val bb = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
            return VideoAccessUnit(bb.getLong(0), payload.copyOfRange(8, payload.size))
        }
    }
}
