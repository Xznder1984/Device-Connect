// Frame codec for the Device Connect protocol (docs/protocol.md 2.3).
// Reference behaviour is the Rust crate in protocol/rust; this port exists so
// TypeScript clients (and the conformance suite) agree on the wire format.

export const FRAME_HEADER_LEN = 4;
export const MIN_BODY_LEN = 8;
export const MAX_BODY_LEN = 1_048_576;
export const FLAG_JSON = 0x0001;

export const MTYPE = {
  request: 0x01,
  response: 0x02,
  event: 0x03,
  error: 0x04,
  fileData: 0x10,
  videoConfig: 0x01,
  videoAccessUnit: 0x02,
  videoAccessUnitFragment: 0x03,
} as const;

export interface Frame {
  channel: number;
  mtype: number;
  flags: number;
  seq: number;
  payload: Uint8Array;
}

export type DecodeResult =
  | { kind: "frame"; frame: Frame; bytesConsumed: number }
  | { kind: "need-more" };

/** Thrown for frames that violate the length bounds. */
export class FrameError extends Error {}

export function encodeFrame(frame: Frame): Uint8Array {
  const bodyLen = MIN_BODY_LEN + frame.payload.length;
  if (bodyLen > MAX_BODY_LEN) {
    throw new FrameError("BodyTooLarge");
  }
  const out = new Uint8Array(FRAME_HEADER_LEN + bodyLen);
  const view = new DataView(out.buffer);
  view.setUint32(0, bodyLen, false);
  out[4] = frame.channel;
  out[5] = frame.mtype;
  view.setUint16(6, frame.flags, false);
  view.setUint32(8, frame.seq, false);
  out.set(frame.payload, 12);
  return out;
}

export function decodeFrame(buf: Uint8Array): DecodeResult {
  if (buf.length < FRAME_HEADER_LEN) {
    return { kind: "need-more" };
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const bodyLen = view.getUint32(0, false);
  if (bodyLen < MIN_BODY_LEN) {
    throw new FrameError("BodyTooSmall");
  }
  if (bodyLen > MAX_BODY_LEN) {
    throw new FrameError("BodyTooLarge");
  }
  const total = FRAME_HEADER_LEN + bodyLen;
  if (buf.length < total) {
    return { kind: "need-more" };
  }
  return {
    kind: "frame",
    bytesConsumed: total,
    frame: {
      channel: buf[4],
      mtype: buf[5],
      flags: view.getUint16(6, false),
      seq: view.getUint32(8, false),
      payload: buf.slice(12, total),
    },
  };
}

/** Incremental decoder for a byte stream. */
export class FrameDecoder {
  private buf: Uint8Array = new Uint8Array(0);

  feed(bytes: Uint8Array): void {
    const merged = new Uint8Array(this.buf.length + bytes.length);
    merged.set(this.buf, 0);
    merged.set(bytes, this.buf.length);
    this.buf = merged;
  }

  next(): Frame | null {
    const result = decodeFrame(this.buf);
    if (result.kind === "need-more") {
      return null;
    }
    this.buf = this.buf.slice(result.bytesConsumed);
    return result.frame;
  }

  buffered(): number {
    return this.buf.length;
  }
}

/**
 * Files data payload: u32be transfer_id, u64be offset, chunk.
 * Offset uses bigint: it can exceed Number.MAX_SAFE_INTEGER.
 */
export interface FileData {
  transferId: number;
  offset: bigint;
  chunk: Uint8Array;
}

export const MAX_FILE_CHUNK = 65536;

export function encodeFileData(data: FileData): Uint8Array {
  const out = new Uint8Array(12 + data.chunk.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, data.transferId, false);
  view.setBigUint64(4, data.offset, false);
  out.set(data.chunk, 12);
  return out;
}

export function decodeFileData(payload: Uint8Array): FileData {
  if (payload.length < 12) {
    throw new FrameError("Incomplete");
  }
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const chunk = payload.slice(12);
  if (chunk.length > MAX_FILE_CHUNK) {
    throw new FrameError("BodyTooLarge");
  }
  return { transferId: view.getUint32(0, false), offset: view.getBigUint64(4, false), chunk };
}

/** Video access unit payload: u64be timestamp_ms followed by Annex B bytes. */
export interface VideoAccessUnit {
  timestampMs: bigint;
  data: Uint8Array;
}

export function encodeVideoAccessUnit(au: VideoAccessUnit): Uint8Array {
  const out = new Uint8Array(8 + au.data.length);
  new DataView(out.buffer).setBigUint64(0, au.timestampMs, false);
  out.set(au.data, 8);
  return out;
}

export function decodeVideoAccessUnit(payload: Uint8Array): VideoAccessUnit {
  if (payload.length < 8) {
    throw new FrameError("Incomplete");
  }
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  return { timestampMs: view.getBigUint64(0, false), data: payload.slice(8) };
}
