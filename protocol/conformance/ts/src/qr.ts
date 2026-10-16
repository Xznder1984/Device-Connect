// Pairing QR payload (docs/protocol.md 3.1): "dc1:" + base64url(JSON).

export const QR_PREFIX = "dc1:";
export const QR_VALIDITY_SECS = 120;
export const NONCE_LEN = 16;

export class QrError extends Error {}

export interface QrPayload {
  v: number;
  /** One-time pairing nonce, base64url of 16 bytes (22 chars). */
  n: string;
  /** TCP port of the PC listener. */
  p: number;
  /** Host name or IP literal (optional). */
  h?: string;
  /** Unix seconds after which the QR is rejected. */
  exp: number;
  /** PC device name (optional). */
  name?: string;
}

export function encodeQrPayload(payload: QrPayload): string {
  return QR_PREFIX + Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

export function decodeQrPayload(text: string): QrPayload {
  const trimmed = text.trim();
  if (!trimmed.startsWith(QR_PREFIX)) {
    throw new QrError("BadPrefix");
  }
  const body = trimmed.slice(QR_PREFIX.length);
  let json: string;
  try {
    json = Buffer.from(body, "base64url").toString("utf8");
  } catch {
    throw new QrError("BadBase64");
  }
  // Buffer.from is lenient; verify the round-trip to catch non-base64url input.
  if (Buffer.from(json, "utf8").toString("base64url") !== body) {
    throw new QrError("BadBase64");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new QrError("BadJson");
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new QrError("BadJson");
  }
  const payload = parsed as QrPayload;
  if (payload.v !== 1) throw new QrError("BadField");
  if (typeof payload.p !== "number" || !Number.isInteger(payload.p) || payload.p < 1 || payload.p > 65535) {
    throw new QrError("BadField");
  }
  if (typeof payload.n !== "string" || payload.n.length !== 22) throw new QrError("BadField");
  const nonce = Buffer.from(payload.n, "base64url");
  if (nonce.length !== NONCE_LEN) throw new QrError("BadField");
  if (typeof payload.exp !== "number" || !Number.isInteger(payload.exp) || payload.exp < 0) {
    throw new QrError("BadField");
  }
  return payload;
}

export function qrNonceBytes(payload: QrPayload): Uint8Array {
  const nonce = Buffer.from(payload.n, "base64url");
  if (nonce.length !== NONCE_LEN) throw new QrError("BadField");
  return new Uint8Array(nonce);
}

export function isQrExpired(payload: QrPayload, nowSecs: number): boolean {
  return nowSecs > payload.exp;
}
