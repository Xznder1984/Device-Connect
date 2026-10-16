// Pairing confirmation code (docs/protocol.md 3.3).
// code = base10(be32(SHA256("dc-confirm-v1" || min(pkA,pkB) || max(pkA,pkB))[0..4])) mod 1000000

import { createHash } from "node:crypto";

const LABEL = Buffer.from("dc-confirm-v1", "ascii");

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

export function confirmationCode(pkA: Uint8Array, pkB: Uint8Array): string {
  const [lo, hi] = compareBytes(pkA, pkB) <= 0 ? [pkA, pkB] : [pkB, pkA];
  const h = createHash("sha256");
  h.update(LABEL);
  h.update(lo);
  h.update(hi);
  const digest = h.digest();
  const value = digest.readUInt32BE(0) % 1_000_000;
  return value.toString().padStart(6, "0");
}
