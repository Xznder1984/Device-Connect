// Device Connect protocol conformance tests.
//
// Runs the committed golden vectors in ../../../test-vectors against this
// TypeScript implementation, and validates every sample message against the
// JSON Schemas in ../../../schema. The Rust crate (protocol/rust) and the
// Kotlin module (android-app/protocol) run the same vectors.

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import Ajv2020 from "ajv/dist/2020.js";

import {
  FrameDecoder,
  FrameError,
  FLAG_JSON,
  encodeFrame,
  decodeFrame,
} from "../src/framing.ts";
import { confirmationCode } from "../src/confirm.ts";
import { decodeQrPayload, encodeQrPayload, isQrExpired, qrNonceBytes } from "../src/qr.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorsDir = path.resolve(here, "../../../test-vectors");
const schemaDir = path.resolve(here, "../../../schema");

function loadVector(name: string): any {
  return JSON.parse(readFileSync(path.join(vectorsDir, name), "utf8"));
}

function loadSchemaText(name: string): any {
  return JSON.parse(readFileSync(path.join(schemaDir, name), "utf8"));
}

function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

const schemaFiles = readdirSync(schemaDir).filter((f) => f.endsWith(".schema.json"));

test("framing: valid vectors decode and re-encode byte-for-byte", () => {
  const vectors = loadVector("frames.json");
  assert.ok(vectors.valid.length >= 6, "expected several valid frame vectors");
  for (const v of vectors.valid) {
    const bytes = fromHex(v.hex);
    const result = decodeFrame(bytes);
    assert.equal(result.kind, "frame", `${v.name}: expected a frame`);
    if (result.kind !== "frame") continue;
    const { frame } = result;
    assert.equal(frame.channel, v.expect.channel, `${v.name} channel`);
    assert.equal(frame.mtype, v.expect.mtype, `${v.name} mtype`);
    assert.equal(frame.flags, v.expect.flags, `${v.name} flags`);
    assert.equal(frame.seq, v.expect.seq, `${v.name} seq`);
    if (v.expect.payloadHex !== undefined) {
      assert.equal(toHex(frame.payload), v.expect.payloadHex, `${v.name} payload bytes`);
    }
    if (v.expect.payloadJson !== undefined) {
      assert.deepEqual(
        JSON.parse(Buffer.from(frame.payload).toString("utf8")),
        v.expect.payloadJson,
        `${v.name} payload JSON`,
      );
    }
    assert.equal(toHex(encodeFrame(frame)), v.hex.toLowerCase(), `${v.name} re-encode`);
  }
});

test("framing: invalid vectors are rejected with the documented reason", () => {
  const vectors = loadVector("frames.json");
  assert.ok(vectors.invalid.length >= 3);
  for (const v of vectors.invalid) {
    assert.throws(
      () => decodeFrame(fromHex(v.hex)),
      (err: unknown) => err instanceof FrameError && err.message === v.error,
      `${v.name} should fail with ${v.error}`,
    );
  }
});

test("framing: stream reassembly across arbitrary chunk boundaries", () => {
  const vectors = loadVector("frames.json");
  const bytes = fromHex(vectors.valid[2].hex);
  for (const split of [1, 3, 11, bytes.length - 1]) {
    const dec = new FrameDecoder();
    dec.feed(bytes.slice(0, split));
    const first = dec.next();
    dec.feed(bytes.slice(split));
    const frame = first ?? dec.next();
    assert.ok(frame, `frame complete after split ${split}`);
    assert.equal(frame!.seq, vectors.valid[2].expect.seq, `seq after split ${split}`);
    assert.equal(dec.next(), null, "no extra frames");
  }
});

test("framing: json flag helper matches vector flags", () => {
  const vectors = loadVector("frames.json");
  for (const v of vectors.valid) {
    const result = decodeFrame(fromHex(v.hex));
    if (result.kind !== "frame") continue;
    if (v.expect.payloadJson !== undefined) {
      assert.ok((result.frame.flags & FLAG_JSON) !== 0, `${v.name} sets JSON flag`);
    }
  }
});

test("qr: valid vectors round-trip and expire as documented", () => {
  const vectors = loadVector("qr.json");
  for (const v of vectors.valid) {
    const payload = decodeQrPayload(v.encoded);
    assert.deepEqual(payload, v.json, "decoded payload matches JSON");
    assert.equal(encodeQrPayload(payload), v.encoded, "re-encoded QR is identical");
    assert.equal(toHex(qrNonceBytes(payload)), v.nonceHex, "nonce bytes");
    assert.equal(isQrExpired(payload, v.expiredAt), true, "expired at documented time");
    assert.equal(isQrExpired(payload, v.json.exp - 1), false, "valid one second before expiry");
  }
  for (const v of vectors.invalid) {
    if (v.error === "Expired") {
      const payload = decodeQrPayload(v.text);
      assert.equal(isQrExpired(payload, 1_700_000_500), true, `${v.name} expired`);
      continue;
    }
    assert.throws(
      () => decodeQrPayload(v.text),
      (err: unknown) => err instanceof Error && err.message === v.error,
      `${v.name} should fail with ${v.error}`,
    );
  }
});

test("pairing: confirmation codes match the vectors and are order independent", () => {
  const vectors = loadVector("confirm-code.json");
  assert.ok(vectors.pairs.length >= 3);
  for (const pair of vectors.pairs) {
    const a = fromHex(pair.pkA);
    const b = fromHex(pair.pkB);
    assert.equal(confirmationCode(a, b), pair.code, "code matches vector");
    assert.equal(confirmationCode(b, a), pair.code, "code is order independent");
    assert.match(pair.code, /^\d{6}$/, "code is six digits");
  }
});

// ---------- JSON Schema validation ----------

const ajv = new Ajv2020({ strict: false, allErrors: true });
for (const file of schemaFiles) {
  ajv.addSchema(loadSchemaText(file), file);
}

const SCHEMA_BASE = "https://device-connect.local/schema/";

function validator(name: string) {
  const v = ajv.getSchema(`${SCHEMA_BASE}${name}`);
  assert.ok(v, `schema ${name} compiles`);
  return v!;
}

/** Map a command name to the schema that defines its args. */
function schemaForCommand(cmd: string): string {
  const ns = cmd.split(".")[0];
  switch (ns) {
    case "screen":
    case "input":
    case "app":
    case "screentext":
    case "wait":
    case "security":
    case "caps":
      return "control.schema.json";
    case "notifications":
      return "notifications.schema.json";
    case "sms":
      return "messages.schema.json";
    case "calls":
      return "calls.schema.json";
    case "clipboard":
      return "clipboard.schema.json";
    case "files":
      return "files.schema.json";
    case "status":
      return "status.schema.json";
    default:
      throw new Error(`no schema mapping for command ${cmd}`);
  }
}

test("schema: every sample request validates against envelope and its channel schema", () => {
  const vectors = loadVector("typed-messages.json");
  const envelope = validator("envelope.schema.json");
  assert.ok(vectors.requests.length >= 20, "expected full command coverage");
  const seen = new Set<string>();
  for (const req of vectors.requests) {
    assert.ok(envelope(req), `envelope rejects request: ${JSON.stringify(envelope.errors)}`);
    const channelSchema = validator(schemaForCommand(req.cmd));
    assert.ok(
      channelSchema(req),
      `channel schema rejects ${req.cmd}: ${JSON.stringify(channelSchema.errors)}`,
    );
    seen.add(req.cmd);
  }
  // Coverage guard: the vectors must exercise every documented control command.
  for (const cmd of [
    "screen.start", "screen.stop", "screen.configure",
    "input.tap", "input.longpress", "input.swipe", "input.scroll", "input.text", "input.key",
    "app.open", "app.list", "screentext.get", "wait.screen",
    "security.unpair", "security.rotate", "caps.set",
    "notifications.list", "notifications.reply", "notifications.dismiss",
    "sms.list", "sms.thread", "sms.send",
    "calls.list", "calls.answer", "calls.reject", "calls.dial",
    "clipboard.get", "clipboard.set",
    "files.push", "files.pull", "files.cancel",
    "status.get",
  ]) {
    assert.ok(seen.has(cmd), `vector missing for command ${cmd}`);
  }
});

test("schema: sample responses and events validate", () => {
  const vectors = loadVector("typed-messages.json");
  const envelope = validator("envelope.schema.json");
  for (const res of vectors.responses) {
    assert.ok(envelope(res), `envelope rejects response: ${JSON.stringify(envelope.errors)}`);
  }
  const eventSchemas: Record<string, string> = {
    "notification.posted": "notifications.schema.json",
    "notification.removed": "notifications.schema.json",
    "sms.received": "messages.schema.json",
    "call.incoming": "calls.schema.json",
    "call.state": "calls.schema.json",
    "clipboard.changed": "clipboard.schema.json",
    "file.progress": "files.schema.json",
    "status.changed": "status.schema.json",
  };
  for (const evt of vectors.events) {
    assert.ok(envelope(evt), `envelope rejects event: ${JSON.stringify(envelope.errors)}`);
    const name = eventSchemas[evt.evt];
    assert.ok(name, `no schema mapping for event ${evt.evt}`);
    const channelSchema = validator(name);
    assert.ok(
      channelSchema(evt),
      `channel schema rejects ${evt.evt}: ${JSON.stringify(channelSchema.errors)}`,
    );
  }
});

test("schema: shared positive and negative cases behave as documented", () => {
  const cases = loadVector("schema-cases.json").cases;
  assert.ok(cases.length >= 25, `expected a broad case set, found ${cases.length}`);
  const valid = cases.filter((c: any) => c.valid);
  const invalid = cases.filter((c: any) => !c.valid);
  assert.ok(valid.length >= 5 && invalid.length >= 15, "both directions covered");
  for (const c of valid) {
    const v = validator(c.schema);
    assert.equal(
      v(c.instance),
      true,
      `case ${c.name} should be valid: ${JSON.stringify(v.errors)}`,
    );
  }
  for (const c of invalid) {
    const v = validator(c.schema);
    assert.equal(v(c.instance), false, `case ${c.name} should be invalid (${c.reason})`);
  }
});

test("schema: all schema files compile and are valid draft 2020-12", () => {
  assert.ok(schemaFiles.length >= 9, `expected all schemas on disk, found ${schemaFiles.length}`);
  for (const file of schemaFiles) {
    const schema = loadSchemaText(file);
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema", `${file} draft`);
    assert.ok(schema.$id.startsWith(SCHEMA_BASE), `${file} has a device-connect $id`);
  }
});
