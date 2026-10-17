//! Runs every golden vector from protocol/test-vectors against this
//! implementation. The Kotlin and TypeScript suites run the same files.

use dc_protocol::confirm::confirmation_code;
use dc_protocol::framing::{Frame, FrameDecoder, FrameError};
use dc_protocol::noise::{handshake_in_memory, NoiseTransport};
use dc_protocol::qr::{QrError, QrPayload};
use dc_protocol::records::{self, DecodeResult};
use dc_protocol::schema::*;
use dc_protocol::ErrorCode;
use serde_json::Value;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest.join("../test-vectors");
    candidate
        .canonicalize()
        .expect("protocol/test-vectors exists")
}

fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in vector")
}

fn unhex32(v: &Value, key: &str) -> [u8; 32] {
    let bytes = unhex(v[key].as_str().unwrap());
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn frames_valid() {
    let vectors = load("frames.json");
    for v in vectors["valid"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let bytes = unhex(v["hex"].as_str().unwrap());
        let frame = Frame::decode(&bytes)
            .unwrap_or_else(|e| panic!("{name}: decode failed: {e}"))
            .unwrap_or_else(|| panic!("{name}: incomplete frame"));
        assert_eq!(
            frame.channel,
            v["expect"]["channel"].as_u64().unwrap() as u8,
            "{name} channel"
        );
        assert_eq!(
            frame.mtype,
            v["expect"]["mtype"].as_u64().unwrap() as u8,
            "{name} mtype"
        );
        assert_eq!(
            frame.flags,
            v["expect"]["flags"].as_u64().unwrap() as u16,
            "{name} flags"
        );
        assert_eq!(
            frame.seq,
            v["expect"]["seq"].as_u64().unwrap() as u32,
            "{name} seq"
        );
        if let Some(payload_hex) = v["expect"].get("payloadHex").and_then(|x| x.as_str()) {
            assert_eq!(frame.payload, unhex(payload_hex), "{name} payload bytes");
        }
        if let Some(payload_json) = v["expect"].get("payloadJson") {
            let parsed: Value = serde_json::from_slice(&frame.payload).expect("payload is JSON");
            assert_eq!(&parsed, payload_json, "{name} payload JSON");
        }
        // Re-encoding must be byte-identical.
        assert_eq!(frame.encode(), bytes, "{name} re-encode");
    }
}

#[test]
fn frames_invalid() {
    let vectors = load("frames.json");
    for v in vectors["invalid"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let bytes = unhex(v["hex"].as_str().unwrap());
        let err = Frame::decode(&bytes).expect_err(&format!("{name} must be rejected"));
        let expect = v["error"].as_str().unwrap();
        let got = match err {
            FrameError::BodyTooSmall { .. } => "BodyTooSmall",
            FrameError::BodyTooLarge { .. } => "BodyTooLarge",
            _ => "other",
        };
        assert_eq!(got, expect, "{name} error kind");
    }
}

#[test]
fn qr_vectors() {
    let vectors = load("qr.json");
    for v in vectors["valid"].as_array().unwrap() {
        let payload = QrPayload::decode(v["encoded"].as_str().unwrap()).expect("valid QR decodes");
        let reencoded = serde_json::to_value(&payload).unwrap();
        assert_eq!(&reencoded, &v["json"], "QR json roundtrip");
        assert_eq!(
            payload.encode(),
            v["encoded"].as_str().unwrap(),
            "QR encode stability"
        );
        assert_eq!(
            hex::encode(payload.nonce_bytes().expect("nonce decodes")),
            v["nonceHex"].as_str().unwrap(),
            "QR nonce"
        );
        assert!(
            payload.is_expired(v["expiredAt"].as_u64().unwrap()),
            "QR expiry"
        );
    }
    for v in vectors["invalid"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let text = v["text"].as_str().unwrap();
        let expect = v["error"].as_str().unwrap();
        if expect == "Expired" {
            let p = QrPayload::decode(text).expect("structurally valid");
            assert!(p.is_expired(1_700_000_500), "{name}");
            continue;
        }
        let err = QrPayload::decode(text).expect_err(&format!("{name} must be rejected"));
        let got = match err {
            QrError::BadPrefix => "BadPrefix",
            QrError::BadBase64 => "BadBase64",
            QrError::BadJson => "BadJson",
            QrError::BadField(_) => "BadField",
        };
        assert_eq!(got, expect, "{name} error kind");
    }
}

#[test]
fn confirmation_codes() {
    let vectors = load("confirm-code.json");
    for p in vectors["pairs"].as_array().unwrap() {
        let a = unhex(p["pkA"].as_str().unwrap());
        let b = unhex(p["pkB"].as_str().unwrap());
        assert_eq!(confirmation_code(&a, &b), p["code"].as_str().unwrap());
        assert_eq!(
            confirmation_code(&b, &a),
            p["code"].as_str().unwrap(),
            "order independence"
        );
    }
}

#[test]
fn noise_known_answer() {
    let kat = load("noise-kat.json");
    let arr = |k: &str| -> [u8; 32] {
        let v = unhex(kat[k].as_str().unwrap());
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    };
    let (m1, m2, m3, it, rt) = handshake_in_memory(
        &arr("initiatorStaticPrivHex"),
        &arr("responderStaticPrivHex"),
        &arr("initiatorEphPrivHex"),
        &arr("responderEphPrivHex"),
        &unhex(kat["prologueHex"].as_str().unwrap()),
    )
    .expect("handshake succeeds");
    assert_eq!(hex::encode(&m1), kat["msg1Hex"], "msg1");
    assert_eq!(hex::encode(&m2), kat["msg2Hex"], "msg2");
    assert_eq!(hex::encode(&m3), kat["msg3Hex"], "msg3");

    let mut it = NoiseTransport::from_state(it);
    let mut rt = NoiseTransport::from_state(rt);

    let t0 = &kat["transports"][0];
    let cipher = it
        .encrypt(t0["plain"].as_str().unwrap().as_bytes())
        .unwrap();
    assert_eq!(
        hex::encode(&cipher),
        t0["cipherHex"],
        "initiator transport encryption"
    );

    // Cross-decrypt both directions.
    for entry in kat["transports"].as_array().unwrap() {
        let cipher = unhex(entry["cipherHex"].as_str().unwrap());
        let (decryptor, plain) = if entry["from"] == "initiator" {
            (&mut rt, entry["plain"].as_str().unwrap())
        } else {
            (&mut it, entry["plain"].as_str().unwrap())
        };
        assert_eq!(decryptor.decrypt(&cipher).unwrap(), plain.as_bytes());
    }

    // A fresh transport wrapper still enforces nonce ordering.
    let mut wrap = NoiseTransport::from_state(
        handshake_in_memory(
            &arr("initiatorStaticPrivHex"),
            &arr("responderStaticPrivHex"),
            &arr("initiatorEphPrivHex"),
            &arr("responderEphPrivHex"),
            &unhex(kat["prologueHex"].as_str().unwrap()),
        )
        .unwrap()
        .3,
    );
    let c1 = wrap.encrypt(b"a").unwrap();
    assert_ne!(c1, wrap.encrypt(b"a").unwrap());
}

#[test]
fn record_layer_carries_the_golden_transports() {
    let kat = load("noise-kat.json");

    // The record the initiator writes for the golden plaintext is the golden
    // cipher, prefixed with its u32be length. That prefix is what the JVM and
    // Rust implementations must agree on byte for byte; the Kotlin suite
    // asserts the mirror image of this test.
    let golden_cipher = unhex(kat["transports"][0]["cipherHex"].as_str().unwrap());
    let record =
        records::encode(&golden_cipher, records::MAX_TRANSPORT_RECORD).expect("encode record");

    let mut manual = (golden_cipher.len() as u32).to_be_bytes().to_vec();
    manual.extend_from_slice(&golden_cipher);
    assert_eq!(record, manual, "record is a u32be length plus the cipher");

    // Reading it back yields the same bytes ...
    let mut cursor = std::io::Cursor::new(record);
    let read_back =
        records::read_record(&mut cursor, records::MAX_TRANSPORT_RECORD).expect("read record");
    assert_eq!(read_back, golden_cipher);

    // ... and they still decrypt with the golden handshake's transport.
    let (_m1, _m2, _m3, _it, rt) = handshake_in_memory(
        &unhex32(&kat, "initiatorStaticPrivHex"),
        &unhex32(&kat, "responderStaticPrivHex"),
        &unhex32(&kat, "initiatorEphPrivHex"),
        &unhex32(&kat, "responderEphPrivHex"),
        &unhex(kat["prologueHex"].as_str().unwrap()),
    )
    .expect("handshake succeeds");
    let mut responder = NoiseTransport::from_state(rt);
    assert_eq!(
        responder.decrypt(&read_back).unwrap(),
        kat["transports"][0]["plain"].as_str().unwrap().as_bytes()
    );

    // The handshake messages travel through the same layer.
    let m1 = unhex(kat["msg1Hex"].as_str().unwrap());
    let framed =
        records::encode(&m1, records::MAX_HANDSHAKE_RECORD).expect("encode handshake record");
    match records::decode(&framed, records::MAX_HANDSHAKE_RECORD).expect("decode handshake record")
    {
        DecodeResult::Decoded {
            payload,
            bytes_consumed,
        } => {
            assert_eq!(payload, m1);
            assert_eq!(bytes_consumed, 4 + m1.len());
        }
        DecodeResult::NeedMore => panic!("a complete record must not ask for more"),
    }
}

#[test]
fn typed_messages() {
    let vectors = load("typed-messages.json");
    for v in vectors["requests"].as_array().unwrap() {
        let req: Request = serde_json::from_value(v.clone()).expect("request parses");
        // Roundtrip through the typed control commands where applicable.
        if req.cmd.starts_with("input.")
            || req.cmd.starts_with("screen.")
            || req.cmd.starts_with("app.")
            || req.cmd.starts_with("security.")
            || req.cmd == "screentext.get"
            || req.cmd == "wait.screen"
            || req.cmd == "caps.set"
        {
            let typed =
                ControlCmd::from_request(&req).unwrap_or_else(|e| panic!("{}: {e}", req.cmd));
            assert_eq!(
                &serde_json::to_value(typed.to_request(req.id)).unwrap(),
                v,
                "{}",
                req.cmd
            );
        }
    }
    for v in vectors["responses"].as_array().unwrap() {
        let res: Response = serde_json::from_value(v.clone()).expect("response parses");
        assert_eq!(&serde_json::to_value(&res).unwrap(), v);
    }
    for v in vectors["events"].as_array().unwrap() {
        let evt: Event = serde_json::from_value(v.clone()).expect("event parses");
        assert_eq!(&serde_json::to_value(&evt).unwrap(), v);
    }
}

#[test]
fn unknown_error_code_is_internal() {
    // Forward compatibility: unknown codes deserialize as INTERNAL.
    let parsed: Response = serde_json::from_str(
        r#"{"id":1,"ok":false,"error":{"code":"SOMETHING_NEW","message":"x"}}"#,
    )
    .unwrap();
    assert_eq!(parsed.error.unwrap().code, ErrorCode::Internal);
}

#[test]
fn stream_reassembly() {
    // Split a valid vector across arbitrary chunk boundaries.
    let vectors = load("frames.json");
    let v = &vectors["valid"][2]; // control_input_tap
    let bytes = unhex(v["hex"].as_str().unwrap());
    for split in [1usize, 3, 11, bytes.len() - 1] {
        let mut dec = FrameDecoder::new();
        dec.feed(&bytes[..split]);
        let a = dec.next_frame().unwrap();
        dec.feed(&bytes[split..]);
        let b = dec.next_frame().unwrap();
        let frame = a.or(b).expect("frame complete after both chunks");
        assert_eq!(frame.seq, 42);
    }
}
