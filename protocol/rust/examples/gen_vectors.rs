//! Golden vector generator: writes protocol/test-vectors/*.json from the
//! reference implementation. Run: cargo run --example gen_vectors
//!
//! The generated files are committed and consumed by the Rust, Kotlin and
//! TypeScript conformance tests. Regenerate only when adding new vectors;
//! existing vectors are append-only (protocol/README.md).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use dc_protocol::confirm::confirmation_code;
use dc_protocol::framing::{mtype, FileData, Frame, FrameError, VideoAu, FLAG_JSON};
use dc_protocol::noise::{handshake_in_memory, prologue, NoiseTransport};
use dc_protocol::qr::{QrPayload, NONCE_LEN};
use dc_protocol::schema::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-vectors")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_json(path: PathBuf, value: &serde_json::Value) {
    let text = serde_json::to_string_pretty(value).unwrap();
    std::fs::write(&path, format!("{text}\n")).expect("write vector file");
    eprintln!("wrote {}", path.display());
}

fn main() {
    let dir = vectors_dir();
    std::fs::create_dir_all(&dir).unwrap();

    // ---- framing ----
    let mut frames_valid = Vec::new();
    let mut push = |name: &str, frame: &Frame, expect: serde_json::Value| {
        frames_valid.push(serde_json::json!({
            "name": name,
            "hex": hex(&frame.encode()),
            "expect": expect
        }));
    };

    let ping = Frame::json(
        0x09,
        mtype::REQUEST,
        0,
        br#"{"t":"ping","ts":1700000000123}"#.to_vec(),
    );
    push(
        "heartbeat_ping",
        &ping,
        serde_json::json!({
            "channel": 9, "mtype": 1, "flags": FLAG_JSON, "seq": 0,
            "payloadJson": {"t":"ping","ts":1700000000123u64}
        }),
    );

    let pong = Frame::json(
        0x09,
        mtype::RESPONSE,
        1,
        br#"{"t":"pong","ts":1700000000123}"#.to_vec(),
    );
    push(
        "heartbeat_pong",
        &pong,
        serde_json::json!({
            "channel": 9, "mtype": 2, "flags": FLAG_JSON, "seq": 1,
            "payloadJson": {"t":"pong","ts":1700000000123u64}
        }),
    );

    let tap = Frame::json(
        0x01,
        mtype::REQUEST,
        42,
        br#"{"id":42,"cmd":"input.tap","args":{"x":100,"y":200}}"#.to_vec(),
    );
    push(
        "control_input_tap",
        &tap,
        serde_json::json!({
            "channel": 1, "mtype": 1, "flags": FLAG_JSON, "seq": 42,
            "payloadJson": {"id":42,"cmd":"input.tap","args":{"x":100,"y":200}}
        }),
    );

    let hello = Frame::json(
        0x01,
        mtype::REQUEST,
        0,
        serde_json::to_vec(&SessionHello::new(
            DeviceInfo {
                id: "0011223344556677".into(),
                name: "Pixel 8".into(),
                model: Some("Pixel 8".into()),
                os: "Android 16".into(),
            },
            vec!["screen_view".into(), "input_control".into()],
        ))
        .unwrap(),
    );
    push(
        "session_hello",
        &hello,
        serde_json::json!({
            "channel": 1, "mtype": 1, "flags": FLAG_JSON, "seq": 0,
            "payloadJson": serde_json::from_str::<serde_json::Value>(
                std::str::from_utf8(&hello.payload).unwrap()).unwrap()
        }),
    );

    let au_payload = VideoAu {
        timestamp_ms: 1700000000999,
        data: vec![0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00],
    }
    .encode();
    let au = Frame::new(0x02, mtype::VIDEO_AU, 7, au_payload.clone());
    push(
        "video_access_unit",
        &au,
        serde_json::json!({
            "channel": 2, "mtype": 2, "flags": 0, "seq": 7,
            "payloadHex": hex(&au_payload)
        }),
    );

    let fd_payload = FileData {
        transfer_id: 9,
        offset: 18446744073709551,
        chunk: b"DATA_CHUNK".to_vec(),
    }
    .encode();
    let fd = Frame::new(0x07, mtype::FILE_DATA, 3, fd_payload.clone());
    push(
        "file_data_chunk",
        &fd,
        serde_json::json!({
            "channel": 7, "mtype": 16, "flags": 0, "seq": 3,
            "payloadHex": hex(&fd_payload)
        }),
    );

    let empty = Frame::new(0x08, mtype::EVENT, 0, vec![]);
    push(
        "empty_payload",
        &empty,
        serde_json::json!({
            "channel": 8, "mtype": 3, "flags": 0, "seq": 0, "payloadHex": ""
        }),
    );

    let frames_invalid = serde_json::json!([
        { "name": "zero_length", "hex": "000000000101000000000000", "error": "BodyTooSmall" },
        { "name": "seven_bytes", "hex": "00000007010100000000000000", "error": "BodyTooSmall" },
        { "name": "too_large", "hex": "ffffffff0101000000000000", "error": "BodyTooLarge" }
    ]);
    let _ = FrameError::Incomplete; // referenced for docs
    write_json(
        dir.join("frames.json"),
        &serde_json::json!({
            "valid": frames_valid,
            "invalid": frames_invalid
        }),
    );

    // ---- QR ----
    let nonce = [0x24u8; NONCE_LEN];
    let payload = QrPayload::new(
        &nonce,
        47321,
        Some("desk-pc.local".into()),
        Some("Desk PC".into()),
        1_700_000_000,
    );
    let encoded = payload.encode();
    let expired = QrPayload {
        exp: 1_600_000_000,
        ..payload.clone()
    };
    write_json(
        dir.join("qr.json"),
        &serde_json::json!({
            "valid": [{
                "json": serde_json::to_value(&payload).unwrap(),
                "encoded": encoded,
                "nonceHex": hex(&nonce),
                "expiredAt": 1_700_000_121
            }],
            "invalid": [
                { "name": "wrong_prefix", "text": "https://example.com", "error": "BadPrefix" },
                { "name": "bad_base64", "text": "dc1:!!!not-base64!!!", "error": "BadBase64" },
                { "name": "bad_json", "text": format!("dc1:{}", URL_SAFE_NO_PAD.encode(br#"{"v":2,"n":"AAAAAAAAAAAAAAAAAAAAAA","p":1,"exp":9}"#)), "error": "BadField" },
                { "name": "expired", "text": expired.encode(), "error": "Expired" }
            ]
        }),
    );

    // ---- confirmation code ----
    let pk_a = [0xA1u8; 32];
    let pk_b = [0xB2u8; 32];
    let pk_c = [0x5Au8; 32];
    write_json(
        dir.join("confirm-code.json"),
        &serde_json::json!({
            "pairs": [
                { "pkA": hex(&pk_a), "pkB": hex(&pk_b), "code": confirmation_code(&pk_a, &pk_b) },
                { "pkA": hex(&pk_c), "pkB": hex(&pk_a), "code": confirmation_code(&pk_c, &pk_a) },
                { "pkA": hex(&[0x00u8; 32]), "pkB": hex(&[0xFFu8; 32]), "code": confirmation_code(&[0x00u8; 32], &[0xFFu8; 32]) }
            ]
        }),
    );

    // ---- Noise known-answer test ----
    let i_static = [0x11u8; 32];
    let r_static = [0x22u8; 32];
    let i_eph = [0x33u8; 32];
    let r_eph = [0x44u8; 32];
    let pro = prologue(Some(&nonce));
    let (m1, m2, m3, it, rt) =
        handshake_in_memory(&i_static, &r_static, &i_eph, &r_eph, &pro).unwrap();
    // The initiator learns the responder's static public key, and vice versa.
    let responder_pub = it
        .get_remote_static()
        .expect("initiator learns responder static")
        .to_vec();
    let initiator_pub = rt
        .get_remote_static()
        .expect("responder learns initiator static")
        .to_vec();
    let mut it = NoiseTransport::from_state(it);
    let mut rt = NoiseTransport::from_state(rt);
    let c1 = it.encrypt(b"ping-from-initiator").unwrap();
    let c2 = rt.encrypt(b"pong-from-responder").unwrap();
    write_json(
        dir.join("noise-kat.json"),
        &serde_json::json!({
            "params": dc_protocol::noise::PARAMS,
            "prologueHex": hex(&pro),
            "initiatorStaticPrivHex": hex(&i_static),
            "initiatorStaticPubHex": hex(&initiator_pub),
            "responderStaticPrivHex": hex(&r_static),
            "responderStaticPubHex": hex(&responder_pub),
            "initiatorEphPrivHex": hex(&i_eph),
            "responderEphPrivHex": hex(&r_eph),
            "msg1Hex": hex(&m1),
            "msg2Hex": hex(&m2),
            "msg3Hex": hex(&m3),
            "transports": [
                { "from": "initiator", "plain": "ping-from-initiator", "cipherHex": hex(&c1) },
                { "from": "responder", "plain": "pong-from-responder", "cipherHex": hex(&c2) }
            ]
        }),
    );

    // ---- typed message samples ----
    let mut caps = BTreeMap::new();
    caps.insert("screen_view".to_string(), true);
    caps.insert("clipboard".to_string(), false);
    let requests: Vec<Request> = vec![
        ControlCmd::ScreenStart {
            width: Some(720),
            height: Some(1280),
            fps: Some(30),
            bitrate: Some(4_000_000),
        }
        .to_request(1),
        ControlCmd::ScreenStop {}.to_request(2),
        ControlCmd::InputTap { x: 540, y: 1200 }.to_request(3),
        ControlCmd::InputLongPress { x: 100, y: 100 }.to_request(4),
        ControlCmd::InputSwipe {
            x1: 500,
            y1: 1500,
            x2: 500,
            y2: 300,
            dur_ms: Some(200),
        }
        .to_request(5),
        ControlCmd::InputScroll {
            x: 300,
            y: 900,
            dx: 0,
            dy: -200,
        }
        .to_request(6),
        ControlCmd::InputText {
            text: "Hello, phone!".into(),
        }
        .to_request(7),
        ControlCmd::InputKey { key: KeyCode::Home }.to_request(8),
        ControlCmd::AppOpen {
            package: "com.android.settings".into(),
        }
        .to_request(9),
        ControlCmd::AppList {}.to_request(10),
        ControlCmd::ScreenTextGet {}.to_request(11),
        ControlCmd::WaitScreen { timeout_ms: 10_000 }.to_request(12),
        ControlCmd::SecurityUnpair {}.to_request(13),
        ControlCmd::CapsSet { caps }.to_request(14),
        ControlCmd::ScreenConfigure {
            width: None,
            height: None,
            fps: Some(15),
            bitrate: Some(1_000_000),
        }
        .to_request(15),
        ControlCmd::SecurityRotate {}.to_request(16),
        // Remaining channels, as plain requests (typed client-side per channel).
        Request::new(17, "notifications.list", serde_json::json!({"limit": 50})),
        Request::new(
            18,
            "notifications.reply",
            serde_json::json!({"key": "0|com.example.chat|42|tag|10007", "actionId": "reply", "text": "On my way too"}),
        ),
        Request::new(
            19,
            "notifications.dismiss",
            serde_json::json!({"key": "0|com.example.chat|42|tag|10007"}),
        ),
        Request::new(
            20,
            "sms.list",
            serde_json::json!({"limit": 20, "beforeId": 91}),
        ),
        Request::new(
            21,
            "sms.thread",
            serde_json::json!({"address": "+15550100", "limit": 50}),
        ),
        Request::new(
            22,
            "sms.send",
            serde_json::json!({"to": "+15550100", "text": "Hello from the PC"}),
        ),
        Request::new(23, "calls.list", serde_json::json!({"limit": 20})),
        Request::new(24, "calls.answer", serde_json::json!({"id": "1"})),
        Request::new(25, "calls.reject", serde_json::json!({"id": "1"})),
        Request::new(26, "calls.dial", serde_json::json!({"number": "+15550123"})),
        Request::new(27, "clipboard.get", serde_json::json!({})),
        Request::new(
            28,
            "clipboard.set",
            serde_json::json!({"text": "copied from PC"}),
        ),
        Request::new(
            29,
            "files.push",
            serde_json::json!({"path": "Download/report.pdf", "size": 20480, "sha256": hex(&[0u8; 32])}),
        ),
        Request::new(
            30,
            "files.pull",
            serde_json::json!({"path": "DCIM/photo.jpg"}),
        ),
        Request::new(31, "files.cancel", serde_json::json!({"transferId": 1})),
        Request::new(32, "status.get", serde_json::json!({})),
    ];
    let responses = [
        Response::ok(
            1,
            serde_json::json!({"width":720,"height":1280,"fps":30,"bitrate":4000000}),
        ),
        Response::ok(2, serde_json::json!({})),
        Response::err(
            3,
            ErrorBody::new(
                dc_protocol::ErrorCode::CapabilityDisabled,
                "input_control is off on the phone",
            ),
        ),
        Response::err(
            4,
            ErrorBody::with_action(
                dc_protocol::ErrorCode::ConfirmRequired,
                "Confirm sending this SMS on the phone",
                "act-17",
            ),
        ),
    ];
    let events = [
        Event::new(
            "notification.posted",
            serde_json::to_value(NotificationItem {
                key: "0|com.example.chat|42|tag|10007".into(),
                app: "com.example.chat".into(),
                app_label: Some("Chat".into()),
                title: "Alex".into(),
                text: Some("On my way".into()),
                post_time: 1_700_000_000_000,
                actions: Some(vec![
                    NotificationAction {
                        id: "reply".into(),
                        title: "Reply".into(),
                        replyable: Some(true),
                    },
                    NotificationAction {
                        id: "dismiss".into(),
                        title: "Dismiss".into(),
                        replyable: None,
                    },
                ]),
            })
            .unwrap(),
        ),
        Event::new(
            "sms.received",
            serde_json::to_value(SmsMessage {
                id: 91,
                address: "+15550100".into(),
                name: Some("Test Contact".into()),
                body: "Sample SMS body".into(),
                sent: false,
                read: Some(false),
                time: 1_700_000_000_000,
            })
            .unwrap(),
        ),
        Event::new(
            "call.incoming",
            serde_json::to_value(CallRecord {
                id: "1".into(),
                number: "+15550123".into(),
                name: None,
                kind: CallType::Incoming,
                duration: None,
                time: 1_700_000_000_000,
            })
            .unwrap(),
        ),
        Event::new(
            "status.changed",
            serde_json::to_value(StatusInfo {
                battery: BatteryStatus {
                    pct: 80,
                    charging: true,
                },
                screen_on: true,
                transport: TransportKind::Wifi,
                uptime_ms: Some(3_600_000),
                network: Some(NetworkStatus {
                    kind: NetworkKind::Wifi,
                }),
                storage: Some(StorageStatus {
                    free_bytes: 12_000_000_000,
                }),
            })
            .unwrap(),
        ),
        Event::new(
            "file.progress",
            serde_json::to_value(FileProgress {
                transfer_id: 1,
                bytes: 65536,
                total: 1048576,
            })
            .unwrap(),
        ),
    ];
    write_json(
        dir.join("typed-messages.json"),
        &serde_json::json!({
            "requests": requests.iter().map(|r| serde_json::to_value(r).unwrap()).collect::<Vec<_>>(),
            "responses": responses.iter().map(|r| serde_json::to_value(r).unwrap()).collect::<Vec<_>>(),
            "events": events.iter().map(|e| serde_json::to_value(e).unwrap()).collect::<Vec<_>>()
        }),
    );

    eprintln!("all vectors generated");
}
