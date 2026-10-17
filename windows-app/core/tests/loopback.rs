//! End-to-end tests: a real TCP socket, a real Noise handshake, the real record
//! layer, with a phone written directly against `dc-protocol`.
//!
//! The phone side here is deliberately *not* built out of `dc-client` helpers.
//! If both sides shared the session code these tests would only prove the code
//! agrees with itself; written against the shared codec instead, they check the
//! bytes that would cross a real network between this PC and a real phone.

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dc_client::pairing::{confirmation_code, PairingOffer};
use dc_client::session::{accept, Listener, SessionConfig, SessionError};
use dc_client::store::FileSecretStore;
use dc_client::trust::{FileTrustStore, TrustStore};
use dc_client::{ActiveSession, HostInfo, Identity};
use dc_protocol::error_codes::ErrorCode;
use dc_protocol::framing::{mtype, Channel, Frame};
use dc_protocol::records::{handshake_over_stream, Role, SecureTransport, WireStream};
use dc_protocol::schema::{
    DeviceInfo, ErrorBody, Request, Response, SessionHello, SessionHelloAck,
};
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

// ------------------------------------------------------------------ the phone --

/// The phone's half of the protocol, over a real socket.
struct Phone {
    wire: WireStream<TcpStream, TcpStream>,
    transport: SecureTransport,
    seq: u32,
    next_id: u32,
    /// The PC's static key, as the handshake revealed it. Kept so tests can
    /// check it against the PC's own view of its key.
    peer: [u8; 32],
}

impl Phone {
    /// Dial, run Noise XX as the initiator, and keep the stream.
    ///
    /// `nonce` is the QR nonce the camera would have read; manual mode passes
    /// `None`, which is the bare mode byte (protocol section 2.2).
    fn dial(addr: SocketAddr, nonce: Option<&[u8; 16]>, secret: [u8; 32]) -> Self {
        let stream = TcpStream::connect(addr).expect("the PC is listening");
        stream.set_nodelay(true).expect("nodelay");
        // A test that hangs is worse than one that fails, so every read here is
        // bounded. The timeout goes on the *reading* handle: on Windows a
        // `try_clone`d socket does not carry `SO_RCVTIMEO` with it, and the
        // handshake and the session both read through the clone.
        let reader = stream.try_clone().expect("clone");
        reader
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read timeout");

        let mut wire = WireStream::new(reader, stream);
        let transport = handshake_over_stream(
            &mut wire,
            Role::Initiator,
            &dc_protocol::noise::prologue(nonce),
            &secret,
            None,
            None,
        )
        .expect("handshake");
        let transport = SecureTransport::new(transport);

        let peer = transport
            .remote_static()
            .expect("the responder sends its static key in XX")
            .try_into()
            .expect("32 bytes");

        Self {
            wire,
            transport,
            seq: 0,
            next_id: 1,
            peer,
        }
    }

    fn device(&self) -> DeviceInfo {
        DeviceInfo {
            id: "0123456789abcdef".to_string(),
            name: "Pixel 8".to_string(),
            model: Some("Pixel 8".to_string()),
            os: "Android 16".to_string(),
        }
    }

    fn send_json<T: serde::Serialize>(&mut self, mtype_byte: u8, message: &T) {
        let payload = serde_json::to_vec(message).expect("serializes");
        let frame = Frame::json(Channel::Control.id(), mtype_byte, self.seq, payload);
        self.seq += 1;
        self.transport
            .send_frame(&mut self.wire, &frame)
            .expect("write");
        self.wire.flush().expect("flush");
    }

    /// The `hello` a real phone sends first.
    fn send_hello(&mut self) {
        self.send_json(mtype::REQUEST, &SessionHello::new(self.device(), vec![]));
    }

    /// Wait for the next thing the PC sends, or `None` when it hangs up.
    fn recv_json(&mut self) -> Option<Value> {
        let frame = match self.transport.read_frame(&mut self.wire) {
            Ok(frame) => frame,
            Err(_) => return None,
        };
        Some(serde_json::from_slice(&frame.payload).expect("json frame"))
    }

    /// The next value the PC sends, or panic: used where the PC must answer.
    fn expect_json(&mut self) -> Value {
        self.recv_json().expect("the PC sent something")
    }

    /// The `hello_ack`.
    fn read_ack(&mut self) -> SessionHelloAck {
        serde_json::from_value(self.expect_json()).expect("hello_ack")
    }

    /// Wait for the next request the PC makes, or `None` when it hangs up.
    fn recv_request(&mut self) -> Option<Request> {
        loop {
            let value = self.recv_json()?;
            if value.get("cmd").is_some() {
                return Some(Request {
                    id: value["id"].as_u64().expect("id") as u32,
                    cmd: value["cmd"].as_str().expect("cmd").to_string(),
                    args: value.get("args").cloned().unwrap_or(Value::Null),
                });
            }
            // Anything that is not a request (a heartbeat, an event) is not what
            // this helper returns.
        }
    }

    fn respond(&mut self, response: &Response) {
        self.send_json(mtype::RESPONSE, response);
    }

    fn send_request(&mut self, cmd: &str, args: Value) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.send_json(mtype::REQUEST, &json!({"id": id, "cmd": cmd, "args": args}));
        id
    }
}

/// How this phone answers the commands the tests use.
fn phone_answer(request: &Request) -> Response {
    match request.cmd.as_str() {
        "status.get" => Response::ok(request.id, json!({"battery": 73, "charging": false})),
        "clipboard.get" => Response::err(
            request.id,
            ErrorBody::new(ErrorCode::CapabilityDisabled, "clipboard is off"),
        ),
        "security.unpair" => Response::ok(request.id, json!({})),
        other => Response::err(
            request.id,
            ErrorBody::new(ErrorCode::Unsupported, format!("no {other}")),
        ),
    }
}

/// Answer every request until the PC closes the link. Returns what was asked.
fn serve_until_closed(phone: &mut Phone, answer: impl Fn(&Request) -> Response) -> Vec<String> {
    let mut seen = Vec::new();
    while let Some(request) = phone.recv_request() {
        seen.push(request.cmd.clone());
        let response = answer(&request);
        phone.respond(&response);
    }
    seen
}

// ----------------------------------------------------------------- the PC side --

struct Harness {
    listener: Listener,
    identity: Identity,
    trust: Arc<dyn TrustStore>,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

impl Harness {
    fn new() -> Self {
        let key_dir = tempfile::tempdir().expect("temp dir");
        let trust_dir = tempfile::tempdir().expect("temp dir");
        let identity =
            Identity::load_or_create(&FileSecretStore::new(key_dir.path())).expect("identity");
        let trust: Arc<dyn TrustStore> =
            Arc::new(FileTrustStore::new(trust_dir.path().join("trusted.json")));
        Self {
            listener: Listener::bind(0).expect("bind"),
            identity,
            trust,
            _dirs: (key_dir, trust_dir),
        }
    }

    fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.listener.port().expect("port")))
    }

    fn config(&self, offer: &PairingOffer) -> SessionConfig {
        SessionConfig::new(self.identity.clone(), host(), Arc::clone(&self.trust)).with_offer(offer)
    }

    /// Accept the connection, run the handshake and the hello exchange, and
    /// confirm the pairing, as the app does once the user agrees.
    fn pair_and_confirm(&self, offer: &PairingOffer) -> ActiveSession {
        let stream = self.listener.accept().expect("the phone connected");
        accept(stream, self.config(offer))
            .expect("handshake and hello")
            .confirm()
            .expect("confirm")
    }

    /// A window whose `port` is the port actually bound.
    fn offer(&self) -> PairingOffer {
        PairingOffer::manual(
            self.listener.port().expect("port"),
            Some("127.0.0.1".into()),
            None,
        )
    }
}

/// What the app layer claims about this PC.
///
/// Deliberately not a real OS version: the core must pass through the string it
/// is given, because only the shell can ask Windows for one, and the assertion
/// below checks exactly that.
fn host() -> HostInfo {
    HostInfo {
        name: "Desk PC".to_string(),
        model: None,
        os: "Test OS 1.2".to_string(),
    }
}

/// A phone's long-term secret, from the operating system's random source.
fn phone_secret() -> [u8; 32] {
    *Identity::generate().secret()
}

/// The public half of a secret, derived here with `x25519-dalek` directly.
///
/// Doing it without `dc-client` is the point: when a test asserts that the PC's
/// `peer_key` equals this value, the two numbers came from two different paths
/// through the same curve.
fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// Run a phone on its own thread, so both ends of the socket are exercised.
fn spawn_phone<R: Send + 'static>(
    addr: SocketAddr,
    nonce: Option<[u8; 16]>,
    secret: [u8; 32],
    body: impl FnOnce(&mut Phone) -> R + Send + 'static,
) -> JoinHandle<R> {
    thread::spawn(move || {
        let mut phone = Phone::dial(addr, nonce.as_ref(), secret);
        body(&mut phone)
    })
}

// ---------------------------------------------------------------------- tests --

#[test]
fn a_new_phone_must_be_confirmed_and_the_code_comes_from_both_keys() {
    let pc = Harness::new();
    let secret = phone_secret();
    let phone_key = public_of(&secret);

    let offer = PairingOffer::qr(
        pc.listener.port().unwrap(),
        Some("127.0.0.1".into()),
        Some("Desk PC".into()),
    );
    // The nonce the camera would read out of the QR.
    let nonce = dc_protocol::qr::QrPayload::decode(&offer.qr_text().unwrap())
        .expect("decode")
        .nonce_bytes()
        .expect("nonce");

    let phone = spawn_phone(pc.addr(), Some(nonce), secret, |phone| {
        phone.send_hello();
        let ack = phone.read_ack();
        // Hold the line; nothing else is asked of this phone.
        let _ = phone.recv_request();
        (ack, phone.peer)
    });

    let stream = pc.listener.accept().expect("connected");
    let pending = accept(stream, pc.config(&offer)).expect("handshake and hello");

    // The handshake proved which key is on the other end, and the PC derived the
    // code from that key plus its own: the two screens show the same digits.
    assert_eq!(pending.info().peer_key, phone_key);
    assert_eq!(
        pending.info().code,
        confirmation_code(&pc.identity.public(), &phone_key)
    );
    assert_eq!(pending.info().code.len(), 6);
    assert!(!pending.already_paired());
    assert_eq!(pending.info().peer_name, "Pixel 8");
    assert_eq!(pending.info().peer_model.as_deref(), Some("Pixel 8"));
    assert_eq!(pending.info().peer_os, "Android 16");
    assert_eq!(pending.info().peer_id.len(), 16);
    assert!(pending.info().peer_caps.is_empty());
    assert!(pc.trust.peers().unwrap().is_empty(), "nothing pinned yet");

    pending.reject();

    let (ack, peer_as_the_phone_saw_it) = phone.join().expect("phone thread");
    assert!(!ack.paired, "a first connection is not paired");
    assert!(ack.caps.is_empty());
    assert_eq!(ack.device.name, "Desk PC");
    assert_eq!(ack.device.os, "Test OS 1.2");
    assert_eq!(ack.device.id, pc.identity.id());

    // The phone's view of the PC's key came out of the Noise handshake, and it
    // is the same key this PC derives for itself with `x25519-dalek`.
    assert_eq!(peer_as_the_phone_saw_it, pc.identity.public());
}

#[test]
fn a_disabled_capability_is_an_answer_and_the_session_keeps_working() {
    let pc = Harness::new();
    let offer = pc.offer();
    let secret = phone_secret();

    let phone = spawn_phone(pc.addr(), None, secret, |phone| {
        phone.send_hello();
        let _ = phone.read_ack();
        serve_until_closed(phone, phone_answer)
    });

    let mut session = pc.pair_and_confirm(&offer);

    let status = session.request("status.get", json!({})).expect("an answer");
    assert!(status.ok);
    assert_eq!(status.result.expect("result")["battery"], 73);

    // A capability the phone has switched off comes back as a refusal with its
    // own code - not as a hang, and not as an empty success.
    let refused = session
        .request("clipboard.get", json!({}))
        .expect("an answer");
    assert!(!refused.ok);
    let error = refused.error.expect("error body");
    assert_eq!(error.code, ErrorCode::CapabilityDisabled);
    assert_eq!(error.message, "clipboard is off");

    assert!(session.request("status.get", json!({})).is_ok());

    session.close();
    assert_eq!(
        phone.join().expect("phone thread"),
        vec!["status.get", "clipboard.get", "status.get"]
    );
}

#[test]
fn the_pinned_key_is_remembered_and_the_phone_reconnects_without_asking_again() {
    let pc = Harness::new();
    let offer = pc.offer();
    let secret = phone_secret();

    let first = spawn_phone(pc.addr(), None, secret, |phone| {
        phone.send_hello();
        let ack = phone.read_ack();
        let _ = phone.recv_request();
        ack
    });
    pc.pair_and_confirm(&offer).close();
    assert!(!first.join().unwrap().paired);

    let peers = pc.trust.peers().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].key_bytes().unwrap(), public_of(&secret));
    assert_eq!(peers[0].name, "Pixel 8");
    let paired_at = peers[0].paired_at;
    assert!(paired_at > 0);

    // Second connection, same phone: the key is already the one the user
    // confirmed, so no code comparison is needed.
    let phone = spawn_phone(pc.addr(), None, secret, |phone| {
        phone.send_hello();
        let ack = phone.read_ack();
        let _ = phone.recv_request();
        ack
    });

    let stream = pc.listener.accept().unwrap();
    let pending = accept(stream, pc.config(&offer)).expect("accepted");
    assert!(pending.already_paired());
    pending.confirm().expect("confirm").close();
    assert!(
        phone.join().unwrap().paired,
        "a pinned phone is told it is paired"
    );

    // Reconnecting must not rewrite when the user confirmed.
    assert_eq!(pc.trust.peers().unwrap()[0].paired_at, paired_at);
}

#[test]
fn an_unconfirmed_phone_leaves_nothing_behind() {
    let pc = Harness::new();
    let offer = pc.offer();

    let phone = spawn_phone(pc.addr(), None, phone_secret(), |phone| {
        phone.send_hello();
        let _ = phone.read_ack();
        // The PC hangs up without confirming.
        phone.recv_request().is_none()
    });

    let stream = pc.listener.accept().unwrap();
    let pending = accept(stream, pc.config(&offer)).expect("accepted");
    assert!(!pending.already_paired());
    pending.reject();

    assert!(pc.trust.peers().unwrap().is_empty());
    assert!(phone.join().unwrap(), "the phone saw the connection close");
}

#[test]
fn a_missing_reply_ends_the_session_instead_of_hanging_forever() {
    let pc = Harness::new();
    let offer = pc.offer();

    let phone = spawn_phone(pc.addr(), None, phone_secret(), |phone| {
        phone.send_hello();
        let _ = phone.read_ack();
        // Take the request and answer nothing at all.
        let request = phone.recv_request().expect("one request");
        thread::sleep(Duration::from_millis(600));
        request.cmd
    });

    let config = pc
        .config(&offer)
        .with_reply_timeout(Duration::from_millis(150));
    let stream = pc.listener.accept().unwrap();
    let mut session = accept(stream, config)
        .expect("handshake")
        .confirm()
        .expect("confirm");

    match session.request("status.get", json!({})) {
        Err(SessionError::Timeout(_)) => {}
        other => panic!("expected a timeout, got {other:?}"),
    }

    assert_eq!(phone.join().unwrap(), "status.get");
}

#[test]
fn a_phone_speaking_another_version_is_told_why_and_dropped() {
    let pc = Harness::new();
    let offer = pc.offer();

    let phone = spawn_phone(pc.addr(), None, phone_secret(), |phone| {
        // Claim a version this build does not speak.
        phone.send_json(
            mtype::REQUEST,
            &SessionHello {
                pv: 2,
                t: "hello".to_string(),
                device: phone.device(),
                caps: vec![],
            },
        );
        phone.expect_json()
    });

    let stream = pc.listener.accept().unwrap();
    match accept(stream, pc.config(&offer)) {
        Err(SessionError::ProtocolMismatch { peer, ours }) => {
            assert_eq!(peer, 2);
            assert_eq!(ours, 1);
        }
        Err(other) => panic!("expected a version refusal, got {other}"),
        Ok(_) => panic!("expected a version refusal, but the session was accepted"),
    }

    let refusal = phone.join().unwrap();
    assert_eq!(refusal["code"], "UNSUPPORTED");
    assert!(refusal["message"].as_str().unwrap().contains("version 1"));
    assert!(pc.trust.peers().unwrap().is_empty());
}

#[test]
fn unpairing_from_the_pc_deletes_the_key_on_both_sides() {
    let pc = Harness::new();
    let offer = pc.offer();

    let phone = spawn_phone(pc.addr(), None, phone_secret(), |phone| {
        phone.send_hello();
        let _ = phone.read_ack();
        let request = phone.recv_request().expect("the unpair request");
        assert_eq!(request.cmd, "security.unpair");
        phone.respond(&Response::ok(request.id, json!({})));
        assert!(phone.recv_request().is_none(), "the PC closed the link");
        request.cmd
    });

    let session = pc.pair_and_confirm(&offer);
    assert_eq!(pc.trust.peers().unwrap().len(), 1);

    session.unpair().expect("unpair");
    assert!(pc.trust.peers().unwrap().is_empty());
    assert_eq!(phone.join().unwrap(), "security.unpair");
}

#[test]
fn unpairing_from_the_phone_is_acted_on_before_it_is_answered() {
    let pc = Harness::new();
    let offer = pc.offer();

    let phone = spawn_phone(pc.addr(), None, phone_secret(), |phone| {
        phone.send_hello();
        let _ = phone.read_ack();

        // The PC asks something. Instead of answering, the phone revokes.
        let _ = phone.recv_request().expect("a request");
        let sent_id = phone.send_request("security.unpair", json!({}));
        let reply = phone.expect_json();
        (sent_id, reply)
    });

    let mut session = pc.pair_and_confirm(&offer);
    match session.request("status.get", json!({})) {
        Err(SessionError::Unpaired) => {}
        other => panic!("expected the pairing to end, got {other:?}"),
    }
    session.close();

    let (sent_id, reply) = phone.join().unwrap();
    assert_eq!(sent_id, 1);
    assert_eq!(reply["ok"], true, "the phone's own request is answered");
    assert_eq!(reply["id"], 1);
    assert!(pc.trust.peers().unwrap().is_empty(), "the key is deleted");
}

#[test]
fn an_unknown_command_from_the_phone_is_refused_without_ending_the_session() {
    let pc = Harness::new();
    let offer = pc.offer();

    let phone = spawn_phone(pc.addr(), None, phone_secret(), |phone| {
        phone.send_hello();
        let _ = phone.read_ack();

        let request = phone.recv_request().expect("a request");
        phone.send_request("not.a.command", json!({}));

        // The refusal comes back first ...
        let refusal = phone.expect_json();
        // ... and then the answer the PC is waiting for.
        phone.respond(&Response::ok(request.id, json!({"battery": 73})));
        (refusal, request.cmd)
    });

    let mut session = pc.pair_and_confirm(&offer);
    let answer = session.request("status.get", json!({})).expect("an answer");
    assert!(answer.ok);
    assert_eq!(answer.result.unwrap()["battery"], 73);
    assert!(session.take_deferred().is_empty());

    // The refusal is a response to the phone's own request, so it carries an id
    // and an `ok: false` envelope rather than a bare error body.
    let (refusal, cmd) = phone.join().unwrap();
    assert_eq!(cmd, "status.get");
    assert_eq!(refusal["ok"], false);
    assert_eq!(refusal["id"], 1);
    assert_eq!(refusal["error"]["code"], "UNSUPPORTED");
    assert!(refusal["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not.a.command"));
}
