//! JSON envelope types and typed command definitions (docs/protocol.md 2.5, 5).
//!
//! The JSON Schemas in `protocol/schema/` are the contract; these Rust types
//! mirror them for the control plane used by the Windows app. Conformance
//! tests on all platforms validate sample payloads against the schemas and
//! against vectors generated from these types.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error_codes::ErrorCode;
use crate::framing::{mtype, Frame, FLAG_JSON};

// ---------- generic envelope ----------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub id: u32,
    pub cmd: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub args: Value,
}

impl Request {
    pub fn new(id: u32, cmd: &str, args: Value) -> Self {
        Self {
            id,
            cmd: cmd.to_string(),
            args,
        }
    }

    pub fn from_frame(frame: &Frame) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(&frame.payload)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    #[serde(rename = "actionId", default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
}

impl ErrorBody {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            action_id: None,
        }
    }

    pub fn with_action(
        code: ErrorCode,
        message: impl Into<String>,
        action_id: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            action_id: Some(action_id.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub id: u32,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    pub fn ok(id: u32, result: Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: u32, error: ErrorBody) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(error),
        }
    }

    pub fn from_frame(frame: &Frame) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(&frame.payload)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub evt: String,
    pub data: Value,
}

impl Event {
    pub fn new(evt: &str, data: Value) -> Self {
        Self {
            evt: evt.to_string(),
            data,
        }
    }

    pub fn from_frame(frame: &Frame) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(&frame.payload)
    }
}

/// Encode any serializable message as a JSON frame on `channel`.
pub fn json_frame<T: Serialize>(channel: u8, mtype_byte: u8, seq: u32, msg: &T) -> Frame {
    let payload = serde_json::to_vec(msg).expect("message serializes");
    Frame {
        channel,
        mtype: mtype_byte,
        flags: FLAG_JSON,
        seq,
        payload,
    }
}

pub fn request_frame(channel: u8, seq: u32, req: &Request) -> Frame {
    json_frame(channel, mtype::REQUEST, seq, req)
}

pub fn response_frame(channel: u8, seq: u32, res: &Response) -> Frame {
    json_frame(channel, mtype::RESPONSE, seq, res)
}

pub fn event_frame(channel: u8, seq: u32, evt: &Event) -> Frame {
    json_frame(channel, mtype::EVENT, seq, evt)
}

// ---------- session negotiation ----------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// 16 hex chars, first 8 bytes of SHA-256 of the static public key.
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub os: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionHello {
    pub pv: u32,
    pub t: String,
    pub device: DeviceInfo,
    pub caps: Vec<String>,
}

impl SessionHello {
    pub fn new(device: DeviceInfo, caps: Vec<String>) -> Self {
        Self {
            pv: crate::PROTOCOL_VERSION,
            t: "hello".into(),
            device,
            caps,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionHelloAck {
    pub pv: u32,
    pub t: String,
    pub device: DeviceInfo,
    pub caps: Vec<String>,
    pub paired: bool,
}

impl SessionHelloAck {
    pub fn new(device: DeviceInfo, caps: Vec<String>, paired: bool) -> Self {
        Self {
            pv: crate::PROTOCOL_VERSION,
            t: "hello_ack".into(),
            device,
            caps,
            paired,
        }
    }
}

// ---------- typed control commands ----------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "args")]
pub enum ControlCmd {
    #[serde(rename = "screen.start")]
    ScreenStart {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        width: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        height: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fps: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bitrate: Option<u64>,
    },
    #[serde(rename = "screen.stop")]
    ScreenStop {},
    #[serde(rename = "screen.configure")]
    ScreenConfigure {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        width: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        height: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fps: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bitrate: Option<u64>,
    },
    #[serde(rename = "input.tap")]
    InputTap { x: u32, y: u32 },
    #[serde(rename = "input.longpress")]
    InputLongPress { x: u32, y: u32 },
    #[serde(rename = "input.swipe")]
    InputSwipe {
        x1: u32,
        y1: u32,
        x2: u32,
        y2: u32,
        #[serde(rename = "durMs", default, skip_serializing_if = "Option::is_none")]
        dur_ms: Option<u32>,
    },
    #[serde(rename = "input.scroll")]
    InputScroll { x: u32, y: u32, dx: i32, dy: i32 },
    #[serde(rename = "input.text")]
    InputText { text: String },
    #[serde(rename = "input.key")]
    InputKey { key: KeyCode },
    #[serde(rename = "app.open")]
    AppOpen { package: String },
    #[serde(rename = "app.list")]
    AppList {},
    #[serde(rename = "screentext.get")]
    ScreenTextGet {},
    #[serde(rename = "wait.screen")]
    WaitScreen {
        #[serde(rename = "timeoutMs")]
        timeout_ms: u32,
    },
    #[serde(rename = "security.unpair")]
    SecurityUnpair {},
    #[serde(rename = "security.rotate")]
    SecurityRotate {},
    #[serde(rename = "caps.set")]
    CapsSet {
        caps: std::collections::BTreeMap<String, bool>,
    },
}

impl ControlCmd {
    pub fn name(&self) -> &'static str {
        match self {
            ControlCmd::ScreenStart { .. } => "screen.start",
            ControlCmd::ScreenStop {} => "screen.stop",
            ControlCmd::ScreenConfigure { .. } => "screen.configure",
            ControlCmd::InputTap { .. } => "input.tap",
            ControlCmd::InputLongPress { .. } => "input.longpress",
            ControlCmd::InputSwipe { .. } => "input.swipe",
            ControlCmd::InputScroll { .. } => "input.scroll",
            ControlCmd::InputText { .. } => "input.text",
            ControlCmd::InputKey { .. } => "input.key",
            ControlCmd::AppOpen { .. } => "app.open",
            ControlCmd::AppList {} => "app.list",
            ControlCmd::ScreenTextGet {} => "screentext.get",
            ControlCmd::WaitScreen { .. } => "wait.screen",
            ControlCmd::SecurityUnpair {} => "security.unpair",
            ControlCmd::SecurityRotate {} => "security.rotate",
            ControlCmd::CapsSet { .. } => "caps.set",
        }
    }

    /// Convert to a wire request. `id` correlates the response.
    pub fn to_request(&self, id: u32) -> Request {
        let args = serde_json::to_value(self).expect("serializes");
        let args = args
            .get("args")
            .cloned()
            .unwrap_or(Value::Object(Default::default()));
        Request::new(id, self.name(), args)
    }

    /// Parse a wire request back into the typed command.
    pub fn from_request(req: &Request) -> Result<Self, serde_json::Error> {
        let wrapper = serde_json::json!({ "cmd": req.cmd, "args": req.args });
        serde_json::from_value(wrapper)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyCode {
    Back,
    Home,
    Recents,
    Power,
    VolumeUp,
    VolumeDown,
    Enter,
    Tab,
    Escape,
    Delete,
    Space,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
}

// ---------- notifications ----------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationAction {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replyable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationItem {
    pub key: String,
    pub app: String,
    #[serde(rename = "appLabel", default, skip_serializing_if = "Option::is_none")]
    pub app_label: Option<String>,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "postTime")]
    pub post_time: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<NotificationAction>>,
}

// ---------- messages ----------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmsMessage {
    pub id: u64,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub body: String,
    pub sent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
    pub time: u64,
}

// ---------- calls ----------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallRecord {
    pub id: String,
    pub number: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub kind: CallType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,
    pub time: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallType {
    Incoming,
    Outgoing,
    Missed,
    Rejected,
    Blocked,
}

// ---------- status ----------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusInfo {
    pub battery: BatteryStatus,
    #[serde(rename = "screenOn")]
    pub screen_on: bool,
    pub transport: TransportKind,
    #[serde(rename = "uptimeMs", default, skip_serializing_if = "Option::is_none")]
    pub uptime_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatteryStatus {
    pub pct: u32,
    pub charging: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Wifi,
    Bluetooth,
    Vpn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkStatus {
    #[serde(rename = "type")]
    pub kind: NetworkKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    Wifi,
    Ethernet,
    Cellular,
    None,
    Bluetooth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageStatus {
    #[serde(rename = "freeBytes")]
    pub free_bytes: u64,
}

// ---------- files ----------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileProgress {
    #[serde(rename = "transferId")]
    pub transfer_id: u32,
    pub bytes: u64,
    pub total: u64,
}

// ---------- heartbeat ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub t: HeartbeatKind,
    pub ts: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatKind {
    Ping,
    Pong,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_cmd_roundtrip() {
        let cmds = vec![
            ControlCmd::ScreenStart {
                width: Some(720),
                height: Some(1280),
                fps: Some(30),
                bitrate: Some(4_000_000),
            },
            ControlCmd::ScreenStop {},
            ControlCmd::InputTap { x: 100, y: 200 },
            ControlCmd::InputSwipe {
                x1: 0,
                y1: 500,
                x2: 0,
                y2: 100,
                dur_ms: Some(150),
            },
            ControlCmd::InputScroll {
                x: 10,
                y: 20,
                dx: 0,
                dy: -120,
            },
            ControlCmd::InputText {
                text: "hello".into(),
            },
            ControlCmd::InputKey { key: KeyCode::Back },
            ControlCmd::AppOpen {
                package: "com.example.app".into(),
            },
            ControlCmd::AppList {},
            ControlCmd::ScreenTextGet {},
            ControlCmd::WaitScreen { timeout_ms: 5000 },
            ControlCmd::SecurityUnpair {},
            ControlCmd::CapsSet {
                caps: [("screen_view".to_string(), true)].into_iter().collect(),
            },
        ];
        for cmd in cmds {
            let req = cmd.to_request(7);
            let parsed = ControlCmd::from_request(&req).unwrap();
            assert_eq!(cmd, parsed, "roundtrip failed for {}", req.cmd);
        }
    }

    #[test]
    fn response_shapes() {
        let ok = Response::ok(
            3,
            serde_json::json!({"battery": {"pct": 80, "charging": false}}),
        );
        let v = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["ok"], true);
        assert!(v.get("error").is_none());
        let err = Response::err(
            4,
            ErrorBody::with_action(ErrorCode::ConfirmRequired, "confirm on phone", "a-1"),
        );
        let v = serde_json::to_value(&err).unwrap();
        assert_eq!(v["error"]["actionId"], "a-1");
        assert_eq!(v["error"]["code"], "CONFIRM_REQUIRED");
    }
}
