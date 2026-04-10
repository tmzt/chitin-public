//! Network transport wire format — Message types and binary codec.
//!
//! No IO, no async. Pure data types + serialization.
//!
//! Wire frame:
//!   [version: u32 LE][checksum: u32 LE][len: u32 LE][bincode Message]
//!
//! Checksum: internet checksum (RFC 1071) over the full frame with
//! version, checksum, and len fields zeroed during computation.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

/// Frame header size: version(4) + checksum(4) + len(4) = 12 bytes.
pub const FRAME_HEADER_SIZE: usize = 12;

// ── Message ──────────────────────────────────────────────────────────

/// Top-level message envelope. Routed by `from`/`to` fields.
/// Addresses use `service@node-id` format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    /// Windowed message ID (monotonic u32, wraps).
    pub id: u32,
    /// Sender address: `service@node-id` or `@node-id`.
    pub from: String,
    /// Destination: `service@node-id`, well-known service, `@*`, `@conc`.
    pub to: String,
    /// On-behalf-of: responses go here instead of `from`.
    pub obo: Option<String>,
    /// Message body.
    pub body: Body,
}

/// Message body variants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Body {
    // ── Connection lifecycle ──
    /// First message on a new connection. Required before any other message.
    Ident {
        node_id: String,
        label: String,
        roles: u64,
        objects: Vec<NodeObject>,
    },
    /// Peer list from concentrator.
    NodeList { nodes: Vec<NodeEntry> },

    // ── Keepalive ──
    Ping,
    Pong,

    // ── Stream lifecycle (direct node-to-node streams via concentrator) ──
    StreamOpen { stream_id: String, priority: u8 },
    StreamClose { stream_id: String },
    StreamQuench { stream_id: String },
    StreamResume { stream_id: String },

    // ── Actor messages ──
    Request { payload: Payload },
    Response { payload: Payload },
}

/// Payload format for actor messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Payload {
    /// JSON string (e.g. `{"op":"infer","prompt":"..."}`)
    Json(String),
    /// Raw binary bytes (e.g. ScreenDiff, KeyInput, opaque data)
    Binary(Vec<u8>),
}

/// An object advertised by a node (project, task, skill, etc).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeObject {
    pub kind: String,
    pub id: String,
    pub label: String,
}

/// A peer node entry in NodeList.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeEntry {
    pub node_id: String,
    pub label: String,
    pub roles: u64,
    pub status: String,
    pub objects: Vec<NodeObject>,
}

// ── Address helpers ──────────────────────────────────────────────────

/// Parse `service@node-id` → (service, node-id). If no `@`, returns (input, "").
pub fn parse_address(addr: &str) -> (&str, &str) {
    match addr.split_once('@') {
        Some((service, node)) => (service, node),
        None => (addr, ""),
    }
}

/// Build an address string.
pub fn address(service: &str, node_id: &str) -> String {
    if service.is_empty() {
        format!("@{}", node_id)
    } else {
        format!("{}@{}", service, node_id)
    }
}

// ── Codec ────────────────────────────────────────────────────────────

impl Message {
    /// Encode to bincode bytes (no frame header).
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Decode from bincode bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }

    /// Encode with frame header: [version:u32][checksum:u32][len:u32][bincode].
    pub fn encode_framed(&self) -> Vec<u8> {
        let body = self.encode();
        let len = body.len() as u32;
        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + body.len());

        // Build frame with all header fields zeroed for checksum computation
        frame.extend_from_slice(&0u32.to_le_bytes()); // version (zeroed for checksum)
        frame.extend_from_slice(&0u32.to_le_bytes()); // checksum (zeroed)
        frame.extend_from_slice(&0u32.to_le_bytes()); // len (zeroed)
        frame.extend_from_slice(&body);

        let checksum = compute_checksum(&frame);

        // Fill in actual header values
        frame[0..4].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        frame[4..8].copy_from_slice(&checksum.to_le_bytes());
        frame[8..12].copy_from_slice(&len.to_le_bytes());

        frame
    }

    /// Decode a framed message. Returns (message, total_bytes_consumed).
    pub fn decode_framed(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < FRAME_HEADER_SIZE {
            return None;
        }

        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let stored_checksum = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;

        if version != PROTOCOL_VERSION {
            return None;
        }

        let total = FRAME_HEADER_SIZE + len;
        if data.len() < total {
            return None;
        }

        // Verify checksum
        let mut check_buf = data[..total].to_vec();
        // Zero version, checksum, len for verification
        check_buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        check_buf[4..8].copy_from_slice(&0u32.to_le_bytes());
        check_buf[8..12].copy_from_slice(&0u32.to_le_bytes());
        let computed = compute_checksum(&check_buf);
        if computed != stored_checksum {
            return None;
        }

        let msg = Self::decode(&data[FRAME_HEADER_SIZE..total])?;
        Some((msg, total))
    }

    /// Human-readable debug string (id as base60).
    pub fn to_debug_string(&self) -> String {
        let id_str = id_to_base60(self.id);
        let body_type = match &self.body {
            Body::Ident { .. } => "Ident",
            Body::NodeList { .. } => "NodeList",
            Body::Ping => "Ping",
            Body::Pong => "Pong",
            Body::StreamOpen { .. } => "StreamOpen",
            Body::StreamClose { .. } => "StreamClose",
            Body::StreamQuench { .. } => "StreamQuench",
            Body::StreamResume { .. } => "StreamResume",
            Body::Request { payload } => match payload {
                Payload::Json(_) => "Request/Json",
                Payload::Binary(b) => return format!("[{}] {} → {} Request/Binary({}B)",
                    id_str, self.from, self.to, b.len()),
            },
            Body::Response { payload } => match payload {
                Payload::Json(_) => "Response/Json",
                Payload::Binary(b) => return format!("[{}] {} → {} Response/Binary({}B)",
                    id_str, self.from, self.to, b.len()),
            },
        };
        format!("[{}] {} → {} {}", id_str, self.from, self.to, body_type)
    }

    /// The node that responses should go back to (obo if set, otherwise from).
    pub fn reply_to(&self) -> &str {
        self.obo.as_deref().unwrap_or(&self.from)
    }
}

// ── Checksum (RFC 1071 internet checksum) ────────────────────────────

fn compute_checksum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_le_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += data[i] as u32;
    }
    // Fold 32-bit sum to 16-bit with carry
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum & 0xFFFF
}

// ── ID display ───────────────────────────────────────────────────────

fn id_to_base60(mut n: u32) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz.~";
    if n == 0 { return "0".into(); }
    let base = ALPHABET.len() as u32;
    let mut chars = Vec::with_capacity(6);
    while n > 0 {
        chars.push(ALPHABET[(n % base) as usize]);
        n /= base;
    }
    chars.reverse();
    String::from_utf8(chars).unwrap_or_else(|_| "?".into())
}

// ── Builder helpers ──────────────────────────────────────────────────

static NEXT_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

fn next_id() -> u32 {
    NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl Message {
    pub fn ident(node_id: &str, label: &str, roles: u64, objects: Vec<NodeObject>) -> Self {
        Self {
            id: next_id(),
            from: address("", node_id),
            to: "@conc".into(),
            obo: None,
            body: Body::Ident {
                node_id: node_id.into(),
                label: label.into(),
                roles,
                objects,
            },
        }
    }

    pub fn ping(from: &str) -> Self {
        Self { id: next_id(), from: from.into(), to: "@conc".into(), obo: None, body: Body::Ping }
    }

    pub fn pong(from: &str, to: &str) -> Self {
        Self { id: next_id(), from: from.into(), to: to.into(), obo: None, body: Body::Pong }
    }

    pub fn request_json(from: &str, to: &str, json: &str) -> Self {
        Self {
            id: next_id(), from: from.into(), to: to.into(), obo: None,
            body: Body::Request { payload: Payload::Json(json.into()) },
        }
    }

    pub fn request_binary(from: &str, to: &str, data: Vec<u8>) -> Self {
        Self {
            id: next_id(), from: from.into(), to: to.into(), obo: None,
            body: Body::Request { payload: Payload::Binary(data) },
        }
    }

    pub fn response_json(id: u32, from: &str, to: &str, json: &str) -> Self {
        Self {
            id, from: from.into(), to: to.into(), obo: None,
            body: Body::Response { payload: Payload::Json(json.into()) },
        }
    }

    pub fn response_binary(id: u32, from: &str, to: &str, data: Vec<u8>) -> Self {
        Self {
            id, from: from.into(), to: to.into(), obo: None,
            body: Body::Response { payload: Payload::Binary(data) },
        }
    }

    pub fn stream_open(from: &str, to: &str, stream_id: &str, priority: u8) -> Self {
        Self {
            id: next_id(), from: from.into(), to: to.into(), obo: None,
            body: Body::StreamOpen { stream_id: stream_id.into(), priority },
        }
    }

    pub fn stream_close(from: &str, to: &str, stream_id: &str) -> Self {
        Self {
            id: next_id(), from: from.into(), to: to.into(), obo: None,
            body: Body::StreamClose { stream_id: stream_id.into() },
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bincode_roundtrip() {
        let msg = Message::request_json("@tui", "fast_thinker", r#"{"op":"infer","prompt":"hello"}"#);
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded.from, "@tui");
        assert_eq!(decoded.to, "fast_thinker");
        match decoded.body {
            Body::Request { payload: Payload::Json(s) } => assert!(s.contains("infer")),
            _ => panic!("wrong body"),
        }
    }

    #[test]
    fn framed_roundtrip() {
        let msg = Message::ident("21dda674-rs", "mac-mini", 0x1c, vec![
            NodeObject { kind: "project".into(), id: "p1".into(), label: "test".into() },
        ]);
        let framed = msg.encode_framed();
        assert!(framed.len() >= FRAME_HEADER_SIZE);

        let (decoded, consumed) = Message::decode_framed(&framed).unwrap();
        assert_eq!(consumed, framed.len());
        assert_eq!(decoded.to, "@conc");
        match decoded.body {
            Body::Ident { node_id, roles, .. } => {
                assert_eq!(node_id, "21dda674-rs");
                assert_eq!(roles, 0x1c);
            }
            _ => panic!("wrong body"),
        }
    }

    #[test]
    fn checksum_detects_corruption() {
        let msg = Message::ping("@test");
        let mut framed = msg.encode_framed();
        // Corrupt one byte in the body
        if let Some(b) = framed.last_mut() { *b ^= 0xFF; }
        assert!(Message::decode_framed(&framed).is_none());
    }

    #[test]
    fn binary_payload_roundtrip() {
        let data = vec![0u8, 1, 2, 3, 255, 254, 253];
        let msg = Message::request_binary("@a", "@b", data.clone());
        let framed = msg.encode_framed();
        let (decoded, _) = Message::decode_framed(&framed).unwrap();
        match decoded.body {
            Body::Request { payload: Payload::Binary(d) } => assert_eq!(d, data),
            _ => panic!("wrong body"),
        }
    }

    #[test]
    fn address_parse() {
        assert_eq!(parse_address("process_engine@21dda674-rs"), ("process_engine", "21dda674-rs"));
        assert_eq!(parse_address("@21dda674-rs"), ("", "21dda674-rs"));
        assert_eq!(parse_address("fast_thinker"), ("fast_thinker", ""));
        assert_eq!(parse_address("@*"), ("", "*"));
        assert_eq!(parse_address("@conc"), ("", "conc"));
    }

    #[test]
    fn address_build() {
        assert_eq!(address("process_engine", "21dda674-rs"), "process_engine@21dda674-rs");
        assert_eq!(address("", "21dda674-rs"), "@21dda674-rs");
    }

    #[test]
    fn debug_string() {
        let msg = Message::request_json("@tui", "fast_thinker", "{}");
        let s = msg.to_debug_string();
        assert!(s.contains("@tui"));
        assert!(s.contains("fast_thinker"));
        assert!(s.contains("Request/Json"));
    }

    #[test]
    fn id_base60_display() {
        assert_eq!(id_to_base60(0), "0");
        assert_eq!(id_to_base60(1), "1");
        let s = id_to_base60(123456);
        assert!(!s.is_empty());
        assert!(s.len() <= 4); // 123456 fits in ~3 base60 digits
    }

    #[test]
    fn stream_lifecycle_roundtrip() {
        let msg = Message::stream_open("@tui", "@rs", "stream-abc@conc", 0);
        let framed = msg.encode_framed();
        let (decoded, _) = Message::decode_framed(&framed).unwrap();
        match decoded.body {
            Body::StreamOpen { stream_id, priority } => {
                assert_eq!(stream_id, "stream-abc@conc");
                assert_eq!(priority, 0);
            }
            _ => panic!("wrong body"),
        }
    }

    #[test]
    fn incomplete_frame_returns_none() {
        let msg = Message::ping("@test");
        let framed = msg.encode_framed();
        // Truncate
        assert!(Message::decode_framed(&framed[..FRAME_HEADER_SIZE - 1]).is_none());
        assert!(Message::decode_framed(&framed[..FRAME_HEADER_SIZE]).is_none()); // no body
    }
}
