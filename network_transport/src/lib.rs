//! Network transport wire format.
//!
//! Unified 16-byte frame header for all traffic (stream 0 control + data streams):
//!
//!   [version: u16 LE][checksum: u16 LE][mesh_key: u32 LE][ext: u32 LE][flags: u16 LE][len: u16 LE][payload]
//!
//! No IO, no async. Pure types + codec.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;
pub const FRAME_HEADER_SIZE: usize = 16;

// ── Node IDs (6 bits) ────────────────────────────────────────────────

pub const NODE_CONC:      u8 = 0;
pub const NODE_RESOLVE:   u8 = 62;  // conc resolves well-known service, patches to real node
pub const NODE_BROADCAST: u8 = 63;

// ── Service IDs (10 bits, u16 numeric index) ─────────────────────────

pub const SVC_NODE:              u16 = 0;
pub const SVC_FAST_THINKER:      u16 = 1;
pub const SVC_DEEP_THINKER:      u16 = 2;
pub const SVC_PROCESS_ENGINE:    u16 = 3;
pub const SVC_REPO_HOST:         u16 = 4;
pub const SVC_CODER_HOST:        u16 = 5;
pub const SVC_VOICE_PROCESSOR:   u16 = 6;
pub const SVC_PROMPT_PROCESSOR:  u16 = 7;
pub const SVC_HEURISTIC_ROUTER:  u16 = 8;
pub const SVC_TERMINAL:          u16 = 9;
pub const SVC_ASR:               u16 = 10;
pub const SVC_DISPLAY:           u16 = 11;
// 12-63: reserved well-known
pub const SVC_DYNAMIC:           u16 = 65;
// 65-1023: dynamic

// ── Role bits (u64 bitmap, Ident `roles` field) ──────────────────────

pub const ROLE_NODE:              u64 = 1 << SVC_NODE;              // 1
pub const ROLE_FAST_THINKER:      u64 = 1 << SVC_FAST_THINKER;      // 2
pub const ROLE_DEEP_THINKER:      u64 = 1 << SVC_DEEP_THINKER;      // 4
pub const ROLE_PROCESS_ENGINE:    u64 = 1 << SVC_PROCESS_ENGINE;    // 8
pub const ROLE_REPO_HOST:         u64 = 1 << SVC_REPO_HOST;         // 16
pub const ROLE_CODER_HOST:        u64 = 1 << SVC_CODER_HOST;        // 32
pub const ROLE_VOICE_PROCESSOR:   u64 = 1 << SVC_VOICE_PROCESSOR;   // 64
pub const ROLE_PROMPT_PROCESSOR:  u64 = 1 << SVC_PROMPT_PROCESSOR;  // 128
pub const ROLE_HEURISTIC_ROUTER:  u64 = 1 << SVC_HEURISTIC_ROUTER;  // 256
pub const ROLE_TERMINAL:          u64 = 1 << SVC_TERMINAL;          // 512
pub const ROLE_ASR:               u64 = 1 << SVC_ASR;               // 1024
pub const ROLE_DISPLAY:           u64 = 1 << SVC_DISPLAY;           // 2048

pub const fn svc_to_role(svc: u16) -> u64 { 1u64 << svc }
pub const fn role_to_svc(role: u64) -> u16 { role.trailing_zeros() as u16 }

// ── Endpoint: node(6) + service(10) packed as u16 ────────────────────

pub const fn endpoint(node_id: u8, service_id: u16) -> u16 {
    ((node_id as u16) << 10) | (service_id & 0x3FF)
}
pub const fn ep_node(ep: u16) -> u8 { (ep >> 10) as u8 }
pub const fn ep_service(ep: u16) -> u16 { ep & 0x3FF }
pub const fn mesh_key(src: u16, dst: u16) -> u32 { ((src as u32) << 16) | (dst as u32) }
pub const fn mesh_src(key: u32) -> u16 { (key >> 16) as u16 }
pub const fn mesh_dst(key: u32) -> u16 { key as u16 }

// ── Flags (u16) ──────────────────────────────────────────────────────

// Format (bits 15-13)
pub const FMT_JSONL:   u16 = 0 << 13;
pub const FMT_BINCODE: u16 = 1 << 13;
pub const FMT_RAW:     u16 = 2 << 13;
pub const FMT_MASK:    u16 = 0x7 << 13;

// TCP-like flags
pub const FLAG_FIN: u16 = 1 << 12;
pub const FLAG_RST: u16 = 1 << 11;
pub const FLAG_ACK: u16 = 1 << 10;
pub const FLAG_SYN: u16 = 1 << 9;

// TTL (bits 8-5, log-scaled, only meaningful with SYN)
pub const TTL_SHIFT: u16 = 5;
pub const TTL_MASK:  u16 = 0xF << 5;

pub const fn flags_format(flags: u16) -> u16 { (flags & FMT_MASK) >> 13 }
pub const fn flags_ttl(flags: u16) -> u8 { ((flags & TTL_MASK) >> TTL_SHIFT) as u8 }
pub const fn flags_is_fin(flags: u16) -> bool { flags & FLAG_FIN != 0 }
pub const fn flags_is_rst(flags: u16) -> bool { flags & FLAG_RST != 0 }
pub const fn flags_is_ack(flags: u16) -> bool { flags & FLAG_ACK != 0 }
pub const fn flags_is_syn(flags: u16) -> bool { flags & FLAG_SYN != 0 }

/// TTL lookup table: index → seconds. 0 = infinite.
pub const TTL_LUT: [u32; 16] = [
    0, 1, 5, 10, 30, 60, 300, 1800,
    3600, 14400, 86400, 604800, 31536000,
    0, 0, 0,
];

pub const fn ttl_seconds(ttl_bits: u8) -> u32 { TTL_LUT[ttl_bits as usize & 0xF] }

// ── Ext field: obo(u16) + in_reply_to(u16) ──────────────────────────

pub const fn ext_pack(obo: u16, in_reply_to: u16) -> u32 {
    ((obo as u32) << 16) | (in_reply_to as u32)
}
pub const fn ext_obo(ext: u32) -> u16 { (ext >> 16) as u16 }
pub const fn ext_irt(ext: u32) -> u16 { ext as u16 }

// ── Frame ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub mesh_key: u32,
    pub ext: u32,
    pub flags: u16,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Encode to wire bytes: [version:u16][checksum:u16][mesh_key:u32][ext:u32][flags:u16][len:u16][payload]
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + self.payload.len());
        // Write header with version=0, checksum=0 for checksum computation
        buf.extend_from_slice(&0u16.to_le_bytes());     // version (zeroed)
        buf.extend_from_slice(&0u16.to_le_bytes());     // checksum (zeroed)
        buf.extend_from_slice(&self.mesh_key.to_le_bytes());
        buf.extend_from_slice(&self.ext.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&self.payload);

        let checksum = inet_checksum(&buf);

        buf[0..2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        buf[2..4].copy_from_slice(&checksum.to_le_bytes());
        buf
    }

    /// Decode from wire bytes. Returns (frame, bytes_consumed).
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < FRAME_HEADER_SIZE { return None; }

        let version = u16::from_le_bytes([data[0], data[1]]);
        let stored_csum = u16::from_le_bytes([data[2], data[3]]);
        let mesh_key = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let ext = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let flags = u16::from_le_bytes([data[12], data[13]]);
        let len = u16::from_le_bytes([data[14], data[15]]) as usize;

        if version != PROTOCOL_VERSION { return None; }
        let total = FRAME_HEADER_SIZE + len;
        if data.len() < total { return None; }

        // Verify checksum
        let mut check = data[..total].to_vec();
        check[0..2].copy_from_slice(&0u16.to_le_bytes());
        check[2..4].copy_from_slice(&0u16.to_le_bytes());
        if inet_checksum(&check) != stored_csum { return None; }

        let payload = data[FRAME_HEADER_SIZE..total].to_vec();
        Some((Self { mesh_key, ext, flags, payload }, total))
    }

    // ── Builders ──

    /// JSONL fire-and-forget (no SYN/FIN).
    pub fn jsonl(from: u16, to: u16, payload: &str) -> Self {
        Self { mesh_key: mesh_key(from, to), ext: 0, flags: FMT_JSONL, payload: payload.as_bytes().to_vec() }
    }

    /// JSONL with in_reply_to.
    pub fn jsonl_reply(from: u16, to: u16, irt: u16, payload: &str) -> Self {
        Self { mesh_key: mesh_key(from, to), ext: ext_pack(0, irt), flags: FMT_JSONL, payload: payload.as_bytes().to_vec() }
    }

    /// Raw binary fire-and-forget.
    pub fn raw(from: u16, to: u16, payload: Vec<u8>) -> Self {
        Self { mesh_key: mesh_key(from, to), ext: 0, flags: FMT_RAW, payload }
    }

    /// SYN (stream open) with TTL.
    pub fn syn(from: u16, to: u16, ttl: u8, payload: Vec<u8>) -> Self {
        let flags = FMT_RAW | FLAG_SYN | ((ttl as u16 & 0xF) << TTL_SHIFT);
        Self { mesh_key: mesh_key(from, to), ext: 0, flags, payload }
    }

    /// FIN (stream close).
    pub fn fin(from: u16, to: u16) -> Self {
        Self { mesh_key: mesh_key(from, to), ext: 0, flags: FLAG_FIN, payload: vec![] }
    }

    /// RST (abort).
    pub fn rst(from: u16, to: u16) -> Self {
        Self { mesh_key: mesh_key(from, to), ext: 0, flags: FLAG_RST, payload: vec![] }
    }

    // ── Accessors ──

    pub fn from_ep(&self) -> u16 { mesh_src(self.mesh_key) }
    pub fn to_ep(&self) -> u16 { mesh_dst(self.mesh_key) }
    pub fn from_node(&self) -> u8 { ep_node(self.from_ep()) }
    pub fn to_node(&self) -> u8 { ep_node(self.to_ep()) }
    pub fn from_service(&self) -> u16 { ep_service(self.from_ep()) }
    pub fn to_service(&self) -> u16 { ep_service(self.to_ep()) }
    pub fn format(&self) -> u16 { flags_format(self.flags) }
    pub fn is_fin(&self) -> bool { flags_is_fin(self.flags) }
    pub fn is_rst(&self) -> bool { flags_is_rst(self.flags) }
    pub fn is_ack(&self) -> bool { flags_is_ack(self.flags) }
    pub fn is_syn(&self) -> bool { flags_is_syn(self.flags) }
    pub fn obo(&self) -> u16 { ext_obo(self.ext) }
    pub fn in_reply_to(&self) -> u16 { ext_irt(self.ext) }
    pub fn ttl(&self) -> u8 { flags_ttl(self.flags) }
    pub fn ttl_seconds(&self) -> u32 { ttl_seconds(self.ttl()) }

    pub fn to_debug_string(&self) -> String {
        let fmt = match self.format() { 0 => "J", 1 => "B", 2 => "R", _ => "?" };
        let mut flags_str = String::new();
        if self.is_syn() { flags_str.push('S'); }
        if self.is_fin() { flags_str.push('F'); }
        if self.is_rst() { flags_str.push('R'); }
        if self.is_ack() { flags_str.push('A'); }
        format!("[{}/{} → {}/{} {}{}{} {}B]",
            self.from_node(), self.from_service(),
            self.to_node(), self.to_service(),
            fmt, flags_str,
            if self.in_reply_to() != 0 { format!(" irt={}", self.in_reply_to()) } else { String::new() },
            self.payload.len())
    }
}

// ── ServiceHandle ────────────────────────────────────────────────────

/// Lightweight handle to a remote service. Tracks message correlation.
#[derive(Debug, Clone)]
pub struct ServiceHandle {
    pub local_ep: u16,
    pub remote_ep: u16,
    pub last_sent_id: std::sync::Arc<std::sync::atomic::AtomicU16>,
    pub last_recv_id: std::sync::Arc<std::sync::atomic::AtomicU16>,
}

impl ServiceHandle {
    pub fn new(local_ep: u16, remote_ep: u16) -> Self {
        Self {
            local_ep, remote_ep,
            last_sent_id: std::sync::Arc::new(std::sync::atomic::AtomicU16::new(0)),
            last_recv_id: std::sync::Arc::new(std::sync::atomic::AtomicU16::new(0)),
        }
    }

    pub fn mesh_key(&self) -> u32 { mesh_key(self.local_ep, self.remote_ep) }

    /// Build a F+F JSONL frame.
    pub fn fire_json(&self, json: &str) -> Frame {
        let id = self.next_id();
        Frame { mesh_key: self.mesh_key(), ext: ext_pack(0, id), flags: FMT_JSONL, payload: json.as_bytes().to_vec() }
    }

    /// Build a F+F raw binary frame.
    pub fn fire_raw(&self, data: Vec<u8>) -> Frame {
        Frame { mesh_key: self.mesh_key(), ext: 0, flags: FMT_RAW, payload: data }
    }

    /// Build a JSONL reply to last received message.
    pub fn reply_json(&self, json: &str) -> Frame {
        let irt = self.last_recv_id.load(std::sync::atomic::Ordering::Relaxed);
        Frame { mesh_key: self.mesh_key(), ext: ext_pack(0, irt), flags: FMT_JSONL, payload: json.as_bytes().to_vec() }
    }

    /// Build a reply with obo.
    pub fn reply_json_obo(&self, obo: u16, json: &str) -> Frame {
        let irt = self.last_recv_id.load(std::sync::atomic::Ordering::Relaxed);
        Frame { mesh_key: self.mesh_key(), ext: ext_pack(obo, irt), flags: FMT_JSONL, payload: json.as_bytes().to_vec() }
    }

    /// Record receipt of a frame from this service.
    pub fn received(&self, frame: &Frame) {
        self.last_recv_id.store(ext_irt(frame.ext), std::sync::atomic::Ordering::Relaxed);
    }

    fn next_id(&self) -> u16 {
        self.last_sent_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed).wrapping_add(1)
    }
}

// ── JSONL control message types (for stream 0) ──────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeObject {
    pub kind: String,
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEntry {
    pub node_id: String,
    pub numeric_id: u8,
    pub label: String,
    pub roles: u64,
    pub status: String,
    pub objects: Vec<NodeObject>,
}

// ── Checksum ─────────────────────────────────────────────────────────

fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_le_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() { sum += data[i] as u32; }
    while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16); }
    (!sum & 0xFFFF) as u16
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_pack_unpack() {
        let ep = endpoint(5, SVC_FAST_THINKER);
        assert_eq!(ep_node(ep), 5);
        assert_eq!(ep_service(ep), SVC_FAST_THINKER);

        let ep2 = endpoint(NODE_BROADCAST, 1023);
        assert_eq!(ep_node(ep2), NODE_BROADCAST);
        assert_eq!(ep_service(ep2), 1023);
    }

    #[test]
    fn mesh_key_pack_unpack() {
        let src = endpoint(2, SVC_FAST_THINKER);
        let dst = endpoint(5, SVC_PROCESS_ENGINE);
        let key = mesh_key(src, dst);
        assert_eq!(mesh_src(key), src);
        assert_eq!(mesh_dst(key), dst);
    }

    #[test]
    fn frame_jsonl_roundtrip() {
        let f = Frame::jsonl(endpoint(1, SVC_NODE), endpoint(2, SVC_FAST_THINKER),
            r#"{"op":"infer","prompt":"hello"}"#);
        let encoded = f.encode();
        assert!(encoded.len() >= FRAME_HEADER_SIZE);
        let (decoded, consumed) = Frame::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.from_node(), 1);
        assert_eq!(decoded.to_service(), SVC_FAST_THINKER);
        assert_eq!(decoded.format(), 0); // JSONL
        assert_eq!(std::str::from_utf8(&decoded.payload).unwrap(), r#"{"op":"infer","prompt":"hello"}"#);
    }

    #[test]
    fn frame_raw_binary_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let f = Frame::raw(endpoint(3, SVC_TERMINAL), endpoint(4, SVC_DISPLAY), data.clone());
        let encoded = f.encode();
        let (decoded, _) = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.format(), 2); // raw
        assert_eq!(decoded.payload, data);
    }

    #[test]
    fn frame_syn_with_ttl() {
        let f = Frame::syn(endpoint(1, 0), endpoint(2, SVC_TERMINAL), 8, vec![]); // TTL=1hr
        assert!(f.is_syn());
        assert_eq!(f.ttl(), 8);
        assert_eq!(f.ttl_seconds(), 3600);

        let encoded = f.encode();
        let (decoded, _) = Frame::decode(&encoded).unwrap();
        assert!(decoded.is_syn());
        assert_eq!(decoded.ttl_seconds(), 3600);
    }

    #[test]
    fn frame_fin_rst() {
        let fin = Frame::fin(endpoint(1, 0), endpoint(2, 0));
        assert!(fin.is_fin());
        assert!(!fin.is_rst());

        let rst = Frame::rst(endpoint(1, 0), endpoint(2, 0));
        assert!(rst.is_rst());
        assert!(!rst.is_fin());
    }

    #[test]
    fn frame_checksum_corruption() {
        let f = Frame::jsonl(endpoint(1, 0), endpoint(2, 0), "test");
        let mut encoded = f.encode();
        if let Some(b) = encoded.last_mut() { *b ^= 0xFF; }
        assert!(Frame::decode(&encoded).is_none());
    }

    #[test]
    fn ext_obo_irt() {
        let f = Frame::jsonl_reply(endpoint(1, 0), endpoint(2, 0), 42, "reply");
        assert_eq!(f.in_reply_to(), 42);
        assert_eq!(f.obo(), 0);

        let encoded = f.encode();
        let (decoded, _) = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.in_reply_to(), 42);
    }

    #[test]
    fn service_handle_fire_reply() {
        let h = ServiceHandle::new(endpoint(1, SVC_NODE), endpoint(2, SVC_FAST_THINKER));
        let f1 = h.fire_json(r#"{"op":"status"}"#);
        assert_eq!(f1.from_node(), 1);
        assert_eq!(f1.to_service(), SVC_FAST_THINKER);

        // Simulate receiving a reply
        let reply = Frame::jsonl_reply(endpoint(2, SVC_FAST_THINKER), endpoint(1, SVC_NODE), 1, "ok");
        h.received(&reply);

        let f2 = h.reply_json(r#"{"ack":true}"#);
        assert_eq!(f2.in_reply_to(), 1); // correlates to the received frame
    }

    #[test]
    fn role_svc_conversion() {
        assert_eq!(svc_to_role(SVC_FAST_THINKER), ROLE_FAST_THINKER);
        assert_eq!(role_to_svc(ROLE_FAST_THINKER), SVC_FAST_THINKER);
        assert_eq!(svc_to_role(SVC_NODE), ROLE_NODE);
        assert_eq!(svc_to_role(SVC_DISPLAY), ROLE_DISPLAY);
    }

    #[test]
    fn resolve_endpoint() {
        let ep = endpoint(NODE_RESOLVE, SVC_FAST_THINKER);
        assert_eq!(ep_node(ep), NODE_RESOLVE);
        assert_eq!(ep_service(ep), SVC_FAST_THINKER);
    }

    #[test]
    fn frame_incomplete() {
        assert!(Frame::decode(&[0; 15]).is_none()); // less than header
        let f = Frame::jsonl(endpoint(1, 0), endpoint(2, 0), "test");
        let encoded = f.encode();
        assert!(Frame::decode(&encoded[..FRAME_HEADER_SIZE]).is_none()); // header but no payload
    }

    #[test]
    fn debug_string() {
        let f = Frame::syn(endpoint(1, SVC_NODE), endpoint(2, SVC_TERMINAL), 5, b"hello".to_vec());
        let s = f.to_debug_string();
        assert!(s.contains("1/0"));
        assert!(s.contains("2/9"));
        assert!(s.contains("S")); // SYN flag
    }
}
