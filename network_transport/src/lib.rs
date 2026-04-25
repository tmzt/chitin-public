//! Network transport wire format.
//!
//! Unified 16-byte frame header for all traffic (stream 0 control + data streams):
//!
//!   [version: u16 LE][checksum: u16 LE][mesh_key: u32 LE][ext: u32 LE][flags: u16 LE][len: u16 LE][payload]
//!
//! No IO, no async. Pure types + codec.

pub mod heap;

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;
pub const FRAME_HEADER_SIZE: usize = 16;

// ── Node IDs (6 bits) ────────────────────────────────────────────────

pub const NODE_CONC:      u8 = 0;
pub const NODE_RESOLVE:   u8 = 62;  // conc resolves well-known service, patches to real node
pub const NODE_BROADCAST: u8 = 63;

// ── Service IDs (6 bits, 0-63, used as id within TYPE_SERVICE) ────────

pub const SVC_NODE:              u8 = 0;
pub const SVC_FAST_THINKER:      u8 = 1;
pub const SVC_DEEP_THINKER:      u8 = 2;
pub const SVC_PROCESS_ENGINE:    u8 = 3;
pub const SVC_REPO_HOST:         u8 = 4;
pub const SVC_CODER_HOST:        u8 = 5;
pub const SVC_VOICE_PROCESSOR:   u8 = 6;
pub const SVC_PROMPT_PROCESSOR:  u8 = 7;
pub const SVC_HEURISTIC_ROUTER:  u8 = 8;
pub const SVC_TERMINAL:          u8 = 9;
pub const SVC_ASR:               u8 = 10;
pub const SVC_DISPLAY:           u8 = 11;
pub const SVC_FEEDBACK:          u8 = 12;
pub const SVC_SERIAL:            u8 = 13;
pub const SVC_DATA:              u8 = 14;
pub const SVC_ANDROID:           u8 = 15;
pub const SVC_SKILLS:            u8 = 16;
// 17-63: dynamic services

// ── Role bits (u64 bitmap, Ident `roles` field) ──────────────────────

pub const ROLE_NODE:              u64 = 1 << SVC_NODE;
pub const ROLE_FAST_THINKER:      u64 = 1 << SVC_FAST_THINKER;
pub const ROLE_DEEP_THINKER:      u64 = 1 << SVC_DEEP_THINKER;
pub const ROLE_PROCESS_ENGINE:    u64 = 1 << SVC_PROCESS_ENGINE;
pub const ROLE_REPO_HOST:         u64 = 1 << SVC_REPO_HOST;
pub const ROLE_CODER_HOST:        u64 = 1 << SVC_CODER_HOST;
pub const ROLE_VOICE_PROCESSOR:   u64 = 1 << SVC_VOICE_PROCESSOR;
pub const ROLE_PROMPT_PROCESSOR:  u64 = 1 << SVC_PROMPT_PROCESSOR;
pub const ROLE_HEURISTIC_ROUTER:  u64 = 1 << SVC_HEURISTIC_ROUTER;
pub const ROLE_TERMINAL:          u64 = 1 << SVC_TERMINAL;
pub const ROLE_ASR:               u64 = 1 << SVC_ASR;
pub const ROLE_DISPLAY:           u64 = 1 << SVC_DISPLAY;
pub const ROLE_SERIAL:            u64 = 1 << SVC_SERIAL;
pub const ROLE_DATA:              u64 = 1 << SVC_DATA;
pub const ROLE_ANDROID:          u64 = 1 << SVC_ANDROID;
pub const ROLE_SKILLS:            u64 = 1 << SVC_SKILLS;

pub const fn svc_to_role(svc: u8) -> u64 { 1u64 << svc }
pub const fn role_to_svc(role: u64) -> u8 { role.trailing_zeros() as u8 }

/// Convert a services bitmap to a human-readable string.
pub fn services_to_str(services: u64) -> String {
    const NAMES: &[(u8, &str)] = &[
        (SVC_NODE, "node"), (SVC_FAST_THINKER, "fast_thinker"),
        (SVC_DEEP_THINKER, "deep_thinker"), (SVC_PROCESS_ENGINE, "process_engine"),
        (SVC_REPO_HOST, "repo_host"), (SVC_CODER_HOST, "coder_host"),
        (SVC_VOICE_PROCESSOR, "voice_processor"), (SVC_PROMPT_PROCESSOR, "prompt_processor"),
        (SVC_HEURISTIC_ROUTER, "heuristic_router"), (SVC_TERMINAL, "terminal"),
        (SVC_ASR, "asr"), (SVC_DISPLAY, "display"), (SVC_SERIAL, "serial"),
        (SVC_DATA, "data"), (SVC_ANDROID, "android"),
        (SVC_SKILLS, "skills"),
    ];
    let mut parts = Vec::new();
    for &(svc, name) in NAMES {
        if services & (1u64 << svc) != 0 {
            parts.push(name);
        }
    }
    if parts.is_empty() { "none".into() } else { parts.join(", ") }
}

/// Convert a list of service name strings to a services bitmap.
pub fn services_from_strs(names: &[String]) -> u64 {
    let mut services: u64 = ROLE_NODE;
    for name in names {
        match name.as_str() {
            "node" => services |= ROLE_NODE,
            "fast_thinker" | "thinker" => services |= ROLE_FAST_THINKER,
            "deep_thinker" => services |= ROLE_DEEP_THINKER,
            "process_engine" | "process_host" => services |= ROLE_PROCESS_ENGINE,
            "repo_host" | "repo" => services |= ROLE_REPO_HOST,
            "coder_host" | "coder" => services |= ROLE_CODER_HOST,
            "voice_processor" => services |= ROLE_VOICE_PROCESSOR,
            "prompt_processor" => services |= ROLE_PROMPT_PROCESSOR,
            "heuristic_router" => services |= ROLE_HEURISTIC_ROUTER,
            "terminal" => services |= ROLE_TERMINAL,
            "asr" => services |= ROLE_ASR,
            "display" => services |= ROLE_DISPLAY,
            "serial" => services |= ROLE_SERIAL,
            "data" => services |= ROLE_DATA,
            "android" => services |= ROLE_ANDROID,
            "skills" => services |= ROLE_SKILLS,
            _ => {}
        }
    }
    services
}

// ── Address: node(6) + type(4) + id(6) packed as u16 ─────────────────

pub const fn addr(node_id: u8, res_type: u8, id: u8) -> u16 {
    ((node_id as u16 & 0x3F) << 10) | ((res_type as u16 & 0xF) << 6) | (id as u16 & 0x3F)
}
pub const fn addr_node(a: u16) -> u8 { (a >> 10) as u8 & 0x3F }
pub const fn addr_type(a: u16) -> u8 { (a >> 6) as u8 & 0xF }
pub const fn addr_id(a: u16) -> u8 { a as u8 & 0x3F }

/// Shorthand: service endpoint = addr(node, TYPE_SERVICE, svc_id)
pub const fn endpoint(node_id: u8, svc_id: u8) -> u16 {
    addr(node_id, TYPE_SERVICE, svc_id)
}
pub const fn ep_node(ep: u16) -> u8 { addr_node(ep) }
pub const fn ep_service(ep: u16) -> u8 { addr_id(ep) }

pub const fn mesh_key(src: u16, dst: u16) -> u32 { ((src as u32) << 16) | (dst as u32) }
pub const fn mesh_src(key: u32) -> u16 { (key >> 16) as u16 }
pub const fn mesh_dst(key: u32) -> u16 { key as u16 }

// ── Resource types (4 bits) ──────────────────────────────────────────

pub const TYPE_SERVICE:  u8 = 0;
pub const TYPE_PROJECT:  u8 = 1;
pub const TYPE_TASK:     u8 = 2;
pub const TYPE_PROCESS:  u8 = 3;
pub const TYPE_NOTE:     u8 = 4;
pub const TYPE_TERMINAL: u8 = 5;
// 6-15: reserved

// ── Resource address (u32) — owner_service:u16 << 16 | resource_id:u16 ──

/// Build a resource address from owning service endpoint + resource ID.
pub const fn resource(owner: u16, id: u16) -> u32 { (owner as u32) << 16 | id as u32 }
/// Extract the owning service endpoint from a resource address.
pub const fn res_owner(r: u32) -> u16 { (r >> 16) as u16 }
/// Extract the resource ID from a resource address.
pub const fn res_id(r: u32) -> u16 { r as u16 }
/// Get the node from a resource address (via owner endpoint).
pub const fn res_node(r: u32) -> u8 { ep_node(res_owner(r)) }
/// Get the service from a resource address (via owner endpoint).
pub const fn res_service(r: u32) -> u8 { ep_service(res_owner(r)) }

/// A registry entry — service or resource advertised by a node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    /// Resource address: (service_u16 << 16) | resource_id.
    /// For services: resource_id = 0 (the service itself).
    pub addr: u32,
    /// Human-readable name.
    pub name: String,
    /// Optional key-value metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Vec<(String, String)>>,
}

impl Entry {
    /// Create a service entry (resource_id = 0).
    pub fn service(owner: u16, name: &str) -> Self {
        Self { addr: resource(owner, 0), name: name.into(), meta: None }
    }

    /// Create a resource entry.
    pub fn resource(owner: u16, id: u16, name: &str) -> Self {
        Self { addr: resource(owner, id), name: name.into(), meta: None }
    }

    /// Create a resource entry with metadata.
    pub fn resource_meta(owner: u16, id: u16, name: &str, meta: Vec<(String, String)>) -> Self {
        Self { addr: resource(owner, id), name: name.into(), meta: Some(meta) }
    }

    /// The owning service endpoint.
    pub fn owner(&self) -> u16 { res_owner(self.addr) }
    /// The resource ID within the service.
    pub fn id(&self) -> u16 { res_id(self.addr) }
    /// The node hosting this entry.
    pub fn node(&self) -> u8 { res_node(self.addr) }
}

/// Display a resource address as base60 (compact, ~6 chars for u32).
pub fn res_display(r: u32) -> String { base60_encode(r as u64) }

/// Parse a resource address from base60 or hex (0x prefix).
pub fn res_parse(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).ok();
    }
    base60_decode(s).map(|v| v as u32)
}

// ── Base60 helpers (delegate to common::util) ────────────────────────

const BASE60: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz.~";

fn base60_encode(mut n: u64) -> String {
    let base = BASE60.len() as u64;
    if n == 0 { return "0".into(); }
    let mut chars = Vec::with_capacity(11);
    while n > 0 { chars.push(BASE60[(n % base) as usize]); n /= base; }
    chars.reverse();
    String::from_utf8(chars).unwrap_or_else(|_| "?".into())
}

fn base60_decode(s: &str) -> Option<u64> {
    let base = BASE60.len() as u64;
    let mut result: u64 = 0;
    for &b in s.as_bytes() {
        let digit = BASE60.iter().position(|&c| c == b)? as u64;
        result = result.checked_mul(base)?.checked_add(digit)?;
    }
    Some(result)
}

// ── Endpoint display/parse ───────────────────────────────────────────

/// Display an endpoint u16 as base60 (2-3 chars).
pub fn ep_display(ep: u16) -> String { base60_encode(ep as u64) }
pub fn node_display(id: u8) -> String { base60_encode(id as u64) }

/// Parse endpoint from base60 or hex (0x prefix).
pub fn ep_parse(s: &str) -> Option<u16> {
    if let Some(hex) = s.strip_prefix("0x") {
        return u16::from_str_radix(hex, 16).ok();
    }
    base60_decode(s).and_then(|v| if v <= u16::MAX as u64 { Some(v as u16) } else { None })
}

/// Format an address for human display.
pub fn addr_label(a: u16) -> String {
    let node = addr_node(a);
    let typ = addr_type(a);
    let id = addr_id(a);

    let node_str = match node {
        NODE_CONC => "conc".into(),
        NODE_RESOLVE => "?".into(),
        NODE_BROADCAST => "*".into(),
        n => format!("{}", n),
    };

    let type_str = match typ {
        TYPE_SERVICE => {
            let svc_name = match id {
                SVC_NODE => "node",
                SVC_FAST_THINKER => "fast_thinker",
                SVC_DEEP_THINKER => "deep_thinker",
                SVC_PROCESS_ENGINE => "process_engine",
                SVC_REPO_HOST => "repo_host",
                SVC_CODER_HOST => "coder_host",
                SVC_VOICE_PROCESSOR => "voice_processor",
                SVC_PROMPT_PROCESSOR => "prompt_processor",
                SVC_HEURISTIC_ROUTER => "heuristic_router",
                SVC_TERMINAL => "terminal",
                SVC_ASR => "asr",
                SVC_DISPLAY => "display",
                SVC_FEEDBACK => "feedback",
                SVC_SERIAL => "serial",
                SVC_DATA => "data",
                SVC_ANDROID => "android",
                _ => return format!("{}/svc:{}", node_str, id),
            };
            return format!("{}/{}", node_str, svc_name);
        }
        TYPE_PROJECT => "proj",
        TYPE_TASK => "task",
        TYPE_PROCESS => "proc",
        TYPE_NOTE => "note",
        TYPE_TERMINAL => "term",
        _ => return format!("{}/t{}:{}", node_str, typ, id),
    };
    format!("{}/{}:{}", node_str, type_str, id)
}

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
    /// len field stores payload size in 4-byte words (padded). Max payload = 65535 * 4 = 256KB.
    pub fn encode(&self) -> Vec<u8> {
        let padded_len = (self.payload.len() + 3) / 4;
        let wire_payload_bytes = padded_len * 4;
        let len_words = padded_len as u16;
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + wire_payload_bytes);
        buf.extend_from_slice(&0u16.to_le_bytes());     // version (zeroed)
        buf.extend_from_slice(&0u16.to_le_bytes());     // checksum (zeroed)
        buf.extend_from_slice(&self.mesh_key.to_le_bytes());
        buf.extend_from_slice(&self.ext.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.extend_from_slice(&len_words.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        // Pad to 4-byte boundary
        let pad = wire_payload_bytes - self.payload.len();
        for _ in 0..pad { buf.push(0); }

        let checksum = inet_checksum(&buf);

        buf[0..2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        buf[2..4].copy_from_slice(&checksum.to_le_bytes());
        buf
    }

    /// Decode from wire bytes. Returns (frame, bytes_consumed).
    /// len field is in 4-byte words. Payload is trimmed of trailing padding.
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < FRAME_HEADER_SIZE { return None; }

        let version = u16::from_le_bytes([data[0], data[1]]);
        let stored_csum = u16::from_le_bytes([data[2], data[3]]);
        let mesh_key = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let ext = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let flags = u16::from_le_bytes([data[12], data[13]]);
        let len_words = u16::from_le_bytes([data[14], data[15]]) as usize;
        let wire_bytes = len_words * 4;

        if version != PROTOCOL_VERSION { return None; }
        let total = FRAME_HEADER_SIZE + wire_bytes;
        if data.len() < total { return None; }

        // Verify checksum
        let mut check = data[..total].to_vec();
        check[0..2].copy_from_slice(&0u16.to_le_bytes());
        check[2..4].copy_from_slice(&0u16.to_le_bytes());
        if inet_checksum(&check) != stored_csum { return None; }

        // Trim trailing zero padding for text formats (JSONL, bincode).
        // Binary (FMT_RAW) keeps the full padded payload — callers use internal
        // length fields (e.g., PCMf num_samples) to determine actual size.
        let raw = &data[FRAME_HEADER_SIZE..total];
        let fmt = (flags >> 13) & 0x7;
        let payload = if fmt == 2 {
            // FMT_RAW: keep all bytes (padding is minimal, callers handle length)
            raw.to_vec()
        } else {
            // JSONL/bincode: trim trailing zeros
            let actual_len = raw.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
            raw[..actual_len].to_vec()
        };
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

    // ── Reply builders ──

    /// Build a JSONL reply to this frame. Swaps from/to, sets irt from
    /// the original's from_ep, preserves obo. The reply goes back to
    /// obo if set, otherwise to from_ep.
    pub fn reply_jsonl(&self, my_ep: u16, payload: &str) -> Self {
        let reply_to = if self.obo() != 0 { self.obo() } else { self.from_ep() };
        Self {
            mesh_key: mesh_key(my_ep, reply_to),
            ext: ext_pack(0, self.from_ep() as u16),
            flags: FMT_JSONL,
            payload: payload.as_bytes().to_vec(),
        }
    }

    /// Build a JSONL reply routed to a different service on the requester.
    /// Use for feedback/status that shouldn't go to the same service handler.
    pub fn reply_jsonl_svc(&self, from_svc: u8, to_svc: u8, payload: &str) -> Self {
        let from_node = ep_node(self.to_ep()); // we are the destination of the original
        let reply_to_node = if self.obo() != 0 { ep_node(self.obo()) } else { self.from_node() };
        Self {
            mesh_key: mesh_key(endpoint(from_node, from_svc), endpoint(reply_to_node, to_svc)),
            ext: ext_pack(0, self.from_ep() as u16),
            flags: FMT_JSONL,
            payload: payload.as_bytes().to_vec(),
        }
    }

    /// Build a raw binary reply to this frame.
    pub fn reply_raw(&self, my_ep: u16, payload: Vec<u8>) -> Self {
        let reply_to = if self.obo() != 0 { self.obo() } else { self.from_ep() };
        Self {
            mesh_key: mesh_key(my_ep, reply_to),
            ext: ext_pack(0, self.from_ep() as u16),
            flags: FMT_RAW,
            payload,
        }
    }

    /// Build a forward of this frame to a different target, setting obo
    /// to the original sender so the response routes back.
    pub fn forward(&self, my_ep: u16, to_ep: u16) -> Self {
        Self {
            mesh_key: mesh_key(my_ep, to_ep),
            ext: ext_pack(self.from_ep(), ext_irt(self.ext)),
            flags: self.flags,
            payload: self.payload.clone(),
        }
    }

    // ── Accessors ──

    pub fn from_ep(&self) -> u16 { mesh_src(self.mesh_key) }
    pub fn to_ep(&self) -> u16 { mesh_dst(self.mesh_key) }
    pub fn from_node(&self) -> u8 { ep_node(self.from_ep()) }
    pub fn to_node(&self) -> u8 { ep_node(self.to_ep()) }
    pub fn from_service(&self) -> u8 { ep_service(self.from_ep()) }
    pub fn to_service(&self) -> u8 { ep_service(self.to_ep()) }
    pub fn from_type(&self) -> u8 { addr_type(self.from_ep()) }
    pub fn to_type(&self) -> u8 { addr_type(self.to_ep()) }
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

// ── Per-service message enums ────────────────────────────────────────

/// Messages for SVC_NODE (control plane on stream 0).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NodeMsg {
    NodeList { nodes: Vec<NodeEntry>, entries: Vec<Entry> },
    NodeAssigned { node_id: u8 },
    ResourceCreated { resource_type: String, name: String, resource_id: String },
    Ping,
    Pong,
    /// Request: which node provides this service?
    ResolveService { service: u8 },
    /// Response: node_id that provides the service, with full endpoint.
    ServiceResolved { service: u8, node_id: u8, endpoint: u16 },
    /// Service not available on any node.
    ServiceNotFound { service: u8 },
}

/// Audio frame fourcc + header for binary PCM data in Frame::raw payloads.
pub const AUDIO_FOURCC: &[u8; 4] = b"PCMf";
pub const AUDIO_HEADER_SIZE: usize = 12; // fourcc(4) + sample_rate(4) + num_samples(4)

/// Build a binary audio frame payload: [PCMf][sample_rate:u32 LE][num_samples:u32 LE][f32 samples...]
pub fn audio_frame_payload(sample_rate: u32, samples: &[f32]) -> Vec<u8> {
    let num = samples.len() as u32;
    let mut buf = Vec::with_capacity(AUDIO_HEADER_SIZE + samples.len() * 4);
    buf.extend_from_slice(AUDIO_FOURCC);
    buf.extend_from_slice(&sample_rate.to_le_bytes());
    buf.extend_from_slice(&num.to_le_bytes());
    for s in samples {
        buf.extend_from_slice(&s.to_le_bytes());
    }
    buf
}

/// Parse a binary audio frame payload. Returns (sample_rate, samples) or None.
pub fn parse_audio_frame(payload: &[u8]) -> Option<(u32, Vec<f32>)> {
    if payload.len() < AUDIO_HEADER_SIZE { return None; }
    if &payload[0..4] != AUDIO_FOURCC { return None; }
    let sample_rate = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let num_samples = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]) as usize;
    let data = &payload[AUDIO_HEADER_SIZE..];
    if data.len() < num_samples * 4 { return None; }
    let samples: Vec<f32> = (0..num_samples)
        .map(|i| {
            let off = i * 4;
            f32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]])
        })
        .collect();
    Some((sample_rate, samples))
}

/// Messages for SVC_FAST_THINKER / SVC_DEEP_THINKER.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ThinkerMsg {
    Infer { prompt: String, max_tokens: u32 },
    InferResult { text: String, tokens_per_sec: f64 },
    Error { message: String },
}

/// An inline attachment extracted from fenced blocks in user input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Original fence language tag (e.g. "rust", "json", "md", "")
    pub fence: String,
    /// Content body
    pub content: String,
}

impl Attachment {
    pub fn new(fence: &str, content: String) -> Self {
        Self { fence: fence.to_string(), content }
    }

    /// Derive MIME type from the fence language tag.
    pub fn mime(&self) -> &str {
        match self.fence.as_str() {
            "" | "md" | "markdown" => "text/markdown",
            "json" => "application/json",
            "yaml" | "yml" => "text/yaml",
            "toml" => "text/toml",
            "rs" | "rust" => "text/x-rust",
            "py" | "python" => "text/x-python",
            "c" | "cpp" | "h" => "text/x-c",
            "sh" | "bash" | "zsh" => "text/x-shellscript",
            "js" | "ts" => "text/javascript",
            "html" => "text/html",
            "css" => "text/css",
            "sql" => "text/x-sql",
            "xml" => "text/xml",
            "csv" => "text/csv",
            _ => "text/plain",
        }
    }

    /// Whether this attachment is safe to write as a file (only .md for now).
    pub fn is_writable(&self) -> bool {
        matches!(self.fence.as_str(), "" | "md" | "markdown")
    }
}

/// Messages for SVC_PROCESS_ENGINE.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProcessMsg {
    TaskDispatch {
        task_type: String, project_id: String, prompt: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        attachments: Vec<Attachment>,
        /// When true, the caller wants the terminal opened immediately
        /// (e.g. /shell). When false (default), the task runs headless
        /// and the user opens the viewer on demand by tapping the task
        /// row (/code, /plan, /refine, /execute).
        #[serde(default)]
        interactive: bool,
    },
    SubmitTicket {
        project_id: String, prompt: String,
        #[serde(default)] branch: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        attachments: Vec<Attachment>,
    },
    /// Create a new empty project (git init) in the writeable projects directory.
    CreateProject { name: String },
    /// Generate a PLAN_N.md using a coder agent, without executing it.
    PlanTask { project_id: String, prompt: String },
    /// Refine the current plan — read existing PLAN, write new PLAN_name_N.md.
    RefinePlan { project_id: String, prompt: String },
    /// Execute the current plan — submit a coder ticket referencing PLAN file.
    ExecutePlan { project_id: String, #[serde(default)] yolo: bool, #[serde(default)] resume_session: Option<String> },
    /// Request current screen text for a running process.
    GetScreen { task_id: String, max_lines: u16 },
    /// Screen text response.
    ScreenText { task_id: String, lines: Vec<String> },
    /// Subscribe to line-by-line output streaming for a task.
    WatchTask { task_id: String },
    /// Incremental line output (pushed by RS to subscriber).
    LineOutput { task_id: String, line_no: u32, text: String },
    ProcessDirective { task_id: String, directive: String },
    Dump { what: String },
    StreamOpen { task_id: String, stream_id: u32, rows: u16, cols: u16 },
    TaskResult {
        task_id: String,
        project: String,
        agent: String,
        status: String,
        output: String,
        /// Echoed back from the triggering `TaskDispatch.interactive`.
        /// Lets clients decide whether to auto-open the terminal
        /// viewer on the ACK even when they didn't originate the
        /// dispatch (another tablet observing the mesh, a restored
        /// session). Serde default keeps older senders compatible.
        #[serde(default)]
        interactive: bool,
    },
    Error { message: String },
}

/// Messages for `SVC_SKILLS`. Resource-server advertises this service
/// and serves the skill catalog from its `~/.chitin/skills` directory;
/// clients discover + dispatch skills over the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SkillMsg {
    /// Enumerate all skills on the responding rs node. The reply is
    /// a `SkillListReply` carrying a `Vec<SkillMetaWire>`.
    List,
    SkillListReply { skills: Vec<SkillMetaWire> },
    /// Dispatch a skill by name with string params.
    Dispatch {
        skill_name: String,
        #[serde(default)]
        params: Vec<(String, String)>,
    },
    /// Initial ack + terminal result share the same shape as
    /// `ProcessMsg::TaskResult` (status: "running" / "complete" / "error").
    TaskResult {
        task_id: String,
        skill_name: String,
        status: String,
        output: String,
    },
    /// Best-effort cancel by task_id.
    Cancel { task_id: String },
    Error { message: String },
}

/// Wire-shape of skill metadata. Kept separate from the domain
/// `common::protocol::SkillMeta` so the transport crate stays dep-free.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillMetaWire {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub param_names: Vec<String>,
    #[serde(default)]
    pub triggers: Vec<String>,
    #[serde(default)]
    pub cron_interval_ms: u64,
}

// ── Checksum ─────────────────────────────────────────────────────────

fn inet_checksum(data: &[u8]) -> u16 {
    // u64 accumulator so multi-hundred-KB payloads (e.g. a full gmail_search
    // result) can't overflow the running sum before the carry-fold. A u32
    // overflows around ~128KB and triggered a debug-mode panic from
    // SVC_DATA replies.
    let mut sum: u64 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_le_bytes([data[i], data[i + 1]]) as u64;
        i += 2;
    }
    if i < data.len() { sum += data[i] as u64; }
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

        let ep2 = endpoint(NODE_BROADCAST, 63);
        assert_eq!(ep_node(ep2), NODE_BROADCAST);
        assert_eq!(ep_service(ep2), 63);
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
    fn ep_display_parse_roundtrip() {
        for ep in [0u16, 1, 42, 63, endpoint(5, SVC_FAST_THINKER), endpoint(NODE_BROADCAST, 63)] {
            let s = ep_display(ep);
            let parsed = ep_parse(&s).unwrap();
            assert_eq!(parsed, ep, "roundtrip failed for ep={}: display='{}' parsed={}", ep, s, parsed);
        }
    }

    #[test]
    fn ep_parse_hex() {
        assert_eq!(ep_parse("0x0401"), Some(endpoint(1, 1)));
        assert_eq!(ep_parse("0x0000"), Some(0));
        assert_eq!(ep_parse("0xFFFF"), Some(u16::MAX));
    }

    #[test]
    fn ep_label_well_known() {
        assert_eq!(addr_label(endpoint(3, SVC_FAST_THINKER)), "3/fast_thinker");
        assert_eq!(addr_label(endpoint(NODE_CONC, SVC_NODE)), "conc/node");
        assert_eq!(addr_label(endpoint(NODE_RESOLVE, SVC_TERMINAL)), "?/terminal");
        assert_eq!(addr_label(endpoint(5, 20)), "5/svc:20"); // dynamic service
    }

    #[test]
    fn resource_address() {
        let owner = endpoint(5, SVC_REPO_HOST);
        let r = resource(owner, 1);
        assert_eq!(res_owner(r), owner);
        assert_eq!(res_id(r), 1);
        assert_eq!(res_node(r), 5);
        assert_eq!(res_service(r), SVC_REPO_HOST);
    }

    #[test]
    fn resource_display_parse() {
        let r = resource(endpoint(5, SVC_REPO_HOST), 42);
        let s = res_display(r);
        let parsed = res_parse(&s).unwrap();
        assert_eq!(parsed, r);
        // Hex also works
        assert_eq!(res_parse("0x00010002"), Some(resource(1, 2)));
    }

    #[test]
    fn entry_builders() {
        let owner = endpoint(5, SVC_REPO_HOST);
        let e = Entry::resource(owner, 1, "htc-kernel-msm7x30");
        assert_eq!(e.name, "htc-kernel-msm7x30");
        assert_eq!(e.owner(), owner);
        assert_eq!(e.id(), 1);
        assert_eq!(e.node(), 5);
        assert!(e.meta.is_none());

        let e2 = Entry::service(owner, "repo_host");
        assert_eq!(e2.id(), 0);
        assert_eq!(e2.owner(), owner);
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
    fn frame_large_payload_no_checksum_overflow() {
        // Regression: inet_checksum's u32 accumulator overflowed on
        // multi-hundred-KB payloads (e.g. a full gmail_search result),
        // producing a debug-mode panic "attempt to add with overflow".
        // The fix uses u64 for the running sum; this must round-trip.
        // Sized just under the u16-word frame limit (65535 * 4 = 262140B).
        let body = "x".repeat(200_000);
        let f = Frame::jsonl(endpoint(1, 0), endpoint(2, 0), &body);
        let encoded = f.encode();
        let (decoded, _) = Frame::decode(&encoded).expect("large frame must round-trip");
        assert_eq!(decoded.payload.len(), body.len());
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

// ── SVC_SERIAL protocol ───────────────────────────────────────────────
//
// Binary frame format (FMT_RAW):
//   [0]     SerialCmd tag (u8)
//   [1..]   Command-specific payload
//
// All multi-byte values are little-endian.

/// Serial service command tags (request → serial node).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialCmd {
    /// List connected USB serial devices.
    /// Response: SerialResp::DeviceList
    ListDevices     = 0x01,
    /// Connect to a device (request USB permission, open, set baud).
    /// Payload: [baud:u32 LE][device_index:u8]
    /// Response: SerialResp::Connected or Error
    Connect         = 0x02,
    /// Disconnect from the current device.
    /// Response: SerialResp::Disconnected
    Disconnect      = 0x03,
    /// Start capture (scrollback accumulates on the serial node).
    /// Requires a prior Connect.
    /// Response: SerialResp::CaptureStarted
    StartCapture    = 0x04,
    /// Stop capture.
    StopCapture     = 0x05,
    /// Read scrollback — last N bytes.
    /// Payload: [len:u32 LE]
    ReadBytes       = 0x06,
    /// Read scrollback — last N lines.
    /// Payload: [count:u32 LE]
    ReadLines       = 0x07,
    /// Write raw bytes to the serial port.
    /// Payload: [bytes...]
    WriteRaw        = 0x08,
    /// Get detailed USB device info (lsusb-style).
    /// Payload: [device_index:u8]
    /// Response: SerialResp::ScrollbackData with text
    DeviceInfo      = 0x09,
    /// Flash an ESP32/ESP32-S3 via ROM bootloader (esptool raw protocol).
    /// Payload: [chip:u8 (0=ESP32, 1=ESP32-S3)][firmware_len:u32 LE][firmware...]
    FlashESP        = 0x10,
    /// Flash via stub loader (faster: higher baud, compression).
    /// Same payload as FlashESP. Uploads stub to IRAM first, then flashes.
    FlashESPStub    = 0x18,
}

/// Serial service response tags (serial node → requester).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialResp {
    /// Device list: [count:u8][device entries...]
    /// Each entry: [vid:u16 LE][pid:u16 LE][name_len:u8][name:utf8...]
    DeviceList      = 0x81,
    /// Device connected and ready.
    Connected       = 0x82,
    /// Device disconnected.
    Disconnected    = 0x83,
    /// Capture started successfully.
    CaptureStarted  = 0x84,
    /// Capture stopped.
    CaptureStopped  = 0x85,
    /// Scrollback data: [len:u32 LE][bytes...]
    ScrollbackData  = 0x86,
    /// Flash progress: [percent:u8][stage_len:u8][stage:utf8...]
    FlashProgress   = 0x90,
    /// Flash complete.
    FlashDone       = 0x91,
    /// Error: [msg_len:u16 LE][msg:utf8...]
    Error           = 0xFF,
}

/// ESP chip variants for FlashESP command.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspChip {
    ESP32   = 0,
    ESP32S3 = 1,
}

impl SerialCmd {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::ListDevices),
            0x02 => Some(Self::Connect),
            0x03 => Some(Self::Disconnect),
            0x04 => Some(Self::StartCapture),
            0x05 => Some(Self::StopCapture),
            0x06 => Some(Self::ReadBytes),
            0x07 => Some(Self::ReadLines),
            0x08 => Some(Self::WriteRaw),
            0x09 => Some(Self::DeviceInfo),
            0x10 => Some(Self::FlashESP),
            0x18 => Some(Self::FlashESPStub),
            _ => None,
        }
    }
}

impl SerialResp {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x81 => Some(Self::DeviceList),
            0x82 => Some(Self::Connected),
            0x83 => Some(Self::Disconnected),
            0x84 => Some(Self::CaptureStarted),
            0x85 => Some(Self::CaptureStopped),
            0x86 => Some(Self::ScrollbackData),
            0x90 => Some(Self::FlashProgress),
            0x91 => Some(Self::FlashDone),
            0xFF => Some(Self::Error),
            _ => None,
        }
    }
}

impl EspChip {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::ESP32),
            1 => Some(Self::ESP32S3),
            _ => None,
        }
    }
}

/// Build a serial command frame payload.
pub fn serial_cmd(cmd: SerialCmd, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(cmd as u8);
    buf.extend_from_slice(data);
    buf
}

/// Build a serial response frame payload.
pub fn serial_resp(resp: SerialResp, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(resp as u8);
    buf.extend_from_slice(data);
    buf
}

/// Build a serial error response.
pub fn serial_error(msg: &str) -> Vec<u8> {
    let bytes = msg.as_bytes();
    let mut buf = Vec::with_capacity(3 + bytes.len());
    buf.push(SerialResp::Error as u8);
    buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(bytes);
    buf
}
