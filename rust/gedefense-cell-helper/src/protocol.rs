//! VGTGC2 line protocol (POINT2 spec §3): Unix socket, HMAC-SHA256, ±30 s,
//! replay cache, SCM_RIGHTS for exactly one export FD. No JSON/TOML.
//!
//! ```text
//! req : "VGTGC2" ␟ id-hex16 ␟ ts ␟ COMMAND ␟ b64url(payload) ␟ mac-hex64 \n
//! resp: "VGTGC2R" ␟ id-hex16 ␟ OK|ERR ␟ b64url(payload) ␟ mac-hex64 \n
//! mac(req) = HMAC-SHA256(key, "VGTGC2" ␟ id ␟ ts ␟ command ␟ b64payload)
//! mac(resp)= HMAC-SHA256(key, "VGTGC2R" ␟ id ␟ status ␟ b64payload)
//! ```
//! `CELL_LIST` payload = `count=N\n` + one 8-field `k=v` row per cell.
//! `id-hex16` = 16 hex chars; MAC = 64 hex chars (URL_SAFE_NO_PAD canonical).
#![allow(dead_code)] // client-parity helpers (`encode_request`, `parse_response`) are test/tooling-only

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::os::fd::RawFd;

use crate::types::{is_hex, is_payload_value, ErrorCode, HARD_MAX_INPUT_BYTES, MAX_TTL_SECONDS, MIN_TTL_SECONDS};

pub const SEP: u8 = 0x1f;
pub const MAX_REQUEST_BYTES: usize = 8192;
pub const MAX_RESPONSE_BYTES: usize = 65536;
pub const TIME_WINDOW_SECS: u64 = 30;
pub const REPLAY_CACHE_CAPACITY: usize = 4096;
pub const MAX_REQUESTS_PER_CONNECTION: usize = 64;
pub const MAX_REQUEST_PAYLOAD: usize = 4096;
pub const MAX_RESPONSE_PAYLOAD: usize = 48 * 1024;
const MAX_RSS_WIRE: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PIDS_WIRE: u64 = 1024;

type HmacSha256 = Hmac<Sha256>;

macro_rules! commands {
    ($( $variant:ident => $wire:literal ),* $(,)?) => {
        /// Closed VGTGC2 command set.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Command { $( $variant ),* }
        impl Command {
            pub const ALL: [Command; 8] = [ $( Command::$variant ),* ];
            pub fn as_str(self) -> &'static str { match self { $( Command::$variant => $wire ),* } }
            pub fn from_str(s: &str) -> Option<Command> {
                Command::ALL.iter().copied().find(|c| c.as_str() == s)
            }
        }
    };
}
commands! {
    CellCapabilities => "CELL_CAPABILITIES", CellCreate => "CELL_CREATE", CellList => "CELL_LIST",
    CellFreeze => "CELL_FREEZE", CellUnfreeze => "CELL_UNFREEZE", CellBurn => "CELL_BURN",
    CellExportRead => "CELL_EXPORT_READ", CellHealth => "CELL_HEALTH",
}
/// Authenticated, fully validated request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub id: String,
    pub ts: u64,
    pub command: Command,
    pub fields: BTreeMap<String, String>,
}
impl Request {
    pub fn get(&self, name: &str) -> Result<&str, ErrorCode> {
        self.fields.get(name).map(|s| s.as_str()).ok_or(ErrorCode::BadRequest)
    }
    pub fn get_u64(&self, name: &str) -> Result<u64, ErrorCode> {
        self.get(name)?.parse::<u64>().map_err(|_| ErrorCode::BadRequest)
    }
}
/// Bounded ID-based replay cache (FIFO eviction, spec §3).
#[derive(Clone, Debug)]
pub struct ReplayCache { seen: HashSet<String>, order: VecDeque<String>, cap: usize }
impl ReplayCache {
    pub fn new(cap: usize) -> Self {
        ReplayCache { seen: HashSet::new(), order: VecDeque::new(), cap: cap.max(1) }
    }
    /// Returns `true` on first sight, `false` for a replayed ID.
    pub fn check_and_insert(&mut self, id: &str) -> bool {
        if self.seen.contains(id) { return false; }
        if self.order.len() >= self.cap {
            if let Some(old) = self.order.pop_front() { self.seen.remove(&old); }
        }
        self.seen.insert(id.to_string());
        self.order.push_back(id.to_string());
        true
    }
    pub fn len(&self) -> usize { self.order.len() }
}
fn mac_parts(key: &[u8], parts: &[&[u8]]) -> Result<HmacSha256, ErrorCode> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ErrorCode::Internal)?;
    for (i, part) in parts.iter().enumerate() {
        if i > 0 { mac.update(&[SEP]); }
        mac.update(part);
    }
    Ok(mac)
}
fn mac_hex(key: &[u8], parts: &[&[u8]]) -> Result<String, ErrorCode> {
    Ok(hex::encode(mac_parts(key, parts)?.finalize().into_bytes()))
}
fn verify_mac(key: &[u8], parts: &[&[u8]], mac_hex_value: &str) -> Result<(), ErrorCode> {
    if !is_hex(mac_hex_value, 64) { return Err(ErrorCode::BadMac); }
    let mut raw = [0u8; 32];
    hex::decode_to_slice(mac_hex_value, &mut raw).map_err(|_| ErrorCode::BadMac)?;
    mac_parts(key, parts)?.verify_slice(&raw).map_err(|_| ErrorCode::BadMac)
}
fn encode_fields(fields: &[(&str, String)]) -> Result<Vec<u8>, ErrorCode> {
    let mut out = Vec::with_capacity(256);
    for (i, (k, v)) in fields.iter().enumerate() {
        let key_ok = k.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !is_payload_value(v) || !key_ok { return Err(ErrorCode::Internal); }
        if i > 0 { out.push(SEP); }
        out.extend_from_slice(k.as_bytes());
        out.push(b'=');
        out.extend_from_slice(v.as_bytes());
    }
    Ok(out)
}
/// Encode a canonical request line (test/tooling parity, ends with `\n`).
pub fn encode_request(id: &str, ts: u64, command: Command, fields: &[(&str, String)], key: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    if !is_hex(id, 16) { return Err(ErrorCode::Internal); }
    let b64 = URL_SAFE_NO_PAD.encode(&encode_fields(fields)?);
    let ts_s = ts.to_string();
    let mac = mac_hex(key, &[b"VGTGC2", id.as_bytes(), ts_s.as_bytes(), command.as_str().as_bytes(), b64.as_bytes()])?;
    let line = format!("VGTGC2\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\n", id, ts_s, command.as_str(), b64, mac);
    if line.len() > MAX_REQUEST_BYTES { return Err(ErrorCode::BadRequest); }
    Ok(line.into_bytes())
}
/// Parse + authenticate one request (peer UID must be pre-resolved, see [`peer_uid`]).
pub fn parse_request(line: &str, key: &[u8], peer_uid: u32, expected_uid: u32, now: u64,
    replay: &mut ReplayCache) -> Result<Request, ErrorCode> {
    if peer_uid != expected_uid || line.len() > MAX_REQUEST_BYTES || line.bytes().any(|b| b == 0) {
        return Err(ErrorCode::BadRequest);
    }
    let line = line.trim_end_matches(['\n', '\r']);
    let parts: Vec<&str> = line.split('\u{1f}').collect();
    // Token 4 (payload) may be empty for commands without fields.
    if parts.len() != 6 || [0usize, 1, 2, 3, 5].iter().any(|i| parts[*i].is_empty()) {
        return Err(ErrorCode::BadRequest);
    }
    let (id, b64) = (parts[1], parts[4]);
    if parts[0] != "VGTGC2" || !is_hex(id, 16) { return Err(ErrorCode::BadRequest); }
    let ts = parse_u64(parts[2])?;
    let command = Command::from_str(parts[3]).ok_or(ErrorCode::UnknownCommand)?;
    if b64.len() > MAX_REQUEST_PAYLOAD * 2
        || !b64.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(ErrorCode::BadRequest);
    }
    let payload = URL_SAFE_NO_PAD.decode(b64).map_err(|_| ErrorCode::BadRequest)?;
    if URL_SAFE_NO_PAD.encode(&payload) != b64 || payload.len() > MAX_REQUEST_PAYLOAD {
        return Err(ErrorCode::BadRequest);
    }
    verify_mac(key, &[b"VGTGC2", id.as_bytes(), parts[2].as_bytes(), parts[3].as_bytes(), b64.as_bytes()], parts[5])?;
    if now.abs_diff(ts) > TIME_WINDOW_SECS { return Err(ErrorCode::Stale); }
    let fields = parse_payload(&payload, command)?;
    if !replay.check_and_insert(id) { return Err(ErrorCode::Replay); }
    Ok(Request { id: id.to_string(), ts, command, fields })
}
fn parse_u64(s: &str) -> Result<u64, ErrorCode> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ErrorCode::BadRequest);
    }
    s.parse::<u64>().map_err(|_| ErrorCode::BadRequest)
}
fn check_num(value: &str, min: u64, max: u64) -> Result<u64, ErrorCode> {
    let n = parse_u64(value)?;
    if n < min || n > max { return Err(ErrorCode::BadRequest); }
    Ok(n)
}
fn parse_payload(payload: &[u8], command: Command) -> Result<BTreeMap<String, String>, ErrorCode> {
    let text = std::str::from_utf8(payload).map_err(|_| ErrorCode::BadRequest)?;
    let mut fields = BTreeMap::new();
    if !text.is_empty() {
        for part in text.split('\u{1f}') {
            let (k, v) = part.split_once('=').ok_or(ErrorCode::BadRequest)?;
            if k.is_empty() || v.contains('=') || !is_payload_value(v) { return Err(ErrorCode::BadRequest); }
            if fields.insert(k.to_string(), v.to_string()).is_some() { return Err(ErrorCode::BadRequest); }
        }
    }
    validate_fields(command, &fields)?;
    Ok(fields)
}
fn validate_fields(command: Command, fields: &BTreeMap<String, String>) -> Result<(), ErrorCode> {
    let required: &[&str] = match command {
        Command::CellCapabilities | Command::CellList | Command::CellHealth => &[],
        Command::CellCreate => &["profile", "input_token", "input_sha256", "input_size", "ttl_seconds", "max_rss_bytes", "max_pids"],
        Command::CellFreeze | Command::CellUnfreeze => &["uuid", "generation", "cgroup_id"],
        Command::CellBurn => &["uuid", "generation", "cgroup_id", "evidence_id", "reason"],
        Command::CellExportRead => &["uuid", "generation"],
    };
    if fields.len() != required.len() || !required.iter().all(|n| fields.contains_key(*n)) {
        return Err(ErrorCode::BadRequest);
    }
    match command {
        Command::CellCreate => {
            let profile = fields["profile"].as_str();
            if profile.len() > 64 || !profile.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-') {
                return Err(ErrorCode::BadRequest);
            }
            if !is_hex(&fields["input_token"], 32) || !is_hex(&fields["input_sha256"], 64) {
                return Err(ErrorCode::BadRequest);
            }
            check_num(&fields["input_size"], 1, HARD_MAX_INPUT_BYTES)?;
            check_num(&fields["ttl_seconds"], MIN_TTL_SECONDS, MAX_TTL_SECONDS)?;
            check_num(&fields["max_rss_bytes"], 1, MAX_RSS_WIRE)?;
            check_num(&fields["max_pids"], 1, MAX_PIDS_WIRE)?;
        }
        Command::CellFreeze | Command::CellUnfreeze | Command::CellBurn | Command::CellExportRead => {
            if !is_hex(&fields["uuid"], 32) { return Err(ErrorCode::BadRequest); }
            check_num(&fields["generation"], 1, u64::MAX)?;
            if command != Command::CellExportRead { check_num(&fields["cgroup_id"], 1, u64::MAX)?; }
            if command == Command::CellBurn
                && (fields["evidence_id"].len() > 128 || fields["reason"].len() > 64) {
                return Err(ErrorCode::BadRequest);
            }
        }
        Command::CellCapabilities | Command::CellList | Command::CellHealth => {}
    }
    Ok(())
}
/// Best-effort request ID for an ERR reply when the line itself is invalid.
pub fn request_id_or_zeros(line: &str) -> String {
    line.split('\u{1f}').nth(1).filter(|s| is_hex(s, 16)).unwrap_or("0000000000000000").to_string()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status { Ok, Err }
impl Status {
    pub fn as_str(self) -> &'static str { match self { Status::Ok => "OK", Status::Err => "ERR" } }
}
/// Parsed response (client tests / Go parity).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response { pub id: String, pub status: Status, pub raw_payload: Vec<u8>, pub fields: BTreeMap<String, String> }
pub fn encode_ok(id: &str, fields: &[(&str, String)], key: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    encode_line(id, Status::Ok, &encode_fields(fields)?, key)
}
pub fn encode_err(id: &str, code: ErrorCode, key: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    encode_line(id, Status::Err, &encode_fields(&[("code", code.as_str().to_string())])?, key)
}
/// Encode an OK response with a pre-built raw payload (e.g. `CELL_LIST` rows).
pub fn encode_ok_raw(id: &str, raw_payload: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    if raw_payload.len() > MAX_RESPONSE_PAYLOAD || raw_payload.contains(&0) { return Err(ErrorCode::Internal); }
    encode_line(id, Status::Ok, raw_payload, key)
}
fn encode_line(id: &str, status: Status, payload: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    if !is_hex(id, 16) { return Err(ErrorCode::Internal); }
    let b64 = URL_SAFE_NO_PAD.encode(payload);
    let mac = mac_hex(key, &[b"VGTGC2R", id.as_bytes(), status.as_str().as_bytes(), b64.as_bytes()])?;
    let line = format!("VGTGC2R\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\n", id, status.as_str(), b64, mac);
    if line.len() > MAX_RESPONSE_BYTES { return Err(ErrorCode::Internal); }
    Ok(line.into_bytes())
}
/// Parse + authenticate a response line (unit tests / integration parity).
pub fn parse_response(line: &str, key: &[u8]) -> Result<Response, ErrorCode> {
    if line.len() > MAX_RESPONSE_BYTES || line.bytes().any(|b| b == 0) { return Err(ErrorCode::BadRequest); }
    let line = line.trim_end_matches(['\n', '\r']);
    let parts: Vec<&str> = line.split('\u{1f}').collect();
    if parts.len() != 5 || parts.iter().any(|p| p.is_empty()) || parts[0] != "VGTGC2R" {
        return Err(ErrorCode::BadRequest);
    }
    let id = parts[1];
    if !is_hex(id, 16) { return Err(ErrorCode::BadRequest); }
    let status = match parts[2] { "OK" => Status::Ok, "ERR" => Status::Err, _ => return Err(ErrorCode::BadRequest) };
    let b64 = parts[3];
    let payload = URL_SAFE_NO_PAD.decode(b64).map_err(|_| ErrorCode::BadRequest)?;
    if URL_SAFE_NO_PAD.encode(&payload) != b64 || payload.len() > MAX_RESPONSE_PAYLOAD {
        return Err(ErrorCode::BadRequest);
    }
    verify_mac(key, &[b"VGTGC2R", id.as_bytes(), parts[2].as_bytes(), b64.as_bytes()], parts[4])?;
    let text = std::str::from_utf8(&payload).map_err(|_| ErrorCode::BadRequest)?;
    let mut fields = BTreeMap::new();
    if !text.is_empty() {
        for part in text.split('\u{1f}') {
            let (k, v) = part.split_once('=').ok_or(ErrorCode::BadRequest)?;
            fields.insert(k.to_string(), v.to_string());
        }
    }
    if status == Status::Err {
        let code = fields.get("code").ok_or(ErrorCode::BadRequest)?;
        if ErrorCode::from_str(code).is_none() { return Err(ErrorCode::BadRequest); }
    }
    Ok(Response { id: id.to_string(), status, raw_payload: payload, fields })
}
/// Build a `CELL_LIST` raw payload: `count=N\n` + one row per cell (8 fields).
pub fn encode_list_payload(rows: &[Vec<(&str, String)>]) -> Result<Vec<u8>, ErrorCode> {
    let mut out = format!("count={}", rows.len()).into_bytes();
    for row in rows {
        out.push(b'\n');
        out.extend_from_slice(&encode_fields(row)?);
    }
    if out.len() > MAX_RESPONSE_PAYLOAD { return Err(ErrorCode::Internal); }
    Ok(out)
}
/// Parse a `CELL_LIST` payload (count must match row count).
pub fn parse_list_payload(payload: &[u8]) -> Result<Vec<BTreeMap<String, String>>, ErrorCode> {
    let text = std::str::from_utf8(payload).map_err(|_| ErrorCode::BadRequest)?;
    let mut lines = text.split('\n');
    let count = check_num(lines.next().ok_or(ErrorCode::BadRequest)?.strip_prefix("count=").ok_or(ErrorCode::BadRequest)?, 0, 64)?;
    let mut rows = Vec::new();
    for row in lines {
        let mut fields = BTreeMap::new();
        for part in row.split('\u{1f}') {
            let (k, v) = part.split_once('=').ok_or(ErrorCode::BadRequest)?;
            fields.insert(k.to_string(), v.to_string());
        }
        rows.push(fields);
    }
    if rows.len() as u64 != count { return Err(ErrorCode::BadRequest); }
    Ok(rows)
}
/// `SO_PEERCRED` UID check (Linux).
pub fn peer_uid(fd: RawFd) -> Result<u32, ErrorCode> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: valid buffers sized for `struct ucred`; SO_PEERCRED fills exactly one.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED,
        &mut cred as *mut libc::ucred as *mut libc::c_void, &mut len) };
    if rc != 0 || len as usize != std::mem::size_of::<libc::ucred>() { return Err(ErrorCode::BadRequest); }
    Ok(cred.uid)
}
/// Send exactly one FD via `SCM_RIGHTS` together with `data`.
pub fn send_fd(fd: RawFd, fd_to_send: RawFd, data: &[u8]) -> Result<(), ErrorCode> {
    if data.is_empty() || data.len() > MAX_RESPONSE_BYTES { return Err(ErrorCode::Internal); }
    // SAFETY: all pointers refer to stack storage valid for the syscall duration;
    // CMSG_SPACE sizes the control buffer exactly for one RawFd.
    unsafe {
        let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
        let mut control = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() { return Err(ErrorCode::Internal); }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::copy_nonoverlapping(&fd_to_send as *const RawFd, libc::CMSG_DATA(cmsg) as *mut RawFd, 1);
        if libc::sendmsg(fd, &msg, 0) < 0 { return Err(ErrorCode::Internal); }
    }
    Ok(())
}
/// Receive exactly one FD via `SCM_RIGHTS` plus the accompanying data bytes.
pub fn recv_fd(fd: RawFd, max_data: usize) -> Result<(RawFd, Vec<u8>), ErrorCode> {
    let cap = max_data.min(MAX_RESPONSE_BYTES).max(1);
    let mut data = vec![0u8; cap];
    // SAFETY: buffers are valid; kernel fills iov/control and reports lengths.
    unsafe {
        let mut iov = libc::iovec { iov_base: data.as_mut_ptr() as *mut libc::c_void, iov_len: data.len() };
        let mut control = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.len();
        let n = libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n < 0 { return Err(ErrorCode::Internal); }
        let mut received: Option<RawFd> = None;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                if (*cmsg).cmsg_len < libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize {
                    return Err(ErrorCode::BadRequest);
                }
                received = Some(std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const RawFd));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        data.truncate(n as usize);
        received.map(|f| (f, data)).ok_or(ErrorCode::BadRequest)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const NOW: u64 = 1_700_000_000;
    const ID: &str = "00112233445566aa";
    fn parse(line: &[u8], cache: &mut ReplayCache) -> Result<Request, ErrorCode> {
        parse_request(std::str::from_utf8(line).unwrap(), KEY, 1000, 1000, NOW, cache)
    }
    fn create_fields() -> Vec<(&'static str, String)> {
        vec![("profile", "pdf-viewer".to_string()), ("input_token", "ab".repeat(16)),
            ("input_sha256", "cd".repeat(32)), ("input_size", "1234".to_string()),
            ("ttl_seconds", "120".to_string()), ("max_rss_bytes", "268435456".to_string()),
            ("max_pids", "32".to_string())]
    }
    #[test]
    fn valid_requests_roundtrip_and_replay_is_bounded() {
        for c in Command::ALL { assert_eq!(Command::from_str(c.as_str()), Some(c)); }
        assert_eq!(Command::from_str("CELL_NOPE"), None);
        let line = encode_request(ID, NOW, Command::CellCreate, &create_fields(), KEY).unwrap();
        let mut cache = ReplayCache::new(REPLAY_CACHE_CAPACITY);
        let req = parse(&line, &mut cache).unwrap();
        assert_eq!((req.id.as_str(), req.command), (ID, Command::CellCreate));
        assert_eq!(req.get("profile").unwrap(), "pdf-viewer");
        assert_eq!(req.get_u64("ttl_seconds").unwrap(), 120);
        assert_eq!(parse(&line, &mut cache), Err(ErrorCode::Replay));
        let mut small = ReplayCache::new(2);
        assert!(small.check_and_insert("a") && small.check_and_insert("b") && small.check_and_insert("c"));
        assert_eq!(small.len(), 2);
        assert!(!small.check_and_insert("c"));
        // 0x1f framing only; space framing is not accepted
        let spaced = String::from_utf8(line).unwrap().trim_end().replace('\u{1f}', " ");
        assert_eq!(parse(spaced.as_bytes(), &mut cache), Err(ErrorCode::BadRequest));
    }
    #[test]
    fn auth_time_and_identity_failures() {
        let mut line = encode_request(ID, NOW, Command::CellHealth, &[], KEY).unwrap();
        let pos = line.len() - 65; // first MAC char
        line[pos] = if line[pos] == b'a' { b'b' } else { b'a' };
        assert_eq!(parse(&line, &mut ReplayCache::new(4)), Err(ErrorCode::BadMac));
        for (ts, want) in [(NOW - 31, ErrorCode::Stale), (NOW + 31, ErrorCode::Stale)] {
            let line = encode_request(ID, ts, Command::CellHealth, &[], KEY).unwrap();
            assert_eq!(parse(&line, &mut ReplayCache::new(4)), Err(want));
        }
        for ts in [NOW - 30, NOW + 30] {
            let line = encode_request(ID, ts, Command::CellHealth, &[], KEY).unwrap();
            assert!(parse(&line, &mut ReplayCache::new(4)).is_ok());
        }
        let line = encode_request(ID, NOW, Command::CellHealth, &[], KEY).unwrap();
        let s = std::str::from_utf8(&line).unwrap();
        assert_eq!(parse_request(s, KEY, 1001, 1000, NOW, &mut ReplayCache::new(4)), Err(ErrorCode::BadRequest));
    }
    #[test]
    fn structural_rejections() {
        let line = encode_request(ID, NOW, Command::CellHealth, &[], KEY).unwrap();
        let text = String::from_utf8(line).unwrap();
        assert_eq!(parse(text.replace("CELL_HEALTH", "CELL_EVIL").as_bytes(), &mut ReplayCache::new(4)), Err(ErrorCode::UnknownCommand));
        assert_eq!(parse(&vec![b'A'; MAX_REQUEST_BYTES + 1], &mut ReplayCache::new(4)), Err(ErrorCode::BadRequest));
        let mut parts: Vec<&str> = text.trim_end().split('\u{1f}').collect();
        parts[4] = "!!!!";
        assert_eq!(parse((parts.join("\u{1f}") + "\n").as_bytes(), &mut ReplayCache::new(4)), Err(ErrorCode::BadRequest));
        // valid base64url payload containing a space is rejected (value charset)
        let b64 = URL_SAFE_NO_PAD.encode(b"profile=pdf viewer");
        let mac = mac_hex(KEY, &[b"VGTGC2", ID.as_bytes(), NOW.to_string().as_bytes(), b"CELL_CREATE", b64.as_bytes()]).unwrap();
        let line = format!("VGTGC2\u{1f}{}\u{1f}{}\u{1f}CELL_CREATE\u{1f}{}\u{1f}{}\n", ID, NOW, b64, mac);
        assert_eq!(parse(line.as_bytes(), &mut ReplayCache::new(4)), Err(ErrorCode::BadRequest));
        // unknown/missing fields
        let line = encode_request(ID, NOW, Command::CellCreate, &[("profile", "x".into()), ("evil", "1".into())], KEY).unwrap();
        assert_eq!(parse(&line, &mut ReplayCache::new(4)), Err(ErrorCode::BadRequest));
        for cmd in [Command::CellCreate, Command::CellBurn, Command::CellFreeze, Command::CellExportRead] {
            let line = encode_request(ID, NOW, cmd, &[("uuid", "ab".repeat(16))], KEY).unwrap();
            assert_eq!(parse(&line, &mut ReplayCache::new(4)), Err(ErrorCode::BadRequest), "{:?}", cmd);
        }
        // value caps
        for (k, v) in [("input_size", (HARD_MAX_INPUT_BYTES + 1).to_string()), ("ttl_seconds", "4".to_string()),
            ("max_pids", "0".to_string()), ("max_pids", "999999".to_string()),
            ("input_token", "zz".repeat(16)), ("input_sha256", "zz".repeat(32))] {
            let mut fields = create_fields();
            for f in fields.iter_mut() { if f.0 == k { *f = (k, v.clone()); } }
            let line = encode_request(ID, NOW, Command::CellCreate, &fields, KEY).unwrap();
            assert_eq!(parse(&line, &mut ReplayCache::new(4)), Err(ErrorCode::BadRequest), "{}={}", k, v);
        }
    }
    #[test]
    fn responses_and_list_payload() {
        let ok = encode_ok(ID, &[("burned", "true".into())], KEY).unwrap();
        assert_eq!(parse_response(std::str::from_utf8(&ok).unwrap(), KEY).unwrap().fields["burned"], "true");
        let err = encode_err(ID, ErrorCode::ProfileUnknown, KEY).unwrap();
        let resp = parse_response(std::str::from_utf8(&err).unwrap(), KEY).unwrap();
        assert_eq!((resp.status, resp.fields["code"].as_str()), (Status::Err, "profile-unknown"));
        assert_eq!(parse_response(std::str::from_utf8(&ok).unwrap(), b"ffffffffffffffffffffffffffffffff"), Err(ErrorCode::BadMac));
        let tampered = encode_line(ID, Status::Err, b"code=evil-code", KEY).unwrap();
        assert_eq!(parse_response(std::str::from_utf8(&tampered).unwrap(), KEY), Err(ErrorCode::BadRequest));
        assert_eq!(encode_ok_raw(ID, &vec![b'x'; MAX_RESPONSE_BYTES], KEY), Err(ErrorCode::Internal));
        let rows = vec![
            vec![("uuid", "ab".repeat(16)), ("generation", "1".into()), ("state", "isolated".into())],
            vec![("uuid", "cd".repeat(16)), ("generation", "2".into()), ("state", "burned".into())],
        ];
        let payload = encode_list_payload(&rows).unwrap();
        assert!(payload.starts_with(b"count=2\n"));
        let parsed = parse_list_payload(&payload).unwrap();
        assert_eq!((parsed.len(), parsed[1]["state"].as_str()), (2, "burned"));
        assert_eq!(parse_list_payload(b"count=3\n"), Err(ErrorCode::BadRequest));
        assert_eq!(parse_response(std::str::from_utf8(&encode_ok_raw(ID, &payload, KEY).unwrap()).unwrap(), KEY).unwrap().raw_payload, payload);
        assert_eq!(request_id_or_zeros("garbage"), "0000000000000000");
        assert_eq!(request_id_or_zeros("VGTGC2\u{1f}00112233445566aa\u{1f}x"), "00112233445566aa");
    }
    #[test]
    fn peer_cred_and_scm_rights() {
        let mut fds = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) }, 0);
        assert_eq!(peer_uid(fds[0]).unwrap(), unsafe { libc::geteuid() });
        // SAFETY: memfd_create with static NUL-terminated name; fd checked.
        let memfd = unsafe { libc::syscall(libc::SYS_memfd_create, b"gd-scm-test\0".as_ptr(), 0) } as RawFd;
        assert!(memfd >= 0);
        assert_eq!(unsafe { libc::write(memfd, b"hello".as_ptr() as *const libc::c_void, 5) }, 5);
        assert_eq!(unsafe { libc::lseek(memfd, 0, libc::SEEK_SET) }, 0);
        send_fd(fds[0], memfd, b"VGTGC2R payload\n").unwrap();
        let (got_fd, data) = recv_fd(fds[1], 4096).unwrap();
        assert_eq!(data, b"VGTGC2R payload\n");
        let mut buf = [0u8; 5];
        assert_eq!(unsafe { libc::read(got_fd, buf.as_mut_ptr() as *mut libc::c_void, 5) }, 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(send_fd(fds[0], fds[0], b""), Err(ErrorCode::Internal));
        assert_eq!(send_fd(fds[0], fds[0], &vec![b'x'; MAX_RESPONSE_BYTES + 1]), Err(ErrorCode::Internal));
        unsafe { for fd in [memfd, got_fd, fds[0], fds[1]] { libc::close(fd); } }
    }
}
