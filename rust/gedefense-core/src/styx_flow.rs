//! Point 3 (Phase 1): pure STYX policy/flow helpers for the privileged core.
//! Owns the testable half of `docs/POINT3-EGRESS-BEACON.md` (§5 parsing and
//! validation, §4 LPM keys, §3.3 text wire); `main.rs` validates completely
//! before its single map write and keeps all map/ring I/O.

use gedefense_common::{
    FlowEvent, NETWORK_FAMILY_V4, NETWORK_FAMILY_V6, STYX_FLAG_ALLOW_HOST_ALLOWLIST,
    STYX_FLAG_ALLOW_METADATA, STYX_FLAG_DNS_RESOLVER, STYX_FLAG_LOG_FLOWS, STYX_MODE_ENFORCE,
    STYX_PROTO_TCP, STYX_PROTO_UDP,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Version advertised and negotiated through `STYX_VERSION` (§5).
pub const STYX_WIRE_VERSION: &str = "styx-v1";
/// §3.3 batch ceiling: 64 records per poll (was 8). The previous 8-record drain
/// could not keep the 16 MiB eBPF `FLOW_EVENTS` ring empty under burst load
/// (`FLOW_RING_DROPS`); the Go parser must be raised to the same values.
pub const MAX_STYX_FLOW_EVENTS_PER_RESPONSE: usize = 64;
/// §3.3 response payload ceiling: worst-case record is 203 bytes (16 hex cgroup
/// id, three 20-digit counters, 32 hex IPv6 bytes, 30 hex comm, separators), so
/// 64 records plus the `<dropped>|` prefix stay below 14 KiB; 16 KiB is the hard
/// bound and keeps room for the bounded status prefix.
pub const MAX_STYX_FLOW_PAYLOAD_BYTES: usize = 16 * 1024;
/// Backwards-compatible rejection for unknown or malformed command shapes (§5).
pub const UNKNOWN_COMMAND: &str = "unknown command";

pub const STYX_SCOPE_CELL: &str = "cell";
pub const STYX_SCOPE_GLOBAL: &str = "global";

/// Named per-cell flag bits of §3.1 accepted in `STYX_MODE_SET`; the mode is a
/// separate argument and must not be repeated in flags.
pub const STYX_MODE_FLAGS_KNOWN: u8 = STYX_FLAG_DNS_RESOLVER
    | STYX_FLAG_ALLOW_METADATA
    | STYX_FLAG_ALLOW_HOST_ALLOWLIST
    | STYX_FLAG_LOG_FLOWS;

/// `STYX_GLOBAL` accepts only documented bit 0 (§5), translated into the
/// internal flag byte carried by the global word (§3.1/§4).
pub const STYX_GLOBAL_FLAG_LOG_FLOWS: u8 = 1 << 0;

const MAX_CIDR_TEXT_BYTES: usize = 128;
const MAX_DECIMAL_TEXT_BYTES: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StyxScope {
    Cell,
    Global,
}

/// Family-checked, canonical policy prefix (host bits zero, network address).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StyxCidr {
    pub family: u8,
    pub address: IpAddr,
    pub prefix: u8,
}

/// Rejects fields that must never reach the MAC-packed IPC wire: empty values
/// and any whitespace or NUL byte are not part of a §5 token.
fn has_rejected_bytes(token: &str) -> bool {
    token.is_empty()
        || token.len() > MAX_CIDR_TEXT_BYTES
        || token
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_whitespace())
}

/// Strict decimal parse (ASCII digits only): `+1`, `1 `, `0x10` and NUL are
/// rejected instead of being silently accepted by the standard parser.
fn decimal(token: &str) -> Result<u64, String> {
    if token.is_empty()
        || token.len() > MAX_DECIMAL_TEXT_BYTES
        || !token.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("styx argument is not a decimal integer".to_owned());
    }
    token
        .parse::<u64>()
        .map_err(|_| "styx argument is out of range".to_owned())
}

pub fn parse_family(token: &str) -> Result<u8, String> {
    match decimal(token)? {
        4 => Ok(NETWORK_FAMILY_V4),
        6 => Ok(NETWORK_FAMILY_V6),
        _ => Err("styx family must be 4 or 6".to_owned()),
    }
}

pub fn parse_cgroup_id(token: &str) -> Result<u64, String> {
    match decimal(token)? {
        0 => Err("styx cgroup id must be non-zero".to_owned()),
        id => Ok(id),
    }
}pub fn parse_u16(token: &str) -> Result<u16, String> {
    u16::try_from(decimal(token)?).map_err(|_| "styx argument is out of range".to_owned())
}

pub fn parse_u8(token: &str) -> Result<u8, String> {
    u8::try_from(decimal(token)?).map_err(|_| "styx argument is out of range".to_owned())
}

pub fn parse_mode(token: &str) -> Result<u8, String> {
    match parse_u8(token)? {
        mode @ 0..=STYX_MODE_ENFORCE => Ok(mode),
        _ => Err("styx mode must be 0, 1 or 2".to_owned()),
    }
}

pub fn parse_mode_flags(token: &str) -> Result<u8, String> {
    match parse_u8(token)? {
        flags if flags & !STYX_MODE_FLAGS_KNOWN == 0 => Ok(flags),
        _ => Err("styx mode flags contain unknown bits".to_owned()),
    }
}

pub fn parse_global_flags(token: &str) -> Result<u8, String> {
    let flags = parse_u8(token)?;
    if flags & !STYX_GLOBAL_FLAG_LOG_FLOWS != 0 {
        return Err("styx global flags contain unknown bits".to_owned());
    }
    // IPC bit 0 (§5) -> internal flag byte (§3.1). Only LOG_FLOWS exists here.
    Ok(if flags & STYX_GLOBAL_FLAG_LOG_FLOWS != 0 { STYX_FLAG_LOG_FLOWS } else { 0 })
}

pub fn parse_scope(token: &str) -> Result<StyxScope, String> {
    match token {
        STYX_SCOPE_CELL => Ok(StyxScope::Cell),
        STYX_SCOPE_GLOBAL => Ok(StyxScope::Global),
        _ => Err("styx scope must be cell or global".to_owned()),
    }
}

/// Parses one canonical CIDR (§5): family matches, host bits are zero, the
/// prefix length is in range, IPv4-mapped IPv6 is refused (the kernel
/// normalises it to IPv4). Non-canonical input is rejected, never repaired.
pub fn parse_cidr(family: u8, token: &str) -> Result<StyxCidr, String> {
    if !matches!(family, NETWORK_FAMILY_V4 | NETWORK_FAMILY_V6) {
        return Err("styx family must be 4 or 6".to_owned());
    }
    if has_rejected_bytes(token) {
        return Err("styx cidr contains rejected characters".to_owned());
    }
    let (text, raw_prefix) = match token.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (token, None),
    };
    let max_bits: u8 = if family == NETWORK_FAMILY_V4 { 32 } else { 128 };
    let prefix = match raw_prefix {
        Some(prefix) => {
            let value = decimal(prefix)?;
            if value > u64::from(max_bits) {
                return Err("styx cidr prefix length is out of range".to_owned());
            }
            value as u8
        }
        None => max_bits,
    };
    if family == NETWORK_FAMILY_V4 {
        let address = text
            .parse::<Ipv4Addr>()
            .map_err(|_| "styx cidr address is invalid".to_owned())?;
        let bits = u32::from(address);
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        if bits & !mask != 0 {
            return Err("styx cidr is not canonical".to_owned());
        }
        return Ok(StyxCidr { family, address: IpAddr::V4(Ipv4Addr::from(bits & mask)), prefix });
    }
    let address = text
        .parse::<Ipv6Addr>()
        .map_err(|_| "styx cidr address is invalid".to_owned())?;
    if address.to_ipv4_mapped().is_some() {
        return Err("styx cidr must not be an IPv4-mapped IPv6 address".to_owned());
    }
    let bits = u128::from(address);
    let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    if bits & !mask != 0 {
        return Err("styx cidr is not canonical".to_owned());
    }
    Ok(StyxCidr { family, address: IpAddr::V6(Ipv6Addr::from(bits & mask)), prefix })
}

/// Block/resolver entries are bare IP prefixes in the §4 length domain
/// (4..=32 for IPv4, 8..=128 for IPv6).
pub fn parse_prefix_cidr(family: u8, token: &str) -> Result<StyxCidr, String> {
    let cidr = parse_cidr(family, token)?;
    let min_prefix = if cidr.family == NETWORK_FAMILY_V4 { 4 } else { 8 };
    if cidr.prefix < min_prefix {
        return Err("styx prefix length is out of range (4..=32 or 8..=128)".to_owned());
    }
    Ok(cidr)
}

pub fn parse_port_range(lo: &str, hi: &str) -> Result<(u16, u16), String> {
    let (lo, hi) = (parse_u16(lo)?, parse_u16(hi)?);
    if lo > hi {
        return Err("styx port range is inverted".to_owned());
    }
    Ok((lo, hi))
}

pub fn parse_proto_mask(token: &str) -> Result<u8, String> {
    let mask = parse_u8(token)?;
    if mask > 3 {
        return Err("styx proto mask must be 0..=3".to_owned());
    }
    Ok(mask)
}

/// Validated `STYX_GLOBAL` request; `flags` is already the internal flag byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StyxGlobalRequest {
    pub mode: u8,
    pub flags: u8,
}

pub fn parse_global_request(args: &[&str]) -> Result<StyxGlobalRequest, String> {
    let [mode, flags] = args else {
        return Err(UNKNOWN_COMMAND.to_owned());
    };
    Ok(StyxGlobalRequest {
        mode: parse_mode(mode)?,
        flags: parse_global_flags(flags)?,
    })
}
/// Validated `STYX_MODE_SET` request: `(cgroup_id, mode, flags)`.
pub fn parse_mode_set_request(args: &[&str]) -> Result<(u64, u8, u8), String> {
    let [cgroup_id, mode, flags] = args else {
        return Err(UNKNOWN_COMMAND.to_owned());
    };
    Ok((
        parse_cgroup_id(cgroup_id)?,
        parse_mode(mode)?,
        parse_mode_flags(flags)?,
    ))
}

pub fn parse_mode_del_request(args: &[&str]) -> Result<u64, String> {
    let [cgroup_id] = args else {
        return Err(UNKNOWN_COMMAND.to_owned());
    };
    parse_cgroup_id(cgroup_id)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StyxAllowRequest {
    pub family: u8,
    pub scope: StyxScope,
    pub cgroup_id: u64,
    pub cidr: StyxCidr,
    pub port_lo: u16,
    pub port_hi: u16,
    pub proto_mask: u8,
}

pub fn parse_allow_request(args: &[&str]) -> Result<StyxAllowRequest, String> {
    let [family, scope, cgroup_id, cidr, port_lo, port_hi, proto_mask] = args else {
        return Err(UNKNOWN_COMMAND.to_owned());
    };
    let family = parse_family(family)?;
    let scope = parse_scope(scope)?;
    let cgroup_id = match (scope, decimal(cgroup_id)?) {
        (StyxScope::Cell, 0) => return Err("styx cell scope requires a cgroup id".to_owned()),
        (StyxScope::Global, id) if id != 0 => {
            return Err("styx global scope must not carry a cgroup id".to_owned())
        }
        (StyxScope::Global, _) => 0,
        (StyxScope::Cell, id) => id,
    };
    let cidr = parse_cidr(family, cidr)?;
    let (port_lo, port_hi) = parse_port_range(port_lo, port_hi)?;
    let proto_mask = parse_proto_mask(proto_mask)?;
    Ok(StyxAllowRequest {
        family,
        scope,
        cgroup_id,
        cidr,
        port_lo,
        port_hi,
        proto_mask,
    })
}
/// Block and resolver commands share one shape: `family`, `cidr`.
pub fn parse_prefix_request(args: &[&str]) -> Result<StyxCidr, String> {
    let [family, cidr] = args else {
        return Err(UNKNOWN_COMMAND.to_owned());
    };
    parse_prefix_cidr(parse_family(family)?, cidr)
}

/// §4 LPM key plus prefix length for one allow rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StyxAllowKey {
    CellV4([u8; 16], u32),
    CellV6([u8; 24], u32),
    GlobalV4([u8; 8], u32),
    GlobalV6([u8; 20], u32),
}

/// §4 block/resolver key: the bare address with the CIDR prefix length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StyxPrefixKey {
    V4([u8; 4], u32),
    V6([u8; 16], u32),
}

impl StyxCidr {
    pub fn prefix_key(&self) -> Result<StyxPrefixKey, String> {
        match (self.family, self.address) {
            (NETWORK_FAMILY_V4, IpAddr::V4(address)) => Ok(StyxPrefixKey::V4(
                address.octets(),
                u32::from(self.prefix),
            )),
            (NETWORK_FAMILY_V6, IpAddr::V6(address)) => Ok(StyxPrefixKey::V6(
                address.octets(),
                u32::from(self.prefix),
            )),
            _ => Err("styx cidr family mismatch".to_owned()),
        }
    }
}

fn v4_bytes(cidr: &StyxCidr) -> Result<[u8; 4], String> {
    match cidr.address {
        IpAddr::V4(address) => Ok(address.octets()),
        IpAddr::V6(_) => Err("styx cidr family mismatch".to_owned()),
    }
}

fn v6_bytes(cidr: &StyxCidr) -> Result<[u8; 16], String> {
    match cidr.address {
        IpAddr::V6(address) => Ok(address.octets()),
        IpAddr::V4(_) => Err("styx cidr family mismatch".to_owned()),
    }
}

struct PortProto {
    port: Option<u16>,
    proto: Option<u8>,
}

/// Maps the §5 port range / proto mask onto the only two LPM encodings §4
/// defines (none, exact port after a full address, exact protocol after that
/// port). Anything else would silently widen or narrow the rule: refused.
fn port_proto(
    cidr: &StyxCidr,
    port_lo: u16,
    port_hi: u16,
    proto_mask: u8,
    full_bits: u8,
) -> Result<PortProto, String> {
    let port = if port_lo == 0 && port_hi == u16::MAX {
        None
    } else if port_lo == port_hi {
        if cidr.prefix != full_bits {
            return Err("styx port rule requires a full-length cidr".to_owned());
        }
        Some(port_lo)
    } else {
        return Err("styx port range must be a single port or 0-65535".to_owned());
    };
    let proto = match proto_mask {
        0 | 3 => None,
        1 => Some(STYX_PROTO_TCP),
        2 => Some(STYX_PROTO_UDP),
        _ => return Err("styx proto mask must be 0..=3".to_owned()),
    };
    if proto.is_some() && port.is_none() {
        return Err("styx proto rule requires an exact port".to_owned());
    }
    Ok(PortProto { port, proto })
}

/// Appends the optional port/proto bytes at their §4 offsets.
fn apply_restriction(key: &mut [u8], at: (usize, usize), prefix: &mut u32, r: &PortProto) {
    if let Some(port) = r.port {
        key[at.0..at.0 + 2].copy_from_slice(&port.to_be_bytes());
        *prefix += 16;
    }
    if let Some(proto) = r.proto {
        key[at.1] = proto;
        *prefix += 8;
    }
}

impl StyxAllowRequest {
    /// Builds the map key and prefix length exactly per §4.
    pub fn allow_key(&self) -> Result<StyxAllowKey, String> {
        if self.cidr.family != self.family {
            return Err("styx cidr family mismatch".to_owned());
        }
        let full_bits: u8 = if self.family == NETWORK_FAMILY_V4 { 32 } else { 128 };
        if self.scope == StyxScope::Cell && self.cgroup_id == 0 {
            return Err("styx cell scope requires a cgroup id".to_owned());
        }
        if self.scope == StyxScope::Cell && self.family == NETWORK_FAMILY_V6 {
            // §4 Phase-1 limit: the cell-v6 key has no port/proto slot, so a
            // port/proto rule is installed as the documented CIDR-only rule.
            let mut key = [0u8; 24];
            key[..8].copy_from_slice(&self.cgroup_id.to_le_bytes());
            key[8..].copy_from_slice(&v6_bytes(&self.cidr)?);
            return Ok(StyxAllowKey::CellV6(key, 64 + u32::from(self.cidr.prefix)));
        }
        let restriction = port_proto(
            &self.cidr,
            self.port_lo,
            self.port_hi,
            self.proto_mask,
            full_bits,
        )?;
        match (self.scope, self.family) {
            (StyxScope::Cell, NETWORK_FAMILY_V4) => {
                let mut key = [0u8; 16];
                key[..8].copy_from_slice(&self.cgroup_id.to_le_bytes());
                key[8..12].copy_from_slice(&v4_bytes(&self.cidr)?);
                let mut prefix = 64 + u32::from(self.cidr.prefix);
                apply_restriction(&mut key, (12, 14), &mut prefix, &restriction);
                Ok(StyxAllowKey::CellV4(key, prefix))
            }
            (StyxScope::Global, NETWORK_FAMILY_V4) => {
                let mut key = [0u8; 8];
                key[..4].copy_from_slice(&v4_bytes(&self.cidr)?);
                let mut prefix = u32::from(self.cidr.prefix);
                apply_restriction(&mut key, (4, 6), &mut prefix, &restriction);
                Ok(StyxAllowKey::GlobalV4(key, prefix))
            }
            (StyxScope::Global, NETWORK_FAMILY_V6) => {
                let mut key = [0u8; 20];
                key[..16].copy_from_slice(&v6_bytes(&self.cidr)?);
                let mut prefix = u32::from(self.cidr.prefix);
                apply_restriction(&mut key, (16, 18), &mut prefix, &restriction);
                Ok(StyxAllowKey::GlobalV6(key, prefix))
            }
            _ => Err("styx allow scope/family combination is invalid".to_owned()),
        }
    }
}
/// §4 `STYX_GLOBAL` word: `epoch (low 32) | flags << 32 | mode << 40`.
pub fn encode_styx_global(epoch: u32, mode: u8, flags: u8) -> u64 {
    debug_assert!(mode <= STYX_MODE_ENFORCE);
    u64::from(epoch) | (u64::from(flags) << 32) | (u64::from(mode) << 40)
}

/// §3.3 text record with the fixed 16-field order.
///
/// `None` means no representable text form exists (PID above signed `pid_t`,
/// unspecified IPv6 destination) and the Go parser would reject the batch. A
/// `comm` with bytes the Go decoder refuses (control, DEL, space) is
/// informational only and degrades to "empty" instead of losing the flow.
pub fn encode_styx_flow_event_text(event: &FlowEvent) -> Option<String> {
    if event.pid > i32::MAX as u32 {
        return None;
    }
    let destination = match event.family {
        NETWORK_FAMILY_V4 => &event.dst[12..16],
        NETWORK_FAMILY_V6 => {
            if event.dst.iter().all(|byte| *byte == 0) {
                return None;
            }
            &event.dst[..16]
        }
        _ => return None,
    };
    let comm_end = event.comm.iter().position(|byte| *byte == 0)?;
    let comm = &event.comm[..comm_end];
    let comm_hex = if comm
        .iter()
        .any(|byte| *byte < 0x20 || *byte == 0x7f || *byte == b' ')
    {
        String::new()
    } else {
        hex::encode(comm)
    };
    Some(format!(
        "{:016x}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        event.cgroup_id,
        event.ts_ns,
        event.tx_bytes,
        event.rx_bytes,
        event.pid,
        event.uid,
        hex::encode(destination),
        event.dst_port,
        event.src_port,
        event.packets,
        event.family,
        event.proto,
        event.direction,
        event.tcp_flags,
        event.verdict,
        comm_hex
    ))
}
/// §5 `STYX_FLOW_HEALTH`: six decimal fields in fixed order.
pub fn encode_styx_flow_health(c: &[u64; 6]) -> String {
    format!("{}:{}:{}:{}:{}:{}", c[0], c[1], c[2], c[3], c[4], c[5])
}
