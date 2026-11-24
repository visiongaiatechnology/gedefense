use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_get_socket_uid, bpf_ktime_get_ns, bpf_skb_ancestor_cgroup_id, bpf_skb_cgroup_id,
    },
    macros::cgroup_skb,
    maps::{lpm_trie::Key, LruPerCpuHashMap},
    programs::SkBuffContext,
    EbpfContext,
};
use core::mem;
use gedefense_common::{
    ACTION_DROP, EgressDropEvent, FlowEvent, LOCKDOWN_FLAG_ALLOW_LOOPBACK, LOCKDOWN_FLAG_DROP_ALL,
    NETWORK_ADDRESS_BYTES, NETWORK_FAMILY_V4, NETWORK_FAMILY_V6, NETWORK_PROTOCOL_TCP,
    STYX_DIR_EGRESS, STYX_FLAG_ALLOW_HOST_ALLOWLIST, STYX_FLAG_ALLOW_METADATA,
    STYX_FLAG_DNS_RESOLVER, STYX_FLAG_LOG_FLOWS, STYX_MODE_ENFORCE, STYX_MODE_MASK,
    STYX_MODE_MONITOR, STYX_MODE_OFF, STYX_PROTO_TCP, STYX_PROTO_UNKNOWN, STYX_PROTO_UDP,
    STYX_VERDICT_ALLOW, STYX_VERDICT_AUDIT_DROP, STYX_VERDICT_DEFAULT_DENY,
    STYX_VERDICT_DNS_PIN, STYX_VERDICT_DROP, STYX_VERDICT_METADATA_VETO, EXEC_COMM_BYTES,
};
use crate::ingress_xdp::lockdown_flags;
use crate::maps::{
    ALLOWLIST_V4, ALLOWLIST_V6, BLOCKLIST_V4, BLOCKLIST_V6, CELL_EGRESS_ALLOW_V4,
    CELL_EGRESS_ALLOW_V6, CELL_EGRESS_MODE, EGRESS_DROPS_TOTAL, EGRESS_EVENTS, EGRESS_PARSE_ERRORS,
    EGRESS_POLICY_DROPS, FLOW_AGG_INSERT_FAILURES, FLOW_AGG_V4, FLOW_AGG_V6, FLOW_EVENTS,
    FLOW_EVENTS_EMITTED, FLOW_RING_DROPS, LOCKDOWN_DROPS, LOCKDOWN_WITNESS_PASSES, STYX_ALLOW_GLOBAL_V4,
    STYX_ALLOW_GLOBAL_V6, STYX_BLOCK_V4, STYX_BLOCK_V6, STYX_GLOBAL, STYX_RESOLVED,
    STYX_RESOLVER_V4, STYX_RESOLVER_V6,
};
use crate::net_parse::{Ipv4Hdr, Ipv6Hdr, TcpPrefix, UdpPrefix};
use crate::util::{increment_counter, MAX_CGROUP_ANCESTOR_LEVELS, NS_PER_SECOND};

// ---------------------------------------------------------------------------
// Point 3 (Phase 1): per-cgroup egress enforcement and flow telemetry.
//
// Contract: docs/POINT3-EGRESS-BEACON.md §3.1/§3.2 (FlowEvent wire record),
// §4 (map ABI) and §6 (ordered decision pipeline). The map names, key/value
// byte layouts, max_entries and flags below are ABI-2 and are looked up by
// name from rust/gedefense-core; do not rename or reshape them.
// ---------------------------------------------------------------------------

/// Index of the single global mode word in `STYX_GLOBAL`.
const STYX_GLOBAL_INDEX: u32 = 0;
/// `u64 = epoch(low 32) | flags << 32 | mode << 40` (§4), see §3.1 for the bits.
const STYX_GLOBAL_FLAGS_SHIFT: u64 = 32;
const STYX_GLOBAL_MODE_SHIFT: u64 = 40;
const STYX_GLOBAL_MODE_MASK: u64 = 0x07;
const STYX_GLOBAL_FLAGS_MASK: u64 = 0xff;

/// Bounded parser limit for IPv6 extension headers before the L4 header (§6.8).
const IPV6_EXT_HEADER_HOPS: u8 = 4;
const IPV6_PROTOCOL_ICMPV6: u8 = 58;
const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;
const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;
const DNS_TRANSPORT_PORT: u16 = 53;
const DOT_TRANSPORT_PORT: u16 = 853;

/// Flow aggregation emission thresholds (§6.5). The aggregation window is reset
/// after every emission, so the emitted `packets`/`tx_bytes` are deltas since
/// the previous event (or since the first packet of the flow).
const FLOW_EMIT_BYTES: u64 = 64 * 1024;
const FLOW_EMIT_PACKETS: u32 = 256;

/// Offset of the aggregation value fields inside the fixed `[u8; 40]` value (§4):
/// [first_ts 8][last_ts 8][tx 8][packets 4][pid 4][tcp_flags 1][verdict 1][pad 6].
const FLOW_AGG_FIRST_TS: usize = 0;
const FLOW_AGG_LAST_TS: usize = 8;
const FLOW_AGG_TX: usize = 16;
const FLOW_AGG_PACKETS: usize = 24;
const FLOW_AGG_PID: usize = 28;
const FLOW_AGG_TCP_FLAGS: usize = 32;
const FLOW_AGG_VERDICT: usize = 33;

/// §4 cgroup-egress fastpath: `Some(0)` = DROP, `Some(1)` = PASS because of
/// the `ALLOW_LOOPBACK` exception, `None` = no active lockdown (legacy path).
/// A packet whose fixed L3 header cannot be read is DROPped while locked down
/// (fail-closed, §4); only a proven loopback packet may pass.
#[inline(always)]
fn lockdown_egress_verdict(ctx: &SkBuffContext) -> Option<i32> {
    let flags = lockdown_flags()?;
    if (flags & LOCKDOWN_FLAG_DROP_ALL) == 0 {
        return None;
    }
    if (flags & LOCKDOWN_FLAG_ALLOW_LOOPBACK) != 0 && lockdown_loopback_packet(ctx) == Some(true) {
        increment_counter(&LOCKDOWN_WITNESS_PASSES);
        return Some(1);
    }
    increment_counter(&LOCKDOWN_DROPS);
    Some(0)
}

/// Minimal L3 loopback proof for §4 `ALLOW_LOOPBACK`: `127.0.0.0/8` and `::1`
/// on both endpoints (a non-loopback source cannot tunnel through the
/// exception). `None` = truncated/unparseable header. Kept as a BPF subprogram
/// (`#[inline(never)]`) so the 2x16/2x4 address temporaries own their own
/// stack frame instead of the hot path (512-byte eBPF stack limit).
#[inline(never)]
fn lockdown_loopback_packet(ctx: &SkBuffContext) -> Option<bool> {
    let version: u8 = ctx.load(0).ok()?;
    match version >> 4 {
        NETWORK_FAMILY_V4 => {
            let src: [u8; 4] = ctx.load(12).ok()?;
            let dst: [u8; 4] = ctx.load(16).ok()?;
            Some(src[0] == 127 && dst[0] == 127)
        }
        NETWORK_FAMILY_V6 => {
            let src: [u8; 16] = ctx.load(8).ok()?;
            let dst: [u8; 16] = ctx.load(24).ok()?;
            Some(ipv6_loopback(&src) && ipv6_loopback(&dst))
        }
        _ => None,
    }
}

/// True for the IPv6 loopback address `::1`.
#[inline(always)]
fn ipv6_loopback(address: &[u8; 16]) -> bool {
    let mut index = 0usize;
    while index < 15 {
        if address[index] != 0 {
            return false;
        }
        index += 1;
    }
    address[15] == 1
}

#[cgroup_skb(egress)]
pub fn gedefense_egress(ctx: SkBuffContext) -> i32 {
    // Point 5 (§4): lockdown precedes the Point-3 STYX_GLOBAL lookup and every
    // other egress decision. Only a proven loopback packet may pass while
    // ALLOW_LOOPBACK is set; everything else (including parse failures) drops.
    if let Some(verdict) = lockdown_egress_verdict(&ctx) {
        return verdict;
    }
    match inspect_egress(&ctx) {
        // 0 = DROP, 1 = PASS (pre-existing return contract, §6.11).
        Ok(true) => 0,
        Ok(false) | Err(()) => 1,
    }
}

/// Ordered Point-3 egress pipeline (§6). `Ok(true)` means DROP, `Ok(false)`
/// means PASS. `Err(())` is only produced by the byte-identical 5.2.0 fallback
/// path for malformed L3 frames (PASS, as before).
#[inline(always)]
fn inspect_egress(ctx: &SkBuffContext) -> Result<bool, ()> {
    // §6.1: one array lookup on the hot path. A missing global word means the
    // core has not initialised Point 3, so behave exactly like 5.2.0.
    let global = match STYX_GLOBAL.get(STYX_GLOBAL_INDEX) {
        Some(value) => *value,
        None => return legacy_inspect_egress(ctx),
    };
    let global_mode = decode_global_mode(global);
    let global_flags = decode_global_flags(global);
    if global_mode == STYX_MODE_OFF && (global_flags & STYX_FLAG_LOG_FLOWS) == 0 {
        // Default deployment after upgrade: byte-identical 5.2.0 verdicts, no
        // IPv4-mapped normalisation, no flow telemetry, no new counters. The
        // only added cost is the array lookup above (§12).
        return legacy_inspect_egress(ctx);
    }
    let epoch = (global & u64::from(u32::MAX)) as u32;

    // §6.2: L3 parse. A malformed frame is only dropped when the resolved scope
    // enforces; otherwise it stays on the pre-existing PASS path.
    let mut packet = EgressPacket::zeroed();
    if !parse_egress_packet(ctx, &mut packet) {
        increment_counter(&EGRESS_PARSE_ERRORS);
        let scope = resolve_egress_scope(ctx, epoch);
        let (mode, _flags) = scope_mode_flags(&scope, global_mode, global_flags);
        if mode == STYX_MODE_ENFORCE {
            increment_counter(&EGRESS_DROPS_TOTAL);
            return Ok(true);
        }
        return Ok(false);
    }

    // §6.3/§6.4: IPv4-mapped/compatible normalisation happened in the parser;
    // attribute the skb to its enforcing cgroup scope (bounded ancestor walk).
    let scope = resolve_egress_scope(ctx, epoch);
    let (mode, flags) = scope_mode_flags(&scope, global_mode, global_flags);
    // §6.7-§6.10: mandatory veto, DNS pinning, allow order, default verdict.
    let decision = evaluate_egress_policy(&packet, &scope, mode, flags, global_flags);

    // §6.5: aggregate per flow and emit bounded FlowEvents - never one event per
    // packet. Telemetry is on when the cgroup (or global scope) logs flows, and
    // always in monitor/enforce mode.
    if (flags & STYX_FLAG_LOG_FLOWS) != 0
        || (global_flags & STYX_FLAG_LOG_FLOWS) != 0
        || mode >= STYX_MODE_MONITOR
    {
        observe_flow(ctx, &packet, scope.cell_cgroup, decision.verdict);
    }

    if decision.drop {
        increment_counter(&EGRESS_DROPS_TOTAL);
        if decision.policy_drop {
            increment_counter(&EGRESS_POLICY_DROPS);
        }
        return Ok(true);
    }
    Ok(false)
}

/// 5.2.0 egress verdict path, kept byte-identical for the default `off` state:
/// allowlist PASS, threat-intel blocklist DROP (with the existing event), else PASS.
/// Kept as a BPF subprogram (`#[inline(never)]`) for stack-frame separation.
#[inline(never)]
fn legacy_inspect_egress(ctx: &SkBuffContext) -> Result<bool, ()> {
    let version: u8 = ctx.load(0).map_err(|_| ())?;
    match version >> 4 {
        NETWORK_FAMILY_V4 => inspect_egress_v4(ctx),
        NETWORK_FAMILY_V6 => inspect_egress_v6(ctx),
        _ => Err(()),
    }
}

#[inline(always)]
fn decode_global_mode(global: u64) -> u8 {
    ((global >> STYX_GLOBAL_MODE_SHIFT) & STYX_GLOBAL_MODE_MASK) as u8
}

#[inline(always)]
fn decode_global_flags(global: u64) -> u8 {
    ((global >> STYX_GLOBAL_FLAGS_SHIFT) & STYX_GLOBAL_FLAGS_MASK) as u8
}

/// Enforcing cgroup scope of one skb (§6.4).
#[derive(Clone, Copy)]
struct EgressScope {
    /// First ancestor with a cell policy, or the skb cgroup when no cell policy
    /// matched (then the global mode applies). 0 = no cgroup at all.
    cell_cgroup: u64,
    /// Raw `CELL_EGRESS_MODE` byte (mode in bits 0..2, flags above); `None`
    /// means the global default applies.
    mode_flags: Option<u8>,
}

#[inline(always)]
fn scope_mode_flags(scope: &EgressScope, global_mode: u8, global_flags: u8) -> (u8, u8) {
    match scope.mode_flags {
        Some(raw) => (raw & STYX_MODE_MASK, raw & !STYX_MODE_MASK),
        None => (global_mode, global_flags),
    }
}

/// §6.4: attribute an skb to its enforcing cgroup scope. Positive results are
/// cached in `STYX_RESOLVED` per skb cgroup together with the core epoch. The
/// resolution walk is bounded to level 0..63 like the existing LSM ancestor
/// walk. Negative results are deliberately not cached: a cell policy installed
/// on an existing ancestor must take effect immediately instead of after the
/// next core restart (the walk is bounded by the real cgroup depth, the kernel
/// returns 0 for levels below the current cgroup).
///
/// Kept as a BPF subprogram (`#[inline(never)]`): the cgroup-attribution state
/// and the LPM key temporaries must not share the hot-path stack frame of the
/// event emission, otherwise the 512-byte eBPF stack limit is exceeded.
#[inline(never)]
fn resolve_egress_scope(ctx: &SkBuffContext, epoch: u32) -> EgressScope {
    let skb_cgroup = unsafe { bpf_skb_cgroup_id(ctx.as_ptr().cast()) };
    if skb_cgroup == 0 {
        return EgressScope { cell_cgroup: 0, mode_flags: None };
    }
    if let Some(cached) = unsafe { STYX_RESOLVED.get(&skb_cgroup) } {
        let cached_epoch = u32::from_le_bytes([cached[8], cached[9], cached[10], cached[11]]);
        if cached_epoch == epoch {
            let cell = u64::from_le_bytes([
                cached[0], cached[1], cached[2], cached[3], cached[4], cached[5], cached[6],
                cached[7],
            ]);
            if let Some(mode_flags) = unsafe { CELL_EGRESS_MODE.get(&cell) } {
                // Re-read the mode byte so STYX_MODE_SET/DEL takes effect for
                // already-cached cgroups without waiting for an epoch change.
                return EgressScope { cell_cgroup: cell, mode_flags: Some(*mode_flags) };
            }
        }
    }
    let mut level: i32 = 0;
    while level < MAX_CGROUP_ANCESTOR_LEVELS {
        let ancestor = unsafe { bpf_skb_ancestor_cgroup_id(ctx.as_ptr().cast(), level) };
        if ancestor == 0 {
            break;
        }
        if let Some(mode_flags) = unsafe { CELL_EGRESS_MODE.get(&ancestor) } {
            cache_egress_resolution(skb_cgroup, ancestor, epoch, *mode_flags);
            return EgressScope { cell_cgroup: ancestor, mode_flags: Some(*mode_flags) };
        }
        level += 1;
    }
    EgressScope { cell_cgroup: skb_cgroup, mode_flags: None }
}

#[inline(always)]
fn cache_egress_resolution(skb_cgroup: u64, cell_cgroup: u64, epoch: u32, mode_flags: u8) {
    // §4 value layout: [cell_cgroup LE 8][epoch LE 4][mode+flags 2][pad 2].
    let mut cached = [0u8; 16];
    cached[0..8].copy_from_slice(&cell_cgroup.to_le_bytes());
    cached[8..12].copy_from_slice(&epoch.to_le_bytes());
    cached[12] = mode_flags & STYX_MODE_MASK;
    cached[13] = mode_flags & !STYX_MODE_MASK;
    // Cache pressure only costs the next packet one bounded walk; ABI-2 has no
    // dedicated health counter for a failed resolve-cache insertion.
    let _ = STYX_RESOLVED.insert(&skb_cgroup, &cached, 0);
}

/// L3/L4 metadata of one egress packet, normalised for policy evaluation.
#[derive(Clone, Copy)]
pub(crate) struct EgressPacket {
    /// 4 or 6. IPv4-mapped/compatible IPv6 destinations are normalised to 4.
    pub(crate) family: u8,
    /// Wire protocol marker for FlowEvent (0/6/17).
    pub(crate) proto: u8,
    /// Actual L4 protocol byte (6/17/1/58/..., 0 when an extension-header chain
    /// was cut by the bound).
    pub(crate) protocol: u8,
    /// Canonical address: IPv4 in the last four bytes, first twelve zero.
    pub(crate) src: [u8; NETWORK_ADDRESS_BYTES],
    pub(crate) dst: [u8; NETWORK_ADDRESS_BYTES],
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) tcp_flags: u8,
    pub(crate) icmpv6_type: u8,
    pub(crate) packet_len: u32,
}

impl EgressPacket {
    pub(crate) const fn zeroed() -> Self {
        Self {
            family: 0,
            proto: 0,
            protocol: 0,
            src: [0u8; NETWORK_ADDRESS_BYTES],
            dst: [0u8; NETWORK_ADDRESS_BYTES],
            src_port: 0,
            dst_port: 0,
            tcp_flags: 0,
            icmpv6_type: 0,
            packet_len: 0,
        }
    }
}

/// Inlined dispatcher into the v4/v6 subprograms so it adds neither a stack
/// frame nor an `Option<EgressPacket>` return buffer (`parse_egress_v4`/`_v6`
/// write directly into `out`, staying well below the 512-byte BPF stack limit).
#[inline(always)]
pub(crate) fn parse_egress_packet(ctx: &SkBuffContext, out: &mut EgressPacket) -> bool {
    let Ok(version) = ctx.load::<u8>(0) else {
        return false;
    };
    match version >> 4 {
        NETWORK_FAMILY_V4 => parse_egress_v4(ctx, out),
        NETWORK_FAMILY_V6 => parse_egress_v6(ctx, out),
        _ => false,
    }
}

/// Kept as a BPF subprogram (`#[inline(never)]`) so the IPv4 header/temporary
/// stack objects do not join the IPv6 parser or hot-path frames.
#[inline(never)]
fn parse_egress_v4(ctx: &SkBuffContext, out: &mut EgressPacket) -> bool {
    let Ok(header) = ctx.load::<Ipv4Hdr>(0) else {
        return false;
    };
    if header.version_ihl >> 4 != NETWORK_FAMILY_V4 || header.version_ihl & 0x0f < 5 {
        return false;
    }
    let transport_offset = usize::from(header.version_ihl & 0x0f) * 4;
    // Non-first fragments carry no L4 header: IP policy only (§6.8).
    let fragment_offset = u16::from_be_bytes(header.frag) & 0x1fff;
    let (src_port, dst_port, tcp_flags) = if fragment_offset == 0 {
        skb_transport_metadata(ctx, transport_offset, header.protocol)
    } else {
        (0, 0, 0)
    };
    let proto = if fragment_offset == 0 {
        wire_protocol(header.protocol)
    } else {
        STYX_PROTO_UNKNOWN
    };
    out.family = NETWORK_FAMILY_V4;
    out.proto = proto;
    out.protocol = header.protocol;
    out.src = canonical_ipv4(header.src);
    out.dst = canonical_ipv4(header.dst);
    out.src_port = src_port;
    out.dst_port = dst_port;
    out.tcp_flags = tcp_flags;
    out.icmpv6_type = 0;
    out.packet_len = ctx.len();
    true
}

/// Kept as a BPF subprogram (`#[inline(never)]`): writes directly into `out` to
/// avoid keeping a 40-byte `Ipv6Hdr`, scratch addresses, and a `sret` return
/// buffer live across subprogram calls on the 512-byte eBPF stack.
#[inline(never)]
fn parse_egress_v6(ctx: &SkBuffContext, out: &mut EgressPacket) -> bool {
    let Ok(version_flow) = ctx.load::<[u8; 4]>(0) else {
        return false;
    };
    if u32::from_be_bytes(version_flow) >> 28 != u32::from(NETWORK_FAMILY_V6) {
        return false;
    }
    let Ok(mut next_header) = ctx.load::<u8>(6) else {
        return false;
    };
    let Ok(src) = ctx.load::<[u8; NETWORK_ADDRESS_BYTES]>(8) else {
        return false;
    };
    let Ok(dst) = ctx.load::<[u8; NETWORK_ADDRESS_BYTES]>(24) else {
        return false;
    };
    out.src = src;
    out.dst = dst;
    // §6.8: walk at most `IPV6_EXT_HEADER_HOPS` extension headers. The transport
    // offset stays a bounded constant expression; malformed/truncated headers
    // fail the bounded `ctx.load` and abort the parse (fail closed in enforce).
    let mut transport_offset = mem::size_of::<Ipv6Hdr>();
    let mut hops: u8 = 0;
    let mut fragmented = false;
    let mut transport_known = true;
    loop {
        let next = next_header;
        let header_len = match next {
            // Hop-by-Hop Options, Routing, Destination Options: (len + 1) * 8.
            0 | 43 | 60 => {
                if hops >= IPV6_EXT_HEADER_HOPS {
                    transport_known = false;
                    break;
                }
                let Ok(following) = ctx.load::<u8>(transport_offset) else {
                    return false;
                };
                let Ok(length) = ctx.load::<u8>(transport_offset + 1) else {
                    return false;
                };
                next_header = following;
                (usize::from(length) + 1) * 8
            }
            // Authentication Header: (len + 2) * 4.
            51 => {
                if hops >= IPV6_EXT_HEADER_HOPS {
                    transport_known = false;
                    break;
                }
                let Ok(following) = ctx.load::<u8>(transport_offset) else {
                    return false;
                };
                let Ok(length) = ctx.load::<u8>(transport_offset + 1) else {
                    return false;
                };
                next_header = following;
                (usize::from(length) + 2) * 4
            }
            // Fragment header: fixed eight bytes. A non-zero fragment offset has
            // no L4 header, so only the IP policy applies.
            44 => {
                if hops >= IPV6_EXT_HEADER_HOPS {
                    transport_known = false;
                    break;
                }
                let Ok(following) = ctx.load::<u8>(transport_offset) else {
                    return false;
                };
                let Ok(fragment) = ctx.load::<[u8; 2]>(transport_offset + 2) else {
                    return false;
                };
                if u16::from_be_bytes(fragment) & 0xfff8 != 0 {
                    fragmented = true;
                }
                next_header = following;
                8
            }
            _ => break,
        };
        let Some(next_offset) = transport_offset.checked_add(header_len) else {
            return false;
        };
        transport_offset = next_offset;
        hops += 1;
    }
    let protocol = if transport_known { next_header } else { 0 };
    let (src_port, dst_port, tcp_flags, icmpv6_type) = if transport_known && !fragmented {
        let (src_port, dst_port, tcp_flags) =
            skb_transport_metadata(ctx, transport_offset, protocol);
        let icmpv6_type = if protocol == IPV6_PROTOCOL_ICMPV6 {
            ctx.load::<u8>(transport_offset).ok().unwrap_or(0)
        } else {
            0
        };
        (src_port, dst_port, tcp_flags, icmpv6_type)
    } else {
        (0, 0, 0, 0)
    };
    let mut family = NETWORK_FAMILY_V6;
    let mut embedded_dst = [0u8; 4];
    if embedded_ipv4(&out.dst, &mut embedded_dst) {
        family = NETWORK_FAMILY_V4;
        out.dst = canonical_ipv4(embedded_dst);
        let mut embedded_src = [0u8; 4];
        out.src = if embedded_ipv4(&out.src, &mut embedded_src) {
            canonical_ipv4(embedded_src)
        } else {
            [0u8; NETWORK_ADDRESS_BYTES]
        };
    }
    let proto = if fragmented {
        STYX_PROTO_UNKNOWN
    } else {
        wire_protocol(protocol)
    };
    out.family = family;
    out.proto = proto;
    out.protocol = protocol;
    out.src_port = src_port;
    out.dst_port = dst_port;
    out.tcp_flags = tcp_flags;
    out.icmpv6_type = icmpv6_type;
    out.packet_len = ctx.len();
    true
}

/// Kept as a BPF subprogram (`#[inline(never)]`): its header-prefix loads would
/// otherwise grow the IPv6 parser frame, and three arguments fit the BPF
/// subprogram ABI.
#[inline(never)]
fn skb_transport_metadata(ctx: &SkBuffContext, offset: usize, protocol: u8) -> (u16, u16, u8) {
    if protocol == NETWORK_PROTOCOL_TCP {
        if let Ok(tcp) = ctx.load::<TcpPrefix>(offset) {
            return (
                u16::from_be_bytes(tcp.src_port),
                u16::from_be_bytes(tcp.dst_port),
                tcp.flags,
            );
        }
    } else if protocol == STYX_PROTO_UDP {
        if let Ok(udp) = ctx.load::<UdpPrefix>(offset) {
            return (
                u16::from_be_bytes(udp.src_port),
                u16::from_be_bytes(udp.dst_port),
                0,
            );
        }
    }
    (0, 0, 0)
}

/// IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible (`::a.b.c.d`) embedded
/// address. `::` and `::1` keep their IPv6 meaning and are not normalised.
/// Kept as a BPF subprogram (`#[inline(never)]`) for stack-frame separation of
/// the 16-byte address copies from the rest of the IPv6 parser. Writes the
/// extracted IPv4 bytes into `out` and returns `bool` (`r0` stays a scalar so
/// LLVM never shifts uninitialized `Option<[u8; 4]>` payload bits into `r0`).
#[inline(never)]
fn embedded_ipv4(address: &[u8; NETWORK_ADDRESS_BYTES], out: &mut [u8; 4]) -> bool {
    let mapped =
        address[0..10].iter().all(|byte| *byte == 0) && address[10] == 0xff && address[11] == 0xff;
    if mapped {
        *out = [address[12], address[13], address[14], address[15]];
        return true;
    }
    if address[0..12].iter().all(|byte| *byte == 0) {
        let ipv4 = [address[12], address[13], address[14], address[15]];
        if ipv4 != [0, 0, 0, 0] && ipv4 != [0, 0, 0, 1] {
            *out = ipv4;
            return true;
        }
    }
    false
}

#[inline(always)]
const fn canonical_ipv4(address: [u8; 4]) -> [u8; NETWORK_ADDRESS_BYTES] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, address[0], address[1], address[2], address[3],
    ]
}

#[inline(always)]
const fn wire_protocol(protocol: u8) -> u8 {
    if protocol == NETWORK_PROTOCOL_TCP {
        STYX_PROTO_TCP
    } else if protocol == STYX_PROTO_UDP {
        STYX_PROTO_UDP
    } else {
        STYX_PROTO_UNKNOWN
    }
}

#[inline(always)]
fn ipv4_octets(packet: &EgressPacket) -> [u8; 4] {
    [
        packet.dst[12],
        packet.dst[13],
        packet.dst[14],
        packet.dst[15],
    ]
}

/// Final verdict for one packet plus whether it is actually dropped.
#[derive(Clone, Copy)]
struct EgressDecision {
    verdict: u8,
    /// True when the packet is dropped: new enforcement in enforce mode, or the
    /// pre-existing threat-intel blocklist (which keeps its 5.2.0 behaviour).
    drop: bool,
    /// True when the drop is caused by new Point-3 enforcement (veto, DNS pin,
    /// default deny) and therefore feeds EGRESS_POLICY_DROPS.
    policy_drop: bool,
}

impl EgressDecision {
    const fn allow() -> Self {
        Self { verdict: STYX_VERDICT_ALLOW, drop: false, policy_drop: false }
    }
}

/// Kept as a BPF subprogram (`#[inline(never)]`): the LPM key temporaries of the
/// individual policy lookups would otherwise inflate the main program frame
/// beyond the 512-byte eBPF stack limit.
#[inline(never)]
fn evaluate_egress_policy(
    packet: &EgressPacket,
    scope: &EgressScope,
    mode: u8,
    flags: u8,
    global_flags: u8,
) -> EgressDecision {
    let enforce = mode == STYX_MODE_ENFORCE;
    let loopback = is_loopback(packet);

    // §6.7: mandatory veto before every allow rule. Loopback is exempt (§6.7);
    // the ICMPv6 ND exception is applied inside `egress_vetoed`.
    if !loopback && egress_vetoed(packet, flags) {
        return EgressDecision {
            verdict: STYX_VERDICT_METADATA_VETO,
            drop: enforce,
            policy_drop: enforce,
        };
    }

    // §6.8: DNS/DoT pinning. Only configured resolver destinations may be
    // reached on 53/853, and only with DNS_RESOLVER on the cell or globally.
    if !loopback && dns_pinning_violated(packet, flags, global_flags) {
        return EgressDecision {
            verdict: STYX_VERDICT_DNS_PIN,
            drop: enforce,
            policy_drop: enforce,
        };
    }

    // §6.9a: per-cell allow, longest prefix match.
    if cell_allow_matches(scope.cell_cgroup, packet) {
        return EgressDecision::allow();
    }
    // §6.9b/§6.9c: global allow and the pre-existing host allowlist apply only
    // when the cgroup opted in with ALLOW_HOST_ALLOWLIST.
    if flags & STYX_FLAG_ALLOW_HOST_ALLOWLIST != 0
        && (global_allow_matches(packet) || legacy_allowlist_matches(packet))
    {
        return EgressDecision::allow();
    }
    // §6.9d: the pre-existing threat-intel blocklist keeps the exact 5.2.0
    // behaviour (DROP plus the unchanged EgressDropEvent wire format) in every
    // mode, so enabling Point-3 telemetry never weakens it.
    if legacy_blocklist_matches(packet) {
        emit_egress_drop(packet.family, packet.protocol, legacy_destination(packet));
        return EgressDecision {
            verdict: STYX_VERDICT_DROP,
            drop: true,
            policy_drop: false,
        };
    }
    // Loopback is never default-denied: local IPC must keep working (no lockout,
    // §1.2). It is evaluated after the blocklist so operator blocklist prefixes
    // that cover 127/8 or ::1 keep their pre-existing effect.
    if loopback {
        return EgressDecision::allow();
    }
    // §6.10: default depends on the mode. Monitor never drops, enforce fails
    // closed; OFF with flow logging records the packet without blocking.
    if enforce {
        return EgressDecision {
            verdict: STYX_VERDICT_DEFAULT_DENY,
            drop: true,
            policy_drop: true,
        };
    }
    if mode == STYX_MODE_MONITOR {
        return EgressDecision {
            verdict: STYX_VERDICT_AUDIT_DROP,
            drop: false,
            policy_drop: false,
        };
    }
    EgressDecision::allow()
}

/// §6.7: mandatory veto against `STYX_BLOCK_*` (the core seeds metadata,
/// link-local and multicast prefixes). `ALLOW_METADATA` only exempts targets
/// outside link-local/multicast scopes: metadata endpoints inside fe80::/10 or
/// a multicast scope remain vetoed.
#[inline(always)]
fn egress_vetoed(packet: &EgressPacket, flags: u8) -> bool {
    if is_nd_exception(packet) {
        return false;
    }
    let blocked = match packet.family {
        NETWORK_FAMILY_V4 => STYX_BLOCK_V4.get(&Key::new(32, ipv4_octets(packet))).is_some(),
        NETWORK_FAMILY_V6 => STYX_BLOCK_V6.get(&Key::new(128, packet.dst)).is_some(),
        _ => false,
    };
    if !blocked {
        return false;
    }
    (flags & STYX_FLAG_ALLOW_METADATA) == 0 || is_link_local_or_multicast(packet)
}

/// §6.8: `dst_port = 53/853` is only allowed to configured resolvers and only
/// with the DNS_RESOLVER flag on the cgroup scope (or globally).
#[inline(always)]
fn dns_pinning_violated(packet: &EgressPacket, flags: u8, global_flags: u8) -> bool {
    if !is_dns_transport_port(packet.dst_port) {
        return false;
    }
    let resolver_known = match packet.family {
        NETWORK_FAMILY_V4 => STYX_RESOLVER_V4.get(&Key::new(32, ipv4_octets(packet))).is_some(),
        NETWORK_FAMILY_V6 => STYX_RESOLVER_V6.get(&Key::new(128, packet.dst)).is_some(),
        _ => false,
    };
    if !resolver_known {
        return true;
    }
    (flags & STYX_FLAG_DNS_RESOLVER) == 0 && (global_flags & STYX_FLAG_DNS_RESOLVER) == 0
}

/// §6.9a: per-cell allow trie. Key (§4): [cgroup LE 8][addr 4][dst_port BE 2]
/// [proto 1][pad 1]; prefix 64 = any destination, 96 = cgroup+IP, 112 = +port,
/// 120 = +protocol. A single lookup returns the longest matching prefix.
#[inline(always)]
fn cell_allow_matches(cell_cgroup: u64, packet: &EgressPacket) -> bool {
    if cell_cgroup == 0 {
        return false;
    }
    match packet.family {
        NETWORK_FAMILY_V4 => {
            let mut key = [0u8; 16];
            key[0..8].copy_from_slice(&cell_cgroup.to_le_bytes());
            key[8..12].copy_from_slice(&ipv4_octets(packet));
            key[12..14].copy_from_slice(&packet.dst_port.to_be_bytes());
            key[14] = packet.proto;
            CELL_EGRESS_ALLOW_V4.get(&Key::new(120, key)).is_some()
        }
        NETWORK_FAMILY_V6 => {
            // Phase 1 v6 cell key (§4): [cgroup LE 8][addr 16], no port/proto
            // slot. The core installs v6 rules as CIDR-only entries.
            let mut key = [0u8; 24];
            key[0..8].copy_from_slice(&cell_cgroup.to_le_bytes());
            key[8..24].copy_from_slice(&packet.dst);
            CELL_EGRESS_ALLOW_V6.get(&Key::new(192, key)).is_some()
        }
        _ => false,
    }
}

/// §6.9b: global host allowlist. Key (§4): [addr][dst_port BE 2][proto 1][pad];
/// prefix 32 = any port/proto, 48 = +port, 56 = +protocol.
#[inline(always)]
fn global_allow_matches(packet: &EgressPacket) -> bool {
    match packet.family {
        NETWORK_FAMILY_V4 => {
            let mut key = [0u8; 8];
            key[0..4].copy_from_slice(&ipv4_octets(packet));
            key[4..6].copy_from_slice(&packet.dst_port.to_be_bytes());
            key[6] = packet.proto;
            STYX_ALLOW_GLOBAL_V4.get(&Key::new(56, key)).is_some()
        }
        NETWORK_FAMILY_V6 => {
            let mut key = [0u8; 20];
            key[0..16].copy_from_slice(&packet.dst);
            key[16..18].copy_from_slice(&packet.dst_port.to_be_bytes());
            key[18] = packet.proto;
            STYX_ALLOW_GLOBAL_V6.get(&Key::new(152, key)).is_some()
        }
        _ => false,
    }
}

#[inline(always)]
fn legacy_allowlist_matches(packet: &EgressPacket) -> bool {
    match packet.family {
        NETWORK_FAMILY_V4 => ALLOWLIST_V4.get(&Key::new(32, ipv4_octets(packet))).is_some(),
        NETWORK_FAMILY_V6 => ALLOWLIST_V6.get(&Key::new(128, packet.dst)).is_some(),
        _ => false,
    }
}

#[inline(always)]
fn legacy_blocklist_matches(packet: &EgressPacket) -> bool {
    match packet.family {
        NETWORK_FAMILY_V4 => BLOCKLIST_V4
            .get(&Key::new(32, ipv4_octets(packet)))
            .is_some_and(|action| *action == ACTION_DROP),
        NETWORK_FAMILY_V6 => BLOCKLIST_V6
            .get(&Key::new(128, packet.dst))
            .is_some_and(|action| *action == ACTION_DROP),
        _ => false,
    }
}

/// Legacy `EgressDropEvent` destination convention (wire format unchanged):
/// IPv4 in the first four bytes, IPv6 in all sixteen.
#[inline(always)]
fn legacy_destination(packet: &EgressPacket) -> [u8; NETWORK_ADDRESS_BYTES] {
    let mut destination = [0u8; NETWORK_ADDRESS_BYTES];
    if packet.family == NETWORK_FAMILY_V4 {
        destination[0..4].copy_from_slice(&ipv4_octets(packet));
    } else {
        destination = packet.dst;
    }
    destination
}

#[inline(always)]
fn is_loopback(packet: &EgressPacket) -> bool {
    match packet.family {
        NETWORK_FAMILY_V4 => packet.dst[12] == 127,
        NETWORK_FAMILY_V6 => {
            packet.dst[0..15].iter().all(|byte| *byte == 0) && packet.dst[15] == 1
        }
        _ => false,
    }
}

#[inline(always)]
fn is_ipv6_link_local(address: &[u8; NETWORK_ADDRESS_BYTES]) -> bool {
    address[0] == 0xfe && (address[1] & 0xc0) == 0x80
}

#[inline(always)]
fn is_link_local_or_multicast(packet: &EgressPacket) -> bool {
    match packet.family {
        NETWORK_FAMILY_V4 => {
            let first = packet.dst[12];
            (first == 169 && packet.dst[13] == 254) || (224..=239).contains(&first)
        }
        NETWORK_FAMILY_V6 => is_ipv6_link_local(&packet.dst) || packet.dst[0] == 0xff,
        _ => false,
    }
}

/// §6.7/§4: NS/NA towards a link-local IPv6 address is exempt from the seeded
/// fe80::/10 veto, otherwise IPv6 neighbour discovery would be vetoed. Only the
/// two neighbour-discovery types are exempt; from a socket this is a local,
/// non-routable scope (kernel-generated ND does not pass the cgroup hook).
#[inline(always)]
fn is_nd_exception(packet: &EgressPacket) -> bool {
    packet.family == NETWORK_FAMILY_V6
        && packet.protocol == IPV6_PROTOCOL_ICMPV6
        && (packet.icmpv6_type == ICMPV6_NEIGHBOR_SOLICITATION
            || packet.icmpv6_type == ICMPV6_NEIGHBOR_ADVERTISEMENT)
        && is_ipv6_link_local(&packet.dst)
}

#[inline(always)]
const fn is_dns_transport_port(port: u16) -> bool {
    port == DNS_TRANSPORT_PORT || port == DOT_TRANSPORT_PORT
}

/// §6.5: aggregate one egress packet into the per-flow LRU map and emit a
/// bounded FlowEvent once a threshold is crossed (first packet of the flow,
/// epoch-second change, >= 64 KiB or >= 256 packets since the last event).
/// No event is ever emitted per packet.
///
/// Kept as a BPF subprogram (`#[inline(never)]`) to keep the flow-aggregation
/// scratch state out of the main program's stack frame.
#[inline(never)]
fn observe_flow(ctx: &SkBuffContext, packet: &EgressPacket, cell_cgroup: u64, verdict: u8) {
    match packet.family {
        NETWORK_FAMILY_V4 => {
            let mut key = [0u8; 16];
            key[0..8].copy_from_slice(&cell_cgroup.to_le_bytes());
            key[8..12].copy_from_slice(&ipv4_octets(packet));
            key[12..14].copy_from_slice(&packet.dst_port.to_be_bytes());
            key[14] = packet.proto;
            observe_flow_aggregate(&FLOW_AGG_V4, &key, ctx, packet, cell_cgroup, verdict);
        }
        NETWORK_FAMILY_V6 => {
            let mut key = [0u8; 32];
            key[0..8].copy_from_slice(&cell_cgroup.to_le_bytes());
            key[8..24].copy_from_slice(&packet.dst);
            key[24..26].copy_from_slice(&packet.dst_port.to_be_bytes());
            key[26] = packet.proto;
            observe_flow_aggregate(&FLOW_AGG_V6, &key, ctx, packet, cell_cgroup, verdict);
        }
        _ => {}
    }
}

/// Inlined into its caller: BPF subprograms only receive five argument
/// registers, and this helper needs six. The caller's frame plus this state
/// still stays below the 512-byte eBPF stack limit.
#[inline(always)]
fn observe_flow_aggregate<K>(
    map: &LruPerCpuHashMap<K, [u8; 40]>,
    key: &K,
    ctx: &SkBuffContext,
    packet: &EgressPacket,
    cell_cgroup: u64,
    verdict: u8,
) {
    let now = unsafe { bpf_ktime_get_ns() };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(value_ptr) = map.get_ptr_mut(key) {
        // SAFETY: the per-CPU map owns this value for the current CPU and no
        // other CPU can observe the in-place mutation until the program returns.
        let value = unsafe { &mut *value_ptr };
        let last_ts = read_agg_u64(value, FLOW_AGG_LAST_TS);
        let tx_bytes =
            read_agg_u64(value, FLOW_AGG_TX).saturating_add(u64::from(packet.packet_len));
        let packets = read_agg_u32(value, FLOW_AGG_PACKETS).saturating_add(1);
        write_agg_u64(value, FLOW_AGG_LAST_TS, now);
        write_agg_u64(value, FLOW_AGG_TX, tx_bytes);
        write_agg_u32(value, FLOW_AGG_PACKETS, packets);
        value[FLOW_AGG_TCP_FLAGS] |= packet.tcp_flags;
        value[FLOW_AGG_VERDICT] = verdict;
        let second_changed = last_ts / NS_PER_SECOND != now / NS_PER_SECOND;
        if !second_changed && tx_bytes < FLOW_EMIT_BYTES && packets < FLOW_EMIT_PACKETS {
            return;
        }
        let stored_pid = read_agg_u32(value, FLOW_AGG_PID);
        let tcp_flags = value[FLOW_AGG_TCP_FLAGS];
        emit_flow_event(
            ctx,
            cell_cgroup,
            packet,
            tx_bytes,
            packets,
            tcp_flags,
            verdict,
            stored_pid,
            now,
        );
        // Start a new aggregation window: the next FlowEvent reports the delta.
        write_agg_u64(value, FLOW_AGG_FIRST_TS, now);
        write_agg_u64(value, FLOW_AGG_TX, 0);
        write_agg_u32(value, FLOW_AGG_PACKETS, 0);
        value[FLOW_AGG_TCP_FLAGS] = packet.tcp_flags;
    } else {
        // §6.5: first packet of a new aggregate - emit immediately and start the
        // window at zero so the next event needs a threshold.
        let mut value = [0u8; 40];
        write_agg_u64(&mut value, FLOW_AGG_FIRST_TS, now);
        write_agg_u64(&mut value, FLOW_AGG_LAST_TS, now);
        write_agg_u64(&mut value, FLOW_AGG_TX, 0);
        write_agg_u32(&mut value, FLOW_AGG_PACKETS, 0);
        write_agg_u32(&mut value, FLOW_AGG_PID, pid);
        value[FLOW_AGG_TCP_FLAGS] = packet.tcp_flags;
        value[FLOW_AGG_VERDICT] = verdict;
        if map.insert(key, &value, 0).is_ok() {
            emit_flow_event(
                ctx,
                cell_cgroup,
                packet,
                u64::from(packet.packet_len),
                1,
                packet.tcp_flags,
                verdict,
                pid,
                now,
            );
        } else {
            increment_counter(&FLOW_AGG_INSERT_FAILURES);
        }
    }
}

/// Emits one native-endian 104-byte `FlowEvent` (§3.2). The struct is shared
/// with the core decoder, so the wire layout is the `repr(C)` layout; the
/// helper skips records the decoder would reject instead of emitting garbage.
/// Inlined into its caller: BPF subprograms only receive five argument
/// registers, and this helper needs more; the 104-byte record is written
/// directly into the ring-buffer reservation and never copied onto the stack.
#[inline(always)]
fn emit_flow_event(
    ctx: &SkBuffContext,
    cell_cgroup: u64,
    packet: &EgressPacket,
    tx_bytes: u64,
    packets: u32,
    tcp_flags: u8,
    verdict: u8,
    pid: u32,
    ts_ns: u64,
) {
    if packets == 0 || ts_ns == 0 {
        return;
    }
    // `decode_styx_flow_event` rejects family 4 with a non-canonical or
    // unspecified destination; never produce such a record.
    if packet.family == NETWORK_FAMILY_V4 && ipv4_octets(packet) == [0, 0, 0, 0] {
        return;
    }
    let uid = unsafe { bpf_get_socket_uid(ctx.as_ptr().cast()) };
    // V6.3.0 AP-9 (S12): both aggregate call sites of this single emitter pass
    // the per-(class, cgroup, uid) flow token bucket before a ring slot is
    // reserved. A suppressed record is counted, never silently lost, and the
    // packet verdict above is unaffected (this hook only reports).
    if !crate::sec_crit::telemetry_budget_allow(
        gedefense_common::SEC_CRIT_BUCKET_FLOW,
        cell_cgroup,
        uid,
    ) {
        crate::sec_crit::telemetry_note_suppressed(gedefense_common::SEC_CRIT_BUCKET_FLOW);
        return;
    }
    let comm = bpf_get_current_comm().unwrap_or([0u8; EXEC_COMM_BYTES]);
    // Write the record directly into the ring-buffer reservation: a 104-byte
    // stack copy would exceed the 512-byte eBPF stack together with the parse
    // state, and the reservation is the exact destination the record needs.
    if let Some(mut entry) = FLOW_EVENTS.reserve::<FlowEvent>(0) {
        let event = entry.as_mut_ptr();
        // SAFETY: the reservation is exactly `size_of::<FlowEvent>()` bytes and
        // aligned for the struct. Every field is written through the raw pointer
        // before the entry is submitted; no reference to uninitialised memory is
        // created and the entry is submitted before this scope ends.
        unsafe {
            core::ptr::addr_of_mut!((*event).cgroup_id).write(cell_cgroup);
            core::ptr::addr_of_mut!((*event).ts_ns).write(ts_ns);
            core::ptr::addr_of_mut!((*event).tx_bytes).write(tx_bytes);
            core::ptr::addr_of_mut!((*event).rx_bytes).write(0);
            core::ptr::addr_of_mut!((*event).pid).write(pid);
            core::ptr::addr_of_mut!((*event).uid).write(uid);
            core::ptr::addr_of_mut!((*event).dst).write(packet.dst);
            core::ptr::addr_of_mut!((*event).src).write(packet.src);
            core::ptr::addr_of_mut!((*event).dst_port).write(packet.dst_port);
            core::ptr::addr_of_mut!((*event).src_port).write(packet.src_port);
            core::ptr::addr_of_mut!((*event).packets).write(packets);
            core::ptr::addr_of_mut!((*event).proto).write(packet.proto);
            core::ptr::addr_of_mut!((*event).family).write(packet.family);
            core::ptr::addr_of_mut!((*event).direction).write(STYX_DIR_EGRESS);
            core::ptr::addr_of_mut!((*event).tcp_flags).write(if packet.proto == STYX_PROTO_TCP {
                tcp_flags
            } else {
                0
            });
            core::ptr::addr_of_mut!((*event).verdict).write(verdict);
            core::ptr::addr_of_mut!((*event).reserved).write([0u8; 3]);
            core::ptr::addr_of_mut!((*event).comm).write(comm);
        }
        entry.submit(0);
        increment_counter(&FLOW_EVENTS_EMITTED);
    } else {
        // Ring full: visibility loss is reported through the health counter, the
        // enforcement verdict above is unaffected.
        increment_counter(&FLOW_RING_DROPS);
    }
}

#[inline(always)]
fn read_agg_u32(value: &[u8; 40], offset: usize) -> u32 {
    u32::from_le_bytes([
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
    ])
}

#[inline(always)]
fn read_agg_u64(value: &[u8; 40], offset: usize) -> u64 {
    u64::from_le_bytes([
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
        value[offset + 4],
        value[offset + 5],
        value[offset + 6],
        value[offset + 7],
    ])
}

#[inline(always)]
fn write_agg_u32(value: &mut [u8; 40], offset: usize, new_value: u32) {
    let bytes = new_value.to_le_bytes();
    value[offset] = bytes[0];
    value[offset + 1] = bytes[1];
    value[offset + 2] = bytes[2];
    value[offset + 3] = bytes[3];
}

#[inline(always)]
fn write_agg_u64(value: &mut [u8; 40], offset: usize, new_value: u64) {
    let bytes = new_value.to_le_bytes();
    value[offset] = bytes[0];
    value[offset + 1] = bytes[1];
    value[offset + 2] = bytes[2];
    value[offset + 3] = bytes[3];
    value[offset + 4] = bytes[4];
    value[offset + 5] = bytes[5];
    value[offset + 6] = bytes[6];
    value[offset + 7] = bytes[7];
}

#[inline(always)]
fn inspect_egress_v4(ctx: &SkBuffContext) -> Result<bool, ()> {
    let header: Ipv4Hdr = ctx.load(0).map_err(|_| ())?;
    if header.version_ihl >> 4 != NETWORK_FAMILY_V4 || header.version_ihl & 0x0f < 5 {
        return Err(());
    }
    let key = Key::new(32, header.dst);
    if ALLOWLIST_V4.get(&key).is_some() {
        return Ok(false);
    }
    if let Some(action) = BLOCKLIST_V4.get(&key) {
        if *action == ACTION_DROP {
            emit_egress_drop(
                NETWORK_FAMILY_V4,
                header.protocol,
                [
                    header.dst[0],
                    header.dst[1],
                    header.dst[2],
                    header.dst[3],
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            );
            return Ok(true);
        }
    }
    Ok(false)
}

#[inline(always)]
fn inspect_egress_v6(ctx: &SkBuffContext) -> Result<bool, ()> {
    let header: Ipv6Hdr = ctx.load(0).map_err(|_| ())?;
    if u32::from_be_bytes(header.version_flow) >> 28 != u32::from(NETWORK_FAMILY_V6) {
        return Err(());
    }
    let key = Key::new(128, header.dst);
    if ALLOWLIST_V6.get(&key).is_some() {
        return Ok(false);
    }
    if let Some(action) = BLOCKLIST_V6.get(&key) {
        if *action == ACTION_DROP {
            emit_egress_drop(NETWORK_FAMILY_V6, header.next_header, header.dst);
            return Ok(true);
        }
    }
    Ok(false)
}

#[inline(always)]
fn emit_egress_drop(family: u8, protocol: u8, destination: [u8; NETWORK_ADDRESS_BYTES]) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; EXEC_COMM_BYTES]);
    let event = EgressDropEvent {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        family,
        protocol,
        action: ACTION_DROP,
        reserved: 0,
        destination,
        comm,
    };
    let _ = EGRESS_EVENTS.output::<EgressDropEvent>(&event, 0);
}

/// V6.3.0 AP-6: true when the global StyX word enables flow observation. The
/// ingress RX observer follows the same switch as the egress flow telemetry, so
/// an operator who disables StyX logging never collects RX flows silently.
#[inline(always)]
pub(crate) fn styx_flow_observation_enabled() -> bool {
    let Some(global) = STYX_GLOBAL.get(STYX_GLOBAL_INDEX) else {
        return false;
    };
    let mode = decode_global_mode(*global);
    let flags = decode_global_flags(*global);
    mode != STYX_MODE_OFF || (flags & STYX_FLAG_LOG_FLOWS) != 0
}
