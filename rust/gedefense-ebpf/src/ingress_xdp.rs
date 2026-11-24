use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, xdp},
    maps::lpm_trie::Key,
    programs::{TcContext, XdpContext},
};
use core::mem;
use gedefense_common::{
    parse_network_header, ACTION_DROP, LOCKDOWN_FLAG_DROP_ALL, LOCKDOWN_MODE_ARMED,
    LOCKDOWN_STATE_ABI, LOCKDOWN_STATE_ABI_SHIFT, LOCKDOWN_STATE_BYTE_MASK,
    LOCKDOWN_STATE_FLAGS_SHIFT, LOCKDOWN_STATE_MAGIC, LOCKDOWN_STATE_MAGIC_SHIFT,
    LOCKDOWN_STATE_MODE_SHIFT, NETWORK_FAMILY_V4, NETWORK_FAMILY_V6, NETWORK_PROTOCOL_TCP,
    NetworkHeader,
};
use crate::maps::{
    ALLOWLIST_V4, ALLOWLIST_V6, BLOCKLIST_V4, BLOCKLIST_V6, LOCKDOWN_DROPS, LOCKDOWN_STATE,
};
use crate::net_parse::{
    observe_ingress_v4, observe_ingress_v6, ptr_at, Ipv4Hdr, Ipv6Hdr, L2Prefix, TcpPrefix,
    UdpPrefix,
};
use crate::util::increment_counter;

/// Index of the single lockdown state word in `LOCKDOWN_STATE` (§4).
const LOCKDOWN_STATE_INDEX: u32 = 0;

// ---------------------------------------------------------------------------
// Point 5 (§4): lockdown fastpath shared by XDP, TC-ingress and cgroup-egress.
//
// Each program reads the state word before its pre-existing pipeline. OFF, an
// absent map entry or a foreign magic/ABI/mode leaves the verdict path
// byte-identical to 5.2.0 (fail-safe, no drop); the only added cost is one
// array lookup. Unknown flag bits are ignored exactly like the core decoder.
// ---------------------------------------------------------------------------

/// Reads the §3 state word. `None` = absent/zero word, foreign magic/ABI or an
/// out-of-range mode; a valid `OFF` word also yields `None` because it is not
/// armed and therefore must not alter any verdict.
#[inline(always)]
pub(crate) fn lockdown_flags() -> Option<u8> {
    let word = *LOCKDOWN_STATE.get(LOCKDOWN_STATE_INDEX)?;
    let magic = ((word >> LOCKDOWN_STATE_MAGIC_SHIFT) & LOCKDOWN_STATE_BYTE_MASK) as u8;
    let abi = ((word >> LOCKDOWN_STATE_ABI_SHIFT) & LOCKDOWN_STATE_BYTE_MASK) as u8;
    let mode = ((word >> LOCKDOWN_STATE_MODE_SHIFT) & LOCKDOWN_STATE_BYTE_MASK) as u8;
    if magic != LOCKDOWN_STATE_MAGIC || abi != LOCKDOWN_STATE_ABI || mode != LOCKDOWN_MODE_ARMED {
        return None;
    }
    let flags = ((word >> LOCKDOWN_STATE_FLAGS_SHIFT) & LOCKDOWN_STATE_BYTE_MASK) as u8;
    Some(flags)
}

/// §4 XDP/TC-ingress condition: armed word with `DROP_ALL`. Loopback is
/// irrelevant on an external ingress path, so there is no exception there.
#[inline(always)]
fn lockdown_drop_active() -> bool {
    match lockdown_flags() {
        Some(flags) => (flags & LOCKDOWN_FLAG_DROP_ALL) != 0,
        None => false,
    }
}

#[xdp]
pub fn gedefense_xdp(ctx: XdpContext) -> u32 {
    // Point 5 (§4): lockdown is the first statement of the program. It drops
    // every frame on the external interface without L3/L4 parsing.
    if lockdown_drop_active() {
        increment_counter(&LOCKDOWN_DROPS);
        return xdp_action::XDP_DROP;
    }
    match inspect(&ctx) {
        Ok(action) => action,
        // Fail closed: the only error paths here are frames advertised as IPv4/IPv6
        // whose headers are truncated or self-contradictory. Such a frame is invalid
        // for the kernel network stack as well, so passing it on would only hand the
        // malformed packet to the stack; non-IP L2 is classified as
        // `NetworkHeader::Other` and stays on the pass path.
        Err(()) => xdp_action::XDP_DROP,
    }
}

#[classifier]
pub fn gedefense_tc_ingress(ctx: TcContext) -> i32 {
    // Point 5 (§4): lockdown shot before the ingress sensor/policy pipeline.
    if lockdown_drop_active() {
        increment_counter(&LOCKDOWN_DROPS);
        return TC_ACT_SHOT;
    }
    match inspect_tc_ingress(&ctx) {
        Ok(true) => TC_ACT_SHOT,
        Ok(false) => TC_ACT_OK,
        // Same fail-closed rule as XDP: malformed/truncated L3 frames cannot be
        // classified against the policy maps, so they are dropped instead of passed.
        Err(()) => TC_ACT_SHOT,
    }
}

#[inline(always)]
fn inspect_tc_ingress(ctx: &TcContext) -> Result<bool, ()> {
    let prefix: L2Prefix = ctx.load(0).map_err(|_| ())?;
    match parse_network_header(&prefix.bytes) {
        NetworkHeader::Ipv4(offset) => inspect_tc_ipv4(ctx, offset),
        NetworkHeader::Ipv6(offset) => inspect_tc_ipv6(ctx, offset),
        NetworkHeader::Other => Ok(false),
    }
}

#[inline(always)]
fn inspect_tc_ipv4(ctx: &TcContext, offset: usize) -> Result<bool, ()> {
    let header: Ipv4Hdr = ctx.load(offset).map_err(|_| ())?;
    if header.version_ihl >> 4 != NETWORK_FAMILY_V4 || header.version_ihl & 0x0f < 5 {
        return Err(());
    }
    let key = Key::new(32, header.src);
    let (src_port, dst_port, flags) = if header.version_ihl & 0x0f == 5 {
        tc_transport_metadata(ctx, offset + mem::size_of::<Ipv4Hdr>(), header.protocol)
    } else {
        (0, 0, 0)
    };
    // Observe before the policy verdict: an allowlisted source must not become
    // invisible to the ingress counters. The previous early return meant a flood
    // from an allowlisted prefix never reached the sensor health/rate telemetry.
    observe_ingress_v4(
        header.src,
        header.dst,
        header.protocol,
        src_port,
        dst_port,
        flags,
        ctx.len(),
    );
    if ALLOWLIST_V4.get(&key).is_some() {
        return Ok(false);
    }
    Ok(BLOCKLIST_V4
        .get(&key)
        .is_some_and(|action| *action == ACTION_DROP))
}

#[inline(always)]
fn inspect_tc_ipv6(ctx: &TcContext, offset: usize) -> Result<bool, ()> {
    let header: Ipv6Hdr = ctx.load(offset).map_err(|_| ())?;
    if u32::from_be_bytes(header.version_flow) >> 28 != u32::from(NETWORK_FAMILY_V6) {
        return Err(());
    }
    let key = Key::new(128, header.src);
    let (src_port, dst_port, flags) =
        tc_transport_metadata(ctx, offset + mem::size_of::<Ipv6Hdr>(), header.next_header);
    // Count before the allowlist verdict; see the IPv4 path above.
    observe_ingress_v6(
        header.src,
        header.dst,
        header.next_header,
        src_port,
        dst_port,
        flags,
        ctx.len(),
    );
    if ALLOWLIST_V6.get(&key).is_some() {
        return Ok(false);
    }
    Ok(BLOCKLIST_V6
        .get(&key)
        .is_some_and(|action| *action == ACTION_DROP))
}

#[inline(always)]
fn tc_transport_metadata(ctx: &TcContext, offset: usize, protocol: u8) -> (u16, u16, u8) {
    if protocol == NETWORK_PROTOCOL_TCP {
        if let Ok(tcp) = ctx.load::<TcpPrefix>(offset) {
            return (
                u16::from_be_bytes(tcp.src_port),
                u16::from_be_bytes(tcp.dst_port),
                tcp.flags,
            );
        }
    } else if protocol == 17 {
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

#[inline(always)]
fn inspect(ctx: &XdpContext) -> Result<u32, ()> {
    let prefix: *const L2Prefix = ptr_at(ctx, 0)?;
    // SAFETY: ptr_at proves the complete fixed prefix lies inside data..data_end.
    // Copying it into the stack exposes the same bounded parser to host fuzzing.
    let bytes = unsafe { (*prefix).bytes };
    match parse_network_header(&bytes) {
        NetworkHeader::Ipv4(offset) => inspect_v4(ctx, offset),
        NetworkHeader::Ipv6(offset) => inspect_v6(ctx, offset),
        NetworkHeader::Other => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn inspect_v4(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let header: *const Ipv4Hdr = ptr_at(ctx, offset)?;
    let version_ihl = unsafe { (*header).version_ihl };
    if version_ihl >> 4 != 4 {
        return Err(());
    }
    let ihl_words = version_ihl & 0x0f;
    if ihl_words < 5 {
        return Err(());
    }

    let src = unsafe { (*header).src };
    let dst = unsafe { (*header).dst };
    let protocol = unsafe { (*header).protocol };
    let key = Key::new(32, src);

    // Transport parsing is deliberately restricted to the fixed IPv4 header
    // form (IHL=5). Packets carrying IPv4 options still contribute source/rate
    // telemetry, but ports remain unknown instead of relying on attacker-
    // controlled pointer arithmetic that hardening kernels may reject.
    let (src_port, dst_port, flags) = if ihl_words == 5 {
        xdp_transport_metadata(ctx, offset + mem::size_of::<Ipv4Hdr>(), protocol)
    } else {
        (0, 0, 0)
    };
    let packet_len = ctx.data_end().saturating_sub(ctx.data()) as u32;
    // Observe before the policy verdict: an allowlisted source must not become
    // invisible to the ingress counters. The previous early return meant a flood
    // from an allowlisted prefix never reached the sensor health/rate telemetry.
    observe_ingress_v4(src, dst, protocol, src_port, dst_port, flags, packet_len);
    if ALLOWLIST_V4.get(&key).is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    if let Some(action) = BLOCKLIST_V4.get(&key) {
        if *action == ACTION_DROP {
            return Ok(xdp_action::XDP_DROP);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn inspect_v6(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let header: *const Ipv6Hdr = ptr_at(ctx, offset)?;
    if u32::from_be_bytes(unsafe { (*header).version_flow }) >> 28 != 6 {
        return Err(());
    }
    let src = unsafe { (*header).src };
    let dst = unsafe { (*header).dst };
    let protocol = unsafe { (*header).next_header };
    let key = Key::new(128, src);

    // Only direct TCP/UDP next-headers are parsed here. Extension-header chains
    // remain visible as IP-level telemetry and are left to userspace/L7 logic.
    let (src_port, dst_port, flags) =
        xdp_transport_metadata(ctx, offset + mem::size_of::<Ipv6Hdr>(), protocol);
    let packet_len = ctx.data_end().saturating_sub(ctx.data()) as u32;
    // Count before the allowlist verdict; see the IPv4 path above.
    observe_ingress_v6(src, dst, protocol, src_port, dst_port, flags, packet_len);
    if ALLOWLIST_V6.get(&key).is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    if let Some(action) = BLOCKLIST_V6.get(&key) {
        if *action == ACTION_DROP {
            return Ok(xdp_action::XDP_DROP);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn xdp_transport_metadata(ctx: &XdpContext, offset: usize, protocol: u8) -> (u16, u16, u8) {
    if protocol == NETWORK_PROTOCOL_TCP {
        if let Ok(tcp) = ptr_at::<TcpPrefix>(ctx, offset) {
            let tcp = unsafe { &*tcp };
            return (
                u16::from_be_bytes(tcp.src_port),
                u16::from_be_bytes(tcp.dst_port),
                tcp.flags,
            );
        }
    } else if protocol == 17 {
        if let Ok(udp) = ptr_at::<UdpPrefix>(ctx, offset) {
            let udp = unsafe { &*udp };
            return (
                u16::from_be_bytes(udp.src_port),
                u16::from_be_bytes(udp.dst_port),
                0,
            );
        }
    }
    (0, 0, 0)
}
