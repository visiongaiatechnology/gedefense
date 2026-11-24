//! V6.3.0 AP-6 — `cgroup_skb/ingress` RX flow observer (eBPF half).
//!
//! STATUS: DIAMANT VGT SUPREME (implementation; verifier acceptance is the real
//! kernel gate).
//!
//! Program `#[cgroup_skb(ingress)] gedefense_ingress_flow`: observe-only. It
//! **always returns the `cgroup_skb` pass verdict `1`** and therefore never
//! drops, rewrites or redirects a packet. It only feeds bounded inbound flow
//! aggregates into the shared `FLOW_EVENTS` ring (`direction =
//! STYX_DIR_INGRESS`, `rx_bytes` accounting, `tx_bytes = 0`, `verdict =
//! STYX_VERDICT_ALLOW`) so the control plane can compute the phase-2
//! `PCR = (tx - rx) / (tx + rx)` per entity.
//!
//! The pass verdict is deliberately written as the local constant
//! [`CGROUP_SKB_ACT_PASS`] and **not** as `aya_ebpf::bindings::TC_ACT_OK`: the
//! TC uapi value `TC_ACT_OK` is `0`, while `__cgroup_bpf_run_filter_skb()`
//! interprets a zero return as `-EPERM` (drop). A real-kernel smoke test caught
//! exactly that mistake; do not "simplify" it back to the TC constant.
//!
//! ## Kernel attach point (why this is a faithful RX observer)
//!
//! `BPF_CGROUP_INET_INGRESS` programs are installed from `sk_filter_trim_cap()`
//! (`net/core/filter.c`) through `__cgroup_bpf_run_filter_skb()` (kernel/bpf/
//! cgroup.c). That function does `offset = -skb_network_offset(skb); __skb_push(
//! skb, offset)` before running the program, so the program sees `skb->data` at
//! the network header — exactly like the existing `cgroup_skb/egress` sensor.
//! It also sets `skb->sk = sk` for the run, so `bpf_skb_cgroup_id()` resolves
//! the *receiving socket's* cgroup and `bpf_get_socket_uid()` the *receiving
//! socket's* UID. The hook runs per received packet after socket lookup, i.e.
//! it observes real inbound traffic of local sockets (fragments/reassembly are
//! kernel responsibilities; non-TCP/UDP L3 payloads carry no ports and are not
//! part of the phase-2 flow model, so they are not aggregated here).
//!
//! ## Reuse of the shared bounded parser
//!
//! Parsing reuses the crate-root `parse_egress_packet`/`EgressPacket` pair. It
//! is the proven, verifier-tested bounded L3/L4 parser of the egress hook (the
//! XDP `parse_network_header` helper parses an L2 prefix, which a `cgroup_skb`
//! program never sees). Reusing it keeps one parser for both directions, so an
//! ingress record can never disagree with an egress record about a packet.
//!
//! ## Bounds
//!
//! * No allocation, no unbounded loop, no static string table.
//! * Both aggregation maps are `LruPerCpuHashMap` with
//!   [`MAX_INGRESS_FLOW_AGG_ENTRIES`] entries per CPU — the same bound as the
//!   egress `FLOW_AGG_*` maps; the LRU eviction is the documented stop of the
//!   bounded state.
//! * At most one `FlowEvent` per aggregate and threshold crossing (first packet,
//!   epoch-second change, >= 64 KiB or >= 256 packets since the last event);
//!   never one event per packet.
//! * Every wire counter is updated with saturating arithmetic (`saturating_add`);
//!   no wrapping arithmetic is used on byte/packet counts.
//!
//! ## ABI (read by `rust/gedefense-core/src/styx_ingress.rs`)
//!
//! Maps (names are the core's lookup names):
//! * `INGRESS_FLOW_AGG_V4` — `LruPerCpuHashMap<[u8; 32], [u8; 40]>`, 4096.
//! * `INGRESS_FLOW_AGG_V6` — `LruPerCpuHashMap<[u8; 48], [u8; 40]>`, 4096.
//! * `INGRESS_FLOW_READ_FAILURES` — `PerCpuArray<u64>`, 1, incremented on a
//!   packet that the bounded parser rejects.
//! * `INGRESS_FLOW_EVENTS_EMITTED` — `PerCpuArray<u64>`, 1, ingress records
//!   successfully queued into the shared ring.
//!
//! Key layout (all multi-byte integers native/little endian, ports big endian so
//! a byte view reads like the wire; every other byte is zero):
//! * V4 (`[u8; 32]`): `[cgroup 8][peer addr 4][peer port 2][local addr 4]
//!   [local port 2][proto 1][reserved 11]`
//! * V6 (`[u8; 48]`): `[cgroup 8][peer addr 16][peer port 2][local addr 16]
//!   [local port 2][proto 1][reserved 3]`
//!
//! The key contains the exact `(cgroup id, remote peer address, remote port,
//! proto)` tuple the phase-2 PCR engine groups by, plus the local endpoint. The
//! local endpoint costs nothing and disambiguates concurrent sockets of one
//! cgroup that talk to the same remote; it also makes the emitted `src_port` a
//! stable value (the parsed local port) instead of a random packet of a mixed
//! aggregate.
//!
//! Value layout (`[u8; 40]`, identical to the egress aggregate so userspace has
//! one decoder): `[first_ts 8][last_ts 8][rx_bytes 8][packets 4][pid 4]
//! [tcp_flags 1][verdict 1][reserved 6]`. `rx_bytes`/`packets` are the deltas
//! since the previous emission of the same aggregate (the window is reset after
//! every emit), exactly like the egress `tx_bytes`/`packets`.

use aya_ebpf::{
    helpers::{bpf_get_socket_uid, bpf_ktime_get_ns, bpf_skb_cgroup_id},
    macros::{cgroup_skb, map},
    maps::{LruPerCpuHashMap, PerCpuArray},
    programs::SkBuffContext,
    EbpfContext,
};
use gedefense_common::{
    FlowEvent, NETWORK_ADDRESS_BYTES, NETWORK_FAMILY_V4, NETWORK_FAMILY_V6, SEC_CRIT_BUCKET_FLOW,
    STYX_DIR_INGRESS, STYX_PROTO_TCP, STYX_PROTO_UDP, STYX_VERDICT_ALLOW,
};
use crate::sec_crit::{telemetry_budget_allow, telemetry_note_suppressed};

/// Verdict returned by every code path of the observer.
///
/// At a `cgroup_skb` hook the kernel treats `0` as "drop" and any other value as
/// "pass" (`__cgroup_bpf_run_filter_skb()` maps a zero return to `-EPERM`).
/// This is *not* the TC action enum (`TC_ACT_OK` is `0` there), so the value is
/// pinned with a dedicated name and covered by the real-kernel smoke test.
const CGROUP_SKB_ACT_PASS: i32 = 1;

/// Maximum aggregated inbound flows tracked per CPU. The same bound as the
/// egress `FLOW_AGG_*` maps (ABI-2 §4); LRU eviction is the bounded stop.
const MAX_INGRESS_FLOW_AGG_ENTRIES: u32 = 4_096;

/// Index of the single per-CPU health counter slot (all health counter maps use
/// key 0, ABI-2 §4).
const INGRESS_HEALTH_KEY: u32 = 0;

/// Aggregation value offsets, byte-identical to the egress value layout:
/// `[first_ts 8][last_ts 8][rx 8][packets 4][pid 4][tcp_flags 1][verdict 1][pad 6]`.
const FLOW_AGG_FIRST_TS: usize = 0;
const FLOW_AGG_LAST_TS: usize = 8;
const FLOW_AGG_RX: usize = 16;
const FLOW_AGG_PACKETS: usize = 24;
const FLOW_AGG_PID: usize = 28;
const FLOW_AGG_TCP_FLAGS: usize = 32;
const FLOW_AGG_VERDICT: usize = 33;

/// V4 key offsets (32 bytes).
const V4_KEY_CGROUP_ID: usize = 0;
const V4_KEY_PEER_ADDRESS: usize = 8;
const V4_KEY_PEER_PORT: usize = 12;
const V4_KEY_LOCAL_ADDRESS: usize = 14;
const V4_KEY_LOCAL_PORT: usize = 18;
const V4_KEY_PROTO: usize = 20;

/// V6 key offsets (48 bytes).
const V6_KEY_CGROUP_ID: usize = 0;
const V6_KEY_PEER_ADDRESS: usize = 8;
const V6_KEY_PEER_PORT: usize = 24;
const V6_KEY_LOCAL_ADDRESS: usize = 26;
const V6_KEY_LOCAL_PORT: usize = 42;
const V6_KEY_PROTO: usize = 44;

/// Emission thresholds. They mirror the egress aggregation contract (§6.5): at
/// most one event per aggregate per epoch second, and only when the delta since
/// the previous event crosses one of the thresholds.
const FLOW_EMIT_BYTES: u64 = 64 * 1024;
const FLOW_EMIT_PACKETS: u32 = 256;
const NS_PER_SECOND: u64 = 1_000_000_000;

#[map]
static INGRESS_FLOW_AGG_V4: LruPerCpuHashMap<[u8; 32], [u8; 40]> =
    LruPerCpuHashMap::with_max_entries(MAX_INGRESS_FLOW_AGG_ENTRIES, 0);

#[map]
static INGRESS_FLOW_AGG_V6: LruPerCpuHashMap<[u8; 48], [u8; 40]> =
    LruPerCpuHashMap::with_max_entries(MAX_INGRESS_FLOW_AGG_ENTRIES, 0);

/// Bounded parse-failure counter. One slot per CPU; the core sums it for
/// `STYX_INGRESS_STATUS`. A failed parse only loses one aggregate update, never
/// the packet and never the capability claim.
#[map]
static INGRESS_FLOW_READ_FAILURES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Ingress records queued into the shared `FLOW_EVENTS` ring. This is the
/// audit trail behind the phase-2 "RX observation is really producing records"
/// status field; the shared `FLOW_EVENTS_EMITTED` counter additionally covers
/// both directions for the existing flow-health wire.
#[map]
static INGRESS_FLOW_EVENTS_EMITTED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// `cgroup_skb/ingress` RX flow observer.
///
/// Observe-only by construction: the single exit value is
/// [`CGROUP_SKB_ACT_PASS`], so no code path can drop or redirect a packet. The
/// StyX global switch gates only the observation, never the pass verdict.
#[cgroup_skb(ingress)]
pub fn gedefense_ingress_flow(ctx: SkBuffContext) -> i32 {
    // The same switch as the egress flow telemetry: an operator who disables
    // StyX logging never collects RX flows silently. When off, the only cost of
    // the attached program is one array lookup.
    if crate::styx_egress::styx_flow_observation_enabled() {
        observe_ingress_flow(&ctx);
    }
    // 1 = pass at a cgroup_skb hook. There is no drop path in this program on
    // purpose (see CGROUP_SKB_ACT_PASS: TC_ACT_OK would be 0 = drop here).
    CGROUP_SKB_ACT_PASS
}

/// Parses one inbound packet and updates its aggregate. Kept as a BPF
/// subprogram (`#[inline(never)]`) so the parser/aggregation temporaries do not
/// join the tiny program frame; the caller stays at the 512-byte stack bound.
#[inline(never)]
fn observe_ingress_flow(ctx: &SkBuffContext) {
    let mut packet = crate::styx_egress::EgressPacket::zeroed();
    // Shared bounded L3/L4 parser (see module docs: at a cgroup_skb hook
    // skb->data starts at the network header, so this is the correct parser).
    if !crate::styx_egress::parse_egress_packet(ctx, &mut packet) {
        crate::util::increment_counter(&INGRESS_FLOW_READ_FAILURES);
        return;
    }
    // Phase-2 PCR is a TCP/UDP flow ratio. Fragments, ICMP and other L3
    // payloads carry no transport ports; they are intentionally outside the
    // flow model instead of being relabelled into a neutral aggregate.
    if packet.proto != STYX_PROTO_TCP && packet.proto != STYX_PROTO_UDP {
        return;
    }
    // `__cgroup_bpf_run_filter_skb` sets skb->sk for the run, so this is the
    // receiving socket's cgroup (the same identity the egress hook of the same
    // socket reports). 0 = attributable by no cgroup (kernel without cgroup v2
    // socket data); the record is still honest because the control plane treats
    // 0 as "unattributed by cgroup" and matches the rest of the tuple.
    let cgroup_id = unsafe { bpf_skb_cgroup_id(ctx.as_ptr().cast()) };
    match packet.family {
        NETWORK_FAMILY_V4 => {
            // The ingress packet's *source* is the remote peer the control
            // plane groups by; FlowEvent.dst therefore carries the peer (the
            // entity) and FlowEvent.src the local address, mirroring the egress
            // record where dst is always the remote entity.
            let mut key = [0u8; 32];
            key[V4_KEY_CGROUP_ID..V4_KEY_CGROUP_ID + 8].copy_from_slice(&cgroup_id.to_le_bytes());
            key[V4_KEY_PEER_ADDRESS..V4_KEY_PEER_ADDRESS + 4]
                .copy_from_slice(&packet.src[12..16]);
            key[V4_KEY_PEER_PORT..V4_KEY_PEER_PORT + 2]
                .copy_from_slice(&packet.src_port.to_be_bytes());
            key[V4_KEY_LOCAL_ADDRESS..V4_KEY_LOCAL_ADDRESS + 4]
                .copy_from_slice(&packet.dst[12..16]);
            key[V4_KEY_LOCAL_PORT..V4_KEY_LOCAL_PORT + 2]
                .copy_from_slice(&packet.dst_port.to_be_bytes());
            key[V4_KEY_PROTO] = packet.proto;
            observe_ingress_aggregate(
                &INGRESS_FLOW_AGG_V4,
                &key,
                ctx,
                &packet,
                cgroup_id,
            );
        }
        NETWORK_FAMILY_V6 => {
            let mut key = [0u8; 48];
            key[V6_KEY_CGROUP_ID..V6_KEY_CGROUP_ID + 8].copy_from_slice(&cgroup_id.to_le_bytes());
            key[V6_KEY_PEER_ADDRESS..V6_KEY_PEER_ADDRESS + NETWORK_ADDRESS_BYTES]
                .copy_from_slice(&packet.src);
            key[V6_KEY_PEER_PORT..V6_KEY_PEER_PORT + 2]
                .copy_from_slice(&packet.src_port.to_be_bytes());
            key[V6_KEY_LOCAL_ADDRESS..V6_KEY_LOCAL_ADDRESS + NETWORK_ADDRESS_BYTES]
                .copy_from_slice(&packet.dst);
            key[V6_KEY_LOCAL_PORT..V6_KEY_LOCAL_PORT + 2]
                .copy_from_slice(&packet.dst_port.to_be_bytes());
            key[V6_KEY_PROTO] = packet.proto;
            observe_ingress_aggregate(
                &INGRESS_FLOW_AGG_V6,
                &key,
                ctx,
                &packet,
                cgroup_id,
            );
        }
        // `parse_egress_packet` only constructs 4 or 6; keep the match total
        // without inventing a record for anything else.
        _ => crate::util::increment_counter(&INGRESS_FLOW_READ_FAILURES),
    }
}

/// Updates one per-CPU aggregate and emits at most one bounded `FlowEvent`.
///
/// Inlined into its caller: the BPF subprogram ABI passes at most five
/// arguments and this helper needs more; the caller frame plus this state stays
/// below the 512-byte eBPF stack limit (same reasoning as the egress helper).
#[inline(always)]
fn observe_ingress_aggregate<K>(
    map: &LruPerCpuHashMap<K, [u8; 40]>,
    key: &K,
    ctx: &SkBuffContext,
    packet: &crate::styx_egress::EgressPacket,
    cgroup_id: u64,
) {
    let now = unsafe { bpf_ktime_get_ns() };
    // No task context is reliable at this hook: `current` is whatever task the
    // softirq/receive path happened to run on, not the socket owner. The record
    // therefore carries pid=0 and an empty comm (both wire-valid) instead of a
    // random unrelated PID/comm. Attribution uses the socket's cgroup + tuple,
    // which are the identities the kernel actually guarantees here.
    let pid = 0u32;
    if let Some(value_ptr) = map.get_ptr_mut(key) {
        // SAFETY: the per-CPU map owns this value for the current CPU and no
        // other CPU can observe the in-place mutation until the program returns.
        let value = unsafe { &mut *value_ptr };
        let last_ts = read_agg_u64(value, FLOW_AGG_LAST_TS);
        let rx_bytes = read_agg_u64(value, FLOW_AGG_RX)
            .saturating_add(u64::from(packet.packet_len));
        let packets = read_agg_u32(value, FLOW_AGG_PACKETS).saturating_add(1);
        write_agg_u64(value, FLOW_AGG_LAST_TS, now);
        write_agg_u64(value, FLOW_AGG_RX, rx_bytes);
        write_agg_u32(value, FLOW_AGG_PACKETS, packets);
        value[FLOW_AGG_TCP_FLAGS] |= packet.tcp_flags;
        value[FLOW_AGG_VERDICT] = STYX_VERDICT_ALLOW;
        let second_changed = last_ts / NS_PER_SECOND != now / NS_PER_SECOND;
        if !second_changed && rx_bytes < FLOW_EMIT_BYTES && packets < FLOW_EMIT_PACKETS {
            return;
        }
        let stored_pid = read_agg_u32(value, FLOW_AGG_PID);
        let tcp_flags = value[FLOW_AGG_TCP_FLAGS];
        emit_ingress_flow_event(
            ctx,
            cgroup_id,
            packet,
            rx_bytes,
            packets,
            tcp_flags,
            stored_pid,
            now,
        );
        // Start a new aggregation window: the next event reports the delta.
        write_agg_u64(value, FLOW_AGG_FIRST_TS, now);
        write_agg_u64(value, FLOW_AGG_RX, 0);
        write_agg_u32(value, FLOW_AGG_PACKETS, 0);
        value[FLOW_AGG_TCP_FLAGS] = packet.tcp_flags;
    } else {
        // First packet of a new aggregate: emit immediately and start the window
        // at zero so the next event needs a threshold (same contract as egress).
        let mut value = [0u8; 40];
        write_agg_u64(&mut value, FLOW_AGG_FIRST_TS, now);
        write_agg_u64(&mut value, FLOW_AGG_LAST_TS, now);
        write_agg_u64(&mut value, FLOW_AGG_RX, 0);
        write_agg_u32(&mut value, FLOW_AGG_PACKETS, 0);
        write_agg_u32(&mut value, FLOW_AGG_PID, pid);
        value[FLOW_AGG_TCP_FLAGS] = packet.tcp_flags;
        value[FLOW_AGG_VERDICT] = STYX_VERDICT_ALLOW;
        if map.insert(key, &value, 0).is_ok() {
            emit_ingress_flow_event(
                ctx,
                cgroup_id,
                packet,
                u64::from(packet.packet_len),
                1,
                packet.tcp_flags,
                pid,
                now,
            );
        }
    }
}

/// Emits one native-endian 104-byte `FlowEvent` with `direction = INGRESS`.
///
/// The record is written directly into the ring-buffer reservation (a 104-byte
/// stack copy would together with the parse state exceed the 512-byte eBPF
/// stack) exactly like the egress emitter. `rx_bytes` is the inbound delta,
/// `tx_bytes` is 0, verdict is ALLOW (this program cannot deny), `dst` is the
/// remote peer and `src` the local address.
///
/// Inlined into its caller for the same BPF-subprogram argument-count reason as
/// [`observe_ingress_aggregate`].
#[inline(always)]
fn emit_ingress_flow_event(
    ctx: &SkBuffContext,
    cgroup_id: u64,
    packet: &crate::styx_egress::EgressPacket,
    rx_bytes: u64,
    packets: u32,
    tcp_flags: u8,
    pid: u32,
    ts_ns: u64,
) {
    if packets == 0 || ts_ns == 0 || rx_bytes == 0 {
        return;
    }
    // `decode_styx_flow_event` rejects family 4 with a non-canonical or
    // unspecified destination (which is the peer here); never produce such a
    // record.
    if packet.family == NETWORK_FAMILY_V4
        && packet.src[12..16] == [0u8, 0, 0, 0]
    {
        return;
    }
    if packet.family == NETWORK_FAMILY_V6
        && packet.src.iter().all(|byte| *byte == 0)
    {
        return;
    }
    let uid = unsafe { bpf_get_socket_uid(ctx.as_ptr().cast()) };
    // V6.3.0 AP-9 (S12): bulk flow telemetry passes the per-(class, cgroup,
    // uid) token bucket before a ring slot is reserved; the packet itself is
    // never dropped by this observer. The egress emitter performs the identical
    // check on the same class so one flooding cgroup cannot spend the flow
    // budget twice.
    if !telemetry_budget_allow(SEC_CRIT_BUCKET_FLOW, cgroup_id, uid) {
        telemetry_note_suppressed(SEC_CRIT_BUCKET_FLOW);
        return;
    }
    if let Some(mut entry) = crate::maps::FLOW_EVENTS.reserve::<FlowEvent>(0) {
        let event = entry.as_mut_ptr();
        // SAFETY: the reservation is exactly `size_of::<FlowEvent>()` bytes and
        // aligned for the struct. Every field is written through the raw pointer
        // before the entry is submitted; no reference to uninitialised memory is
        // created and the entry is submitted before this scope ends.
        unsafe {
            core::ptr::addr_of_mut!((*event).cgroup_id).write(cgroup_id);
            core::ptr::addr_of_mut!((*event).ts_ns).write(ts_ns);
            core::ptr::addr_of_mut!((*event).tx_bytes).write(0);
            core::ptr::addr_of_mut!((*event).rx_bytes).write(rx_bytes);
            core::ptr::addr_of_mut!((*event).pid).write(pid);
            core::ptr::addr_of_mut!((*event).uid).write(uid);
            // dst = remote peer (the entity), src = local address.
            core::ptr::addr_of_mut!((*event).dst).write(packet.src);
            core::ptr::addr_of_mut!((*event).src).write(packet.dst);
            // dst_port = remote port, src_port = local port (remote endpoint
            // first, matching the egress record where dst is the remote entity).
            core::ptr::addr_of_mut!((*event).dst_port).write(packet.src_port);
            core::ptr::addr_of_mut!((*event).src_port).write(packet.dst_port);
            core::ptr::addr_of_mut!((*event).packets).write(packets);
            core::ptr::addr_of_mut!((*event).proto).write(packet.proto);
            core::ptr::addr_of_mut!((*event).family).write(packet.family);
            core::ptr::addr_of_mut!((*event).direction).write(STYX_DIR_INGRESS);
            core::ptr::addr_of_mut!((*event).tcp_flags).write(
                if packet.proto == STYX_PROTO_TCP {
                    tcp_flags
                } else {
                    0
                },
            );
            core::ptr::addr_of_mut!((*event).verdict).write(STYX_VERDICT_ALLOW);
            core::ptr::addr_of_mut!((*event).reserved).write([0u8; 3]);
            // pid=0 (see observe_ingress_aggregate): an honest empty comm is
            // better than the comm of whatever task the softirq interrupted.
            core::ptr::addr_of_mut!((*event).comm).write([0u8; 16]);
        }
        entry.submit(0);
        crate::util::increment_counter(&crate::maps::FLOW_EVENTS_EMITTED);
        crate::util::increment_counter(&INGRESS_FLOW_EVENTS_EMITTED);
    } else {
        // Ring full: visibility loss is counted in the shared health counter and
        // the local one; the packet still passes (this program never drops).
        crate::util::increment_counter(&crate::maps::FLOW_RING_DROPS);
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

/// Compile-time ABI guards: the key/value sizes and the wire size are shared
/// with userspace, so a change here must fail the build, not a live probe.
const _: () = assert!(core::mem::size_of::<FlowEvent>() == 104);
const _: () = assert!(V4_KEY_PROTO < 32 && V4_KEY_PROTO + 1 == 21);
const _: () = assert!(V6_KEY_PROTO < 48 && V6_KEY_PROTO + 1 == 45);
const _: () = assert!(FLOW_AGG_VERDICT < 40 && FLOW_AGG_VERDICT + 1 == 34);
// `INGRESS_HEALTH_KEY` is the per-CPU counter key; keep it referenced so the
// documentation constant cannot drift silently.
const _: () = assert!(INGRESS_HEALTH_KEY == 0);

#[cfg(test)]
mod tests {
    // The eBPF crate is `no_std` and only builds for the BPF target; the pure
    // layout assertions above are the host-visible contract. Userspace-side
    // decode/round-trip tests live in `gedefense-common` and `gedefense-core`.
}
