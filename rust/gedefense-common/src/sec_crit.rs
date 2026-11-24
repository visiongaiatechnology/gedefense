//! V6.3.0 AP-9 (S12) — high-priority security evidence ring contract and the
//! kernel-token-bucket math shared by every telemetry emitter.
//!
//! The `SEC_CRIT_EVENTS` ring is independent of the bulk telemetry rings
//! (`EXEC_ARGV_EVENTS`, `KERNEL_PROBE_EVENTS`, `FLOW_EVENTS`): credential,
//! attach-time eBPF, LKM, cross-view/hidden and self-tamper evidence can never
//! be displaced by exec/log spam. Bulk emitters first pass through the
//! per-(class, cgroup, uid) token bucket below; only an exhausted bucket is
//! reported (aggregated), never silent blindness.
//!
//! Fixed `#[repr(C)]` 64-byte record with a rejecting decoder. Native endian.

/// Wire size of one [`SecCritEvent`].
pub const SEC_CRIT_EVENT_WIRE_BYTES: usize = 64;
/// `SEC_CRIT_EVENTS` ring size: 256 KiB = 4096 queued 64-byte records.
pub const SEC_CRIT_EVENT_RING_BYTES: u32 = 1 << 18;
/// Maximum records drained from the ring per VGT3 response.
pub const SEC_CRIT_MAX_EVENTS_PER_DRAIN: usize = 16;
/// Maximum text payload per drain (bounded VGT3 response).
pub const SEC_CRIT_MAX_DRAIN_PAYLOAD_BYTES: usize = 4096;

/// Source families carried in `source`.
pub const SEC_CRIT_SOURCE_CRED_GUARD: u8 = 1;
pub const SEC_CRIT_SOURCE_BPF_GUARD: u8 = 2;
pub const SEC_CRIT_SOURCE_KERNEL_HOOKS: u8 = 3;
pub const SEC_CRIT_SOURCE_CROSS_VIEW: u8 = 4;
pub const SEC_CRIT_SOURCE_SELF_TAMPER: u8 = 5;
pub const SEC_CRIT_SOURCE_RANSOM: u8 = 6;
pub const SEC_CRIT_SOURCE_PERSISTENCE: u8 = 7;
pub const SEC_CRIT_SOURCE_MAX: u8 = SEC_CRIT_SOURCE_PERSISTENCE;

/// Action tokens: observe-only evidence vs. a kernel-enforced decision.
pub const SEC_CRIT_ACTION_OBSERVE: u8 = 1;
pub const SEC_CRIT_ACTION_ENFORCE: u8 = 2;
pub const SEC_CRIT_ACTION_MAX: u8 = SEC_CRIT_ACTION_ENFORCE;

/// `SEC_CRIT_STATE` word layout (ABI 1): epoch 0..31, armed bit 32,
/// magic 40..47 (`0x53`), ABI 48..55. A zero/absent word means "not armed".
pub const SEC_CRIT_STATE_MAGIC: u8 = 0x53;
pub const SEC_CRIT_STATE_ABI: u8 = 1;
pub const SEC_CRIT_STATE_ARMED_SHIFT: u64 = 32;
pub const SEC_CRIT_STATE_MAGIC_SHIFT: u64 = 40;
pub const SEC_CRIT_STATE_ABI_SHIFT: u64 = 48;
pub const SEC_CRIT_STATE_BYTE_MASK: u64 = 0xff;

/// Token-bucket class: bulk exec/argv capture.
pub const SEC_CRIT_BUCKET_EXEC_ARGV: u8 = 1;
/// Token-bucket class: kernel probe telemetry (ptrace/openat/...).
pub const SEC_CRIT_BUCKET_KERNEL_PROBE: u8 = 2;
/// Token-bucket class: network flow telemetry (egress + ingress).
pub const SEC_CRIT_BUCKET_FLOW: u8 = 3;
/// Token-bucket class: DNS capture.
pub const SEC_CRIT_BUCKET_DNS: u8 = 4;
pub const SEC_CRIT_BUCKET_MAX: u8 = SEC_CRIT_BUCKET_DNS;

/// Bucket capacity and refill rate (tokens per second) for one class
/// (class, cgroup, uid) key. Sized so a single flooding cgroup is throttled
/// while normal telemetry is never affected.
pub const SEC_CRIT_BUCKET_CAPACITY: u64 = 512;
pub const SEC_CRIT_BUCKET_REFILL_PER_SECOND: u64 = 512;

/// `TELEMETRY_FLOOD_BUCKETS` key bytes: class u8 + 3 zero + cgroup u64 (LE at
/// offset 8) + uid u32 (LE at offset 16) + 4 zero. Fixed, zero-padded.
pub const SEC_CRIT_BUCKET_KEY_BYTES: usize = 24;
/// `TELEMETRY_FLOOD_BUCKETS` value bytes: tokens u64, last_refill_ns u64,
/// suppressed u32, reserved u32 (zero).
pub const SEC_CRIT_BUCKET_VALUE_BYTES: usize = 24;
/// Maximum tracked flood buckets (bounded kernel memory).
pub const SEC_CRIT_BUCKET_ENTRIES: u32 = 4096;

/// Counter lanes of `SEC_CRIT_COUNTERS` (PerCpuArray<u64>).
pub const SEC_CRIT_COUNTER_EMITTED: u32 = 0;
pub const SEC_CRIT_COUNTER_RING_DROPS: u32 = 1;
pub const SEC_CRIT_COUNTER_REFUSED_UNARMED: u32 = 2;
pub const SEC_CRIT_COUNTER_READ_FAILURES: u32 = 3;
pub const SEC_CRIT_COUNTER_SUPPRESSED: u32 = 4;
pub const SEC_CRIT_COUNTER_LANES: u32 = 5;

/// One high-priority security record (see module docs for the byte layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecCritEvent {
    pub ts_ns: u64,
    pub source: u8,
    pub kind: u8,
    pub action: u8,
    pub reserved: u8,
    pub detail_code: u32,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub dev: u32,
    pub ino: u64,
    pub comm: [u8; 16],
    pub extra: [u8; 8],
}

const _: () = assert!(core::mem::size_of::<SecCritEvent>() == SEC_CRIT_EVENT_WIRE_BYTES);

/// True when `bytes` is exactly one NUL-terminated, printable `comm` slot. The
/// kernel task-name helper always NUL-terminates within 16 bytes, so a full
/// 16-byte printable slot without a terminator is a producer-impossible record.
fn comm_is_padded(comm: &[u8; 16]) -> bool {
    let mut ended = false;
    for byte in comm {
        if *byte == 0 {
            ended = true;
        } else if ended || !(0x20..=0x7e).contains(byte) {
            return false;
        }
    }
    ended && comm[0] != 0
}

/// Rejecting decoder: any record the producer cannot have emitted is refused
/// (wrong length, zero timestamp/pid/tgid, unknown source/action/max kind,
/// non-zero reserved byte, unpadded `comm`). Never repairs.
pub fn decode_sec_crit_event(bytes: &[u8]) -> Option<SecCritEvent> {
    if bytes.len() != SEC_CRIT_EVENT_WIRE_BYTES {
        return None;
    }
    let ts_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let source = bytes[8];
    let kind = bytes[9];
    let action = bytes[10];
    let reserved = bytes[11];
    let detail_code = u32::from_ne_bytes(bytes[12..16].try_into().ok()?);
    let pid = u32::from_ne_bytes(bytes[16..20].try_into().ok()?);
    let tgid = u32::from_ne_bytes(bytes[20..24].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[24..28].try_into().ok()?);
    let dev = u32::from_ne_bytes(bytes[28..32].try_into().ok()?);
    let ino = u64::from_ne_bytes(bytes[32..40].try_into().ok()?);
    let comm: [u8; 16] = bytes[40..56].try_into().ok()?;
    let extra: [u8; 8] = bytes[56..64].try_into().ok()?;
    if ts_ns == 0
        || pid == 0
        || tgid == 0
        || kind == 0
        || source == 0
        || source > SEC_CRIT_SOURCE_MAX
        || action == 0
        || action > SEC_CRIT_ACTION_MAX
        || reserved != 0
        || !comm_is_padded(&comm)
    {
        return None;
    }
    Some(SecCritEvent {
        ts_ns,
        source,
        kind,
        action,
        reserved,
        detail_code,
        pid,
        tgid,
        uid,
        dev,
        ino,
        comm,
        extra,
    })
}

/// Canonical encoder (exact inverse of the decoder for every valid record).
pub fn encode_sec_crit_event(event: &SecCritEvent) -> [u8; SEC_CRIT_EVENT_WIRE_BYTES] {
    let mut raw = [0u8; SEC_CRIT_EVENT_WIRE_BYTES];
    raw[0..8].copy_from_slice(&event.ts_ns.to_ne_bytes());
    raw[8] = event.source;
    raw[9] = event.kind;
    raw[10] = event.action;
    raw[11] = 0;
    raw[12..16].copy_from_slice(&event.detail_code.to_ne_bytes());
    raw[16..20].copy_from_slice(&event.pid.to_ne_bytes());
    raw[20..24].copy_from_slice(&event.tgid.to_ne_bytes());
    raw[24..28].copy_from_slice(&event.uid.to_ne_bytes());
    raw[28..32].copy_from_slice(&event.dev.to_ne_bytes());
    raw[32..40].copy_from_slice(&event.ino.to_ne_bytes());
    raw[40..56].copy_from_slice(&event.comm);
    raw[56..64].copy_from_slice(&event.extra);
    raw
}

/// Builds a zero-padded `comm` slot from a bounded task-name prefix.
pub fn sec_crit_comm(name: &[u8]) -> [u8; 16] {
    let mut comm = [0u8; 16];
    let limit = name.len().min(15);
    comm[..limit].copy_from_slice(&name[..limit]);
    comm
}

/// Token-bucket step shared by the eBPF helper and the unit tests.
///
/// Pure integer math (no floats, saturating): refill `tokens` by
/// `elapsed_seconds * refill_per_second`, cap at `capacity`, then consume one
/// token. Returns `(new_tokens, new_last_refill_ns, allowed)`.
pub fn telemetry_bucket_step(
    tokens: u64,
    last_refill_ns: u64,
    now_ns: u64,
    capacity: u64,
    refill_per_second: u64,
) -> (u64, u64, bool) {
    if capacity == 0 {
        return (0, now_ns, false);
    }
    if now_ns < last_refill_ns {
        // Clock went backwards: rebase without granting free tokens.
        return (tokens.min(capacity), now_ns, false);
    }
    let elapsed_ns = now_ns - last_refill_ns;
    let elapsed_seconds = elapsed_ns / 1_000_000_000;
    let refill = elapsed_seconds.saturating_mul(refill_per_second);
    let current = tokens.saturating_add(refill).min(capacity);
    if current == 0 {
        return (0, now_ns, false);
    }
    (current - 1, now_ns, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;

    fn sample() -> SecCritEvent {
        SecCritEvent {
            ts_ns: 1_700_000_000_000_000_000,
            source: SEC_CRIT_SOURCE_CRED_GUARD,
            kind: 3,
            action: SEC_CRIT_ACTION_ENFORCE,
            reserved: 0,
            detail_code: 13,
            pid: 4242,
            tgid: 4242,
            uid: 0,
            dev: 8,
            ino: 123_456,
            comm: sec_crit_comm(b"fake_sshd"),
            extra: [0u8; 8],
        }
    }

    #[test]
    fn wire_layout_matches_the_64_byte_contract() {
        assert_eq!(core::mem::size_of::<SecCritEvent>(), 64);
        assert_eq!(offset_of!(SecCritEvent, ts_ns), 0);
        assert_eq!(offset_of!(SecCritEvent, source), 8);
        assert_eq!(offset_of!(SecCritEvent, kind), 9);
        assert_eq!(offset_of!(SecCritEvent, action), 10);
        assert_eq!(offset_of!(SecCritEvent, reserved), 11);
        assert_eq!(offset_of!(SecCritEvent, detail_code), 12);
        assert_eq!(offset_of!(SecCritEvent, pid), 16);
        assert_eq!(offset_of!(SecCritEvent, tgid), 20);
        assert_eq!(offset_of!(SecCritEvent, uid), 24);
        assert_eq!(offset_of!(SecCritEvent, dev), 28);
        assert_eq!(offset_of!(SecCritEvent, ino), 32);
        assert_eq!(offset_of!(SecCritEvent, comm), 40);
        assert_eq!(offset_of!(SecCritEvent, extra), 56);
    }

    #[test]
    fn decoder_roundtrips_every_source_and_action() {
        for source in 1..=SEC_CRIT_SOURCE_MAX {
            for action in 1..=SEC_CRIT_ACTION_MAX {
                let mut event = sample();
                event.source = source;
                event.action = action;
                assert_eq!(decode_sec_crit_event(&encode_sec_crit_event(&event)), Some(event));
            }
        }
    }

    #[test]
    fn decoder_rejects_records_the_producer_cannot_have_emitted() {
        let encode = encode_sec_crit_event;
        let mut bad = sample();
        bad.ts_ns = 0;
        assert!(decode_sec_crit_event(&encode(&bad)).is_none());
        bad = sample();
        bad.pid = 0;
        assert!(decode_sec_crit_event(&encode(&bad)).is_none());
        bad = sample();
        bad.source = 0;
        assert!(decode_sec_crit_event(&encode(&bad)).is_none());
        bad = sample();
        bad.source = SEC_CRIT_SOURCE_MAX + 1;
        assert!(decode_sec_crit_event(&encode(&bad)).is_none());
        bad = sample();
        bad.action = 0;
        assert!(decode_sec_crit_event(&encode(&bad)).is_none());
        bad = sample();
        bad.kind = 0;
        assert!(decode_sec_crit_event(&encode(&bad)).is_none());
        // The canonical encoder always emits reserved=0; a hostile record with a
        // non-zero reserved byte is rejected directly on the wire.
        let mut hostile = encode_sec_crit_event(&sample());
        hostile[11] = 1;
        assert!(decode_sec_crit_event(&hostile).is_none());
        bad = sample();
        bad.comm = [b'x'; 16];
        assert!(decode_sec_crit_event(&encode(&bad)).is_none());
        bad = sample();
        bad.comm = [0u8; 16];
        assert!(decode_sec_crit_event(&encode(&bad)).is_none());
        for len in 0..64 {
            assert!(decode_sec_crit_event(&[0u8; 64][..len]).is_none(), "{len}");
        }
    }

    #[test]
    fn token_bucket_refills_caps_and_throttles() {
        // Empty bucket, no elapsed time: refused.
        assert_eq!(telemetry_bucket_step(0, 10, 10, 4, 2), (0, 10, false));
        // 1.5 s at 2 tokens/s from empty: refill 2, consume 1 -> (1, allowed).
        assert_eq!(
            telemetry_bucket_step(0, 0, 1_500_000_000, 4, 2),
            (1, 1_500_000_000, true)
        );
        // Refill is capped at capacity before the take.
        assert_eq!(
            telemetry_bucket_step(0, 0, 60_000_000_000, 4, 2),
            (3, 60_000_000_000, true)
        );
        // Backwards clock grants no free token.
        assert_eq!(telemetry_bucket_step(4, 10, 5, 4, 2), (4, 5, false));
        // Zero capacity is a closed bucket.
        assert_eq!(telemetry_bucket_step(10, 0, 1, 0, 2), (0, 1, false));
        // Saturating math never panics on huge elapsed times.
        let (tokens, _, allowed) = telemetry_bucket_step(u64::MAX, 0, u64::MAX, 8, u64::MAX);
        assert!(tokens <= 8 && allowed);
    }

    #[test]
    fn bucket_layout_bounds_are_consistent() {
        assert_eq!(SEC_CRIT_BUCKET_KEY_BYTES, 24);
        assert_eq!(SEC_CRIT_BUCKET_VALUE_BYTES, 24);
        assert!(SEC_CRIT_BUCKET_ENTRIES >= 1024);
        assert!(SEC_CRIT_EVENT_RING_BYTES as usize / SEC_CRIT_EVENT_WIRE_BYTES >= 4096);
        assert!(SEC_CRIT_MAX_DRAIN_PAYLOAD_BYTES > SEC_CRIT_MAX_EVENTS_PER_DRAIN * 64);
        assert_eq!(SEC_CRIT_COUNTER_LANES, 5);
    }
}
