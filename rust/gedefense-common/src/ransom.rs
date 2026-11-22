//! M2.2 (6.2.0): shared wire contract and bounded policy constants of the
//! eBPF ransomware/rename-storm sensor.
//!
//! Rust half of the sensor ABI: the eBPF object (`rust/gedefense-ebpf/src/ransom.rs`)
//! emits fixed 64-byte [`RansomEvent`] records into `RANSOM_EVENTS`; the core
//! decodes them with [`decode_ransom_event`] (reject, never repair), freezes the
//! whole process group with `SIGSTOP`, and forwards an 8-field text record to
//! the control plane (which is adjusted separately).
//!
//! Native endian, `repr(C)`, exactly [`RANSOM_EVENT_WIRE_BYTES`] bytes. The
//! sensor is *reversible by design*: the kernel-side action is a decision hint,
//! the freeze is `SIGSTOP` and only the control plane escalates with
//! `XDR_KILL_TREE`.
//!
//! Bounded budgets shared by producer and consumers: one per-TGID tracker entry
//! is `[u64; 8]`, at most [`RANSOM_TRACK_ENTRIES`] trackers (LRU), at most
//! [`RANSOM_TRUSTED_COMM_ENTRIES`] trusted-comm exemptions. Signal A fires at
//! [`RANSOM_ENTROPY_DISTINCT_THRESHOLD`] distinct high-entropy inode writes
//! inside [`RANSOM_ENTROPY_WINDOW_NS`]; Signal B at
//! [`RANSOM_META_THRESHOLD`] rename/unlink operations inside
//! [`RANSOM_META_WINDOW_NS`]. The entropy estimator is integer-only: it builds
//! a 256-bit distinct-byte bitmap from at most [`RANSOM_SAMPLE_BYTES`] sampled
//! bytes and compares its population count with
//! [`RANSOM_ENTROPY_MIN_DISTINCT`].

/// Wire size of one [`RansomEvent`].
pub const RANSOM_EVENT_WIRE_BYTES: usize = 64;

/// Sensor signal identifiers (`signal` byte of [`RansomEvent`]).
pub const RANSOM_SIGNAL_ENTROPY_BURST: u8 = 1;
pub const RANSOM_SIGNAL_RENAME_STORM: u8 = 2;
/// Highest valid signal value.
pub const RANSOM_SIGNAL_MAX: u8 = RANSOM_SIGNAL_RENAME_STORM;

/// Action byte: the kernel only ever audits (1); the core owns the response.
pub const RANSOM_ACTION_AUDIT: u8 = 1;

/// `RANSOM_STATE` word layout (ABI 1): epoch 0..31, armed bit 32, magic 40..47,
/// ABI 48..55. Default 0 (kernel map zero-init) = disarmed = no event.
pub const RANSOM_STATE_MAGIC: u8 = 0x52;
pub const RANSOM_STATE_ABI: u8 = 1;
pub const RANSOM_STATE_ARMED_SHIFT: u64 = 32;
pub const RANSOM_STATE_MAGIC_SHIFT: u64 = 40;
pub const RANSOM_STATE_ABI_SHIFT: u64 = 48;
pub const RANSOM_STATE_BYTE_MASK: u64 = 0xff;

/// One entropy window (Signal A).
pub const RANSOM_ENTROPY_WINDOW_NS: u64 = 500_000_000;
/// Distinct high-entropy inode writes that trigger Signal A.
pub const RANSOM_ENTROPY_DISTINCT_THRESHOLD: u64 = 15;
/// Bytes sampled from the write buffer for the integer entropy estimate.
pub const RANSOM_SAMPLE_BYTES: usize = 64;
/// Distinct byte values (of 256) that make a sample "high entropy".
pub const RANSOM_ENTROPY_MIN_DISTINCT: u32 = 40;
/// One metadata window (Signal B).
pub const RANSOM_META_WINDOW_NS: u64 = 250_000_000;
/// Rename/unlink operations that trigger Signal B.
pub const RANSOM_META_THRESHOLD: u64 = 25;
/// Per-TGID tracker capacity (LRU); bounded kernel memory.
pub const RANSOM_TRACK_ENTRIES: u32 = 4_096;
/// Trusted-comm exemption capacity (package managers, compilers, snapshots).
pub const RANSOM_TRUSTED_COMM_ENTRIES: u32 = 128;
/// `RANSOM_EVENTS` ring size (1 MiB = 16384 queued 64-byte records).
pub const RANSOM_EVENT_RING_BYTES: u32 = 1 << 20;

/// One ransomware/rename-storm sample emitted by the eBPF sensor.
///
/// Byte layout (native endian, size 64): `ts_ns` 0, `cgroup_id` 8, `tgid` 16,
/// `tid` 20, `uid` 24, `gid` 28, `count` 32 (distinct inodes or operations),
/// `window_ms` 36, `signal` 40, `action` 41, `comm` 42 (16 NUL-padded bytes),
/// `reserved` 58 (6 zero bytes). `tgid` is the process-group leader candidate;
/// the core resolves the real PGID from `/proc/<tgid>/stat`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RansomEvent {
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub tgid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub count: u32,
    pub window_ms: u32,
    pub signal: u8,
    pub action: u8,
    pub comm: [u8; 16],
    pub reserved: [u8; 6],
}

/// Decodes one fixed-size sensor record. Returns `None` for every record the
/// producer cannot have emitted: wrong length, unknown signal, non-audit
/// action, zero `ts_ns`/`tgid`, non-zero reserved bytes, or a `comm` without
/// NUL padding.
pub fn decode_ransom_event(bytes: &[u8]) -> Option<RansomEvent> {
    if bytes.len() != RANSOM_EVENT_WIRE_BYTES {
        return None;
    }
    let ts_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let cgroup_id = u64::from_ne_bytes(bytes[8..16].try_into().ok()?);
    let tgid = u32::from_ne_bytes(bytes[16..20].try_into().ok()?);
    let tid = u32::from_ne_bytes(bytes[20..24].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[24..28].try_into().ok()?);
    let gid = u32::from_ne_bytes(bytes[28..32].try_into().ok()?);
    let count = u32::from_ne_bytes(bytes[32..36].try_into().ok()?);
    let window_ms = u32::from_ne_bytes(bytes[36..40].try_into().ok()?);
    let signal = bytes[40];
    let action = bytes[41];
    let comm: [u8; 16] = bytes[42..58].try_into().ok()?;
    let reserved: [u8; 6] = bytes[58..64].try_into().ok()?;
    if !matches!(signal, RANSOM_SIGNAL_ENTROPY_BURST | RANSOM_SIGNAL_RENAME_STORM)
        || action != RANSOM_ACTION_AUDIT
        || ts_ns == 0
        || tgid == 0
        || reserved != [0u8; 6]
        || !comm_is_nul_padded(&comm)
    {
        return None;
    }
    Some(RansomEvent {
        ts_ns,
        cgroup_id,
        tgid,
        tid,
        uid,
        gid,
        count,
        window_ms,
        signal,
        action,
        comm,
        reserved,
    })
}

/// A producer `comm` is NUL-terminated and NUL-padded (`bpf_get_current_comm`
/// zero-fills the rest of the 16-byte task name).
fn comm_is_nul_padded(comm: &[u8; 16]) -> bool {
    let mut padded = false;
    for &byte in comm.iter() {
        if padded {
            if byte != 0 {
                return false;
            }
        } else if byte == 0 {
            padded = true;
        }
    }
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RansomEvent {
        RansomEvent {
            ts_ns: 987_654_321,
            cgroup_id: 3149,
            tgid: 4242,
            tid: 4243,
            uid: 0,
            gid: 0,
            count: 15,
            window_ms: 500,
            signal: RANSOM_SIGNAL_ENTROPY_BURST,
            action: RANSOM_ACTION_AUDIT,
            comm: *b"encryptor\0\0\0\0\0\0\0",
            reserved: [0; 6],
        }
    }

    fn encode(event: &RansomEvent) -> [u8; RANSOM_EVENT_WIRE_BYTES] {
        let mut raw = [0u8; RANSOM_EVENT_WIRE_BYTES];
        raw[0..8].copy_from_slice(&event.ts_ns.to_ne_bytes());
        raw[8..16].copy_from_slice(&event.cgroup_id.to_ne_bytes());
        raw[16..20].copy_from_slice(&event.tgid.to_ne_bytes());
        raw[20..24].copy_from_slice(&event.tid.to_ne_bytes());
        raw[24..28].copy_from_slice(&event.uid.to_ne_bytes());
        raw[28..32].copy_from_slice(&event.gid.to_ne_bytes());
        raw[32..36].copy_from_slice(&event.count.to_ne_bytes());
        raw[36..40].copy_from_slice(&event.window_ms.to_ne_bytes());
        raw[40] = event.signal;
        raw[41] = event.action;
        raw[42..58].copy_from_slice(&event.comm);
        raw[58..64].copy_from_slice(&event.reserved);
        raw
    }

    #[test]
    fn wire_layout_and_roundtrip_match_the_abi() {
        use core::mem::{align_of, offset_of, size_of};
        assert_eq!(size_of::<RansomEvent>(), RANSOM_EVENT_WIRE_BYTES);
        assert_eq!(align_of::<RansomEvent>(), 8);
        assert_eq!(offset_of!(RansomEvent, ts_ns), 0);
        assert_eq!(offset_of!(RansomEvent, cgroup_id), 8);
        assert_eq!(offset_of!(RansomEvent, tgid), 16);
        assert_eq!(offset_of!(RansomEvent, tid), 20);
        assert_eq!(offset_of!(RansomEvent, uid), 24);
        assert_eq!(offset_of!(RansomEvent, gid), 28);
        assert_eq!(offset_of!(RansomEvent, count), 32);
        assert_eq!(offset_of!(RansomEvent, window_ms), 36);
        assert_eq!(offset_of!(RansomEvent, signal), 40);
        assert_eq!(offset_of!(RansomEvent, action), 41);
        assert_eq!(offset_of!(RansomEvent, comm), 42);
        assert_eq!(offset_of!(RansomEvent, reserved), 58);
        assert_eq!(offset_of!(RansomEvent, reserved) + size_of::<[u8; 6]>(), 64);
        let event = sample();
        assert_eq!(decode_ransom_event(&encode(&event)), Some(event));
    }

    #[test]
    fn every_signal_is_decodable() {
        for signal in [RANSOM_SIGNAL_ENTROPY_BURST, RANSOM_SIGNAL_RENAME_STORM] {
            let mut event = sample();
            event.signal = signal;
            assert_eq!(decode_ransom_event(&encode(&event)), Some(event));
        }
    }

    #[test]
    fn rejects_records_the_producer_cannot_have_emitted() {
        let raw = encode(&sample());
        for len in [0usize, 1, 32, 63] {
            assert!(decode_ransom_event(&raw[..len]).is_none(), "{len}");
        }
        let mut longer = [0u8; 128];
        longer[..RANSOM_EVENT_WIRE_BYTES].copy_from_slice(&raw);
        assert!(decode_ransom_event(&longer[..65]).is_none());
        let mut bad = sample();
        bad.signal = 3;
        assert!(decode_ransom_event(&encode(&bad)).is_none());
        bad = sample();
        bad.action = 2;
        assert!(decode_ransom_event(&encode(&bad)).is_none());
        bad = sample();
        bad.ts_ns = 0;
        assert!(decode_ransom_event(&encode(&bad)).is_none());
        bad = sample();
        bad.tgid = 0;
        assert!(decode_ransom_event(&encode(&bad)).is_none());
        bad = sample();
        bad.reserved = [1, 0, 0, 0, 0, 0];
        assert!(decode_ransom_event(&encode(&bad)).is_none());
        bad = sample();
        bad.comm = [b'x'; 16];
        assert!(decode_ransom_event(&encode(&bad)).is_none());
    }

    #[test]
    fn policy_constants_are_the_documented_budgets() {
        assert_eq!(RANSOM_ENTROPY_WINDOW_NS, 500_000_000);
        assert_eq!(RANSOM_ENTROPY_DISTINCT_THRESHOLD, 15);
        assert_eq!(RANSOM_META_WINDOW_NS, 250_000_000);
        assert_eq!(RANSOM_META_THRESHOLD, 25);
        assert_eq!(RANSOM_SAMPLE_BYTES, 64);
        assert!(RANSOM_ENTROPY_MIN_DISTINCT < RANSOM_SAMPLE_BYTES as u32);
        assert_eq!(RANSOM_EVENT_RING_BYTES, 1 << 20);
        assert_eq!(RANSOM_EVENT_RING_BYTES as usize / RANSOM_EVENT_WIRE_BYTES, 16_384);
    }
}
