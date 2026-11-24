//! V6.3.0 AP-2 — attach-time eBPF guard wire contract (`BPF_GUARD_EVENTS`).
//!
//! The kernel half (`rust/gedefense-ebpf/src/bpf_guard.rs`) observes BPF
//! program/map attachment at load time:
//!
//! - `lsm/bpf_prog` (`security_bpf_prog`): a BPF program received a program fd,
//! - `tp/syscalls/sys_enter_bpf`: the loader's `bpf()` command, program type and
//!   bounded attribute head (program *name* is intentionally not read: offset 48
//!   of `union bpf_attr` is outside the 16-byte bounded attribute read and the
//!   fixed 64-byte record has no name slot — the loader `comm` is the identity),
//! - BTF/kallsyms-gated `kprobe/check_helper_call`: the raw 32-bit helper id from
//!   `struct bpf_insn.imm` (UAPI-stable offset 4) read **before**
//!   `do_misc_fixups()`, aggregated into a per-program helper-risk bitmap.
//!
//! The guard is observe-only: it never denies, kills or changes kernel policy.
//! The control plane maps the records onto `XDR.BPF_ANOMALY` /
//! `XDR.BPF_ROOTKIT_HELPER` evidence.
//!
//! # Wire layout (64 bytes, native endian, `#[repr(C)]`)
//!
//! ```text
//! offset  size  field
//!      0     8  ts_ns: u64
//!      8     4  pid: u32            (loader thread id)
//!     12     4  tgid: u32           (loader process id)
//!     16     4  uid: u32
//!     20     1  action: u8          1=OBSERVED 2=HELPER_RISK 3=DENIED
//!     21     1  command: u8         UAPI `enum bpf_cmd` (bounded by u8)
//!     22     1  prog_type: u8       UAPI `enum bpf_prog_type` (0..=63)
//!     23     1  reserved: u8        must be zero
//!     24     4  helper_mask: u32    HELPER_BIT_* subset
//!     28     8  helper_ids: [u16;4] raw risk helper ids, zero-padded tail
//!     36     4  exe_dev: u32        loader executable `st_dev` (0 = unresolved)
//!     40     8  exe_ino: u64        loader executable `st_ino` (0 = unresolved)
//!     48    16  comm: [u8;16]       NUL-padded loader task name
//!     64
//! ```
//!
//! The enumerated contract in `docs/V6.3.0-PLAN.md` asks for a 64-byte record
//! with `helper_ids: [u32;4]` **and** an 8-byte `reserved2` tail. Those fields
//! alone (plus the mandatory identity/comm/timestamp fields) sum to 80 bytes, so
//! at least 16 bytes must go. The wire keeps every *semantic* field and uses
//! 16-bit helper-id lanes (helper ids are `< 1024`, encoded as `u16` and rejected
//! above `BPF_GUARD_MAX_HELPER_ID`); the `reserved2` tail is not needed because
//! this layout has no implicit padding. Every byte is either a named field or
//! the checked `reserved` byte, which is asserted by the wire-layout test.
//!
//! The decoder rejects rather than repairs: any record the kernel producer
//! cannot have emitted (length, action, zero timestamp/pid/tgid, unknown
//! program type range, non-zero reserved byte, helper-bit/mask inconsistency,
//! non-compact or out-of-range helper ids, half-null executable identity,
//! missing `comm` NUL padding) decodes to `None`.

/// Wire size of one [`BpfGuardEvent`].
pub const BPF_GUARD_EVENT_WIRE_BYTES: usize = 64;
/// `BPF_GUARD_EVENTS` ring size (64 KiB = 1024 queued 64-byte records).
pub const BPF_GUARD_EVENT_RING_BYTES: u32 = 64 * 1024;
/// Maximum records the core returns per drain (bounded control-plane response).
pub const BPF_GUARD_MAX_EVENTS_PER_DRAIN: usize = 16;
/// Maximum text payload bytes the core returns per drain.
pub const BPF_GUARD_MAX_DRAIN_PAYLOAD_BYTES: usize = 4096;
/// `BPF_GUARD_HELPER_BITMAP` capacity: per-loader helper-risk masks.
pub const BPF_GUARD_HELPER_BITMAP_ENTRIES: u32 = 4096;
/// `BPF_GUARD_HELPER_IDS` capacity: per-loader deduplicated raw helper ids.
pub const BPF_GUARD_HELPER_IDS_ENTRIES: u32 = 4096;
/// Number of raw helper-id lanes in one record (deduplicated, zero padded).
pub const BPF_GUARD_HELPER_IDS_PER_EVENT: usize = 4;
/// Bound for representable helper ids (control-plane contract; helper ids are
/// currently < 120 and the kernel's `__BPF_FUNC_MAX_ID` is far below this).
pub const BPF_GUARD_MAX_HELPER_ID: u16 = 1024;

/// `BPF_GUARD_STATE` word layout (ABI 1): epoch 0..31, armed bit 32, magic
/// 40..47, ABI 48..55. An absent/zero word means "not armed": every eBPF
/// program returns its fail-open verdict and emits nothing.
pub const BPF_GUARD_STATE_MAGIC: u8 = 0x42;
pub const BPF_GUARD_STATE_ABI: u8 = 1;
pub const BPF_GUARD_STATE_ARMED_SHIFT: u64 = 32;
pub const BPF_GUARD_STATE_MAGIC_SHIFT: u64 = 40;
pub const BPF_GUARD_STATE_ABI_SHIFT: u64 = 48;
pub const BPF_GUARD_STATE_BYTE_MASK: u64 = 0xff;

/// Event action: the kernel observed a BPF load/attach.
pub const BPF_GUARD_ACTION_OBSERVED: u8 = 1;
/// Event action: the verifier read a high-risk helper id for a loaded program.
pub const BPF_GUARD_ACTION_HELPER_RISK: u8 = 2;
/// Event action: reserved for a future kernel denial. The shipped guard is
/// observe-only and never emits it; the decoder accepts it as a closed value.
pub const BPF_GUARD_ACTION_DENIED: u8 = 3;

// UAPI `enum bpf_cmd` values (stable, `include/uapi/linux/bpf.h`).
pub const BPF_GUARD_COMMAND_MAP_CREATE: u8 = 0;
pub const BPF_GUARD_COMMAND_PROG_LOAD: u8 = 5;
pub const BPF_GUARD_COMMAND_PROG_ATTACH: u8 = 8;
pub const BPF_GUARD_COMMAND_RAW_TRACEPOINT_OPEN: u8 = 17;
pub const BPF_GUARD_COMMAND_LINK_CREATE: u8 = 28;

/// Unknown/unresolved program type. Kept representable because the LSM hook
/// cannot read `struct bpf_prog->type` without kernel-private offsets.
pub const BPF_GUARD_PROG_TYPE_UNKNOWN: u8 = 0;
/// Bounded representation of UAPI `enum bpf_prog_type`. Values above this are
/// not rejected as records by the decoder — they are clamped to
/// [`BPF_GUARD_PROG_TYPE_UNKNOWN`] by the kernel producer, so the wire contract
/// stays bounded while a future program type cannot invalidate a whole batch.
pub const BPF_GUARD_PROG_TYPE_MAX: u8 = 63;
/// Rootkit-relevant common program types (validated against the vendored aya
/// eBPF bindings / `include/uapi/linux/bpf.h`).
pub const BPF_GUARD_PROG_TYPE_KPROBE: u8 = 2;
pub const BPF_GUARD_PROG_TYPE_TRACEPOINT: u8 = 5;
pub const BPF_GUARD_PROG_TYPE_RAW_TRACEPOINT: u8 = 17;
/// `BPF_PROG_TYPE_TRACING` (fentry/fexit). The PLAN text says 26 for
/// `STRUCT_OPS`; the UAPI values are TRACING=26 and STRUCT_OPS=27, verified
/// against the vendored `aya-ebpf-bindings` (`BPF_PROG_TYPE_STRUCT_OPS: Type = 27`).
pub const BPF_GUARD_PROG_TYPE_TRACING: u8 = 26;
pub const BPF_GUARD_PROG_TYPE_STRUCT_OPS: u8 = 27;
pub const BPF_GUARD_PROG_TYPE_LSM: u8 = 29;
pub const BPF_GUARD_PROG_TYPE_SK_LOOKUP: u8 = 30;
pub const BPF_GUARD_PROG_TYPE_SYSCALL: u8 = 31;

// High-risk helper bits of the per-program bitmap.
/// `bpf_probe_write_user` (GhostMap/VoidLink class): helper id 36.
pub const HELPER_BIT_PROBE_WRITE_USER: u32 = 1 << 0;
/// `bpf_override_return` (LinkPro class): helper id 58.
pub const HELPER_BIT_OVERRIDE_RETURN: u32 = 1 << 1;
/// `bpf_send_signal` / `bpf_send_signal_thread` (Atomic Arch class): ids 109/117.
pub const HELPER_BIT_SEND_SIGNAL: u32 = 1 << 2;
/// Every helper bit the wire contract currently defines.
pub const BPF_GUARD_HELPER_MASK_ALL: u32 =
    HELPER_BIT_PROBE_WRITE_USER | HELPER_BIT_OVERRIDE_RETURN | HELPER_BIT_SEND_SIGNAL;

/// Stable helper ids (`include/uapi/linux/bpf.h` `__BPF_FUNC_MAPPER`), verified
/// against the vendored `aya-ebpf-bindings` constants:
/// `BPF_FUNC_probe_write_user = 36`, `BPF_FUNC_override_return = 58`,
/// `BPF_FUNC_send_signal = 109`, `BPF_FUNC_send_signal_thread = 117`.
pub const HELPER_ID_PROBE_WRITE_USER: u16 = 36;
pub const HELPER_ID_OVERRIDE_RETURN: u16 = 58;
pub const HELPER_ID_SEND_SIGNAL: u16 = 109;
pub const HELPER_ID_SEND_SIGNAL_THREAD: u16 = 117;

/// Maps one raw helper id to its risk bit; `0` for helpers that are not part of
/// the rootkit-relevant set. A plain `match` (no static slice table) keeps the
/// eBPF verifier happy: no `.data.rel.ro` pointer loads, no stack bitmasks.
#[inline(always)]
pub const fn helper_id_to_bit(helper_id: u32) -> u32 {
    match helper_id {
        36 => HELPER_BIT_PROBE_WRITE_USER,
        58 => HELPER_BIT_OVERRIDE_RETURN,
        109 | 117 => HELPER_BIT_SEND_SIGNAL,
        _ => 0,
    }
}

/// Packs the `BPF_GUARD_STATE` word (epoch | armed | magic | ABI).
#[inline(always)]
pub const fn bpf_guard_state_word(epoch: u32, armed: bool) -> u64 {
    (epoch as u64)
        | ((armed as u64) << BPF_GUARD_STATE_ARMED_SHIFT)
        | ((BPF_GUARD_STATE_MAGIC as u64) << BPF_GUARD_STATE_MAGIC_SHIFT)
        | ((BPF_GUARD_STATE_ABI as u64) << BPF_GUARD_STATE_ABI_SHIFT)
}

/// True only for an armed, magic/ABI-valid state word. Every eBPF program calls
/// this before any map read of the guard; absent/foreign/stale words are
/// disarmed (fail-open, no event).
#[inline(always)]
pub const fn bpf_guard_state_armed(word: u64) -> bool {
    let magic = ((word >> BPF_GUARD_STATE_MAGIC_SHIFT) & BPF_GUARD_STATE_BYTE_MASK) as u8;
    let abi = ((word >> BPF_GUARD_STATE_ABI_SHIFT) & BPF_GUARD_STATE_BYTE_MASK) as u8;
    let armed = (word >> BPF_GUARD_STATE_ARMED_SHIFT) & 1;
    magic == BPF_GUARD_STATE_MAGIC && abi == BPF_GUARD_STATE_ABI && armed == 1
}

/// One attach-time eBPF guard record (see the module-level wire layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfGuardEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub action: u8,
    pub command: u8,
    pub prog_type: u8,
    pub reserved: u8,
    pub helper_mask: u32,
    pub helper_ids: [u16; BPF_GUARD_HELPER_IDS_PER_EVENT],
    pub exe_dev: u32,
    pub exe_ino: u64,
    pub comm: [u8; 16],
}

// Compile-time coupling to the wire contract: a layout drift must fail the
// eBPF and core builds, not silently corrupt a ring record.
const _: () = assert!(core::mem::size_of::<BpfGuardEvent>() == BPF_GUARD_EVENT_WIRE_BYTES);
const _: () = assert!(core::mem::align_of::<BpfGuardEvent>() == 8);

/// Decodes one fixed-size guard record; `None` for every record the kernel
/// producer cannot have emitted.
pub fn decode_bpf_guard_event(bytes: &[u8]) -> Option<BpfGuardEvent> {
    if bytes.len() != BPF_GUARD_EVENT_WIRE_BYTES {
        return None;
    }
    let ts_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let pid = u32::from_ne_bytes(bytes[8..12].try_into().ok()?);
    let tgid = u32::from_ne_bytes(bytes[12..16].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[16..20].try_into().ok()?);
    let action = bytes[20];
    let command = bytes[21];
    let prog_type = bytes[22];
    let reserved = bytes[23];
    let helper_mask = u32::from_ne_bytes(bytes[24..28].try_into().ok()?);
    let helper_ids: [u16; BPF_GUARD_HELPER_IDS_PER_EVENT] = [
        u16::from_ne_bytes(bytes[28..30].try_into().ok()?),
        u16::from_ne_bytes(bytes[30..32].try_into().ok()?),
        u16::from_ne_bytes(bytes[32..34].try_into().ok()?),
        u16::from_ne_bytes(bytes[34..36].try_into().ok()?),
    ];
    let exe_dev = u32::from_ne_bytes(bytes[36..40].try_into().ok()?);
    let exe_ino = u64::from_ne_bytes(bytes[40..48].try_into().ok()?);
    let comm: [u8; 16] = bytes[48..64].try_into().ok()?;

    if ts_ns == 0
        || pid == 0
        || tgid == 0
        || reserved != 0
        || prog_type > BPF_GUARD_PROG_TYPE_MAX
        || !matches!(
            action,
            BPF_GUARD_ACTION_OBSERVED | BPF_GUARD_ACTION_HELPER_RISK | BPF_GUARD_ACTION_DENIED
        )
        || helper_mask & !BPF_GUARD_HELPER_MASK_ALL != 0
        || !helper_ids_are_compact(&helper_ids)
        || (exe_dev == 0) != (exe_ino == 0)
        || !comm_is_nul_padded(&comm)
    {
        return None;
    }

    // Producer invariants: only a HELPER_RISK record carries the helper bitmap
    // and the raw ids; an OBSERVED/DENIED record carries neither.
    if action == BPF_GUARD_ACTION_HELPER_RISK {
        if helper_mask == 0 || helper_ids[0] == 0 {
            return None;
        }
    } else if helper_mask != 0 || helper_ids != [0u16; BPF_GUARD_HELPER_IDS_PER_EVENT] {
        return None;
    }

    Some(BpfGuardEvent {
        ts_ns,
        pid,
        tgid,
        uid,
        action,
        command,
        prog_type,
        reserved,
        helper_mask,
        helper_ids,
        exe_dev,
        exe_ino,
        comm,
    })
}

/// Raw helper ids are recorded deduplicated and left-packed: a zero lane after
/// a non-zero lane cannot be produced, every recorded id must be in the bounded
/// representable range and must map onto one of the defined risk bits.
fn helper_ids_are_compact(ids: &[u16; BPF_GUARD_HELPER_IDS_PER_EVENT]) -> bool {
    let mut zero_seen = false;
    let mut index = 0usize;
    while index < ids.len() {
        let id = ids[index];
        if id == 0 {
            zero_seen = true;
        } else {
            if zero_seen || id > BPF_GUARD_MAX_HELPER_ID {
                return false;
            }
            if helper_id_to_bit(u32::from(id)) == 0 {
                return false;
            }
        }
        index += 1;
    }
    true
}

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
    use core::mem::{align_of, offset_of, size_of};

    fn sample_observed() -> BpfGuardEvent {
        BpfGuardEvent {
            ts_ns: 987_654_321_000,
            pid: 4242,
            tgid: 4241,
            uid: 1000,
            action: BPF_GUARD_ACTION_OBSERVED,
            command: BPF_GUARD_COMMAND_PROG_LOAD,
            prog_type: BPF_GUARD_PROG_TYPE_LSM,
            reserved: 0,
            helper_mask: 0,
            helper_ids: [0; BPF_GUARD_HELPER_IDS_PER_EVENT],
            exe_dev: 0,
            exe_ino: 0,
            comm: *b"bpftool\0\0\0\0\0\0\0\0\0",
        }
    }

    fn sample_helper_risk() -> BpfGuardEvent {
        BpfGuardEvent {
            ts_ns: 987_654_321_001,
            pid: 5000,
            tgid: 5000,
            uid: 0,
            action: BPF_GUARD_ACTION_HELPER_RISK,
            command: BPF_GUARD_COMMAND_PROG_LOAD,
            prog_type: BPF_GUARD_PROG_TYPE_KPROBE,
            reserved: 0,
            helper_mask: HELPER_BIT_PROBE_WRITE_USER | HELPER_BIT_OVERRIDE_RETURN,
            helper_ids: [
                HELPER_ID_PROBE_WRITE_USER,
                HELPER_ID_OVERRIDE_RETURN,
                0,
                0,
            ],
            exe_dev: 0,
            exe_ino: 0,
            comm: *b"rootkit\0\0\0\0\0\0\0\0\0",
        }
    }

    fn encode(event: &BpfGuardEvent) -> [u8; BPF_GUARD_EVENT_WIRE_BYTES] {
        let mut raw = [0u8; BPF_GUARD_EVENT_WIRE_BYTES];
        raw[0..8].copy_from_slice(&event.ts_ns.to_ne_bytes());
        raw[8..12].copy_from_slice(&event.pid.to_ne_bytes());
        raw[12..16].copy_from_slice(&event.tgid.to_ne_bytes());
        raw[16..20].copy_from_slice(&event.uid.to_ne_bytes());
        raw[20] = event.action;
        raw[21] = event.command;
        raw[22] = event.prog_type;
        raw[23] = event.reserved;
        raw[24..28].copy_from_slice(&event.helper_mask.to_ne_bytes());
        raw[28..30].copy_from_slice(&event.helper_ids[0].to_ne_bytes());
        raw[30..32].copy_from_slice(&event.helper_ids[1].to_ne_bytes());
        raw[32..34].copy_from_slice(&event.helper_ids[2].to_ne_bytes());
        raw[34..36].copy_from_slice(&event.helper_ids[3].to_ne_bytes());
        raw[36..40].copy_from_slice(&event.exe_dev.to_ne_bytes());
        raw[40..48].copy_from_slice(&event.exe_ino.to_ne_bytes());
        raw[48..64].copy_from_slice(&event.comm);
        raw
    }

    #[test]
    fn wire_layout_matches_the_64_byte_contract() {
        assert_eq!(size_of::<BpfGuardEvent>(), BPF_GUARD_EVENT_WIRE_BYTES);
        assert_eq!(align_of::<BpfGuardEvent>(), 8);
        assert_eq!(offset_of!(BpfGuardEvent, ts_ns), 0);
        assert_eq!(offset_of!(BpfGuardEvent, pid), 8);
        assert_eq!(offset_of!(BpfGuardEvent, tgid), 12);
        assert_eq!(offset_of!(BpfGuardEvent, uid), 16);
        assert_eq!(offset_of!(BpfGuardEvent, action), 20);
        assert_eq!(offset_of!(BpfGuardEvent, command), 21);
        assert_eq!(offset_of!(BpfGuardEvent, prog_type), 22);
        assert_eq!(offset_of!(BpfGuardEvent, reserved), 23);
        assert_eq!(offset_of!(BpfGuardEvent, helper_mask), 24);
        assert_eq!(offset_of!(BpfGuardEvent, helper_ids), 28);
        assert_eq!(offset_of!(BpfGuardEvent, exe_dev), 36);
        assert_eq!(offset_of!(BpfGuardEvent, exe_ino), 40);
        assert_eq!(offset_of!(BpfGuardEvent, comm), 48);
        // No implicit padding: the named fields cover every one of the 64 bytes,
        // so a stored record cannot leak uninitialised stack bytes.
        assert_eq!(offset_of!(BpfGuardEvent, comm) + 16, BPF_GUARD_EVENT_WIRE_BYTES);
    }

    #[test]
    fn decoders_roundtrip_both_producer_shapes() {
        for event in [sample_observed(), sample_helper_risk()] {
            assert_eq!(decode_bpf_guard_event(&encode(&event)), Some(event));
        }
    }

    #[test]
    fn decoder_rejects_records_the_kernel_cannot_have_emitted() {
        let observed = encode(&sample_observed());
        for length in [0usize, 1, 32, 48, 63] {
            assert!(decode_bpf_guard_event(&observed[..length]).is_none(), "{length}");
        }
        let mut extra = [0u8; BPF_GUARD_EVENT_WIRE_BYTES + 1];
        extra[..BPF_GUARD_EVENT_WIRE_BYTES].copy_from_slice(&observed);
        assert!(decode_bpf_guard_event(&extra).is_none());

        let mut bad = sample_observed();
        bad.action = 9;
        assert!(decode_bpf_guard_event(&encode(&bad)).is_none());
        bad = sample_observed();
        bad.reserved = 1;
        assert!(decode_bpf_guard_event(&encode(&bad)).is_none());
        bad = sample_observed();
        bad.ts_ns = 0;
        assert!(decode_bpf_guard_event(&encode(&bad)).is_none());
        bad = sample_observed();
        bad.pid = 0;
        assert!(decode_bpf_guard_event(&encode(&bad)).is_none());
        bad = sample_observed();
        bad.tgid = 0;
        assert!(decode_bpf_guard_event(&encode(&bad)).is_none());
        bad = sample_observed();
        bad.prog_type = BPF_GUARD_PROG_TYPE_MAX + 1;
        assert!(decode_bpf_guard_event(&encode(&bad)).is_none());
        bad = sample_observed();
        bad.helper_mask = HELPER_BIT_PROBE_WRITE_USER;
        assert!(decode_bpf_guard_event(&encode(&bad)).is_none());
        bad = sample_observed();
        bad.helper_mask = 1 << 7;
        assert!(decode_bpf_guard_event(&encode(&bad)).is_none());
        bad = sample_observed();
        bad.exe_dev = 8;
        assert!(decode_bpf_guard_event(&encode(&bad)).is_none());
        bad = sample_observed();
        bad.comm = [b'x'; 16];
        assert!(decode_bpf_guard_event(&encode(&bad)).is_none());

        // HELPER_RISK records must carry a bit and at least one id.
        let mut risk = sample_helper_risk();
        risk.helper_mask = 0;
        risk.helper_ids = [0; BPF_GUARD_HELPER_IDS_PER_EVENT];
        assert!(decode_bpf_guard_event(&encode(&risk)).is_none());
        let mut risk = sample_helper_risk();
        risk.helper_mask = HELPER_BIT_SEND_SIGNAL;
        risk.helper_ids = [0; BPF_GUARD_HELPER_IDS_PER_EVENT];
        assert!(decode_bpf_guard_event(&encode(&risk)).is_none());
        let mut risk = sample_helper_risk();
        risk.helper_ids = [HELPER_ID_SEND_SIGNAL_THREAD, 0, HELPER_ID_SEND_SIGNAL, 0];
        assert!(decode_bpf_guard_event(&encode(&risk)).is_none());
        let mut risk = sample_helper_risk();
        risk.helper_ids = [BPF_GUARD_MAX_HELPER_ID + 1, 0, 0, 0];
        assert!(decode_bpf_guard_event(&encode(&risk)).is_none());
        let mut risk = sample_helper_risk();
        risk.helper_ids = [7, 0, 0, 0];
        assert!(decode_bpf_guard_event(&encode(&risk)).is_none());
    }

    #[test]
    fn helper_mapping_and_bits_use_the_stable_uapi_ids() {
        assert_eq!(helper_id_to_bit(36), HELPER_BIT_PROBE_WRITE_USER);
        assert_eq!(helper_id_to_bit(58), HELPER_BIT_OVERRIDE_RETURN);
        assert_eq!(helper_id_to_bit(109), HELPER_BIT_SEND_SIGNAL);
        assert_eq!(helper_id_to_bit(117), HELPER_BIT_SEND_SIGNAL);
        for non_risk in [0u32, 1, 14, 16, 44, 45, 57, 59, 108, 112, 200, u32::MAX] {
            assert_eq!(helper_id_to_bit(non_risk), 0, "{non_risk}");
        }
        assert_eq!(
            BPF_GUARD_HELPER_MASK_ALL,
            HELPER_BIT_PROBE_WRITE_USER | HELPER_BIT_OVERRIDE_RETURN | HELPER_BIT_SEND_SIGNAL
        );
        for id in [
            HELPER_ID_PROBE_WRITE_USER,
            HELPER_ID_OVERRIDE_RETURN,
            HELPER_ID_SEND_SIGNAL,
            HELPER_ID_SEND_SIGNAL_THREAD,
        ] {
            assert!(
                helper_id_to_bit(u32::from(id)) != 0,
                "helper id {id} lost its risk bit"
            );
            assert!(id <= BPF_GUARD_MAX_HELPER_ID);
        }
    }

    #[test]
    fn uapi_commands_and_program_types_match_the_kernel_headers() {
        // `enum bpf_cmd` (stable UAPI numbering).
        assert_eq!(BPF_GUARD_COMMAND_MAP_CREATE, 0);
        assert_eq!(BPF_GUARD_COMMAND_PROG_LOAD, 5);
        assert_eq!(BPF_GUARD_COMMAND_PROG_ATTACH, 8);
        assert_eq!(BPF_GUARD_COMMAND_RAW_TRACEPOINT_OPEN, 17);
        assert_eq!(BPF_GUARD_COMMAND_LINK_CREATE, 28);
        // `enum bpf_prog_type` (stable UAPI numbering, aya-ebpf-bindings verified).
        assert_eq!(BPF_GUARD_PROG_TYPE_KPROBE, 2);
        assert_eq!(BPF_GUARD_PROG_TYPE_TRACEPOINT, 5);
        assert_eq!(BPF_GUARD_PROG_TYPE_RAW_TRACEPOINT, 17);
        assert_eq!(BPF_GUARD_PROG_TYPE_TRACING, 26);
        assert_eq!(BPF_GUARD_PROG_TYPE_STRUCT_OPS, 27);
        assert_eq!(BPF_GUARD_PROG_TYPE_LSM, 29);
        assert_eq!(BPF_GUARD_PROG_TYPE_SK_LOOKUP, 30);
        assert_eq!(BPF_GUARD_PROG_TYPE_SYSCALL, 31);
        assert!(BPF_GUARD_PROG_TYPE_MAX >= BPF_GUARD_PROG_TYPE_SYSCALL);
        assert!(BPF_GUARD_PROG_TYPE_MAX < BPF_GUARD_STATE_MAGIC.wrapping_add(64));
    }

    #[test]
    fn state_word_is_armed_only_for_the_current_magic_abi_and_armed_bit() {
        let word = bpf_guard_state_word(0xdead_beef, true);
        assert!(bpf_guard_state_armed(word));
        assert_eq!((word & u64::from(u32::MAX)) as u32, 0xdead_beef);
        assert_eq!(
            (word >> BPF_GUARD_STATE_MAGIC_SHIFT) & BPF_GUARD_STATE_BYTE_MASK,
            u64::from(BPF_GUARD_STATE_MAGIC)
        );
        assert!(!bpf_guard_state_armed(bpf_guard_state_word(1, false)));
        assert!(!bpf_guard_state_armed(0));
        assert!(!bpf_guard_state_armed(u64::MAX));
        let mut foreign = word;
        foreign &= !(0xff << BPF_GUARD_STATE_ABI_SHIFT);
        foreign |= 2 << BPF_GUARD_STATE_ABI_SHIFT;
        assert!(!bpf_guard_state_armed(foreign));
        assert_eq!(BPF_GUARD_STATE_MAGIC, b'B');
        assert_eq!(BPF_GUARD_STATE_ABI, 1);
        assert_eq!(BPF_GUARD_EVENT_RING_BYTES as usize / BPF_GUARD_EVENT_WIRE_BYTES, 1024);
    }
}
