//! V6.3.0 AP-1 — executable-inode trust wire contract (`TRUSTED_EXEC_INODES`).
//!
//! The kernel credential/ransom guards used to trust `bpf_get_current_comm()`,
//! which a local attacker can spoof with `prctl(PR_SET_NAME, "sshd")`. AP-1
//! replaces that primary decision with the *real* executable identity
//! `current->task_struct.mm -> mm_struct.exe_file -> file.f_inode ->
//! (i_sb->s_dev, i_ino)` and a BPF hash map of trusted inode keys.
//!
//! This module is the shared ABI between the privileged core
//! (`rust/gedefense-core/src/exec_inode.rs`), the eBPF guards
//! (`rust/gedefense-ebpf/src/{exec_inode,credential_guard,ransom}.rs`) and the
//! Go control plane (`control/{coreipc,xdr}_execinode.go`):
//!
//! - 16-byte identity keys: `s_dev` LE u32 at 0, `i_ino` LE u64 at 4, four zero
//!   reserved bytes at 12. The map values are the `EXEC_INODE_ALLOW_*` bitmask.
//! - `EXEC_INODE_STATE` word layout (epoch/armed/magic/ABI). A default/zero word
//!   means "gate not available": consumers fall back to the documented comm
//!   allowlist and the fallback is visible in status and events (it is never
//!   silently equated with the inode gate).
//! - `EXEC_INODE_OFFSETS` index table: runtime BTF offsets published by the core
//!   (magic, ABI, `task_struct.mm`, `mm_struct.exe_file`, `file.f_inode`,
//!   `inode.i_ino`, `inode.i_sb`, `super_block.s_dev`, task/mm struct sizes).
//!   Kernel struct offsets are never hard-coded in the eBPF object.
//! - [`ExecInodeEvent`]: fixed 64-byte ring record (native endian, `repr(C)`)
//!   with a rejecting decoder: wrong length, unknown action, zero producer
//!   ts/pid/tgid, non-zero reserved bytes, unpadded/empty `comm`, undefined
//!   trust-flag bits, or an identity-less mismatch/deny record are all `None`.
//!
//! Event actions: `OBSERVED_MISMATCH` (comm and executable identity disagree,
//! the `prctl` spoof signature), `DENIED_UNTRUSTED` (the inode gate denied) and
//! `FALLBACK_COMM` (the weaker comm allowlist was used because BTF/offsets are
//! unavailable — an explicit, operator-visible degradation).
//!
//! Observe/evidence only: this contract changes no kill-eligibility and adds no
//! response action.

/// Wire size of one identity-map key (`s_dev u32 LE | i_ino u64 LE | zero4`).
pub const EXEC_INODE_KEY_BYTES: usize = 16;

/// Trust flag: the executable may read protected credential objects.
pub const EXEC_INODE_ALLOW_CRED_READ: u32 = 1;
/// Trust flag: the executable is exempt from both ransom signals.
pub const EXEC_INODE_ALLOW_RANSOM_FULL: u32 = 2;
/// Trust flag: the executable is exempt from the metadata (`rename/unlink`)
/// signal only; the entropy-burst signal stays live.
pub const EXEC_INODE_ALLOW_RANSOM_POOL_META: u32 = 4;
/// Every flag bit the contract defines; consumers reject values outside it.
pub const EXEC_INODE_FLAGS_ALL: u32 = EXEC_INODE_ALLOW_CRED_READ
    | EXEC_INODE_ALLOW_RANSOM_FULL
    | EXEC_INODE_ALLOW_RANSOM_POOL_META;

/// `TRUSTED_EXEC_INODES` map capacity (identity -> flag bitmask).
pub const EXEC_INODE_TRUST_MAP_ENTRIES: u32 = 2_048;
/// `MALWARE_TTL_INODES` map capacity (identity -> TTL seconds carrier).
pub const EXEC_INODE_TTL_MAP_ENTRIES: u32 = 256;
/// `EXEC_INODE_EVENTS` ring size (64 KiB = 1024 queued 64-byte records).
pub const EXEC_INODE_EVENT_RING_BYTES: u32 = 1 << 16;
/// Maximum number of `MALWARE_TTL_INODES` locks the core tracks at once.
pub const EXEC_INODE_MAX_TTL_LOCKS: usize = EXEC_INODE_TTL_MAP_ENTRIES as usize;
/// Bounded TTL bounds accepted by `MALWARE_INODE_LOCK` (1 second ..= 24 hours).
pub const EXEC_INODE_MIN_TTL_SECONDS: u32 = 1;
pub const EXEC_INODE_MAX_TTL_SECONDS: u32 = 86_400;

/// `EXEC_INODE_STATE` word layout (ABI 1): epoch 0..31, armed bit 32, magic
/// 40..47, ABI 48..55. A zero/default word means "not available": the inode
/// gate is not evaluated and the guards fall back to the comm allowlist.
pub const EXEC_INODE_STATE_MAGIC: u8 = 0x45;
pub const EXEC_INODE_STATE_ABI: u8 = 1;
pub const EXEC_INODE_STATE_ARMED_SHIFT: u64 = 32;
pub const EXEC_INODE_STATE_MAGIC_SHIFT: u64 = 40;
pub const EXEC_INODE_STATE_ABI_SHIFT: u64 = 48;
pub const EXEC_INODE_STATE_BYTE_MASK: u64 = 0xff;

/// `EXEC_INODE_OFFSETS` table length (10 used, 6 reserved).
pub const EXEC_INODE_OFFSETS_TABLE_LEN: usize = 16;
/// `EXEC_INODE_OFFSETS` magic/ABI words (index 0/1). The eBPF helpers refuse a
/// table without both words before they dereference anything.
pub const EXEC_INODE_OFFSETS_MAGIC: u32 = 0x4549_4e31;
pub const EXEC_INODE_OFFSETS_ABI: u32 = 1;
/// `EXEC_INODE_OFFSETS` index enum shared by the core publisher and eBPF reader.
pub const EXEC_INODE_OFF_MAGIC: u32 = 0;
pub const EXEC_INODE_OFF_ABI: u32 = 1;
pub const EXEC_INODE_OFF_TASK_MM: u32 = 2;
pub const EXEC_INODE_OFF_MM_EXE_FILE: u32 = 3;
pub const EXEC_INODE_OFF_FILE_F_INODE: u32 = 4;
pub const EXEC_INODE_OFF_INODE_I_INO: u32 = 5;
pub const EXEC_INODE_OFF_INODE_I_SB: u32 = 6;
pub const EXEC_INODE_OFF_SUPER_S_DEV: u32 = 7;
pub const EXEC_INODE_OFF_TASK_SIZE: u32 = 8;
pub const EXEC_INODE_OFF_MM_SIZE: u32 = 9;
/// First reserved index after the AP-1 offset set.
pub const EXEC_INODE_OFF_RESERVED_FIRST: u32 = 10;
/// Defensive upper bound for a published `task_struct`/`mm_struct` size.
pub const EXEC_INODE_MAX_STRUCT_SIZE: u32 = 65_536;

/// Event action: comm allowlist and executable-inode gate disagree (this is the
/// `prctl(PR_SET_NAME)` masquerade signature in both directions).
pub const EXEC_INODE_ACTION_OBSERVED_MISMATCH: u8 = 1;
/// Event action: the executable-inode gate denied the operation.
pub const EXEC_INODE_ACTION_DENIED_UNTRUSTED: u8 = 2;
/// Event action: the inode gate was unavailable and the comm allowlist decided
/// (explicit, rate-limited degradation record).
pub const EXEC_INODE_ACTION_FALLBACK_COMM: u8 = 3;
/// Highest action value the producer may emit.
pub const EXEC_INODE_ACTION_MAX: u8 = EXEC_INODE_ACTION_FALLBACK_COMM;

/// Wire size of one [`ExecInodeEvent`].
pub const EXEC_INODE_EVENT_WIRE_BYTES: usize = 64;

/// Packs one `(s_dev, i_ino)` identity as the 16-byte map key.
#[inline(always)]
pub const fn exec_inode_key(dev: u32, ino: u64) -> [u8; EXEC_INODE_KEY_BYTES] {
    let mut key = [0u8; EXEC_INODE_KEY_BYTES];
    key[0] = (dev & 0xff) as u8;
    key[1] = ((dev >> 8) & 0xff) as u8;
    key[2] = ((dev >> 16) & 0xff) as u8;
    key[3] = ((dev >> 24) & 0xff) as u8;
    let mut index = 0usize;
    while index < 8 {
        key[4 + index] = ((ino >> (index * 8)) & 0xff) as u8;
        index += 1;
    }
    key
}

/// Unpacks a 16-byte identity key. `None` for a wrong length or non-zero
/// reserved bytes — a producer cannot have written such a key. Zero `dev`/`ino`
/// are refused as well: no kernel inode has that identity, so a key containing
/// zeros can only be an uninitialised value and must never match a policy.
pub fn decode_exec_inode_key(key: &[u8]) -> Option<(u32, u64)> {
    if key.len() != EXEC_INODE_KEY_BYTES {
        return None;
    }
    let mut raw = [0u8; EXEC_INODE_KEY_BYTES];
    raw.copy_from_slice(key);
    if raw[12..16] != [0u8; 4] {
        return None;
    }
    let dev = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let ino = u64::from_le_bytes([
        raw[4], raw[5], raw[6], raw[7], raw[8], raw[9], raw[10], raw[11],
    ]);
    if dev == 0 || ino == 0 {
        return None;
    }
    Some((dev, ino))
}

/// True when `flags` is a non-zero subset of [`EXEC_INODE_FLAGS_ALL`]. The core
/// refuses every other flag word, so the kernel cannot receive an undefined
/// trust bit.
#[inline(always)]
pub const fn exec_inode_flags_valid(flags: u32) -> bool {
    flags != 0 && (flags & !EXEC_INODE_FLAGS_ALL) == 0
}

/// One executable-inode gate decision/audit record emitted by the eBPF guards.
///
/// Byte layout (native endian, size 64): `ts_ns` 0, `pid` 8, `tgid` 12, `uid`
/// 16, `exe_dev` 20, `exe_ino` 24, `trust_flags` 32, `action` 36, `comm` 37 (16
/// NUL-padded bytes), `reserved` 53 (11 zero bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecInodeEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub exe_dev: u32,
    pub exe_ino: u64,
    pub trust_flags: u32,
    pub action: u8,
    pub comm: [u8; 16],
    pub reserved: [u8; 11],
}

impl ExecInodeEvent {
    /// The `comm` bytes up to the first NUL (the decoder already proved the slot
    /// is NUL-padded, so the terminator always exists).
    pub fn comm_bytes(&self) -> &[u8] {
        let mut end = 0usize;
        while end < self.comm.len() && self.comm[end] != 0 {
            end += 1;
        }
        &self.comm[..end]
    }
}

/// Decodes one fixed-size executable-inode record. Returns `None` for every
/// record the producer cannot have emitted: wrong length, unknown action, zero
/// `ts_ns`/`pid`/`tgid`, reserved bytes that are not zero, a `comm` slot that is
/// empty or not NUL-padded, undefined trust-flag bits, or a mismatch/deny
/// record without a resolved executable identity (only the fallback record may
/// lack one because the offsets/state that resolve it were unavailable).
pub fn decode_exec_inode_event(bytes: &[u8]) -> Option<ExecInodeEvent> {
    if bytes.len() != EXEC_INODE_EVENT_WIRE_BYTES {
        return None;
    }
    let ts_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let pid = u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let tgid = u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let uid = u32::from_ne_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let exe_dev = u32::from_ne_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    let exe_ino = u64::from_ne_bytes([
        bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
    ]);
    let trust_flags = u32::from_ne_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
    let action = bytes[36];
    let mut comm = [0u8; 16];
    comm.copy_from_slice(&bytes[37..53]);
    let mut reserved = [0u8; 11];
    reserved.copy_from_slice(&bytes[53..64]);
    let identity_required = matches!(
        action,
        EXEC_INODE_ACTION_OBSERVED_MISMATCH | EXEC_INODE_ACTION_DENIED_UNTRUSTED
    );
    if !matches!(
        action,
        EXEC_INODE_ACTION_OBSERVED_MISMATCH
            | EXEC_INODE_ACTION_DENIED_UNTRUSTED
            | EXEC_INODE_ACTION_FALLBACK_COMM
    ) || ts_ns == 0
        || pid == 0
        || tgid == 0
        || reserved != [0u8; 11]
        || !comm_is_nul_padded(&comm)
        || comm[0] == 0
        || (trust_flags & !EXEC_INODE_FLAGS_ALL) != 0
        || (identity_required && (exe_dev == 0 || exe_ino == 0))
    {
        return None;
    }
    Some(ExecInodeEvent {
        ts_ns,
        pid,
        tgid,
        uid,
        exe_dev,
        exe_ino,
        trust_flags,
        action,
        comm,
        reserved,
    })
}

/// A producer `comm` slot is NUL-terminated and NUL-padded
/// (`bpf_get_current_comm` zero-fills the remainder of the 16-byte task name).
#[inline(always)]
pub fn exec_inode_comm_is_nul_padded(comm: &[u8; 16]) -> bool {
    comm_is_nul_padded(comm)
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

    fn sample() -> ExecInodeEvent {
        ExecInodeEvent {
            ts_ns: 987_654_321,
            pid: 4242,
            tgid: 4242,
            uid: 1000,
            exe_dev: 0x0801,
            exe_ino: 0xdead_beef_1234_5678,
            trust_flags: EXEC_INODE_ALLOW_CRED_READ,
            action: EXEC_INODE_ACTION_OBSERVED_MISMATCH,
            comm: *b"sshd\0\0\0\0\0\0\0\0\0\0\0\0",
            reserved: [0; 11],
        }
    }

    fn encode(event: &ExecInodeEvent) -> [u8; EXEC_INODE_EVENT_WIRE_BYTES] {
        let mut raw = [0u8; EXEC_INODE_EVENT_WIRE_BYTES];
        raw[0..8].copy_from_slice(&event.ts_ns.to_ne_bytes());
        raw[8..12].copy_from_slice(&event.pid.to_ne_bytes());
        raw[12..16].copy_from_slice(&event.tgid.to_ne_bytes());
        raw[16..20].copy_from_slice(&event.uid.to_ne_bytes());
        raw[20..24].copy_from_slice(&event.exe_dev.to_ne_bytes());
        raw[24..32].copy_from_slice(&event.exe_ino.to_ne_bytes());
        raw[32..36].copy_from_slice(&event.trust_flags.to_ne_bytes());
        raw[36] = event.action;
        raw[37..53].copy_from_slice(&event.comm);
        raw[53..64].copy_from_slice(&event.reserved);
        raw
    }

    #[test]
    fn wire_layout_and_roundtrip_match_the_abi() {
        use core::mem::{align_of, offset_of, size_of};
        assert_eq!(size_of::<ExecInodeEvent>(), EXEC_INODE_EVENT_WIRE_BYTES);
        assert_eq!(align_of::<ExecInodeEvent>(), 8);
        assert_eq!(offset_of!(ExecInodeEvent, ts_ns), 0);
        assert_eq!(offset_of!(ExecInodeEvent, pid), 8);
        assert_eq!(offset_of!(ExecInodeEvent, tgid), 12);
        assert_eq!(offset_of!(ExecInodeEvent, uid), 16);
        assert_eq!(offset_of!(ExecInodeEvent, exe_dev), 20);
        assert_eq!(offset_of!(ExecInodeEvent, exe_ino), 24);
        assert_eq!(offset_of!(ExecInodeEvent, trust_flags), 32);
        assert_eq!(offset_of!(ExecInodeEvent, action), 36);
        assert_eq!(offset_of!(ExecInodeEvent, comm), 37);
        assert_eq!(offset_of!(ExecInodeEvent, reserved), 53);
        let event = sample();
        assert_eq!(decode_exec_inode_event(&encode(&event)), Some(event));
        assert_eq!(event.comm_bytes(), b"sshd");
    }

    #[test]
    fn every_documented_action_decodes() {
        for action in [
            EXEC_INODE_ACTION_OBSERVED_MISMATCH,
            EXEC_INODE_ACTION_DENIED_UNTRUSTED,
            EXEC_INODE_ACTION_FALLBACK_COMM,
        ] {
            let mut event = sample();
            event.action = action;
            assert_eq!(decode_exec_inode_event(&encode(&event)), Some(event), "{action}");
        }
        let mut fallback = sample();
        fallback.action = EXEC_INODE_ACTION_FALLBACK_COMM;
        fallback.exe_dev = 0;
        fallback.exe_ino = 0;
        fallback.trust_flags = 0;
        assert_eq!(
            decode_exec_inode_event(&encode(&fallback)),
            Some(fallback)
        );
    }

    #[test]
    fn rejects_records_the_producer_cannot_have_emitted() {
        let raw = encode(&sample());
        for length in [0usize, 1, 32, 63] {
            assert!(decode_exec_inode_event(&raw[..length]).is_none(), "{length}");
        }
        let mut longer = [0u8; 128];
        longer[..EXEC_INODE_EVENT_WIRE_BYTES].copy_from_slice(&raw);
        assert!(decode_exec_inode_event(&longer[..65]).is_none());

        for action in [0u8, 4, 0xff] {
            let mut bad = sample();
            bad.action = action;
            assert!(decode_exec_inode_event(&encode(&bad)).is_none(), "{action}");
        }
        let mut bad = sample();
        bad.ts_ns = 0;
        assert!(decode_exec_inode_event(&encode(&bad)).is_none());
        bad = sample();
        bad.pid = 0;
        assert!(decode_exec_inode_event(&encode(&bad)).is_none());
        bad = sample();
        bad.tgid = 0;
        assert!(decode_exec_inode_event(&encode(&bad)).is_none());
        bad = sample();
        bad.trust_flags = 8;
        assert!(decode_exec_inode_event(&encode(&bad)).is_none());
        bad = sample();
        bad.reserved[10] = 1;
        assert!(decode_exec_inode_event(&encode(&bad)).is_none());
        bad = sample();
        bad.comm = [0u8; 16];
        assert!(decode_exec_inode_event(&encode(&bad)).is_none());
        bad = sample();
        bad.comm = [b'x'; 16];
        assert!(decode_exec_inode_event(&encode(&bad)).is_none());
        bad = sample();
        bad.comm[5] = b'x';
        assert!(decode_exec_inode_event(&encode(&bad)).is_none());
        // A mismatch/deny record without a resolved executable identity is not
        // representable: the gate can only decide on a resolved identity.
        for action in [
            EXEC_INODE_ACTION_OBSERVED_MISMATCH,
            EXEC_INODE_ACTION_DENIED_UNTRUSTED,
        ] {
            let mut bad = sample();
            bad.action = action;
            bad.exe_dev = 0;
            assert!(decode_exec_inode_event(&encode(&bad)).is_none());
            bad.exe_dev = 8;
            bad.exe_ino = 0;
            assert!(decode_exec_inode_event(&encode(&bad)).is_none());
        }
    }

    #[test]
    fn identity_keys_roundtrip_and_reject_reserved_or_zero_fields() {
        let key = exec_inode_key(0x0801, 0xdead_beef_1234_5678);
        assert_eq!(
            decode_exec_inode_key(&key),
            Some((0x0801, 0xdead_beef_1234_5678))
        );
        let mut bad = key;
        bad[12] = 1;
        assert_eq!(decode_exec_inode_key(&bad), None);
        assert_eq!(decode_exec_inode_key(&exec_inode_key(0, 5)), None);
        assert_eq!(decode_exec_inode_key(&exec_inode_key(5, 0)), None);
        assert_eq!(decode_exec_inode_key(&[0u8; 15]), None);
        assert_eq!(decode_exec_inode_key(&[0u8; 17]), None);
    }

    #[test]
    fn flag_and_offset_contracts_are_closed() {
        assert_eq!(EXEC_INODE_ALLOW_CRED_READ, 1);
        assert_eq!(EXEC_INODE_ALLOW_RANSOM_FULL, 2);
        assert_eq!(EXEC_INODE_ALLOW_RANSOM_POOL_META, 4);
        assert_eq!(EXEC_INODE_FLAGS_ALL, 7);
        assert!(exec_inode_flags_valid(EXEC_INODE_FLAGS_ALL));
        assert!(exec_inode_flags_valid(EXEC_INODE_ALLOW_RANSOM_POOL_META));
        assert!(!exec_inode_flags_valid(0));
        assert!(!exec_inode_flags_valid(8));
        assert!(!exec_inode_flags_valid(EXEC_INODE_FLAGS_ALL | 0x80));
        assert_eq!(EXEC_INODE_STATE_MAGIC, b'E');
        assert_eq!(EXEC_INODE_OFFSETS_TABLE_LEN, 16);
        assert_eq!(EXEC_INODE_OFF_RESERVED_FIRST, 10);
        assert!(
            EXEC_INODE_OFF_TASK_SIZE < EXEC_INODE_OFF_RESERVED_FIRST
                && EXEC_INODE_OFF_MM_SIZE < EXEC_INODE_OFF_RESERVED_FIRST
        );
        assert_eq!(
            EXEC_INODE_EVENT_RING_BYTES as usize / EXEC_INODE_EVENT_WIRE_BYTES,
            1024
        );
        assert_eq!(EXEC_INODE_TRUST_MAP_ENTRIES, 2_048);
        assert_eq!(EXEC_INODE_TTL_MAP_ENTRIES, 256);
        assert_eq!(
            EXEC_INODE_MAX_TTL_LOCKS,
            EXEC_INODE_TTL_MAP_ENTRIES as usize
        );
        assert_eq!(EXEC_INODE_MIN_TTL_SECONDS, 1);
        assert_eq!(EXEC_INODE_MAX_TTL_SECONDS, 86_400);
        assert_eq!(EXEC_INODE_ACTION_MAX, 3);
        assert!(EXEC_INODE_MAX_STRUCT_SIZE >= 8);
    }
}
