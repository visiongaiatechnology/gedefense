//! Point 1 (Phase 1): shared wire contract for the Titan exec/library gate.
//!
//! Rust half of ABI-1 in `docs/POINT1-TITAN-EXEC-GATE.md` (§3.1 constants,
//! §3.2 `TitanExecEvent`): native endian, `repr(C)`, exactly 88 bytes, never
//! portable. `decode_titan_exec_event` rejects every record the producer
//! cannot have emitted instead of repairing it (doctrine of
//! `decode_styx_flow_event`): §3.2 length/hook/action/reason/pid/ts, mmap
//! without prot, DENY without ground, dev/ino zero outside the §3.2 identity
//! exceptions, comm padding; all other fields are carried through unchanged.

/// Wire size of one [`TitanExecEvent`] (`sizeof(TitanExecEvent) == 88`).
pub const TITAN_EXEC_EVENT_WIRE_BYTES: usize = 88;

/// LSM hooks (§3.1): `bprm_check_security` (execve) and `mmap_file` (exec map).
pub const TITAN_EXEC_HOOK_BPRM: u8 = 1;
pub const TITAN_EXEC_HOOK_MMAP: u8 = 2;

/// Verdicts (§3.1): audit (never blocks) and deny (kernel already enforced it).
pub const TITAN_EXEC_ACTION_AUDIT: u8 = 1;
pub const TITAN_EXEC_ACTION_DENY: u8 = 2;

/// Decision grounds 0..=13 (§3.1). 11..=13 are the §4.2 UNTRUSTED-mode grounds
/// (drop-root path, non-root-owned file, world-writable ancestor directory); the
/// Go parser must accept the widened `<= 13` range in 6.2.0.
pub const TITAN_EXEC_REASON_NONE: u8 = 0;
pub const TITAN_EXEC_REASON_UNLINKED: u8 = 1;
pub const TITAN_EXEC_REASON_TMPFS: u8 = 2;
pub const TITAN_EXEC_REASON_MEMFD: u8 = 3;
pub const TITAN_EXEC_REASON_NOT_ALLOWLISTED: u8 = 4;
pub const TITAN_EXEC_REASON_WX: u8 = 5;
pub const TITAN_EXEC_REASON_ANON_NO_JIT: u8 = 6;
pub const TITAN_EXEC_REASON_READ_FAILURE: u8 = 7;
pub const TITAN_EXEC_REASON_STATE_NOT_READY: u8 = 8;
pub const TITAN_EXEC_REASON_CTIME_MISMATCH: u8 = 9;
pub const TITAN_EXEC_REASON_FS_HARD: u8 = 10;
pub const TITAN_EXEC_REASON_UNTRUSTED_PATH: u8 = 11;
pub const TITAN_EXEC_REASON_NON_ROOT_OWNER: u8 = 12;
pub const TITAN_EXEC_REASON_WORLD_WRITABLE_PATH: u8 = 13;
/// Highest valid [`TitanExecEvent::reason`] value (§3.1).
pub const TITAN_EXEC_REASON_MAX: u8 = TITAN_EXEC_REASON_WORLD_WRITABLE_PATH;

/// Gate modes (§3.1); `OFF` is the default after upgrade. `UNTRUSTED` (4) is a
/// *global-only* restrictive mode added in 6.2.0: it applies the CONTAIN
/// containment rules plus the drop-root/owner/world-writable path gates. It is
/// not representable as a per-cgroup scope (the scope value has two mode bits).
pub const TITAN_EXEC_MODE_OFF: u8 = 0;
pub const TITAN_EXEC_MODE_OBSERVE: u8 = 1;
pub const TITAN_EXEC_MODE_CONTAIN: u8 = 2;
pub const TITAN_EXEC_MODE_STRICT: u8 = 3;
pub const TITAN_EXEC_MODE_UNTRUSTED: u8 = 4;
/// Highest valid per-cgroup scope mode (scope value carries mode bits 2..=3).
pub const TITAN_EXEC_SCOPE_MODE_MAX: u8 = TITAN_EXEC_MODE_STRICT;

/// Per-cgroup scope flag: anonymous executable mappings (JIT) are allowed.
pub const TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW: u8 = 1 << 0;

/// `PROT_*` bits relevant to executable mappings and `I_CTIME_QUERIED` from
/// Linux `<linux/fs.h>` (`BIT(31)`, set in `inode.i_ctime_nsec` on multigrain
/// ctime queries and masked out by kernel `inode_get_ctime_nsec()`).
const PROT_EXEC: u32 = 0x4;
pub const TITAN_I_CTIME_QUERIED: u32 = 1 << 31;

/// Masks the multigrain `I_CTIME_QUERIED` flag bit from a raw 32-bit kernel
/// `inode.i_ctime_nsec` value, matching kernel `inode_get_ctime_nsec()`.
#[inline(always)]
pub const fn strip_ctime_queried_flag(raw_nsec: u32) -> u32 {
    raw_nsec & !TITAN_I_CTIME_QUERIED
}

/// `TITAN_EXEC_STATE` magic `b'T'` (word bits 56..63) and its ABI (48..55).
pub const TITAN_EXEC_STATE_MAGIC: u8 = 0x54;
pub const TITAN_EXEC_STATE_ABI: u8 = 1;
/// `TITAN_EXEC_OFFSETS` magic `0x5449544f` ("TITO") and its ABI version. ABI 2
/// (6.2.0) adds indices 29..=34 for the UNTRUSTED mode: `bprm->filename`,
/// `inode.i_uid`, the `file->f_path.dentry` pointer, `dentry.d_parent`,
/// `dentry.d_inode` and the `dentry` structure size. Kernels/cores that publish
/// ABI 1 are refused by the eBPF programs (`titan_offsets()` returns `None`,
/// the gate fails open with a READ_FAILURE audit instead of using a stale
/// layout table).
pub const TITAN_EXEC_OFFSETS_MAGIC: u32 = 0x5449_544f;
pub const TITAN_EXEC_OFFSETS_ABI: u32 = 2;

/// One Titan exec-gate decision emitted by the eBPF sensor.
///
/// Byte layout (native endian, no implicit padding, size 88): `cgroup_id` 0,
/// `ts_ns` 8, `dev` 16, `inode_mode` 20, `ino` 24, `generation` 32, `pid` 36,
/// `tgid` 40, `uid` 44, `gid` 48, `prot` 52, `f_flags` 56, `hook` 60, `action`
/// 61, `reason` 62, `flags` 63, `comm` 64, `reserved` 80. `dev`/`ino` are
/// `s_dev`/`i_ino` (the policy key), `generation` is forensics only, `prot`
/// carries `PROT_*` for mmap and 0 for bprm, `flags` bit0 = ctime mismatch,
/// bit1 = scope snapshot, `comm` is NUL-padded, `reserved` is zero.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TitanExecEvent {
    pub cgroup_id: u64,
    pub ts_ns: u64,
    pub dev: u32,
    pub inode_mode: u32,
    pub ino: u64,
    pub generation: u32,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub prot: u32,
    pub f_flags: u32,
    pub hook: u8,
    pub action: u8,
    pub reason: u8,
    pub flags: u8,
    pub comm: [u8; 16],
    pub reserved: [u8; 8],
}

/// Decodes one fixed-size Titan exec-event wire record.
///
/// Returns `None` for every record the producer cannot have emitted (see the
/// module reject matrix); `dev`/`ino` must be non-zero except for read-failure
/// audits, because the policy key is `(s_dev, i_ino)`.
pub fn decode_titan_exec_event(bytes: &[u8]) -> Option<TitanExecEvent> {
    if bytes.len() != TITAN_EXEC_EVENT_WIRE_BYTES {
        return None;
    }

    let cgroup_id = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let ts_ns = u64::from_ne_bytes(bytes[8..16].try_into().ok()?);
    let dev = u32::from_ne_bytes(bytes[16..20].try_into().ok()?);
    let inode_mode = u32::from_ne_bytes(bytes[20..24].try_into().ok()?);
    let ino = u64::from_ne_bytes(bytes[24..32].try_into().ok()?);
    let generation = u32::from_ne_bytes(bytes[32..36].try_into().ok()?);
    let pid = u32::from_ne_bytes(bytes[36..40].try_into().ok()?);
    let tgid = u32::from_ne_bytes(bytes[40..44].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[44..48].try_into().ok()?);
    let gid = u32::from_ne_bytes(bytes[48..52].try_into().ok()?);
    let prot = u32::from_ne_bytes(bytes[52..56].try_into().ok()?);
    let f_flags = u32::from_ne_bytes(bytes[56..60].try_into().ok()?);
    let hook = bytes[60];
    let action = bytes[61];
    let reason = bytes[62];
    let flags = bytes[63];
    let comm: [u8; 16] = bytes[64..80].try_into().ok()?;
    let reserved: [u8; 8] = bytes[80..88].try_into().ok()?;

    // §3.2: a null identity is only possible for a read-failure audit (no
    // inode to name) or an anonymous executable mmap without JIT allowance
    // (file==NULL, so no dev/ino); a half-null identity is corruption.
    let identity_valid = match (dev == 0, ino == 0) {
        (false, false) => true,
        (true, true) => {
            (action == TITAN_EXEC_ACTION_AUDIT && reason == TITAN_EXEC_REASON_READ_FAILURE)
                || (hook == TITAN_EXEC_HOOK_MMAP
                    && reason == TITAN_EXEC_REASON_ANON_NO_JIT
                    && prot & PROT_EXEC != 0)
        }
        _ => false,
    };

    if !matches!(hook, TITAN_EXEC_HOOK_BPRM | TITAN_EXEC_HOOK_MMAP)
        || !matches!(action, TITAN_EXEC_ACTION_AUDIT | TITAN_EXEC_ACTION_DENY)
        || reason > TITAN_EXEC_REASON_MAX
        || pid == 0
        || ts_ns == 0
        // mmap events always carry the requested protection (§3.2).
        || (hook == TITAN_EXEC_HOOK_MMAP && prot == 0)
        // A deny needs a ground the gate can name.
        || (action == TITAN_EXEC_ACTION_DENY
            && matches!(
                reason,
                TITAN_EXEC_REASON_NONE | TITAN_EXEC_REASON_READ_FAILURE
            ))
        || !identity_valid
    {
        return None;
    }

    // `comm` is NUL-terminated and NUL-padded by the producer
    // (`bpf_get_current_comm` zero-fills the remainder); embedded arbitrary
    // bytes before the terminator are allowed, a missing terminator or garbage
    // behind it is not.
    if !comm_is_nul_padded(&comm) {
        return None;
    }

    Some(TitanExecEvent {
        cgroup_id,
        ts_ns,
        dev,
        inode_mode,
        ino,
        generation,
        pid,
        tgid,
        uid,
        gid,
        prot,
        f_flags,
        hook,
        action,
        reason,
        flags,
        comm,
        reserved,
    })
}

/// A producer `comm` is NUL-terminated (task names are at most 15 bytes plus
/// NUL) and all bytes behind the terminator are zero padding (§3.2).
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

/// Serialises one event into the §3.2 wire layout (native endian).
///
/// Writes the documented hard-coded offsets (independent of field order) and
/// does not validate; the reject matrix lives in the decoder only.
pub fn encode_titan_exec_event(event: &TitanExecEvent) -> [u8; TITAN_EXEC_EVENT_WIRE_BYTES] {
    let mut raw = [0u8; TITAN_EXEC_EVENT_WIRE_BYTES];
    raw[0..8].copy_from_slice(&event.cgroup_id.to_ne_bytes());
    raw[8..16].copy_from_slice(&event.ts_ns.to_ne_bytes());
    raw[16..20].copy_from_slice(&event.dev.to_ne_bytes());
    raw[20..24].copy_from_slice(&event.inode_mode.to_ne_bytes());
    raw[24..32].copy_from_slice(&event.ino.to_ne_bytes());
    raw[32..36].copy_from_slice(&event.generation.to_ne_bytes());
    raw[36..40].copy_from_slice(&event.pid.to_ne_bytes());
    raw[40..44].copy_from_slice(&event.tgid.to_ne_bytes());
    raw[44..48].copy_from_slice(&event.uid.to_ne_bytes());
    raw[48..52].copy_from_slice(&event.gid.to_ne_bytes());
    raw[52..56].copy_from_slice(&event.prot.to_ne_bytes());
    raw[56..60].copy_from_slice(&event.f_flags.to_ne_bytes());
    raw[60] = event.hook;
    raw[61] = event.action;
    raw[62] = event.reason;
    raw[63] = event.flags;
    raw[64..80].copy_from_slice(&event.comm);
    raw[80..88].copy_from_slice(&event.reserved);
    raw
}
