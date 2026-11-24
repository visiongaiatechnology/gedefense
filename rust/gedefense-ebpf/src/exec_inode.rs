//! V6.3.0 AP-1 — executable-inode identity resolution (eBPF half).
//!
//! Replaces the spoofable `bpf_get_current_comm()` allowlists of the credential
//! guard and the ransomware sensor with the identity of the *real* executable:
//!
//! ```text
//! task_struct.mm -> mm_struct.exe_file -> file.f_inode -> inode
//!   -> (inode.i_ino, inode.i_sb->s_dev)
//! ```
//!
//! Every kernel structure offset is resolved from vmlinux BTF by the privileged
//! core and published into `EXEC_INODE_OFFSETS`; nothing is hard-coded here. The
//! readers re-validate the magic/ABI words, the struct sizes and every field
//! bound before a single pointer is dereferenced. An absent/stale table, a
//! disarmed `EXEC_INODE_STATE` word or a failed chain read makes the gate
//! unavailable (`None`): the callers then use the documented comm fallback and
//! say so in status/events. A broken gate never locks out login.
//!
//! This module owns the maps (no programs of its own): the credential guard
//! (`credential_guard.rs`) and the ransomware sensor (`ransom.rs`) consume the
//! `#[inline(always)]` helpers below.
//!
//! Trust contract: [`TRUSTED_EXEC_INODES`] is keyed by the shared 16-byte
//! `(s_dev u32 LE, i_ino u64 LE, zero4)` identity and stores the
//! `EXEC_INODE_ALLOW_*` bitmask. `MALWARE_TTL_INODES` is a separate, TTL-bounded
//! carrier map so the credential-deny path and the core's TTL loader never race
//! on one map handle with a different value semantic.
//!
//! Verifier discipline: no allocations, no static `&[&str]` tables, no
//! unbounded loops; only bounded `bpf_probe_read_kernel` reads and hash-map
//! lookups.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
    },
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
};
use gedefense_common::{
    decode_exec_inode_key, exec_inode_key, kernel_s_dev_to_stat_u32, ExecInodeEvent,
    EXEC_INODE_ACTION_DENIED_UNTRUSTED, EXEC_INODE_ACTION_FALLBACK_COMM,
    EXEC_INODE_ACTION_OBSERVED_MISMATCH, EXEC_INODE_ALLOW_CRED_READ,
    EXEC_INODE_ALLOW_RANSOM_FULL, EXEC_INODE_ALLOW_RANSOM_POOL_META, EXEC_INODE_EVENT_RING_BYTES,
    EXEC_INODE_EVENT_WIRE_BYTES, EXEC_INODE_FLAGS_ALL, EXEC_INODE_MAX_STRUCT_SIZE,
    EXEC_INODE_OFF_ABI, EXEC_INODE_OFF_FILE_F_INODE, EXEC_INODE_OFF_INODE_I_INO,
    EXEC_INODE_OFF_INODE_I_SB, EXEC_INODE_OFF_MAGIC, EXEC_INODE_OFF_MM_EXE_FILE,
    EXEC_INODE_OFF_MM_SIZE, EXEC_INODE_OFF_SUPER_S_DEV, EXEC_INODE_OFF_TASK_MM,
    EXEC_INODE_OFF_TASK_SIZE,
    EXEC_INODE_OFFSETS_ABI, EXEC_INODE_OFFSETS_MAGIC, EXEC_INODE_OFFSETS_TABLE_LEN,
    EXEC_INODE_STATE_ABI, EXEC_INODE_STATE_ABI_SHIFT, EXEC_INODE_STATE_ARMED_SHIFT,
    EXEC_INODE_STATE_BYTE_MASK, EXEC_INODE_STATE_MAGIC, EXEC_INODE_STATE_MAGIC_SHIFT,
    EXEC_INODE_TTL_MAP_ENTRIES, EXEC_INODE_TRUST_MAP_ENTRIES,
};

/// Index of the single gate state word in `EXEC_INODE_STATE`.
const EXEC_INODE_STATE_INDEX: u32 = 0;
/// Identity-key length reused for the two map key arrays.
const EXEC_INODE_KEY_LEN: usize = 16;
/// The offset table is indexed by the shared `EXEC_INODE_OFF_*` enum.
const EXEC_INODE_OFFSETS_ENTRIES: u32 = EXEC_INODE_OFFSETS_TABLE_LEN as u32;

#[map]
pub(crate) static EXEC_INODE_STATE: Array<u64> = Array::with_max_entries(1, 0);
/// BTF-resolved runtime offsets (see the `EXEC_INODE_OFF_*` index enum).
#[map]
pub(crate) static EXEC_INODE_OFFSETS: Array<u32> =
    Array::with_max_entries(EXEC_INODE_OFFSETS_ENTRIES, 0);
/// Trusted executable identities: `(s_dev, i_ino)` -> `EXEC_INODE_ALLOW_*`.
#[map]
pub(crate) static TRUSTED_EXEC_INODES: HashMap<[u8; EXEC_INODE_KEY_LEN], u32> =
    HashMap::with_max_entries(EXEC_INODE_TRUST_MAP_ENTRIES, 0);
/// TTL-bounded behaviour-carrier locks (separate handle from the pre-existing
/// `MALWARE_DENIED_INODES` so the two loaders never race on one map).
#[map]
pub(crate) static MALWARE_TTL_INODES: HashMap<[u8; EXEC_INODE_KEY_LEN], u32> =
    HashMap::with_max_entries(EXEC_INODE_TTL_MAP_ENTRIES, 0);
/// Bounded name/path mismatch evidence ring (1024 queued 64-byte records).
#[map]
pub(crate) static EXEC_INODE_EVENTS: RingBuf =
    RingBuf::with_byte_size(EXEC_INODE_EVENT_RING_BYTES, 0);
/// Number of decisions in which the inode gate allowed the operation.
#[map]
pub(crate) static EXEC_INODE_ALLOWED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
/// Number of decisions in which the inode gate denied the operation.
#[map]
pub(crate) static EXEC_INODE_DENIED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static EXEC_INODE_EVENTS_EMITTED: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static EXEC_INODE_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
/// Per-CPU count of comm-fallback decisions. The fallback event is emitted at
/// most once per CPU (bounded by the buffer capacity class) so a
/// permanently-unavailable BTF table cannot flood the evidence ring.
#[map]
pub(crate) static EXEC_INODE_FALLBACK_EMITTED: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(1, 0);

/// Wire-layout guard shared with the core decoder: a drift between the struct
/// and the published wire size would make the core reject every record.
const _: () = assert!(core::mem::size_of::<ExecInodeEvent>() == EXEC_INODE_EVENT_WIRE_BYTES);

/// Runtime offset table re-read from `EXEC_INODE_OFFSETS` (never hard-coded).
#[derive(Clone, Copy)]
pub(crate) struct ExecInodeOffsets {
    pub(crate) task_mm: u32,
    pub(crate) task_size: u32,
    pub(crate) mm_exe_file: u32,
    pub(crate) mm_size: u32,
    pub(crate) file_inode: u32,
    pub(crate) inode_ino: u32,
    pub(crate) inode_sb: u32,
    pub(crate) sb_dev: u32,
}

#[inline(always)]
fn increment_counter(counter: &PerCpuArray<u64>) {
    if let Some(value) = counter.get_ptr_mut(0) {
        // SAFETY: per-CPU array index 0 is owned by this CPU for the duration of
        // the update; the BPF map's per-CPU split resolves cross-CPU races.
        unsafe { *value = (*value).wrapping_add(1) };
    }
}

/// Reads one `EXEC_INODE_OFFSETS` entry; an absent slot is a read failure.
#[inline(always)]
fn exec_inode_offset(index: u32) -> Option<u32> {
    EXEC_INODE_OFFSETS.get(index).copied()
}

/// Field fits the BTF-reported structure size (defensive against a partial or
/// stale offset table).
#[inline(always)]
fn exec_inode_field_fits(offset: u32, width: u64, size: u32) -> bool {
    u64::from(offset).saturating_add(width) <= u64::from(size)
}

/// Reads and fully validates the `EXEC_INODE_OFFSETS` table. `None` for every
/// absent/partial/implausible table, so a caller fails over to the documented
/// comm fallback instead of dereferencing a guessed offset.
#[inline(always)]
pub(crate) fn exec_inode_offsets() -> Option<ExecInodeOffsets> {
    if exec_inode_offset(EXEC_INODE_OFF_MAGIC)? != EXEC_INODE_OFFSETS_MAGIC {
        return None;
    }
    if exec_inode_offset(EXEC_INODE_OFF_ABI)? != EXEC_INODE_OFFSETS_ABI {
        return None;
    }
    let task_size = exec_inode_offset(EXEC_INODE_OFF_TASK_SIZE)?;
    let mm_size = exec_inode_offset(EXEC_INODE_OFF_MM_SIZE)?;
    let offsets = ExecInodeOffsets {
        task_mm: exec_inode_offset(EXEC_INODE_OFF_TASK_MM)?,
        task_size,
        mm_exe_file: exec_inode_offset(EXEC_INODE_OFF_MM_EXE_FILE)?,
        mm_size,
        file_inode: exec_inode_offset(EXEC_INODE_OFF_FILE_F_INODE)?,
        inode_ino: exec_inode_offset(EXEC_INODE_OFF_INODE_I_INO)?,
        inode_sb: exec_inode_offset(EXEC_INODE_OFF_INODE_I_SB)?,
        sb_dev: exec_inode_offset(EXEC_INODE_OFF_SUPER_S_DEV)?,
    };
    // Every pointer field is 8-aligned and non-zero (a zero "offset" would
    // silently read the struct header instead of the field). The task/mm sizes
    // bound the two dereferences this module performs on those structures; the
    // file/inode/super sizes are validated by the core publisher and re-bounded
    // here against the documented maximum before they are used.
    if task_size < 8
        || task_size > EXEC_INODE_MAX_STRUCT_SIZE
        || mm_size < 8
        || mm_size > EXEC_INODE_MAX_STRUCT_SIZE
        || offsets.task_mm == 0
        || offsets.task_mm & 7 != 0
        || !exec_inode_field_fits(offsets.task_mm, 8, task_size)
        || offsets.mm_exe_file == 0
        || offsets.mm_exe_file & 7 != 0
        || !exec_inode_field_fits(offsets.mm_exe_file, 8, mm_size)
        || offsets.file_inode == 0
        || offsets.file_inode & 7 != 0
        || !exec_inode_field_fits(offsets.file_inode, 8, EXEC_INODE_MAX_STRUCT_SIZE)
        || offsets.inode_ino == 0
        || offsets.inode_ino & 7 != 0
        || !exec_inode_field_fits(offsets.inode_ino, 8, EXEC_INODE_MAX_STRUCT_SIZE)
        || offsets.inode_sb == 0
        || offsets.inode_sb & 7 != 0
        || !exec_inode_field_fits(offsets.inode_sb, 8, EXEC_INODE_MAX_STRUCT_SIZE)
        || offsets.sb_dev == 0
        || offsets.sb_dev & 3 != 0
        || offsets.sb_dev > EXEC_INODE_MAX_STRUCT_SIZE - 4
    {
        return None;
    }
    Some(offsets)
}

/// Reads and validates the gate state word (`epoch | armed | magic | ABI`).
/// Absent/foreign/stale words are "not available", never "active".
#[inline(always)]
pub(crate) fn exec_inode_state_active() -> bool {
    let Some(word) = EXEC_INODE_STATE.get(EXEC_INODE_STATE_INDEX) else {
        return false;
    };
    let magic = ((*word >> EXEC_INODE_STATE_MAGIC_SHIFT) & EXEC_INODE_STATE_BYTE_MASK) as u8;
    let abi = ((*word >> EXEC_INODE_STATE_ABI_SHIFT) & EXEC_INODE_STATE_BYTE_MASK) as u8;
    let armed = (*word >> EXEC_INODE_STATE_ARMED_SHIFT) & 1;
    magic == EXEC_INODE_STATE_MAGIC && abi == EXEC_INODE_STATE_ABI && armed == 1
}

/// Bounded kernel-structure field read. The base pointer is deliberately kept
/// as a scalar `u64` and only the helper turns the computed address into a real
/// kernel access — the verifier-safe pattern for runtime offsets.
#[inline(always)]
fn exec_inode_probe<T>(base: u64, offset: u32) -> Option<T> {
    let address = base.wrapping_add(u64::from(offset)) as *const T;
    // SAFETY: the helper validates the kernel address; a faulting read is an
    // Err and makes the caller fail over to the comm fallback.
    unsafe { bpf_probe_read_kernel(address).ok() }
}

/// Resolves the current task's executable identity and the trust bitmask found
/// in `TRUSTED_EXEC_INODES`. The second tuple element is the trust flags `u32`
/// (0 when the executable is not trusted); the function only succeeds when the
/// gate is armed, the offsets are valid and both published structure sizes are
/// greater than zero. `None` is "gate unavailable for this decision", never
/// "trusted".
#[inline(always)]
pub(crate) fn current_exec_identity(
    offsets: &ExecInodeOffsets,
) -> Option<([u8; EXEC_INODE_KEY_LEN], u32)> {
    if offsets.task_size == 0 || offsets.mm_size == 0 {
        return None;
    }
    // SAFETY: bpf_get_current_task returns the current task_struct pointer and
    // is available to every program type that may call these helpers.
    let task: u64 = unsafe { bpf_get_current_task() };
    if task == 0 {
        return None;
    }
    let mm: u64 = exec_inode_probe(task, offsets.task_mm)?;
    if mm == 0 {
        // Kernel threads and tasks between exec/exit have no user mm: no
        // executable identity exists, so the caller uses the comm fallback.
        return None;
    }
    let exe_file: u64 = exec_inode_probe(mm, offsets.mm_exe_file)?;
    if exe_file == 0 {
        return None;
    }
    let inode: u64 = exec_inode_probe(exe_file, offsets.file_inode)?;
    if inode == 0 {
        return None;
    }
    let super_block: u64 = exec_inode_probe(inode, offsets.inode_sb)?;
    if super_block == 0 {
        return None;
    }
    let raw_dev: u32 = exec_inode_probe(super_block, offsets.sb_dev)?;
    let dev = kernel_s_dev_to_stat_u32(raw_dev);
    let ino: u64 = exec_inode_probe(inode, offsets.inode_ino)?;
    if dev == 0 || ino == 0 {
        return None;
    }
    let identity = exec_inode_key(dev, ino);
    let flags = unsafe { TRUSTED_EXEC_INODES.get(&identity).copied().unwrap_or(0) };
    // A core-written value is a non-zero subset of the documented flags; an
    // undefined bit means a foreign/stale object -> gate unavailable.
    if flags != 0 && (flags & !EXEC_INODE_FLAGS_ALL) != 0 {
        return None;
    }
    Some((identity, flags))
}

/// Looks up the trust flags of an already resolved executable identity.
/// `None` when the gate is not armed/published; `Some(0)` means "available, but
/// the executable is not trusted" — the distinction the callers need.
///
/// Part of the module API consumed by the guards and future sensors; the shipped
/// guards resolve identity and flags together through [`current_exec_trust`].
#[allow(dead_code)]
#[inline(always)]
pub(crate) fn exec_inode_flags(identity: &[u8; EXEC_INODE_KEY_LEN]) -> Option<u32> {
    if !exec_inode_state_active() {
        return None;
    }
    exec_inode_offsets()?;
    let flags = unsafe { TRUSTED_EXEC_INODES.get(identity).copied().unwrap_or(0) };
    if flags != 0 && (flags & !EXEC_INODE_FLAGS_ALL) != 0 {
        return None;
    }
    Some(flags)
}

/// Resolves the current executable's trust flags; `None` = gate unavailable.
#[inline(always)]
pub(crate) fn current_exec_trust() -> Option<([u8; EXEC_INODE_KEY_LEN], u32)> {
    if !exec_inode_state_active() {
        return None;
    }
    let offsets = exec_inode_offsets()?;
    current_exec_identity(&offsets)
}

/// Gate verdict for one operations class:
/// `Some(true)` = trusted, `Some(false)` = resolved but not trusted,
/// `None` = gate unavailable (the caller must use the documented comm fallback).
/// Kept as the small public decision API next to [`current_exec_trust`], which
/// returns the identity/flags the evidence records need.
#[allow(dead_code)]
#[inline(always)]
pub(crate) fn exec_inode_allowed(flag: u32) -> Option<bool> {
    let (_, flags) = current_exec_trust()?;
    Some(flags & flag != 0)
}

/// Counts one inode-gate allow decision (`EXEC_INODE_ALLOWED`). Only the guard
/// that actually made a decision calls this — a bare availability probe does
/// not inflate the operator-visible enforcement counters.
#[inline(always)]
pub(crate) fn note_exec_inode_allowed() {
    increment_counter(&EXEC_INODE_ALLOWED);
}

/// Counts one inode-gate deny decision (`EXEC_INODE_DENIED`).
#[inline(always)]
pub(crate) fn note_exec_inode_denied() {
    increment_counter(&EXEC_INODE_DENIED);
}

/// True when a TTL malware lock is held for this inode identity. Independent of
/// the gate state: a behaviour-carrier lock is enforced even when BTF offsets
/// are unavailable (same contract as the pre-existing `MALWARE_DENIED_INODES`).
#[inline(always)]
pub(crate) fn ttl_inode_denied(identity: &[u8; EXEC_INODE_KEY_LEN]) -> bool {
    unsafe { MALWARE_TTL_INODES.get(identity).is_some() }
}

/// Emits one 64-byte `ExecInodeEvent` into `EXEC_INODE_EVENTS`. The identity is
/// all-zero for a fallback record (no executable identity was resolvable); the
/// comm slot is NUL-padded exactly like the pre-existing credential event writer
/// so the decoder contract always holds.
#[inline(always)]
pub(crate) fn emit_exec_inode_event(
    identity: &[u8; EXEC_INODE_KEY_LEN],
    trust_flags: u32,
    action: u8,
    comm: &[u8; 16],
) {
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    if ts_ns == 0 || pid == 0 {
        return;
    }
    let (dev, ino) = match decode_exec_inode_key(identity) {
        Some(values) => values,
        None => (0u32, 0u64),
    };
    let mut comm_padded = *comm;
    let mut has_nul = false;
    let mut index = 0usize;
    while index < comm_padded.len() {
        if comm_padded[index] == 0 {
            has_nul = true;
            break;
        }
        index += 1;
    }
    if !has_nul {
        comm_padded[15] = 0;
    }
    // An empty task name is not representable in the decoder contract; the
    // fallback record then names the unknown process explicitly.
    if comm_padded[0] == 0 {
        comm_padded[0] = b'?';
    }
    let event = ExecInodeEvent {
        ts_ns,
        pid,
        tgid: (pid_tgid >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        exe_dev: dev,
        exe_ino: ino,
        trust_flags,
        action,
        comm: comm_padded,
        reserved: [0; 11],
    };
    if let Some(mut entry) = EXEC_INODE_EVENTS.reserve::<ExecInodeEvent>(0) {
        // SAFETY: the reservation is exactly size_of::<ExecInodeEvent>() bytes,
        // 8-aligned, written once and submitted below.
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
        increment_counter(&EXEC_INODE_EVENTS_EMITTED);
    } else {
        // Ring full: visibility loss is counted, never an action change.
        increment_counter(&EXEC_INODE_RING_DROPS);
    }
}

/// Emits the "gate unavailable, comm fallback decided" audit record at most once
/// per CPU. A permanently-missing BTF table must be visible to the operator
/// without flooding the ring on every credential read.
#[inline(always)]
pub(crate) fn emit_exec_inode_fallback_once(comm: &[u8; 16]) {
    let counter = EXEC_INODE_FALLBACK_EMITTED.get_ptr_mut(0);
    let empty_identity = [0u8; EXEC_INODE_KEY_LEN];
    match counter {
        Some(value) => {
            // SAFETY: per-CPU array index 0 is owned by this CPU for the
            // duration of the update.
            let first = unsafe { *value } == 0;
            unsafe { *value = (*value).wrapping_add(1) };
            if first {
                emit_exec_inode_event(
                    &empty_identity,
                    0,
                    EXEC_INODE_ACTION_FALLBACK_COMM,
                    comm,
                );
            }
        }
        // If the counter map is absent (foreign object) emit once anyway: the
        // operator-facing fact matters more than a potential duplicate.
        None => emit_exec_inode_event(&empty_identity, 0, EXEC_INODE_ACTION_FALLBACK_COMM, comm),
    }
}

/// Convenience re-exports for the two consumer modules: the credential guard
/// needs the mismatch/deny action names and the ransom sensor needs the flag
/// bits; keeping the constants here makes the intent of the call sites explicit.
pub(crate) const EXEC_INODE_MISMATCH_ACTION: u8 = EXEC_INODE_ACTION_OBSERVED_MISMATCH;
pub(crate) const EXEC_INODE_DENY_ACTION: u8 = EXEC_INODE_ACTION_DENIED_UNTRUSTED;
pub(crate) const EXEC_INODE_CRED_FLAG: u32 = EXEC_INODE_ALLOW_CRED_READ;
pub(crate) const EXEC_INODE_RANSOM_FULL_FLAG: u32 = EXEC_INODE_ALLOW_RANSOM_FULL;
pub(crate) const EXEC_INODE_RANSOM_POOL_META_FLAG: u32 = EXEC_INODE_ALLOW_RANSOM_POOL_META;

/// Bounded comm extraction helper shared by the guards: reads the current task
/// name and returns it NUL-padded (zero-filled when the helper fails).
#[inline(always)]
pub(crate) fn current_comm() -> [u8; 16] {
    bpf_get_current_comm().unwrap_or([0u8; 16])
}
