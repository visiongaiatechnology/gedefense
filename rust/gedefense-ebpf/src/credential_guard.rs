//! M2.4 (6.2.0): eBPF `file_open` LSM credential guard (kernel half).
//!
//! Denies `file_open` on the protected credential inodes for every task that is
//! not an allowlisted authentication/system binary:
//!
//! - exact protected inodes: `/etc/shadow`, `/etc/gshadow` and the files of
//!   `/etc/vgt/gedefense/secrets/` (populated by the core into
//!   `CRED_GUARD_FILES`),
//! - protected directory: a file whose *immediate parent* inode is in
//!   `CRED_GUARD_DIRS` (`/etc/vgt/gedefense/secrets`), so a secret created after
//!   startup is covered without an unbounded path walk.
//!
//! Resolution is bounded and uses only the existing TITAN ABI-2 BTF offsets:
//! `file -> f_inode -> {i_sb -> s_dev, i_ino, i_mode}` and one
//! `dentry -> d_parent -> d_inode` step for the directory key. No `d_name` walk,
//! no string copy, no unbounded loop.
//!
//! Fail-safe: an absent/invalid `CRED_GUARD_STATE` word means "not ready" and
//! the hook returns 0 (allow) - a broken guard must never lock out PAM/login.
//! The core reports `active=0` in that case instead of claiming enforcement.
//! Every structural read failure is counted (`CRED_GUARD_READ_FAILURES`) and
//! audited in the ring, never silently swallowed.
//!
//! Allowlist: exact auth/system task names plus `systemd*`/`gedefense*`
//! prefixes (`gedefense_common::credential_reader_allowed`). Task names are
//! spoofable by a local attacker; the control plane correlates
//! `XDR.CREDENTIAL_READ_BLOCKED` with the XDR exec sensor instead of trusting
//! the name alone.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{lsm, map},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::LsmContext,
};
use gedefense_common::{
    credential_identity_key, credential_reader_allowed, kernel_s_dev_to_stat_u32,
    CredentialGuardEvent, CRED_GUARD_ACTION_DENY, CRED_GUARD_DIR_MAP_ENTRIES,
    CRED_GUARD_EVENT_RING_BYTES, CRED_GUARD_EVENT_WIRE_BYTES, CRED_GUARD_FILE_MAP_ENTRIES,
    CRED_GUARD_STATE_ABI, CRED_GUARD_STATE_ABI_SHIFT, CRED_GUARD_STATE_ARMED_SHIFT,
    CRED_GUARD_STATE_BYTE_MASK, CRED_GUARD_STATE_MAGIC, CRED_GUARD_STATE_MAGIC_SHIFT,
};
use crate::{titan_offsets, titan_probe, TitanOffsets};

const EACCES: i32 = 13;
/// Index of the single guard state word in `CRED_GUARD_STATE`.
const CRED_GUARD_STATE_INDEX: u32 = 0;

#[map]
pub(crate) static CRED_GUARD_STATE: Array<u64> = Array::with_max_entries(1, 0);
/// Exact protected file inodes (key = `dev LE u32 | ino LE u64 | zero4`).
#[map]
pub(crate) static CRED_GUARD_FILES: HashMap<[u8; 16], u8> =
    HashMap::with_max_entries(CRED_GUARD_FILE_MAP_ENTRIES, 0);
/// Malware-locked inodes: files detected in non-writable drop dirs (`0755` non-root)
/// whose unlinking was refused without broad DAC override are locked at `file_open`.
#[map]
pub(crate) static MALWARE_DENIED_INODES: HashMap<[u8; 16], u8> =
    HashMap::with_max_entries(4_096, 0);
/// Protected directory inodes: every direct child is a credential secret.
#[map]
pub(crate) static CRED_GUARD_DIRS: HashMap<[u8; 16], u8> =
    HashMap::with_max_entries(CRED_GUARD_DIR_MAP_ENTRIES, 0);
#[map]
pub(crate) static CRED_GUARD_EVENTS: RingBuf = RingBuf::with_byte_size(CRED_GUARD_EVENT_RING_BYTES, 0);
#[map]
pub(crate) static CRED_GUARD_EVENTS_EMITTED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static CRED_GUARD_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static CRED_GUARD_READ_FAILURES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static CRED_GUARD_DENIED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

const _: () = assert!(
    core::mem::size_of::<CredentialGuardEvent>() == CRED_GUARD_EVENT_WIRE_BYTES
);

#[inline(always)]
fn increment_counter(counter: &PerCpuArray<u64>) {
    if let Some(value) = counter.get_ptr_mut(0) {
        // SAFETY: per-CPU array index 0 is owned by this CPU for this update.
        unsafe { *value = (*value).wrapping_add(1) };
    }
}

/// Reads and validates the guard state word. Absent/foreign/stale = not ready.
#[inline(always)]
fn guard_active() -> bool {
    let Some(word) = CRED_GUARD_STATE.get(CRED_GUARD_STATE_INDEX) else {
        return false;
    };
    let magic = ((*word >> CRED_GUARD_STATE_MAGIC_SHIFT) & CRED_GUARD_STATE_BYTE_MASK) as u8;
    let abi = ((*word >> CRED_GUARD_STATE_ABI_SHIFT) & CRED_GUARD_STATE_BYTE_MASK) as u8;
    let armed = (*word >> CRED_GUARD_STATE_ARMED_SHIFT) & 1;
    magic == CRED_GUARD_STATE_MAGIC && abi == CRED_GUARD_STATE_ABI && armed == 1
}

/// Identity of a kernel inode through the shared runtime offset table.
#[inline(always)]
fn inode_identity(inode: u64, offsets: &TitanOffsets) -> Option<([u8; 16], u32)> {
    if inode == 0 {
        return None;
    }
    let super_block: u64 = titan_probe(inode, offsets.inode_sb)?;
    if super_block == 0 {
        return None;
    }
    let raw_dev: u32 = titan_probe(super_block, offsets.sb_dev)?;
    let dev = kernel_s_dev_to_stat_u32(raw_dev);
    let ino: u64 = titan_probe(inode, offsets.inode_ino)?;
    let mode: u16 = titan_probe(inode, offsets.inode_mode)?;
    if dev == 0 || ino == 0 {
        return None;
    }
    Some((credential_identity_key(dev, ino), u32::from(mode)))
}

/// True when the opened file is an exact protected inode or a direct child of a
/// protected secrets directory. One bounded parent step only.
#[inline(always)]
fn credential_target(file_ptr: u64, offsets: &TitanOffsets) -> Option<([u8; 16], u32)> {
    let inode: u64 = titan_probe(file_ptr, offsets.file_inode)?;
    let (identity, mode) = inode_identity(inode, offsets)?;
    if unsafe { CRED_GUARD_FILES.get(&identity).is_some() } {
        return Some((identity, mode));
    }
    let dentry: u64 = titan_probe(file_ptr, offsets.file_f_path_dentry)?;
    if dentry == 0 {
        return None;
    }
    let parent: u64 = titan_probe(dentry, offsets.dentry_parent)?;
    if parent == 0 {
        return None;
    }
    let parent_inode: u64 = titan_probe(parent, offsets.dentry_inode)?;
    let (parent_identity, _) = inode_identity(parent_inode, offsets)?;
    if unsafe { CRED_GUARD_DIRS.get(&parent_identity).is_some() } {
        return Some((identity, mode));
    }
    None
}

#[inline(always)]
fn emit_credential_event(identity: &[u8; 16], inode_mode: u32, action: u8, comm: &[u8; 16]) {
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    if ts_ns == 0 || pid == 0 {
        return;
    }
    let uid_gid = bpf_get_current_uid_gid();
    let mut raw = [0u8; 16];
    raw.copy_from_slice(identity);
    let dev = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let ino = u64::from_le_bytes([
        raw[4], raw[5], raw[6], raw[7], raw[8], raw[9], raw[10], raw[11],
    ]);
    // The decoder requires a NUL-terminated comm; a 16-byte kernel task name is
    // truncated (the record then names 15 bytes) instead of becoming invalid.
    let mut comm_padded = *comm;
    let mut has_nul = false;
    let mut idx = 0usize;
    while idx < comm_padded.len() {
        if comm_padded[idx] == 0 {
            has_nul = true;
            break;
        }
        idx += 1;
    }
    if !has_nul {
        comm_padded[15] = 0;
    }
    let event = CredentialGuardEvent {
        ts_ns,
        dev,
        ino,
        pid,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        inode_mode,
        action,
        reserved: [0; 3],
        comm: comm_padded,
        reserved2: [0; 4],
    };
    if let Some(mut entry) = CRED_GUARD_EVENTS.reserve::<CredentialGuardEvent>(0) {
        // SAFETY: the reservation is exactly size_of::<CredentialGuardEvent>()
        // bytes, 8-aligned, written once and submitted below.
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
        increment_counter(&CRED_GUARD_EVENTS_EMITTED);
    } else {
        increment_counter(&CRED_GUARD_RING_DROPS);
    }
}

#[inline(always)]
fn starts_with_bytes(haystack: &[u8], prefix: &[u8]) -> bool {
    if haystack.len() < prefix.len() {
        return false;
    }
    let mut i = 0usize;
    while i < prefix.len() {
        let Some(&a) = haystack.get(i) else {
            return false;
        };
        let Some(&b) = prefix.get(i) else {
            return false;
        };
        if a != b {
            return false;
        }
        i += 1;
    }
    true
}

#[lsm(hook = "file_open")]
pub fn gedefense_credential_guard_file_open(ctx: LsmContext) -> i32 {
    match try_credential_guard_file_open(&ctx) {
        Ok(verdict) | Err(verdict) => verdict,
    }
}

#[inline(always)]
fn try_credential_guard_file_open(ctx: &LsmContext) -> Result<i32, i32> {
    // Defer to a previously attached LSM program exactly like the kernel chain.
    let previous: i32 = ctx.arg(1);
    if previous != 0 {
        return Ok(previous);
    }
    let file_ptr: u64 = ctx.arg(0);
    if file_ptr == 0 {
        increment_counter(&CRED_GUARD_READ_FAILURES);
        return Ok(0);
    }
    let offsets = match titan_offsets() {
        Some(offsets) => offsets,
        None => {
            increment_counter(&CRED_GUARD_READ_FAILURES);
            return Ok(0);
        }
    };
    let inode: u64 = match titan_probe(file_ptr, offsets.file_inode) {
        Some(v) => v,
        None => return Ok(0),
    };
    let Some((identity, mode)) = inode_identity(inode, &offsets) else {
        return Ok(0);
    };
    if unsafe { MALWARE_DENIED_INODES.get(&identity).is_some() } {
        let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        if !starts_with_bytes(&comm, b"gedefense-") {
            increment_counter(&CRED_GUARD_DENIED);
            emit_credential_event(&identity, mode, CRED_GUARD_ACTION_DENY, &comm);
            return Err(-EACCES);
        }
    }
    if !guard_active() {
        return Ok(0);
    }
    // Cheap path: most opens are not credential targets.
    let target = match credential_target(file_ptr, &offsets) {
        Some(target) => target,
        None => return Ok(0),
    };
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let mut comm_end = 0usize;
    while comm_end < comm.len() {
        if comm[comm_end] == 0 {
            break;
        }
        comm_end += 1;
    }
    if credential_reader_allowed(&comm[..comm_end]) {
        return Ok(0);
    }
    increment_counter(&CRED_GUARD_DENIED);
    emit_credential_event(&target.0, target.1, CRED_GUARD_ACTION_DENY, &comm);
    // Deny: the open cannot proceed. The event already names the identity.
    Err(-EACCES)
}
