//! M2.2 (6.2.0): kernel-side ransomware / rename-storm sensor.
//!
//! Three optional kprobes feed two bounded integer-only signals per TGID:
//!
//! - Signal A (`RANSOM_SIGNAL_ENTROPY_BURST`, `vfs_write`): a high-entropy write
//!   sample to a regular file plus at least `RANSOM_ENTROPY_DISTINCT_THRESHOLD`
//!   distinct inode identities inside `RANSOM_ENTROPY_WINDOW_NS`. The entropy
//!   estimator samples at most 64 user bytes, builds a 256-bit distinct-byte
//!   bitmap and compares its popcount with `RANSOM_ENTROPY_MIN_DISTINCT`
//!   (integer-only, no floating point). Distinct inodes are tracked per TGID
//!   with a bounded last-identity slot; an encryptor that walks file after file
//!   always advances it, which is the class this sensor exists for.
//! - Signal B (`RANSOM_SIGNAL_RENAME_STORM`, `vfs_rename` + `vfs_unlink`): at
//!   least `RANSOM_META_THRESHOLD` rename/unlink operations inside
//!   `RANSOM_META_WINDOW_NS`.
//!
//! Package managers / compilers / backup tools and pooled service workers are
//! exempted through the *real executable identity* (V6.3.0 AP-1): the flags
//! `ALLOW_RANSOM_FULL` / `ALLOW_RANSOM_POOL_META` of `TRUSTED_EXEC_INODES`,
//! resolved from `current->mm->exe_file->f_inode` with BTF-published offsets.
//! `RANSOM_TRUSTED_COMM` (the pre-existing comm-keyed exemption map) is only a
//! *fallback* used when the inode gate is genuinely unavailable (BTF
//! offsets/state missing, or no resolvable `exe_file`); the weaker mode is
//! documented here and reported through the exec-inode gate status. Comm is
//! spoofable by a local attacker, the executable inode is not.
//!
//! The sensor is armed through `RANSOM_STATE` (default 0 = disarmed); the kernel
//! only emits evidence, the userspace core freezes the process group
//! (`SIGSTOP`) and the control plane decides.
//!
//! Map names, the state-word layout and the 64-byte `RansomEvent` are ABI and
//! are looked up by name from `rust/gedefense-core`; do not rename or reshape.

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user,
    },
    macros::{kprobe, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::ProbeContext,
};
use gedefense_common::{
    RansomEvent, RANSOM_ACTION_AUDIT, RANSOM_ENTROPY_DISTINCT_THRESHOLD,
    RANSOM_ENTROPY_MIN_DISTINCT, RANSOM_ENTROPY_WINDOW_NS, RANSOM_EVENT_RING_BYTES,
    RANSOM_EVENT_WIRE_BYTES, RANSOM_META_THRESHOLD, RANSOM_META_WINDOW_NS,
    RANSOM_SAMPLE_BYTES, RANSOM_SIGNAL_ENTROPY_BURST, RANSOM_SIGNAL_RENAME_STORM,
    RANSOM_STATE_ABI, RANSOM_STATE_ABI_SHIFT, RANSOM_STATE_ARMED_SHIFT, RANSOM_STATE_BYTE_MASK,
    RANSOM_STATE_MAGIC, RANSOM_STATE_MAGIC_SHIFT, RANSOM_TRACK_ENTRIES,
    RANSOM_TRUSTED_COMM_ENTRIES, RANSOM_TRUST_FULL, RANSOM_TRUST_POOL_METADATA,
};
use crate::{
    exec_inode::{
        current_exec_trust, EXEC_INODE_RANSOM_FULL_FLAG, EXEC_INODE_RANSOM_POOL_META_FLAG,
    },
    titan_exec::{titan_offsets, titan_probe, TitanOffsets},
};

/// Index of the single sensor state word in `RANSOM_STATE`.
const RANSOM_STATE_INDEX: u32 = 0;
/// Per-TGID tracker value lanes (bounded `[u64; 8]`).
const TRACK_START: usize = 0;
const TRACK_DISTINCT: usize = 1;
const TRACK_LAST_IDENTITY: usize = 2;
const TRACK_LAST_EMIT: usize = 3;
const TRACK_META_START: usize = 4;
const TRACK_META_OPS: usize = 5;
const TRACK_META_LAST_EMIT: usize = 6;
const NS_PER_MS: u64 = 1_000_000;
const S_IFMT: u16 = 0o170000;
const S_IFREG: u16 = 0o100000;

#[map]
pub(crate) static RANSOM_STATE: Array<u64> = Array::with_max_entries(1, 0);
#[map]
pub(crate) static RANSOM_TRACK: LruHashMap<u32, [u64; 8]> =
    LruHashMap::with_max_entries(RANSOM_TRACK_ENTRIES, 0);
#[map]
pub(crate) static RANSOM_TRUSTED_COMM: HashMap<[u8; 16], u8> =
    HashMap::with_max_entries(RANSOM_TRUSTED_COMM_ENTRIES, 0);
#[map]
pub(crate) static RANSOM_EVENTS: RingBuf = RingBuf::with_byte_size(RANSOM_EVENT_RING_BYTES, 0);
#[map]
pub(crate) static RANSOM_EVENTS_EMITTED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static RANSOM_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static RANSOM_TRACK_FAILURES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Wire-layout guard shared with the core decoder.
const _: () = assert!(core::mem::size_of::<RansomEvent>() == RANSOM_EVENT_WIRE_BYTES);

#[inline(always)]
fn increment_counter(counter: &PerCpuArray<u64>) {
    if let Some(value) = counter.get_ptr_mut(0) {
        // SAFETY: per-CPU array index 0 is owned by this CPU for the duration
        // of the update; BPF map races are resolved by the per-CPU split.
        unsafe { *value = (*value).wrapping_add(1) };
    }
}

/// Reads and validates the armed state word. Any absent/foreign word is
/// disarmed (fail-safe): a stale object or a half-written word never emits.
#[inline(always)]
fn ransom_armed() -> bool {
    let Some(word) = RANSOM_STATE.get(RANSOM_STATE_INDEX) else {
        return false;
    };
    let magic =
        ((*word >> RANSOM_STATE_MAGIC_SHIFT) & RANSOM_STATE_BYTE_MASK) as u8;
    let abi = ((*word >> RANSOM_STATE_ABI_SHIFT) & RANSOM_STATE_BYTE_MASK) as u8;
    let armed = (*word >> RANSOM_STATE_ARMED_SHIFT) & 1;
    magic == RANSOM_STATE_MAGIC && abi == RANSOM_STATE_ABI && armed == 1
}

#[inline(always)]
fn trust_level(comm: &[u8; 16]) -> u8 {
    unsafe { RANSOM_TRUSTED_COMM.get(comm).copied().unwrap_or(0) }
}

/// Maps the executable-inode trust flags of `TRUSTED_EXEC_INODES` onto the two
/// pre-existing exemption tiers. The inode gate is authoritative when it is
/// available; `0` means "resolved executable, no exemption".
#[inline(always)]
fn exec_inode_trust_tier(flags: u32) -> u8 {
    if flags & EXEC_INODE_RANSOM_FULL_FLAG != 0 {
        RANSOM_TRUST_FULL
    } else if flags & EXEC_INODE_RANSOM_POOL_META_FLAG != 0 {
        RANSOM_TRUST_POOL_METADATA
    } else {
        0
    }
}

/// Integer-only distinct-byte estimator: samples up to 64 user bytes into a
/// 256-bit bitmap (four u64 words) and returns the popcount of that bitmap.
#[inline(always)]
fn sample_distinct_bytes(buf: u64) -> Option<u32> {
    let mut w0: u64 = 0;
    let mut w1: u64 = 0;
    let mut w2: u64 = 0;
    let mut w3: u64 = 0;
    for offset in 0..RANSOM_SAMPLE_BYTES {
        let address = buf.checked_add(offset as u64)?;
        // SAFETY: the write buffer address is bounded to the caller-supplied
        // count (≥ RANSOM_SAMPLE_BYTES) and the helper performs the copy; a
        // faulting/unmapped buffer is an Err and skips the sample.
        let byte: u8 = unsafe { bpf_probe_read_user(address as *const u8).ok()? };
        if byte < 64 {
            w0 |= 1u64 << byte;
        } else if byte < 128 {
            w1 |= 1u64 << (byte - 64);
        } else if byte < 192 {
            w2 |= 1u64 << (byte - 128);
        } else {
            w3 |= 1u64 << (byte - 192);
        }
    }
    Some(
        popcount64(w0)
            .saturating_add(popcount64(w1))
            .saturating_add(popcount64(w2))
            .saturating_add(popcount64(w3)),
    )
}

/// SWAR population count (no intrinsic/libcall on the BPF target).
#[inline(always)]
fn popcount64(mut value: u64) -> u32 {
    value = value.wrapping_sub((value >> 1) & 0x5555_5555_5555_5555);
    value = (value & 0x3333_3333_3333_3333).wrapping_add((value >> 2) & 0x3333_3333_3333_3333);
    value = value.wrapping_add(value >> 4) & 0x0f0f_0f0f_0f0f_0f0f;
    value = value.wrapping_mul(0x0101_0101_0101_0101);
    (value >> 56) as u32
}

/// Identity hash for one inode: `(s_dev, i_ino)` folded into one u64. A hash is
/// enough here (distinct tracking); collisions can only weaken a heuristic.
#[inline(always)]
fn inode_identity(dev: u32, ino: u64) -> u64 {
    (u64::from(dev) << 32)
        ^ ino
        ^ ino.rotate_left(17)
}

#[inline(always)]
fn emit_ransom_event(
    tgid: u32,
    tid: u32,
    uid_gid: u64,
    count: u32,
    window_ms: u32,
    signal: u8,
    comm: &[u8; 16],
) {
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    if ts_ns == 0 || tgid == 0 {
        return;
    }
    let event = RansomEvent {
        ts_ns,
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        tgid,
        tid,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        count,
        window_ms,
        signal,
        action: RANSOM_ACTION_AUDIT,
        comm: *comm,
        reserved: [0; 6],
    };
    if let Some(mut entry) = RANSOM_EVENTS.reserve::<RansomEvent>(0) {
        // SAFETY: the reservation is exactly `size_of::<RansomEvent>()` bytes
        // and 8-aligned; the record is written once and submitted below.
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
        increment_counter(&RANSOM_EVENTS_EMITTED);
    } else {
        // Ring full: visibility loss is counted, never an action change.
        increment_counter(&RANSOM_RING_DROPS);
    }
}

#[inline(always)]
fn load_track(tgid: u32) -> [u64; 8] {
    match unsafe { RANSOM_TRACK.get(&tgid) } {
        Some(value) => *value,
        None => [0u64; 8],
    }
}

#[inline(always)]
fn store_track(tgid: u32, value: &[u64; 8]) {
    if RANSOM_TRACK.insert(&tgid, value, 0).is_err() {
        increment_counter(&RANSOM_TRACK_FAILURES);
    }
}

/// Signal A bookkeeping (see module docs): bounded per-TGID window, distinct
/// inode identity tracking via the last-identity lane, one event per window.
#[inline(always)]
fn track_entropy(tgid: u32, identity: u64, now: u64, uid_gid: u64, comm: &[u8; 16]) -> Option<()> {
    let mut value = load_track(tgid);
    if value[TRACK_START] == 0 || now.saturating_sub(value[TRACK_START]) > RANSOM_ENTROPY_WINDOW_NS
    {
        value[TRACK_START] = now;
        value[TRACK_DISTINCT] = 0;
        value[TRACK_LAST_IDENTITY] = identity;
    }
    if identity != value[TRACK_LAST_IDENTITY] {
        value[TRACK_DISTINCT] = value[TRACK_DISTINCT].saturating_add(1);
        value[TRACK_LAST_IDENTITY] = identity;
    }
    if value[TRACK_DISTINCT] >= RANSOM_ENTROPY_DISTINCT_THRESHOLD
        && now.saturating_sub(value[TRACK_LAST_EMIT]) > RANSOM_ENTROPY_WINDOW_NS
    {
        let window_ms = now
            .saturating_sub(value[TRACK_START])
            .checked_div(NS_PER_MS)
            .unwrap_or(0)
            .min(u64::from(u32::MAX)) as u32;
        emit_ransom_event(
            tgid,
            tgid,
            uid_gid,
            value[TRACK_DISTINCT] as u32,
            window_ms,
            RANSOM_SIGNAL_ENTROPY_BURST,
            comm,
        );
        value[TRACK_DISTINCT] = 0;
        value[TRACK_START] = now;
        value[TRACK_LAST_EMIT] = now;
    }
    store_track(tgid, &value);
    Some(())
}

/// Signal B bookkeeping: rename/unlink op counter with the bounded window.
#[inline(always)]
fn track_metadata(tgid: u32, now: u64, uid_gid: u64, comm: &[u8; 16]) -> Option<()> {
    let mut value = load_track(tgid);
    if value[TRACK_META_START] == 0
        || now.saturating_sub(value[TRACK_META_START]) > RANSOM_META_WINDOW_NS
    {
        value[TRACK_META_START] = now;
        value[TRACK_META_OPS] = 0;
    }
    value[TRACK_META_OPS] = value[TRACK_META_OPS].saturating_add(1);
    if value[TRACK_META_OPS] >= RANSOM_META_THRESHOLD
        && now.saturating_sub(value[TRACK_META_LAST_EMIT]) > RANSOM_META_WINDOW_NS
    {
        let window_ms = now
            .saturating_sub(value[TRACK_META_START])
            .checked_div(NS_PER_MS)
            .unwrap_or(0)
            .min(u64::from(u32::MAX)) as u32;
        emit_ransom_event(
            tgid,
            tgid,
            uid_gid,
            value[TRACK_META_OPS] as u32,
            window_ms,
            RANSOM_SIGNAL_RENAME_STORM,
            comm,
        );
        value[TRACK_META_OPS] = 0;
        value[TRACK_META_START] = now;
        value[TRACK_META_LAST_EMIT] = now;
    }
    store_track(tgid, &value);
    Some(())
}

#[inline(always)]
fn current_identity(skip_pool_metadata: bool) -> Option<(u32, u32, u64, u64, [u8; 16])> {
    if !ransom_armed() {
        return None;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if tgid == 0 {
        return None;
    }
    let comm = bpf_get_current_comm().ok()?;
    // V6.3.0 AP-1: inode identity first, comm allowlist only when the gate is
    // genuinely unavailable for this decision.
    let tier = match current_exec_trust() {
        Some((_identity, flags)) => exec_inode_trust_tier(flags),
        None => trust_level(&comm),
    };
    if tier == RANSOM_TRUST_FULL || (skip_pool_metadata && tier == RANSOM_TRUST_POOL_METADATA) {
        return None;
    }
    Some((
        tgid,
        pid_tgid as u32,
        unsafe { bpf_ktime_get_ns() },
        bpf_get_current_uid_gid(),
        comm,
    ))
}

/// `vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)`.
#[kprobe]
pub fn gedefense_ransom_vfs_write(ctx: ProbeContext) -> u32 {
    let _ = try_ransom_vfs_write(&ctx);
    0
}

#[inline(always)]
fn try_ransom_vfs_write(ctx: &ProbeContext) -> Option<()> {
    let (tgid, _tid, now, uid_gid, comm) = current_identity(false)?;
    let file: u64 = ctx.arg(0)?;
    let buffer: u64 = ctx.arg(1)?;
    let count: u64 = ctx.arg(2)?;
    if file == 0 || buffer == 0 || count < RANSOM_SAMPLE_BYTES as u64 {
        return None;
    }
    let offsets: TitanOffsets = titan_offsets()?;
    let inode: u64 = titan_probe(file, offsets.file_inode)?;
    if inode == 0 {
        return None;
    }
    let mode: u16 = titan_probe(inode, offsets.inode_mode)?;
    if mode & S_IFMT != S_IFREG {
        return None;
    }
    if sample_distinct_bytes(buffer)? < RANSOM_ENTROPY_MIN_DISTINCT {
        return None;
    }
    let super_block: u64 = titan_probe(inode, offsets.inode_sb)?;
    if super_block == 0 {
        return None;
    }
    let dev: u32 = titan_probe(super_block, offsets.sb_dev)?;
    let ino: u64 = titan_probe(inode, offsets.inode_ino)?;
    if dev == 0 || ino == 0 {
        return None;
    }
    track_entropy(tgid, inode_identity(dev, ino), now, uid_gid, &comm)
}

/// `vfs_rename(...)`: only the operation itself is counted (no struct reads).
#[kprobe]
pub fn gedefense_ransom_vfs_rename(_ctx: ProbeContext) -> u32 {
    let _ = try_ransom_metadata();
    0
}

/// `vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode **delegated)`.
#[kprobe]
pub fn gedefense_ransom_vfs_unlink(_ctx: ProbeContext) -> u32 {
    let _ = try_ransom_metadata();
    0
}

#[inline(always)]
fn try_ransom_metadata() -> Option<()> {
    let (tgid, _tid, now, uid_gid, comm) = current_identity(true)?;
    track_metadata(tgid, now, uid_gid, &comm)
}
