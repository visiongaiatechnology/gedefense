//! V6.3.0 AP-9 (S12) — high-priority security evidence ring and telemetry
//! token buckets (eBPF half).
//!
//! This module owns no program of its own. It provides the two-class telemetry
//! backpressure contract for every emitter in the object:
//!
//! - [`SEC_CRIT_EVENTS`] is an independent 256 KiB ring (4096 queued 64-byte
//!   records) for critical security evidence. Bulk telemetry (exec argv, kernel
//!   probe, network flow, DNS) can therefore never displace it: the rings are
//!   separate BPF maps with separate consumers.
//! - [`TELEMETRY_FLOOD_BUCKETS`] is a per-`(class, cgroup, uid)` token bucket.
//!   Bulk emitters call [`telemetry_budget_allow`] *before* reserving a ring
//!   slot; a throttled record is not written and the refusal is counted
//!   ([`telemetry_note_suppressed`]). Only the offending cgroup/uid is
//!   throttled; every other workload keeps its normal telemetry rate.
//! - [`SEC_CRIT_STATE`] is the armed word (epoch/armed/magic `0x53`/ABI 1). A
//!   zero or foreign word means "not armed": critical records are refused and
//!   counted, bulk telemetry is never throttled (the bucket exists to protect
//!   the observer, not to police a disarmed one).
//!
//! # Critical record kinds
//!
//! `kind` is namespaced by `source` (both fields of [`SecCritEvent`]). This
//! module (and the control-plane parser) therefore fix `kind = 1` for every
//! producer family documented here; a future family must allocate a new
//! `(source, kind)` pair in `gedefense-common` **and** in the control parser
//! instead of overloading these:
//!
//! | source (`SEC_CRIT_SOURCE_*`) | kind constant | action | payload |
//! |---|---|---|---|
//! | 1 `CRED_GUARD` | [`SEC_CRIT_KIND_CRED_DENY`] = 1 | ENFORCE | `dev`/`ino` of the denied credential object, `detail_code` = inode mode |
//! | 2 `BPF_GUARD` | [`SEC_CRIT_KIND_BPF_HELPER_RISK`] = 1 | OBSERVE | `detail_code` = aggregated helper-risk mask, `pid` = loading task |
//! | 3 `KERNEL_HOOKS` | [`SEC_CRIT_KIND_LKM_LOAD`] = 1 | OBSERVE | `extra[0..4]` = LE u32 kernel taint mask, `extra[4..8]` = up to four printable module-name bytes, `detail_code` = family detail (taints on `module/load`, fd/flags on the syscall kprobes) |
//! | 7 `PERSISTENCE` | [`SEC_CRIT_KIND_PERSIST_CRIT`] = 1 | OBSERVE | `dev`/`ino`, `detail_code` = `class << 8 OR record kind`, `extra[0..4]` = LE u32 original record detail code |
//!
//! # Verifier discipline
//!
//! Every helper is `#[inline(always)]`, allocation-free, loop-free (only
//! fixed-16 fixed-bound loops in the comm sanitiser) and free of static
//! `&[&str]` tables. Every record is bounds-checked inside the emitter: the
//! wire struct is written field-by-field directly into the ring reservation and
//! every field is validated against the shared rejecting decoder's contract
//! before the entry is submitted.

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns,
    },
    macros::map,
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
};
use gedefense_common::{
    telemetry_bucket_step, SecCritEvent, SEC_CRIT_ACTION_ENFORCE, SEC_CRIT_ACTION_MAX,
    SEC_CRIT_ACTION_OBSERVE, SEC_CRIT_BUCKET_CAPACITY, SEC_CRIT_BUCKET_ENTRIES,
    SEC_CRIT_BUCKET_KEY_BYTES, SEC_CRIT_BUCKET_MAX, SEC_CRIT_BUCKET_REFILL_PER_SECOND,
    SEC_CRIT_BUCKET_VALUE_BYTES, SEC_CRIT_COUNTER_EMITTED, SEC_CRIT_COUNTER_LANES,
    SEC_CRIT_COUNTER_READ_FAILURES, SEC_CRIT_COUNTER_REFUSED_UNARMED, SEC_CRIT_COUNTER_RING_DROPS,
    SEC_CRIT_COUNTER_SUPPRESSED, SEC_CRIT_EVENT_RING_BYTES, SEC_CRIT_EVENT_WIRE_BYTES,
    SEC_CRIT_SOURCE_MAX, SEC_CRIT_STATE_ABI, SEC_CRIT_STATE_ABI_SHIFT, SEC_CRIT_STATE_ARMED_SHIFT,
    SEC_CRIT_STATE_BYTE_MASK, SEC_CRIT_STATE_MAGIC, SEC_CRIT_STATE_MAGIC_SHIFT,
};

/// Index of the single armed word in [`SEC_CRIT_STATE`].
const SEC_CRIT_STATE_INDEX: u32 = 0;
/// Index of the single aggregate suppression counter in
/// [`TELEMETRY_FLOOD_SUPPRESSED`].
const TELEMETRY_FLOOD_SUPPRESSED_INDEX: u32 = 0;
/// `TELEMETRY_FLOOD_BUCKETS` value offsets (byte layout is fixed by
/// `gedefense_common::sec_crit`; little-endian).
const BUCKET_VALUE_TOKENS: usize = 0;
const BUCKET_VALUE_LAST_REFILL: usize = 8;
const BUCKET_VALUE_SUPPRESSED: usize = 16;
/// `TELEMETRY_FLOOD_BUCKETS` key offsets (little-endian).
const BUCKET_KEY_CLASS: usize = 0;
const BUCKET_KEY_CGROUP: usize = 8;
const BUCKET_KEY_UID: usize = 16;

/// Critical-record kind for source [`SEC_CRIT_SOURCE_CRED_GUARD`]
/// (payload: `dev`/`ino` of the denied object, `detail_code` = inode mode).
pub(crate) const SEC_CRIT_KIND_CRED_DENY: u8 = 1;
/// Critical-record kind for source [`SEC_CRIT_SOURCE_BPF_GUARD`]
/// (payload: `detail_code` = aggregated helper-risk mask).
pub(crate) const SEC_CRIT_KIND_BPF_HELPER_RISK: u8 = 1;
/// Critical-record kind for source [`SEC_CRIT_SOURCE_KERNEL_HOOKS`]
/// (payload: taints in `extra[0..4]`, module-name prefix in `extra[4..8]`).
pub(crate) const SEC_CRIT_KIND_LKM_LOAD: u8 = 1;
/// Critical-record kind for source [`SEC_CRIT_SOURCE_PERSISTENCE`]
/// (payload: `detail_code` = `(class << 8) | record kind`).
pub(crate) const SEC_CRIT_KIND_PERSIST_CRIT: u8 = 1;

/// Independent high-priority evidence ring (256 KiB = 4096 queued records).
#[map]
pub(crate) static SEC_CRIT_EVENTS: RingBuf =
    RingBuf::with_byte_size(SEC_CRIT_EVENT_RING_BYTES, 0);
/// Armed word: epoch low 32 bits | armed bit 32 | magic 40..47 | ABI 48..55.
#[map]
pub(crate) static SEC_CRIT_STATE: Array<u64> = Array::with_max_entries(1, 0);
/// Counter lanes (see `SEC_CRIT_COUNTER_*` in `gedefense_common`).
#[map]
pub(crate) static SEC_CRIT_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(SEC_CRIT_COUNTER_LANES, 0);
/// Per-`(class, cgroup, uid)` token bucket (bounded LRU, 4096 entries).
#[map]
pub(crate) static TELEMETRY_FLOOD_BUCKETS: LruHashMap<
    [u8; SEC_CRIT_BUCKET_KEY_BYTES],
    [u8; SEC_CRIT_BUCKET_VALUE_BYTES],
> = LruHashMap::with_max_entries(SEC_CRIT_BUCKET_ENTRIES, 0);
/// Aggregated suppression counter (one lane, per-CPU).
#[map]
pub(crate) static TELEMETRY_FLOOD_SUPPRESSED: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(1, 0);

// Compile-time coupling to the shared wire contract: a drift fails the eBPF
// build instead of silently producing records the core decoder rejects.
const _: () = assert!(core::mem::size_of::<SecCritEvent>() == SEC_CRIT_EVENT_WIRE_BYTES);
const _: () = assert!(core::mem::align_of::<SecCritEvent>() <= 8);
const _: () = assert!(SEC_CRIT_STATE_MAGIC == 0x53);
const _: () = assert!(SEC_CRIT_STATE_ABI == 1);
const _: () = assert!(SEC_CRIT_STATE_ARMED_SHIFT == 32);
const _: () = assert!(SEC_CRIT_STATE_MAGIC_SHIFT == 40);
const _: () = assert!(SEC_CRIT_STATE_ABI_SHIFT == 48);
const _: () = assert!(SEC_CRIT_STATE_BYTE_MASK == 0xff);
const _: () = assert!(SEC_CRIT_ACTION_OBSERVE == 1);
const _: () = assert!(SEC_CRIT_ACTION_ENFORCE == 2);
const _: () = assert!(SEC_CRIT_ACTION_MAX == 2);
const _: () = assert!(SEC_CRIT_SOURCE_MAX == 7);
const _: () = assert!(SEC_CRIT_BUCKET_MAX == 4);
const _: () = assert!(SEC_CRIT_BUCKET_KEY_BYTES == 24);
const _: () = assert!(SEC_CRIT_BUCKET_VALUE_BYTES == 24);
const _: () = assert!(core::mem::size_of::<u64>() == 8);

/// Increments one counter lane of [`SEC_CRIT_COUNTERS`]. A missing lane (stale
/// object) is a silent no-op: counters are health telemetry, never a decision.
#[inline(always)]
fn bump_counter(lane: u32) {
    if let Some(counter) = SEC_CRIT_COUNTERS.get_ptr_mut(lane) {
        // SAFETY: per-CPU array lane is owned by this CPU for this update.
        unsafe { *counter = (*counter).wrapping_add(1) };
    }
}

/// Reads and validates the armed word. Absent/foreign/stale words are disarmed.
///
/// Every helper in this module evaluates this first (state word first), so a
/// disarmed observer adds one array lookup and no map writes to the fast path.
#[inline(always)]
pub(crate) fn sec_crit_armed() -> bool {
    let Some(word) = SEC_CRIT_STATE.get(SEC_CRIT_STATE_INDEX) else {
        return false;
    };
    let magic = ((*word >> SEC_CRIT_STATE_MAGIC_SHIFT) & SEC_CRIT_STATE_BYTE_MASK) as u8;
    let abi = ((*word >> SEC_CRIT_STATE_ABI_SHIFT) & SEC_CRIT_STATE_BYTE_MASK) as u8;
    let armed = (*word >> SEC_CRIT_STATE_ARMED_SHIFT) & 1;
    magic == SEC_CRIT_STATE_MAGIC && abi == SEC_CRIT_STATE_ABI && armed == 1
}

/// The decoder requires a NUL-padded, printable `comm`; a full 16-byte kernel
/// task name could not be represented. Kernel task names are attacker-controlled
/// (`prctl(PR_SET_NAME)`), so every control/high byte before the NUL becomes
/// `?` (terminal-injection guard for every operator surface) and a full name is
/// truncated to 15 bytes plus NUL. An unreadable/empty name emits `?`.
#[inline(always)]
fn sanitize_comm(raw: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut index = 0usize;
    while index < 15 {
        let byte = raw[index];
        if byte == 0 {
            break;
        }
        out[index] = if (0x20..=0x7e).contains(&byte) {
            byte
        } else {
            b'?'
        };
        index += 1;
    }
    if index == 0 {
        out[0] = b'?';
    }
    out
}

/// Emits one 64-byte [`SecCritEvent`] into [`SEC_CRIT_EVENTS`].
///
/// The armed word is checked first: a disarmed observer refuses the record and
/// bumps `refused_unarmed` (the record is counted, never silently dropped). The
/// struct is written field-by-field directly into the ring reservation, so no
/// 64-byte stack copy is made; a full ring bumps `ring_drops`. Inputs are
/// validated against the shared rejecting decoder's contract before anything is
/// written, so an emitter can never publish a record the core would reject:
/// `source` 1..=7, `kind != 0`, `action` 1..=2, non-zero timestamp/pid/tgid.
#[inline(always)]
pub(crate) fn sec_crit_emit(
    source: u8,
    kind: u8,
    action: u8,
    detail_code: u32,
    dev: u32,
    ino: u64,
    comm: [u8; 16],
    extra: [u8; 8],
) {
    if !sec_crit_armed() {
        bump_counter(SEC_CRIT_COUNTER_REFUSED_UNARMED);
        return;
    }
    if source == 0
        || source > SEC_CRIT_SOURCE_MAX
        || kind == 0
        || action == 0
        || action > SEC_CRIT_ACTION_MAX
    {
        // Producer bug: the decoder would reject this record. Count it as a
        // read failure instead of publishing garbage into the evidence ring.
        bump_counter(SEC_CRIT_COUNTER_READ_FAILURES);
        return;
    }
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    if ts_ns == 0 || pid == 0 || tgid == 0 {
        bump_counter(SEC_CRIT_COUNTER_READ_FAILURES);
        return;
    }
    let uid_gid = bpf_get_current_uid_gid();
    let comm = sanitize_comm(comm);
    if let Some(mut entry) = SEC_CRIT_EVENTS.reserve::<SecCritEvent>(0) {
        let event = entry.as_mut_ptr();
        // SAFETY: the reservation is exactly `size_of::<SecCritEvent>()` bytes
        // and aligned for the struct. Every field is written through the raw
        // pointer before the entry is submitted; no reference to uninitialised
        // memory is created.
        unsafe {
            core::ptr::addr_of_mut!((*event).ts_ns).write(ts_ns);
            core::ptr::addr_of_mut!((*event).source).write(source);
            core::ptr::addr_of_mut!((*event).kind).write(kind);
            core::ptr::addr_of_mut!((*event).action).write(action);
            core::ptr::addr_of_mut!((*event).reserved).write(0);
            core::ptr::addr_of_mut!((*event).detail_code).write(detail_code);
            core::ptr::addr_of_mut!((*event).pid).write(pid);
            core::ptr::addr_of_mut!((*event).tgid).write(tgid);
            core::ptr::addr_of_mut!((*event).uid).write(uid_gid as u32);
            core::ptr::addr_of_mut!((*event).dev).write(dev);
            core::ptr::addr_of_mut!((*event).ino).write(ino);
            core::ptr::addr_of_mut!((*event).comm).write(comm);
            core::ptr::addr_of_mut!((*event).extra).write(extra);
        }
        entry.submit(0);
        bump_counter(SEC_CRIT_COUNTER_EMITTED);
    } else {
        // Ring full (or closed): the critical record is lost and the loss is
        // counted in the status; the dedicated critical rings are unaffected.
        bump_counter(SEC_CRIT_COUNTER_RING_DROPS);
    }
}

/// Token bucket for one bulk telemetry class. `true` = emit, `false` = the
/// `(class, cgroup, uid)` bucket is exhausted: do not emit and call
/// [`telemetry_note_suppressed`] exactly once.
///
/// The bucket key is `class u8 | 3 zero | cgroup u64 LE | uid u32 LE | 4 zero`;
/// the value is `tokens u64 LE | last_refill_ns u64 LE | suppressed u32 LE |
/// reserved u32` (fixed by `gedefense_common::sec_crit`). A new key starts full
/// and consumes one token immediately. `gedefense_common::telemetry_bucket_step`
/// performs the integer refill maths (no floats, saturating).
///
/// Fail-open boundaries (documented, never silent): an unknown class, a
/// disarmed observer or an unreadable clock allows the emission. Throttling is
/// part of the armed observer; it never reduces telemetry of a disarmed one and
/// never turns a bucket-map failure into a blind spot.
#[inline(always)]
pub(crate) fn telemetry_budget_allow(class: u8, cgroup_id: u64, uid: u32) -> bool {
    if class == 0 || class > SEC_CRIT_BUCKET_MAX {
        return true;
    }
    if !sec_crit_armed() {
        return true;
    }
    let now_ns = unsafe { bpf_ktime_get_ns() };
    if now_ns == 0 {
        bump_counter(SEC_CRIT_COUNTER_READ_FAILURES);
        return true;
    }
    let mut key = [0u8; SEC_CRIT_BUCKET_KEY_BYTES];
    key[BUCKET_KEY_CLASS] = class;
    key[BUCKET_KEY_CGROUP..BUCKET_KEY_CGROUP + 8].copy_from_slice(&cgroup_id.to_le_bytes());
    key[BUCKET_KEY_UID..BUCKET_KEY_UID + 4].copy_from_slice(&uid.to_le_bytes());
    if let Some(value_ptr) = TELEMETRY_FLOOD_BUCKETS.get_ptr_mut(&key) {
        // SAFETY: LRU map value pointer is valid for this program invocation.
        let value = unsafe { &mut *value_ptr };
        let tokens = u64::from_le_bytes([
            value[BUCKET_VALUE_TOKENS],
            value[BUCKET_VALUE_TOKENS + 1],
            value[BUCKET_VALUE_TOKENS + 2],
            value[BUCKET_VALUE_TOKENS + 3],
            value[BUCKET_VALUE_TOKENS + 4],
            value[BUCKET_VALUE_TOKENS + 5],
            value[BUCKET_VALUE_TOKENS + 6],
            value[BUCKET_VALUE_TOKENS + 7],
        ]);
        let last_refill_ns = u64::from_le_bytes([
            value[BUCKET_VALUE_LAST_REFILL],
            value[BUCKET_VALUE_LAST_REFILL + 1],
            value[BUCKET_VALUE_LAST_REFILL + 2],
            value[BUCKET_VALUE_LAST_REFILL + 3],
            value[BUCKET_VALUE_LAST_REFILL + 4],
            value[BUCKET_VALUE_LAST_REFILL + 5],
            value[BUCKET_VALUE_LAST_REFILL + 6],
            value[BUCKET_VALUE_LAST_REFILL + 7],
        ]);
        let (new_tokens, new_last_refill_ns, allowed) = telemetry_bucket_step(
            tokens,
            last_refill_ns,
            now_ns,
            SEC_CRIT_BUCKET_CAPACITY,
            SEC_CRIT_BUCKET_REFILL_PER_SECOND,
        );
        value[BUCKET_VALUE_TOKENS..BUCKET_VALUE_TOKENS + 8]
            .copy_from_slice(&new_tokens.to_le_bytes());
        value[BUCKET_VALUE_LAST_REFILL..BUCKET_VALUE_LAST_REFILL + 8]
            .copy_from_slice(&new_last_refill_ns.to_le_bytes());
        if !allowed {
            // Per-bucket suppression count for operator forensics (bounded u32).
            let suppressed = u32::from_le_bytes([
                value[BUCKET_VALUE_SUPPRESSED],
                value[BUCKET_VALUE_SUPPRESSED + 1],
                value[BUCKET_VALUE_SUPPRESSED + 2],
                value[BUCKET_VALUE_SUPPRESSED + 3],
            ])
            .saturating_add(1);
            value[BUCKET_VALUE_SUPPRESSED..BUCKET_VALUE_SUPPRESSED + 4]
                .copy_from_slice(&suppressed.to_le_bytes());
        }
        return allowed;
    }
    // First packet of this (class, cgroup, uid): create the bucket full and
    // consume one token. An insert failure fails open (bulk telemetry is never
    // hidden by a bucket-map error).
    let mut value = [0u8; SEC_CRIT_BUCKET_VALUE_BYTES];
    let (new_tokens, new_last_refill_ns, _allowed) = telemetry_bucket_step(
        SEC_CRIT_BUCKET_CAPACITY,
        0,
        now_ns,
        SEC_CRIT_BUCKET_CAPACITY,
        SEC_CRIT_BUCKET_REFILL_PER_SECOND,
    );
    value[BUCKET_VALUE_TOKENS..BUCKET_VALUE_TOKENS + 8].copy_from_slice(&new_tokens.to_le_bytes());
    value[BUCKET_VALUE_LAST_REFILL..BUCKET_VALUE_LAST_REFILL + 8]
        .copy_from_slice(&new_last_refill_ns.to_le_bytes());
    let _ = TELEMETRY_FLOOD_BUCKETS.insert(&key, &value, 0);
    true
}

/// Current task's cgroup id, used by the process-context bulk emitters (exec
/// argv, kernel probe, DNS) as the bucket dimension. `0` when the helper is
/// unavailable on this kernel: `(class, 0, uid)` is still a valid, bounded key
/// (the cgroup dimension degrades to the uid dimension), never a blind spot.
#[inline(always)]
pub(crate) fn telemetry_current_cgroup_id() -> u64 {
    unsafe { bpf_get_current_cgroup_id() }
}

/// Increments **both** aggregate suppression counters: the
/// `SEC_CRIT_COUNTER_SUPPRESSED` lane of [`SEC_CRIT_COUNTERS`] and
/// [`TELEMETRY_FLOOD_SUPPRESSED`]. Callers invoke this exactly once per refused
/// bulk emission (the per-bucket `suppressed` u32 is incremented inside
/// [`telemetry_budget_allow`] itself, so nothing is counted twice).
///
/// `class` is accepted because the documented helper contract carries it; the
/// five mandated counter lanes are aggregate, so it does not allocate a lane.
#[inline(always)]
pub(crate) fn telemetry_note_suppressed(_class: u8) {
    bump_counter(SEC_CRIT_COUNTER_SUPPRESSED);
    if let Some(counter) = TELEMETRY_FLOOD_SUPPRESSED.get_ptr_mut(TELEMETRY_FLOOD_SUPPRESSED_INDEX) {
        // SAFETY: per-CPU array index 0 is owned by this CPU for this update.
        unsafe { *counter = (*counter).wrapping_add(1) };
    }
}
