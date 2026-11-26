//! V6.3.0 AP-2 — attach-time eBPF guard (eBPF half).
//!
//! Programs:
//! - [`gedefense_bpf_prog_guard`] `#[lsm(hook = "bpf_prog")]`
//!   (`security_bpf_prog(prog)`, called for every BPF program fd creation):
//!   emits one `OBSERVED` record for the loading task. The `struct bpf_prog`
//!   fields are kernel-private, so the program type stays
//!   [`BPF_GUARD_PROG_TYPE_UNKNOWN`] instead of hardcoding a private offset.
//!   The hook is fail-open: it always returns the previous LSM program's
//!   verdict (or 0), never a denial.
//! - [`gedefense_bpf_syscall`] `#[tracepoint]` on `syscalls/sys_enter_bpf`:
//!   reads the loader's `bpf()` command (`args[0]`, UAPI-stable tracepoint
//!   offset 16) and, for `BPF_PROG_LOAD`, the first 16 bytes of `union bpf_attr`
//!   through one bounded `bpf_probe_read_user` call (`prog_type` at 0,
//!   `insn_cnt` at 4, `insns` at 8 — never a full struct copy). Read-only and
//!   mutation commands (`MAP_LOOKUP_ELEM`/`MAP_UPDATE_ELEM`/`OBJ_GET`/…) are
//!   deliberately not emitted: a busy datapath agent performs thousands of
//!   those per second and would flood the 64 KiB ring. The attach/load command
//!   set is `MAP_CREATE`, `PROG_LOAD`, `PROG_ATTACH`, `RAW_TRACEPOINT_OPEN`,
//!   `LINK_CREATE`.
//! - [`gedefense_check_helper_call`] `#[kprobe]` on `check_helper_call`:
//!   the kernel v6.2 signature is
//!   `static int check_helper_call(struct bpf_verifier_env *env,
//!   struct bpf_insn *insn, int *insn_idx_p)` (verified upstream); `insn->imm`
//!   is read at the UAPI-stable `struct bpf_insn` offset 4 **before**
//!   `do_misc_fixups()`, mapped to the helper-risk bit and OR-ed into a
//!   per-loader bitmap.
//!
//! Anti-flood and verifier discipline: every program checks the
//! [`BPF_GUARD_STATE`] magic/ABI/armed word first and returns without an event
//! or map write when the guard is not armed (default 0 = disarmed); every loop
//! is a fixed 16-iteration loop or a 4-way if-chain; no allocation, no static
//! `&[&str]` tables.
//!
//! Per-program bitmap key: `bpf_get_current_pid_tgid() >> 32` (tgid). The
//! verifier runs synchronously in the loading task, so the bitmap always
//! belongs to the process that loaded the program. Residual ambiguity: one
//! process loading several programs within the LRU lifetime shares one
//! aggregated bitmap, and a pre-existing program that is never re-loaded has no
//! bitmap entry (identity is observed at load time only by design).

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, bpf_probe_read_user,
    },
    macros::{kprobe, lsm, map, tracepoint},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, ProbeContext, TracePointContext},
};
use gedefense_common::{
    bpf_guard_state_armed, helper_id_to_bit, BpfGuardEvent, BPF_GUARD_ACTION_HELPER_RISK,
    BPF_GUARD_ACTION_OBSERVED, BPF_GUARD_COMMAND_LINK_CREATE, BPF_GUARD_COMMAND_MAP_CREATE,
    BPF_GUARD_COMMAND_PROG_ATTACH, BPF_GUARD_COMMAND_PROG_LOAD,
    BPF_GUARD_COMMAND_RAW_TRACEPOINT_OPEN, BPF_GUARD_EVENT_RING_BYTES,
    BPF_GUARD_EVENT_WIRE_BYTES, BPF_GUARD_HELPER_BITMAP_ENTRIES, BPF_GUARD_HELPER_IDS_ENTRIES,
    BPF_GUARD_HELPER_IDS_PER_EVENT, BPF_GUARD_PROG_TYPE_MAX, BPF_GUARD_PROG_TYPE_UNKNOWN,
    BPF_GUARD_STATE_ABI, BPF_GUARD_STATE_ABI_SHIFT, BPF_GUARD_STATE_ARMED_SHIFT,
    BPF_GUARD_STATE_BYTE_MASK, BPF_GUARD_STATE_MAGIC, BPF_GUARD_STATE_MAGIC_SHIFT,
    SEC_CRIT_ACTION_OBSERVE, SEC_CRIT_SOURCE_BPF_GUARD,
};
use crate::sec_crit::{sec_crit_emit, SEC_CRIT_KIND_BPF_HELPER_RISK};

/// Index of the single guard state word in `BPF_GUARD_STATE`.
const BPF_GUARD_STATE_INDEX: u32 = 0;
/// `struct trace_event_raw_sys_enter`: `trace_entry` (8) + `long id` (8), then
/// `unsigned long args[6]`; `bpf(int cmd, union bpf_attr *attr, unsigned int size)`.
const SYS_ENTER_ARG0_OFFSET: usize = 16;
const SYS_ENTER_ARG1_OFFSET: usize = 24;
/// Bounded `union bpf_attr` head read for `BPF_PROG_LOAD`: `prog_type` u32 at 0,
/// `insn_cnt` u32 at 4, `insns` u64 at 8. Never a full struct copy.
const BPF_ATTR_HEAD_BYTES: usize = 16;
const BPF_ATTR_PROG_TYPE_OFFSET: usize = 0;

/// UAPI `struct bpf_insn`: `__u8 code; __u8 dst_reg:4, src_reg:4; __s16 off;
/// __s32 imm;`. The raw helper id lives in `imm` at offset 4 and is stable UAPI.
#[repr(C)]
#[allow(dead_code)]
struct BpfInsnUapi {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}
const BPF_INSN_IMM_OFFSET: u64 = core::mem::offset_of!(BpfInsnUapi, imm) as u64;
const _: () = assert!(BPF_INSN_IMM_OFFSET == 4);
const _: () = assert!(core::mem::size_of::<BpfInsnUapi>() == 8);

#[map]
pub(crate) static BPF_GUARD_STATE: Array<u64> = Array::with_max_entries(1, 0);
#[map]
pub(crate) static BPF_GUARD_EVENTS: RingBuf =
    RingBuf::with_byte_size(BPF_GUARD_EVENT_RING_BYTES, 0);
/// Per-loader helper-risk bitmap keyed by tgid (see the residual-ambiguity note).
#[map]
pub(crate) static BPF_GUARD_HELPER_BITMAP: LruHashMap<u32, u32> =
    LruHashMap::with_max_entries(BPF_GUARD_HELPER_BITMAP_ENTRIES, 0);
/// Per-loader deduplicated raw risk helper ids (up to
/// [`BPF_GUARD_HELPER_IDS_PER_EVENT`], left-packed).
#[map]
pub(crate) static BPF_GUARD_HELPER_IDS: LruHashMap<u32, [u16; BPF_GUARD_HELPER_IDS_PER_EVENT]> =
    LruHashMap::with_max_entries(BPF_GUARD_HELPER_IDS_ENTRIES, 0);
#[map]
pub(crate) static BPF_GUARD_EVENTS_EMITTED: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static BPF_GUARD_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static BPF_GUARD_READ_FAILURES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static BPF_GUARD_PROGRAM_LOADS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static BPF_GUARD_HELPER_RISK: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

const _: () = assert!(core::mem::size_of::<BpfGuardEvent>() == BPF_GUARD_EVENT_WIRE_BYTES);
const _: () = assert!(
    core::mem::align_of::<BpfGuardEvent>() <= 8,
    "ring record must stay 8-aligned"
);

#[inline(always)]
fn increment_counter(counter: &PerCpuArray<u64>) {
    if let Some(value) = counter.get_ptr_mut(0) {
        // SAFETY: per-CPU array index 0 is owned by this CPU for this update.
        unsafe { *value = (*value).wrapping_add(1) };
    }
}

/// Reads and validates the guard state word. Absent/foreign/stale = not armed.
#[inline(always)]
fn guard_active() -> bool {
    match BPF_GUARD_STATE.get(BPF_GUARD_STATE_INDEX) {
        Some(word) => bpf_guard_state_armed(*word),
        None => false,
    }
}

/// The decoder requires a NUL-terminated, printable comm. Kernel task names are
/// attacker-controlled (`prctl(PR_SET_NAME)`), so each pre-NUL byte is replaced
/// with `?` when it is a control byte (terminal-injection guard for every
/// operator surface) and a full 16-byte name is truncated to 15 bytes instead of
/// producing an invalid record.
#[inline(always)]
fn normalize_comm(raw: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut index = 0usize;
    while index < out.len() {
        let byte = raw[index];
        if byte == 0 {
            break;
        }
        out[index] = if byte < 0x20 || byte == 0x7f || byte >= 0x80 {
            b'?'
        } else {
            byte
        };
        index += 1;
    }
    if index == out.len() {
        out[15] = 0;
    }
    out
}

#[inline(always)]
fn emit_event(action: u8, command: u8, prog_type: u8, helper_mask: u32, helper_ids: [u16; 4]) {
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    if ts_ns == 0 || pid == 0 || tgid == 0 {
        increment_counter(&BPF_GUARD_READ_FAILURES);
        return;
    }
    let uid_gid = bpf_get_current_uid_gid();
    let comm = match bpf_get_current_comm() {
        Ok(raw) => normalize_comm(raw),
        Err(_) => {
            increment_counter(&BPF_GUARD_READ_FAILURES);
            [0u8; 16]
        }
    };
    // V6.3.0 AP-9 (S12): a helper-risk verdict is critical evidence; duplicate
    // it into the independent high-priority ring before the family ring is
    // written, so an overflow of the attach-time ring cannot hide the rootkit
    // helper evidence from the safety-net channel. `detail_code` carries the
    // aggregated helper-risk mask, `pid` is the loading task (the verifier runs
    // synchronously in it).
    if action == BPF_GUARD_ACTION_HELPER_RISK {
        sec_crit_emit(
            SEC_CRIT_SOURCE_BPF_GUARD,
            SEC_CRIT_KIND_BPF_HELPER_RISK,
            SEC_CRIT_ACTION_OBSERVE,
            helper_mask,
            0,
            0,
            comm,
            [0u8; 8],
        );
    }
    let (exe_dev, exe_ino) = crate::exec_inode::current_exe_dev_ino();
    let event = BpfGuardEvent {
        ts_ns,
        pid,
        tgid,
        uid: uid_gid as u32,
        action,
        command,
        prog_type,
        reserved: 0,
        helper_mask,
        helper_ids,
        exe_dev,
        exe_ino,
        comm,
    };
    if let Some(mut entry) = BPF_GUARD_EVENTS.reserve::<BpfGuardEvent>(0) {
        // SAFETY: the reservation is exactly size_of::<BpfGuardEvent>() bytes,
        // 8-aligned, written once and submitted below.
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
        increment_counter(&BPF_GUARD_EVENTS_EMITTED);
    } else {
        increment_counter(&BPF_GUARD_RING_DROPS);
    }
}

/// True for the attach/load command set; read-only data-path commands are
/// intentionally excluded so the 64 KiB ring cannot be flooded.
#[inline(always)]
fn is_attach_command(cmd: u8) -> bool {
    cmd == BPF_GUARD_COMMAND_MAP_CREATE
        || cmd == BPF_GUARD_COMMAND_PROG_LOAD
        || cmd == BPF_GUARD_COMMAND_PROG_ATTACH
        || cmd == BPF_GUARD_COMMAND_RAW_TRACEPOINT_OPEN
        || cmd == BPF_GUARD_COMMAND_LINK_CREATE
}

/// `#[lsm(hook = "bpf_prog")]` — `security_bpf_prog(struct bpf_prog *prog)`.
///
/// Observe-only by construction: the hook returns the previous LSM program's
/// verdict (the trailing LSM ctx slot) or 0. A guard that cannot read the guard
/// state word emits nothing and still allows the load (fail-open).
#[lsm(hook = "bpf_prog")]
pub fn gedefense_bpf_prog_guard(ctx: LsmContext) -> i32 {
    // Defer to a previously attached LSM program exactly like the kernel chain.
    let previous: i32 = ctx.arg(1);
    if previous != 0 {
        return previous;
    }
    if guard_active() {
        let prog: u64 = ctx.arg(0);
        if prog == 0 {
            increment_counter(&BPF_GUARD_READ_FAILURES);
        } else {
            emit_event(
                BPF_GUARD_ACTION_OBSERVED,
                BPF_GUARD_COMMAND_PROG_LOAD,
                BPF_GUARD_PROG_TYPE_UNKNOWN,
                0,
                [0u16; BPF_GUARD_HELPER_IDS_PER_EVENT],
            );
        }
    }
    // Observe-only: never deny, never alter the load path.
    0
}

#[tracepoint]
pub fn gedefense_bpf_syscall(ctx: TracePointContext) -> u32 {
    let _ = try_bpf_syscall(&ctx);
    0
}

#[inline(always)]
fn try_bpf_syscall(ctx: &TracePointContext) -> Option<()> {
    if !guard_active() {
        return None;
    }
    let cmd_raw: u64 = unsafe { ctx.read_at(SYS_ENTER_ARG0_OFFSET).ok()? };
    if cmd_raw > u64::from(u8::MAX) {
        // A command outside the u8 wire slot cannot be represented; never
        // mislabel it as MAP_CREATE (0).
        increment_counter(&BPF_GUARD_READ_FAILURES);
        return None;
    }
    let cmd = cmd_raw as u8;
    if !is_attach_command(cmd) {
        return None;
    }
    let mut prog_type = BPF_GUARD_PROG_TYPE_UNKNOWN;
    if cmd == BPF_GUARD_COMMAND_PROG_LOAD {
        increment_counter(&BPF_GUARD_PROGRAM_LOADS);
        match unsafe { ctx.read_at::<u64>(SYS_ENTER_ARG1_OFFSET) } {
            Ok(attr_ptr) if attr_ptr != 0 => {
                match unsafe { bpf_probe_read_user(attr_ptr as *const [u8; BPF_ATTR_HEAD_BYTES]) } {
                    Ok(attr) => {
                        let raw = u32::from_le_bytes([
                            attr[BPF_ATTR_PROG_TYPE_OFFSET],
                            attr[BPF_ATTR_PROG_TYPE_OFFSET + 1],
                            attr[BPF_ATTR_PROG_TYPE_OFFSET + 2],
                            attr[BPF_ATTR_PROG_TYPE_OFFSET + 3],
                        ]);
                        // Bounded representation: a future program type cannot
                        // invalidate the whole drain batch, it degrades to
                        // UNKNOWN.
                        prog_type = if raw <= u32::from(BPF_GUARD_PROG_TYPE_MAX) {
                            raw as u8
                        } else {
                            BPF_GUARD_PROG_TYPE_UNKNOWN
                        };
                    }
                    Err(_) => increment_counter(&BPF_GUARD_READ_FAILURES),
                }
            }
            _ => increment_counter(&BPF_GUARD_READ_FAILURES),
        }
    }
    emit_event(
        BPF_GUARD_ACTION_OBSERVED,
        cmd,
        prog_type,
        0,
        [0u16; BPF_GUARD_HELPER_IDS_PER_EVENT],
    );
    Some(())
}

#[kprobe]
pub fn gedefense_check_helper_call(ctx: ProbeContext) -> u32 {
    let _ = try_check_helper_call(&ctx);
    0
}

#[inline(always)]
fn try_check_helper_call(ctx: &ProbeContext) -> Option<()> {
    if !guard_active() {
        return None;
    }
    // kernel v6.2: check_helper_call(struct bpf_verifier_env *env,
    //                                struct bpf_insn *insn, int *insn_idx_p)
    let env: u64 = ctx.arg(0)?;
    let insn: u64 = ctx.arg(1)?;
    if env == 0 || insn == 0 {
        increment_counter(&BPF_GUARD_READ_FAILURES);
        return None;
    }
    let imm_address = insn.wrapping_add(BPF_INSN_IMM_OFFSET) as *const u32;
    let imm: u32 = match unsafe { bpf_probe_read_kernel(imm_address) } {
        Ok(value) => value,
        Err(_) => {
            increment_counter(&BPF_GUARD_READ_FAILURES);
            return None;
        }
    };
    // `imm` is the signed 32-bit helper index; a negative value is not a
    // helper call at all (pseudo call / invalid insn).
    if (imm as i32) < 0 {
        return None;
    }
    record_helper_risk(imm);
    Some(())
}

/// Maps one raw helper id to its risk bit, ORs it into the per-loader bitmap,
/// records the deduplicated raw id (bounded 4-way if-chain, no loops) and emits
/// one `HELPER_RISK` record. Non-risk helpers are ignored.
#[inline(always)]
fn record_helper_risk(helper_id: u32) -> bool {
    let bit = helper_id_to_bit(helper_id);
    if bit == 0 {
        return false;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if tgid == 0 {
        increment_counter(&BPF_GUARD_READ_FAILURES);
        return false;
    }
    let previous_mask = unsafe { BPF_GUARD_HELPER_BITMAP.get(&tgid) }
        .copied()
        .unwrap_or(0);
    let mask = previous_mask | bit;
    let _ = BPF_GUARD_HELPER_BITMAP.insert(&tgid, &mask, 0);
    let mut ids = unsafe { BPF_GUARD_HELPER_IDS.get(&tgid) }
        .copied()
        .unwrap_or([0u16; BPF_GUARD_HELPER_IDS_PER_EVENT]);
    let lane = if helper_id <= u32::from(u16::MAX) {
        helper_id as u16
    } else {
        0
    };
    if lane != 0
        && ids[0] != lane
        && ids[1] != lane
        && ids[2] != lane
        && ids[3] != lane
    {
        if ids[0] == 0 {
            ids[0] = lane;
        } else if ids[1] == 0 {
            ids[1] = lane;
        } else if ids[2] == 0 {
            ids[2] = lane;
        } else if ids[3] == 0 {
            ids[3] = lane;
        }
        let _ = BPF_GUARD_HELPER_IDS.insert(&tgid, &ids, 0);
    }
    emit_event(
        BPF_GUARD_ACTION_HELPER_RISK,
        BPF_GUARD_COMMAND_PROG_LOAD,
        BPF_GUARD_PROG_TYPE_UNKNOWN,
        mask,
        ids,
    );
    increment_counter(&BPF_GUARD_HELPER_RISK);
    true
}

/// Compile-time coupling: the state-word ABI constants used by the decoders are
/// the ones this module reads. A drift fails the eBPF build instead of silently
/// disabling the guard.
const _: () = assert!(BPF_GUARD_STATE_MAGIC == 0x42);
const _: () = assert!(BPF_GUARD_STATE_ABI == 1);
const _: () = assert!(BPF_GUARD_STATE_ARMED_SHIFT == 32);
const _: () = assert!(BPF_GUARD_STATE_MAGIC_SHIFT == 40);
const _: () = assert!(BPF_GUARD_STATE_ABI_SHIFT == 48);
const _: () = assert!(BPF_GUARD_STATE_BYTE_MASK == 0xff);
