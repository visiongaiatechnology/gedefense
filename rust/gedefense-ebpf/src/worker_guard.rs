//! 6.1.0 Module B: worker crash-storm sensor and the LPE socket-deny flags.
//!
//! The guard watches only processes the operator registered (comm or uid) and
//! only fatal memory-corruption/abort signals. Identity comes from the bpf
//! helpers rather than the tracepoint layout, so the program does not depend on
//! the `signal_deliver` field order beyond the stable `sig` slot at offset 8
//! (common tracepoint header is 8 bytes). The control plane validates the
//! signal number again, so an unexpected layout cannot create a false crash.
//!
//! Map names are part of the 6.1.0 wire contract; the core looks them up by
//! name. Do not rename or reshape them.

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use gedefense_common::{worker_signal_is_fatal, WorkerCrashEvent, WORKER_CRASH_EVENT_WIRE_BYTES};

/// 256 KiB ring: ~5400 records, far above a realistic worker crash burst.
const WORKER_CRASH_RING_BYTES: u32 = 1 << 18;
const MAX_WORKER_COMMS: u32 = 256;
const MAX_WORKER_UIDS: u32 = 256;
/// Bit 0 of the state word arms the sensor. Everything else is reserved.
const WORKER_GUARD_STATE_ENABLED: u64 = 1;

#[map]
static WORKER_GUARD_STATE: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static WORKER_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(MAX_WORKER_COMMS, 0);

#[map]
static WORKER_UIDS: HashMap<u32, u8> = HashMap::with_max_entries(MAX_WORKER_UIDS, 0);

#[map]
static WORKER_CRASH_EVENTS: RingBuf = RingBuf::with_byte_size(WORKER_CRASH_RING_BYTES, 0);

#[map]
static WORKER_CRASH_EMITTED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static WORKER_CRASH_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// The userspace decoder rejects a record whose size drifted, so the assertion
// is part of the contract rather than a style check.
const _: () = assert!(core::mem::size_of::<WorkerCrashEvent>() == WORKER_CRASH_EVENT_WIRE_BYTES);

#[inline(always)]
fn guard_enabled() -> bool {
    match WORKER_GUARD_STATE.get(0) {
        Some(word) => *word & WORKER_GUARD_STATE_ENABLED != 0,
        None => false,
    }
}

#[inline(always)]
fn worker_registered(comm: &[u8; 16]) -> bool {
    if unsafe { WORKER_COMMS.get(comm) }.is_some() {
        return true;
    }
    let uid = bpf_get_current_uid_gid() as u32;
    unsafe { WORKER_UIDS.get(&uid) }.is_some()
}

#[inline(always)]
fn emit_crash(signal: u32) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = match bpf_get_current_comm() {
        Ok(value) => value,
        Err(_) => return 0,
    };
    if !worker_registered(&comm) {
        return 0;
    }
    let event = WorkerCrashEvent {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        signal,
        exit_code: -1,
        reserved: 0,
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        comm,
    };
    match WORKER_CRASH_EVENTS.output::<WorkerCrashEvent>(&event, 0) {
        Ok(()) => {
            increment_counter(&WORKER_CRASH_EMITTED);
            0
        }
        Err(_) => {
            increment_counter(&WORKER_CRASH_RING_DROPS);
            0
        }
    }
}

#[inline(always)]
fn increment_counter(counter: &PerCpuArray<u64>) {
    if let Some(ptr) = counter.get_ptr_mut(0) {
        let value = unsafe { &mut *ptr };
        *value = value.saturating_add(1);
    }
}

/// `signal:signal_deliver`: `sig` is the first tracepoint field after the
/// 8-byte common header. Only fatal signals for registered workers are emitted.
#[tracepoint]
pub fn gedefense_worker_signal(ctx: TracePointContext) -> u32 {
    if !guard_enabled() {
        return 0;
    }
    let raw: i32 = match unsafe { ctx.read_at(8) } {
        Ok(value) => value,
        Err(_) => return 0,
    };
    if raw <= 0 {
        return 0;
    }
    let signal = raw as u32;
    if !worker_signal_is_fatal(signal) {
        return 0;
    }
    emit_crash(signal)
}
