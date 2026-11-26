//! V6.3.0 AP-2 — attach-time eBPF guard (`BPF_GUARD_*`).
//!
//! Loads and drains the `BPF_GUARD_EVENTS` ring produced by
//! `rust/gedefense-ebpf/src/bpf_guard.rs`:
//! - `lsm/bpf_prog` (`security_bpf_prog`): every BPF program fd creation,
//! - `tp/syscalls/sys_enter_bpf`: the loader's command/program type at attach,
//! - BTF/kallsyms-gated `kprobe/check_helper_call`: the raw 32-bit helper ids
//!   from `bpf_insn->imm` before `do_misc_fixups()`, aggregated into a
//!   per-loader helper-risk bitmap (`bpf_probe_write_user`,
//!   `bpf_override_return`, `bpf_send_signal`).
//!
//! The guard is observe-only for the XDR response engine: it produces
//! `XDR.BPF_ANOMALY` / `XDR.BPF_ROOTKIT_HELPER` evidence, never a kill on a
//! single helper hit. Own-PID and PermitV1-tolerated loaders are filtered by the
//! control plane, not silently by the kernel.
//!
//! Attach ladder (each step is optional and honest):
//! 1. the LSM hook is only attached when BPF-LSM is active and the LSM BTF is
//!    available; a failure reports `lsm=0`,
//! 2. the syscall tracepoint is attached best-effort; a failure reports `tp=0`,
//! 3. the verifier kprobe is only attempted when `check_helper_call` exists in
//!    `/proc/kallsyms` (including compiler clones such as
//!    `check_helper_call.isra.0`) or in the vmlinux BTF FUNC table; a failure
//!    reports `kprobe=0` — never a fake claim.
//!
//! Every counter is read from a per-CPU map, the drain is bounded to
//! [`BPF_GUARD_MAX_EVENTS_PER_DRAIN`] records and
//! [`BPF_GUARD_MAX_DRAIN_PAYLOAD_BYTES`] bytes, and a stale object (missing
//! mandatory map) fails the whole core load loudly.

mod attach;
mod drain;
mod helpers;

use self::helpers::*;
use aya::{
    maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf},
    programs::{KProbe, Lsm, TracePoint},
    Btf, Ebpf,
};
use gedefense_common::{
    bpf_guard_state_word, decode_bpf_guard_event, BpfGuardEvent,
    BPF_GUARD_HELPER_BITMAP_ENTRIES, BPF_GUARD_HELPER_IDS_ENTRIES, BPF_GUARD_HELPER_IDS_PER_EVENT,
    BPF_GUARD_MAX_DRAIN_PAYLOAD_BYTES, BPF_GUARD_MAX_EVENTS_PER_DRAIN,
};
use std::{
    error::Error,
    fs,
    io::{BufRead as _, Read as _},
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Index of the single state word in `BPF_GUARD_STATE`.
const BPF_GUARD_STATE_INDEX: u32 = 0;
/// LSM program name + kernel hook name (ABI with the eBPF object).
const BPF_GUARD_LSM_PROGRAM: &str = "gedefense_bpf_prog_guard";
const BPF_GUARD_LSM_HOOK: &str = "bpf_prog";
/// Syscall tracepoint program name + tracefs category/event.
const BPF_GUARD_TP_PROGRAM: &str = "gedefense_bpf_syscall";
const BPF_GUARD_TP_CATEGORY: &str = "syscalls";
const BPF_GUARD_TP_NAME: &str = "sys_enter_bpf";
/// Verifier kprobe program name + the upstream kernel symbol it targets.
const BPF_GUARD_HELPER_PROGRAM: &str = "gedefense_check_helper_call";
const BPF_GUARD_HELPER_SYMBOL: &str = "check_helper_call";
/// Bounded kallsyms scan (a hardened host may make the file unreadable; that is
/// handled by the BTF fallback, never by a claimed attach).
const KALLSYMS_PATH: &str = "/proc/kallsyms";
const MAX_KALLSYMS_BYTES: u64 = 16 * 1024 * 1024;
const MAX_KALLSYMS_LINES: usize = 1_500_000;
const MAX_PROBE_SYMBOL_CANDIDATES: usize = 4;

// BTF constants reused from the shared vmlinux parser (same file/bounds).
use crate::btf_offsets::{
    BTF_HEADER_BYTES, BTF_MAGIC, BTF_VERSION, MAX_VMLINUX_BTF_BYTES, VMLINUX_BTF_PATH,
};

/// Core-side owner of the attach-time eBPF guard maps/ring.
pub(crate) struct BpfGuardCore {
    events: RingBuf<MapData>,
    state: AyaArray<MapData, u64>,
    /// Per-loader helper-risk bitmap (`LruHashMap<u32, u32>` in the object).
    helper_bitmap: AyaHashMap<MapData, u32, u32>,
    /// Per-loader deduplicated raw risk helper ids (`LruHashMap<u32, [u16;4]>`).
    helper_ids: AyaHashMap<MapData, u32, [u16; BPF_GUARD_HELPER_IDS_PER_EVENT]>,
    emitted: PerCpuArray<MapData, u64>,
    ring_drops: PerCpuArray<MapData, u64>,
    read_failures: PerCpuArray<MapData, u64>,
    program_loads: PerCpuArray<MapData, u64>,
    helper_risk: PerCpuArray<MapData, u64>,
    /// Random per-boot epoch. The state word carries the low 32 bits; the
    /// operator-visible epoch is the full 64-bit value (16 hex chars).
    epoch: u64,
    enabled: bool,
    lsm_attached: bool,
    tp_attached: bool,
    kprobe_attached: bool,
    rejected: u64,
    last_ring_drops: u64,
}

impl BpfGuardCore {
    /// Takes the mandatory `BPF_GUARD_*` maps, attaches the LSM/TP/kprobe
    /// programs when the kernel supports them and arms the state word.
    ///
    /// A stale object fails loudly (missing map); an unsupported hook only
    /// degrades the corresponding status flag to 0.
    pub(crate) fn load(
        ebpf: &mut Ebpf,
        btf: Option<&Btf>,
        bpf_lsm_active: bool,
    ) -> Result<Self, BoxError> {
        let events = RingBuf::try_from(
            ebpf.take_map(&crate::chameleon::map_name("BPF_GUARD_EVENTS"))
                .ok_or("BPF_GUARD_EVENTS missing")?,
        )?;
        let state = AyaArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("BPF_GUARD_STATE"))
                .ok_or("BPF_GUARD_STATE missing")?,
        )?;
        let helper_bitmap = AyaHashMap::try_from(
            ebpf.take_map(&crate::chameleon::map_name("BPF_GUARD_HELPER_BITMAP"))
                .ok_or("BPF_GUARD_HELPER_BITMAP missing")?,
        )?;
        let helper_ids = AyaHashMap::try_from(
            ebpf.take_map(&crate::chameleon::map_name("BPF_GUARD_HELPER_IDS"))
                .ok_or("BPF_GUARD_HELPER_IDS missing")?,
        )?;
        let emitted = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("BPF_GUARD_EVENTS_EMITTED"))
                .ok_or("BPF_GUARD_EVENTS_EMITTED missing")?,
        )?;
        let ring_drops = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("BPF_GUARD_RING_DROPS"))
                .ok_or("BPF_GUARD_RING_DROPS missing")?,
        )?;
        let read_failures = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("BPF_GUARD_READ_FAILURES"))
                .ok_or("BPF_GUARD_READ_FAILURES missing")?,
        )?;
        let program_loads = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("BPF_GUARD_PROGRAM_LOADS"))
                .ok_or("BPF_GUARD_PROGRAM_LOADS missing")?,
        )?;
        let helper_risk = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("BPF_GUARD_HELPER_RISK"))
                .ok_or("BPF_GUARD_HELPER_RISK missing")?,
        )?;

        let mut core = Self {
            events,
            state,
            helper_bitmap,
            helper_ids,
            emitted,
            ring_drops,
            read_failures,
            program_loads,
            helper_risk,
            epoch: random_epoch(),
            enabled: false,
            lsm_attached: false,
            tp_attached: false,
            kprobe_attached: false,
            rejected: 0,
            last_ring_drops: 0,
        };
        core.attach_lsm(ebpf, btf, bpf_lsm_active);
        core.attach_tracepoint(ebpf);
        core.attach_helper_kprobe(ebpf);
        // Arm last: the eBPF programs ignore every event until the state word is
        // magic/ABI-valid and armed.
        core.set_armed(true)?;
        eprintln!(
            "GeDefense attach-time eBPF guard: enabled={} lsm={} tp={} kprobe={}",
            core.enabled, core.lsm_attached, core.tp_attached, core.kprobe_attached
        );
        Ok(core)
    }

    /// Random per-boot epoch rendered as 16 lowercase hex chars.
    pub(crate) fn epoch(&self) -> String {
        format!("{:016x}", self.epoch)
    }

    /// Reports whether this daemon's own `lsm/bpf_prog` guard hook attached.
    pub(crate) fn lsm_attached(&self) -> bool {
        self.lsm_attached
    }

}

#[cfg(test)]
mod tests;
