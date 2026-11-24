//! V6.3.0 AP-4 — `io_uring` bypass closure and LKM hooks (`KERNEL_HOOK_*`).
//!
//! Loads, attaches and drains the `KERNEL_HOOK_EVENTS` ring produced by
//! `rust/gedefense-ebpf/src/kernel_hooks.rs`:
//!
//! - `tp/io_uring/io_uring_create|io_uring_register|io_uring_submit_req`
//!   (io_uring requests can bypass the syscall tracepoints a classic sensor
//!   watches, but they still create rings/registrations and submit requests),
//! - `tp/module/module_load` plus `init_module`/`finit_module`/`delete_module`
//!   kprobes for pre-stealth capture before a rootkit can unlink the module
//!   from `mod_list`,
//! - BTF-optional LSM hooks (`uring_override_creds`, `uring_sqpoll`,
//!   `uring_cmd`) where the running kernel exposes them.
//!
//! The hooks are observe-only for the XDR response engine: they produce
//! `XDR.IO_URING_ANOMALY` / `XDR.LKM_LOAD` evidence, never a kill on a single
//! event and never an active response.
//!
//! # Attach ladder (each step is optional and honest)
//!
//! 1. mandatory maps are taken first; a stale object (missing map) fails the
//!    whole core load loudly,
//! 2. the kernel's tracepoint `format` files are read to derive the byte offsets
//!    of the payload fields and published into `KERNEL_HOOK_OFFSETS`; if a file
//!    is unreadable its slots stay `0` and the programs emit identity-only
//!    records (read failures are counted, never faked),
//! 3. each io_uring tracepoint is attached independently (`io_uring=1` when at
//!    least one attached),
//! 4. `module/module_load` is attached independently (`module_trace=1`),
//! 5. the three module-syscall kprobes are only attempted when their symbol
//!    exists in `/proc/kallsyms` (compiler clones such as `.isra.N` and the
//!    `__do_sys_*`/`__se_sys_*`/`__x64_sys_*` variants included); `kprobes` is
//!    the count of attached probes. The core also records whether a probe
//!    attached to a direct-argument symbol, because the syscall wrapper receives
//!    `struct pt_regs *` and its first argument must never be reported as a
//!    module fd/name,
//! 6. the LSM hooks are only attempted when BPF-LSM is active and the LSM BTF is
//!    available; `lsm_extra` is the count of attached hooks,
//! 7. the state word is armed last, so no event can be produced before the
//!    layout and the ladder are final.

mod layout;
mod attach;
mod drain;

use self::layout::*;
use self::drain::*;
use aya::{
    maps::{Array as AyaArray, MapData, PerCpuArray, RingBuf},
    programs::{KProbe, Lsm, TracePoint},
    Btf, Ebpf,
};
use gedefense_common::{
    decode_kernel_hook_event, kernel_hook_state_word, KernelHookEvent,
    KERNEL_HOOK_DETAIL_BYTES, KERNEL_HOOK_FLAG_DELETE_DIRECT_ARGS,
    KERNEL_HOOK_FLAG_FINIT_DIRECT_ARGS, KERNEL_HOOK_MAX_DRAIN_PAYLOAD_BYTES,
    KERNEL_HOOK_MAX_EVENTS_PER_DRAIN, KERNEL_HOOK_OFFSET_IO_URING_CREATE_FD,
    KERNEL_HOOK_OFFSET_IO_URING_CREATE_FLAGS, KERNEL_HOOK_OFFSET_IO_URING_REGISTER_NR_FILES,
    KERNEL_HOOK_OFFSET_IO_URING_REGISTER_OPCODE, KERNEL_HOOK_OFFSET_IO_URING_SUBMIT_OPCODE,
    KERNEL_HOOK_OFFSET_MODULE_LOAD_NAME, KERNEL_HOOK_OFFSET_MODULE_LOAD_TAINTS,
    KERNEL_HOOK_OFFSET_SLOTS,
};
use std::{
    error::Error,
    fs,
    io::{BufRead as _, Read as _},
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Index of the single state word in `KERNEL_HOOK_STATE`.
const KERNEL_HOOK_STATE_INDEX: u32 = 0;

/// `tp/io_uring/*`: program name, tracefs category, tracepoint name.
const IO_URING_TRACEPOINTS: [(&str, &str, &str); 3] = [
    (
        "gedefense_io_uring_create",
        "io_uring",
        "io_uring_create",
    ),
    (
        "gedefense_io_uring_register",
        "io_uring",
        "io_uring_register",
    ),
    (
        "gedefense_io_uring_submit_req",
        "io_uring",
        "io_uring_submit_req",
    ),
];

/// `tp/module/module_load`.
const MODULE_TRACEPOINT: (&str, &str, &str) =
    ("gedefense_module_load", "module", "module_load");

/// One module-syscall kprobe: program name, upstream symbol base name and the
/// state flag that records a direct-argument attach tier.
struct ModuleProbe {
    program: &'static str,
    base: &'static str,
    direct_args_flag: u8,
}

const MODULE_KPROBES: [ModuleProbe; 3] = [
    ModuleProbe {
        program: "gedefense_init_module",
        base: "init_module",
        direct_args_flag: 0,
    },
    ModuleProbe {
        program: "gedefense_finit_module",
        base: "finit_module",
        direct_args_flag: KERNEL_HOOK_FLAG_FINIT_DIRECT_ARGS,
    },
    ModuleProbe {
        program: "gedefense_delete_module",
        base: "delete_module",
        direct_args_flag: KERNEL_HOOK_FLAG_DELETE_DIRECT_ARGS,
    },
];

/// BTF-optional LSM hooks: program name, kernel hook name.
const LSM_HOOKS: [(&str, &str); 3] = [
    ("gedefense_lsm_uring_override_creds", "uring_override_creds"),
    ("gedefense_lsm_uring_sqpoll", "uring_sqpoll"),
    ("gedefense_lsm_uring_cmd", "uring_cmd"),
];

/// Tracefs event roots, newest mount point first (`tracefs` may be mounted at
/// `/sys/kernel/tracing` or, on older systems, below debugfs).
const TRACEFS_EVENT_ROOTS: [&str; 2] = [
    "/sys/kernel/tracing/events",
    "/sys/kernel/debug/tracing/events",
];
/// Bounded format-file read (a real tracepoint format is well under 4 KiB).
const MAX_FORMAT_BYTES: u64 = 16 * 1024;

const KALLSYMS_PATH: &str = "/proc/kallsyms";
const MAX_KALLSYMS_BYTES: u64 = 16 * 1024 * 1024;
const MAX_KALLSYMS_LINES: usize = 1_500_000;
/// Upper bound on the symbol candidates tried per kprobe.
const MAX_KPROBE_SYMBOL_CANDIDATES: usize = 6;


/// Core-side owner of the io_uring/LKM hook maps/ring.
pub(crate) struct KernelHooksCore {
    events: RingBuf<MapData>,
    state: AyaArray<MapData, u64>,
    offsets: AyaArray<MapData, u32>,
    emitted: PerCpuArray<MapData, u64>,
    ring_drops: PerCpuArray<MapData, u64>,
    read_failures: PerCpuArray<MapData, u64>,
    module_loads: PerCpuArray<MapData, u64>,
    ring_creates: PerCpuArray<MapData, u64>,
    /// Random per-boot epoch; the state word carries its low 32 bits and the
    /// operator-visible epoch is the full 64-bit value (16 hex characters).
    epoch: u64,
    /// Producer flags published in the state word (kprobe attach tiers).
    flags: u8,
    enabled: bool,
    io_uring_attached: bool,
    module_trace_attached: bool,
    kprobes_attached: u8,
    lsm_attached: u8,
    rejected: u64,
    last_ring_drops: u64,
    /// Last observed kernel-side payload read-failure count (drain telemetry).
    last_read_failures: u64,
}

impl KernelHooksCore {
    /// Takes the mandatory `KERNEL_HOOK_*` maps, publishes the tracepoint
    /// layout, attaches the hook ladder and arms the state word.
    ///
    /// A stale object fails loudly (missing map); an unsupported hook only
    /// degrades the corresponding status flag — never a fake claim.
    pub(crate) fn load(
        ebpf: &mut Ebpf,
        btf: Option<&Btf>,
        bpf_lsm_active: bool,
    ) -> Result<Self, BoxError> {
        let events = RingBuf::try_from(
            ebpf.take_map(&crate::chameleon::map_name("KERNEL_HOOK_EVENTS"))
                .ok_or("KERNEL_HOOK_EVENTS missing")?,
        )?;
        let state = AyaArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("KERNEL_HOOK_STATE"))
                .ok_or("KERNEL_HOOK_STATE missing")?,
        )?;
        let offsets = AyaArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("KERNEL_HOOK_OFFSETS"))
                .ok_or("KERNEL_HOOK_OFFSETS missing")?,
        )?;
        let emitted = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("KERNEL_HOOK_EVENTS_EMITTED"))
                .ok_or("KERNEL_HOOK_EVENTS_EMITTED missing")?,
        )?;
        let ring_drops = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("KERNEL_HOOK_RING_DROPS"))
                .ok_or("KERNEL_HOOK_RING_DROPS missing")?,
        )?;
        let read_failures = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("KERNEL_HOOK_READ_FAILURES"))
                .ok_or("KERNEL_HOOK_READ_FAILURES missing")?,
        )?;
        let module_loads = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("KERNEL_HOOK_MODULE_LOADS"))
                .ok_or("KERNEL_HOOK_MODULE_LOADS missing")?,
        )?;
        let ring_creates = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("KERNEL_HOOK_RING_CREATES"))
                .ok_or("KERNEL_HOOK_RING_CREATES missing")?,
        )?;

        let mut core = Self {
            events,
            state,
            offsets,
            emitted,
            ring_drops,
            read_failures,
            module_loads,
            ring_creates,
            epoch: random_epoch(),
            flags: 0,
            enabled: false,
            io_uring_attached: false,
            module_trace_attached: false,
            kprobes_attached: 0,
            lsm_attached: 0,
            rejected: 0,
            last_ring_drops: 0,
            last_read_failures: 0,
        };
        core.attach_io_uring_tracepoints(ebpf);
        core.attach_module_tracepoint(ebpf);
        core.attach_module_kprobes(ebpf);
        core.attach_lsm_hooks(ebpf, btf, bpf_lsm_active);
        // Publish the layout after the ladder so the kprobe tier flags are final,
        // then arm: no event can be produced with a half-derived layout.
        core.publish_layout(&derive_layout())?;
        core.set_armed(true)?;
        eprintln!(
            "GeDefense io_uring/LKM hooks: enabled={} io_uring={} module_trace={} kprobes={} lsm_extra={} flags={:#04x}",
            core.enabled,
            core.io_uring_attached,
            core.module_trace_attached,
            core.kprobes_attached,
            core.lsm_attached,
            core.flags
        );
        Ok(core)
    }

    /// Random per-boot epoch rendered as 16 lowercase hex characters.
    pub(crate) fn epoch(&self) -> String {
        format!("{:016x}", self.epoch)
    }

    /// Drains up to [`KERNEL_HOOK_MAX_EVENTS_PER_DRAIN`] records as
    /// `<dropped>|<record>[,<record>…]`; `empty` when nothing is pending.
    pub(crate) fn take_events(&mut self) -> Result<String, BoxError> {
        let mut records: Vec<String> = Vec::with_capacity(KERNEL_HOOK_MAX_EVENTS_PER_DRAIN);
        let mut payload_bytes = 0usize;
        let rejected_before = self.rejected;
        while records.len() < KERNEL_HOOK_MAX_EVENTS_PER_DRAIN {
            let Some(item) = self.events.next() else {
                break;
            };
            let Some(event) = decode_kernel_hook_event(&item) else {
                self.rejected = self.rejected.saturating_add(1);
                continue;
            };
            let record = encode_event_text(&event);
            let separator = usize::from(!records.is_empty());
            if payload_bytes
                .saturating_add(separator)
                .saturating_add(record.len())
                .saturating_add(24) // drop-prefix headroom
                > KERNEL_HOOK_MAX_DRAIN_PAYLOAD_BYTES
            {
                // Defensive: a bounded 9-field record is mathematically far below
                // the budget; this branch only guards a future record-width change.
                eprintln!(
                    "kernel hooks drain budget exhausted at {} record(s); remainder stays queued",
                    records.len()
                );
                break;
            }
            payload_bytes = payload_bytes
                .saturating_add(separator)
                .saturating_add(record.len());
            records.push(record);
        }
        if self.rejected > rejected_before {
            eprintln!(
                "kernel hooks rejected {} malformed record(s) in this drain (total {})",
                self.rejected.saturating_sub(rejected_before),
                self.rejected
            );
        }
        let ring_drops = Self::per_cpu_sum(&self.ring_drops)?;
        let dropped = ring_drops.saturating_sub(self.last_ring_drops);
        self.last_ring_drops = ring_drops;
        // Kernel-side payload read failures mean a tracepoint layout slot was
        // unknown or a probe read faulted: the events in this batch are
        // identity-only (honest degraded detail). Report the delta once per
        // drain instead of per record.
        let read_failures = Self::per_cpu_sum_or_zero(&self.read_failures);
        if read_failures > self.last_read_failures {
            eprintln!(
                "kernel hooks: {} kernel-side payload read failure(s) since the last drain; affected records carry identity only",
                read_failures.saturating_sub(self.last_read_failures)
            );
            self.last_read_failures = read_failures;
        }
        if records.is_empty() {
            if dropped == 0 && self.rejected == rejected_before {
                return Ok("empty".to_owned());
            }
            return Ok(format!("{dropped}|"));
        }
        Ok(format!("{dropped}|{}", records.join(",")))
    }

}

#[cfg(test)]
mod tests;
