//! Wave 3a extraction: the shared core state types (`KernelCore`,
//! `TitanExecGate`) moved from `main.rs`; behaviour lives in `ebpf_loader.rs`
//! (load) and `ipc::dispatch_titan` (Titan exec gate methods).

use crate::ipc::dispatch_net::Target;
use crate::*;

// Point 1 (§4/§5): one Titan exec-gate state object.
//
// The maps are taken even when BPF LSM is inactive so a stale eBPF object fails
// loudly at startup instead of running blind (§8). `attached` becomes true only
// after both LSM hooks attached on an active kernel, so no command can claim
// enforcement the kernel does not deliver; the default mode stays OFF.
pub(crate) struct TitanExecGate {
    pub(crate) state: AyaArray<MapData, u64>,
    pub(crate) offsets: AyaArray<MapData, u32>,
    pub(crate) modes: AyaHashMap<MapData, u64, u8>,
    pub(crate) policy: AyaHashMap<MapData, [u8; 16], [u8; 16]>,
    pub(crate) events: RingBuf<MapData>,
    pub(crate) emitted: PerCpuArray<MapData, u64>,
    pub(crate) ring_drops: PerCpuArray<MapData, u64>,
    pub(crate) read_failures: PerCpuArray<MapData, u64>,
    pub(crate) denies: PerCpuArray<MapData, u64>,
    pub(crate) audits: PerCpuArray<MapData, u64>,
    pub(crate) ctime_rejects: PerCpuArray<MapData, u64>,
    pub(crate) store: titan_exec::TitanExecPolicy,
    pub(crate) epoch: u32,
    pub(crate) epoch_hex: String,
    pub(crate) mode: u8,
    pub(crate) flags: u8,
    pub(crate) lsm_active: bool,
    pub(crate) offsets_valid: bool,
    pub(crate) attached: bool,
    pub(crate) last_ring_drops: u64,
    pub(crate) rejected_events: u64,
}

pub(crate) struct KernelCore {
    pub(crate) _ebpf: Ebpf,
    pub(crate) exec_events: RingBuf<MapData>,
    pub(crate) egress_events: RingBuf<MapData>,
    pub(crate) ingress_events: RingBuf<MapData>,
    pub(crate) ingress_events_emitted: PerCpuArray<MapData, u64>,
    pub(crate) ingress_ring_drops: PerCpuArray<MapData, u64>,
    pub(crate) ingress_track_insert_failures: PerCpuArray<MapData, u64>,
    pub(crate) cell_lsm_events: RingBuf<MapData>,
    pub(crate) cell_lsm_policies: AyaHashMap<MapData, u64, u8>,
    pub(crate) allow_v4: LpmTrie<MapData, [u8; 4], u8>,
    pub(crate) allow_v6: LpmTrie<MapData, [u8; 16], u8>,
    pub(crate) v4: LpmTrie<MapData, [u8; 4], u8>,
    pub(crate) v6: LpmTrie<MapData, [u8; 16], u8>,
    pub(crate) blocked: HashSet<Target>,
    pub(crate) mode: String,
    // Which hook is actually enforcing ingress, decided at attach time and reported
    // through INGRESS_HEALTH. The attach ladder degrades native XDP -> generic XDP -> TC
    // ingress, and until now the outcome was only written to stderr at start: an operator
    // had no way to tell which of the three was live on their hardware.
    pub(crate) ingress_mode: &'static str,
    pub(crate) cell_lsm_attached: bool,
    pub(crate) cell_policy_epoch: String,
    // Point 3 ABI-2 (§4): policy maps, flow ring/counters and the global word.
    pub(crate) styx_global: AyaArray<MapData, u64>,
    pub(crate) styx_mode: AyaHashMap<MapData, u64, u8>,
    pub(crate) styx_cell_allow_v4: LpmTrie<MapData, [u8; 16], u8>,
    pub(crate) styx_cell_allow_v6: LpmTrie<MapData, [u8; 24], u8>,
    pub(crate) styx_allow_global_v4: LpmTrie<MapData, [u8; 8], u8>,
    pub(crate) styx_allow_global_v6: LpmTrie<MapData, [u8; 20], u8>,
    pub(crate) styx_block_v4: LpmTrie<MapData, [u8; 4], u8>,
    pub(crate) styx_block_v6: LpmTrie<MapData, [u8; 16], u8>,
    pub(crate) styx_resolver_v4: LpmTrie<MapData, [u8; 4], u8>,
    pub(crate) styx_resolver_v6: LpmTrie<MapData, [u8; 16], u8>,
    pub(crate) styx_flow_events: RingBuf<MapData>,
    pub(crate) styx_flow_emitted: PerCpuArray<MapData, u64>,
    pub(crate) styx_ring_drops: PerCpuArray<MapData, u64>,
    pub(crate) styx_agg_insert_failures: PerCpuArray<MapData, u64>,
    pub(crate) styx_egress_parse_errors: PerCpuArray<MapData, u64>,
    pub(crate) styx_egress_drops_total: PerCpuArray<MapData, u64>,
    pub(crate) styx_egress_policy_drops: PerCpuArray<MapData, u64>,
    // Opaque handles for maps only the kernel reads/writes. Taking them makes the
    // startup ABI gate complete: an object missing any §4 map fails loudly here
    // instead of running with silently absent telemetry/caching.
    pub(crate) _styx_resolved: Map,
    pub(crate) _flow_agg_v4: Map,
    pub(crate) _flow_agg_v6: Map,
    pub(crate) styx_epoch: u64,
    pub(crate) styx_epoch_hex: String,
    pub(crate) styx_last_ring_drops: u64,
    pub(crate) styx_flow_rejected: u64,
    // Point 1 (§4/§5): Titan exec-gate maps, RAM policy mirror and honest state.
    pub(crate) titan_exec: TitanExecGate,
    // Point 5 (§5/§6): lockdown state machine (word store + net counters are
    // owned by it; the maps are mandatory above so it can always verify).
    pub(crate) lockdown: lockdown::LockdownCore,
    // 6.1.0 Module B: worker crash-storm sensor (mandatory maps, optional
    // tracepoint attach reported honestly through WORKER_GUARD_STATUS).
    pub(crate) worker_guard: worker_guard::WorkerGuardCore,
    // 6.2.0 M2.2: ransomware/rename-storm sensor (mandatory maps, optional
    // kprobe attach reported through RANSOM_STATUS; the kernel only audits and
    // the core freezes the resolved process group with SIGSTOP).
    pub(crate) ransom: ransom::RansomCore,
    // 6.2.0 M2.4: file_open LSM credential guard (mandatory maps, optional
    // LSM attach reported through CRED_GUARD_STATUS; the kernel denies with -EACCES).
    pub(crate) credential_guard: credential_guard::CredentialGuardCore,
    // Kernel XDR behavioral tracepoints & probe emitters.
    pub(crate) xdr_kernel: xdr_kernel::XdrKernelCore,
    // V6.3.0 AP-0: eBPF pin manifest, synthetic canary self-test and the
    // bounded self-tamper queue (observability only, never enforcement).
    pub(crate) self_defense: self_defense::SelfDefenseCore,
    // V6.3.0 AP-1: executable-inode trust (`TRUSTED_EXEC_INODES`) + TTL malware
    // inode locks; the kernel guard keys on the real exe inode, not comm.
    pub(crate) exec_inode: exec_inode::ExecInodeCore,
    // V6.3.0 AP-2: attach-time eBPF guard (LSM bpf_prog + sys_enter_bpf +
    // BTF-gated check_helper_call helper-risk bitmap).
    pub(crate) bpf_guard: bpf_guard::BpfGuardCore,
    // V6.3.0 AP-3: 8-domain cross-view verifier (eBPF id gap, sock_diag,
    // /proc cross-view, LKM/ftrace, maps/libraries). Observe-only evidence.
    pub(crate) cross_view: cross_view::CrossViewCore,
    // V6.3.0 AP-4: io_uring tracepoints/LSM hooks and pre-stealth LKM capture.
    pub(crate) kernel_hooks: kernel_hooks::KernelHooksCore,
    // V6.3.0 AP-5: linker/PAM/sshd/systemd persistence integrity and desktop
    // peripheral/credential sensors. Observe-only evidence.
    pub(crate) persistence: persistence::PersistenceCore,
    // V6.3.0 AP-6: cgroup_skb/ingress RX flow observer (honest
    // RxObservationAvailable; never drops packets).
    pub(crate) styx_ingress: styx_ingress::StyxIngressCore,
    // V6.3.0 AP-6: bounded DNS query capture (the control plane runs the
    // multi-signal tunnelling analysis).
    pub(crate) dns_capture: dns_capture::DnsCaptureCore,
    // V6.3.0 AP-9 (S12): high-priority security evidence ring, independent of
    // the bulk telemetry rings, plus the aggregated flood-suppression status.
    pub(crate) sec_crit: sec_crit::SecCritCore,
}
