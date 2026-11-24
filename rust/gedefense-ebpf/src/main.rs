#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::tracepoint,
    programs::TracePointContext,
};
use gedefense_common::ExecEvent;

/// 6.1.0 Module B: independent worker crash sensor (own maps/program).
mod worker_guard;

/// 6.2.0 M2.2: ransomware / rename-storm sensor (own maps/kprobes).
mod ransom;

/// 6.2.0 M2.4: file_open LSM credential guard (own map set/program).
mod credential_guard;

/// Kernel XDR behavioral tracepoints & probe emitters.
mod xdr_kernel;

/// V6.3.0 AP-1: executable-inode identity resolution for the credential and
/// ransomware guards (replaces the spoofable `comm` allowlists).
mod exec_inode;

/// V6.3.0 AP-2: attach-time eBPF guard (`security_bpf_prog`,
/// `sys_enter_bpf`, BTF-gated `check_helper_call` helper-risk bitmap).
mod bpf_guard;

/// V6.3.0 AP-3: cross-view kernel supports (socket AF_PACKET/setsockopt tap,
/// BTF-gated `bpf_iter` programs).
mod iter;

/// V6.3.0 AP-4: io_uring tracepoints/LSM hooks and module-load capture.
mod kernel_hooks;

/// V6.3.0 AP-5: linker/PAM/sshd/peripheral persistence sensors.
mod persistence;

/// V6.3.0 AP-6: cgroup_skb/ingress RX flow observation (PCR phase 2).
mod ingress_flow;

/// V6.3.0 AP-6: bounded DNS query capture for tunnelling detection.
mod dns_capture;

/// V6.3.0 AP-9 (S12): high-priority security evidence ring and telemetry
/// token buckets used by the bulk emitters.
mod sec_crit;

mod maps;
mod net_parse;
mod ingress_xdp;
mod styx_egress;
mod cell_lsm;
mod titan_exec;
mod util;

use crate::maps::EXEC_EVENTS;

#[tracepoint]
pub fn gedefense_exec(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = match bpf_get_current_comm() {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let event = ExecEvent {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        comm,
    };
    let _ = EXEC_EVENTS.output::<ExecEvent>(&event, 0);
    xdr_kernel::flush_pending_exec_argv(pid_tgid as u32, comm);
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // eBPF programs cannot unwind. This branch is unreachable in verified paths.
    unsafe { core::hint::unreachable_unchecked() }
}
