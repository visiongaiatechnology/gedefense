//! Wave 3a extraction: the XDR/process-response and sensor command surface
//! (`EXEC_*`, `KERNEL_PROBE_*`, `XDR_*`, `CROSS_VIEW_*`, `BPF_GUARD_*`) formerly
//! inline in `main.rs`.

use crate::*;

pub(crate) fn dispatch(
    core: &mut KernelCore,
    parts: &[&str],
) -> Result<Option<String>, BoxError> {
    let result = match parts {
        ["EXEC_EVENTS"] => core.take_exec_events(),
        ["EXEC_ARGV_EVENTS"] => core.xdr_kernel.take_exec_argv_events(),
        ["KERNEL_PROBE_EVENTS"] => core.xdr_kernel.take_kernel_probe_events(),
        ["XDR_STOP", pid, start, rule] => {
            let pid = pid.parse::<i32>()?;
            let start = start.parse::<u64>()?;
            pidfd_signal(pid, start, libc::SIGSTOP, rule).map(|_| "stopped".into())
        }
        ["XDR_CONT", pid, start, rule] | ["XDR_RESUME", pid, start, rule] => {
            let pid = pid.parse::<i32>()?;
            let start = start.parse::<u64>()?;
            pidfd_signal(pid, start, libc::SIGCONT, rule).map(|_| "resumed".into())
        }
        ["XDR_KILL", pid, start, rule] => {
            let pid = pid.parse::<i32>()?;
            let start = start.parse::<u64>()?;
            pidfd_signal(pid, start, libc::SIGKILL, rule).map(|_| "killed".into())
        }
        // M2.3 (6.2.0 ABI v2): bounded process-tree/process-group response.
        // Wire: XDR_KILL_TREE <pid> <start_ticks> <rule> -> "killed:<n>";
        // XDR_GROUP_STOP|<pgid> <rule> -> "stopped"; XDR_GROUP_CONT -> "resumed".
        ["XDR_KILL_TREE", args @ ..] => {
            let (pid, start, rule) = process_tree::parse_kill_tree_request(args)?;
            process_tree::signal_process_tree(pid, start, &rule)
                .map(|count| format!("killed:{count}"))
        }
        ["XDR_GROUP_STOP", args @ ..] => {
            let (pgid, rule) = process_tree::parse_group_request(args)?;
            process_tree::stop_process_group(pgid, &rule).map(|_| "stopped".to_owned())
        }
        ["XDR_GROUP_CONT", args @ ..] => {
            let (pgid, rule) = process_tree::parse_group_request(args)?;
            process_tree::resume_process_group(pgid, &rule).map(|_| "resumed".to_owned())
        }
        // V6.3.0 AP-2: attach-time eBPF guard (helper-risk bitmap, observe-only).
        ["BPF_GUARD_EPOCH"] => Ok(core.bpf_guard.epoch()),
        ["BPF_GUARD_STATUS"] => Ok(core.bpf_guard.status()),
        ["BPF_GUARD_EVENTS"] => core.bpf_guard.take_events(),
        ["BPF_GUARD_SET", state] => core.bpf_guard.set_enabled_token(state),
        // V6.3.0 AP-3: 8-domain cross-view verifier (contradictions are evidence,
        // never a block).
        ["CROSS_VIEW_STATUS"] => Ok(core.cross_view.status()),
        ["CROSS_VIEW_REPORT"] => core.cross_view.report(),
        ["CROSS_VIEW_EVENTS"] => core.cross_view.take_events(),
        _ => return Ok(None),
    };
    Ok(Some(result?))
}
