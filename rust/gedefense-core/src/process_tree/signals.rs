//! M2.3 bounded signaling: the hard protection allowlist, pidfd identity
//! verification and the tree/descendant `SIGSTOP`/`SIGKILL` operations.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{process_control::valid_rule_token, BoxError};

use super::tree::{collect_tree, proc_start_ticks, read_process_table, ProcEntry};

fn resolve_exe(pid: i32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

/// Pure hard protection predicate: PID 1..4, own core, systemd*/sshd/gedefense
/// tasks, kernel threads (no readable `exe`) and every process running one of
/// the protected system executables. Never widened by callers.
fn protected_comm_or_exe(pid: i32, comm: &str, exe: Option<&Path>, own_pid: i32) -> bool {
    if pid <= 4 || pid == own_pid {
        return true;
    }
    if comm == "systemd"
        || comm.starts_with("systemd-")
        || comm == "(systemd)"
        || comm == "(sd-executor)"
        || comm == "(sd-pam)"
        || comm == "(udev-worker)"
        || comm == "udevadm"
        || comm == "sshd"
        || comm.starts_with("sshd:")
        || comm.starts_with("gedefense")
    {
        return true;
    }
    let Some(exe) = exe else {
        return false;
    };
    let exe = exe.to_string_lossy();
    exe.starts_with("/opt/vgt/gedefense")
        || exe.contains("/systemd")
        || exe.ends_with("/sshd")
        || exe.ends_with("/sshd-session")
        || exe.starts_with("/usr/lib/systemd")
        || exe.starts_with("/lib/systemd")
}

/// Pure hard protection predicate for a live `/proc/<pid>` entry: PID 1..4,
/// kernel threads (`ppid == 2`), own core, systemd*/sshd/gedefense tasks, and
/// every process running one of the protected system executables. Unreadable
/// `/proc/<pid>/exe` on a non-kernel userspace process (`ppid != 2`, expected
/// for `uid != 0` when `CAP_SYS_PTRACE` is absent) does not shield malware.
pub(crate) fn protected_proc_entry(
    entry: &ProcEntry,
    exe: Option<&Path>,
    own_pid: i32,
) -> bool {
    entry.ppid == 2 || protected_comm_or_exe(entry.pid, &entry.comm, exe, own_pid)
}

#[cfg(test)]
pub(crate) fn protected_target(pid: i32, comm: &str, exe: Option<&Path>, own_pid: i32) -> bool {
    protected_comm_or_exe(pid, comm, exe, own_pid) || exe.is_none()
}

/// Pure check over a `/proc` snapshot: true when any member of `pgid` satisfies
/// [`protected_proc_entry`]. Keeps rapid kernel-side bursts in system daemons
/// (such as `systemd-udevd`) from ever receiving a `SIGSTOP`.
pub(crate) fn group_has_protected_target<F>(
    pgid: i32,
    table: &[ProcEntry],
    own_pid: i32,
    mut exe_lookup: F,
) -> bool
where
    F: FnMut(i32) -> Option<PathBuf>,
{
    if pgid <= 1 {
        return true;
    }
    table.iter().any(|entry| {
        entry.pgrp == pgid
            && protected_proc_entry(entry, exe_lookup(entry.pid).as_deref(), own_pid)
    })
}

/// Reads the bounded `/proc` snapshot and checks whether any member of `pgid`
/// is protected.
pub(crate) fn process_group_has_protected_target(pgid: i32) -> Result<bool, BoxError> {
    let table = read_process_table()?;
    let own_pid = std::process::id() as i32;
    Ok(group_has_protected_target(pgid, &table, own_pid, resolve_exe))
}

fn is_benign_kill_error(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ESRCH) | Some(libc::ENOENT))
}

/// M2.2 isolated freeze for pooled daemon workers: freezes only `root_pid` and
/// its verified PPID descendants via pidfd `SIGSTOP`, keeping pool siblings alive.
pub(crate) fn stop_process_descendants(root_pid: i32, rule: &str) -> Result<(), BoxError> {
    if root_pid <= 4 || root_pid == std::process::id() as i32 {
        return Err("protected PID".into());
    }
    if !valid_rule_token(rule) {
        return Err("invalid rule token".into());
    }
    let table = read_process_table()?;
    let members = collect_tree(root_pid, &table)?;
    let own_pid = std::process::id() as i32;
    let mut stopped = 0u32;
    for member in &members {
        let exe = resolve_exe(member.pid);
        if protected_proc_entry(member, exe.as_deref(), own_pid) {
            continue;
        }
        if pidfd_sig_verified(member.pid, member.start_ticks, libc::SIGSTOP).is_ok() {
            stopped += 1;
        }
    }
    if stopped == 0 {
        return Err("isolated worker freeze signaled no process".into());
    }
    Ok(())
}

/// Signals one identity-verified PID with the requested signal through pidfd.
fn pidfd_sig_verified(pid: i32, expected_start: u64, sig: i32) -> Result<(), BoxError> {
    if proc_start_ticks(pid)? != expected_start {
        return Err("PID identity mismatch before pidfd_open".into());
    }
    // SAFETY: pidfd_open is called with a validated positive PID and flags=0.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) as i32 };
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = (|| {
        if proc_start_ticks(pid)? != expected_start {
            return Err("PID identity mismatch after pidfd_open".into());
        }
        // SAFETY: pidfd is identity-checked and a null siginfo is supported.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    })();
    // SAFETY: pidfd is owned by this function and closed exactly once.
    unsafe { libc::close(pidfd) };
    result
}

/// Signals exactly one identity-verified PID with `SIGKILL` through pidfd. The
/// start time is checked before and after `pidfd_open`; a vanished process is a
/// benign skip, any other failure is reported.
fn pidfd_sigkill_verified(pid: i32, expected_start: u64) -> Result<(), BoxError> {
    pidfd_sig_verified(pid, expected_start, libc::SIGKILL)
}

/// M2.3: bounded, identity-checked process-tree/group `SIGKILL`. The root must
/// satisfy the pre-existing objective-evidence contract for `SIGKILL`; members
/// are protected by the compiled allowlist and by the double start-time check.
/// Returns the number of signaled processes.
pub(crate) fn signal_process_tree(
    root_pid: i32,
    expected_start: u64,
    rule: &str,
) -> Result<u32, BoxError> {
    if root_pid <= 4 || root_pid == std::process::id() as i32 {
        return Err("protected PID".into());
    }
    if !valid_rule_token(rule) {
        return Err("invalid rule token".into());
    }
    if proc_start_ticks(root_pid)? != expected_start {
        return Err("PID identity mismatch before tree collection".into());
    }
    if !crate::process_control::objective_kill_evidence_for_root(root_pid, rule) {
        return Err("kill rejected: objective evidence missing".into());
    }
    let table = read_process_table()?;
    let members = collect_tree(root_pid, &table)?;
    let own_pid = std::process::id() as i32;
    // SAFETY: getpgrp has no arguments and cannot fail.
    let own_pgrp = unsafe { libc::getpgrp() };
    let mut killed = 0u32;
    let mut skipped = 0u32;
    for member in &members {
        if member.pgrp == own_pgrp && member.pid == own_pid {
            skipped += 1;
            continue;
        }
        let exe = resolve_exe(member.pid);
        if protected_proc_entry(member, exe.as_deref(), own_pid) {
            if member.pid == root_pid {
                return Err("kill tree root is protected".into());
            }
            skipped += 1;
            continue;
        }
        match pidfd_sigkill_verified(member.pid, member.start_ticks) {
            Ok(()) => killed += 1,
            Err(error) => {
                let benign = error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(is_benign_kill_error);
                if benign {
                    skipped += 1;
                } else if member.pid == root_pid {
                    return Err(format!("tree root kill failed: {error}").into());
                } else {
                    eprintln!(
                        "GeDefense tree kill skipped pid={} comm={} error={error}",
                        member.pid, member.comm
                    );
                    skipped += 1;
                }
            }
        }
    }
    eprintln!(
        "GeDefense process tree killed root={root_pid} rule={rule} killed={killed} skipped={skipped}"
    );
    if killed == 0 {
        return Err("tree kill signaled no process".into());
    }
    Ok(killed)
}
