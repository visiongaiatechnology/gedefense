//! Privileged process response primitives of the Rust core.
//!
//! 6.1.x: single-PID response via `pidfd_send_signal` with a double-checked
//! `/proc/<pid>/stat` start-time identity (`XDR_STOP`, `XDR_CONT`/`XDR_RESUME`,
//! `XDR_KILL`).
//!
//! 6.2.0 ABI (M2.3, endpoint P1): the kill family is extended by a *bounded
//! process-tree/process-group* response (implementation in [`crate::process_tree`]).
//! Wire commands (exactly):
//!
//! ```text
//! XDR_KILL_TREE <pid> <start_ticks> <rule>     -> "killed:<n>"
//! XDR_GROUP_STOP <pgid> <rule>                 -> "stopped"
//! XDR_GROUP_CONT <pgid> <rule>                 -> "resumed"
//! ```
//!
//! `pid`/`start_ticks`/`pgid` are strict decimal tokens, `rule` uses the
//! pre-existing `valid_rule_token` alphabet, `n` is the number of processes
//! that received `SIGKILL` (root included). The tree response is bounded
//! (`MAX_TREE_SIGNALS` members, `MAX_TREE_DEPTH` levels, `MAX_TREE_PROCESSES`
//! snapshot); exceeding a budget is an error (fail-closed), never a partially
//! silent partial kill. Every target is re-verified by start ticks before and
//! after `pidfd_open`, so PID reuse can only lose a kill, never hit an
//! unrelated process. `XDR_GROUP_STOP`/`XDR_GROUP_CONT` are the reversible
//! immediate-freeze pair of the M2.2 ransomware broker; the own process group
//! is always refused.
//!
//! Hard protection allowlist (compiled in, the root is an error instead of a
//! silent skip): PID 1..4, the core itself, `systemd`/`systemd-*`, `sshd`,
//! every `gedefense-*` task, kernel threads (unreadable `/proc/<pid>/exe`) and
//! processes running the protected system executables.

use crate::BoxError;
use std::{
    ffi::CString,
    fs,
    os::{fd::AsRawFd, unix::net::UnixStream},
};

pub(super) fn valid_rule_token(rule: &str) -> bool {
    !rule.is_empty()
        && rule.len() <= 64
        && rule
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Objective evidence contract for `SIGKILL` (unchanged from 6.1.x; the tree
/// broker re-validates it for the tree root): the rule name decides which
/// `/proc` fact must be verifiable before a kill.
pub(crate) fn objective_kill_evidence_for_root(pid: i32, rule: &str) -> bool {
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    match rule {
        "XDR.MEMFD_EXEC" => exe.contains("/memfd:") || exe.starts_with("memfd:"),
        "XDR.EXE_DELETED" => exe.ends_with(" (deleted)"),
        "XDR.TEMP_EXEC" => {
            exe.starts_with("/tmp/") || exe.starts_with("/var/tmp/") || exe.starts_with("/dev/shm/")
        }
        "XDR.RANSOM_ENTROPY_BURST" | "XDR.RANSOM_RENAME_STORM" => {
            // The ransomware broker already correlated the kernel sample; the
            // kill evidence is the live root identity that was checked above.
            !exe.is_empty() || fs::metadata(format!("/proc/{pid}/stat")).is_ok()
        }
        "KD.LINUX.DESTRUCTIVE" => {
            let command = fs::read(format!("/proc/{pid}/cmdline"))
                .ok()
                .map(|bytes| String::from_utf8_lossy(&bytes).replace('\0', " "))
                .unwrap_or_default();
            command.contains("rm -rf /")
                || command.contains("mkfs.")
                || command.contains("of=/dev/")
        }
        _ => false,
    }
}

pub(super) fn pidfd_signal(
    pid: i32,
    expected_start: u64,
    signal: i32,
    rule: &str,
) -> Result<(), BoxError> {
    if pid <= 4 || pid == std::process::id() as i32 {
        return Err("protected PID".into());
    }
    if !valid_rule_token(rule) {
        return Err("invalid rule token".into());
    }
    if signal != libc::SIGSTOP && signal != libc::SIGKILL && signal != libc::SIGCONT {
        return Err("unsupported signal".into());
    }
    if crate::process_tree::proc_start_ticks(pid)? != expected_start {
        return Err("PID identity mismatch before pidfd_open".into());
    }
    // SAFETY: pidfd_open is called with a validated positive PID and flags=0.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) as i32 };
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = (|| {
        if crate::process_tree::proc_start_ticks(pid)? != expected_start {
            return Err("PID identity mismatch after pidfd_open".into());
        }
        if signal == libc::SIGKILL && !objective_kill_evidence_for_root(pid, rule) {
            return Err("kill rejected: objective evidence missing".into());
        }
        // SAFETY: pidfd is identity-checked, signal is caller-restricted to
        // SIGSTOP/SIGKILL/SIGCONT, and a null siginfo is supported by the syscall.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    })();
    // SAFETY: pidfd is owned by this function and is not used after close.
    unsafe {
        libc::close(pidfd);
    }
    result
}

pub(super) fn lookup_identity(user: &str) -> Result<(u32, u32), BoxError> {
    let name = CString::new(user)?;
    // SAFETY: name is NUL-terminated; copied UID/GID values outlive libc state.
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };
    if entry.is_null() {
        return Err(format!("control user {user:?} does not exist").into());
    }
    // SAFETY: null was checked above.
    Ok(unsafe { ((*entry).pw_uid, (*entry).pw_gid) })
}

pub(super) fn peer_uid(stream: &UnixStream) -> Result<u32, BoxError> {
    let mut cred = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the output buffer matches ucred and returned size is verified.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if len as usize != std::mem::size_of::<libc::ucred>() {
        return Err("unexpected SO_PEERCRED response size".into());
    }
    // SAFETY: getsockopt succeeded and returned the exact ucred size.
    Ok(unsafe { cred.assume_init().uid })
}
