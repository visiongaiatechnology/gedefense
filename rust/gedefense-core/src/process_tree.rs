//! M2.3 (6.2.0): bounded process-tree/process-group response for the core.
//!
//! Wire commands (ABI v2, exactly; see `process_control.rs` module docs):
//! `XDR_KILL_TREE <pid> <start_ticks> <rule>` -> `killed:<n>`,
//! `XDR_GROUP_STOP <pgid> <rule>` -> `stopped`,
//! `XDR_GROUP_CONT <pgid> <rule>` -> `resumed`.
//!
//! Every decision here is bounded and fail-closed: a `/proc` snapshot above
//! [`MAX_TREE_PROCESSES`], a tree above [`MAX_TREE_SIGNALS`] members or above
//! [`MAX_TREE_DEPTH`] ancestry levels is an error, never a partial silent
//! response. All targets are re-verified by start ticks around `pidfd_open`, so
//! a PID-reuse race loses a kill but can never hit an unrelated process. The
//! compiled protection allowlist cannot be widened by a caller.

use crate::{process_control::valid_rule_token, BoxError};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};

/// Bounded `/proc` snapshot size for one tree response.
pub(crate) const MAX_TREE_PROCESSES: usize = 4096;
/// Bounded PPID ancestry depth.
pub(crate) const MAX_TREE_DEPTH: u8 = 64;
/// Hard cap on processes one response may signal.
pub(crate) const MAX_TREE_SIGNALS: usize = 1024;
/// `/proc/<pid>/stat` read bound (the real line is far shorter).
const MAX_PROC_STAT_BYTES: u64 = 4096;

/// One `/proc/<pid>/stat` snapshot needed for tree/group decisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcEntry {
    pub(crate) pid: i32,
    pub(crate) ppid: i32,
    pub(crate) pgrp: i32,
    pub(crate) start_ticks: u64,
    pub(crate) comm: String,
}

/// Parses `/proc/<pid>/stat` without trusting spaces or parentheses inside the
/// task `comm` (the kernel encloses it in the first `(` .. last `)` pair).
pub(crate) fn parse_proc_stat(pid: i32, stat: &str) -> Option<ProcEntry> {
    if pid <= 0 {
        return None;
    }
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close <= open + 1 {
        return None;
    }
    let comm = stat.get(open + 1..close)?;
    if comm.is_empty()
        || comm.len() > 64
        || comm.bytes().any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return None;
    }
    let fields: Vec<&str> = stat.get(close + 2..)?.split_whitespace().collect();
    // After comm: state=0, ppid=1, pgrp=2, ... starttime=19 (stat field 22).
    if fields.len() <= 19 {
        return None;
    }
    Some(ProcEntry {
        pid,
        ppid: fields[1].parse().ok()?,
        pgrp: fields[2].parse().ok()?,
        start_ticks: fields[19].parse().ok()?,
        comm: comm.to_owned(),
    })
}

fn read_proc_entry(pid: i32) -> Option<ProcEntry> {
    use std::io::Read as _;
    let file = fs::File::open(format!("/proc/{pid}/stat")).ok()?;
    let mut stat = String::new();
    file.take(MAX_PROC_STAT_BYTES + 1)
        .read_to_string(&mut stat)
        .ok()?;
    if stat.len() as u64 > MAX_PROC_STAT_BYTES {
        return None;
    }
    parse_proc_stat(pid, &stat)
}

/// Start time (stat field 22) of one live PID.
pub(crate) fn proc_start_ticks(pid: i32) -> Result<u64, BoxError> {
    read_proc_entry(pid)
        .map(|entry| entry.start_ticks)
        .ok_or_else(|| "malformed proc stat".into())
}

/// Pure exemption check over a synthetic `/proc` snapshot: true when any member
/// of `pgid` runs a trusted task name (package manager / compiler / backup
/// tool). The M2.2 freeze broker uses it to keep `apt`/`dpkg`/`tar`/build
/// child-task bursts from being frozen, even though the child task itself does
/// not carry the parent's `comm`.
pub(crate) fn group_has_trusted_comm(
    pgid: i32,
    table: &[ProcEntry],
    trusted: &[&str],
) -> bool {
    if pgid <= 1 {
        return true;
    }
    table.iter().any(|entry| {
        entry.pgrp == pgid && trusted.iter().any(|name| *name == entry.comm)
    })
}

/// Reads the bounded `/proc` snapshot and answers the exemption question for
/// one process group.
pub(crate) fn process_group_has_trusted_comm(
    pgid: i32,
    trusted: &[&str],
) -> Result<bool, BoxError> {
    let table = read_process_table()?;
    Ok(group_has_trusted_comm(pgid, &table, trusted))
}

/// Resolves the process group of one TGID (used by the M2.2 freeze broker).
pub(crate) fn process_group_of(pid: i32) -> Result<i32, BoxError> {
    read_proc_entry(pid)
        .map(|entry| entry.pgrp)
        .ok_or_else(|| "process group target disappeared".into())
}

/// Reads a bounded snapshot of every numeric `/proc/<pid>` entry. Processes
/// that exit while the snapshot is taken are skipped; a snapshot larger than
/// [`MAX_TREE_PROCESSES`] is an error (fail-closed, no truncated tree).
pub(crate) fn read_process_table() -> Result<Vec<ProcEntry>, BoxError> {
    let mut table = Vec::with_capacity(256);
    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<i32>() else { continue };
        if pid <= 0 {
            continue;
        }
        if let Some(proc_entry) = read_proc_entry(pid) {
            table.push(proc_entry);
        }
        if table.len() > MAX_TREE_PROCESSES {
            return Err("proc snapshot exceeds the tree budget".into());
        }
    }
    Ok(table)
}

/// Collects the bounded kill set for `root_pid`: PPID descendants (BFS, depth
/// capped) plus every member of the root's process group. The visited set makes
/// the walk cycle-safe even against a synthetic `/proc` snapshot; ordering is
/// deepest-first so children are stopped before their parent. The root must
/// remain present.
pub(crate) fn collect_tree(root_pid: i32, table: &[ProcEntry]) -> Result<Vec<ProcEntry>, BoxError> {
    let Some(root) = table.iter().find(|entry| entry.pid == root_pid) else {
        return Err("kill tree root is not present in the proc snapshot".into());
    };
    let mut children: HashMap<i32, Vec<&ProcEntry>> = HashMap::new();
    for entry in table {
        children.entry(entry.ppid).or_default().push(entry);
    }
    let mut visited: HashSet<i32> = HashSet::new();
    let mut ordered: Vec<(u8, ProcEntry)> = Vec::new();
    let mut queue: VecDeque<(i32, u8)> = VecDeque::from([(root.pid, 0)]);
    while let Some((pid, depth)) = queue.pop_front() {
        if !visited.insert(pid) {
            continue;
        }
        let Some(entry) = table.iter().find(|entry| entry.pid == pid) else {
            continue;
        };
        if ordered.len() >= MAX_TREE_SIGNALS {
            return Err("kill tree exceeds the signal budget".into());
        }
        ordered.push((depth, entry.clone()));
        let child_depth = depth.checked_add(1).ok_or("kill tree depth overflow")?;
        if child_depth > MAX_TREE_DEPTH {
            return Err("kill tree exceeds the depth budget".into());
        }
        if let Some(children) = children.get(&pid) {
            for child in children {
                queue.push_back((child.pid, child_depth));
            }
        }
    }
    // Process-group members of the root's group (the PGID half of the scope).
    for entry in table {
        if entry.pgrp == root.pgrp && !visited.contains(&entry.pid) {
            if ordered.len() >= MAX_TREE_SIGNALS {
                return Err("kill tree exceeds the signal budget".into());
            }
            visited.insert(entry.pid);
            ordered.push((1, entry.clone()));
        }
    }
    if !ordered.iter().any(|(_, entry)| entry.pid == root.pid) {
        return Err("kill tree root escaped the collection".into());
    }
    // Deepest first; the root (depth 0) is signaled last. Stable tie-break on
    // PID for determinism.
    ordered.sort_unstable_by(|left, right| right.0.cmp(&left.0).then(left.1.pid.cmp(&right.1.pid)));
    Ok(ordered.into_iter().map(|(_, entry)| entry).collect())
}

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

/// Signals exactly one identity-verified PID with `SIGKILL` through pidfd. The
/// start time is checked before and after `pidfd_open`; a vanished process is a
/// benign skip, any other failure is reported.
fn pidfd_sigkill_verified(pid: i32, expected_start: u64) -> Result<(), BoxError> {
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
                libc::SIGKILL,
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

/// Pure request parser for `XDR_KILL_TREE`; all tokens are strict.
pub(crate) fn parse_kill_tree_request(args: &[&str]) -> Result<(i32, u64, String), BoxError> {
    let [pid, start, rule] = args else {
        return Err("XDR_KILL_TREE requires pid, start ticks and rule".into());
    };
    let pid = pid
        .parse::<i32>()
        .map_err(|_| -> BoxError { "kill tree pid is not a decimal integer".into() })?;
    if pid <= 4 {
        return Err("kill tree pid is protected".into());
    }
    let start = start
        .parse::<u64>()
        .map_err(|_| -> BoxError { "kill tree start ticks are not a decimal integer".into() })?;
    if start == 0 {
        return Err("kill tree start ticks must be non-zero".into());
    }
    if !valid_rule_token(rule) {
        return Err("invalid rule token".into());
    }
    Ok((pid, start, rule.to_string()))
}

/// M2.2 immediate freeze: `kill(-pgid, SIGSTOP)` after refusing the own group
/// and the unsafe special groups. Bounded and reversible (`XDR_GROUP_CONT`).
pub(crate) fn stop_process_group(pgid: i32, rule: &str) -> Result<(), BoxError> {
    group_signal(pgid, libc::SIGSTOP, rule)
}

/// M2.2 reversal: `kill(-pgid, SIGCONT)` with the same guards as the freeze.
pub(crate) fn resume_process_group(pgid: i32, rule: &str) -> Result<(), BoxError> {
    group_signal(pgid, libc::SIGCONT, rule)
}

/// Strict parser for the group commands: positive PGID, valid rule token.
pub(crate) fn parse_group_request(args: &[&str]) -> Result<(i32, String), BoxError> {
    let [pgid, rule] = args else {
        return Err("group command requires pgid and rule".into());
    };
    let pgid = pgid
        .parse::<i32>()
        .map_err(|_| -> BoxError { "process-group id is not a decimal integer".into() })?;
    if pgid <= 1 {
        return Err("protected process group".into());
    }
    if !valid_rule_token(rule) {
        return Err("invalid rule token".into());
    }
    Ok((pgid, rule.to_string()))
}

fn group_signal(pgid: i32, signal: i32, rule: &str) -> Result<(), BoxError> {
    let (pgid, _) = parse_group_request(&[&pgid.to_string(), rule])?;
    // SAFETY: getpgrp has no arguments and cannot fail.
    let own_pgrp = unsafe { libc::getpgrp() };
    if pgid == own_pgrp || pgid == std::process::id() as i32 {
        return Err("own process group is protected".into());
    }
    if signal != libc::SIGSTOP && signal != libc::SIGCONT {
        return Err("unsupported group signal".into());
    }
    let rc = unsafe { libc::kill(-pgid, signal) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        return Err(std::io::Error::other(format!(
            "process-group signal failed pgid={pgid}: {error}"
        ))
        .into());
    }
    Ok(())
}
