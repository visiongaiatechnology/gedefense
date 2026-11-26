//! M2.3 bounded `/proc` model: strict `stat` parsing, the bounded snapshot
//! and the process-tree/process-group collectors used by the kill/freeze
//! paths.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
};

use crate::BoxError;

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

pub(crate) fn read_proc_entry(pid: i32) -> Option<ProcEntry> {
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

/// Pure predicate for immutable hosting-panel server trees (never webroots
/// such as `/www/wwwroot`).
pub(crate) fn is_panel_server_exe_path(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.starts_with("/www/server/") || text.starts_with("/opt/plesk/")
}

/// Verifies via `symlink_metadata` that every segment strictly below `root_prefix`
/// up to `path` contains no symlink and carries no group/world write permission;
/// when `require_root` is true every checked segment must be owned by uid 0.
pub(crate) fn path_chain_immutable_under(
    root_prefix: &Path,
    path: &Path,
    require_root: bool,
) -> bool {
    let Ok(rel) = path.strip_prefix(root_prefix) else {
        return false;
    };
    let mut cur = root_prefix.to_path_buf();
    let total = rel.components().count();
    if total == 0 {
        return false;
    }
    for (idx, comp) in rel.components().enumerate() {
        cur.push(comp);
        let Ok(meta) = fs::symlink_metadata(&cur) else {
            return false;
        };
        if meta.file_type().is_symlink() {
            return false;
        }
        if idx + 1 < total && !meta.is_dir() {
            return false;
        }
        if idx + 1 == total && !meta.is_file() {
            return false;
        }
        if (meta.mode() & 0o022) != 0 {
            return false;
        }
        if require_root && meta.uid() != 0 {
            return false;
        }
    }
    true
}

/// Checks whether a live PID is backed by a non-deleted executable under a
/// trusted system root whose binary filename matches its `/proc/<pid>/stat`
/// `comm` (mitigates `prctl(PR_SET_NAME)` spoofing bypass, LIN-H04).
pub(crate) fn verified_trusted_comm_exe(pid: i32, comm: &str, trusted: &[&str]) -> bool {
    if !trusted.iter().any(|name| *name == comm) {
        return false;
    }
    let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    let text = exe.to_string_lossy();
    if text.ends_with(" (deleted)") {
        return false;
    }
    let trusted_prefix = text.starts_with("/usr/")
        || text.starts_with("/bin/")
        || text.starts_with("/sbin/")
        || text.starts_with("/lib/")
        || text.starts_with("/lib64/")
        || text.starts_with("/opt/vgt/gedefense/");
    let trusted_panel = is_panel_server_exe_path(&exe)
        && path_chain_immutable_under(Path::new("/"), &exe, true);
    if !trusted_prefix && !trusted_panel {
        return false;
    }
    exe.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|base| base == comm || base.starts_with(comm))
}

fn verified_apt_method_exe(pid: i32) -> bool {
    let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    let text = exe.to_string_lossy();
    !text.ends_with(" (deleted)") && text.starts_with("/usr/lib/apt/methods/")
}

/// Live `/proc` exemption check requiring `/proc/<pid>/exe` corroboration.
pub(crate) fn process_group_has_verified_trusted_exe(
    pgid: i32,
    trusted: &[&str],
) -> Result<bool, BoxError> {
    if pgid <= 1 {
        return Ok(true);
    }
    let table = read_process_table()?;
    Ok(table.iter().any(|entry| {
        entry.pgrp == pgid
            && (verified_trusted_comm_exe(entry.pid, &entry.comm, trusted)
                || verified_apt_method_exe(entry.pid))
    }))
}

/// Reads the bounded `/proc` snapshot and answers the exemption question for
/// one process group.
#[allow(dead_code)]
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

/// Pure synthetic predicate over a `/proc` snapshot: true when `root` is a
/// non-leader worker inside a shared multi-worker service pool. Live `/proc`
/// callers must use [`verified_entry_is_service_pool_worker`] so spoofed
/// `comm` strings without matching executables cannot isolate malware.
pub(crate) fn entry_is_service_pool_worker(root: &ProcEntry, table: &[ProcEntry]) -> bool {
    if root.pid <= 1 || root.pid == root.pgrp {
        return false;
    }
    if crate::ransom::POOL_SERVICE_COMMS.contains(&root.comm.as_str()) {
        return true;
    }
    table.iter().any(|entry| {
        entry.pid == root.pgrp && crate::ransom::POOL_SERVICE_COMMS.contains(&entry.comm.as_str())
    })
}

/// Live `/proc` service-pool worker check requiring `/proc/<pid>/exe` system-prefix corroboration.
pub(crate) fn verified_entry_is_service_pool_worker(root: &ProcEntry, table: &[ProcEntry]) -> bool {
    if root.pid <= 1 || root.pid == root.pgrp {
        return false;
    }
    if verified_trusted_comm_exe(root.pid, &root.comm, crate::ransom::POOL_SERVICE_COMMS) {
        return true;
    }
    table.iter().any(|entry| {
        entry.pid == root.pgrp
            && verified_trusted_comm_exe(entry.pid, &entry.comm, crate::ransom::POOL_SERVICE_COMMS)
    })
}

/// Checks whether a live PID is a verified worker inside a pooled service daemon group.
pub(crate) fn is_service_pool_worker(pid: i32) -> Result<bool, BoxError> {
    if pid <= 1 {
        return Ok(false);
    }
    let table = read_process_table()?;
    let Some(root) = table.iter().find(|entry| entry.pid == pid) else {
        return Ok(false);
    };
    Ok(verified_entry_is_service_pool_worker(root, &table))
}

fn collect_tree_with_isolation(
    root: &ProcEntry,
    table: &[ProcEntry],
    isolate_worker_only: bool,
) -> Result<Vec<ProcEntry>, BoxError> {
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
    // Process-group members of the root's group (the PGID half of the scope),
    // skipped when isolating a verified pooled service worker to avoid master/sibling DoS.
    if !isolate_worker_only {
        for entry in table {
            if entry.pgrp == root.pgrp && !visited.contains(&entry.pid) {
                if ordered.len() >= MAX_TREE_SIGNALS {
                    return Err("kill tree exceeds the signal budget".into());
                }
                visited.insert(entry.pid);
                ordered.push((1, entry.clone()));
            }
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

/// Collects the bounded kill set for `root_pid` over a synthetic snapshot.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn collect_tree(root_pid: i32, table: &[ProcEntry]) -> Result<Vec<ProcEntry>, BoxError> {
    let Some(root) = table.iter().find(|entry| entry.pid == root_pid) else {
        return Err("kill tree root is not present in the proc snapshot".into());
    };
    let isolate_worker_only = entry_is_service_pool_worker(root, table);
    collect_tree_with_isolation(root, table, isolate_worker_only)
}

/// Live-host variant requiring `/proc/<pid>/exe` corroboration before isolating a worker.
pub(crate) fn collect_tree_live(root_pid: i32, table: &[ProcEntry]) -> Result<Vec<ProcEntry>, BoxError> {
    let Some(root) = table.iter().find(|entry| entry.pid == root_pid) else {
        return Err("kill tree root is not present in the proc snapshot".into());
    };
    let isolate_worker_only = verified_entry_is_service_pool_worker(root, table);
    collect_tree_with_isolation(root, table, isolate_worker_only)
}
