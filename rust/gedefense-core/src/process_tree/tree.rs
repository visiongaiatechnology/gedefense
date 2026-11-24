//! M2.3 bounded `/proc` model: strict `stat` parsing, the bounded snapshot
//! and the process-tree/process-group collectors used by the kill/freeze
//! paths.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
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

/// Returns true when `root` is a non-leader worker inside a shared multi-worker
/// service pool (e.g. `php-fpm`, `lsphp`, `httpd`, `nginx`) whose PGID leader
/// serves other traffic. In that topology, containment targets `root` and its
/// own PPID descendants instead of sweeping sibling workers or the pool master.
pub(crate) fn entry_is_service_pool_worker(root: &ProcEntry, table: &[ProcEntry]) -> bool {
    if root.pid <= 1 || root.pid == root.pgrp {
        return false;
    }
    if crate::ransom::POOL_SERVICE_COMMS.contains(&root.comm.as_str()) {
        return true;
    }
    table.iter().any(|entry| {
        entry.pid == root.pgrp
            && crate::ransom::POOL_SERVICE_COMMS.contains(&entry.comm.as_str())
    })
}

/// Checks whether a live PID is a worker inside a pooled service daemon group.
pub(crate) fn is_service_pool_worker(pid: i32) -> Result<bool, BoxError> {
    if pid <= 1 {
        return Ok(false);
    }
    let table = read_process_table()?;
    let Some(root) = table.iter().find(|entry| entry.pid == pid) else {
        return Ok(false);
    };
    Ok(entry_is_service_pool_worker(root, &table))
}

/// Collects the bounded kill set for `root_pid`: PPID descendants (BFS, depth
/// capped) plus every member of the root's process group (except when `root` is
/// a worker inside a shared multi-worker service pool, so sibling workers and
/// the master daemon stay online). The visited set makes the walk cycle-safe
/// even against a synthetic `/proc` snapshot; ordering is deepest-first so
/// children are stopped before their parent. The root must remain present.
pub(crate) fn collect_tree(root_pid: i32, table: &[ProcEntry]) -> Result<Vec<ProcEntry>, BoxError> {
    let Some(root) = table.iter().find(|entry| entry.pid == root_pid) else {
        return Err("kill tree root is not present in the proc snapshot".into());
    };
    let isolate_worker_only = entry_is_service_pool_worker(root, table);
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
    // skipped when isolating a pooled service worker to avoid master/sibling DoS.
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
