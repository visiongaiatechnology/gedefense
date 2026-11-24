use super::*;

pub(super) const MAX_TRACEFS_BYTES: u64 = 64 * 1024;

/// Parses `/sys/kernel/tracing/events/syscalls/<event>/format` (with the legacy
/// debugfs path as fallback) and returns `(pid_offset, target_pid_offset,
/// record_size)`. Any unreadable/malformed format degrades the corresponding
/// tracepoint to a pid/comm-only record instead of guessing offsets.
pub(super) fn resolve_tracepoint_offsets(event: &str) -> Option<(u32, u32, u32)> {
    let candidates = [
        format!("/sys/kernel/tracing/events/syscalls/{event}/format"),
        format!("/sys/kernel/debug/tracing/events/syscalls/{event}/format"),
    ];
    for candidate in candidates {
        let Ok(data) = read_bounded_file(Path::new(&candidate), MAX_TRACEFS_BYTES) else {
            continue;
        };
        let text = String::from_utf8_lossy(&data);
        if let Some(offsets) = parse_tracepoint_format(&text) {
            return Some(offsets);
        }
    }
    None
}

/// Pure tracefs `format` parser (unit-testable).
pub(super) fn parse_tracepoint_format(text: &str) -> Option<(u32, u32, u32)> {
    let mut pid_offset: Option<u32> = None;
    let mut target_offset: Option<u32> = None;
    let mut record_size: u32 = 0;
    for line in text.lines().take(256) {
        let Some(rest) = line.trim().strip_prefix("field:") else {
            continue;
        };
        let mut parts = rest.split(';');
        let declaration = parts.next()?;
        let name = declaration.split_whitespace().last()?;
        let mut offset: Option<u32> = None;
        let mut size: Option<u32> = None;
        for part in parts {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("offset:") {
                offset = value.trim().parse().ok();
            } else if let Some(value) = part.strip_prefix("size:") {
                size = value.trim().parse().ok();
            }
        }
        let (Some(offset), Some(size)) = (offset, size) else {
            return None;
        };
        if size == 0 || size > 64 || offset > PERSIST_MAX_TRACEPOINT_BYTES {
            return None;
        }
        record_size = record_size.max(offset.saturating_add(size));
        if name == "pid" {
            pid_offset = Some(offset);
        } else if name == "target_pid" {
            target_offset = Some(offset);
        }
    }
    let pid_offset = pid_offset?;
    let target_offset = target_offset?;
    if record_size < 16
        || record_size > PERSIST_MAX_TRACEPOINT_BYTES
        || pid_offset < 8
        || target_offset < 8
        || pid_offset == target_offset
        || pid_offset.saturating_add(4) > record_size
        || target_offset.saturating_add(4) > record_size
    {
        return None;
    }
    Some((pid_offset, target_offset, record_size))
}

/// Reads the vmlinux BTF and the two process_vm tracepoint formats and returns
/// the best-effort offset set. A BTF file that cannot be read/parsed is an
/// `Err` (the whole identity ladder is blind); individual missing fields stay
/// unresolved so the unaffected sensors keep working.
pub(super) fn resolve_persistence_offsets() -> Result<ResolvedOffsets, String> {
    let btf_path = Path::new(crate::btf_offsets::VMLINUX_BTF_PATH);
    let data = read_bounded_file(btf_path, crate::btf_offsets::MAX_VMLINUX_BTF_BYTES as u64)?;
    let facts = parse_persistence_btf(&data)?;
    let mut resolved = ResolvedOffsets::default();
    resolved.file_f_inode = btf_member(&facts, "file", "f_inode", 8, 8);
    resolved.file_f_flags = btf_member(&facts, "file", "f_flags", 4, 4);
    resolved.file_file_size = facts
        .structs
        .iter()
        .find(|(name, _)| **name == "file")
        .map(|(_, facts)| facts.size)
        .filter(|size| *size > 0 && *size <= PERSIST_MAX_STRUCT_SIZE)
        .unwrap_or(u32::MAX);
    resolved.file_f_dentry = resolve_nested_member(&facts, "file", "f_path", "path", "dentry");
    resolved.inode_i_ino = btf_member(&facts, "inode", "i_ino", 8, 8);
    resolved.inode_i_sb = btf_member(&facts, "inode", "i_sb", 8, 8);
    resolved.inode_i_mode = btf_member(&facts, "inode", "i_mode", 2, 2);
    resolved.inode_size = facts
        .structs
        .iter()
        .find(|(name, _)| **name == "inode")
        .map(|(_, facts)| facts.size)
        .filter(|size| *size > 0 && *size <= PERSIST_MAX_STRUCT_SIZE)
        .unwrap_or(u32::MAX);
    resolved.super_s_dev = btf_member(&facts, "super_block", "s_dev", 4, 4);
    resolved.super_size = facts
        .structs
        .iter()
        .find(|(name, _)| **name == "super_block")
        .map(|(_, facts)| facts.size)
        .filter(|size| *size > 0 && *size <= PERSIST_MAX_STRUCT_SIZE)
        .unwrap_or(u32::MAX);
    resolved.dentry_parent = btf_member(&facts, "dentry", "d_parent", 8, 8);
    resolved.dentry_inode = btf_member(&facts, "dentry", "d_inode", 8, 8);
    resolved.dentry_size = facts
        .structs
        .iter()
        .find(|(name, _)| **name == "dentry")
        .map(|(_, facts)| facts.size)
        .filter(|size| *size > 0 && *size <= PERSIST_MAX_STRUCT_SIZE)
        .unwrap_or(u32::MAX);
    resolved.task_pid = btf_member(&facts, "task_struct", "pid", 4, 4);
    resolved.task_tgid = btf_member(&facts, "task_struct", "tgid", 4, 4);
    resolved.task_mm = btf_member(&facts, "task_struct", "mm", 8, 8);
    resolved.task_size = facts
        .structs
        .iter()
        .find(|(name, _)| **name == "task_struct")
        .map(|(_, facts)| facts.size)
        .filter(|size| *size > 0 && *size <= PERSIST_MAX_STRUCT_SIZE)
        .unwrap_or(u32::MAX);
    resolved.mm_exe_file = btf_member(&facts, "mm_struct", "exe_file", 8, 8);
    resolved.mm_size = facts
        .structs
        .iter()
        .find(|(name, _)| **name == "mm_struct")
        .map(|(_, facts)| facts.size)
        .filter(|size| *size > 0 && *size <= PERSIST_MAX_STRUCT_SIZE)
        .unwrap_or(u32::MAX);
    resolved.file_open_nargs = facts
        .func_nargs
        .get("bpf_lsm_file_open")
        .copied()
        .unwrap_or(0);
    resolved.mmap_nargs = facts
        .func_nargs
        .get("bpf_lsm_mmap_file")
        .copied()
        .unwrap_or(0);
    resolved.ptrace_nargs = facts
        .func_nargs
        .get("bpf_lsm_ptrace_access_check")
        .copied()
        .unwrap_or(0);
    if let Some((pid, target, size)) = resolve_tracepoint_offsets(TRACEPOINT_READV) {
        resolved.readv_pid = pid;
        resolved.readv_target = target;
        resolved.readv_size = size;
        resolved.readv_ready = true;
    }
    if let Some((pid, target, size)) = resolve_tracepoint_offsets(TRACEPOINT_WRITEV) {
        resolved.writev_pid = pid;
        resolved.writev_target = target;
        resolved.writev_size = size;
        resolved.writev_ready = true;
    }
    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Package-database ownership index (parsed from files only, never executed)
// ---------------------------------------------------------------------------
