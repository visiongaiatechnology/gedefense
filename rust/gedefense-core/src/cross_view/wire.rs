use super::*;

/// Writable drop roots a raw tap executable must never live in (BPFDoor class).
pub(super) const SUSPICIOUS_EXEC_ROOTS: [&str; 6] = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
    "/run/user/",
    "/var/run/user/",
];

pub(super) fn errno_to_view_error(errno: i32) -> ViewError {
    if errno == libc::EPERM || errno == libc::EACCES {
        ViewError::Denied
    } else if errno == libc::EAFNOSUPPORT
        || errno == libc::EPROTONOSUPPORT
        || errno == libc::EOPNOTSUPP
        || errno == libc::ENOSYS
    {
        ViewError::Unsupported
    } else {
        ViewError::Failed
    }
}

// ===========================================================================
// Raw NETLINK_SOCK_DIAG layer
// ===========================================================================

pub(super) fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn random_epoch() -> u64 {
    let mut bytes = [0u8; 8];
    if let Ok(mut file) = fs::File::open("/dev/urandom") {
        if file.read_exact(&mut bytes).is_ok() {
            let value = u64::from_ne_bytes(bytes);
            if value != 0 {
                return value;
            }
        }
    }
    (unix_millis().wrapping_mul(1_000_003).rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15) | 1
}

pub(super) fn fnv64(bytes: &[u8]) -> u64 {
    let mut hash = CROSS_VIEW_FNV64_OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(CROSS_VIEW_FNV64_PRIME);
    }
    hash
}

pub(super) fn bounded_comm(label: &str) -> [u8; 16] {
    let mut comm = [0u8; 16];
    let mut index = 0usize;
    for byte in label.bytes() {
        if index >= 15 || !(0x20..=0x7e).contains(&byte) {
            break;
        }
        comm[index] = byte;
        index += 1;
    }
    comm
}

pub(super) fn normalize_wire_comm(raw: [u8; 16]) -> [u8; 16] {
    let mut comm = [0u8; 16];
    let mut index = 0usize;
    while index < raw.len() {
        let byte = raw[index];
        if byte == 0 {
            break;
        }
        comm[index] = if (0x20..=0x7e).contains(&byte) {
            byte
        } else {
            b'?'
        };
        index += 1;
    }
    if index == comm.len() {
        comm[15] = 0;
    }
    comm
}

pub(super) fn suspicious_executable_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    if path.ends_with(" (deleted)") {
        return true;
    }
    SUSPICIOUS_EXEC_ROOTS
        .iter()
        .any(|root| path.starts_with(root))
}

pub(super) fn is_suspicious_object_name(name: &str) -> bool {
    if name.is_empty() || name.len() > BPF_OBJ_NAME_BYTES {
        return false;
    }
    const MARKERS: [&str; 4] = ["hidden", "hide", "masq", "rootkit"];
    MARKERS
        .iter()
        .any(|marker| ascii_contains_ci(name.as_bytes(), marker.as_bytes()))
}

pub(super) fn ascii_contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let last = haystack.len() - needle.len();
    for start in 0..=last {
        let mut matches = true;
        for (offset, wanted) in needle.iter().enumerate() {
            let Some(actual) = haystack.get(start + offset) else {
                matches = false;
                break;
            };
            if actual.to_ascii_lowercase() != *wanted {
                matches = false;
                break;
            }
        }
        if matches {
            return true;
        }
    }
    false
}

pub(super) fn encode_event_text(event: &CrossViewEvent) -> String {
    let comm_end = event
        .comm
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(event.comm.len());
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        event.ts_ns,
        event.pid,
        event.uid,
        event.dev,
        event.ino,
        event.domain,
        event.kind,
        event.severity,
        event.detail_code,
        hex::encode(&event.comm[..comm_end]),
    )
}

// ===========================================================================
// attach helpers
// ===========================================================================

pub(super) fn link_program_tamper(
    now_ms: u64,
    link_id: u32,
    visible_progs: &HashSet<u32>,
) -> Option<CrossViewEvent> {
    let fd = bpf_fd_by_id(BPF_CMD_LINK_GET_FD_BY_ID, link_id).ok()?;
    let info = bpf_object_info(fd.as_raw_fd())?;
    let prog_id = info.link_prog_id?;
    if prog_id == 0 || visible_progs.contains(&prog_id) {
        return None;
    }
    Some(CrossViewEvent {
        ts_ns: now_ms.saturating_mul(1_000_000),
        ino: u64::from(link_id),
        pid: 0,
        uid: 0,
        dev: prog_id,
        detail_code: CROSS_VIEW_DETAIL_ID_GAP,
        domain: CROSS_VIEW_DOMAIN_EBPF_ID_GAP,
        kind: CROSS_VIEW_KIND_LINK_TAMPER,
        severity: CROSS_VIEW_SEVERITY_CRITICAL,
        action: CROSS_VIEW_ACTION_AUDIT,
        comm: bounded_comm("bpf-link"),
        reserved: [0u8; 12],
    })
}
