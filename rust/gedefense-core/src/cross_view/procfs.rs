use super::*;

/// Socket inode column in `/proc/net/tcp*`/`udp*` (split_whitespace index).
pub(super) const PROC_NET_INET_INODE_INDEX: usize = 9;
/// Socket inode column in `/proc/net/packet`.
pub(super) const PROC_NET_PACKET_INODE_INDEX: usize = 8;
pub(super) const PROC_NET_MAX_BYTES: usize = 4 * 1024 * 1024;
pub(super) const PROC_NET_MAX_LINES: usize = 65_536;

// ------------------------------------------------------------ process/module

pub(super) const PROC_STAT_MAX: u64 = 4096;
pub(super) const PROC_EXE_MAX: usize = 512;
pub(super) const PROC_COMM_MAX: u64 = 64;
pub(super) const PROCFS_PATH: &str = "/proc";

impl CrossViewCore {
    pub(super) fn scan_pins(&mut self, now_ms: u64, outcome: &mut ScanOutcome) {
        let current = read_pin_entries(&self.pin_root);
        if current.is_empty() && !Path::new(&self.pin_root).is_dir() {
            self.pins_available = false;
            self.pins_count = 0;
            outcome.reason("pins_unavailable");
            return;
        }
        self.pins_available = true;
        self.pins_count = current.len() as u64;
        outcome.domains += 1;

        let current_set: HashSet<&str> = current.iter().map(String::as_str).collect();
        let baseline: Vec<String> = self.pin_baseline.clone();
        let baseline_set: HashSet<&str> = baseline.iter().map(String::as_str).collect();
        for name in baseline_set.difference(&current_set).take(8) {
            self.enqueue(pin_event(
                now_ms,
                name,
                CROSS_VIEW_DETAIL_PIN_MISSING,
                CROSS_VIEW_SEVERITY_HIGH,
            ));
        }
        for name in current_set.difference(&baseline_set).take(8) {
            self.enqueue(pin_event(
                now_ms,
                name,
                CROSS_VIEW_DETAIL_PIN_UNEXPECTED,
                CROSS_VIEW_SEVERITY_MEDIUM,
            ));
        }

        // Resolve a bounded subset of the live pins and prove that each still
        // names the BPF object the pin manifest recorded. This catches a pin
        // replaced with a different object, not only a removed pin. Note that
        // kernel bpf_map_info.name is NUL-terminated inside BPF_OBJ_NAME_BYTES
        // (16 bytes -> at most 15 chars), so long pin names match the 15-byte
        // kernel-truncated object name.
        for name in current.iter().take(PIN_RESOLVE_LIMIT) {
            let full = format!("{}/{}", self.pin_root.trim_end_matches('/'), name);
            match resolve_pinned_object(&full) {
                Ok(Some(object_name)) => {
                    if !pin_matches_kernel_object_name(name, &object_name) {
                        self.enqueue(pin_event(
                            now_ms,
                            name,
                            CROSS_VIEW_DETAIL_PIN_REPLACED,
                            CROSS_VIEW_SEVERITY_HIGH,
                        ));
                    }
                }
                Ok(None) => {}
                Err(()) => {
                    // One short confirmation: the self-defence restorer can be
                    // between unlink and re-pin for a moment.
                    std::thread::sleep(Duration::from_millis(2));
                    match resolve_pinned_object(&full) {
                        Ok(Some(object_name)) => {
                            if !pin_matches_kernel_object_name(name, &object_name) {
                                self.enqueue(pin_event(
                                    now_ms,
                                    name,
                                    CROSS_VIEW_DETAIL_PIN_REPLACED,
                                    CROSS_VIEW_SEVERITY_HIGH,
                                ));
                            }
                        }
                        Ok(None) => {}
                        Err(()) => self.enqueue(pin_event(
                            now_ms,
                            name,
                            CROSS_VIEW_DETAIL_PIN_DANGLING,
                            CROSS_VIEW_SEVERITY_HIGH,
                        )),
                    }
                }
            }
        }
    }
}

pub(super) fn pin_matches_kernel_object_name(pin_name: &str, kernel_object_name: &str) -> bool {
    let cap = BPF_OBJ_NAME_BYTES.saturating_sub(1);
    let expected = if pin_name.len() > cap {
        &pin_name[..cap]
    } else {
        pin_name
    };
    kernel_object_name == expected
}

pub(super) fn pin_event(now_ms: u64, name: &str, detail: u32, severity: u8) -> CrossViewEvent {
    CrossViewEvent {
        ts_ns: now_ms.saturating_mul(1_000_000),
        ino: fnv64(name.as_bytes()),
        pid: 0,
        uid: 0,
        dev: 0,
        detail_code: detail,
        domain: CROSS_VIEW_DOMAIN_PIN_VIEW,
        kind: CROSS_VIEW_KIND_PIN_MISMATCH,
        severity,
        action: CROSS_VIEW_ACTION_AUDIT,
        comm: bounded_comm(name),
        reserved: [0u8; 12],
    }
}

// ===========================================================================
// Domain 3 — process cross-view
// ===========================================================================

pub(super) fn hidden_process_event(
    now_ms: u64,
    pid: u32,
    uid: u32,
    detail: u32,
    severity: u8,
) -> CrossViewEvent {
    CrossViewEvent {
        ts_ns: now_ms.saturating_mul(1_000_000),
        ino: u64::from(pid),
        pid,
        uid,
        dev: 0,
        detail_code: detail,
        domain: CROSS_VIEW_DOMAIN_PROCESS_VIEW,
        kind: CROSS_VIEW_KIND_HIDDEN_PROCESS,
        severity,
        action: CROSS_VIEW_ACTION_AUDIT,
        comm: bounded_comm("proc"),
        reserved: [0u8; 12],
    }
}

// ===========================================================================
// Domain 1 + 8 — eBPF id gap and map-name cross-view
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProcNetError {
    Missing,
    Unreadable,
}

/// Parses one `/proc/net/*` socket table strictly. The header is skipped; any
/// data line that is too short or whose inode column is not a decimal number
/// rejects the whole file instead of silently under-reporting the view.
pub(super) fn read_proc_net_inodes(
    path: &str,
    inode_index: usize,
) -> Result<HashSet<u32>, ProcNetError> {
    let text = match read_bounded_string(path, PROC_NET_MAX_BYTES as u64) {
        Ok((text, _)) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ProcNetError::Missing)
        }
        Err(_) => return Err(ProcNetError::Unreadable),
    };
    parse_proc_net_inodes(&text, inode_index)
}

/// Strict text parser behind [`read_proc_net_inodes`]; separate so the wire
/// format is unit-testable without a live `/proc`.
pub(super) fn parse_proc_net_inodes(
    text: &str,
    inode_index: usize,
) -> Result<HashSet<u32>, ProcNetError> {
    let mut inodes: HashSet<u32> = HashSet::new();
    let mut lines = 0usize;
    for line in text.lines() {
        lines += 1;
        if lines > PROC_NET_MAX_LINES {
            return Err(ProcNetError::Unreadable);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("sl") || trimmed.starts_with("sk") {
            continue;
        }
        let Some(token) = trimmed.split_whitespace().nth(inode_index) else {
            return Err(ProcNetError::Unreadable);
        };
        let Ok(inode) = token.parse::<u32>() else {
            return Err(ProcNetError::Unreadable);
        };
        if inode != 0 {
            inodes.insert(inode);
        }
    }
    Ok(inodes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StatRead {
    Gone,
    Refused,
}

pub(super) fn read_proc_stat(pid: u32) -> Result<String, StatRead> {
    match read_bounded_string(&format!("{PROCFS_PATH}/{pid}/stat"), PROC_STAT_MAX) {
        Ok((text, _)) if !text.is_empty() => Ok(text),
        Ok(_) => Err(StatRead::Gone),
        Err(error) => {
            if error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(3) {
                Err(StatRead::Gone)
            } else {
                Err(StatRead::Refused)
            }
        }
    }
}

pub(super) fn parse_proc_status_tgid(status: &str) -> Option<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse::<u32>().ok().filter(|tgid| *tgid != 0);
        }
    }
    None
}

/// Resolves the owning thread-group id (`TGID`) for one `/proc/<tid>/status`
/// entry so a normal sub-thread omitted from `readdir("/proc")` is recognised
/// when its parent process is visible.
pub(super) fn read_proc_tgid(pid: u32) -> Option<u32> {
    let (text, _) =
        read_bounded_string(&format!("{PROCFS_PATH}/{pid}/status"), PROC_STAT_MAX).ok()?;
    parse_proc_status_tgid(&text)
}

/// One bounded `/proc` pid listing (positive numeric entries only).
pub(super) fn read_proc_pids() -> Result<Vec<u32>, std::io::Error> {
    let entries = fs::read_dir(PROCFS_PATH)?;
    let mut pids: Vec<u32> = Vec::with_capacity(512);
    for entry in entries.flatten() {
        if pids.len() >= CROSS_VIEW_MAX_PIDS {
            break;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Ok(pid) = name.parse::<u32>() {
            if pid != 0 {
                pids.push(pid);
            }
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

pub(super) fn read_proc_exe(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let target = fs::read_link(format!("{PROCFS_PATH}/{pid}/exe")).ok()?;
    let text = target.to_string_lossy();
    if text.len() > PROC_EXE_MAX || !text.starts_with('/') {
        return None;
    }
    Some(text.into_owned())
}

pub(super) fn read_proc_comm(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let (text, _) =
        read_bounded_string(&format!("{PROCFS_PATH}/{pid}/comm"), PROC_COMM_MAX).ok()?;
    let comm = text.trim_end_matches(['\n', '\r']).trim();
    if comm.is_empty() || comm.len() > 16 {
        return None;
    }
    if !comm.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return None;
    }
    Some(comm.to_owned())
}

pub(super) fn proc_uid(pid: u32) -> Option<u32> {
    fs::metadata(format!("{PROCFS_PATH}/{pid}"))
        .ok()
        .map(|metadata| metadata.uid())
}

pub(super) fn read_pin_entries(root: &str) -> Vec<String> {
    let mut names = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return names;
    };
    for entry in entries.flatten().take(CROSS_VIEW_MAX_PINS) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.is_empty() || name.len() > 128 || name.contains('/') {
            continue;
        }
        if entry
            .file_type()
            .map(|kind| kind.is_file())
            .unwrap_or(false)
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    names
}

/// Resolves the self-defence pin root from our own command line
/// (`/proc/self/cmdline`, no exec/shell) so a `--bpf-pin-root` override is
/// honoured without touching `main.rs`; falls back to the documented default.
pub(super) fn resolve_pin_root() -> String {
    if let Ok((cmdline, _)) = read_bounded_string("/proc/self/cmdline", PIN_MAX_BYTES) {
        if let Some(root) = parse_pin_root_arg(&cmdline) {
            return root;
        }
    }
    DEFAULT_BPF_PIN_ROOT.to_owned()
}

pub(super) fn parse_pin_root_arg(cmdline: &str) -> Option<String> {
    let mut arguments = cmdline.split('\0');
    while let Some(argument) = arguments.next() {
        if argument == "--bpf-pin-root" {
            let value = arguments.next()?;
            return validate_pin_root(value);
        }
        if let Some(value) = argument.strip_prefix("--bpf-pin-root=") {
            return validate_pin_root(value);
        }
    }
    None
}

pub(super) fn validate_pin_root(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 128 || !value.starts_with('/') {
        return None;
    }
    if value
        .split('/')
        .any(|component| component == ".." || component == ".")
    {
        return None;
    }
    Some(value.trim_end_matches('/').to_owned())
}

/// Bounded file read: returns the text and the number of bytes read. The reader
/// is capped with `take`, so a hostile/huge file can never exhaust memory.
pub(super) fn read_bounded_string(path: &str, limit: u64) -> Result<(String, u64), std::io::Error> {
    if limit == 0 || limit > 64 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bounded read limit out of range",
        ));
    }
    let file = fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024) as usize + 1);
    let read = file.take(limit).read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok((text, read as u64))
}
