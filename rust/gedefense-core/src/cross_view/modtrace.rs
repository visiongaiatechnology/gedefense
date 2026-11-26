use super::*;

pub(super) const PROC_MODULES_PATH: &str = "/proc/modules";
pub(super) const PROC_TAINTS_PATH: &str = "/proc/sys/kernel/tainted";
pub(super) const SYS_MODULE_PATH: &str = "/sys/module";
pub(super) const MODULE_LIST_MAX_BYTES: u64 = 2 * 1024 * 1024;
pub(super) const MODULE_LIST_MAX_ENTRIES: usize = 4096;
/// Kernel taint bits: bit 12 O (out-of-tree), bit 13 E (unsigned/forced),
/// bit 14 L (soft lockup). Forced-load is bit 1 (F) and is folded into the
/// "forced" evidence via `TAINT_FORCED_MODULE`.
pub(super) const TAINT_OOT_MODULE: u32 = 1 << 12;
pub(super) const TAINT_UNSIGNED_MODULE: u32 = 1 << 13;
pub(super) const TAINT_FORCED_MODULE: u32 = 1 << 1;
pub(super) const TAINT_FORCED_MASK: u32 =
    TAINT_OOT_MODULE | TAINT_UNSIGNED_MODULE | TAINT_FORCED_MODULE;

// ----------------------------------------------------------------- ftrace

pub(super) const FTRACE_ENABLED_PATHS: [&str; 2] = [
    "/sys/kernel/tracing/enabled_functions",
    "/sys/kernel/debug/tracing/enabled_functions",
];
pub(super) const FTRACE_MAX_BYTES: u64 = 1024 * 1024;
/// Kernel functions rootkits hook with ftrace to hide processes/sockets/BPF
/// objects. A hit is an observation, not an enforcement decision.
pub(super) const FTRACE_SENSITIVE_TARGETS: [&str; 24] = [
    "__x64_sys_getdents64",
    "__x64_sys_getdents",
    "__x64_sys_newfstatat",
    "__x64_sys_stat",
    "__x64_sys_lstat",
    "__x64_sys_kill",
    "__x64_sys_read",
    "__x64_sys_write",
    "__x64_sys_openat",
    "proc_pid_readdir",
    "proc_root_readdir",
    "filldir64",
    "tcp4_seq_show",
    "tcp6_seq_show",
    "udp4_seq_show",
    "udp6_seq_show",
    "raw_seq_show",
    "packet_seq_show",
    "netlink_seq_show",
    "inet_diag_dump_icsk",
    "bpf_prog_get_info_by_fd",
    "bpf_prog_get_next_id",
    "sk_attach_filter",
    "bpf_lsm_bpf_prog",
];

// ----------------------------------------------------------------- library

// ===========================================================================
// Domain 4 — module / ftrace cross-view
// ===========================================================================

impl CrossViewCore {
    pub(super) fn scan_module_trace(
        &mut self,
        now_ms: u64,
        deadline: Instant,
        outcome: &mut ScanOutcome,
    ) {
        let proc_modules = match read_proc_modules() {
            Ok(modules) => modules,
            Err(error) => {
                eprintln!("cross-view module view: {PROC_MODULES_PATH} unavailable ({error})");
                outcome.degrade("modules_unreadable");
                self.module_available = false;
                return;
            }
        };
        let sys_modules = match read_sys_modules() {
            Ok(modules) => modules,
            Err(error) => {
                eprintln!("cross-view module view: {SYS_MODULE_PATH} unavailable ({error})");
                outcome.degrade("sysfs_modules_unreadable");
                self.module_available = false;
                return;
            }
        };
        self.module_available = true;
        outcome.domains += 1;
        let taint = read_tainted().unwrap_or(0);
        let tainted = taint & TAINT_FORCED_MASK != 0;

        // One confirmation re-read: a module is legitimately in transit for a
        // few microseconds during load/unload; only a persistent mismatch is
        // evidence.
        let mut proc_only: Vec<String> = proc_modules.difference(&sys_modules).cloned().collect();
        let mut sys_only: Vec<String> = sys_modules.difference(&proc_modules).cloned().collect();
        if !proc_only.is_empty() || !sys_only.is_empty() {
            if let (Ok(proc_again), Ok(sys_again)) = (read_proc_modules(), read_sys_modules()) {
                proc_only.retain(|name| proc_again.contains(name) && !sys_again.contains(name));
                sys_only.retain(|name| sys_again.contains(name) && !proc_again.contains(name));
            }
        }
        proc_only.sort();
        sys_only.sort();
        let sev = if tainted {
            CROSS_VIEW_SEVERITY_HIGH
        } else {
            CROSS_VIEW_SEVERITY_MEDIUM
        };
        for name in proc_only.iter().take(8) {
            self.enqueue(module_event(
                now_ms,
                name,
                CROSS_VIEW_DETAIL_PROC_ONLY,
                sev,
                taint,
            ));
        }
        for name in sys_only.iter().take(8) {
            self.enqueue(module_event(
                now_ms,
                name,
                CROSS_VIEW_DETAIL_SYSFS_ONLY,
                sev,
                taint,
            ));
        }
        if !proc_only.is_empty() || !sys_only.is_empty() {
            outcome.reason(if tainted {
                "module_view_mismatch_tainted"
            } else {
                "module_view_mismatch"
            });
        }

        // ftrace: a readable enabled_functions table is a privilege; absence is
        // reported as an unsupported capability, never guessed.
        if Instant::now() < deadline {
            match read_ftrace_enabled() {
                Ok(Some(table)) => {
                    self.trace_available = true;
                    let mut hits = 0usize;
                    for line in table.lines().take(65_536) {
                        if hits >= 8 {
                            break;
                        }
                        let Some(function) = ftrace_line_function(line) else {
                            continue;
                        };
                        // Our own `sk_attach_filter` kprobe and `bpf_guard`'s `bpf_prog`
                        // LSM hook show up in enabled_functions via ftrace trampolines;
                        // those are self-induced evidence, never rootkit hooks.
                        if (self.kprobe_attached && function == SK_ATTACH_FILTER_SYMBOL)
                            || (self.bpf_guard_lsm_attached && function == BPF_LSM_BPF_PROG_SYMBOL)
                        {
                            continue;
                        }
                        if let Some(index) = FTRACE_SENSITIVE_TARGETS
                            .iter()
                            .position(|target| *target == function)
                        {
                            hits += 1;
                            self.enqueue(ftrace_event(now_ms, function, index + 1));
                        }
                    }
                }
                Ok(None) => {
                    self.trace_available = false;
                    outcome.reason("ftrace_unavailable");
                }
                Err(error) => {
                    self.trace_available = false;
                    eprintln!("cross-view ftrace view unavailable ({error})");
                    outcome.reason("ftrace_unavailable");
                }
            }
        }
    }
}

pub(super) fn module_event(
    now_ms: u64,
    name: &str,
    detail: u32,
    severity: u8,
    taint: u32,
) -> CrossViewEvent {
    CrossViewEvent {
        ts_ns: now_ms.saturating_mul(1_000_000),
        ino: fnv64(name.as_bytes()),
        pid: 0,
        uid: 0,
        // For module records `dev` carries the raw kernel taint word so the
        // control plane can show O/E/forced bits without a second command.
        dev: taint,
        detail_code: detail,
        domain: CROSS_VIEW_DOMAIN_MODULE_TRACE_VIEW,
        kind: CROSS_VIEW_KIND_LKM_HIDDEN,
        severity,
        action: CROSS_VIEW_ACTION_AUDIT,
        comm: bounded_comm(name),
        reserved: [0u8; 12],
    }
}

pub(super) fn ftrace_event(now_ms: u64, function: &str, index: usize) -> CrossViewEvent {
    CrossViewEvent {
        ts_ns: now_ms.saturating_mul(1_000_000),
        ino: fnv64(function.as_bytes()),
        pid: 0,
        uid: 0,
        dev: 0,
        detail_code: index as u32,
        domain: CROSS_VIEW_DOMAIN_MODULE_TRACE_VIEW,
        kind: CROSS_VIEW_KIND_FTRACE_HOOK,
        severity: CROSS_VIEW_SEVERITY_HIGH,
        action: CROSS_VIEW_ACTION_AUDIT,
        comm: bounded_comm(function),
        reserved: [0u8; 12],
    }
}

// ===========================================================================
// Domain 6 — self-defence pin cross-view
// ===========================================================================

pub(super) fn read_proc_modules() -> Result<HashSet<String>, std::io::Error> {
    let (text, _) = read_bounded_string(PROC_MODULES_PATH, MODULE_LIST_MAX_BYTES)?;
    let mut modules = HashSet::new();
    for line in text.lines().take(MODULE_LIST_MAX_ENTRIES) {
        if let Some(name) = line.split_whitespace().next() {
            if !name.is_empty() {
                modules.insert(name.to_owned());
            }
        }
    }
    Ok(modules)
}

/// `/sys/module` contains directories for built-in modules that merely carry
/// parameters, so only entries with a `coresize` attribute are loadable modules
/// (the value every loaded module exposes).
pub(super) fn read_sys_modules() -> Result<HashSet<String>, std::io::Error> {
    let entries = fs::read_dir(SYS_MODULE_PATH)?;
    let mut modules = HashSet::new();
    for entry in entries.flatten().take(MODULE_LIST_MAX_ENTRIES) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if entry.path().join("coresize").metadata().is_ok() {
            modules.insert(name.to_owned());
        }
    }
    Ok(modules)
}

pub(super) fn read_tainted() -> Option<u32> {
    let (text, _) = read_bounded_string(PROC_TAINTS_PATH, 64).ok()?;
    text.trim().parse::<u32>().ok()
}

/// Reads the ftrace `enabled_functions` table from the first reachable tracefs
/// mount. `Ok(None)` means "this kernel has no readable table" (capability gap),
/// `Err` only for a transient read failure.
pub(super) fn read_ftrace_enabled() -> Result<Option<String>, std::io::Error> {
    let mut last_error = None;
    for path in FTRACE_ENABLED_PATHS {
        match read_bounded_string(path, FTRACE_MAX_BYTES) {
            Ok((text, _)) => return Ok(Some(text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

/// Extracts the hooked function name from one `enabled_functions` line.
///
/// The seq output is `%ps` (symbol name, optionally `+0x…/0x…`) followed by the
/// bounded `(count) flags tramp:/ops:` trailer (`kernel/trace/ftrace.c`,
/// `t_show`); a line starting with `####` is the "all/notrace" marker.
pub(super) fn ftrace_line_function(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let token = trimmed.split_whitespace().next()?;
    let function = token.split('+').next()?;
    if function.is_empty() || function.len() > 128 {
        return None;
    }
    Some(function)
}
