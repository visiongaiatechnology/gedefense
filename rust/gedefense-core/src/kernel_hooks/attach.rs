use super::*;

impl KernelHooksCore {
    /// Each io_uring tracepoint is attached independently: a kernel that lacks
    /// one event must not disable the others.
    pub(super) fn attach_io_uring_tracepoints(&mut self, ebpf: &mut Ebpf) {
        for (program_name, category, event) in IO_URING_TRACEPOINTS {
            let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(program_name)) else {
                eprintln!("kernel hooks program {program_name} missing; not attached");
                continue;
            };
            let result = (|| -> Result<(), BoxError> {
                let tracepoint: &mut TracePoint = program.try_into()?;
                tracepoint.load()?;
                tracepoint.attach(category, event)?;
                Ok(())
            })();
            match result {
                Ok(()) => {
                    self.io_uring_attached = true;
                    eprintln!("kernel hooks tracepoint {category}:{event} attached");
                }
                Err(error) => eprintln!(
                    "kernel hooks tracepoint {category}:{event} unavailable ({error}); io_uring bit stays degraded"
                ),
            }
        }
    }
}

impl KernelHooksCore {
    pub(super) fn attach_module_tracepoint(&mut self, ebpf: &mut Ebpf) {
        let (program_name, category, event) = MODULE_TRACEPOINT;
        let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(program_name)) else {
            eprintln!(
                "kernel hooks program {program_name} missing; module tracepoint not attached"
            );
            return;
        };
        let result = (|| -> Result<(), BoxError> {
            let tracepoint: &mut TracePoint = program.try_into()?;
            tracepoint.load()?;
            tracepoint.attach(category, event)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.module_trace_attached = true;
                eprintln!("kernel hooks tracepoint {category}:{event} attached");
            }
            Err(error) => eprintln!(
                "kernel hooks tracepoint {category}:{event} unavailable ({error}); module_trace=0"
            ),
        }
    }
}

impl KernelHooksCore {
    /// The kprobes are only attempted for symbols the running kernel really
    /// exports. `/proc/kallsyms` is the same source the kprobe PMU resolves, so
    /// an absent symbol is never guessed.
    pub(super) fn attach_module_kprobes(&mut self, ebpf: &mut Ebpf) {
        let Some(symbols) = read_kallsyms_candidates() else {
            eprintln!(
                "kernel hooks module kprobes not attached: {KALLSYMS_PATH} unreadable; kprobes=0"
            );
            return;
        };
        for probe in MODULE_KPROBES {
            let candidates = probe_symbol_candidates(&symbols, probe.base);
            if candidates.is_empty() {
                eprintln!(
                    "kernel hooks kprobe {} not attached: symbol absent from {KALLSYMS_PATH}",
                    probe.base
                );
                continue;
            }
            let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(probe.program)) else {
                eprintln!(
                    "kernel hooks program {} missing; kprobe not attached",
                    probe.program
                );
                continue;
            };
            let result = (|| -> Result<String, BoxError> {
                let kprobe: &mut KProbe = program.try_into()?;
                kprobe.load()?;
                for symbol in &candidates {
                    match kprobe.attach(symbol.as_str(), 0) {
                        Ok(_) => return Ok(symbol.clone()),
                        Err(error) => eprintln!(
                            "kernel hooks kprobe {} attach to {symbol} failed ({error}); trying next candidate",
                            probe.base
                        ),
                    }
                }
                Err(format!(
                    "all {} candidate symbol(s) failed to attach",
                    candidates.len()
                )
                .into())
            })();
            match result {
                Ok(symbol) => {
                    self.kprobes_attached = self.kprobes_attached.saturating_add(1);
                    if probe.direct_args_flag != 0 && direct_arguments_symbol(&symbol, probe.base) {
                        self.flags |= probe.direct_args_flag;
                    }
                    eprintln!(
                        "kernel hooks kprobe {} attached to {symbol} (direct_args={})",
                        probe.base,
                        u8::from(
                            probe.direct_args_flag != 0 && self.flags & probe.direct_args_flag != 0
                        )
                    );
                }
                Err(error) => eprintln!(
                    "kernel hooks kprobe {} unavailable ({error}); kprobe bit stays 0",
                    probe.base
                ),
            }
        }
    }
}

impl KernelHooksCore {
    /// BTF-optional LSM hooks: only attempted with active BPF-LSM and LSM BTF.
    /// The programs themselves always defer to the previous LSM verdict.
    pub(super) fn attach_lsm_hooks(
        &mut self,
        ebpf: &mut Ebpf,
        btf: Option<&Btf>,
        bpf_lsm_active: bool,
    ) {
        if !bpf_lsm_active {
            eprintln!(
                "kernel hooks LSM hooks inactive: BPF-LSM is not active (no attach, no visibility claim)"
            );
            return;
        }
        let Some(btf) = btf else {
            eprintln!("kernel hooks LSM hooks inactive: BPF-LSM BTF unavailable");
            return;
        };
        for (program_name, hook_name) in LSM_HOOKS {
            let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(program_name)) else {
                eprintln!("kernel hooks program {program_name} missing; LSM hook not attached");
                continue;
            };
            let result = (|| -> Result<(), BoxError> {
                let lsm: &mut Lsm = program.try_into()?;
                lsm.load(hook_name, btf)?;
                lsm.attach()?;
                Ok(())
            })();
            match result {
                Ok(()) => {
                    self.lsm_attached = self.lsm_attached.saturating_add(1);
                    eprintln!("kernel hooks LSM hook {hook_name} attached");
                }
                Err(error) => eprintln!(
                    "kernel hooks LSM hook {hook_name} unavailable ({error}); lsm_extra bit stays degraded"
                ),
            }
        }
    }
}

impl KernelHooksCore {
    /// Publishes every derived tracepoint payload offset into the eBPF map.
    pub(super) fn publish_layout(&mut self, layout: &KernelHookLayout) -> Result<(), BoxError> {
        let mut slot = 0u32;
        while slot < KERNEL_HOOK_OFFSET_SLOTS {
            let Some(value) = layout.slots.get(slot as usize).copied() else {
                break;
            };
            self.offsets.set(slot, value, 0)?;
            slot += 1;
        }
        if layout.known_fields() == 0 {
            eprintln!(
                "kernel hooks: no tracepoint format was readable; events carry pid/comm/timestamp only (honest degraded detail)"
            );
        } else {
            eprintln!(
                "kernel hooks: published {} tracepoint field offset(s)",
                layout.known_fields()
            );
        }
        Ok(())
    }
}

impl KernelHooksCore {
    pub(super) fn set_armed(&mut self, armed: bool) -> Result<String, BoxError> {
        let word = kernel_hook_state_word(self.epoch as u32, armed, self.flags);
        self.state.set(KERNEL_HOOK_STATE_INDEX, word, 0)?;
        self.enabled = armed;
        Ok(if armed { "armed" } else { "disarmed" }.to_owned())
    }
}

impl KernelHooksCore {
    /// `KERNEL_HOOK_SET <0|1>` -> `armed` / `disarmed`.
    pub(crate) fn set_enabled_token(&mut self, token: &str) -> Result<String, BoxError> {
        match token {
            "0" => self.set_armed(false),
            "1" => self.set_armed(true),
            _ => Err("KERNEL_HOOK_SET accepts 0 or 1".into()),
        }
    }
}

/// Reads the `/proc/kallsyms` entries that can possibly belong to one of the
/// three module-syscall probes. The pre-filter keeps memory bounded (a full
/// kallsyms image carries >1M symbols): only names containing a probe base name
/// are collected. Returns `None` when the file cannot be read at all (hardened
/// host): the kprobe ladder is then reported as `kprobes=0` instead of guessing.
pub(super) fn read_kallsyms_candidates() -> Option<Vec<String>> {
    const PROBE_BASES: [&str; 3] = ["init_module", "finit_module", "delete_module"];
    let file = match fs::File::open(KALLSYMS_PATH) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("kernel hooks: open {KALLSYMS_PATH} failed ({error})");
            return None;
        }
    };
    let reader = std::io::BufReader::new(file.take(MAX_KALLSYMS_BYTES));
    let mut symbols = Vec::new();
    for line in reader.lines().take(MAX_KALLSYMS_LINES) {
        let Ok(line) = line else { break };
        let Some(name) = line.split_whitespace().nth(2) else {
            continue;
        };
        if PROBE_BASES.iter().any(|base| name.contains(base)) {
            symbols.push(name.to_owned());
        }
    }
    Some(symbols)
}

/// True when the attached symbol receives the real syscall arguments (so its
/// first argument may be reported), false for a `pt_regs *` syscall wrapper.
pub(super) fn direct_arguments_symbol(symbol: &str, base: &str) -> bool {
    let core = strip_clone_suffix(symbol);
    core == base
        || core == format!("__do_sys_{base}")
        || core == format!("__se_sys_{base}")
        || core == format!("__do_compat_sys_{base}")
}

/// `__x64_sys_init_module`, `__arm64_sys_finit_module`, …: the architecture
/// syscall wrapper whose single argument is `struct pt_regs *`.
pub(super) fn syscall_wrapper_symbol(symbol: &str, base: &str) -> bool {
    symbol.starts_with("__") && symbol.ends_with(&format!("_sys_{base}"))
}

/// Strips a compiler clone suffix (`init_module.isra.0`, `.constprop.1`).
pub(super) fn strip_clone_suffix(symbol: &str) -> &str {
    match symbol.find('.') {
        Some(index) => &symbol[..index],
        None => symbol,
    }
}

/// Ordered kprobe symbol candidates: direct-argument symbols first (richest
/// payload), then syscall wrappers, then compiler clones of either.
pub(super) fn probe_symbol_candidates(symbols: &[String], base: &str) -> Vec<String> {
    let mut direct: Vec<String> = Vec::new();
    let mut wrappers: Vec<String> = Vec::new();
    let mut clones: Vec<String> = Vec::new();
    for symbol in symbols {
        let core = strip_clone_suffix(symbol);
        let is_clone = core.len() != symbol.len();
        if direct_arguments_symbol(core, base) {
            if is_clone {
                clones.push(symbol.clone());
            } else if direct.is_empty() {
                direct.push(symbol.clone());
            }
        } else if syscall_wrapper_symbol(core, base) {
            if is_clone {
                clones.push(symbol.clone());
            } else {
                wrappers.push(symbol.clone());
            }
        }
    }
    direct.extend(wrappers);
    direct.extend(clones);
    direct.truncate(MAX_KPROBE_SYMBOL_CANDIDATES);
    direct
}
