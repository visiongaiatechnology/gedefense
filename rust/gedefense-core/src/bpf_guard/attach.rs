use super::*;

impl BpfGuardCore {
    /// BPF-LSM `bpf_prog` hook. Only attempted with active BPF-LSM and BTF; the
    /// eBPF program itself always defers to the previous hook result.
    pub(super) fn attach_lsm(&mut self, ebpf: &mut Ebpf, btf: Option<&Btf>, bpf_lsm_active: bool) {
        if !bpf_lsm_active {
            eprintln!(
                "bpf guard LSM hook inactive: BPF-LSM is not active (no attach, no visibility claim)"
            );
            return;
        }
        let Some(btf) = btf else {
            eprintln!("bpf guard LSM hook inactive: BPF-LSM BTF unavailable");
            return;
        };
        let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(BPF_GUARD_LSM_PROGRAM)) else {
            eprintln!("bpf guard program {BPF_GUARD_LSM_PROGRAM} missing; not attached");
            return;
        };
        let result = (|| -> Result<(), BoxError> {
            let lsm: &mut Lsm = program.try_into()?;
            lsm.load(BPF_GUARD_LSM_HOOK, btf)?;
            lsm.attach()?;
            Ok(())
        })();
        match result {
            Ok(()) => self.lsm_attached = true,
            Err(error) => {
                eprintln!("bpf guard LSM bpf_prog attach failed ({error}); lsm=0")
            }
        }
    }
}

impl BpfGuardCore {
    /// `syscalls/sys_enter_bpf` tracepoint. Attached independently of BPF-LSM.
    pub(super) fn attach_tracepoint(&mut self, ebpf: &mut Ebpf) {
        let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(BPF_GUARD_TP_PROGRAM)) else {
            eprintln!("bpf guard program {BPF_GUARD_TP_PROGRAM} missing; tracepoint not attached");
            return;
        };
        let result = (|| -> Result<(), BoxError> {
            let tp: &mut TracePoint = program.try_into()?;
            tp.load()?;
            tp.attach(BPF_GUARD_TP_CATEGORY, BPF_GUARD_TP_NAME)?;
            Ok(())
        })();
        match result {
            Ok(()) => self.tp_attached = true,
            Err(error) => eprintln!(
                "bpf guard tracepoint {BPF_GUARD_TP_CATEGORY}:{BPF_GUARD_TP_NAME} unavailable ({error}); tp=0"
            ),
        }
    }
}

impl BpfGuardCore {
    /// Verifier kprobe. The symbol is gated through `/proc/kallsyms` (which is
    /// what the kprobe PMU resolves) with the vmlinux BTF FUNC table as a
    /// fallback when kallsyms is unreadable. Compiler clones such as
    /// `check_helper_call.isra.0` are tried after the plain symbol because
    /// modern kernel builds rename the static function.
    pub(super) fn attach_helper_kprobe(&mut self, ebpf: &mut Ebpf) {
        let candidates = probe_symbol_candidates();
        if candidates.is_empty() {
            eprintln!(
                "bpf guard helper kprobe not attached: symbol {BPF_GUARD_HELPER_SYMBOL} absent from kallsyms and vmlinux BTF; helper-risk bitmap unavailable (kprobe=0)"
            );
            return;
        }
        let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(BPF_GUARD_HELPER_PROGRAM)) else {
            eprintln!("bpf guard program {BPF_GUARD_HELPER_PROGRAM} missing; kprobe not attached");
            return;
        };
        let result = (|| -> Result<String, BoxError> {
            let kprobe: &mut KProbe = program.try_into()?;
            kprobe.load()?;
            for symbol in &candidates {
                match kprobe.attach(symbol.as_str(), 0) {
                    Ok(_) => return Ok(symbol.clone()),
                    Err(error) => eprintln!(
                        "bpf guard helper kprobe attach to {symbol} failed ({error}); trying next candidate"
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
                self.kprobe_attached = true;
                eprintln!("bpf guard helper kprobe attached to {symbol}");
            }
            Err(error) => eprintln!("bpf guard helper kprobe unavailable ({error}); kprobe=0"),
        }
    }
}

impl BpfGuardCore {
    pub(super) fn set_armed(&mut self, armed: bool) -> Result<String, BoxError> {
        let word = encode_state_word(self.epoch, armed);
        self.state.set(BPF_GUARD_STATE_INDEX, word, 0)?;
        self.enabled = armed;
        if !armed {
            // A disarmed guard must not keep stale per-loader attribution: drop
            // the (bounded) helper tracking so a re-arm starts clean.
            self.clear_helper_tracking();
        }
        Ok(if armed { "armed" } else { "disarmed" }.to_owned())
    }
}

impl BpfGuardCore {
    pub(super) fn clear_helper_tracking(&mut self) {
        let keys: Vec<u32> = self
            .helper_bitmap
            .keys()
            .filter_map(Result::ok)
            .take(BPF_GUARD_HELPER_BITMAP_ENTRIES as usize)
            .collect();
        for key in keys {
            let _ = self.helper_bitmap.remove(&key);
        }
        let keys: Vec<u32> = self
            .helper_ids
            .keys()
            .filter_map(Result::ok)
            .take(BPF_GUARD_HELPER_IDS_ENTRIES as usize)
            .collect();
        for key in keys {
            let _ = self.helper_ids.remove(&key);
        }
    }
}

/// Candidate kprobe symbols for the verifier helper check: the exact upstream
/// name first, then compiler-generated clones (`.isra.N`, `.constprop.N`, …).
pub(super) fn probe_symbol_candidates() -> Vec<String> {
    let mut exact: Vec<String> = Vec::new();
    let mut clones: Vec<String> = Vec::new();
    if let Ok(file) = fs::File::open(KALLSYMS_PATH) {
        let reader = std::io::BufReader::new(file.take(MAX_KALLSYMS_BYTES));
        for line in reader.lines().take(MAX_KALLSYMS_LINES) {
            let Ok(line) = line else { break };
            let Some(name) = line.split_whitespace().nth(2) else {
                continue;
            };
            if name == BPF_GUARD_HELPER_SYMBOL {
                if exact.is_empty() {
                    exact.push(name.to_owned());
                }
            } else if let Some(suffix) = name.strip_prefix(BPF_GUARD_HELPER_SYMBOL) {
                if suffix.starts_with('.') && clones.len() < MAX_PROBE_SYMBOL_CANDIDATES {
                    clones.push(name.to_owned());
                }
            }
        }
    } else {
        eprintln!("bpf guard: {KALLSYMS_PATH} unreadable; falling back to the vmlinux BTF gate");
    }
    exact.extend(clones);
    exact.truncate(MAX_PROBE_SYMBOL_CANDIDATES);
    if exact.is_empty() && btf_has_func(BPF_GUARD_HELPER_SYMBOL) {
        // BTF knows the verifier function but kallsyms is unreadable (hardened
        // host): the plain name is the only honest attach attempt left.
        exact.push(BPF_GUARD_HELPER_SYMBOL.to_owned());
    }
    exact
}

/// Bounded `/sys/kernel/btf/vmlinux` FUNC-name scan used only as the kprobe
/// attach gate. Any parse/read problem is reported and treated as "absent" —
/// the caller then reports `kprobe=0` instead of guessing.
pub(super) fn btf_has_func(function: &str) -> bool {
    let file = match fs::File::open(VMLINUX_BTF_PATH) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("bpf guard BTF gate: open {VMLINUX_BTF_PATH} failed ({error})");
            return false;
        }
    };
    let length = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            eprintln!("bpf guard BTF gate: stat {VMLINUX_BTF_PATH} failed ({error})");
            return false;
        }
    };
    if length > MAX_VMLINUX_BTF_BYTES as u64 {
        eprintln!("bpf guard BTF gate: vmlinux BTF exceeds the 64 MiB bound");
        return false;
    }
    let mut data = Vec::with_capacity(length as usize + 1);
    if let Err(error) = file
        .take(MAX_VMLINUX_BTF_BYTES as u64 + 1)
        .read_to_end(&mut data)
    {
        eprintln!("bpf guard BTF gate: read {VMLINUX_BTF_PATH} failed ({error})");
        return false;
    }
    if data.len() > MAX_VMLINUX_BTF_BYTES {
        eprintln!("bpf guard BTF gate: vmlinux BTF grew beyond the 64 MiB bound");
        return false;
    }
    match btf_has_func_in(&data, function) {
        Ok(found) => found,
        Err(error) => {
            eprintln!("bpf guard BTF gate: vmlinux BTF is invalid ({error})");
            false
        }
    }
}

pub(super) fn u16_le(data: &[u8], at: usize) -> Result<u16, String> {
    let slice = data
        .get(at..at + 2)
        .ok_or_else(|| format!("truncated BTF at {at}"))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

pub(super) fn u32_le(data: &[u8], at: usize) -> Result<u32, String> {
    let slice = data
        .get(at..at + 4)
        .ok_or_else(|| format!("truncated BTF at {at}"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Focused, bounded BTF FUNC-name scan over a raw vmlinux BTF image. It parses
/// the same fixed header/section layout as
/// `crate::btf_offsets::VmlinuxBtf` but only answers "is this FUNC present",
/// which is the kprobe attach gate. Every structurally impossible byte is an
/// `Err`.
pub(crate) fn btf_has_func_in(data: &[u8], function: &str) -> Result<bool, String> {
    const KIND_FUNC: u32 = 12;
    if data.len() < BTF_HEADER_BYTES {
        return Err("BTF is shorter than its 24-byte header".to_owned());
    }
    if u16_le(data, 0)? != BTF_MAGIC {
        return Err("BTF magic mismatch".to_owned());
    }
    if data[2] != BTF_VERSION {
        return Err(format!("BTF version {} is not {BTF_VERSION}", data[2]));
    }
    let hdr_len = u32_le(data, 4)? as usize;
    if hdr_len < BTF_HEADER_BYTES || hdr_len > data.len() {
        return Err(format!("BTF hdr_len {hdr_len} is out of range"));
    }
    let type_off = u32_le(data, 8)? as usize;
    let type_len = u32_le(data, 12)? as usize;
    let str_off = u32_le(data, 16)? as usize;
    let str_len = u32_le(data, 20)? as usize;
    if str_len == 0 {
        return Err("BTF string section is empty".to_owned());
    }
    let type_start = hdr_len
        .checked_add(type_off)
        .ok_or("BTF type section overflows")?;
    let type_end = type_start
        .checked_add(type_len)
        .ok_or("BTF type section overflows")?;
    let str_start = hdr_len
        .checked_add(str_off)
        .ok_or("BTF string section overflows")?;
    let str_end = str_start
        .checked_add(str_len)
        .ok_or("BTF string section overflows")?;
    if type_end > data.len() || str_end > data.len() {
        return Err("BTF section lies outside the image".to_owned());
    }
    if type_end > str_start {
        return Err("BTF type and string sections overlap".to_owned());
    }
    let name_at = |offset: u32| -> Result<&str, String> {
        let offset = offset as usize;
        if offset >= str_end - str_start {
            return Err(format!("BTF string offset {offset} is out of range"));
        }
        let tail = &data[str_start + offset..str_end];
        let length = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("unterminated BTF string")?;
        std::str::from_utf8(&tail[..length]).map_err(|_| "non-UTF8 BTF string".to_owned())
    };
    let mut at = type_start;
    while at < type_end {
        if at + 12 > type_end {
            return Err("truncated BTF type header".to_owned());
        }
        let name_off = u32_le(data, at)?;
        let info = u32_le(data, at + 4)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        at += 12;
        let extra = match kind {
            // INT/VAR/DECL_TAG
            1 | 14 | 17 => 4,
            // ARRAY
            3 => 12,
            // ENUM
            6 => vlen.checked_mul(8).ok_or("BTF enum overflows")?,
            // STRUCT/UNION/DATASEC
            4 | 5 | 15 => vlen.checked_mul(12).ok_or("BTF struct overflows")?,
            // FUNC_PROTO
            13 => vlen.checked_mul(8).ok_or("BTF proto overflows")?,
            // ENUM64
            19 => vlen.checked_mul(12).ok_or("BTF enum64 overflows")?,
            // PTR/FWD/TYPEDEF/VOLATILE/CONST/RESTRICT/FUNC/FLOAT/TYPE_TAG
            _ => 0,
        };
        if at.saturating_add(extra) > type_end {
            return Err("truncated BTF type body".to_owned());
        }
        if kind == KIND_FUNC && name_at(name_off)? == function {
            return Ok(true);
        }
        at += extra;
    }
    if at != type_end {
        return Err("BTF type section length mismatch".to_owned());
    }
    Ok(false)
}
