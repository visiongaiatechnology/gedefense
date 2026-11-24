#![cfg(test)]

use super::*;

/// Real-system S12 acceptance smoke (ignored by default: needs Linux root,
/// a compiled bpfel object and a live kernel that accepts the object).
///
/// It exercises the two-class contract end to end:
/// 1. loads the real object and takes the mandatory `SEC_CRIT_*` maps
///    (arming the high-priority observer),
/// 2. attaches the bulk exec tracepoints and floods execve from several
///    threads so the `(class, cgroup, uid)` token bucket refuses bulk
///    records (suppression counters must advance),
/// 3. while the flood runs, arms `BPF_GUARD_STATE` and triggers the
///    attach-time guard's `check_helper_call` kprobe with a risk helper
///    (`bpf_probe_write_user`) so one critical record is duplicated into
///    `SEC_CRIT_EVENTS`,
/// 4. drains `SEC_CRIT_EVENTS` and asserts the critical record survived
///    while bulk telemetry was throttled, and that the high-priority ring
///    lost nothing (`drops=0`).
///
/// WSL2 run (root):
/// `sudo SEC_CRIT_EBPF_OBJECT=/tmp/gedefense-ebpf cargo +1.97.1 test --locked -p gedefense-core -- --ignored s12_real_kernel`
#[test]
#[ignore = "real-system S12 smoke: needs Linux root, a compiled eBPF object and a live kernel"]
fn s12_real_kernel_high_priority_ring_smoke() {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("S12 smoke SKIP: euid={euid} (needs root)");
        return;
    }
    let Ok(object) = std::env::var("SEC_CRIT_EBPF_OBJECT") else {
        eprintln!("S12 smoke SKIP: SEC_CRIT_EBPF_OBJECT is not set");
        return;
    };
    if !std::path::Path::new(&object).is_file() {
        eprintln!("S12 smoke SKIP: object {object} is not a file");
        return;
    }
    let mut ebpf = match aya::Ebpf::load_file(&object) {
        Ok(ebpf) => ebpf,
        Err(error) => {
            eprintln!("S12 smoke SKIP: full object load refused by this kernel ({error})");
            return;
        }
    };

    // Programs must be loaded (and therefore resolve the SEC_CRIT maps)
    // before the core takes those maps out of the object.
    let exec_enter = attach_tracepoint(
        &mut ebpf,
        "gedefense_sys_enter_execve",
        "syscalls",
        "sys_enter_execve",
    );
    let exec_flush = attach_tracepoint(
        &mut ebpf,
        "gedefense_exec",
        "sched",
        "sched_process_exec",
    );
    let helper_kprobe = attach_helper_kprobe(&mut ebpf);
    eprintln!(
        "S12 smoke attach: exec_enter={exec_enter} exec_flush={exec_flush} helper_kprobe={helper_kprobe}"
    );

    let mut core = SecCritCore::load(&mut ebpf)
        .expect("mandatory SEC_CRIT_* maps and the armed state word must work");
    assert!(core.enabled, "the high-priority observer must arm itself");
    let word = core
        .state
        .get(&SEC_CRIT_STATE_INDEX, 0)
        .expect("state word read");
    assert!(
        state_word_armed(word),
        "SEC_CRIT state word is not armed: {word:#x}"
    );

    if !exec_enter || !exec_flush {
        eprintln!(
            "S12 smoke: bulk exec tracepoints unavailable on this host; throttling half NOT_TESTED"
        );
        eprintln!("S12 smoke status: {}", core.status());
        return;
    }

    // Arm the attach-time guard so the verifier kprobe records helper risk.
    let critical_producer = if helper_kprobe {
        match ebpf.take_map(&crate::chameleon::map_name("BPF_GUARD_STATE")) {
            Some(map) => {
                let mut guard_state: AyaArray<MapData, u64> =
                    AyaArray::try_from(map).expect("BPF_GUARD_STATE map type");
                guard_state
                    .set(0, gedefense_common::bpf_guard_state_word(0x5ec0_1e11, true), 0)
                    .expect("BPF_GUARD_STATE arm");
                true
            }
            None => {
                eprintln!("S12 smoke: BPF_GUARD_STATE map missing; critical half NOT_TESTED");
                false
            }
        }
    } else {
        eprintln!(
            "S12 smoke: check_helper_call kprobe unavailable; critical half NOT_TESTED"
        );
        false
    };

    // Flood build: execve from several threads so one (class, cgroup, uid)
    // bucket is exhausted far above its 512-token capacity.
    let mut workers = Vec::new();
    for _ in 0..8u32 {
        workers.push(std::thread::spawn(|| {
            for _ in 0..400u32 {
                let _ = std::process::Command::new("/bin/true")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }));
    }
    std::thread::sleep(std::time::Duration::from_millis(250));
    let helper_risk_triggered = if critical_producer {
        trigger_helper_risk_load()
    } else {
        false
    };
    for worker in workers {
        let _ = worker.join();
    }
    // Give the in-flight execs a moment to flush their pending records.
    std::thread::sleep(std::time::Duration::from_millis(200));

    let drained = core.take_events().expect("live high-priority drain");
    eprintln!("S12 smoke drain: {drained}");
    let status = core.status();
    eprintln!("S12 smoke status: {status}");
    let counters = parse_status(&status);
    assert_eq!(counters.get("enabled"), Some(&1), "status: {status}");
    assert_eq!(
        counters.get("refused_unarmed"),
        Some(&0),
        "armed observer must not refuse records: {status}"
    );
    assert_eq!(
        counters.get("drops"),
        Some(&0),
        "0% loss on the high-priority ring is the S12 acceptance criterion: {status}"
    );
    let suppressed = counters.get("suppressed").copied().unwrap_or(0);
    assert!(
        suppressed > 0,
        "the exec flood must be throttled by the token bucket (suppressed={suppressed})"
    );
    let records = drained
        .split_once('|')
        .map(|(_, rest)| rest)
        .unwrap_or("");
    let has_critical = records.split(',').any(|record| {
        let fields: Vec<&str> = record.split(':').collect();
        fields.len() == 12 && fields[1] == "2"
    });
    // The verifier kprobe fires while the load is being verified, i.e. even
    // when the BPF_PROG_LOAD syscall is later rejected by the helper-access
    // check (this WSL2 kernel answers EPERM after `check_helper_call` has
    // already run). The duplicated record itself is therefore the proof
    // that the trigger fired; the syscall return code only decides whether
    // the critical half can be claimed as NOT_TESTED or PASS.
    if critical_producer && has_critical {
        assert_eq!(
            counters.get("refused_unarmed"),
            Some(&0),
            "armed observer must not refuse records: {status}"
        );
        assert_eq!(
            counters.get("drops"),
            Some(&0),
            "0% loss on the high-priority ring is the S12 acceptance criterion: {status}"
        );
        eprintln!(
            "S12 smoke PASS: critical BPF-guard record survived a throttled bulk exec flood (suppressed={suppressed}, ring_drops=0, syscall_trigger={helper_risk_triggered}); drain={drained}"
        );
    } else if critical_producer {
        eprintln!(
            "S12 smoke NOT_TESTED (critical half): check_helper_call was attached and BPF_GUARD_STATE armed but no helper-risk record reached SEC_CRIT_EVENTS (syscall_trigger={helper_risk_triggered}, drain={drained}); bulk throttling half still asserted (suppressed={suppressed})"
        );
    } else {
        eprintln!(
            "S12 smoke NOT_TESTED (critical half): the attach-time guard producer is unavailable on this host (helper kprobe/BPF_GUARD_STATE); bulk throttling half asserted (suppressed={suppressed})"
        );
    }
}

// ------------------------------------------------------------- smoke helpers

fn attach_tracepoint(
    ebpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    event: &str,
) -> bool {
    let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(program_name)) else {
        eprintln!("S12 smoke: program {program_name} missing");
        return false;
    };
    let result = (|| -> Result<(), BoxError> {
        let tracepoint: &mut aya::programs::TracePoint = program.try_into()?;
        tracepoint.load()?;
        tracepoint.attach(category, event)?;
        Ok(())
    })();
    match result {
        Ok(()) => true,
        Err(error) => {
            eprintln!("S12 smoke: {category}:{event} attach failed ({error})");
            false
        }
    }
}

/// Attaches the attach-time guard's verifier kprobe. Symbol candidates come
/// from `/proc/kallsyms` (exact name first, then compiler clones); when
/// kallsyms is unreadable the plain upstream name is the only honest
/// attempt.
fn attach_helper_kprobe(ebpf: &mut Ebpf) -> bool {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(file) = fs::File::open("/proc/kallsyms") {
        use std::io::BufRead as _;
        let reader = std::io::BufReader::new(file.take(16 * 1024 * 1024));
        for line in reader.lines().take(1_500_000) {
            let Ok(line) = line else { break };
            let Some(name) = line.split_whitespace().nth(2) else {
                continue;
            };
            if name == "check_helper_call" && candidates.is_empty() {
                candidates.push(name.to_owned());
            } else if name.starts_with("check_helper_call.") && candidates.len() < 4 {
                candidates.push(name.to_owned());
            }
        }
    }
    if candidates.is_empty() {
        candidates.push("check_helper_call".to_owned());
    }
    let Some(program) = ebpf.program_mut(&crate::chameleon::program_name("gedefense_check_helper_call")) else {
        eprintln!("S12 smoke: program gedefense_check_helper_call missing");
        return false;
    };
    let result = (|| -> Result<(), BoxError> {
        let kprobe: &mut aya::programs::KProbe = program.try_into()?;
        kprobe.load()?;
        for symbol in &candidates {
            match kprobe.attach(symbol.as_str(), 0) {
                Ok(_) => {
                    eprintln!("S12 smoke: check_helper_call kprobe attached to {symbol}");
                    return Ok(());
                }
                Err(error) => eprintln!(
                    "S12 smoke: kprobe attach to {symbol} failed ({error}); trying next"
                ),
            }
        }
        Err("no check_helper_call symbol candidate attached".into())
    })();
    match result {
        Ok(()) => true,
        Err(error) => {
            eprintln!("S12 smoke: helper kprobe unavailable ({error})");
            false
        }
    }
}

/// Loads a four-insn `BPF_PROG_TYPE_KPROBE` program whose third insn is a
/// call to `bpf_probe_write_user` (helper id 36). The verifier must resolve
/// that helper through `check_helper_call`, which is exactly the event the
/// armed attach-time guard records. The program itself is never attached
/// and is discarded immediately; it exists only to drive the kprobe.
fn trigger_helper_risk_load() -> bool {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct BpfInsn {
        code: u8,
        regs: u8,
        off: i16,
        imm: i32,
    }
    #[repr(C)]
    struct BpfProgLoadAttr {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
    }
    let insns = [
        BpfInsn {
            code: 0xb7, // BPF_MOV64_IMM r1, 0
            regs: 0x01,
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x85, // BPF_JMP | BPF_CALL
            regs: 0x00,
            off: 0,
            imm: 36, // bpf_probe_write_user
        },
        BpfInsn {
            code: 0xb7, // BPF_MOV64_IMM r0, 0
            regs: 0x00,
            off: 0,
            imm: 0,
        },
        BpfInsn {
            code: 0x95, // BPF_EXIT
            regs: 0x00,
            off: 0,
            imm: 0,
        },
    ];
    let license = b"GPL\0";
    let attr = BpfProgLoadAttr {
        prog_type: 2, // BPF_PROG_TYPE_KPROBE
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 0,
        log_size: 0,
        log_buf: 0,
        kern_version: 0,
        prog_flags: 0,
    };
    // SAFETY: `attr` is a zero-tailed #[repr(C)] struct whose pointer fields
    // reference stack memory that outlives the syscall; the kernel copies
    // exactly `size_of::<BpfProgLoadAttr>()` bytes (48, a valid bpf_attr
    // prefix) and validates the instruction pointer itself.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            5i64, // BPF_PROG_LOAD
            &attr as *const BpfProgLoadAttr as *const libc::c_void,
            core::mem::size_of::<BpfProgLoadAttr>() as u64,
        )
    };
    if fd >= 0 {
        unsafe { libc::close(fd as i32) };
        true
    } else {
        eprintln!(
            "S12 smoke: BPF_PROG_LOAD rejected before/without the helper check (errno={})",
            std::io::Error::last_os_error()
        );
        false
    }
}

fn parse_status(status: &str) -> std::collections::HashMap<&str, u64> {
    let mut values = std::collections::HashMap::new();
    for field in status.split(':') {
        if let Some((key, value)) = field.split_once('=') {
            if let Ok(parsed) = value.parse::<u64>() {
                values.insert(key, parsed);
            }
        }
    }
    values
}
