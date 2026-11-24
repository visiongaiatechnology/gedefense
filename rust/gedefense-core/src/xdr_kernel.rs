//! Kernel-side XDR behavioral telemetry loader & ring buffer drain:
//! - `EXEC_ARGV_EVENTS` (`sys_enter_execve`)
//! - `KERNEL_PROBE_EVENTS` (`sys_enter_ptrace`, `sys_enter_openat`,
//!   `sys_enter_symlinkat`, and `socket_create` blacklisted protocol denies)

use aya::{
    maps::{MapData, RingBuf},
    programs::{KProbe, TracePoint},
    Ebpf,
};
use gedefense_common::{decode_exec_argv_event, decode_kernel_probe_event};
use std::error::Error;

type BoxError = Box<dyn Error + Send + Sync + 'static>;

const MAX_EXEC_ARGV_EVENTS_PER_RESPONSE: usize = 32;
const MAX_EXEC_ARGV_PAYLOAD_BYTES: usize = 56_000;
const MAX_KERNEL_PROBE_EVENTS_PER_RESPONSE: usize = 32;
const MAX_KERNEL_PROBE_PAYLOAD_BYTES: usize = 12_000;

const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("gedefense_sys_enter_execve", "syscalls", "sys_enter_execve"),
    (
        "gedefense_sys_enter_execveat",
        "syscalls",
        "sys_enter_execveat",
    ),
    ("gedefense_sys_enter_ptrace", "syscalls", "sys_enter_ptrace"),
    ("gedefense_openat_cred_probe", "syscalls", "sys_enter_openat"),
    (
        "gedefense_openat2_cred_probe",
        "syscalls",
        "sys_enter_openat2",
    ),
    (
        "gedefense_symlinkat_sensitive",
        "syscalls",
        "sys_enter_symlinkat",
    ),
    (
        "gedefense_symlink_sensitive",
        "syscalls",
        "sys_enter_symlink",
    ),
];

const KRETPROBES: &[(&str, &str)] = &[("gedefense_getname_flags_ret", "getname_flags")];

pub(crate) struct XdrKernelCore {
    exec_argv_events: RingBuf<MapData>,
    kernel_probe_events: RingBuf<MapData>,
    attached_execve: bool,
    attached_ptrace: bool,
    attached_openat: bool,
    attached_symlinkat: bool,
    attached_getname_ret: bool,
    rejected_exec_argv: u64,
    rejected_probes: u64,
}

fn decode_c_slot(raw: &[u8]) -> Vec<u8> {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    raw[..end]
        .iter()
        .map(|&b| match b {
            b'\n' | b'\r' | b'\t' => b' ',
            0..=0x1f | 0x7f => b'?',
            _ => b,
        })
        .collect()
}

impl XdrKernelCore {
    pub(crate) fn load(ebpf: &mut Ebpf) -> Result<Self, BoxError> {
        let exec_argv_events = RingBuf::try_from(
            ebpf.take_map(&crate::chameleon::map_name("EXEC_ARGV_EVENTS"))
                .ok_or("EXEC_ARGV_EVENTS missing")?,
        )?;
        let kernel_probe_events = RingBuf::try_from(
            ebpf.take_map(&crate::chameleon::map_name("KERNEL_PROBE_EVENTS"))
                .ok_or("KERNEL_PROBE_EVENTS missing")?,
        )?;
        let mut core = Self {
            exec_argv_events,
            kernel_probe_events,
            attached_execve: false,
            attached_ptrace: false,
            attached_openat: false,
            attached_symlinkat: false,
            attached_getname_ret: false,
            rejected_exec_argv: 0,
            rejected_probes: 0,
        };
        core.attach_tracepoints(ebpf);
        core.attach_kretprobes(ebpf);
        eprintln!(
            "GeDefense XDR kernel probes: execve={} ptrace={} openat={} symlinkat={} getname_ret={}",
            core.attached_execve,
            core.attached_ptrace,
            core.attached_openat,
            core.attached_symlinkat,
            core.attached_getname_ret
        );
        Ok(core)
    }

    fn attach_tracepoints(&mut self, ebpf: &mut Ebpf) {
        for (prog_name, category, tp_name) in TRACEPOINTS {
            let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(prog_name)) else {
                eprintln!("XDR kernel tracepoint {prog_name} missing; skipped");
                continue;
            };
            let result = (|| -> Result<(), BoxError> {
                let tp: &mut TracePoint = program.try_into()?;
                tp.load()?;
                tp.attach(category, tp_name)?;
                Ok(())
            })();
            match result {
                Ok(()) => match *prog_name {
                    "gedefense_sys_enter_execve" | "gedefense_sys_enter_execveat" => {
                        self.attached_execve = true
                    }
                    "gedefense_sys_enter_ptrace" => self.attached_ptrace = true,
                    "gedefense_openat_cred_probe" | "gedefense_openat2_cred_probe" => {
                        self.attached_openat = true
                    }
                    "gedefense_symlinkat_sensitive" | "gedefense_symlink_sensitive" => {
                        self.attached_symlinkat = true
                    }
                    _ => {}
                },
                Err(error) => {
                    eprintln!("XDR kernel tracepoint {category}:{tp_name} unavailable ({error}); degraded");
                }
            }
        }
    }

    fn attach_kretprobes(&mut self, ebpf: &mut Ebpf) {
        for (prog_name, symbol) in KRETPROBES {
            let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(prog_name)) else {
                eprintln!("XDR kernel kretprobe {prog_name} missing; skipped");
                continue;
            };
            let result = (|| -> Result<(), BoxError> {
                let kp: &mut KProbe = program.try_into()?;
                kp.load()?;
                kp.attach(*symbol, 0)?;
                Ok(())
            })();
            match result {
                Ok(()) => {
                    if *prog_name == "gedefense_getname_flags_ret" {
                        self.attached_getname_ret = true;
                    }
                }
                Err(error) => {
                    eprintln!("XDR kernel kretprobe {symbol} unavailable ({error}); cold-page fallback degraded");
                }
            }
        }
    }

    pub(crate) fn take_exec_argv_events(&mut self) -> Result<String, BoxError> {
        let mut records = Vec::with_capacity(MAX_EXEC_ARGV_EVENTS_PER_RESPONSE);
        let mut total_bytes = 0usize;
        while records.len() < MAX_EXEC_ARGV_EVENTS_PER_RESPONSE {
            let Some(item) = self.exec_argv_events.next() else {
                break;
            };
            let Some(event) = decode_exec_argv_event(&item) else {
                self.rejected_exec_argv = self.rejected_exec_argv.saturating_add(1);
                continue;
            };
            let comm_end = event.comm.iter().position(|b| *b == 0).unwrap_or(15);
            let filename_bytes = decode_c_slot(&event.buf[0..64]);
            let mut parts: Vec<Vec<u8>> = Vec::with_capacity(5);
            if !filename_bytes.is_empty() {
                parts.push(filename_bytes.clone());
            }
            for (start, end) in [(64usize, 128usize), (128, 320), (320, 384), (384, 448)] {
                let arg = decode_c_slot(&event.buf[start..end]);
                if !arg.is_empty() {
                    parts.push(arg);
                }
            }
            let cmdline_bytes = parts.join(&b' ');
            let record = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                event.pid,
                event.ppid,
                event.uid,
                event.gid,
                hex::encode(&event.comm[..comm_end]),
                hex::encode(&filename_bytes),
                hex::encode(&cmdline_bytes),
            );
            let sep = usize::from(!records.is_empty());
            if total_bytes.saturating_add(sep).saturating_add(record.len())
                > MAX_EXEC_ARGV_PAYLOAD_BYTES
            {
                break;
            }
            total_bytes = total_bytes.saturating_add(sep).saturating_add(record.len());
            records.push(record);
        }
        if records.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(records.join(","))
        }
    }

    pub(crate) fn take_kernel_probe_events(&mut self) -> Result<String, BoxError> {
        let mut records = Vec::with_capacity(MAX_KERNEL_PROBE_EVENTS_PER_RESPONSE);
        let mut total_bytes = 0usize;
        while records.len() < MAX_KERNEL_PROBE_EVENTS_PER_RESPONSE {
            let Some(item) = self.kernel_probe_events.next() else {
                break;
            };
            let Some(event) = decode_kernel_probe_event(&item) else {
                self.rejected_probes = self.rejected_probes.saturating_add(1);
                continue;
            };
            let comm_end = event.comm.iter().position(|b| *b == 0).unwrap_or(15);
            let detail_end = usize::from(event.detail_len).min(event.detail.len());
            let record = format!(
                "{}:{}:{}:{}:{}:{}:{}:{}:{}",
                event.ts_ns,
                event.pid,
                event.uid,
                event.target_pid,
                event.kind,
                event.action,
                event.detail_code,
                hex::encode(&event.comm[..comm_end]),
                hex::encode(&event.detail[..detail_end]),
            );
            let sep = usize::from(!records.is_empty());
            if total_bytes.saturating_add(sep).saturating_add(record.len())
                > MAX_KERNEL_PROBE_PAYLOAD_BYTES
            {
                break;
            }
            total_bytes = total_bytes.saturating_add(sep).saturating_add(record.len());
            records.push(record);
        }
        if records.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(records.join(","))
        }
    }
}
