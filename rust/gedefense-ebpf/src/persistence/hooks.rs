//! Program bodies of the AP-5 persistence sensors (child module of
//! `persistence`). Each body runs only behind the armed/shape gates and emits at
//! most one bounded record; the public `#[lsm]`/`#[tracepoint]` entry points stay
//! in the parent module.

use aya_ebpf::{helpers::bpf_get_current_pid_tgid, programs::{LsmContext, TracePointContext}};
use gedefense_common::{
    persistence_class_is_device, persistence_class_is_secret, persistence_class_known,
    persistence_identity_key, persistence_path_class, persistence_path_is_directory,
    persistence_path_owner_uid, persistence_path_value_valid, PERSIST_DETAIL_ACC_MASK,
    PERSIST_DETAIL_ACC_UNKNOWN,
    PERSIST_DETAIL_READV, PERSIST_DETAIL_WRITEV, PERSIST_KIND_INTEGRITY_WRITE,
    PERSIST_KIND_LIBRARY_MMAP, PERSIST_KIND_MEMORY_SCRAPE, PERSIST_KIND_PERIPHERAL_OPEN,
    PERSIST_KIND_PTRACE_ACCESS, PERSIST_KIND_SECRET_OPEN,
};
use crate::titan_probe;

use super::events::{increment_counter, write_small_decimal};
use super::paths::{
    current_exe_identity, exec_offsets, field_fits, file_identity, file_open_abi_ok, file_offsets,
    parent_identity, persistence_armed, vm_offsets, PtraceAbi,
};
use super::{
    emit_persistence_event, PERSIST_GUARD_DEVICE_EVENTS, PERSIST_GUARD_EXECS,
    PERSIST_GUARD_MMAP_EVENTS, PERSIST_GUARD_PATHS, PERSIST_GUARD_READ_FAILURES,
    PERSIST_GUARD_SECRET_EVENTS,
};

#[inline(always)]
pub(crate) fn try_persistence_file_open(ctx: &LsmContext) -> Option<()> {
    if !persistence_armed() {
        return None;
    }
    if !file_open_abi_ok() {
        increment_counter(&PERSIST_GUARD_READ_FAILURES);
        return None;
    }
    let file: u64 = ctx.arg(0);
    if file == 0 {
        increment_counter(&PERSIST_GUARD_READ_FAILURES);
        return None;
    }
    let offsets = match file_offsets() {
        Some(offsets) => offsets,
        None => {
            increment_counter(&PERSIST_GUARD_READ_FAILURES);
            return None;
        }
    };
    let (dev, ino) = match file_identity(file, &offsets) {
        Some(identity) => identity,
        None => {
            increment_counter(&PERSIST_GUARD_READ_FAILURES);
            return None;
        }
    };
    let identity = persistence_identity_key(dev, ino);
    // Exact watched inode first. A directory entry only matches through the
    // bounded parent step below (opening the directory itself is not an
    // integrity event).
    let mut matched: Option<u64> = None;
    if let Some(value) = unsafe { PERSIST_GUARD_PATHS.get(&identity).copied() } {
        if !persistence_path_is_directory(value) && persistence_path_value_valid(value) {
            matched = Some(value);
        }
    }
    if matched.is_none() {
        if let Some(parent) = parent_identity(file, &offsets) {
            if let Some(value) = unsafe { PERSIST_GUARD_PATHS.get(&parent).copied() } {
                if persistence_path_is_directory(value) && persistence_path_value_valid(value) {
                    matched = Some(value);
                }
            }
        }
    }
    let Some(value) = matched else {
        return None;
    };
    let class = persistence_path_class(value);
    if !persistence_class_known(class) {
        return None;
    }
    let kind;
    let detail_code;
    if persistence_class_is_secret(class) {
        kind = PERSIST_KIND_SECRET_OPEN;
        // The control plane compares this owner uid with the opener uid and the
        // expected per-store tool set; it is evidence, never an enforcement key.
        detail_code = persistence_path_owner_uid(value);
        increment_counter(&PERSIST_GUARD_SECRET_EVENTS);
    } else if persistence_class_is_device(class) {
        kind = PERSIST_KIND_PERIPHERAL_OPEN;
        // Session correlation bits are filled in by the core (userspace) when it
        // encodes the text record; the kernel has no logind view.
        detail_code = 0;
        increment_counter(&PERSIST_GUARD_DEVICE_EVENTS);
    } else {
        kind = PERSIST_KIND_INTEGRITY_WRITE;
        // Access intent lets the control plane separate writes from harmless
        // reads; an unreadable f_flags offset is the conservative "unknown".
        detail_code = if field_fits(offsets.f_flags, 4, offsets.file_size) {
            match titan_probe::<u32>(file, offsets.f_flags) {
                Some(flags) => flags & PERSIST_DETAIL_ACC_MASK,
                None => PERSIST_DETAIL_ACC_UNKNOWN,
            }
        } else {
            PERSIST_DETAIL_ACC_UNKNOWN
        };
    }
    emit_persistence_event(dev, ino, class, kind, detail_code, &[0u8; 8]);
    Some(())
}

#[inline(always)]
pub(crate) fn try_persistence_mmap(ctx: &LsmContext, prot_arg: u32) -> Option<()> {
    if !persistence_armed() {
        return None;
    }
    let offsets = file_offsets()?;
    let exec = exec_offsets()?;
    // Cheap early exit: only protected executables are relevant.
    let exe_identity = current_exe_identity(&offsets, &exec)?;
    if unsafe { PERSIST_GUARD_EXECS.get(&exe_identity).is_none() } {
        return None;
    }
    let file: u64 = ctx.arg(0);
    let (dev, ino) = file_identity(file, &offsets)?;
    let prot: u64 = ctx.arg(prot_arg as usize);
    increment_counter(&PERSIST_GUARD_MMAP_EVENTS);
    emit_persistence_event(
        dev,
        ino,
        gedefense_common::PERSIST_CLASS_LD_SO,
        PERSIST_KIND_LIBRARY_MMAP,
        prot as u32,
        &[0u8; 8],
    );
    Some(())
}

#[inline(always)]
pub(crate) fn try_persistence_ptrace(ctx: &LsmContext, abi: &PtraceAbi) -> Option<()> {
    if !persistence_armed() {
        return None;
    }
    let child: u64 = ctx.arg(abi.child_arg as usize);
    if child == 0 {
        increment_counter(&PERSIST_GUARD_READ_FAILURES);
        return None;
    }
    let mode: u32 = ctx.arg(abi.mode_arg as usize);
    let child_tgid: u32 = match titan_probe(child, abi.task.tgid) {
        Some(tgid) => tgid,
        None => {
            increment_counter(&PERSIST_GUARD_READ_FAILURES);
            return None;
        }
    };
    if child_tgid == 0 {
        increment_counter(&PERSIST_GUARD_READ_FAILURES);
        return None;
    }
    let mut detail = [0u8; 8];
    write_small_decimal(mode, &mut detail);
    emit_persistence_event(
        0,
        0,
        gedefense_common::PERSIST_CLASS_UNSPECIFIED,
        PERSIST_KIND_PTRACE_ACCESS,
        child_tgid,
        &detail,
    );
    Some(())
}

#[inline(always)]
pub(crate) fn try_process_vm(ctx: &TracePointContext, readv: bool) -> Option<()> {
    if !persistence_armed() {
        return None;
    }
    let detail = if readv {
        PERSIST_DETAIL_READV
    } else {
        PERSIST_DETAIL_WRITEV
    };
    // Whenever the core could not resolve the tracepoint format the record
    // degrades honestly to pid/comm-only (target pid 0) instead of guessing an
    // offset; the core status carries the offsets flag.
    let mut target_pid: u32 = 0;
    if let Some((pid_offset, target_offset, _size)) = vm_offsets(readv) {
        let caller: u32 = match unsafe { ctx.read_at(pid_offset as usize) } {
            Ok(value) => value,
            Err(_) => {
                increment_counter(&PERSIST_GUARD_READ_FAILURES);
                0
            }
        };
        let target: u32 = match unsafe { ctx.read_at(target_offset as usize) } {
            Ok(value) => value,
            Err(_) => {
                increment_counter(&PERSIST_GUARD_READ_FAILURES);
                0
            }
        };
        if caller == 0 || target == 0 {
            // A process_vm call with an unreadable target is not useful
            // evidence: it cannot be correlated with a victim process.
            return None;
        }
        // Reading your own address space is not cross-process scraping.
        if target == (bpf_get_current_pid_tgid() as u32) {
            return None;
        }
        target_pid = target;
    }
    emit_persistence_event(
        0,
        0,
        gedefense_common::PERSIST_CLASS_UNSPECIFIED,
        PERSIST_KIND_MEMORY_SCRAPE,
        target_pid,
        &detail,
    );
    Some(())
}
