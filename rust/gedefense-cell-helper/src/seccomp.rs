//! Seccomp-BPF filter for ephemeral parser cells (POINT2 spec §4.4).
//!
//! The filter is a pure, deterministic classic-BPF program for x86_64:
//!
//! 1. architecture check: `AUDIT_ARCH_X86_64` is mandatory, any other ABI is
//!    killed with `SECCOMP_RET_KILL_PROCESS` (fail-closed, no ptrace tricks);
//! 2. **x32 ABI guard**: a syscall number carrying `__X32_SYSCALL_BIT`
//!    (`0x4000_0000`) is refused with `EPERM` before any deny/socket rule.
//!    Without it `syscall(0x4000_0000 | nr)` addresses a *different* syscall
//!    table entry than the bare `nr` and would slip past every `JEQ` rule;
//! 3. deny list from spec §4.4 returns `EPERM` (never `ENOSYS`, so callers see
//!    a hard refusal instead of silent fallbacks);
//! 4. `socket(2)`/`socketpair(2)` are allowed only for `AF_UNIX`
//!    (`args[0]` is a scalar and therefore inspectable in classic BPF);
//! 5. everything else is allowed.  The remaining confinement is provided by
//!    the private mount namespace/tmpfs root, the empty network namespace,
//!    zero capabilities, `no_new_privs` and `PR_SET_PDEATHSIG` (sandbox.rs).
//!
//! `EPERM` (not `KILL_PROCESS`) is chosen for the x32 guard: it is the same
//! hard refusal the deny list already uses, a parser that accidentally issues
//! an x32 call stays observable instead of being killed, and the whole x32 ABI
//! becomes unusable, which is exactly the fail-closed outcome a filter designed
//! for the x86_64 ABI needs.
//!
//! # Documented classic-BPF limitation
//!
//! Classic seccomp BPF cannot dereference user-space pointers.  The sockaddr
//! family of `connect(2)`/`bind(2)` therefore *cannot* be checked here.  No
//! non-AF_UNIX socket can ever be created (rule 3) and every unrelated file
//! descriptor is closed before `execve`, so a parser has no way to reach an
//! `AF_INET` socket in the first place; the cell runs in its own netns whose
//! only interface `lo` stays down.  This is the strongest verifiable position
//! for a phase-1 classic-BPF filter and is reported as a residual risk.
//!
//! The filter is built **before** `clone(2)` and installed with a pre-built
//! program slice so that the forked child never allocates memory: the helper
//! process may be multi-threaded and the raw syscall path deliberately avoids
//! glibc's `fork(2)` atfork handlers.

use crate::types::ErrorCode;

/// `AUDIT_ARCH_X86_64` (linux/audit.h).
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// `__X32_SYSCALL_BIT` (arch/x86/include/uapi/asm/unistd.h): set on every
/// syscall number issued through the x32 ABI.  Such numbers index a separate
/// syscall table, so they must be rejected before the `JEQ` deny list runs.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
/// `BPF_MAXINSNS` is not exposed consistently by libc; pin the kernel value.
const MAX_INSNS: usize = 4096;

// Classic BPF opcodes (linux/filter.h): LD|W|ABS, JMP|JEQ|K, JMP|JSET|K, RET|K.
const LD_W_ABS: libc::c_ushort = 0x20;
const JMP_JEQ_K: libc::c_ushort = 0x15;
const JMP_JSET_K: libc::c_ushort = 0x45;
const RET_K: libc::c_ushort = 0x06;

/// Offsets inside `struct seccomp_data` (linux/seccomp.h).
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0: u32 = 16;

/// Syscalls refused with `EPERM` (POINT2 spec §4.4, exact list).
pub const DENY: &[(libc::c_long, &str)] = &[
    (libc::SYS_ptrace, "ptrace"),
    (libc::SYS_process_vm_readv, "process_vm_readv"),
    (libc::SYS_process_vm_writev, "process_vm_writev"),
    (libc::SYS_bpf, "bpf"),
    (libc::SYS_perf_event_open, "perf_event_open"),
    (libc::SYS_userfaultfd, "userfaultfd"),
    (libc::SYS_io_uring_setup, "io_uring_setup"),
    (libc::SYS_io_uring_enter, "io_uring_enter"),
    (libc::SYS_io_uring_register, "io_uring_register"),
    (libc::SYS_mount, "mount"),
    (libc::SYS_umount2, "umount2"),
    (libc::SYS_pivot_root, "pivot_root"),
    (libc::SYS_chroot, "chroot"),
    (libc::SYS_unshare, "unshare"),
    (libc::SYS_setns, "setns"),
    (libc::SYS_clone, "clone"),
    (libc::SYS_clone3, "clone3"),
    (libc::SYS_fork, "fork"),
    (libc::SYS_vfork, "vfork"),
    (libc::SYS_keyctl, "keyctl"),
    (libc::SYS_add_key, "add_key"),
    (libc::SYS_request_key, "request_key"),
    (libc::SYS_kexec_load, "kexec_load"),
    (libc::SYS_kexec_file_load, "kexec_file_load"),
    (libc::SYS_init_module, "init_module"),
    (libc::SYS_finit_module, "finit_module"),
    (libc::SYS_delete_module, "delete_module"),
    (libc::SYS_open_by_handle_at, "open_by_handle_at"),
    (libc::SYS_name_to_handle_at, "name_to_handle_at"),
];

/// Defence in depth beyond §4.4: blocks cross-cell fd theft / signalling and
/// cross-process side channels between sibling cells that share the same
/// unprivileged UID.  No parser needs these syscalls.
pub const EXTRA_DENY: &[(libc::c_long, &str)] = &[
    (libc::SYS_pidfd_open, "pidfd_open"),
    (libc::SYS_pidfd_getfd, "pidfd_getfd"),
    (libc::SYS_pidfd_send_signal, "pidfd_send_signal"),
    (libc::SYS_kcmp, "kcmp"),
];

fn stmt(code: libc::c_ushort, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

fn jump(code: libc::c_ushort, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Build the deterministic seccomp program.  Refused on non-x86_64 hosts.
pub fn build_program() -> Result<Vec<libc::sock_filter>, ErrorCode> {
    if !cfg!(target_arch = "x86_64") {
        return Err(ErrorCode::SandboxUnavailable);
    }
    let extra = DENY.len() + EXTRA_DENY.len();
    let mut p: Vec<libc::sock_filter> = Vec::with_capacity(6 + 2 * extra + 7);
    // arch guard: [0] load arch, [1] match => skip kill, else [2] kill.
    p.push(stmt(LD_W_ABS, OFF_ARCH));
    p.push(jump(JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0));
    p.push(stmt(RET_K, RET_KILL_PROCESS));
    // syscall number.
    p.push(stmt(LD_W_ABS, OFF_NR));
    // x32 ABI guard: any number with __X32_SYSCALL_BIT set indexes the x32
    // syscall table and would bypass every JEQ rule below, so it is denied
    // before the deny list.  jt=0 falls into the EPERM, jf=1 skips it.
    p.push(jump(JMP_JSET_K, X32_SYSCALL_BIT, 0, 1));
    p.push(stmt(RET_K, RET_ERRNO | libc::EPERM as u32));
    for &(nr, _) in DENY.iter().chain(EXTRA_DENY.iter()) {
        // equal => fall through to the RET, not equal => skip it.
        p.push(jump(JMP_JEQ_K, nr as u32, 0, 1));
        p.push(stmt(RET_K, RET_ERRNO | libc::EPERM as u32));
    }
    // socket/socketpair family pinning on args[0] (domain).
    // not socket => +2 (to socketpair check); not socketpair => return ALLOW.
    p.push(jump(JMP_JEQ_K, libc::SYS_socket as u32, 2, 0));
    p.push(jump(JMP_JEQ_K, libc::SYS_socketpair as u32, 1, 0));
    p.push(stmt(RET_K, RET_ALLOW));
    p.push(stmt(LD_W_ABS, OFF_ARG0));
    // AF_UNIX => skip EPERM to the final ALLOW; anything else => EPERM.
    p.push(jump(JMP_JEQ_K, libc::AF_UNIX as u32, 1, 0));
    p.push(stmt(RET_K, RET_ERRNO | libc::EPERM as u32));
    p.push(stmt(RET_K, RET_ALLOW));
    Ok(p)
}

/// Install a pre-built program.  Sets `PR_SET_NO_NEW_PRIVS` first, then uses
/// `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)`.  Allocation-free so it is
/// safe in a forked child of a possibly multi-threaded helper.
pub fn install_program(prog: &[libc::sock_filter]) -> Result<(), ErrorCode> {
    if prog.is_empty() || prog.len() > MAX_INSNS {
        return Err(ErrorCode::SandboxUnavailable);
    }
    let mut fprog = libc::sock_fprog { len: prog.len() as libc::c_ushort, filter: prog.as_ptr() as *mut libc::sock_filter };
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(ErrorCode::SandboxUnavailable);
        }
        if libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &mut fprog as *mut libc::sock_fprog) != 0 {
            return Err(ErrorCode::SandboxUnavailable);
        }
    }
    Ok(())
}

/// Convenience: build + install (used by tests and non-sandbox callers).
pub fn install() -> Result<(), ErrorCode> {
    install_program(&build_program()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal classic-BPF interpreter for `seccomp_data` subset.
    fn eval(prog: &[libc::sock_filter], arch: u32, nr: u32, arg0: u64) -> u32 {
        let mut a: u32 = 0;
        let mut pc = 0usize;
        loop {
            let ins = prog[pc];
            match ins.code {
                LD_W_ABS => {
                    a = match ins.k {
                        OFF_NR => nr,
                        OFF_ARCH => arch,
                        OFF_ARG0 => arg0 as u32,
                        _ => 0,
                    };
                    pc += 1;
                }
                JMP_JEQ_K => {
                    let skip = if a == ins.k { ins.jt as usize } else { ins.jf as usize };
                    pc += 1 + skip;
                }
                JMP_JSET_K => {
                    let skip = if a & ins.k != 0 { ins.jt as usize } else { ins.jf as usize };
                    pc += 1 + skip;
                }
                RET_K => return ins.k,
                other => panic!("unexpected BPF opcode {other:#x}"),
            }
        }
    }

    const EPERM: u32 = RET_ERRNO | libc::EPERM as u32;
    const ALLOW: u32 = RET_ALLOW;

    #[test]
    fn program_is_deterministic_and_bounded() {
        let a = build_program().expect("x86_64");
        let b = build_program().expect("x86_64");
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!((x.code, x.jt, x.jf, x.k), (y.code, y.jt, y.jf, y.k));
        }
        let expected = 6 + 2 * (DENY.len() + EXTRA_DENY.len()) + 7;
        assert_eq!(a.len(), expected);
        assert!(a.len() <= 512 && a.len() < MAX_INSNS);
        // every jump target must stay inside the program (u8 range is fine).
        assert!(a.len() < 256, "short jumps only; program too large: {}", a.len());
    }

    #[test]
    fn arch_guard_is_first_and_fail_closed() {
        let p = build_program().unwrap();
        assert_eq!(p[0].k, OFF_ARCH);
        assert_eq!(p[2].k, RET_KILL_PROCESS);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, libc::SYS_read as u32, 0), ALLOW);
        assert_eq!(eval(&p, 0xC000_00B7, libc::SYS_read as u32, 0), RET_KILL_PROCESS); // aarch64 ABI
        assert_eq!(eval(&p, 0, libc::SYS_read as u32, 0), RET_KILL_PROCESS);
    }

    #[test]
    fn spec_deny_list_is_complete_and_numeric() {
        let p = build_program().unwrap();
        assert!(DENY.len() >= 29);
        for &(nr, name) in DENY {
            assert_eq!(eval(&p, AUDIT_ARCH_X86_64, nr as u32, 0), EPERM, "not denied: {name}");
        }
        for &(nr, name) in EXTRA_DENY {
            assert_eq!(eval(&p, AUDIT_ARCH_X86_64, nr as u32, 0), EPERM, "not denied: {name}");
        }
        let mut seen = std::collections::HashSet::new();
        for &(nr, _) in DENY.iter().chain(EXTRA_DENY.iter()) {
            assert!(seen.insert(nr), "duplicate syscall number {nr}");
        }
        // Pinned x86_64 numbers (kernel ABI, must never drift silently).
        assert_eq!(libc::SYS_ptrace, 101);
        assert_eq!(libc::SYS_mount, 165);
        assert_eq!(libc::SYS_bpf, 321);
        assert_eq!(libc::SYS_io_uring_setup, 425);
        assert_eq!(libc::SYS_clone3, 435);
        assert_eq!(libc::SYS_socket, 41);
        assert_eq!(libc::SYS_open_by_handle_at, 304);
    }

    #[test]
    fn x32_syscall_numbers_are_rejected_before_the_deny_and_socket_rules() {
        let p = build_program().unwrap();
        // The x32 guard is instruction [4], directly after `LD nr` and before
        // the first deny rule (which starts at [6]).
        assert_eq!((p[3].k, p[4].code, p[4].k), (OFF_NR, JMP_JSET_K, X32_SYSCALL_BIT));
        let x32 = |nr: libc::c_long| nr as u32 | X32_SYSCALL_BIT;
        // x32 variants of deny-listed and socket-pinned syscalls are refused,
        // even with an AF_UNIX domain argument that the 64-bit path allows.
        for nr in [
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_io_uring_setup,
            libc::SYS_clone3,
            libc::SYS_socket,
            libc::SYS_socketpair,
        ] {
            assert_eq!(
                eval(&p, AUDIT_ARCH_X86_64, x32(nr), libc::AF_UNIX as u64),
                EPERM,
                "x32 variant of syscall {nr} escaped the filter"
            );
        }
        // The guard rejects *every* x32-numbered syscall, not just the list;
        // the AF_INET socket variants stay refused regardless of args[0].
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, x32(libc::SYS_read), 0), EPERM);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, x32(libc::SYS_openat), 0), EPERM);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, x32(libc::SYS_socket), libc::AF_INET as u64), EPERM);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, x32(libc::SYS_socketpair), libc::AF_INET as u64), EPERM);
        // Normal x86_64 numbers keep their exact previous behaviour.
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, libc::SYS_read as u32, 0), ALLOW);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, libc::SYS_socket as u32, libc::AF_UNIX as u64), ALLOW);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, libc::SYS_socket as u32, libc::AF_INET as u64), EPERM);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, libc::SYS_ptrace as u32, 0), EPERM);
        // A foreign ABI is still killed before the x32 guard runs.
        assert_eq!(eval(&p, 0xC000_00B7, x32(libc::SYS_read), 0), RET_KILL_PROCESS);
    }

    #[test]
    fn socket_families_are_pinned_to_af_unix() {
        let p = build_program().unwrap();
        let sock = libc::SYS_socket as u32;
        let pair = libc::SYS_socketpair as u32;
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, sock, libc::AF_UNIX as u64), ALLOW);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, sock, libc::AF_INET as u64), EPERM);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, sock, libc::AF_INET6 as u64), EPERM);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, sock, libc::AF_NETLINK as u64), EPERM);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, pair, libc::AF_UNIX as u64), ALLOW);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, pair, libc::AF_INET as u64), EPERM);
        // high garbage in args[0] must not confuse the 32-bit domain load.
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, sock, 0xdead_beef_0000_0001), ALLOW);
        assert_eq!(eval(&p, AUDIT_ARCH_X86_64, sock, 0xdead_beef_0000_0002), EPERM);
    }

    #[test]
    fn benign_syscalls_stay_allowed_but_fork_family_is_not() {
        let p = build_program().unwrap();
        for nr in [libc::SYS_read, libc::SYS_write, libc::SYS_openat, libc::SYS_execve, libc::SYS_connect, libc::SYS_bind, libc::SYS_wait4, libc::SYS_exit_group] {
            assert_eq!(eval(&p, AUDIT_ARCH_X86_64, nr as u32, 0), ALLOW, "over-blocked {nr}");
        }
        for nr in [libc::SYS_fork, libc::SYS_vfork, libc::SYS_clone, libc::SYS_clone3] {
            assert_eq!(eval(&p, AUDIT_ARCH_X86_64, nr as u32, 0), EPERM);
        }
    }

    /// Filter works unprivileged via `no_new_privs`; no root required.
    #[test]
    fn installed_filter_denies_ptrace_in_child() {
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                libc::close(fds[0]);
                if install().is_err() {
                    libc::_exit(11);
                }
                let denied = libc::ptrace(libc::PTRACE_TRACEME, 0, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
                let allowed = libc::getpid() > 0;
                let byte = [denied as u8, allowed as u8];
                libc::write(fds[1], byte.as_ptr().cast(), byte.len());
                libc::_exit(0);
            }
        }
        assert!(pid > 0);
        let mut buf = [0u8; 2];
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
        }
        assert_eq!(n, 2);
        assert_eq!(buf, [1, 1], "ptrace denied+EPERM, benign syscall allowed");
    }
}
