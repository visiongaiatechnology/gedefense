use crate::BoxError;
use std::{
    ffi::CString,
    fs,
    os::{fd::AsRawFd, unix::net::UnixStream},
};

pub(super) fn valid_rule_token(rule: &str) -> bool {
    !rule.is_empty()
        && rule.len() <= 64
        && rule
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn proc_start_ticks(pid: i32) -> Result<u64, BoxError> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = stat.rfind(')').ok_or("malformed proc stat")?;
    let fields: Vec<&str> = stat
        .get(close + 2..)
        .ok_or("malformed proc stat")?
        .split_whitespace()
        .collect();
    if fields.len() <= 19 {
        return Err("short proc stat".into());
    }
    Ok(fields[19].parse::<u64>()?)
}

fn objective_kill_evidence(pid: i32, rule: &str) -> bool {
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    match rule {
        "XDR.MEMFD_EXEC" => exe.contains("/memfd:") || exe.starts_with("memfd:"),
        "XDR.EXE_DELETED" => exe.ends_with(" (deleted)"),
        "XDR.TEMP_EXEC" => {
            exe.starts_with("/tmp/") || exe.starts_with("/var/tmp/") || exe.starts_with("/dev/shm/")
        }
        "KD.LINUX.DESTRUCTIVE" => {
            let command = fs::read(format!("/proc/{pid}/cmdline"))
                .ok()
                .map(|bytes| String::from_utf8_lossy(&bytes).replace('\0', " "))
                .unwrap_or_default();
            command.contains("rm -rf /")
                || command.contains("mkfs.")
                || command.contains("of=/dev/")
        }
        _ => false,
    }
}

pub(super) fn pidfd_signal(
    pid: i32,
    expected_start: u64,
    signal: i32,
    rule: &str,
) -> Result<(), BoxError> {
    if pid <= 4 || pid == std::process::id() as i32 {
        return Err("protected PID".into());
    }
    if !valid_rule_token(rule) {
        return Err("invalid rule token".into());
    }
    if proc_start_ticks(pid)? != expected_start {
        return Err("PID identity mismatch before pidfd_open".into());
    }
    // SAFETY: pidfd_open is called with a validated positive PID and flags=0.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) as i32 };
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = (|| {
        if proc_start_ticks(pid)? != expected_start {
            return Err("PID identity mismatch after pidfd_open".into());
        }
        if signal == libc::SIGKILL && !objective_kill_evidence(pid, rule) {
            return Err("kill rejected: objective evidence missing".into());
        }
        // SAFETY: pidfd is identity-checked, signal is caller-restricted to
        // SIGSTOP/SIGKILL, and a null siginfo is supported by the syscall.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    })();
    // SAFETY: pidfd is owned by this function and is not used after close.
    unsafe {
        libc::close(pidfd);
    }
    result
}

pub(super) fn lookup_identity(user: &str) -> Result<(u32, u32), BoxError> {
    let name = CString::new(user)?;
    // SAFETY: name is NUL-terminated; copied UID/GID values outlive libc state.
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };
    if entry.is_null() {
        return Err(format!("control user {user:?} does not exist").into());
    }
    // SAFETY: null was checked above.
    Ok(unsafe { ((*entry).pw_uid, (*entry).pw_gid) })
}

pub(super) fn peer_uid(stream: &UnixStream) -> Result<u32, BoxError> {
    let mut cred = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the output buffer matches ucred and returned size is verified.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if len as usize != std::mem::size_of::<libc::ucred>() {
        return Err("unexpected SO_PEERCRED response size".into());
    }
    // SAFETY: getsockopt succeeded and returned the exact ucred size.
    Ok(unsafe { cred.assume_init().uid })
}
