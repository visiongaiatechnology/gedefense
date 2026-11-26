//! Sandbox backend: spawn/kill one ephemeral parser cell (POINT2 spec §4).
//!
//! Parent: raw `clone(2)` (`CLONE_NEWNS|NEWPID|NEWIPC|NEWUTS|NEWNET`, never
//! glibc `fork`, so no atfork handlers in a multi-threaded helper), pre-built
//! plan/seccomp program, `CLOEXEC` sync pipe (EOF = parser exec succeeded,
//! 4 bytes = child error). Child (allocation-free): `PR_SET_PDEATHSIG`, private
//! mount tree, tmpfs root 0755 + `/tmp`,`/home/parser`,`/run`, minimal `/dev`,
//! read-only parser/library binds, `/proc` `hidepid=2`, validated input
//! materialised read-only, `pivot_root` (fallback `chroot`), stdio `/dev/null`,
//! export FD 3, permanent `nobody` credentials, cleared caps, rlimits,
//! `umask(077)`, `PR_SET_NO_NEW_PRIVS`, then raw `fork(2)`: PID 1 reaps, its
//! child installs the filter and only `execve`s the pinned binary. Input is
//! copied from the validated FD into the private tmpfs (0640
//! `gedefense:gedefense` staging is unreadable for `nobody`) and bound
//! read-only. X11 refused (`capability-missing`); only a verified Wayland/
//! PipeWire socket is bound read-only. Library dirs stay exec-allowed: the ELF
//! interpreter is `open_exec`-checked. Classic BPF cannot inspect `sockaddr`.

use crate::types::{is_hex, CellHandle, CellSpec, ErrorCode, Limits, DEFAULT_CELL_GID, DEFAULT_CELL_UID, HARD_MAX_INPUT_BYTES, MAX_ARGV};
use std::ffi::{CString, OsStr, OsString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
const EXPORT_FD: RawFd = 3;
const ERR_FD: RawFd = 200;
const SYNC_TIMEOUT_MS: u64 = 15_000;
const REAP_TIMEOUT_MS: u64 = 5_000;
const CELL_INPUT: &str = "/input/document.bin";
const E_SECCOMP: u32 = 2;
const E_EXEC: u32 = 3;
const NOEXEC: libc::c_ulong = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
const CLONE_FLAGS: libc::c_int = libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS | libc::CLONE_NEWNET | libc::SIGCHLD;
const RESERVED_ENV: [&str; 10] = ["HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "XDG_RUNTIME_DIR", "WAYLAND_DISPLAY", "PIPEWIRE_REMOTE", "GEDEFENSE_EXPORT_FD", "GEDEFENSE_INPUT_FD"];
#[derive(Default, Debug, PartialEq, Eq)]
struct Display { wayland: Option<PathBuf>, pipewire: Option<PathBuf> }
impl Display { fn any(&self) -> bool { self.wayland.is_some() || self.pipewire.is_some() } }
enum Op {
    Mkdir(CString, u32), CreateFile(CString), Symlink(CString, CString), Tmpfs(CString, CString, libc::c_ulong),
    Chown(CString, u32, u32), Proc(CString), Dir(CString, CString), File { src: CString, dst: CString, ro: bool, exec: bool },
}
struct Plan {
    ops: Vec<Op>, args: Vec<CString>, envs: Vec<CString>, binary: CString, newroot: CString, input_target: CString,
    seccomp: Vec<libc::sock_filter>, input: OwnedFd, export: OwnedFd, input_size: u64, uid: u32, gid: u32,
    limits: Limits, err_w: RawFd, pipe_r: RawFd,
}
fn cp(p: &Path) -> Result<CString, ErrorCode> { CString::new(p.as_os_str().as_bytes()).map_err(|_| ErrorCode::Internal) }
fn clean_abs(p: &Path) -> bool { p.is_absolute() && p.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_))) }
/// Unprivileged cell credentials; `0` (unset) maps to the spec default.
fn cell_ids(uid: u32, gid: u32) -> (u32, u32) { (if uid == 0 { DEFAULT_CELL_UID } else { uid }, if gid == 0 { DEFAULT_CELL_GID } else { gid }) }
fn validate_spec(spec: &CellSpec) -> Result<(), ErrorCode> {
    if !is_hex(&spec.uuid, 32) { return Err(ErrorCode::BadRequest); }
    spec.limits.validate()?;
    if !clean_abs(&spec.root_dir) || !clean_abs(&spec.binary) || !clean_abs(&spec.input_path) { return Err(ErrorCode::ProfileInvalid); }
    let md = std::fs::symlink_metadata(&spec.binary).map_err(|_| ErrorCode::ProfileInvalid)?;
    if md.file_type().is_symlink() || !md.is_file() || md.uid() != 0 || md.mode() & 0o111 == 0 { return Err(ErrorCode::ProfileInvalid); }
    if spec.argv.is_empty() || spec.argv.len() > MAX_ARGV || spec.argv.iter().any(|a| a.is_empty() || a.len() > 4096) { return Err(ErrorCode::ProfileInvalid); }
    if spec.argv.iter().map(|a| a.matches("{input}").count()).sum::<usize>() > 1 { return Err(ErrorCode::ProfileInvalid); }
    Ok(())
}
fn check_export_fd(fd: RawFd) -> Result<(), ErrorCode> {
    let fl = if fd < 0 { -1 } else { unsafe { libc::fcntl(fd, libc::F_GETFL) } };
    if fl < 0 || fl & libc::O_ACCMODE == libc::O_RDONLY { Err(ErrorCode::Internal) } else { Ok(()) }
}
fn open_input(spec: &CellSpec) -> Result<OwnedFd, ErrorCode> {
    let Some(preopened) = spec.input_fd.as_ref() else {
        return Err(ErrorCode::InputInvalid);
    };
    let fd = unsafe { libc::fcntl(preopened.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 { return Err(ErrorCode::InputInvalid); }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let size = spec.input_size;
    let ok = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } == 0
        && unsafe { libc::fstat(fd, &mut st) } == 0
        && st.st_mode & libc::S_IFMT == libc::S_IFREG
        && st.st_size as u64 == size
        && size > 0
        && size <= HARD_MAX_INPUT_BYTES;
    if !ok { unsafe { libc::close(fd) }; return Err(ErrorCode::InputInvalid); }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
/// Dup above the child's fixed low numbers, keeping it inheritable.
fn dup_high(fd: RawFd) -> Result<OwnedFd, ErrorCode> {
    let mut d = unsafe { libc::fcntl(fd, libc::F_DUPFD, 100) };
    if d == ERR_FD { let d2 = unsafe { libc::fcntl(fd, libc::F_DUPFD, ERR_FD + 1) }; unsafe { libc::close(d) }; d = d2; }
    if d < 0 { return Err(ErrorCode::Internal); }
    Ok(unsafe { OwnedFd::from_raw_fd(d) })
}
fn unix_socket(dir: &Path, name: &OsStr, uid: u32) -> Result<PathBuf, ErrorCode> {
    let err = ErrorCode::display_unavailable(); let b = name.as_bytes();
    if b.is_empty() || b.len() > 64 || b.iter().any(|c| !(c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))) { return Err(err); }
    let p = dir.join(name); let md = std::fs::symlink_metadata(&p).map_err(|_| err)?;
    if md.file_type().is_symlink() || !md.file_type().is_socket() || md.uid() != uid { return Err(err); }
    Ok(p)
}
/// Display policy: X11 always refused; Wayland/PipeWire only when requested and
/// a verified AF_UNIX socket owned by the cell UID exists.
fn display_from(wayland: bool, pipewire: bool, allow: &[String], uid: u32, rt: Option<OsString>, wl: Option<OsString>) -> Result<Display, ErrorCode> {
    let err = ErrorCode::display_unavailable();
    if allow.iter().any(|n| n == "DISPLAY" || n == "XAUTHORITY") { return Err(err); }
    if !wayland && !pipewire { return Ok(Display::default()); }
    let rt = PathBuf::from(rt.ok_or(err)?); let md = std::fs::symlink_metadata(&rt).map_err(|_| err)?;
    if !clean_abs(&rt) || md.file_type().is_symlink() || !md.is_dir() { return Err(err); }
    let mut d = Display::default();
    if wayland { d.wayland = Some(unix_socket(&rt, &wl.unwrap_or_else(|| OsString::from("wayland-0")), uid)?); }
    if pipewire { d.pipewire = Some(unix_socket(&rt, OsStr::new("pipewire-0"), uid)?); }
    Ok(d)
}
fn plan_display(spec: &CellSpec) -> Result<Display, ErrorCode> {
    if !spec.wayland && !spec.pipewire { return display_from(false, false, &spec.env_allow, spec.uid, None, None); }
    display_from(spec.wayland, spec.pipewire, &spec.env_allow, spec.uid, std::env::var_os("XDG_RUNTIME_DIR"), std::env::var_os("WAYLAND_DISPLAY"))
}
fn build_args(spec: &CellSpec) -> Result<Vec<CString>, ErrorCode> {
    let mut out = Vec::with_capacity(spec.argv.len());
    for a in &spec.argv {
        let v = if a.contains("{input}") { a.replace("{input}", CELL_INPUT) } else { a.replace("{export}", "/proc/self/fd/3") };
        out.push(CString::new(v).map_err(|_| ErrorCode::ProfileInvalid)?);
    }
    Ok(out)
}
fn build_env(spec: &CellSpec, display: &Display) -> Result<Vec<CString>, ErrorCode> {
    let mut v: Vec<CString> = ["HOME=/home/parser", "USER=parser", "LOGNAME=parser", "PATH=/usr/bin:/bin", "TMPDIR=/tmp", "GEDEFENSE_EXPORT_FD=3"]
        .iter().map(|s| CString::new(*s).expect("static env")).collect();
    if display.any() { v.push(CString::new("XDG_RUNTIME_DIR=/run/cell").expect("static")); }
    if display.wayland.is_some() { v.push(CString::new("WAYLAND_DISPLAY=wayland-0").expect("static")); }
    if display.pipewire.is_some() { v.push(CString::new("PIPEWIRE_REMOTE=pipewire-0").expect("static")); }
    for name in &spec.env_allow {
        if name == "DISPLAY" || name == "XAUTHORITY" { return Err(ErrorCode::display_unavailable()); }
        if RESERVED_ENV.contains(&name.as_str()) { continue; }
        if let Some(val) = std::env::var_os(name) {
            let mut kv = name.as_bytes().to_vec(); kv.push(b'='); kv.extend_from_slice(val.as_bytes());
            if kv.len() <= 4096 { v.push(CString::new(kv).map_err(|_| ErrorCode::ProfileInvalid)?); }
        }
    }
    Ok(v)
}
fn mirror_dirs(ops: &mut Vec<Op>, root: &Path, abs: &Path) -> Result<(), ErrorCode> {
    let mut cur = root.to_path_buf();
    for c in abs.components() { if let Component::Normal(n) = c { cur.push(n); ops.push(Op::Mkdir(cp(&cur)?, 0o755)); } }
    Ok(())
}

fn mount_ops(ops: &mut Vec<Op>, spec: &CellSpec, root: &Path, display: &Display) -> Result<(), ErrorCode> {    let rel = |s: &str| root.join(s.trim_start_matches('/'));
    let tmp = |size: u32| CString::new(format!("size={size},mode=0700")).expect("tmpfs opts");
    ops.push(Op::Tmpfs(cp(root)?, CString::new(format!("size={},mode=0755", 16 << 20)).expect("tmpfs opts"), NOEXEC));
    for d in ["tmp", "home", "home/parser", "run", "dev", "proc", "input"] { ops.push(Op::Mkdir(cp(&rel(d))?, 0o755)); }
    ops.push(Op::Tmpfs(cp(&rel("tmp"))?, tmp(64 << 20), NOEXEC));
    ops.push(Op::Tmpfs(cp(&rel("home/parser"))?, tmp(8 << 20), NOEXEC));
    ops.push(Op::Tmpfs(cp(&rel("run"))?, tmp(8 << 20), NOEXEC));
    ops.push(Op::Mkdir(cp(&rel("run/cell"))?, 0o755));
    for d in ["tmp", "home/parser", "run/cell"] { ops.push(Op::Chown(cp(&rel(d))?, spec.uid, spec.gid)); }
    for dev in ["null", "zero", "urandom"] {
        let dst = cp(&rel(&format!("dev/{dev}")))?; ops.push(Op::CreateFile(dst.clone()));
        ops.push(Op::File { src: cp(Path::new(&format!("/dev/{dev}")))?, dst, ro: false, exec: false });
    }
    let parent = spec.binary.parent().ok_or(ErrorCode::ProfileInvalid)?;
    mirror_dirs(ops, root, parent)?;
    let bin_dst = cp(&rel(spec.binary.to_str().ok_or(ErrorCode::ProfileInvalid)?))?;
    ops.push(Op::CreateFile(bin_dst.clone()));
    ops.push(Op::File { src: cp(&spec.binary)?, dst: bin_dst, ro: true, exec: true });
    let mut bound: Vec<PathBuf> = Vec::new();
    for lib in ["/lib", "/lib64", "/usr/lib", "/usr/lib64"] {
        let src = Path::new(lib); let (Ok(md), Ok(real)) = (std::fs::symlink_metadata(src), std::fs::canonicalize(src)) else { continue };
        if md.file_type().is_symlink() {
            let Ok(target) = std::fs::read_link(src) else { continue };
            if let Some(p) = src.parent() { mirror_dirs(ops, root, p)?; }
            ops.push(Op::Symlink(cp(&target)?, cp(&rel(lib))?));
        }
        if !bound.contains(&real) {
            mirror_dirs(ops, root, &real)?;
            ops.push(Op::Dir(cp(&real)?, cp(&rel(real.to_str().ok_or(ErrorCode::Internal)?))?));
            bound.push(real);
        }
    }
    for (sock, name) in [(&display.wayland, "wayland-0"), (&display.pipewire, "pipewire-0")] {
        if let Some(src) = sock {
            let dst = cp(&rel(&format!("run/cell/{name}")))?; ops.push(Op::CreateFile(dst.clone()));
            ops.push(Op::File { src: cp(src)?, dst, ro: true, exec: false });
        }
    }
    ops.push(Op::Proc(cp(&rel("proc"))?));
    Ok(())
}
fn build_plan(spec: &CellSpec) -> Result<Plan, ErrorCode> {
    validate_spec(spec)?; check_export_fd(spec.export_fd)?;
    let display = plan_display(spec)?; let (uid, gid) = cell_ids(spec.uid, spec.gid);
    std::fs::create_dir_all(&spec.root_dir).map_err(|_| ErrorCode::Internal)?;
    let root = spec.root_dir.join("root");
    std::fs::create_dir_all(&root).map_err(|_| ErrorCode::Internal)?;
    let md = std::fs::symlink_metadata(&root).map_err(|_| ErrorCode::Internal)?;
    if md.file_type().is_symlink() || !md.is_dir() { return Err(ErrorCode::Internal); }
    let input = open_input(spec)?; let export = dup_high(spec.export_fd)?;
    let seccomp = crate::seccomp::build_program()?;
    let mut ops = Vec::new(); mount_ops(&mut ops, spec, &root, &display)?;
    Ok(Plan {
        ops, args: build_args(spec)?, envs: build_env(spec, &display)?, binary: cp(&spec.binary)?, newroot: cp(&root)?,
        input_target: cp(&root.join("input/document.bin"))?, seccomp, input, export, input_size: spec.input_size,
        uid, gid, limits: spec.limits, err_w: -1, pipe_r: -1,
    })
}
fn remount(dst: &CString, noexec: bool) -> bool {
    let mut flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
    if noexec { flags |= libc::MS_NOEXEC; }
    unsafe { libc::mount(std::ptr::null(), dst.as_ptr(), std::ptr::null(), flags, std::ptr::null()) == 0 }
}
fn bind(src: &CString, dst: &CString) -> bool { unsafe { libc::mount(src.as_ptr(), dst.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) == 0 } }
/// Run one plan op in the child; allocation-free.
unsafe fn run_op(op: &Op) -> bool {
    match op {
        Op::Mkdir(p, mode) => libc::mkdir(p.as_ptr(), *mode) == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST),
        Op::CreateFile(p) => { let fd = libc::open(p.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC, 0o600); if fd < 0 { return false; } libc::close(fd); true }
        Op::Symlink(t, l) => libc::symlink(t.as_ptr(), l.as_ptr()) == 0,
        Op::Tmpfs(dst, data, flags) => libc::mount(c"tmpfs".as_ptr(), dst.as_ptr(), c"tmpfs".as_ptr(), *flags, data.as_ptr().cast()) == 0,
        Op::Chown(p, uid, gid) => libc::chown(p.as_ptr(), *uid, *gid) == 0,
        Op::Proc(dst) => libc::mount(c"proc".as_ptr(), dst.as_ptr(), c"proc".as_ptr(), NOEXEC, c"hidepid=2".as_ptr().cast()) == 0,
        Op::Dir(src, dst) => bind(src, dst) && remount(dst, false),
        Op::File { src, dst, ro, exec } => bind(src, dst) && (!*ro || remount(dst, !*exec)),
    }
}
/// Copy the validated input FD into the private tmpfs, then bind it read-only.
unsafe fn materialize_input(plan: &Plan) -> bool {
    let fd = libc::open(plan.input_target.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC, 0o400);
    if fd < 0 { return false; }
    let mut ok = libc::lseek(plan.input.as_raw_fd(), 0, libc::SEEK_SET) >= 0;
    let mut buf = [0u8; 8192]; let mut left = plan.input_size;
    while ok && left > 0 {
        let n = libc::read(plan.input.as_raw_fd(), buf.as_mut_ptr().cast(), left.min(buf.len() as u64) as usize);
        if n <= 0 { ok = false; break; }
        let mut off = 0usize;
        while ok && off < n as usize {
            let w = libc::write(fd, buf.as_ptr().add(off).cast(), n as usize - off);
            if w <= 0 { ok = false; } else { off += w as usize; }
        }
        left -= n as u64;
    }
    libc::close(fd);
    ok && left == 0 && libc::chown(plan.input_target.as_ptr(), plan.uid, plan.gid) == 0
}
unsafe fn pivot(plan: &Plan) -> bool {
    if libc::chdir(plan.newroot.as_ptr()) != 0 { return false; }
    if libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) != 0 {
        return false;
    }
    libc::umount2(c".".as_ptr(), libc::MNT_DETACH);
    libc::chdir(c"/".as_ptr()) == 0
}
/// Drop all capabilities/groups and make the unprivileged identity permanent.
unsafe fn creds(plan: &Plan) -> bool {
    for cap in 0..=63 { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0); }
    if libc::setgroups(0, std::ptr::null()) != 0 || libc::setresgid(plan.gid, plan.gid, plan.gid) != 0 || libc::setresuid(plan.uid, plan.uid, plan.uid) != 0 { return false; }
    #[repr(C)] struct Header { version: u32, pid: i32 }
    #[repr(C)] #[derive(Clone, Copy)] struct Data { effective: u32, permitted: u32, inheritable: u32 }
    let mut h = Header { version: 0x2008_0522, pid: 0 };
    let mut d = [Data { effective: 0, permitted: 0, inheritable: 0 }; 2];
    if libc::syscall(libc::SYS_capset, &mut h as *mut Header, d.as_mut_ptr()) != 0 { return false; }
    libc::prctl(47, 4 as libc::c_ulong, 0, 0, 0); // PR_CAP_AMBIENT / CLEAR_ALL
    libc::setresuid(0, 0, 0) != 0 && libc::setresgid(0, 0, 0) != 0
}
unsafe fn rlimits(plan: &Plan) -> bool {
    let l = plan.limits; let lim = |cur: u64| libc::rlimit { rlim_cur: cur as libc::rlim_t, rlim_max: cur as libc::rlim_t };
    libc::setrlimit(libc::RLIMIT_NOFILE, &lim(64)) == 0 && libc::setrlimit(libc::RLIMIT_NPROC, &lim(64)) == 0
        && libc::setrlimit(libc::RLIMIT_CORE, &lim(0)) == 0 && libc::setrlimit(libc::RLIMIT_FSIZE, &lim(l.max_export_bytes)) == 0
        && libc::setrlimit(libc::RLIMIT_CPU, &lim(l.ttl_seconds.saturating_add(5))) == 0 && libc::setrlimit(libc::RLIMIT_AS, &lim(l.max_rss_bytes)) == 0
}
unsafe fn fail(code: u32) -> ! { libc::write(ERR_FD, code.to_le_bytes().as_ptr().cast(), 4); libc::_exit(126) }
/// Child entry point; never returns (final `execve` or `_exit`).
unsafe fn child_main(plan: &Plan) -> ! {    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0) != 0 || libc::dup2(plan.err_w, ERR_FD) < 0 {
        libc::_exit(126);
    }
    libc::fcntl(ERR_FD, libc::F_SETFD, libc::FD_CLOEXEC);
    if plan.err_w != ERR_FD { libc::close(plan.err_w); }
    if plan.pipe_r != ERR_FD { libc::close(plan.pipe_r); }
    if libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) != 0 { fail(11); }
    for (i, op) in plan.ops.iter().enumerate() { if !run_op(op) { fail(20 + i as u32); } }
    if !materialize_input(plan) { fail(13); }
    if !bind(&plan.input_target, &plan.input_target) || !remount(&plan.input_target, true) { fail(14); }
    if !pivot(plan) { fail(15); }
    let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
    if devnull < 0 { fail(16); }
    for fd in 0..3 { if libc::dup2(devnull, fd) < 0 { fail(17); } }
    if devnull > 2 { libc::close(devnull); }
    if libc::dup2(plan.export.as_raw_fd(), EXPORT_FD) < 0 { fail(18); }
    libc::fcntl(EXPORT_FD, libc::F_SETFD, 0);
    if !creds(plan) { fail(19); } if !rlimits(plan) { fail(25); }
    libc::umask(0o077);
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 { fail(22); }
    let mut argv: [*const libc::c_char; 40] = [std::ptr::null(); 40];
    let mut envp: [*const libc::c_char; 40] = [std::ptr::null(); 40];
    if plan.args.len() >= argv.len() || plan.envs.len() >= envp.len() { fail(26); }
    for (i, a) in plan.args.iter().enumerate() { argv[i] = a.as_ptr(); }
    for (i, e) in plan.envs.iter().enumerate() { envp[i] = e.as_ptr(); }
    for fd in 4..1024 { if fd != ERR_FD { libc::close(fd); } }
    let parser = libc::syscall(libc::SYS_fork) as libc::pid_t; // PID 1 = reaper
    if parser < 0 { fail(23); }
    if parser == 0 {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0) != 0 { fail(24); }
        if crate::seccomp::install_program(&plan.seccomp).is_err() { fail(E_SECCOMP); }
        libc::execve(plan.binary.as_ptr(), argv.as_ptr(), envp.as_ptr());
        fail(E_EXEC);
    }
    for fd in 3..1024 { if fd != ERR_FD { libc::close(fd); } }
    if crate::seccomp::install_program(&plan.seccomp).is_err() { fail(E_SECCOMP); }
    libc::close(ERR_FD);
    let mut status: libc::c_int = 0;
    loop {
        let w = libc::wait4(-1, &mut status, 0, std::ptr::null_mut());
        if w < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
        break;
    }
    libc::_exit(0)
}
/// EOF = parser exec succeeded; 4 bytes = child error code.
fn sync_wait(read_fd: RawFd) -> Result<(), ErrorCode> {
    let deadline = Instant::now() + Duration::from_millis(SYNC_TIMEOUT_MS);
    let mut buf = [0u8; 4]; let mut got = 0usize;
    while got < buf.len() {
        let ms = deadline.saturating_duration_since(Instant::now()).as_millis().min(i32::MAX as u128) as i32;
        if ms == 0 { return Err(ErrorCode::SandboxUnavailable); }
        let mut pfd = libc::pollfd { fd: read_fd, events: libc::POLLIN, revents: 0 };
        let pr = unsafe { libc::poll(&mut pfd, 1, ms) };
        if pr < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
        if pr <= 0 { return Err(ErrorCode::SandboxUnavailable); }
        let n = unsafe { libc::read(read_fd, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
        if n <= 0 { return if got == 0 { Ok(()) } else { Err(ErrorCode::SandboxUnavailable) }; }
        got += n as usize;
    }
    let code = u32::from_le_bytes(buf);
    Err(match code { E_SECCOMP | E_EXEC => ErrorCode::SandboxUnavailable, 13 => ErrorCode::InputInvalid, _ => ErrorCode::SandboxUnavailable })
}
fn kill_reap(pid: libc::pid_t) -> bool {
    let deadline = Instant::now() + Duration::from_millis(REAP_TIMEOUT_MS);
    let mut status: libc::c_int = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid || (r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)) { return true; }
        if Instant::now() >= deadline { return false; }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn terminate(pid: libc::pid_t) -> bool {
    unsafe {
        let pidfd = libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long) as RawFd;
        let sent = pidfd >= 0 && libc::syscall(libc::SYS_pidfd_send_signal, pidfd as libc::c_long, libc::SIGKILL as libc::c_long, std::ptr::null::<libc::siginfo_t>(), 0 as libc::c_long) == 0;
        if pidfd >= 0 { libc::close(pidfd); }
        if !sent { libc::kill(pid, libc::SIGKILL); }
    }
    kill_reap(pid)
}
fn cleanup_root(root_dir: &Path) {
    if !clean_abs(root_dir) { return; }
    let root = root_dir.join("root");
    if let Ok(c) = cp(&root) { unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) }; }
    let _ = std::fs::remove_dir_all(&root);
}
/// Spawn one parser cell. Returned PID is PID 1 of the cell (host view); the
/// lifecycle layer owns cgroup/freeze/state and overrides the handle fields.
pub fn spawn(spec: &CellSpec) -> Result<CellHandle, ErrorCode> {
    let mut plan = build_plan(spec)?;
    let mut pipe = [0 as RawFd; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 { return Err(ErrorCode::SandboxUnavailable); }
    let pipe_r = unsafe { OwnedFd::from_raw_fd(pipe[0]) }; let pipe_w = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    plan.err_w = pipe_w.as_raw_fd(); plan.pipe_r = pipe_r.as_raw_fd();
    let child = unsafe { libc::syscall(libc::SYS_clone, CLONE_FLAGS as libc::c_long, 0 as libc::c_long, 0 as libc::c_long, 0 as libc::c_long, 0 as libc::c_long) as libc::pid_t };
    if child == 0 { unsafe { child_main(&plan) } }
    if child < 0 { return Err(ErrorCode::SandboxUnavailable); }
    drop(pipe_w);
    let sync = sync_wait(pipe_r.as_raw_fd());
    drop(pipe_r);
    if let Err(e) = sync { terminate(child); cleanup_root(&spec.root_dir); return Err(e); }
    Ok(CellHandle {
        pid: child, uuid: spec.uuid.clone(), generation: spec.generation, cgroup_id: 0, cgroup_path: PathBuf::new(),
        root_dir: spec.root_dir.clone(), export_fd: spec.export_fd, export_path: spec.export_path.clone(), started_at: 0, expires_at: 0,
    })
}
/// Kill + reap one cell (idempotent) and drop its private tmpfs directory.
pub fn kill(handle: &CellHandle) -> Result<(), ErrorCode> {
    if handle.pid <= 0 { return Err(ErrorCode::UnknownCell); }
    let dead = terminate(handle.pid);
    cleanup_root(&handle.root_dir);
    if dead { Ok(()) } else { Err(ErrorCode::BurnFailed) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_support::TempDir;
    fn spec(td: &TempDir, binary: &str, argv: Vec<String>) -> CellSpec {
        let input_path = td.write("in.bin", b"hello").expect("input");
        let input_file = std::fs::File::open(&input_path).expect("open input");
        CellSpec {
            uuid: "ab".repeat(16), generation: 1, profile_id: "test".into(), binary: PathBuf::from(binary),
            binary_sha256: "cd".repeat(32), argv, env_allow: vec![], wayland: false, pipewire: false,
            input_path, input_fd: Some(std::sync::Arc::new(OwnedFd::from(input_file))), input_size: 5, input_sha256: "ef".repeat(32),
            input_token: "01".repeat(16), export_fd: -1, export_path: td.child("export.bin"),
            limits: Limits::new(30, 256 << 20, 16, 1 << 20), uid: 0, gid: 65534, root_dir: td.child("cell"),
        }
    }
    fn with_export(td: &TempDir, mut s: CellSpec) -> (CellSpec, std::fs::File) {
        let f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(td.child("export.bin")).expect("export");
        s.export_fd = f.as_raw_fd();
        (s, f)
    }

    #[test]
    fn validation_and_credentials_reject_hostile_specs() {
        assert_eq!(cell_ids(0, 0), (DEFAULT_CELL_UID, DEFAULT_CELL_GID));
        assert_eq!(cell_ids(1000, 1001), (1000, 1001));
        assert!(!clean_abs(Path::new("/a/../b")) && !clean_abs(Path::new("rel/x")) && clean_abs(Path::new("/")));
        let td = TempDir::new("sandbox-val").expect("tempdir");
        let good = spec(&td, "/bin/true", vec!["/bin/true".into(), "{input}".into()]);
        assert_eq!(validate_spec(&good), Ok(()));
        assert_eq!(check_export_fd(-1), Err(ErrorCode::Internal));
        let mut cases: Vec<(CellSpec, ErrorCode)> = Vec::new();
        let mut x = good.clone(); x.binary = PathBuf::from("/etc/shadow"); cases.push((x, ErrorCode::ProfileInvalid));
        let mut x = good.clone(); x.binary = PathBuf::from("bin/true"); cases.push((x, ErrorCode::ProfileInvalid));
        let mut x = good.clone(); x.input_path = PathBuf::from("/tmp/../etc/passwd"); cases.push((x, ErrorCode::ProfileInvalid));
        let mut x = good.clone(); x.argv = vec!["{input}".into(), "{input}".into()]; cases.push((x, ErrorCode::ProfileInvalid));
        let mut x = good.clone(); x.argv = (0..=MAX_ARGV).map(|i| i.to_string()).collect(); cases.push((x, ErrorCode::ProfileInvalid));
        let mut x = good.clone(); x.limits.ttl_seconds = 0; cases.push((x, ErrorCode::BadRequest));
        let mut x = good.clone(); x.uuid = "../".into(); cases.push((x, ErrorCode::BadRequest));
        for (s, want) in cases { assert_eq!(validate_spec(&s), Err(want)); }
    }

    #[test]
    fn display_plan_refuses_x11_and_requires_verified_socket() {
        let e = Err(ErrorCode::display_unavailable());
        assert_eq!(display_from(false, false, &["DISPLAY".into()], 0, None, None), e);
        assert_eq!(display_from(false, false, &["XAUTHORITY".into()], 0, None, None), e);
        assert_eq!(display_from(true, false, &[], 0, None, None), e);
        assert_eq!(display_from(true, false, &[], 0, Some(OsString::from("rel/dir")), None), e);
        let td = TempDir::new("sandbox-display").expect("tempdir");
        assert_eq!(display_from(false, true, &[], 0, Some(td.path.clone().into()), None), e);
        let sock = td.child("wayland-0");
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, b) in sock.as_os_str().as_bytes().iter().enumerate() { addr.sun_path[i] = *b as libc::c_char; }
        let bound = unsafe { libc::bind(fd, &addr as *const libc::sockaddr_un as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_un>() as u32) == 0 };
        unsafe { libc::close(fd) };
        if bound {
            let uid = unsafe { libc::geteuid() }; let rt = Some(td.path.clone().into());
            assert_eq!(display_from(true, false, &[], uid, rt.clone(), Some("wayland-0".into())).map(|d| d.wayland), Ok(Some(sock)));
            assert_eq!(display_from(true, false, &[], uid + 1, rt.clone(), Some("wayland-0".into())), e);
            assert_eq!(display_from(true, false, &[], uid, rt, Some("../w".into())), e);
        }
    }

    #[test]
    fn plan_layout_and_argument_substitution() {
        let td = TempDir::new("sandbox-plan").expect("tempdir");
        let (s, _export) = with_export(&td, spec(&td, "/bin/true", vec!["/bin/true".into(), "{input}".into()]));
        let plan = build_plan(&s).expect("plan");
        assert_eq!(plan.uid, DEFAULT_CELL_UID);
        assert!(plan.envs.iter().any(|e| e.to_str() == Ok("HOME=/home/parser")) && !plan.seccomp.is_empty());
        assert_eq!(plan.args[1].to_str(), Ok(CELL_INPUT));
        assert!(plan.ops.iter().any(|o| matches!(o, Op::Proc(_))) && plan.ops.iter().any(|o| matches!(o, Op::Dir(..))));
        assert_eq!(plan.ops.iter().filter(|o| matches!(o, Op::Tmpfs(..))).count(), 4);
        assert!(plan.ops.iter().any(|o| matches!(o, Op::File { dst, exec: true, .. } if dst.to_str().map(|s| s.ends_with("/bin/true")).unwrap_or(false))));
        assert_eq!(plan.ops.iter().filter(|o| matches!(o, Op::File { src, .. } if src.to_str().map(|s| s.starts_with("/dev/")).unwrap_or(false))).count(), 3);
        let s2 = spec(&td, "/bin/true", vec!["/bin/true".into(), "{export}".into()]);
        assert_eq!(build_args(&s2).unwrap()[1].to_str(), Ok("/proc/self/fd/3"));
        assert!(plan.input_target.to_str().unwrap().ends_with("/input/document.bin"));
    }
    /// Environment gate: verified root + pid/mount namespace capability, else documented SKIP.
    fn env_ready() -> bool {
        if unsafe { libc::geteuid() } != 0 { eprintln!("SKIP root_gated_namespace_isolation_and_kill: requires root (EUID != 0)"); return false; }
        let pid = unsafe { libc::fork() };
        if pid == 0 { unsafe { libc::_exit(if libc::unshare(libc::CLONE_NEWPID | libc::CLONE_NEWNS) == 0 { 0 } else { 1 }) } }
        let mut st: libc::c_int = 0; let ok = unsafe { libc::waitpid(pid, &mut st, 0) } == pid && libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0;
        if !ok { eprintln!("SKIP root_gated_namespace_isolation_and_kill: CLONE_NEWPID/CLONE_NEWNS unavailable"); }
        ok
    }
    /// Root-gated integration test (WSL: `sudo -n cargo test ... -- --ignored`).
    #[test]
    #[ignore = "requires root + mount/pid/net namespace capabilities"]
    fn root_gated_namespace_isolation_and_kill() {
        if !env_ready() { return; }
        let td = TempDir::new("sandbox-root").expect("tempdir");
        let (mut s, _export) = with_export(&td, spec(&td, "/bin/sleep", vec!["/bin/sleep".into(), "30".into()]));
        s.root_dir = td.child("cell-root");
        let h = match spawn(&s) {
            Ok(h) => h,
            Err(e) => panic!("spawn failed (required root/namespace capability missing): {}", e.as_str()),
        };
        let pid = h.pid; assert!(pid > 0);
        for ns in ["mnt", "net", "pid", "ipc", "uts"] {
            assert_ne!(std::fs::read_link(format!("/proc/{pid}/ns/{ns}")).ok(), std::fs::read_link(format!("/proc/self/ns/{ns}")).ok(), "ns {ns} not separated");
        }
        let root = PathBuf::from(format!("/proc/{pid}/root"));
        assert!(root.join("home/parser").is_dir() && !root.join("home").join(std::env::var("SUDO_USER").unwrap_or_else(|_| "operator".into())).exists() && !root.join("etc/shadow").exists());
        assert_eq!(std::fs::metadata(root.join("input/document.bin")).map(|m| m.len()).ok(), Some(5));
        let netdev = std::fs::read_to_string(format!("/proc/{pid}/net/dev")).unwrap_or_default();
        assert!(netdev.contains("lo:") && !netdev.contains("eth0"), "interfaces visible: {netdev}");
        assert_eq!(kill(&h), Ok(()));
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "cell survived kill");
        let td2 = TempDir::new("sandbox-cat").expect("tempdir");
        let (mut c, _e2) = with_export(&td2, spec(&td2, "/bin/cat", vec!["/bin/cat".into(), "{input}".into()]));
        c.root_dir = td2.child("cell-root");
        let h2 = spawn(&c).expect("spawn cat");
        let mut status: libc::c_int = 0;
        assert_eq!(unsafe { libc::waitpid(h2.pid, &mut status, 0) }, h2.pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "cat could not read {{input}}: status={status}");
        assert_eq!(kill(&h2), Ok(()));
    }
}
