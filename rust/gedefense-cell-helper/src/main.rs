//! `gedefense-cell-helper` — privileged ephemeral parser-cell helper (P2-T1).
//!
//! VGTGC2 listener (docs/POINT2-PARSER-CELLS.md §3): owns cell lifecycle,
//! cgroups, TTL burn, sealed-export brokering and the burn ledger.  Go-Control
//! stays unprivileged; only `sandbox.rs`/`seccomp.rs` (P2-T2) spawn cells.
//! Safety: no secret is logged, requests are authenticated (HMAC + SO_PEERCRED
//! + ±30 s + replay cache), responses are bounded, `--check` has no side effects.
mod config;
mod export;
mod lifecycle;
mod protocol;
mod sandbox;
mod seccomp;
mod types;
use std::io::{BufRead, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::lifecycle::{CellRegistry, CreateRequest, MonotonicTimer, TimeSample};
use crate::protocol::{Command, ReplayCache, Request};
use crate::types::*;
const DEFAULT_SOCKET: &str = "/run/vgt-gedefense/cell-helper.sock";
const DEFAULT_KEY: &str = "/etc/vgt/gedefense/secrets/cell-helper.key";
const DEFAULT_PROFILES: &str = "/etc/vgt/gedefense/parser-profiles.conf";
const DEFAULT_INPUTS: &str = "/var/lib/vgt/gedefense/parser-inputs";
const DEFAULT_EXPORTS: &str = "/var/lib/vgt/gedefense/parser-exports";
const DEFAULT_LEDGER: &str = "/var/lib/vgt/gedefense/parser-burn-ledger.jsonl";
const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup/vgt-cells";
const DEFAULT_CELL_ROOT: &str = "/run/vgt-gedefense/cells";
const DEFAULT_MAX_CELLS: usize = 16;
const CONTROL_USER: &str = "gedefense";
static SHUTDOWN: AtomicBool = AtomicBool::new(false);
/// Fully resolved CLI configuration.
#[derive(Clone, Debug)]
pub struct Cli {
    pub socket: PathBuf,
    pub key_file: PathBuf,
    pub profiles: PathBuf,
    pub staging_inputs: PathBuf,
    pub staging_exports: PathBuf,
    pub ledger: PathBuf,
    pub cgroup_root: PathBuf,
    pub cell_root: PathBuf,
    pub max_cells: usize,
    pub peer_uid: Option<u32>,
}
impl Default for Cli {
    fn default() -> Self {
        Cli {
            socket: DEFAULT_SOCKET.into(), key_file: DEFAULT_KEY.into(), profiles: DEFAULT_PROFILES.into(),
            staging_inputs: DEFAULT_INPUTS.into(), staging_exports: DEFAULT_EXPORTS.into(),
            ledger: DEFAULT_LEDGER.into(), cgroup_root: DEFAULT_CGROUP_ROOT.into(),
            cell_root: DEFAULT_CELL_ROOT.into(), max_cells: DEFAULT_MAX_CELLS, peer_uid: None,
        }
    }
}
fn usage() -> String {
    format!("gedefense-cell-helper {}\n--socket <path> --key-file <path> --profiles <path> \
             --staging-inputs <path> --staging-exports <path> --ledger <path> --cgroup-root <path> \
             --cell-root <path> --max-cells <1..=64> --peer-uid <uid> --check", env!("CARGO_PKG_VERSION"))
}
/// Parse argv (without program name). Reject-not-repair: unknown args and
/// out-of-range values are hard errors (returns usage text for `--help`).
pub fn parse_args(args: &[String]) -> Result<(Cli, bool), String> {
    let mut cli = Cli::default();
    let mut check = false;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--check" { check = true; i += 1; continue; }
        if arg == "--help" || arg == "-h" { return Err(usage()); }
        let (name, inline) = match arg.split_once('=') { Some((n, v)) => (n, Some(v.to_string())), None => (arg.as_str(), None) };
        if !matches!(name, "--socket" | "--key-file" | "--profiles" | "--staging-inputs" | "--staging-exports"
            | "--ledger" | "--cgroup-root" | "--cell-root" | "--max-cells" | "--peer-uid") {
            return Err(format!("unknown argument: {}", arg));
        }
        let value = match inline { Some(v) => v, None => { i += 1; args.get(i).cloned().ok_or_else(|| format!("missing value for {}", name))? } };
        match name {
            "--socket" => cli.socket = value.into(),
            "--key-file" => cli.key_file = value.into(),
            "--profiles" => cli.profiles = value.into(),
            "--staging-inputs" => cli.staging_inputs = value.into(),
            "--staging-exports" => cli.staging_exports = value.into(),
            "--ledger" => cli.ledger = value.into(),
            "--cgroup-root" => cli.cgroup_root = value.into(),
            "--cell-root" => cli.cell_root = value.into(),
            "--max-cells" => {
                cli.max_cells = value.parse::<usize>().ok().filter(|n| (1..=MAX_ACTIVE_CELLS).contains(n))
                    .ok_or_else(|| format!("invalid --max-cells: {}", value))?;
            }
            "--peer-uid" => cli.peer_uid = Some(value.parse::<u32>().map_err(|_| format!("invalid --peer-uid: {}", value))?),
            _ => unreachable!(),
        }
        i += 1;
    }
    Ok((cli, check))
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cli, check) = match parse_args(&args) {
        Ok(v) => v,
        Err(msg) => { eprintln!("{}", msg); std::process::exit(2); }
    };
    std::process::exit(if check { run_check(&cli) } else { run_service(cli) });
}
// ---- --check / capability + cgroup probes --------------------------------
static CGROUP_PROBE_OK: AtomicBool = AtomicBool::new(false);
/// Files the kernel exposes in every non-root cgroup. `cgroup.kill` is
/// `CFTYPE_NOT_ON_ROOT` (never on `/sys/fs/cgroup` itself), so the probe runs
/// against a throwaway child of the dedicated `--cgroup-root`.
const CGROUP_PROBE_FILES: [&str; 3] = ["cgroup.kill", "cgroup.freeze", "cgroup.procs"];
/// Operator-facing `--check` failure (diagnostic codes; the VGTGC2 wire code
/// list stays closed — these strings are never sent to Go-Control).
struct CheckFailure { code: &'static str, detail: String }
impl CheckFailure {
    fn new(code: &'static str, detail: impl Into<String>) -> Self { CheckFailure { code, detail: detail.into() } }
    fn wire(code: ErrorCode) -> Self { CheckFailure::new(code.as_str(), String::new()) }
}
fn missing_cgroup_files(dir: &Path) -> Vec<&'static str> {
    CGROUP_PROBE_FILES.iter().copied().filter(|f| !dir.join(f).is_file()).collect()
}
/// Probe the dedicated (non-root) cgroup root: create a throwaway child, verify
/// cgroup.kill/freeze/procs and always rmdir it (side-effect free on success).
fn probe_cgroup_root(cgroup_root: &Path) -> Result<(), CheckFailure> {
    let md = std::fs::symlink_metadata(cgroup_root)
        .map_err(|_| CheckFailure::new("cgroup-root-missing", cgroup_root.display().to_string()))?;
    if !md.is_dir() || md.file_type().is_symlink() {
        return Err(CheckFailure::new("cgroup-root-invalid", cgroup_root.display().to_string()));
    }
    let probe = cgroup_root.join(format!("parser-probe-{}-{}", std::process::id(), lifecycle::mono_ms().unwrap_or(0)));
    if let Err(e) = std::fs::create_dir(&probe) {
        return Err(CheckFailure::new("cgroup-unavailable", format!("probe-mkdir: {}", e.kind())));
    }
    let missing = missing_cgroup_files(&probe);
    if std::fs::remove_dir(&probe).is_err() {
        return Err(CheckFailure::new("cgroup-unavailable", "probe-rmdir-failed"));
    }
    if !missing.is_empty() {
        return Err(CheckFailure::new("cgroup-unavailable", format!("missing={}", missing.join(","))));
    }
    CGROUP_PROBE_OK.store(true, Ordering::SeqCst);
    Ok(())
}
fn run_check(cli: &Cli) -> i32 {
    match check_all(cli) {
        Ok(report) => { println!("check-ok {}", report); 0 }
        Err(f) => { eprintln!("check-failed code={} detail={}", f.code, f.detail); 1 }
    }
}
fn check_all(cli: &Cli) -> Result<String, CheckFailure> {
    if !config::is_root() || !cfg!(target_arch = "x86_64") { return Err(CheckFailure::wire(ErrorCode::SandboxUnavailable)); }
    let caps = types::cap_effective().map_err(CheckFailure::wire)?;
    let missing = types::missing_capabilities(caps);
    if !missing.is_empty() { return Err(CheckFailure::new("sandbox-unavailable", format!("missing_caps={}", missing.join(",")))); }
    let gedefense_uid = match cli.peer_uid { Some(uid) => uid,
        None => lookup_user(CONTROL_USER).ok_or_else(|| CheckFailure::new("control-user-missing", CONTROL_USER))?.0 };
    config::load_key(&cli.key_file).map_err(|_| CheckFailure::new("key-invalid", cli.key_file.display().to_string()))?;
    let profiles = config::load_profiles(&cli.profiles).map_err(|_| CheckFailure::new("profiles-invalid", cli.profiles.display().to_string()))?;
    config::validate_staging_dirs(&cli.staging_inputs, &cli.staging_exports, gedefense_uid)
        .map_err(|_| CheckFailure::new("staging-invalid", "parser-inputs/-exports owner/mode"))?;
    if !["mnt", "pid", "net", "ipc", "uts"].iter().all(|ns| Path::new(&format!("/proc/self/ns/{}", ns)).exists()) {
        return Err(CheckFailure::new("namespace-unavailable", "missing /proc/self/ns"));
    }
    let controllers = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").unwrap_or_default();
    if !["memory", "pids", "cpu"].iter().all(|n| controllers.split_whitespace().any(|c| c == *n)) {
        return Err(CheckFailure::new("cgroup2-unavailable", "memory/pids/cpu controllers missing"));
    }
    probe_cgroup_root(&cli.cgroup_root)?;
    Ok(format!("abi={} profiles={} caps={}/{} cgroup_root={} cgroup2=ok namespaces=ok bpf_lsm={}",
        ABI, profiles.len(), types::required_capabilities().len(), types::required_capabilities().len(),
        cli.cgroup_root.display(), read_bpf_lsm()))
}
fn read_bpf_lsm() -> String {
    match std::fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(s) if s.split(',').any(|m| m.trim() == "bpf") => "active".into(),
        _ => "inactive".into(),
    }
}
/// Conservative advertisement: root + x86_64 + successful startup cgroup probe.
fn sandbox_available() -> bool {
    config::is_root() && cfg!(target_arch = "x86_64") && CGROUP_PROBE_OK.load(Ordering::SeqCst)
}
// ---- listener / service ---------------------------------------------------
fn lookup_user(name: &str) -> Option<(u32, u32)> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0i8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: valid C string and buffers; result points into `pw` on success.
    let rc = unsafe { libc::getpwnam_r(cname.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut result) };
    (rc == 0 && !result.is_null()).then_some((pw.pw_uid, pw.pw_gid))
}
fn setup_listener(path: &Path, owner_uid: u32, gid: u32) -> Result<UnixListener, ErrorCode> {
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).map_err(|_| ErrorCode::Internal)?; }
    match std::fs::symlink_metadata(path) {
        Ok(md) => {
            use std::os::unix::fs::FileTypeExt;
            if !md.file_type().is_socket() { return Err(ErrorCode::Internal); }
            std::fs::remove_file(path).map_err(|_| ErrorCode::Internal)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ErrorCode::Internal),
    }
    let listener = UnixListener::bind(path).map_err(|_| ErrorCode::Internal)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).map_err(|_| ErrorCode::Internal)?;
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| ErrorCode::Internal)?;
    // SAFETY: valid NUL-terminated path; chown(2) result is checked.
    if unsafe { libc::chown(cpath.as_ptr(), owner_uid, gid) } != 0 { return Err(ErrorCode::Internal); }
    Ok(listener)
}
fn run_service(cli: Cli) -> i32 {
    match service_main(cli) {
        Ok(()) => 0,
        Err(code) => { eprintln!("service-failed code={}", code.as_str()); 1 }
    }
}
fn service_main(cli: Cli) -> Result<(), ErrorCode> {
    if !config::is_root() { return Err(ErrorCode::SandboxUnavailable); }
    // Fail-closed privileged preconditions before any state is built.
    let caps = types::cap_effective().map_err(|_| ErrorCode::SandboxUnavailable)?;
    let missing = types::missing_capabilities(caps);
    if !missing.is_empty() { eprintln!("capability-check-failed missing={}", missing.join(",")); return Err(ErrorCode::SandboxUnavailable); }
    if let Err(f) = probe_cgroup_root(&cli.cgroup_root) {
        eprintln!("cgroup-check-failed code={} detail={}", f.code, f.detail);
        return Err(ErrorCode::SandboxUnavailable);
    }
    let (gedefense_uid, gedefense_gid) = lookup_user(CONTROL_USER).ok_or(ErrorCode::Internal)?;
    let peer_uid = cli.peer_uid.unwrap_or(gedefense_uid);
    let key = config::load_key(&cli.key_file)?;
    let profiles = config::load_profiles(&cli.profiles)?;
    config::validate_staging_dirs(&cli.staging_inputs, &cli.staging_exports, gedefense_uid)?;
    let mut registry = CellRegistry::new(cli.cgroup_root.clone(), cli.cell_root.clone(), cli.ledger.clone(),
        cli.max_cells, Some(gedefense_gid))?;
    let swept = registry.sweep_orphans(TimeSample::now())?;
    if swept > 0 { eprintln!("orphan-sweep: removed {} stale parser cgroups", swept); }
    let listener = setup_listener(&cli.socket, 0, gedefense_gid)?;
    eprintln!("gedefense-cell-helper {}: abi={} profiles={} sandbox={} bpf_lsm={} socket={} max_cells={}",
        env!("CARGO_PKG_VERSION"), ABI, profiles.len(), sandbox_available(), read_bpf_lsm(),
        cli.socket.display(), registry.max_cells());
    // SAFETY: plain extern "C" handler only stores an atomic flag.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
    let timer = MonotonicTimer::new()?;
    let mut replay = ReplayCache::new(protocol::REPLAY_CACHE_CAPACITY);
    let mut armed: Option<u64> = None;
    while !SHUTDOWN.load(Ordering::SeqCst) {
        let next = registry.next_deadline_mono();
        if next != armed {
            match next { Some(deadline) => timer.arm(deadline)?, None => timer.disarm()? }
            armed = next;
        }
        let timeout = match next {
            Some(deadline) => deadline.saturating_sub(lifecycle::mono_ms().unwrap_or(deadline)).min(1000) as i32,
            None => 1000,
        };
        let mut fds = [
            libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: timer.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        // SAFETY: poll(2) on two valid descriptors with an initialized array.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                || SHUTDOWN.load(Ordering::SeqCst) { continue; }
            return Err(ErrorCode::Internal);
        }
        if fds[1].revents & libc::POLLIN != 0 { let _ = timer.consume(); armed = None; }
        if fds[0].revents & libc::POLLIN != 0 {
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Err(code) = handle_connection(stream, &key, &profiles, &cli, &mut registry, peer_uid, &mut replay) {
                        eprintln!("connection-error code={}", code.as_str());
                    }
                }
                Err(e) => eprintln!("accept-error: {}", e),
            }
        }
            let burned = registry.expire_due(TimeSample::now());
        if burned > 0 { eprintln!("ttl-burn: {} cell(s)", burned); }
    }
    eprintln!("gedefense-cell-helper: shutdown requested");
    Ok(())
}
extern "C" fn on_signal(_sig: libc::c_int) { SHUTDOWN.store(true, Ordering::SeqCst); }
fn handle_connection(stream: UnixStream, key: &[u8], profiles: &[Profile], cli: &Cli,
    registry: &mut CellRegistry, peer_uid: u32, replay: &mut ReplayCache) -> Result<(), ErrorCode> {
    let peer = protocol::peer_uid(stream.as_raw_fd())?;
    let mut writer = stream.try_clone().map_err(|_| ErrorCode::Internal)?;
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
    let mut reader = std::io::BufReader::new(&stream);
    for _ in 0..protocol::MAX_REQUESTS_PER_CONNECTION {
        let line = match read_line_bounded(&mut reader)? { Some(line) => line, None => return Ok(()) };
        if line.len() > protocol::MAX_REQUEST_BYTES {
            return send_err(&mut writer, "0000000000000000", ErrorCode::BadRequest, key);
        }
        let line_str = String::from_utf8_lossy(&line);
        let id = protocol::request_id_or_zeros(&line_str);
        let req = match protocol::parse_request(&line_str, key, peer, peer_uid, lifecycle::wall_s(), replay) {
            Ok(req) => req,
            Err(code) => {
                send_err(&mut writer, &id, code, key)?;
                            if matches!(code, ErrorCode::BadMac | ErrorCode::Stale | ErrorCode::Replay) { return Ok(()); }
                continue;
            }
        };
        let reply = match dispatch(&req, profiles, cli, registry) {
            Ok(reply) => reply,
            Err(code) => { send_err(&mut writer, &req.id, code, key)?; continue; }
        };
        let response = match (&reply.raw, reply.fd) {
            (Some(raw), _) => protocol::encode_ok_raw(&req.id, raw, key)?,
            (None, _) => protocol::encode_ok(&req.id, &reply.fields, key)?,
        };
        match reply.fd {
            Some(fd) => protocol::send_fd(writer.as_raw_fd(), fd, &response)?,
            None => writer.write_all(&response).map_err(|_| ErrorCode::Internal)?,
        }
    }
    Ok(())
}
fn send_err(writer: &mut UnixStream, id: &str, code: ErrorCode, key: &[u8]) -> Result<(), ErrorCode> {
    writer.write_all(&protocol::encode_err(id, code, key)?).map_err(|_| ErrorCode::Internal)
}
/// Read one newline-terminated request line, bounded to `MAX_REQUEST_BYTES`+1.
fn read_line_bounded<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, ErrorCode> {
    let mut out: Vec<u8> = Vec::with_capacity(256);
    loop {
        let chunk = reader.fill_buf().map_err(|_| ErrorCode::BadRequest)?;
        if chunk.is_empty() { return Ok(if out.is_empty() { None } else { Some(out) }); }
        let pos = chunk.iter().position(|b| *b == b'\n');
        let take = pos.map(|p| p + 1).unwrap_or(chunk.len());
        if out.len() + take > protocol::MAX_REQUEST_BYTES + 1 { return Err(ErrorCode::BadRequest); }
        out.extend_from_slice(&chunk[..take]);
        reader.consume(take);
        if pos.is_some() { return Ok(Some(out)); }
    }
}
/// One protocol reply: bounded `k=v` fields or a raw payload (LIST), optional FD.
struct Reply { fields: Vec<(&'static str, String)>, raw: Option<Vec<u8>>, fd: Option<RawFd> }
impl Reply {
    fn fields(fields: Vec<(&'static str, String)>) -> Reply { Reply { fields, raw: None, fd: None } }
}
fn dispatch(req: &Request, profiles: &[Profile], cli: &Cli, registry: &mut CellRegistry) -> Result<Reply, ErrorCode> {
    let num = |name: &str| -> Result<u64, ErrorCode> { req.get(name)?.parse::<u64>().map_err(|_| ErrorCode::BadRequest) };
    match req.command {
        Command::CellCapabilities => Ok(Reply::fields(Capabilities {
            sandbox: sandbox_available(),
            profiles: profiles.iter().map(|p| p.id.clone()).collect(),
            max_concurrent: registry.max_cells(), max_input_bytes: HARD_MAX_INPUT_BYTES,
            max_export_bytes: HARD_MAX_EXPORT_BYTES, ttl_max_seconds: MAX_TTL_SECONDS, bpf_lsm: read_bpf_lsm(),
        }.payload_fields())),
        Command::CellCreate => {
            let create = CreateRequest {
                profile_id: req.get("profile")?.to_string(), input_token: req.get("input_token")?.to_string(),
                input_sha256: req.get("input_sha256")?.to_string(), input_size: num("input_size")?,
                ttl_seconds: num("ttl_seconds")?, max_rss_bytes: num("max_rss_bytes")?, max_pids: num("max_pids")?,
            };
            let uid = lookup_user(CONTROL_USER).map(|(uid, _)| uid).ok_or(ErrorCode::Internal)?;
            let record = registry.create(profiles, &create, &cli.staging_inputs, &cli.staging_exports, uid, TimeSample::now())?;
            Ok(Reply::fields(vec![
                ("uuid", record.uuid), ("generation", record.generation.to_string()),
                ("cgroup_id", record.cgroup_id.to_string()), ("cgroup_path", record.cgroup_path.display().to_string()),
                ("pid", record.pid.to_string()), ("expires_at", record.expires_at.to_string()),
                ("sandbox", "true".to_string()), ("netns", "true".to_string()),
            ]))
        }
        Command::CellList => {
            let rows: Vec<Vec<(&str, String)>> = registry.list().into_iter().map(|r| vec![
                ("uuid", r.uuid), ("generation", r.generation.to_string()), ("cgroup_id", r.cgroup_id.to_string()),
                ("profile", r.profile), ("state", r.state.as_str().to_string()),
                ("expires_at", r.expires_at.to_string()), ("pid", r.pid.to_string()),
                ("export_size", r.export_size.to_string()),
            ]).collect();
            Ok(Reply { fields: Vec::new(), raw: Some(protocol::encode_list_payload(&rows)?), fd: None })
        }
        Command::CellFreeze => {
            registry.freeze(req.get("uuid")?, num("generation")?, num("cgroup_id")?)?;
            Ok(Reply::fields(vec![("state", "applied".to_string())]))
        }
        Command::CellUnfreeze => {
            registry.unfreeze(req.get("uuid")?, num("generation")?, num("cgroup_id")?)?;
            Ok(Reply::fields(vec![("state", "deleted".to_string())]))
        }
        Command::CellBurn => {
            let meta = registry.burn(req.get("uuid")?, num("generation")?, num("cgroup_id")?,
                req.get("evidence_id")?, req.get("reason")?, TimeSample::now())?;
            Ok(Reply::fields(vec![("burned", "true".to_string()),
                ("export_size", meta.size.to_string()), ("export_sha256", meta.sha256)]))
        }
        Command::CellExportRead => {
            let (fd, meta) = registry.export_read(req.get("uuid")?, num("generation")?)?;
            Ok(Reply { fields: vec![("size", meta.size.to_string()), ("sha256", meta.sha256), ("type", meta.kind)], raw: None, fd: Some(fd) })
        }
        Command::CellHealth => Ok(Reply::fields(registry.health().payload_fields())),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_support::TempDir;
    fn args(list: &[&str]) -> Vec<String> { list.iter().map(|s| s.to_string()).collect() }
    #[test]
    fn cli_defaults_flags_and_rejections() {
        let (cli, check) = parse_args(&args(&[])).unwrap();
        assert!(!check && cli.socket == PathBuf::from(DEFAULT_SOCKET) && cli.max_cells == DEFAULT_MAX_CELLS);
        let (cli, check) = parse_args(&args(&["--check", "--socket=/tmp/x.sock", "--max-cells", "8", "--peer-uid=1234", "--cgroup-root", "/sys/fs/cgroup/vgt-cells"])).unwrap();
        assert!(check && cli.socket == PathBuf::from("/tmp/x.sock") && cli.max_cells == 8 && cli.peer_uid == Some(1234));
        for bad in [vec!["--evil"], vec!["--max-cells", "0"], vec!["--max-cells", "65"], vec!["--max-cells", "x"],
            vec!["--socket"], vec!["--peer-uid", "-1"], vec!["stray"]] {
            assert!(parse_args(&args(&bad)).is_err(), "should reject {:?}", bad);
        }
    }
    #[test]
    fn check_and_cgroup_probe_are_fail_closed_and_side_effect_free() {
        let td = TempDir::new("main-check").unwrap();
        let cli = Cli { key_file: td.child("missing.key"), profiles: td.child("missing.conf"),
            staging_inputs: td.child("in"), staging_exports: td.child("out"), ..Cli::default() };
        let err = check_all(&cli).err().expect("check must fail");
        if !config::is_root() { assert_eq!(err.code, "sandbox-unavailable"); }
        assert!(!td.child("in").exists() && !td.child("out").exists());
        assert!(matches!(read_bpf_lsm().as_str(), "active" | "inactive"));
        // cgroup probe: missing root -> clear cgroup-root-missing (no silent OK)
        assert_eq!(probe_cgroup_root(&td.child("nope")).err().unwrap().code, "cgroup-root-missing");
        // fake root: child cgroup gets no kernel files -> cgroup-unavailable
        assert_eq!(probe_cgroup_root(&td.path).err().unwrap().code, "cgroup-unavailable");
        assert!(!std::fs::read_dir(&td.path).unwrap().any(|e| {
            e.map(|e| e.file_name().to_string_lossy().starts_with("parser-probe-")).unwrap_or(false)
        }));
        // pure probe logic: required files present -> Ok; cgroup.kill missing -> list
        let fake = td.child("fake-cgroup");
        std::fs::create_dir(&fake).unwrap();
        for f in CGROUP_PROBE_FILES { std::fs::write(fake.join(f), "1").unwrap(); }
        assert!(missing_cgroup_files(&fake).is_empty());
        std::fs::remove_file(fake.join("cgroup.kill")).unwrap();
        assert_eq!(missing_cgroup_files(&fake), vec!["cgroup.kill"]);
        // the kernel root cgroup never exposes cgroup.kill (CFTYPE_NOT_ON_ROOT)
        if Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
            assert!(missing_cgroup_files(Path::new("/sys/fs/cgroup")).contains(&"cgroup.kill"));
        }
    }
    #[test]
    fn read_line_bounded_limits_and_terminates() {
        let mut input = b"one\ntwo\n".to_vec();
        input.extend(vec![b'x'; protocol::MAX_REQUEST_BYTES + 5]);
        let mut cursor = std::io::Cursor::new(input);
        assert_eq!(read_line_bounded(&mut cursor).unwrap(), Some(b"one\n".to_vec()));
        assert_eq!(read_line_bounded(&mut cursor).unwrap(), Some(b"two\n".to_vec()));
        assert_eq!(read_line_bounded(&mut cursor), Err(ErrorCode::BadRequest));
        assert_eq!(read_line_bounded(&mut std::io::Cursor::new(Vec::new())).unwrap(), None);
    }
    #[test]
    fn listener_socket_is_0660_and_stale_socket_replaced() {
        use std::os::unix::fs::MetadataExt;
        let td = TempDir::new("main-sock").unwrap();
        let path = td.child("helper.sock");
        let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let listener = setup_listener(&path, euid, egid).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o660);
        drop(listener);
        setup_listener(&path, euid, egid).unwrap(); // stale socket replaced
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"x").unwrap();
        assert_eq!(setup_listener(&path, euid, egid).err(), Some(ErrorCode::Internal));
    }
    fn test_registry(td: &TempDir) -> CellRegistry {
        std::fs::create_dir(td.child("cgroup")).unwrap();
        CellRegistry::new(td.child("cgroup"), td.child("cells"), td.child("ledger"), 4, None).unwrap()
    }
    fn request(command: Command, fields: &[(&str, String)]) -> Request {
        Request { id: "00112233445566aa".into(), ts: lifecycle::wall_s(), command,
            fields: fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() }
    }
    #[test]
    fn dispatch_capabilities_health_and_closed_errors() {
        let td = TempDir::new("main-dispatch").unwrap();
        let mut reg = test_registry(&td);
        let cli = Cli { staging_inputs: td.child("in"), staging_exports: td.child("out"), ..Cli::default() };
        let caps = dispatch(&request(Command::CellCapabilities, &[]), &[], &cli, &mut reg).unwrap();
        assert_eq!(caps.fields.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            vec!["abi", "sandbox", "profiles", "max_concurrent", "input_bytes", "export_bytes", "ttl_max", "bpf_lsm"]);
        assert_eq!(caps.fields[0].1, ABI);
        assert_eq!(dispatch(&request(Command::CellHealth, &[]), &[], &cli, &mut reg).unwrap().fields[0], ("state", "ok".to_string()));
        assert_eq!(dispatch(&request(Command::CellExportRead, &[("uuid", "ab".repeat(16)), ("generation", "1".into())]), &[], &cli, &mut reg).err(), Some(ErrorCode::UnknownCell));
        assert_eq!(dispatch(&request(Command::CellFreeze, &[("uuid", "ab".repeat(16)), ("generation", "1".into()), ("cgroup_id", "1".into())]), &[], &cli, &mut reg).err(), Some(ErrorCode::UnknownCell));
        let key = [9u8; 32];
        let line = protocol::encode_ok("00112233445566aa", &[("state", "ok".to_string())], &key).unwrap();
        assert_eq!(protocol::parse_response(std::str::from_utf8(&line).unwrap(), &key).unwrap().fields["state"], "ok");
        let err = protocol::encode_err("00112233445566aa", ErrorCode::BadRequest, &key).unwrap();
        assert_eq!(protocol::parse_response(std::str::from_utf8(&err).unwrap(), &key).unwrap().fields["code"], "bad-request");
        let _ = lookup_user(CONTROL_USER);
        assert_eq!(lookup_user("definitely-not-a-real-user-gd"), None);
    }
}
