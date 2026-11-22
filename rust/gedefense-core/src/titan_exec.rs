//! Point 1 (§5/§6): pure Titan exec-gate helpers for the privileged core.
//!
//! Owns the testable half of `docs/POINT1-TITAN-EXEC-GATE.md`: the LSM
//! activation probe (§6, token `bpf` in `/sys/kernel/security/lsm`), the
//! bounded in-RAM policy/scope store, the fd-safe executable-path resolver
//! (`O_PATH|O_NOFOLLOW` + `fstat`), base64 batch decoding (§5), §4 map
//! encoders, §3.3 event text wire, §5 health/status formats and the `PING`
//! status token. `main.rs` validates completely before its first map write and
//! keeps all map/ring I/O.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use gedefense_common::{
    TitanExecEvent, TITAN_EXEC_MODE_OFF, TITAN_EXEC_MODE_UNTRUSTED, TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW,
    TITAN_EXEC_SCOPE_MODE_MAX,
};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

/// §5 `TITAN_EXEC_VERSION`.
pub const TITAN_EXEC_VERSION: &str = "titan-exec-v1";
/// §6 store bounds: policy entries and per-cgroup scopes.
pub const TITAN_EXEC_MAX_POLICY_ENTRIES: usize = 65536;
pub const TITAN_EXEC_MAX_SCOPES: usize = 4096;
/// §5 caps: path bytes, decoded batch bytes/paths, batch token, events, payload.
pub const TITAN_EXEC_MAX_PATH_BYTES: usize = 2048;
pub const TITAN_EXEC_MAX_BATCH_BYTES: usize = 2048;
pub const TITAN_EXEC_MAX_BATCH_PATHS: usize = 256;
pub const TITAN_EXEC_MAX_BATCH_TOKEN_BYTES: usize = 4096;
pub const TITAN_EXEC_MAX_EVENTS_PER_RESPONSE: usize = 8;
pub const TITAN_EXEC_MAX_PAYLOAD_BYTES: usize = 2048;
/// §4 policy value: only `action=1 (ALLOW)` exists; flag bit0 = REQUIRE_CTIME.
pub const TITAN_EXEC_ALLOW_ACTION: u8 = 1;
pub const TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME: u8 = 1 << 0;
/// §5 `TITAN_EXEC_SET_GLOBAL` flags: bit0 REQUIRE_CTIME.
pub const TITAN_EXEC_GLOBAL_FLAG_REQUIRE_CTIME: u8 = 1 << 0;
/// §4 STATE word flag bits 40..47: bit0 offsets_valid, bit1 lsm_active,
/// bit2 ctime_check_enabled.
pub const TITAN_EXEC_STATE_FLAG_OFFSETS_VALID: u8 = 1 << 0;
pub const TITAN_EXEC_STATE_FLAG_LSM_ACTIVE: u8 = 1 << 1;
pub const TITAN_EXEC_STATE_FLAG_CTIME_CHECK: u8 = 1 << 2;
/// §4 `TITAN_EXEC_MODE` value: mode in bits 2..3, scope flags in bit0.
pub const TITAN_EXEC_SCOPE_MODE_SHIFT: u8 = 2;
pub const TITAN_EXEC_SCOPE_FLAGS_KNOWN: u8 = TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW;
/// §5 error for `SET_GLOBAL mode>0` while the kernel gate cannot enforce.
pub const ENFORCEMENT_UNAVAILABLE: &str = "enforcement-unavailable";
/// §6 LSM activation probe path.
pub const LSM_LIST_PATH: &str = "/sys/kernel/security/lsm";
/// §5 batch response: no rejected path.
pub const BATCH_ERROR_NONE: &str = "none";

/// §6 pure activation probe: `/sys/kernel/security/lsm` must list token `bpf`
/// (comma-separated, whitespace tolerated, case-sensitive, repeats harmless).
pub fn bpf_lsm_active_from_list(list: &str) -> bool {
    list.split(',').any(|token| token.trim() == "bpf")
}

/// Reads the activation probe file; unreadable is `Err` (caller reports
/// `inactive` and attaches nothing instead of guessing).
pub fn bpf_lsm_active_from_sys_fs() -> Result<bool, String> {
    let mut list = String::new();
    std::fs::File::open(LSM_LIST_PATH)
        .and_then(|file| file.take(4096).read_to_string(&mut list))
        .map_err(|error| format!("read {LSM_LIST_PATH}: {error}"))?;
    Ok(bpf_lsm_active_from_list(&list))
}

fn decimal(token: &str) -> Result<u64, String> {
    if token.is_empty() || token.len() > 20 || !token.bytes().all(|b| b.is_ascii_digit()) {
        return Err("titan-exec argument is not a plain decimal integer".to_owned());
    }
    token
        .parse::<u64>()
        .map_err(|_| "titan-exec argument is out of range".to_owned())
}

pub fn parse_u8(token: &str) -> Result<u8, String> {
    u8::try_from(decimal(token)?).map_err(|_| "titan-exec argument is out of range".to_owned())
}

/// §5 mode `0..=4` (OFF/OBSERVE/CONTAIN/STRICT/UNTRUSTED). UNTRUSTED is a
/// global-only mode and extends CONTAIN with the drop-root/owner gates; a
/// per-cgroup scope cannot carry it (the scope value has two mode bits), so
/// [`parse_scope_mode`] rejects it there instead of silently truncating it.
pub fn parse_mode(token: &str) -> Result<u8, String> {
    let mode = parse_u8(token)?;
    if mode > TITAN_EXEC_MODE_UNTRUSTED {
        return Err("titan-exec mode is not 0..4".to_owned());
    }
    Ok(mode)
}

/// §5 `SCOPE_SET` mode `0..=3` (the scope value packs the mode into bits 2..=3).
pub fn parse_scope_mode(token: &str) -> Result<u8, String> {
    let mode = parse_mode(token)?;
    if mode > TITAN_EXEC_SCOPE_MODE_MAX {
        return Err("titan-exec scope mode is not 0..3".to_owned());
    }
    Ok(mode)
}

/// §5 `SET_GLOBAL` flags: bit0 REQUIRE_CTIME, no unknown bits.
pub fn parse_global_flags(token: &str) -> Result<u8, String> {
    let flags = parse_u8(token)?;
    if flags & !TITAN_EXEC_GLOBAL_FLAG_REQUIRE_CTIME != 0 {
        return Err("titan-exec global flags contain unknown bits".to_owned());
    }
    Ok(flags)
}

/// §5 `SCOPE_SET` flags: bit0 JIT_ALLOW, no unknown bits.
pub fn parse_scope_flags(token: &str) -> Result<u8, String> {
    let flags = parse_u8(token)?;
    if flags & !TITAN_EXEC_SCOPE_FLAGS_KNOWN != 0 {
        return Err("titan-exec scope flags contain unknown bits".to_owned());
    }
    Ok(flags)
}

/// §5 `SCOPE_SET`/`SCOPE_DEL` cgroup id: decimal, non-zero.
pub fn parse_scope_cgroup(token: &str) -> Result<u64, String> {
    match decimal(token)? {
        0 => Err("titan-exec cgroup id must be non-zero".to_owned()),
        value => Ok(value),
    }
}

/// §5 `ALLOW_DEL` device number: decimal u32, non-zero.
pub fn parse_policy_dev(token: &str) -> Result<u32, String> {
    match u32::try_from(decimal(token)?).map_err(|_| "titan-exec dev is out of range")? {
        0 => Err("titan-exec dev must be non-zero".to_owned()),
        value => Ok(value),
    }
}

/// §5 `ALLOW_DEL` inode number: decimal u64, non-zero.
pub fn parse_policy_ino(token: &str) -> Result<u64, String> {
    match decimal(token)? {
        0 => Err("titan-exec ino must be non-zero".to_owned()),
        value => Ok(value),
    }
}

/// §4 mode text used by `PING` and `STATUS`.
pub fn mode_name(mode: u8) -> &'static str {
    match mode {
        TITAN_EXEC_MODE_OFF => "off",
        1 => "observe",
        2 => "contain",
        TITAN_EXEC_MODE_UNTRUSTED => "untrusted",
        _ => "strict",
    }
}

/// §5/§6 `PING` suffix: honest `inactive` unless the hooks are really attached.
pub fn ping_titan_exec_token(enforcement_available: bool, mode: u8) -> &'static str {
    if enforcement_available {
        mode_name(mode)
    } else {
        "inactive"
    }
}

/// One `TITAN_EXEC_POLICY` entry (§4): ALLOW action, flags, ctime fingerprint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyEntry {
    pub action: u8,
    pub flags: u8,
    pub ctime_ns: u64,
}

/// Bounded in-RAM mirror of `TITAN_EXEC_POLICY` + `TITAN_EXEC_MODE` (§6).
#[derive(Default)]
pub struct TitanExecPolicy {
    entries: HashMap<(u32, u64), PolicyEntry>,
    scopes: HashMap<u64, u8>,
}

impl TitanExecPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn scope_count(&self) -> usize {
        self.scopes.len()
    }

    pub fn entry(&self, dev: u32, ino: u64) -> Option<PolicyEntry> {
        self.entries.get(&(dev, ino)).copied()
    }

    pub fn keys(&self) -> Vec<(u32, u64)> {
        self.entries.keys().copied().collect()
    }

    /// Inserts/updates one allow entry; `Ok(false)` means it already existed.
    pub fn insert(&mut self, dev: u32, ino: u64, entry: PolicyEntry) -> Result<bool, String> {
        if dev == 0 || ino == 0 {
            return Err("titan-exec policy identity is zero".to_owned());
        }
        if entry.action != TITAN_EXEC_ALLOW_ACTION {
            return Err("titan-exec policy action is not ALLOW".to_owned());
        }
        if !self.entries.contains_key(&(dev, ino)) && self.entries.len() >= TITAN_EXEC_MAX_POLICY_ENTRIES {
            return Err("titan-exec policy entry cap is reached".to_owned());
        }
        Ok(self.entries.insert((dev, ino), entry).is_none())
    }

    /// Removes one entry; the boolean reports whether it existed (DELETE is idempotent).
    pub fn remove(&mut self, dev: u32, ino: u64) -> bool {
        self.entries.remove(&(dev, ino)).is_some()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// §4 scope value write; the cap applies on first insert only.
    pub fn scope_set(&mut self, cgroup: u64, value: u8) -> Result<(), String> {
        if cgroup == 0 {
            return Err("titan-exec cgroup id must be non-zero".to_owned());
        }
        if !self.scopes.contains_key(&cgroup) && self.scopes.len() >= TITAN_EXEC_MAX_SCOPES {
            return Err("titan-exec scope cap is reached".to_owned());
        }
        self.scopes.insert(cgroup, value);
        Ok(())
    }

    /// Removes one scope; the boolean reports whether it existed (idempotent).
    pub fn scope_remove(&mut self, cgroup: u64) -> bool {
        self.scopes.remove(&cgroup).is_some()
    }
}

/// fd-verified executable identity (`fstat` of an `O_PATH|O_NOFOLLOW` fd).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecFileIdentity {
    pub dev: u32,
    pub ino: u64,
    pub ctime_ns: u64,
    pub mode: u32,
}

/// Why a path was not accepted for `ALLOW_ADD` (§5/§6); stable ASCII tokens
/// are returned verbatim in the `ALLOW_ADD_BATCH` response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathReject {
    Empty,
    TooLong,
    Nul,
    NotAbsolute,
    NotCanonical,
    Open,
    Symlink,
    NotRegular,
    NotExecutable,
    DeviceOutOfRange,
    ClockOutOfRange,
}

impl PathReject {
    pub fn token(self) -> &'static str {
        match self {
            PathReject::Empty => "empty", PathReject::TooLong => "too-long",
            PathReject::Nul => "nul", PathReject::NotAbsolute => "not-absolute",
            PathReject::NotCanonical => "not-canonical", PathReject::Open => "open-failed",
            PathReject::Symlink => "symlink", PathReject::NotRegular => "not-regular",
            PathReject::NotExecutable => "not-executable",
            PathReject::DeviceOutOfRange => "device-out-of-range",
            PathReject::ClockOutOfRange => "clock-out-of-range",
        }
    }
}
/// Pure §5 path validation: absolute, canonical (no `.`/`..`/`//`/trailing
/// slash), NUL-free, at most 2048 bytes, with a final file component.
pub fn validate_exec_path(path: &str) -> Result<(), PathReject> {
    if path.is_empty() {
        return Err(PathReject::Empty);
    }
    if path.len() > TITAN_EXEC_MAX_PATH_BYTES {
        return Err(PathReject::TooLong);
    }
    if path.contains('\0') {
        return Err(PathReject::Nul);
    }
    // No control characters: an executable path never contains a newline,
    // tab or other C0/DEL byte; the batch payload decodes to raw bytes.
    if path.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(PathReject::NotCanonical);
    }
    if !path.starts_with('/') {
        return Err(PathReject::NotAbsolute);
    }
    let mut file = false;
    for segment in path[1..].split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(PathReject::NotCanonical);
        }
        file = true;
    }
    if !file {
        return Err(PathReject::NotCanonical);
    }
    Ok(())
}

/// §6 fd-safe resolution: `O_PATH|O_NOFOLLOW` open, then `fstat` the very fd
/// (no second path walk, so a swapped path cannot change the identity).
pub fn resolve_exec_path(path: &str) -> Result<ExecFileIdentity, PathReject> {
    validate_exec_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| PathReject::Open)?;
    let metadata = file.metadata().map_err(|_| PathReject::Open)?;
    if metadata.file_type().is_symlink() {
        return Err(PathReject::Symlink);
    }
    if !metadata.is_file() {
        return Err(PathReject::NotRegular);
    }
    if metadata.mode() & 0o111 == 0 {
        return Err(PathReject::NotExecutable);
    }
    let dev = u32::try_from(metadata.dev()).map_err(|_| PathReject::DeviceOutOfRange)?;
    let seconds = u64::try_from(metadata.ctime()).map_err(|_| PathReject::ClockOutOfRange)?;
    let nanos = u64::try_from(metadata.ctime_nsec()).map_err(|_| PathReject::ClockOutOfRange)?;
    if nanos >= 1_000_000_000 {
        return Err(PathReject::ClockOutOfRange);
    }
    let ctime_ns = seconds
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanos))
        .ok_or(PathReject::ClockOutOfRange)?;
    Ok(ExecFileIdentity {
        dev,
        ino: metadata.ino(),
        ctime_ns,
        mode: metadata.mode(),
    })
}

/// §5 `ALLOW_ADD_BATCH`: base64url or standard base64 of newline-separated
/// absolute paths; decoded size ≤2048 B, ≤256 paths, one optional final
/// newline, no empty line. Every path is validated here (pure); resolution of
/// each identity happens per path in the caller.
pub fn decode_allow_batch(token: &str) -> Result<Vec<String>, String> {
    if token.is_empty() || token.len() > TITAN_EXEC_MAX_BATCH_TOKEN_BYTES {
        return Err("titan-exec batch token is empty or oversized".to_owned());
    }
    let mut decoded = None;
    for engine in [URL_SAFE_NO_PAD, URL_SAFE, STANDARD_NO_PAD, STANDARD] {
        if let Ok(bytes) = engine.decode(token) {
            decoded = Some(bytes);
            break;
        }
    }
    let decoded = decoded.ok_or("titan-exec batch is not base64")?;
    if decoded.len() > TITAN_EXEC_MAX_BATCH_BYTES {
        return Err("titan-exec batch exceeds the 2048-byte cap".to_owned());
    }
    let text = std::str::from_utf8(&decoded).map_err(|_| "titan-exec batch is not UTF-8")?;
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.is_empty() {
        return Err("titan-exec batch is empty".to_owned());
    }
    let mut paths = Vec::new();
    for line in body.split('\n') {
        if line.is_empty() {
            return Err("titan-exec batch contains an empty path".to_owned());
        }
        validate_exec_path(line).map_err(|reject| {
            format!("titan-exec batch path rejected: {}", reject.token())
        })?;
        if paths.len() >= TITAN_EXEC_MAX_BATCH_PATHS {
            return Err("titan-exec batch exceeds the 256-path cap".to_owned());
        }
        paths.push(line.to_owned());
    }
    Ok(paths)
}

/// §5 `ALLOW_ADD_BATCH` response: `added:<n>;rejected:<n>;error=<token>`.
pub fn encode_allow_batch_response(added: usize, rejected: usize, error: &str) -> String {
    format!("added:{added};rejected:{rejected};error={error}")
}

/// §3.3 one text record: 16 `:`-separated decimal fields plus `comm` hex.
pub fn encode_exec_event_text(event: &TitanExecEvent) -> String {
    let comm_len = event.comm.iter().position(|byte| *byte == 0).unwrap_or(event.comm.len());
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        event.cgroup_id,
        event.ts_ns,
        event.dev,
        event.inode_mode,
        event.ino,
        event.generation,
        event.pid,
        event.tgid,
        event.uid,
        event.gid,
        event.prot,
        event.f_flags,
        event.hook,
        event.action,
        event.reason,
        hex::encode(&event.comm[..comm_len])
    )
}

/// §3.3 batch: `empty` or `<dropped>|<record>[,<record>…]`, ≤8 records and
/// ≤2048 payload bytes; a truncation would be a silent loss, so it is an `Err`.
pub fn encode_exec_events_batch(records: &[String], dropped: u64) -> Result<String, String> {
    if records.len() > TITAN_EXEC_MAX_EVENTS_PER_RESPONSE {
        return Err("titan-exec event batch exceeds 8 records".to_owned());
    }
    let payload = if records.is_empty() {
        if dropped == 0 {
            "empty".to_owned()
        } else {
            format!("{dropped}|")
        }
    } else {
        format!("{dropped}|{}", records.join(","))
    };
    if payload.len() > TITAN_EXEC_MAX_PAYLOAD_BYTES {
        return Err("titan-exec event batch exceeds the response payload budget".to_owned());
    }
    Ok(payload)
}

/// §5 `TITAN_EXEC_HEALTH`: six per-CPU counter sums in fixed order.
pub fn encode_exec_health(counters: &[u64; 6]) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        counters[0], counters[1], counters[2], counters[3], counters[4], counters[5]
    )
}

// Status/state rendering lives in its own module (module size cap); re-exported
// here so the 	itan_exec:: call surface in main.rs is unchanged.
pub(crate) use crate::titan_status::{encode_exec_status, exec_state, StatusView};
#[cfg(test)]
pub(crate) use crate::titan_status::ExecState;
