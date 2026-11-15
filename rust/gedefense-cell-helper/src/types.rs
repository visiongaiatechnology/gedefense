//! Shared, bounded value types of the `gedefense-cell-helper` (contract with
//! the P2-T2 sandbox backend and the VGTGC2 wire layer).
//!
//! Everything crossing the wire or a syscall boundary has a hard cap; the error
//! code list is closed (POINT2 spec §3). No serde/TOML: see `protocol`/`config`.

use std::os::fd::RawFd;
use std::path::PathBuf;

pub const ABI: &str = "cell-runtime-v1";
#[allow(dead_code)]
pub const KEY_LEN: usize = 32;
pub const DEFAULT_CELL_UID: u32 = 65534; pub const DEFAULT_CELL_GID: u32 = 65534;
/// Hard admission cap for concurrent cells (spec §3: ≤64).
pub const MAX_ACTIVE_CELLS: usize = 64;
pub const HARD_MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;
pub const HARD_MAX_EXPORT_BYTES: u64 = 2 * 1024 * 1024;
pub const MIN_TTL_SECONDS: u64 = 5; pub const MAX_TTL_SECONDS: u64 = 3600;
pub const MAX_ARGV: usize = 32; pub const MAX_ENV_ALLOW: usize = 16;
pub const MAX_RETAINED_EXPORTS: usize = 16; pub const MAX_PROFILE_ID_LEN: usize = 64;

pub type ProfileId = String;

macro_rules! error_codes {
    ($( $variant:ident => $wire:literal ),* $(,)?) => {
        /// Closed error-code set from POINT2 spec §3 (wire string + short list).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum ErrorCode { $( $variant ),* }

        impl ErrorCode {
            pub const ALL: [ErrorCode; 18] = [ $( ErrorCode::$variant ),* ];
            pub fn as_str(self) -> &'static str { match self { $( ErrorCode::$variant => $wire ),* } }
            pub fn from_str(s: &str) -> Option<ErrorCode> {
                ErrorCode::ALL.iter().copied().find(|c| c.as_str() == s)
            }
            /// Display/X11 refusal maps onto the closed `capability-missing` code.
            pub fn display_unavailable() -> ErrorCode { ErrorCode::CapabilityMissing }
        }
    };
}

error_codes! {
    BadRequest => "bad-request", BadMac => "bad-mac", Stale => "stale", Replay => "replay",
    UnknownCommand => "unknown-command", CapabilityMissing => "capability-missing",
    ProfileUnknown => "profile-unknown", ProfileInvalid => "profile-invalid",
    InputInvalid => "input-invalid", InputMissing => "input-missing",
    SandboxUnavailable => "sandbox-unavailable", CellLimit => "cell-limit",
    UnknownCell => "unknown-cell", StaleGeneration => "stale-generation",
    ExportMissing => "export-missing", ExportOverflow => "export-overflow",
    BurnFailed => "burn-failed", Internal => "internal",
}

/// Package-managed parser profile (spec §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub id: ProfileId,
    /// Absolute, root-owned, non-symlink binary path (validated in `config`).
    pub binary: PathBuf,
    /// Lowercase hex SHA-256 of `binary` (64 chars).
    pub sha256: String,
    /// Full argv incl. `argv[0]`; at most one `{input}` placeholder.
    pub argv: Vec<String>,
    /// Environment variable NAMES that may be inherited (never values).
    pub env_allow: Vec<String>,
    pub wayland: bool,
    pub pipewire: bool,
    pub max_input_bytes: u64,
    pub max_export_bytes: u64,
    pub ttl_max_seconds: u64,
}

impl Profile {
    /// Structural validation only (filesystem/ownership checks live in `config`).
    pub fn validate(&self) -> Result<(), ErrorCode> {
        let ok = is_profile_id(&self.id)
            && self.binary.is_absolute()
            && !self.binary.as_os_str().is_empty()
            && is_hex(&self.sha256, 64)
            && !self.argv.is_empty()
            && self.argv.len() <= MAX_ARGV
            && self.argv.iter().all(|a| is_argv_value(a))
            && self.argv.iter().filter(|a| a.contains("{input}")).count() <= 1
            && self.env_allow.len() <= MAX_ENV_ALLOW
            && self.env_allow.iter().all(|e| is_env_name(e))
            && (1..=HARD_MAX_INPUT_BYTES).contains(&self.max_input_bytes)
            && (1..=HARD_MAX_EXPORT_BYTES).contains(&self.max_export_bytes)
            && (MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&self.ttl_max_seconds);
        if ok { Ok(()) } else { Err(ErrorCode::ProfileInvalid) }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputMeta {
    /// Lowercase hex token (32 chars) naming `<token>.bin`.
    pub token: String,
    /// Lowercase hex SHA-256 (64 chars).
    pub sha256: String,
    pub size: u64,
}

impl InputMeta {
    pub fn validate(&self, max_input_bytes: u64) -> Result<(), ErrorCode> {
        if !is_hex(&self.token, 32) || !is_hex(&self.sha256, 64) || self.size == 0
            || self.size > max_input_bytes || self.size > HARD_MAX_INPUT_BYTES {
            return Err(ErrorCode::InputInvalid);
        }
        Ok(())
    }
    /// The only accepted staging file name for this token.
    pub fn file_name(&self) -> String { format!("{}.bin", self.token) }
}

/// Client-supplied resource caps, clamped against profile/wire hard caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub ttl_seconds: u64,
    pub max_rss_bytes: u64,
    pub max_pids: u64,
    pub max_export_bytes: u64,
}

impl Limits {
    pub fn new(ttl_seconds: u64, max_rss_bytes: u64, max_pids: u64, max_export_bytes: u64) -> Self {
        Limits { ttl_seconds, max_rss_bytes, max_pids, max_export_bytes }
    }
    /// Clamp against profile + hard caps; never widens a client request.
    pub fn clamp_for(profile: &Profile, ttl_seconds: u64, max_rss_bytes: u64, max_pids: u64) -> Self {
        Limits {
            ttl_seconds: ttl_seconds.clamp(MIN_TTL_SECONDS, profile.ttl_max_seconds.min(MAX_TTL_SECONDS)),
            max_rss_bytes: max_rss_bytes.clamp(16 * 1024 * 1024, 4 * 1024 * 1024 * 1024),
            max_pids: max_pids.clamp(4, 256),
            max_export_bytes: profile.max_export_bytes.min(HARD_MAX_EXPORT_BYTES),
        }
    }
    pub fn validate(&self) -> Result<(), ErrorCode> {
        let ok = (MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&self.ttl_seconds)
            && self.max_rss_bytes > 0 && self.max_pids > 0
            && self.max_export_bytes > 0 && self.max_export_bytes <= HARD_MAX_EXPORT_BYTES;
        if ok { Ok(()) } else { Err(ErrorCode::BadRequest) }
    }
}

/// Everything the sandbox backend needs to spawn one cell (spec §4).
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct CellSpec {
    pub uuid: String,
    pub generation: u64,
    pub profile_id: ProfileId,
    pub binary: PathBuf,
    pub binary_sha256: String,
    /// Full argv incl. `argv[0]`; sandbox substitutes the `{input}` placeholder.
    pub argv: Vec<String>,
    pub env_allow: Vec<String>,
    pub wayland: bool,
    pub pipewire: bool,
    pub input_path: PathBuf,
    pub input_size: u64,
    pub input_sha256: String,
    pub input_token: String,
    /// Pre-opened write-only export FD (FD_CLOEXEC cleared; only write channel).
    pub export_fd: RawFd,
    pub export_path: PathBuf,
    pub limits: Limits,
    pub uid: u32,
    pub gid: u32,
    pub root_dir: PathBuf,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct CellHandle {
    /// Host-visible PID of the cell (PID 1 in its new PID namespace).
    pub pid: i32,
    pub uuid: String,
    pub generation: u64,
    pub cgroup_id: u64,
    pub cgroup_path: PathBuf,
    pub root_dir: PathBuf,
    pub export_fd: RawFd,
    pub export_path: PathBuf,
    pub started_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportMeta { pub size: u64, pub sha256: String, pub kind: String }

/// Lifecycle state machine (spec §6). `Requested`/`Spawned` document the full
/// transition sequence; `create` reports `Isolated` only after a successful spawn.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellState { Requested, Spawned, Isolated, Expiring, Burning, Burned, Failed }

impl CellState {
    pub fn as_str(self) -> &'static str {
        match self {
            CellState::Requested => "requested", CellState::Spawned => "spawned",
            CellState::Isolated => "isolated", CellState::Expiring => "expiring",
            CellState::Burning => "burning", CellState::Burned => "burned",
            CellState::Failed => "failed",
        }
    }
    pub fn from_str(s: &str) -> Option<CellState> {
        use CellState::*;
        [Requested, Spawned, Isolated, Expiring, Burning, Burned, Failed]
            .iter().copied().find(|c| c.as_str() == s)
    }
    pub fn is_terminal(self) -> bool { matches!(self, CellState::Burned | CellState::Failed) }
}

/// Public status record (`CELL_LIST`/reconciliation).
#[derive(Clone, Debug)]
pub struct CellRecord {
    pub uuid: String,
    pub generation: u64,
    pub profile: ProfileId,
    pub state: CellState,
    pub pid: i32,
    pub cgroup_id: u64,
    pub cgroup_path: PathBuf,
    pub created_at: u64,
    pub expires_at: u64,
    pub export_size: u64,
    pub export_sha256: String,
    pub burn_reason: String,
    pub evidence_id: String,
}

/// One durable burn-ledger line (own text format, `0x1f`-separated `k=v`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnLedgerEntry {
    pub ts: u64,
    pub uuid: String,
    pub generation: u64,
    pub cgroup_id: u64,
    pub profile: String,
    pub reason: String,
    pub export_size: u64,
    pub export_sha256: String,
    pub evidence_id: String,
    /// `burn` for policy/TTL burns, `orphan` for the startup sweep.
    pub kind: String,
}

const LEDGER_FIELDS: [&str; 10] = [
    "ts", "uuid", "generation", "cgroup_id", "profile", "reason", "export_size", "export_sha256",
    "evidence_id", "kind",
];

impl BurnLedgerEntry {
    /// Serialize as one bounded line, values sanitized to payload-safe chars.
    pub fn to_line(&self) -> String {
        let values = [
            self.ts.to_string(), token_or_dash(&self.uuid), self.generation.to_string(),
            self.cgroup_id.to_string(), token_or_dash(&self.profile), token_or_dash(&self.reason),
            self.export_size.to_string(), token_or_dash(&self.export_sha256),
            token_or_dash(&self.evidence_id), token_or_dash(&self.kind),
        ];
        let body: Vec<String> = LEDGER_FIELDS.iter().zip(values).map(|(k, v)| format!("{}={}", k, v)).collect();
        format!("{}\n", body.join("\u{1f}"))
    }

    /// Parse one ledger line (reconciliation tests).
    pub fn from_line(line: &str) -> Option<BurnLedgerEntry> {
        let parts: Vec<&str> = line.trim_end_matches('\n').split('\u{1f}').collect();
        if parts.len() != LEDGER_FIELDS.len() { return None; }
        let mut vals: Vec<&str> = Vec::with_capacity(parts.len());
        for (part, expected) in parts.iter().zip(LEDGER_FIELDS) {
            let (k, v) = part.split_once('=')?;
            if k != expected { return None; }
            vals.push(v);
        }
        let s = |v: &str| if v == "-" { String::new() } else { v.to_string() };
        Some(BurnLedgerEntry {
            ts: vals[0].parse().ok()?, uuid: s(vals[1]), generation: vals[2].parse().ok()?,
            cgroup_id: vals[3].parse().ok()?, profile: s(vals[4]), reason: s(vals[5]),
            export_size: vals[6].parse().ok()?, export_sha256: s(vals[7]),
            evidence_id: s(vals[8]), kind: s(vals[9]),
        })
    }
}

/// Helper health snapshot.
#[derive(Clone, Debug)]
pub struct Health {
    pub state: String,
    pub active_cells: usize,
    pub burned_total: u64,
    pub last_error: Option<String>,
    pub started_at: u64,
}

impl Health {
    pub fn healthy(active_cells: usize, burned_total: u64, started_at: u64) -> Self {
        Health { state: "ok".into(), active_cells, burned_total, last_error: None, started_at }
    }
    pub fn degraded(last_error: &str, burned_total: u64, started_at: u64) -> Self {
        Health { state: "degraded".into(), active_cells: 0, burned_total,
            last_error: Some(token_or_dash(last_error)), started_at }
    }
    pub fn payload_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("state", self.state.clone()), ("active_cells", self.active_cells.to_string()),
            ("burned_total", self.burned_total.to_string()),
            ("last_error", self.last_error.clone().unwrap_or_else(|| "none".into())),
            ("started_at", self.started_at.to_string()), ("abi", ABI.to_string()),
        ]
    }
}

/// Capability negotiation snapshot for `CELL_CAPABILITIES`.
#[derive(Clone, Debug)]
pub struct Capabilities {
    pub sandbox: bool,
    pub profiles: Vec<ProfileId>,
    pub max_concurrent: usize,
    pub max_input_bytes: u64,
    pub max_export_bytes: u64,
    pub ttl_max_seconds: u64,
    pub bpf_lsm: String,
}

impl Capabilities {
    pub fn payload_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("abi", ABI.to_string()), ("sandbox", self.sandbox.to_string()),
            ("profiles", self.profiles.join(",")), ("max_concurrent", self.max_concurrent.to_string()),
            ("input_bytes", self.max_input_bytes.to_string()),
            ("export_bytes", self.max_export_bytes.to_string()),
            ("ttl_max", self.ttl_max_seconds.to_string()), ("bpf_lsm", self.bpf_lsm.clone()),
        ]
    }
}

/// True when `s` is exactly `len` lowercase hex chars.
pub fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Payload values: `[A-Za-z0-9._:/+-]`, bounded, no whitespace/NUL.
pub fn is_payload_value(s: &str) -> bool {
    !s.is_empty() && s.len() <= 4096
        && s.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'/' | b'+' | b'-'))
}

fn is_profile_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_PROFILE_ID_LEN
        && s.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn is_argv_value(s: &str) -> bool {
    !s.is_empty() && s.len() <= 1024 && !s.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r' || b == 0x1f)
}

fn is_env_name(s: &str) -> bool {
    let syntax_ok = !s.is_empty() && s.len() <= 64
        && s.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'));
    if !syntax_ok || s.starts_with("LD_") {
        return false;
    }
    !matches!(
        s,
        "GCONV_PATH" | "GETCONF_DIR" | "HOSTALIASES" | "LOCALDOMAIN" | "LOCPATH"
            | "MALLOC_TRACE" | "MALLOC_CHECK_" | "NLSPATH" | "RESOLV_HOST_CONF"
            | "RES_OPTIONS" | "IFS" | "ENV" | "BASH_ENV"
    )
}

/// Ledger/sanitized-string helper: keep payload-safe chars, replace the rest.
pub fn token_or_dash(s: &str) -> String {
    let mut out: String = s.bytes().take(256)
        .filter_map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'/' | b'+' | b'-' => Some(b as char),
            _ => Some('-'),
        }).collect();
    if out.is_empty() { out.push('-'); }
    out
}

/// Helper capabilities (Unit `CapabilityBoundingSet`, spec §4.9; `CAP_CHOWN` for staging/export ownership).
pub const REQUIRED_CAPABILITIES: [(&str, u32); 6] = [
    ("CAP_SYS_ADMIN", 21), ("CAP_SETUID", 7), ("CAP_SETGID", 6),
    ("CAP_KILL", 5), ("CAP_SYS_RESOURCE", 24), ("CAP_CHOWN", 0),
];

pub fn required_capabilities() -> &'static [(&'static str, u32)] { &REQUIRED_CAPABILITIES }

/// Effective capability mask from `/proc/self/status` (`CapEff:` hex, unprivileged).
pub fn cap_effective() -> Result<u64, ErrorCode> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|_| ErrorCode::Internal)?;
    let line = status.lines().find(|l| l.starts_with("CapEff:")).ok_or(ErrorCode::Internal)?;
    let hex = line.split_whitespace().nth(1).ok_or(ErrorCode::Internal)?;
    u64::from_str_radix(hex, 16).map_err(|_| ErrorCode::Internal)
}

/// Pure decoder: required capability names missing from an effective mask.
pub fn missing_capabilities(cap_eff: u64) -> Vec<&'static str> {
    REQUIRED_CAPABILITIES.iter().filter(|(_, bit)| cap_eff & (1u64 << bit) == 0)
        .map(|(name, _)| *name).collect()
}

/// Fail-closed capability self-check for service start and `--check`.
pub fn check_required_capabilities() -> Result<(), ErrorCode> {
    if missing_capabilities(cap_effective()?).is_empty() { Ok(()) } else { Err(ErrorCode::SandboxUnavailable) }
}

#[cfg(test)]
pub mod test_support {
    use std::path::{Path, PathBuf};

    /// Minimal RAII temp directory (no external crate is available offline).
    pub struct TempDir { pub path: PathBuf }

    impl TempDir {
        pub fn new(tag: &str) -> Option<TempDir> {
            let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_nanos();
            let path = std::env::temp_dir().join(format!("gd-cell-{}-{}-{}", tag, std::process::id(), nanos));
            std::fs::create_dir_all(&path).ok()?;
            Some(TempDir { path })
        }
        pub fn child(&self, name: &str) -> PathBuf { self.path.join(name) }
        pub fn write(&self, name: &str, data: &[u8]) -> Option<PathBuf> {
            let p = self.child(name);
            std::fs::write(&p, data).ok()?;
            Some(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.path); }
    }

    pub fn exists(p: &Path) -> bool { p.exists() }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> Profile {
        Profile { id: "pdf-viewer".into(), binary: PathBuf::from("/usr/bin/pdftoppm"), sha256: "a".repeat(64),
            argv: vec!["/usr/bin/pdftoppm".into(), "{input}".into(), "/tmp/cell/out/".into()],
            env_allow: vec!["LANG".into()], wayland: false, pipewire: false,
            max_input_bytes: HARD_MAX_INPUT_BYTES, max_export_bytes: HARD_MAX_EXPORT_BYTES, ttl_max_seconds: 300 }
    }
    #[test]
    fn error_codes_closed_and_stable() {
        let mut seen = std::collections::HashSet::new();
        for code in ErrorCode::ALL {
            assert!(seen.insert(code.as_str()));
            assert_eq!(ErrorCode::from_str(code.as_str()), Some(code));
        }
        assert_eq!((seen.len(), ErrorCode::from_str("bad-code")), (18, None));
        assert_eq!(ErrorCode::display_unavailable(), ErrorCode::CapabilityMissing);
    }
    #[test]
    fn profile_input_limits_and_state_bounds() {
        assert_eq!(profile().validate(), Ok(()));
        for mutate in [
            (|p: &mut Profile| p.binary = PathBuf::from("rel/bin")), (|p: &mut Profile| p.sha256 = "A".repeat(64)),
            (|p: &mut Profile| p.argv = vec!["{input}".into(), "{input}".into()]),
            (|p: &mut Profile| p.max_input_bytes = HARD_MAX_INPUT_BYTES + 1)] {
            let mut p = profile(); mutate(&mut p); assert_eq!(p.validate(), Err(ErrorCode::ProfileInvalid));
        }
        let meta = InputMeta { token: "ab".repeat(16), sha256: "cd".repeat(32), size: 10 };
        assert_eq!(meta.validate(HARD_MAX_INPUT_BYTES), Ok(()));
        assert_eq!(InputMeta { token: "../x".into(), ..meta.clone() }.validate(1024), Err(ErrorCode::InputInvalid));
        assert_eq!(InputMeta { size: HARD_MAX_INPUT_BYTES + 1, ..meta }.validate(HARD_MAX_INPUT_BYTES), Err(ErrorCode::InputInvalid));
        let l = Limits::clamp_for(&profile(), 999_999, 1, 1);
        assert!(l.ttl_seconds <= 300 && l.max_pids >= 4 && l.max_export_bytes == HARD_MAX_EXPORT_BYTES);
        assert_eq!(Limits::clamp_for(&profile(), 1, u64::MAX >> 2, 10_000).validate(), Ok(()));
        for st in [CellState::Requested, CellState::Spawned, CellState::Isolated, CellState::Expiring, CellState::Burning, CellState::Burned, CellState::Failed] { assert_eq!(CellState::from_str(st.as_str()), Some(st)); }
        assert!(CellState::Burned.is_terminal() && !CellState::Burning.is_terminal());
    }
    #[test]
    fn ledger_health_caps_and_charset() {
        let e = BurnLedgerEntry { ts: 1_700_000_000, uuid: "ab".repeat(16), generation: 7, cgroup_id: 42,
            profile: "pdf-viewer".into(), reason: "ttl-expired".into(), export_size: 1234,
            export_sha256: "ef".repeat(32), evidence_id: String::new(), kind: "burn".into() };
        assert_eq!(BurnLedgerEntry::from_line(&e.to_line()), Some(e.clone()));
        let dirty = BurnLedgerEntry { reason: "bad reason\nstuff".into(), ..e };
        assert_eq!(BurnLedgerEntry::from_line(&dirty.to_line()).map(|x| x.reason), Some("bad-reason-stuff".into()));
        assert_eq!(BurnLedgerEntry::from_line("ts=x"), None);
        assert_eq!(Health::healthy(2, 5, 100).payload_fields()[0].0, "state");
        let caps = Capabilities { sandbox: true, profiles: vec!["pdf-viewer".into()], max_concurrent: 16,
            max_input_bytes: HARD_MAX_INPUT_BYTES, max_export_bytes: HARD_MAX_EXPORT_BYTES,
            ttl_max_seconds: MAX_TTL_SECONDS, bpf_lsm: "inactive".into() };
        assert_eq!((caps.payload_fields().len(), caps.payload_fields()[2].1.as_str()), (8, "pdf-viewer"));
        assert!(is_payload_value("sha256:4686/base64+._-abc"));
        for bad in ["", "has space", "nul\0", "semi;colon"] { assert!(!is_payload_value(bad)); }
        assert!(is_hex("0123456789abcdef", 16) && !is_hex("0123456789ABCDEF", 16));
    }
    #[test]
    fn capability_decoder_and_runtime_check() {
        assert_eq!(required_capabilities().len(), 6);
        let all: u64 = REQUIRED_CAPABILITIES.iter().fold(0, |m, (_, bit)| m | (1u64 << bit));
        assert!(missing_capabilities(all).is_empty());
        assert_eq!(missing_capabilities(1 << 0), vec!["CAP_SYS_ADMIN", "CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_SYS_RESOURCE"]);
        // runtime self-check: root (with full caps) passes, non-root fails closed
        let eff = cap_effective().expect("capget");
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(check_required_capabilities(), Ok(()));
            assert_eq!(missing_capabilities(eff).len(), 0);
        } else {
            assert_eq!(check_required_capabilities(), Err(ErrorCode::SandboxUnavailable));
        }
        let td = test_support::TempDir::new("types").expect("tempdir");
        let p = td.write("x", b"y").expect("write");
        assert!(test_support::exists(&p));
    }
}