//! M1.1 (6.2.0): pure policy surface of the asynchronous on-write sensor.
//!
//! Kept separate from the fanotify/queue wiring in [`crate::on_write`] so both
//! modules stay inside the VGT module size cap and the whole candidate/root
//! policy is unit-testable without root privileges or a fanotify group.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
/// Default on-write roots. They mirror the writable drop paths granted by
/// `packaging/systemd/gedefense-core.service`; a missing directory is skipped
/// (bounded, logged) instead of failing the privileged core at startup.
pub(crate) const DEFAULT_ON_WRITE_ROOTS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/var/www"];
/// Hard cap on configured roots (same budget as the exec watch roots).
pub(crate) const MAX_ON_WRITE_ROOTS: usize = 16;
/// Full scan budget for an executable drop.
pub(crate) const ON_WRITE_MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
/// The signature probe budget for non-executable data files. It is deliberately
/// larger than the old 1 MiB because webservers and benchmark users commonly
/// write archives and staged payloads as uid 33/1000 into the watched roots;
/// 16 MiB covers the HardRed archive class without unbounded work.
pub(crate) const ON_WRITE_SIGNATURE_PROBE_BYTES: u64 = 16 * 1024 * 1024;
/// Observed but deliberately *not* scanned: root-owned system package trees,
/// the GeDefense state/quarantine vault and the kernel API file systems. These
/// trees are read-only for the unit and every write there already belongs to a
/// signed package transition or to GeDefense itself.
const TRUSTED_PREFIXES: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/boot",
    "/snap",
    "/opt/vgt/gedefense",
    "/var/lib/vgt/gedefense",
    "/var/lib/dpkg",
    "/var/lib/apt",
    "/var/lib/rpm",
    "/var/cache/apt",
    "/var/lib/snapd",
    "/proc",
    "/sys",
];
/// One bounded scan class; `None` (no candidate) is the filter default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Candidate {
    /// Executable, outside the trusted trees, ≤64 MiB.
    FullScan,
    /// Not executable, ≤16 MiB (bounded signature/archive probe).
    SignatureProbe,
}

/// True when `path` is exactly or below one of `roots` on a component boundary
/// (`/tmp2` is not below `/tmp`). Roots are validated absolute paths.
pub(crate) fn path_is_below_any(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path == root || path.starts_with(root))
}

/// Trusted system/state prefix check; see [`TRUSTED_PREFIXES`].
pub(crate) fn path_is_trusted(path: &Path) -> bool {
    TRUSTED_PREFIXES
        .iter()
        .any(|prefix| path == Path::new(prefix) || path.starts_with(prefix))
}

/// Pure candidate predicate over the fields that matter; separated from
/// `Metadata` so it is fully testable on an unprivileged test runner.
pub(crate) fn classify_write(
    mode: u32,
    _owner_uid: u32,
    size: u64,
    is_regular_file: bool,
) -> Option<Candidate> {
    // Ownership is deliberately NOT a filter. A webserver (www-data) or a
    // benchmark user (uid 1000) drops payloads into the watched roots just as
    // an attacker would; ignoring uid != 0 made FAN_CLOSE_WRITE effectively
    // blind for exactly those cases. The root boundary remains enforced by
    // the watch roots and the fd-anchored quarantine broker.
    if !is_regular_file || size == 0 {
        return None;
    }
    if mode & 0o111 != 0 {
        return (size <= ON_WRITE_MAX_SCAN_BYTES).then_some(Candidate::FullScan);
    }
    (size <= ON_WRITE_SIGNATURE_PROBE_BYTES).then_some(Candidate::SignatureProbe)
}

/// The metadata binding of [`classify_write`].
pub(crate) fn classify_candidate(metadata: &fs::Metadata) -> Option<Candidate> {
    classify_write(
        metadata.mode(),
        metadata.uid(),
        metadata.len(),
        metadata.is_file(),
    )
}

/// Strict root parser: absolute, canonical (no `.`/`..`/empty/root), unique and
/// at most [`MAX_ON_WRITE_ROOTS`] entries. An empty input yields an empty vector
/// so the caller can apply [`DEFAULT_ON_WRITE_ROOTS`].
pub(crate) fn parse_roots(raw: &str) -> Result<Vec<PathBuf>, BoxError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let mut roots: Vec<PathBuf> = Vec::new();
    for token in raw.split(',') {
        let path = Path::new(token);
        if token.is_empty()
            || token.len() > 512
            || token.contains('\0')
            || !path.is_absolute()
            || path == Path::new("/")
            // `Path::components` folds `//` and a trailing slash away, so the
            // textual form is checked explicitly: two spellings of one root
            // must not end up as two different marks/budget entries.
            || token.contains("//")
            || token.ends_with('/')
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err("on-write watch root is not a canonical absolute directory".into());
        }
        if !roots.iter().any(|known| known == path) {
            roots.push(path.to_path_buf());
        }
        if roots.len() > MAX_ON_WRITE_ROOTS {
            return Err("on-write watch root boundary rejected".into());
        }
    }
    Ok(roots)
}

/// Resolves the operator-supplied roots, defaulting to [`DEFAULT_ON_WRITE_ROOTS`]
/// when no `--on-write-watch-root` flag was passed.
pub(crate) fn resolve_roots(configured: &[String]) -> Result<Vec<PathBuf>, BoxError> {
    if configured.is_empty() {
        return Ok(DEFAULT_ON_WRITE_ROOTS.iter().map(PathBuf::from).collect());
    }
    let mut roots: Vec<PathBuf> = Vec::new();
    for value in configured {
        for root in parse_roots(value)? {
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
    }
    if roots.is_empty() || roots.len() > MAX_ON_WRITE_ROOTS {
        return Err("on-write watch root boundary rejected".into());
    }
    Ok(roots)
}
