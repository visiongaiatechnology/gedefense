//! V6.3.0 AP-8 — GeDefense Chameleon Identity Mode (opt-in install profile).
//!
//! Chameleon is an **installation property, not a runtime self-mutation**: when
//! the installer created a signed install manifest, the privileged core renames
//! the kernel-visible eBPF program/map identifiers of the shipped object once at
//! load time, and the signed local VGT admin audit keeps the real mapping. With
//! no manifest (the documented default) every name and path is the public
//! GeDefense one and this module is a transparent pass-through. The profile is
//! installed once, before the eBPF loaders run; there is no setter that can
//! re-enable or disable it later.
//!
//! Public contract (keep stable):
//! - [`ChameleonProfile::from_manifest`] parses the bounded manifest,
//! - [`ChameleonProfile::load_object`] returns the `aya::Ebpf` object (plain
//!   `load_file` when disabled, neutralised in memory when enabled),
//! - [`ChameleonProfile::name`] resolves a public name to the installed name,
//! - [`ChameleonProfile::active`] reports whether the profile is enabled.
//!
//! What is renamed and what is not:
//! - **Renamed:** the ELF `.strtab`/`.symtab` spelling of the known GeDefense
//!   program/map namespace. Those are exactly the strings aya hands to the
//!   kernel as `prog_name`/map name, so `bpftool prog list` / `bpftool map
//!   list` no longer show `gedefense*`/`STYX_*`/`TITAN_*` identifiers.
//! - **Not renamed:** ELF section names (aya parses them to select program
//!   types), program instructions/relocations, unrelated BTF type names, and the
//!   on-disk binary path itself.
//!
//! The neutral name is a pure function of the installation salt and the public
//! identifier (HMAC-SHA256 with a `map:`/`prog:` domain separator), mapped onto
//! `[a-z0-9_]` with a lowercase letter as the first character and forced to the
//! **same byte length** as the public name. Collisions are resolved with a
//! counter inside the hash input; an exhausted search is an error, never a
//! silent fallback to the public name.
//!
//! Why the patcher appends strings instead of rewriting the existing ones: the
//! bpf-linker output merges `.strtab` and `.shstrtab`, and LLVM suffix-merges
//! strings aggressively. In the shipped object the section name `xdp` is a
//! suffix of the program symbol `gedefense_xdp` (and `EXEC_EVENTS` is a suffix of
//! `TITAN_EXEC_EVENTS`). An in-place same-length rewrite would therefore corrupt
//! a section name that aya needs. The patcher instead appends the neutral names
//! to the string table, repoints exactly the managed symbol entries
//! (`st_name`), zeroes the now-unreferenced public bytes without touching any
//! section name or unmanaged symbol name, and shifts the trailing section data
//! and section header table by one constant delta. Section names, program
//! sections, instructions, relocations and the section-type layout are byte
//! identical, and `aya::Ebpf::load(&bytes)` cannot observe a public identifier.

mod audit;
mod elf;
mod file;
mod manifest;
mod names;
mod patch;

use self::audit::*;
use self::elf::*;
use self::file::*;
use self::manifest::*;
use self::names::*;
use self::patch::*;

use std::{
    collections::HashMap,
    error::Error,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Process-wide profile installed by the privileged core before the eBPF object
/// loaders run. Chameleon is decided once at startup; there is no runtime
/// mutation and no setter that can re-enable/disable it later.
static ACTIVE_PROFILE: Mutex<Option<ChameleonProfile>> = Mutex::new(None);

/// Installs the startup profile so every module loader can resolve its public
/// program/map names through [`map_name`] / [`program_name`].
pub(crate) fn install_active(profile: ChameleonProfile) {
    if let Ok(mut slot) = ACTIVE_PROFILE.lock() {
        *slot = Some(profile);
    }
}

/// Resolves a public map name to the name used in this installation (identity
/// when Chameleon is off). Never fails: a poisoned lock falls back to the
/// public name, which is only reachable after a panic in the startup path.
pub(crate) fn map_name(public_name: &str) -> String {
    match ACTIVE_PROFILE.lock() {
        Ok(slot) => match slot.as_ref() {
            Some(profile) => profile.name(public_name),
            None => public_name.to_owned(),
        },
        Err(_) => public_name.to_owned(),
    }
}

/// Resolves a public eBPF program name to the installed name (identity when off).
pub(crate) fn program_name(public_name: &str) -> String {
    map_name(public_name)
}

/// Maximum accepted manifest size (strict, small config file).
pub const CHAMELEON_MANIFEST_MAX_BYTES: usize = 16 * 1024;
/// Manifest schema token expected in the first line.
pub const CHAMELEON_MANIFEST_SCHEMA: &str = "vgt-gedefense-chameleon-v1";

/// Upper bound for the eBPF object the patcher accepts. The shipped object is
/// far below 1 MiB; the bound exists so a corrupted/hostile path cannot make the
/// privileged core read an unbounded file into memory.
const CHAMELEON_OBJECT_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Upper bound for the admin audit file (one line per identifier).
const CHAMELEON_AUDIT_MAX_BYTES: usize = 256 * 1024;
/// Audit file name inside `state_dir` when the manifest has no explicit path.
const CHAMELEON_AUDIT_FILE_NAME: &str = "chameleon-map.audit";
/// Audit header token (schema for the admin-readable mapping document).
const CHAMELEON_AUDIT_SCHEMA: &str = "vgt-gedefense-chameleon-map-v1";

/// Parsed, validated installation manifest.
///
/// The core uses `salt`, `install_id`, `state_dir` and the optional audit path;
/// the socket/pin/port/unit fields are part of the strict schema shared with the
/// control plane and installer (the Rust core validates them so a manifest can
/// never be accepted half-valid) and are reported here for the admin audit.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct ChameleonManifest {
    install_id: String,
    salt: [u8; 32],
    core_socket: String,
    scan_socket: String,
    bpf_pin_root: String,
    state_dir: String,
    config_dir: String,
    public_port: u16,
    backend_port: u16,
    neutral_unit_prefix: String,
    admin_audit_path: Option<String>,
}

impl ChameleonManifest {
    fn audit_path(&self) -> PathBuf {
        match &self.admin_audit_path {
            Some(path) => PathBuf::from(path),
            None => Path::new(&self.state_dir).join(CHAMELEON_AUDIT_FILE_NAME),
        }
    }
}

/// Process-local state of one profile: the per-object name plan discovered when
/// the eBPF object was patched. `Arc`/`Mutex` so the startup clone installed in
/// [`ACTIVE_PROFILE`] observes the plan computed by
/// [`ChameleonProfile::load_object`].
#[derive(Debug, Default)]
struct NamePlan {
    /// public identifier -> neutral identifier
    names: HashMap<String, String>,
}

/// Parsed opt-in installation profile.
#[derive(Debug, Clone, Default)]
pub struct ChameleonProfile {
    enabled: bool,
    manifest: Option<ChameleonManifest>,
    plan: Arc<Mutex<NamePlan>>,
}

impl ChameleonProfile {
    /// Loads and validates the manifest at `path`. An empty path disables the
    /// profile (the documented default). A present but invalid manifest is an
    /// error: an operator who asked for Chameleon must never silently get the
    /// public identity.
    pub fn from_manifest(path: &str) -> Result<Self, BoxError> {
        if path.trim().is_empty() {
            return Ok(Self::default());
        }
        let manifest_path = Path::new(path);
        if !manifest_path.is_absolute() {
            return Err("chameleon manifest path must be absolute".into());
        }
        if path.chars().any(char::is_control) {
            return Err("chameleon manifest path contains control characters".into());
        }
        let bytes = read_plain_file(
            manifest_path,
            CHAMELEON_MANIFEST_MAX_BYTES,
            "chameleon manifest",
        )?;
        let manifest = parse_manifest(&bytes)?;
        Ok(Self {
            enabled: true,
            manifest: Some(manifest),
            plan: Arc::new(Mutex::new(NamePlan::default())),
        })
    }

    /// True when the installation opted into the neutral identity.
    ///
    /// Kept as public API for the startup seam and operator diagnostics; the core
    /// itself only ever branches on the manifest presence.
    #[allow(dead_code)]
    pub fn active(&self) -> bool {
        self.enabled
    }

    /// Returns an `aya::Ebpf` object. Disabled: plain `load_file` (byte-identical
    /// to the historical path). Enabled: the object is neutralised in memory
    /// (same-length neutral identifiers derived from the install salt, appended
    /// to the string table and bound to the managed symbols), the admin audit
    /// mapping is written, and the object is parsed with `Ebpf::load(&bytes)`.
    pub fn load_object(&self, object_path: &str) -> Result<aya::Ebpf, BoxError> {
        if !self.enabled {
            return Ok(aya::Ebpf::load_file(object_path)?);
        }
        let manifest = self
            .manifest
            .as_ref()
            .ok_or("chameleon profile is enabled without a parsed manifest")?;
        let object = Path::new(object_path);
        if !object.is_absolute() {
            return Err("chameleon eBPF object path must be absolute".into());
        }
        let raw = read_plain_file(object, CHAMELEON_OBJECT_MAX_BYTES, "chameleon eBPF object")?;
        if raw.is_empty() {
            return Err("chameleon eBPF object is empty".into());
        }
        let patched = patch_object(&raw, &manifest.salt)?;
        {
            let mut plan = self
                .plan
                .lock()
                .map_err(|_| "chameleon name plan lock poisoned")?;
            plan.names = patched.plan.clone();
        }
        // `aya::Ebpf::load` documents that the buffer be 4-byte aligned. A
        // Vec<u8> only guarantees alignment 1, so the patched bytes are copied
        // into an aligned word buffer before they are handed to aya.
        let word_count = patched.bytes.len().div_ceil(8);
        let mut words: Vec<u64> = vec![0u64; word_count];
        // SAFETY: `words` is a live allocation of `word_count * 8` initialized
        // bytes with 8-byte alignment; the slice covers exactly patched.len()
        // bytes and stays inside that allocation.
        let bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), patched.bytes.len())
        };
        bytes.copy_from_slice(&patched.bytes);
        // Load first: a refused object must fail the boot without leaving an
        // audit document that claims a live mapping.
        // SAFETY: `words` is still live and the slice is exactly the patched
        // bytes with 8-byte alignment.
        let aligned: &[u8] = unsafe {
            std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), patched.bytes.len())
        };
        let ebpf = aya::Ebpf::load(aligned)
            .map_err(|error| format!("chameleon eBPF object load failed: {error}"))?;
        write_audit_mapping(manifest, &patched)?;
        Ok(ebpf)
    }

    /// Resolves one public program/map name to the name used in the kernel. When
    /// the profile is disabled this is an identity operation.
    pub fn name(&self, public_name: &str) -> String {
        if !self.enabled {
            return public_name.to_owned();
        }
        if !is_managed_identifier(public_name) {
            return public_name.to_owned();
        }
        if let Ok(plan) = self.plan.lock() {
            if let Some(neutral) = plan.names.get(public_name) {
                return neutral.clone();
            }
        }
        // The plan is only missing before the object was patched (or after a
        // panic poisoned the lock). Derive the deterministic first candidate so
        // the caller fails on the lookups (missing map/program) instead of
        // silently using the public name.
        let manifest = match &self.manifest {
            Some(manifest) => manifest,
            None => return public_name.to_owned(),
        };
        derive_neutral_identifier(
            &manifest.salt,
            identifier_domain(public_name),
            public_name,
            0,
            public_name.len(),
        )
    }
}

/// `aya::Ebpf` wrapper that resolves program/map names through the process-wide
/// Chameleon profile before delegating to aya. The main loader keeps calling
/// `ebpf.take_map("…")` / `ebpf.program_mut("…")` with the public names; when
/// Chameleon is off the resolvers are identity functions, so the default path is
/// byte-identical to the historical code.
pub(crate) struct ManagedEbpf {
    inner: aya::Ebpf,
}

impl ManagedEbpf {
    pub(crate) fn new(inner: aya::Ebpf) -> Self {
        Self { inner }
    }

    pub(crate) fn into_inner(self) -> aya::Ebpf {
        self.inner
    }

    pub(crate) fn take_map(&mut self, name: &str) -> Option<aya::maps::Map> {
        self.inner.take_map(&map_name(name))
    }

    pub(crate) fn program_mut(&mut self, name: &str) -> Option<&mut aya::programs::Program> {
        let resolved = program_name(name);
        self.inner.program_mut(&resolved)
    }
}

impl Deref for ManagedEbpf {
    type Target = aya::Ebpf;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ManagedEbpf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_elf;
