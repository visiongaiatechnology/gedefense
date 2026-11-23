//! M2.4 (6.2.0): userspace half of the eBPF `file_open` credential guard.
//!
//! Owns the `CRED_GUARD_*` maps of `rust/gedefense-ebpf/src/credential_guard.rs`:
//! the armed state word, the protected-inode maps, the denial ring and the
//! health counters. At startup it resolves the protected path contract into
//! `(s_dev, i_ino)` identity keys, attaches the LSM hook when BPF-LSM is
//! available and arms the guard. Denials are already enforced in the kernel
//! (`-EACCES`); this module only drains the bounded evidence ring and reports
//! honest status:
//!
//! - `CRED_GUARD_EVENTS` -> `empty` or `<dropped>|<record>[,<record>…]`
//!   (≤8 records, ≤2048 bytes) with the 8-field text record
//!   `<pid>:<tgid>:<uid>:<dev>:<ino>:<action>:<ts_ns>:<comm_hex>`,
//! - `CRED_GUARD_STATUS` -> `active:attached:armed:files:dirs:emitted:drops:denied`,
//! - `CRED_GUARD_SET <0|1>` -> `armed`/`disarmed`.
//!
//! Fail-safe: without BPF-LSM/BTF the hook is not attached and status reports
//! `active=0`; without a resolved policy (no protected inode) `active=0` too.
//! The guard never claims enforcement it does not have.

use aya::{
    maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf},
    programs::Lsm,
    Btf, Ebpf,
};
use gedefense_common::{
    decode_credential_guard_event, credential_identity_key, CredentialGuardEvent,
    CRED_GUARD_PROTECTED_DIRS, CRED_GUARD_PROTECTED_FILES, CRED_GUARD_STATE_ABI,
    CRED_GUARD_STATE_ABI_SHIFT, CRED_GUARD_STATE_ARMED_SHIFT, CRED_GUARD_STATE_MAGIC,
    CRED_GUARD_STATE_MAGIC_SHIFT,
};
use std::{
    error::Error,
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{Arc, Mutex},
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Bounded event batch (same shape as the other 6.x drains).
pub(crate) const MAX_CREDENTIAL_EVENTS_PER_RESPONSE: usize = 8;
pub(crate) const MAX_CREDENTIAL_PAYLOAD_BYTES: usize = 2048;
/// LSM hook program name + kernel hook name (ABI with the eBPF object).
const CREDENTIAL_GUARD_PROGRAM: &str = "gedefense_credential_guard_file_open";
const CREDENTIAL_GUARD_HOOK: &str = "file_open";
/// Startup bound for the secrets-directory scan (matches the map capacity).
const MAX_SECRET_FILES: usize = 128;

/// Shared handle allowing the on-write scanner to lock a malicious `(dev, ino)`
/// directly inside the eBPF `MALWARE_DENIED_INODES` map when a non-root `0755`
/// drop directory refuses unlinking without `CAP_DAC_OVERRIDE`.
pub(crate) type SharedMalwareInodeLock =
    Arc<Mutex<Option<Arc<Mutex<AyaHashMap<MapData, [u8; 16], u8>>>>>>;

pub(crate) fn deny_malware_inode(
    slot: &SharedMalwareInodeLock,
    dev: u64,
    ino: u64,
) -> Result<(), BoxError> {
    let dev = u32::try_from(dev).map_err(|_| "malware inode lock: device id out of range")?;
    if dev == 0 || ino == 0 {
        return Err("malware inode lock: invalid identity".into());
    }
    let map_arc = {
        let guard = slot.lock().map_err(|_| "malware inode lock poisoned")?;
        guard
            .as_ref()
            .cloned()
            .ok_or("malware inode lock map not yet initialized")?
    };
    let mut map = map_arc
        .lock()
        .map_err(|_| "malware inode map lock poisoned")?;
    map.insert(credential_identity_key(dev, ino), 1u8, 0)?;
    Ok(())
}

/// Credential guard state owned by the core.
pub(crate) struct CredentialGuardCore {
    events: RingBuf<MapData>,
    state: AyaArray<MapData, u64>,
    files: AyaHashMap<MapData, [u8; 16], u8>,
    dirs: AyaHashMap<MapData, [u8; 16], u8>,
    malware_denied_inodes: Arc<Mutex<AyaHashMap<MapData, [u8; 16], u8>>>,
    emitted: PerCpuArray<MapData, u64>,
    ring_drops: PerCpuArray<MapData, u64>,
    read_failures: PerCpuArray<MapData, u64>,
    denied: PerCpuArray<MapData, u64>,
    epoch: u64,
    attached: bool,
    armed: bool,
    file_entries: u32,
    dir_entries: u32,
    last_ring_drops: u64,
    rejected: u64,
}

impl CredentialGuardCore {
    /// Takes the mandatory maps, resolves the protected inode set, attaches the
    /// LSM hook best-effort and arms the guard. Map lookups are mandatory (a
    /// stale object fails loudly); policy/attach problems degrade the status to
    /// `active=0` and never lock the host out.
    pub(crate) fn load(
        ebpf: &mut Ebpf,
        btf: Option<&Btf>,
        bpf_lsm_active: bool,
    ) -> Result<Self, BoxError> {
        let events = RingBuf::try_from(
            ebpf.take_map("CRED_GUARD_EVENTS")
                .ok_or("CRED_GUARD_EVENTS missing")?,
        )?;
        let state = AyaArray::try_from(
            ebpf.take_map("CRED_GUARD_STATE")
                .ok_or("CRED_GUARD_STATE missing")?,
        )?;
        let files = AyaHashMap::try_from(
            ebpf.take_map("CRED_GUARD_FILES")
                .ok_or("CRED_GUARD_FILES missing")?,
        )?;
        let dirs = AyaHashMap::try_from(
            ebpf.take_map("CRED_GUARD_DIRS")
                .ok_or("CRED_GUARD_DIRS missing")?,
        )?;
        let malware_denied_inodes = Arc::new(Mutex::new(AyaHashMap::try_from(
            ebpf.take_map("MALWARE_DENIED_INODES")
                .ok_or("MALWARE_DENIED_INODES missing")?,
        )?));
        let emitted = PerCpuArray::try_from(
            ebpf.take_map("CRED_GUARD_EVENTS_EMITTED")
                .ok_or("CRED_GUARD_EVENTS_EMITTED missing")?,
        )?;
        let ring_drops = PerCpuArray::try_from(
            ebpf.take_map("CRED_GUARD_RING_DROPS")
                .ok_or("CRED_GUARD_RING_DROPS missing")?,
        )?;
        let read_failures = PerCpuArray::try_from(
            ebpf.take_map("CRED_GUARD_READ_FAILURES")
                .ok_or("CRED_GUARD_READ_FAILURES missing")?,
        )?;
        let denied = PerCpuArray::try_from(
            ebpf.take_map("CRED_GUARD_DENIED")
                .ok_or("CRED_GUARD_DENIED missing")?,
        )?;
        let mut core = Self {
            events,
            state,
            files,
            dirs,
            malware_denied_inodes,
            emitted,
            ring_drops,
            read_failures,
            denied,
            epoch: random_epoch(),
            attached: false,
            armed: false,
            file_entries: 0,
            dir_entries: 0,
            last_ring_drops: 0,
            rejected: 0,
        };
        core.populate_policy()?;
        core.attach(ebpf, btf, bpf_lsm_active);
        core.set_armed(true)?;
        eprintln!(
            "GeDefense credential guard: active={} attached={} files={} dirs={}",
            core.active(),
            core.attached,
            core.file_entries,
            core.dir_entries
        );
        Ok(core)
    }

    /// Resolves the protected path contract into inode identity keys. Missing
    /// paths are logged and skipped; the guard then protects what exists.
    fn populate_policy(&mut self) -> Result<(), BoxError> {
        for path in CRED_GUARD_PROTECTED_FILES {
            match fs::symlink_metadata(path) {
                Ok(metadata) if metadata.is_file() => {
                    self.insert_file_identity(path, metadata.dev(), metadata.ino())?;
                }
                Ok(_) => eprintln!("credential guard: {path} is not a regular file; skipped"),
                Err(error) => eprintln!("credential guard: stat {path} failed: {error}"),
            }
        }
        for dir in CRED_GUARD_PROTECTED_DIRS {
            match fs::symlink_metadata(dir) {
                Ok(metadata) if metadata.is_dir() => {
                    self.insert_dir_identity(dir, metadata.dev(), metadata.ino())?;
                    self.scan_secret_directory(Path::new(dir));
                }
                Ok(_) => eprintln!("credential guard: {dir} is not a directory; skipped"),
                Err(error) => eprintln!("credential guard: stat {dir} failed: {error}"),
            }
        }
        Ok(())
    }

    fn scan_secret_directory(&mut self, dir: &Path) {
        let Ok(entries) = fs::read_dir(dir) else {
            eprintln!("credential guard: read_dir {} failed", dir.display());
            return;
        };
        let mut scanned = 0usize;
        for entry in entries.flatten() {
            if scanned >= MAX_SECRET_FILES {
                eprintln!(
                    "credential guard: {} has more than {MAX_SECRET_FILES} entries; extra files are covered by the directory key only",
                    dir.display()
                );
                break;
            }
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            if let Err(error) =
                self.insert_file_identity(&path.to_string_lossy(), metadata.dev(), metadata.ino())
            {
                eprintln!("credential guard: map insert for {} failed: {error}", path.display());
            }
            scanned += 1;
        }
    }

    fn insert_file_identity(&mut self, label: &str, dev: u64, ino: u64) -> Result<(), BoxError> {
        let dev = u32::try_from(dev).map_err(|_| "credential guard: device id out of range")?;
        if dev == 0 || ino == 0 {
            return Ok(());
        }
        self.files
            .insert(credential_identity_key(dev, ino), 1u8, 0)
            .map_err(|error| -> BoxError { format!("{label}: {error}").into() })?;
        self.file_entries = self.file_entries.saturating_add(1);
        Ok(())
    }

    fn insert_dir_identity(&mut self, label: &str, dev: u64, ino: u64) -> Result<(), BoxError> {
        let dev = u32::try_from(dev).map_err(|_| "credential guard: device id out of range")?;
        if dev == 0 || ino == 0 {
            return Ok(());
        }
        self.dirs
            .insert(credential_identity_key(dev, ino), 1u8, 0)
            .map_err(|error| -> BoxError { format!("{label}: {error}").into() })?;
        self.dir_entries = self.dir_entries.saturating_add(1);
        Ok(())
    }

    /// Best-effort LSM attach; a kernel without BPF-LSM keeps the rest of the
    /// core alive and reports `active=0`/`attached=0`.
    fn attach(&mut self, ebpf: &mut Ebpf, btf: Option<&Btf>, bpf_lsm_active: bool) {
        if !bpf_lsm_active {
            eprintln!(
                "credential guard inactive: BPF LSM is not active (no attach, no enforcement claim)"
            );
            return;
        }
        let Some(btf) = btf else {
            eprintln!("credential guard inactive: BPF LSM BTF unavailable");
            return;
        };
        let Some(program) = ebpf.program_mut(CREDENTIAL_GUARD_PROGRAM) else {
            eprintln!("credential guard program {CREDENTIAL_GUARD_PROGRAM} missing; not attached");
            return;
        };
        let result = (|| -> Result<(), BoxError> {
            let lsm: &mut Lsm = program.try_into()?;
            lsm.load(CREDENTIAL_GUARD_HOOK, btf)?;
            lsm.attach()?;
            Ok(())
        })();
        match result {
            Ok(()) => self.attached = true,
            Err(error) => eprintln!("credential guard attach failed ({error}); inactive"),
        }
    }

    pub(crate) fn malware_inode_lock_handle(
        &self,
    ) -> Arc<Mutex<AyaHashMap<MapData, [u8; 16], u8>>> {
        Arc::clone(&self.malware_denied_inodes)
    }

    /// Truthful enforcement state: hook attached AND at least one protected
    /// inode resolved. Never claims more than it has.
    pub(crate) fn active(&self) -> bool {
        self.armed && self.attached && (self.file_entries > 0 || self.dir_entries > 0)
    }

    fn set_armed(&mut self, armed: bool) -> Result<String, BoxError> {
        let word = encode_state_word(self.epoch, armed);
        self.state.set(0, word, 0)?;
        self.armed = armed;
        Ok(if armed { "armed" } else { "disarmed" }.to_owned())
    }

    pub(crate) fn set_armed_token(&mut self, token: &str) -> Result<String, BoxError> {
        match token {
            "0" => self.set_armed(false),
            "1" => self.set_armed(true),
            _ => Err("CRED_GUARD_SET accepts 0 or 1".into()),
        }
    }

    /// Drains up to 8 denial records as the bounded 8-field text batch.
    pub(crate) fn take_events(&mut self) -> Result<String, BoxError> {
        let mut records = Vec::with_capacity(MAX_CREDENTIAL_EVENTS_PER_RESPONSE);
        while records.len() < MAX_CREDENTIAL_EVENTS_PER_RESPONSE {
            let Some(item) = self.events.next() else {
                break;
            };
            let Some(event) = decode_credential_guard_event(&item) else {
                self.rejected = self.rejected.saturating_add(1);
                continue;
            };
            records.push(encode_event_text(&event));
        }
        let ring_drops = Self::per_cpu_sum(&self.ring_drops)?;
        let dropped = ring_drops.saturating_sub(self.last_ring_drops);
        self.last_ring_drops = ring_drops;
        if records.is_empty() {
            if dropped == 0 && self.rejected == 0 {
                return Ok("empty".to_owned());
            }
            return Ok(format!("{dropped}|"));
        }
        let payload = format!("{dropped}|{}", records.join(","));
        if payload.len() > MAX_CREDENTIAL_PAYLOAD_BYTES {
            return Err("credential guard event batch exceeds the response payload budget".into());
        }
        Ok(payload)
    }

    /// Nine decimal health fields:
    /// `active:attached:armed:files:dirs:emitted:drops:denied:read_failures`.
    pub(crate) fn status(&self) -> Result<String, BoxError> {
        let emitted = Self::per_cpu_sum(&self.emitted)?;
        let drops = Self::per_cpu_sum(&self.ring_drops)?;
        let denied = Self::per_cpu_sum(&self.denied)?;
        let read_failures = Self::per_cpu_sum(&self.read_failures)?;
        Ok(format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            u8::from(self.active()),
            u8::from(self.attached),
            u8::from(self.armed),
            self.file_entries,
            self.dir_entries,
            emitted,
            drops,
            denied,
            read_failures
        ))
    }

    fn per_cpu_sum(counter: &PerCpuArray<MapData, u64>) -> Result<u64, BoxError> {
        let values = counter.get(&0, 0)?;
        Ok(values
            .iter()
            .copied()
            .fold(0u64, |sum, value| sum.saturating_add(value)))
    }
}

fn random_epoch() -> u64 {
    use std::io::Read as _;
    let mut bytes = [0u8; 8];
    match fs::File::open("/dev/urandom") {
        Ok(mut file) => {
            let _ = file.read_exact(&mut bytes);
            u64::from_ne_bytes(bytes)
        }
        Err(_) => 0,
    }
}

/// Packs the `CRED_GUARD_STATE` word (epoch | armed | magic | abi).
pub(crate) fn encode_state_word(epoch: u64, armed: bool) -> u64 {
    (epoch & u64::from(u32::MAX))
        | (u64::from(armed) << CRED_GUARD_STATE_ARMED_SHIFT)
        | (u64::from(CRED_GUARD_STATE_MAGIC) << CRED_GUARD_STATE_MAGIC_SHIFT)
        | (u64::from(CRED_GUARD_STATE_ABI) << CRED_GUARD_STATE_ABI_SHIFT)
}

/// Encodes the 8-field control-plane text record
/// (`pid:tgid:uid:dev:ino:action:ts_ns:comm_hex`).
pub(crate) fn encode_event_text(event: &CredentialGuardEvent) -> String {
    let comm_end = event.comm.iter().position(|byte| *byte == 0).unwrap_or(15);
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}",
        event.pid,
        event.tgid,
        event.uid,
        event.dev,
        event.ino,
        event.action,
        event.ts_ns,
        hex::encode(&event.comm[..comm_end]),
    )
}
