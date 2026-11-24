//! Wave 3a extraction: the Titan exec gate, Gaia Cell policy and 6.2.0 sensor
//! command surface (`TITAN_EXEC_*`, `CELL_*`, `RANSOM_*`, `CRED_GUARD_*`) plus
//! the map encoders formerly inline in `main.rs`.

use crate::*;

pub(crate) const MAX_CELL_LSM_EVENTS_PER_RESPONSE: usize = 24;

/// §4 `TITAN_EXEC_STATE` word: epoch | mode | flags | abi=1 | magic='T'.
pub(crate) fn encode_titan_exec_state(epoch: u32, mode: u8, flags: u8) -> u64 {
    u64::from(epoch)
        | (u64::from(mode) << 32)
        | (u64::from(flags) << 40)
        | (u64::from(TITAN_EXEC_STATE_ABI) << 48)
        | (u64::from(TITAN_EXEC_STATE_MAGIC) << 56)
}

/// §4 `TITAN_EXEC_POLICY` key: `dev u32 LE @0 | ino u64 LE @4 | pad`.
pub(crate) fn encode_titan_exec_policy_key(dev: u32, ino: u64) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[0..4].copy_from_slice(&dev.to_le_bytes());
    key[4..12].copy_from_slice(&ino.to_le_bytes());
    key
}

/// §4 `TITAN_EXEC_POLICY` value: `action @0 | flags @1 | reserved @2 | ctime_ns LE @4`.
pub(crate) fn encode_titan_exec_policy_value(entry: &titan_exec::PolicyEntry) -> [u8; 16] {
    let mut value = [0u8; 16];
    value[0] = entry.action;
    value[1] = entry.flags;
    value[4..12].copy_from_slice(&entry.ctime_ns.to_le_bytes());
    value
}

/// §4 `TITAN_EXEC_MODE` value: `(mode << 2) | (scope flags & 1)`, validated.
pub(crate) fn encode_titan_exec_scope_value(mode: u8, flags: u8) -> Result<u8, BoxError> {
    if mode > gedefense_common::TITAN_EXEC_MODE_STRICT {
        return Err("titan-exec scope mode is not 0..3".into());
    }
    if flags & !TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW != 0 {
        return Err("titan-exec scope flags contain unknown bits".into());
    }
    Ok((mode << titan_exec::TITAN_EXEC_SCOPE_MODE_SHIFT) | flags)
}

/// §4.1 `TITAN_EXEC_OFFSETS` table (48 words, reserved indices stay 0).
pub(crate) fn encode_titan_exec_offsets_table(
    offsets: &btf_offsets::TitanExecOffsets,
) -> [u32; btf_offsets::TITAN_EXEC_OFFSETS_TABLE_LEN] {
    let mut table = [0u32; btf_offsets::TITAN_EXEC_OFFSETS_TABLE_LEN];
    table[btf_offsets::OFF_MAGIC] = TITAN_EXEC_OFFSETS_MAGIC;
    table[btf_offsets::OFF_ABI] = TITAN_EXEC_OFFSETS_ABI;
    table[btf_offsets::OFF_BPRM_FILE] = offsets.bprm_file_off;
    table[btf_offsets::OFF_FILE_F_INODE] = offsets.file_f_inode_off;
    table[btf_offsets::OFF_INODE_I_INO] = offsets.inode_i_ino_off;
    table[btf_offsets::OFF_INODE_I_SB] = offsets.inode_i_sb_off;
    table[btf_offsets::OFF_INODE_I_NLINK] = offsets.inode_i_nlink_off;
    table[btf_offsets::OFF_INODE_I_MODE] = offsets.inode_i_mode_off;
    table[btf_offsets::OFF_INODE_I_GEN] = offsets.inode_i_generation_off;
    table[btf_offsets::OFF_SUPER_S_DEV] = offsets.super_s_dev_off;
    table[btf_offsets::OFF_SUPER_S_MAGIC] = offsets.super_s_magic_off;
    table[btf_offsets::OFF_INODE_I_CTIME_SEC] = offsets.inode_i_ctime_sec_off;
    table[btf_offsets::OFF_INODE_I_CTIME_NSEC] = offsets.inode_i_ctime_nsec_off;
    table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH] = offsets.inode_i_ctime_nsec_width;
    // §4.1 ABI 2 (6.2.0): UNTRUSTED exec-mode facts.
    table[btf_offsets::OFF_BPRM_FILENAME] = offsets.bprm_filename_off;
    table[btf_offsets::OFF_INODE_I_UID] = offsets.inode_i_uid_off;
    table[btf_offsets::OFF_FILE_F_PATH_DENTRY] = offsets.file_f_path_dentry_off;
    table[btf_offsets::OFF_DENTRY_D_PARENT] = offsets.dentry_d_parent_off;
    table[btf_offsets::OFF_DENTRY_D_INODE] = offsets.dentry_d_inode_off;
    table[btf_offsets::OFF_DENTRY_SIZE] = offsets.dentry_size;
    table[btf_offsets::OFF_BPRM_NARGS] = offsets.bprm_nargs;
    table[btf_offsets::OFF_MMAP_NARGS] = offsets.mmap_nargs;
    table[btf_offsets::OFF_MMAP_FILE_ARG] = offsets.mmap_file_arg_idx;
    table[btf_offsets::OFF_MMAP_PROT_ARG] = offsets.mmap_prot_arg_idx;
    table[btf_offsets::OFF_MMAP_FLAGS_ARG] = offsets.mmap_flags_arg_idx;
    table[btf_offsets::OFF_TMPFS_MAGIC] = btf_offsets::TMPFS_MAGIC;
    table[btf_offsets::OFF_DEVTMPFS_MAGIC] = btf_offsets::DEVTMPFS_MAGIC;
    table[btf_offsets::OFF_PROC_MAGIC] = btf_offsets::PROC_SUPER_MAGIC;
    table[btf_offsets::OFF_SYSFS_MAGIC] = btf_offsets::SYSFS_MAGIC;
    table[btf_offsets::OFF_OVERLAY_MAGIC] = btf_offsets::OVERLAYFS_SUPER_MAGIC;
    table[btf_offsets::OFF_BPRM_RETVAL_SLOT] = offsets.bprm_retval_slot;
    table[btf_offsets::OFF_MMAP_RETVAL_SLOT] = offsets.mmap_retval_slot;
    table[btf_offsets::OFF_INODE_SIZE] = offsets.inode_size;
    table[btf_offsets::OFF_FILE_SIZE] = offsets.file_size;
    table[btf_offsets::OFF_BPRM_SIZE] = offsets.bprm_size;
    table
}

/// §4.1: the eBPF programs hard-code `bprm file=0/previous=1` and
/// `mmap file=0/prot=2/previous=4`; only this hook shape may be attached.
pub(crate) fn titan_exec_offsets_match_ebpf_slots(offsets: &btf_offsets::TitanExecOffsets) -> bool {
    offsets.bprm_nargs == 1
        && offsets.mmap_nargs == 4
        && offsets.mmap_file_arg_idx == 0
        && offsets.mmap_prot_arg_idx == 2
        && offsets.mmap_flags_arg_idx == 3
        && offsets.bprm_retval_slot == 1
        && offsets.mmap_retval_slot == 4
}

/// §4 STATE flag byte bits 40..47: offsets_valid, lsm_active (only when both
/// hooks are attached) and ctime_check_enabled (SET_GLOBAL REQUIRE_CTIME).
pub(crate) fn encode_titan_exec_state_flags(offsets_valid: bool, attached: bool, ctime_check: bool) -> u8 {
    (if offsets_valid { titan_exec::TITAN_EXEC_STATE_FLAG_OFFSETS_VALID } else { 0 })
        | (if attached { titan_exec::TITAN_EXEC_STATE_FLAG_LSM_ACTIVE } else { 0 })
        | (if ctime_check { titan_exec::TITAN_EXEC_STATE_FLAG_CTIME_CHECK } else { 0 })
}


impl TitanExecGate {
    /// §6: only an active LSM list, validated offsets and both attached hooks
    /// may ever be reported or acted upon as enforcement.
    pub(crate) fn enforcement_available(&self) -> bool {
        self.lsm_active && self.offsets_valid && self.attached
    }

    pub(crate) fn state_text(&self) -> &'static str {
        titan_exec::exec_state(
            self.enforcement_available(),
            self.lsm_active,
            self.offsets_valid,
        )
        .text()
    }

    /// Rewrites the §4 STATE word from the current truthful gate state.
    pub(crate) fn write_state(&mut self) -> Result<(), BoxError> {
        let ctime_check = self.flags & titan_exec::TITAN_EXEC_GLOBAL_FLAG_REQUIRE_CTIME != 0;
        let flags = encode_titan_exec_state_flags(self.offsets_valid, self.attached, ctime_check);
        self.state
            .set(0, encode_titan_exec_state(self.epoch, self.mode, flags), 0)?;
        Ok(())
    }

    pub(crate) fn version(&self) -> Result<String, BoxError> {
        Ok(titan_exec::TITAN_EXEC_VERSION.to_owned())
    }

    pub(crate) fn epoch(&self) -> Result<String, BoxError> {
        Ok(self.epoch_hex.clone())
    }

    pub(crate) fn status(&self) -> Result<String, BoxError> {
        Ok(titan_exec::encode_exec_status(&titan_exec::StatusView {
            state: titan_exec::exec_state(
                self.enforcement_available(),
                self.lsm_active,
                self.offsets_valid,
            ),
            mode: self.mode,
            flags: self.flags,
            path_bpf_lsm: self.attached,
            lsm_active: self.lsm_active,
            offsets_valid: self.offsets_valid,
            entries: self.store.entry_count(),
            scopes: self.store.scope_count(),
            epoch: &self.epoch_hex,
        }))
    }

    pub(crate) fn health(&self) -> Result<String, BoxError> {
        let counters = [
            KernelCore::per_cpu_counter_sum(&self.emitted)?,
            KernelCore::per_cpu_counter_sum(&self.ring_drops)?,
            KernelCore::per_cpu_counter_sum(&self.read_failures)?,
            KernelCore::per_cpu_counter_sum(&self.denies)?,
            KernelCore::per_cpu_counter_sum(&self.audits)?,
            KernelCore::per_cpu_counter_sum(&self.ctime_rejects)?,
        ];
        Ok(titan_exec::encode_exec_health(&counters))
    }

    /// §5 `SET_GLOBAL`: mode>0 only when the gate can really enforce; the
    /// REQUIRE_CTIME flag is mirrored into STATE bit2 and every policy value.
    pub(crate) fn set_global(&mut self, mode: &str, flags: &str) -> Result<String, BoxError> {
        let mode = titan_exec::parse_mode(mode).map_err(|message| -> BoxError { message.into() })?;
        let flags =
            titan_exec::parse_global_flags(flags).map_err(|message| -> BoxError { message.into() })?;
        if mode != TITAN_EXEC_MODE_OFF && !self.enforcement_available() {
            return Err(titan_exec::ENFORCEMENT_UNAVAILABLE.into());
        }
        let require_ctime = flags & titan_exec::TITAN_EXEC_GLOBAL_FLAG_REQUIRE_CTIME != 0;
        let mut updates = Vec::new();
        for (dev, ino) in self.store.keys() {
            let Some(mut entry) = self.store.entry(dev, ino) else {
                continue;
            };
            let wanted = if require_ctime {
                entry.flags | titan_exec::TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME
            } else {
                entry.flags & !titan_exec::TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME
            };
            if wanted != entry.flags {
                entry.flags = wanted;
                updates.push(((dev, ino), entry));
            }
        }
        for ((dev, ino), entry) in &updates {
            self.policy.insert(
                encode_titan_exec_policy_key(*dev, *ino),
                encode_titan_exec_policy_value(entry),
                0,
            )?;
        }
        for ((dev, ino), entry) in updates {
            self.store.insert(dev, ino, entry)?;
        }
        self.mode = mode;
        self.flags = flags;
        self.write_state()?;
        Ok("applied".to_owned())
    }

    /// §5 `ALLOW_ADD`/`ALLOW_ADD_BATCH` per-path step: validate fully, then the
    /// single map write, then the RAM mirror. `Ok(false)` means "already there".
    pub(crate) fn insert_resolved(&mut self, path: &str) -> Result<(u32, u64, bool), &'static str> {
        let identity = titan_exec::resolve_exec_path(path).map_err(|reject| reject.token())?;
        if self.store.entry(identity.dev, identity.ino).is_some() {
            return Ok((identity.dev, identity.ino, false));
        }
        if self.store.entry_count() >= titan_exec::TITAN_EXEC_MAX_POLICY_ENTRIES {
            return Err("cap-reached");
        }
        let entry = titan_exec::PolicyEntry {
            action: titan_exec::TITAN_EXEC_ALLOW_ACTION,
            flags: if self.flags & titan_exec::TITAN_EXEC_GLOBAL_FLAG_REQUIRE_CTIME != 0 {
                titan_exec::TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME
            } else {
                0
            },
            ctime_ns: identity.ctime_ns,
        };
        self.policy
            .insert(
                encode_titan_exec_policy_key(identity.dev, identity.ino),
                encode_titan_exec_policy_value(&entry),
                0,
            )
            .map_err(|_| "map-write-failed")?;
        self.store
            .insert(identity.dev, identity.ino, entry)
            .map_err(|_| "store-write-failed")?;
        Ok((identity.dev, identity.ino, true))
    }

    pub(crate) fn allow_add(&mut self, path: &str) -> Result<String, BoxError> {
        match self.insert_resolved(path) {
            Ok((dev, ino, true)) => Ok(format!("added:{dev}:{ino}")),
            Ok((dev, ino, false)) => Ok(format!("exists:{dev}:{ino}")),
            Err(token) => Err(format!("titan-exec path rejected: {token}").into()),
        }
    }

    pub(crate) fn allow_add_batch(&mut self, token: &str) -> Result<String, BoxError> {
        let paths = titan_exec::decode_allow_batch(token).map_err(|message| -> BoxError { message.into() })?;
        let (mut added, mut rejected) = (0usize, 0usize);
        let mut error = titan_exec::BATCH_ERROR_NONE;
        for path in paths {
            match self.insert_resolved(&path) {
                Ok(_) => added = added.saturating_add(1),
                Err(reason) => {
                    rejected = rejected.saturating_add(1);
                    if error == titan_exec::BATCH_ERROR_NONE {
                        error = reason;
                    }
                }
            }
        }
        Ok(titan_exec::encode_allow_batch_response(added, rejected, error))
    }

    /// §5 `ALLOW_DEL`: validate, drop from the eBPF map (KeyNotFound is fine),
    /// then from the mirror; DELETE is idempotent.
    pub(crate) fn allow_del(&mut self, dev: &str, ino: &str) -> Result<String, BoxError> {
        let dev = titan_exec::parse_policy_dev(dev).map_err(|message| -> BoxError { message.into() })?;
        let ino = titan_exec::parse_policy_ino(ino).map_err(|message| -> BoxError { message.into() })?;
        match self.policy.remove(&encode_titan_exec_policy_key(dev, ino)) {
            Ok(()) | Err(MapError::KeyNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        self.store.remove(dev, ino);
        Ok("deleted".to_owned())
    }

    pub(crate) fn clear(&mut self) -> Result<String, BoxError> {
        for (dev, ino) in self.store.keys() {
            match self.policy.remove(&encode_titan_exec_policy_key(dev, ino)) {
                Ok(()) | Err(MapError::KeyNotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.store.clear();
        Ok("cleared".to_owned())
    }

    /// §5 `SCOPE_SET`: mode>0 only on the enforcing gate; a failed mirror insert
    /// rolls the eBPF map write back so store and map never disagree.
    pub(crate) fn scope_set(&mut self, cgroup: &str, mode: &str, flags: &str) -> Result<String, BoxError> {
        let cgroup =
            titan_exec::parse_scope_cgroup(cgroup).map_err(|message| -> BoxError { message.into() })?;
        // §4: the per-cgroup scope value has only two mode bits, so UNTRUSTED
        // (4) stays a global mode and is rejected here instead of truncating.
        let mode = titan_exec::parse_scope_mode(mode).map_err(|message| -> BoxError { message.into() })?;
        let flags = titan_exec::parse_scope_flags(flags).map_err(|message| -> BoxError { message.into() })?;
        if mode != TITAN_EXEC_MODE_OFF && !self.enforcement_available() {
            return Err(titan_exec::ENFORCEMENT_UNAVAILABLE.into());
        }
        let value = encode_titan_exec_scope_value(mode, flags)?;
        self.modes.insert(cgroup, value, 0)?;
        if let Err(error) = self.store.scope_set(cgroup, value) {
            let _ = self.modes.remove(&cgroup);
            return Err(error.into());
        }
        Ok("applied".to_owned())
    }

    pub(crate) fn scope_del(&mut self, cgroup: &str) -> Result<String, BoxError> {
        let cgroup =
            titan_exec::parse_scope_cgroup(cgroup).map_err(|message| -> BoxError { message.into() })?;
        match self.modes.remove(&cgroup) {
            Ok(()) | Err(MapError::KeyNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        self.store.scope_remove(cgroup);
        Ok("deleted".to_owned())
    }

    /// §3.3/§6 event drain: ≤8 records, 88-byte and decoder check, undecodable
    /// records are skipped and counted (never an abort), `dropped` is the ring
    /// drop delta since the previous drain.
    pub(crate) fn take_events(&mut self) -> Result<String, BoxError> {
        let mut records = Vec::with_capacity(titan_exec::TITAN_EXEC_MAX_EVENTS_PER_RESPONSE);
        while records.len() < titan_exec::TITAN_EXEC_MAX_EVENTS_PER_RESPONSE {
            let Some(item) = self.events.next() else {
                break;
            };
            if item.len() != TITAN_EXEC_EVENT_WIRE_BYTES {
                self.rejected_events = self.rejected_events.saturating_add(1);
                continue;
            }
            let Some(event) = decode_titan_exec_event(&item) else {
                self.rejected_events = self.rejected_events.saturating_add(1);
                continue;
            };
            records.push(titan_exec::encode_exec_event_text(&event));
        }
        if self.rejected_events > 0 && self.rejected_events <= 4 {
            eprintln!(
                "Titan exec ring record rejected: {} records so far fit no TitanExecEvent; the drain continues",
                self.rejected_events
            );
        }
        let ring_drops = KernelCore::per_cpu_counter_sum(&self.ring_drops)?;
        let dropped = ring_drops.saturating_sub(self.last_ring_drops);
        self.last_ring_drops = ring_drops;
        titan_exec::encode_exec_events_batch(&records, dropped).map_err(Into::into)
    }
}

impl KernelCore {
    pub(crate) fn cell_policy_epoch(&self) -> Result<String, BoxError> {
        self.require_cell_lsm()?;
        Ok(self.cell_policy_epoch.clone())
    }

    pub(crate) fn set_cell_policy(&mut self, cgroup_id: &str, flags: &str) -> Result<String, BoxError> {
        self.require_cell_lsm()?;
        let cgroup_id = parse_cell_cgroup_id(cgroup_id)?;
        let flags = parse_cell_policy_flags(flags)?;
        self.cell_lsm_policies.insert(cgroup_id, flags, 0)?;
        Ok("applied".to_owned())
    }

    pub(crate) fn delete_cell_policy(&mut self, cgroup_id: &str) -> Result<String, BoxError> {
        self.require_cell_lsm()?;
        let cgroup_id = parse_cell_cgroup_id(cgroup_id)?;
        match self.cell_lsm_policies.remove(&cgroup_id) {
            Ok(()) | Err(MapError::KeyNotFound) => Ok("deleted".to_owned()),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn take_cell_lsm_events(&mut self) -> Result<String, BoxError> {
        self.require_cell_lsm()?;
        let mut encoded = Vec::with_capacity(MAX_CELL_LSM_EVENTS_PER_RESPONSE);
        let mut skipped = 0u64;
        while encoded.len() < MAX_CELL_LSM_EVENTS_PER_RESPONSE {
            let Some(item) = self.cell_lsm_events.next() else {
                break;
            };
            match decode_cell_lsm_deny_event(&item)? {
                Some(record) => encoded.push(record),
                None => {
                    skipped = skipped.saturating_add(1);
                    if skipped == 1 {
                        eprintln!(
                            "kernel Gaia Cell LSM denied an AF_UNSPEC socket; the denial is enforced but the record is not representable on the typed control-plane wire"
                        );
                    }
                }
            }
        }
        if encoded.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(encoded.join(","))
        }
    }

    pub(crate) fn require_cell_lsm(&self) -> Result<(), BoxError> {
        if self.cell_lsm_attached {
            Ok(())
        } else {
            Err("Gaia Cell BPF LSM is unavailable".into())
        }
    }
}

pub(crate) fn parse_cell_cgroup_id(value: &str) -> Result<u64, BoxError> {
    let parsed = value.parse::<u64>()?;
    if parsed == 0 {
        return Err("Gaia Cell cgroup ID must be non-zero".into());
    }
    Ok(parsed)
}

pub(crate) fn parse_cell_policy_flags(value: &str) -> Result<u8, BoxError> {
    let parsed = value.parse::<u8>()?;
    // 6.1.0 Module D widens the policy word with the LPE deny bits. Zero and
    // unknown bits stay rejected; every pre-6.1.0 value (1) keeps its exact
    // meaning.
    if parsed == 0 || parsed & !CELL_LSM_DENY_ALL_KNOWN != 0 {
        return Err("Gaia Cell LSM policy flags are invalid".into());
    }
    Ok(parsed)
}

// GAIA-CELL LSM DENY EVENT DECODING
//
// One malformed record must not be able to wedge the whole enforcement-event
// drain: the control plane reads a failed CELL_LSM_EVENTS call as a lost kernel
// hook, pauses automatic decisions and raises a critical alert, so a single
// undecodable record is a cheap denial of service against event correlation.
//
// AF_UNSPEC (0) is a legal socket(2) family: the LSM hook in the kernel denies
// it like every other non-AF_UNIX family and emits it verbatim. The IPC wire
// record carries only a typed, non-zero, non-AF_UNIX family (the control plane
// rejects anything else and would then discard the entire batch), so that one
// denial cannot be represented. It is skipped explicitly, which keeps the rest
// of the batch intact; the kernel denial itself has already been enforced.
pub(crate) fn decode_cell_lsm_deny_event(item: &[u8]) -> Result<Option<String>, BoxError> {
    if item.len() != std::mem::size_of::<CellLsmDenyEvent>() {
        return Err("kernel Gaia Cell LSM event has invalid size".into());
    }
    let cgroup_id = u64::from_ne_bytes(item[0..8].try_into()?);
    let pid = u32::from_ne_bytes(item[8..12].try_into()?);
    let uid = u32::from_ne_bytes(item[12..16].try_into()?);
    let family = i32::from_ne_bytes(item[16..20].try_into()?);
    let action = item[20];
    if cgroup_id == 0 || pid == 0 || action != ACTION_DROP {
        return Err("kernel Gaia Cell LSM event has invalid metadata".into());
    }
    if family == libc::AF_UNSPEC {
        return Ok(None);
    }
    if family <= 0 || family > i32::from(u8::MAX) || family == libc::AF_UNIX {
        return Err("kernel Gaia Cell LSM event has invalid metadata".into());
    }
    Ok(Some(format!("{cgroup_id}:{pid}:{uid}:{family}")))
}

pub(crate) fn dispatch(
    core: &mut KernelCore,
    parts: &[&str],
) -> Result<Option<String>, BoxError> {
    let result = match parts {
        ["CELL_POLICY_EPOCH"] => core.cell_policy_epoch(),
        ["CELL_POLICY_SET", cgroup_id, flags] => core.set_cell_policy(cgroup_id, flags),
        ["CELL_POLICY_DEL", cgroup_id] => core.delete_cell_policy(cgroup_id),
        ["CELL_LSM_EVENTS"] => core.take_cell_lsm_events(),
        // Point 1 (§5): Titan exec-gate command surface. Every argument is
        // validated before the first map write; enforcement cannot be claimed
        // while LSM/offsets/attach are not all green.
        ["TITAN_EXEC_VERSION"] => core.titan_exec.version(),
        ["TITAN_EXEC_EPOCH"] => core.titan_exec.epoch(),
        ["TITAN_EXEC_STATUS"] => core.titan_exec.status(),
        ["TITAN_EXEC_SET_GLOBAL", mode, flags] => core.titan_exec.set_global(mode, flags),
        ["TITAN_EXEC_ALLOW_ADD", path] => core.titan_exec.allow_add(path),
        ["TITAN_EXEC_ALLOW_ADD_BATCH", token] => core.titan_exec.allow_add_batch(token),
        ["TITAN_EXEC_ALLOW_DEL", dev, ino] => core.titan_exec.allow_del(dev, ino),
        ["TITAN_EXEC_CLEAR"] => core.titan_exec.clear(),
        ["TITAN_EXEC_SCOPE_SET", cgroup, mode, flags] => {
            core.titan_exec.scope_set(cgroup, mode, flags)
        }
        ["TITAN_EXEC_SCOPE_DEL", cgroup] => core.titan_exec.scope_del(cgroup),
        ["TITAN_EXEC_EVENTS"] => core.titan_exec.take_events(),
        ["TITAN_EXEC_HEALTH"] => core.titan_exec.health(),
        // 6.2.0 M2.2: ransomware/rename-storm sensor (kernel audit -> core freeze).
        ["RANSOM_EVENTS"] => core.ransom.take_events(),
        ["RANSOM_STATUS"] => core.ransom.status(),
        ["RANSOM_SET", state] => core.ransom.set_armed_token(state),
        // 6.2.0 M2.4: file_open credential guard (kernel -EACCES, bounded evidence).
        ["CRED_GUARD_EVENTS"] => core.credential_guard.take_events(),
        ["CRED_GUARD_STATUS"] => core.credential_guard.status(),
        ["CRED_GUARD_SET", state] => core.credential_guard.set_armed_token(state),
        _ => return Ok(None),
    };
    Ok(Some(result?))
}
