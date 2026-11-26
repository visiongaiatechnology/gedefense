use super::*;

impl ExecInodeCore {
    /// Takes the mandatory `EXEC_INODE_*`/`TRUSTED_EXEC_INODES` maps, resolves
    /// the BTF offsets for `task_struct -> mm -> exe_file -> f_inode` and
    /// populates the default trusted path contract.
    ///
    /// A BTF resolution failure does not fail core startup: the gate stays
    /// disarmed (fail-open) and the status reports `enabled=0:offsets=0`. Only a
    /// missing/incompatible eBPF object or a map write failure is an error.
    pub(crate) fn load(ebpf: &mut Ebpf) -> Result<Self, BoxError> {
        let events = RingBuf::try_from(
            ebpf.take_map(&crate::chameleon::map_name("EXEC_INODE_EVENTS"))
                .ok_or("EXEC_INODE_EVENTS missing")?,
        )?;
        let state = AyaArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("EXEC_INODE_STATE"))
                .ok_or("EXEC_INODE_STATE missing")?,
        )?;
        let offsets = AyaArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("EXEC_INODE_OFFSETS"))
                .ok_or("EXEC_INODE_OFFSETS missing")?,
        )?;
        let trusted = AyaHashMap::try_from(
            ebpf.take_map(&crate::chameleon::map_name("TRUSTED_EXEC_INODES"))
                .ok_or("TRUSTED_EXEC_INODES missing")?,
        )?;
        let ttl = AyaHashMap::try_from(
            ebpf.take_map(&crate::chameleon::map_name("MALWARE_TTL_INODES"))
                .ok_or("MALWARE_TTL_INODES missing")?,
        )?;
        let self_daemons = ebpf
            .take_map(&crate::chameleon::map_name("SELF_DAEMON_INODES"))
            .map(AyaHashMap::try_from)
            .transpose()?;
        let allowed = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("EXEC_INODE_ALLOWED"))
                .ok_or("EXEC_INODE_ALLOWED missing")?,
        )?;
        let denied = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("EXEC_INODE_DENIED"))
                .ok_or("EXEC_INODE_DENIED missing")?,
        )?;
        let emitted = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("EXEC_INODE_EVENTS_EMITTED"))
                .ok_or("EXEC_INODE_EVENTS_EMITTED missing")?,
        )?;
        let ring_drops = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("EXEC_INODE_RING_DROPS"))
                .ok_or("EXEC_INODE_RING_DROPS missing")?,
        )?;
        let fallbacks = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("EXEC_INODE_FALLBACK_EMITTED"))
                .ok_or("EXEC_INODE_FALLBACK_EMITTED missing")?,
        )?;
        let mut core = Self {
            events,
            state,
            offsets,
            trusted,
            ttl,
            self_daemons,
            allowed,
            denied,
            emitted,
            ring_drops,
            fallbacks,
            trusted_entries: BTreeMap::new(),
            ttl_locks: BTreeMap::new(),
            epoch: random_epoch(),
            offsets_ok: false,
            armed: false,
            missing_paths: 0,
            expired_locks: 0,
            last_ring_drops: 0,
            rejected: 0,
        };
        // Policy first, then offsets, then the armed state word last: the kernel
        // gate can only match a fully published map, never a half-loaded one.
        core.populate_default_trust();
        core.populate_self_daemon_inodes();
        // A gate that resolved no credential reader is NOT armed: on a minimal
        // host without any known auth binary every credential read would be
        // denied (a login lockout through the back door). Fail-open with
        // `enabled=0:offsets=1` and the documented comm fallback instead.
        let has_credential_reader = core
            .trusted_entries
            .values()
            .any(|flags| flags & EXEC_INODE_ALLOW_CRED_READ != 0);
        match btf_offsets::resolve_vmlinux_exec_inode_offsets() {
            Ok(resolved) => {
                core.publish_offsets(&resolved)?;
                core.offsets_ok = true;
                if has_credential_reader {
                    core.write_state(true)?;
                    core.armed = true;
                } else {
                    eprintln!(
                        "GeDefense exec-inode gate not armed: no trusted credential reader could be resolved from the default path contract; staying fail-open (comm fallback) instead of denying every credential read"
                    );
                    core.armed = false;
                }
            }
            Err(error) => {
                // Fail-open: keep the comm fallback alive and make the weaker
                // mode explicit in the status (offsets=0) instead of claiming
                // enforcement the eBPF object does not have.
                eprintln!(
                    "GeDefense exec-inode gate unavailable: BTF offsets are invalid ({error}); staying fail-open (comm fallback, never a lockout)"
                );
                core.offsets_ok = false;
                core.armed = false;
            }
        }
        eprintln!(
            "GeDefense exec-inode gate: enabled={} offsets={} trusted={} missing={}",
            u8::from(core.enabled()),
            u8::from(core.offsets_ok),
            core.trusted_entries.len(),
            core.missing_paths
        );
        Ok(core)
    }
}

impl ExecInodeCore {
    /// Publishes the validated BTF offsets into `EXEC_INODE_OFFSETS`.
    pub(super) fn publish_offsets(&mut self, offsets: &ExecInodeOffsets) -> Result<(), BoxError> {
        let table = encode_offsets_table(offsets);
        for (index, value) in table.iter().enumerate() {
            self.offsets.set(index as u32, *value, 0)?;
        }
        Ok(())
    }
}

impl ExecInodeCore {
    /// Writes the `EXEC_INODE_STATE` word (`epoch | armed | magic | ABI`).
    pub(super) fn write_state(&mut self, armed: bool) -> Result<(), BoxError> {
        let word = encode_state_word(self.epoch, armed);
        self.state.set(0, word, 0)?;
        self.armed = armed;
        Ok(())
    }
}

/// Encodes the `EXEC_INODE_STATE` word (`epoch | armed | magic | ABI`).
pub(crate) fn encode_state_word(epoch: u64, armed: bool) -> u64 {
    (epoch & u64::from(u32::MAX))
        | (u64::from(armed) << EXEC_INODE_STATE_ARMED_SHIFT)
        | (u64::from(EXEC_INODE_STATE_MAGIC) << EXEC_INODE_STATE_MAGIC_SHIFT)
        | (u64::from(EXEC_INODE_STATE_ABI) << EXEC_INODE_STATE_ABI_SHIFT)
}

/// Packs the resolved BTF offsets into the 16-entry `EXEC_INODE_OFFSETS` table.
pub(crate) fn encode_offsets_table(
    offsets: &ExecInodeOffsets,
) -> [u32; EXEC_INODE_OFFSETS_TABLE_LEN] {
    let mut table = [0u32; EXEC_INODE_OFFSETS_TABLE_LEN];
    table[EXEC_INODE_OFF_MAGIC as usize] = EXEC_INODE_OFFSETS_MAGIC;
    table[EXEC_INODE_OFF_ABI as usize] = EXEC_INODE_OFFSETS_ABI;
    table[EXEC_INODE_OFF_TASK_MM as usize] = offsets.task_mm_off;
    table[EXEC_INODE_OFF_MM_EXE_FILE as usize] = offsets.mm_exe_file_off;
    table[EXEC_INODE_OFF_FILE_F_INODE as usize] = offsets.file_f_inode_off;
    table[EXEC_INODE_OFF_INODE_I_INO as usize] = offsets.inode_i_ino_off;
    table[EXEC_INODE_OFF_INODE_I_SB as usize] = offsets.inode_i_sb_off;
    table[EXEC_INODE_OFF_SUPER_S_DEV as usize] = offsets.super_s_dev_off;
    table[EXEC_INODE_OFF_TASK_SIZE as usize] = offsets.task_size;
    table[EXEC_INODE_OFF_MM_SIZE as usize] = offsets.mm_size;
    table
}

pub(super) fn random_epoch() -> u64 {
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
