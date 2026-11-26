use super::*;

impl CrossViewCore {
    /// Takes the mandatory `CROSS_VIEW_*` maps, attaches the socket-tap LSM and
    /// kprobe programs through the honest attach ladder and arms the state word.
    pub(crate) fn load(ebpf: &mut Ebpf) -> Result<Self, BoxError> {
        let events = RingBuf::try_from(
            ebpf.take_map(&crate::chameleon::map_name("CROSS_VIEW_EVENTS"))
                .ok_or("CROSS_VIEW_EVENTS missing")?,
        )?;
        let state = AyaArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("CROSS_VIEW_STATE"))
                .ok_or("CROSS_VIEW_STATE missing")?,
        )?;
        let counters = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("CROSS_VIEW_COUNTERS"))
                .ok_or("CROSS_VIEW_COUNTERS missing")?,
        )?;

        let mut core = Self {
            events,
            state,
            counters,
            epoch: random_epoch(),
            enabled: false,
            lsm_create_attached: false,
            lsm_setsockopt_attached: false,
            kprobe_attached: false,
            bpf_guard_lsm_attached: false,
            scans: 0,
            contradictions: 0,
            events_total: 0,
            queue: VecDeque::with_capacity(32),
            queue_drops: 0,
            rejected: 0,
            last_ring_drops: 0,
            last_queue_drops: 0,
            last_rejected: 0,
            last_scan_ms: 0,
            last_bounds_ok: true,
            last_domains: 0,
            last_reasons: Vec::new(),
            bpf_available: false,
            socket_available: false,
            proc_available: false,
            module_available: false,
            trace_available: false,
            pkgdb: PkgDbState::Unbuilt,
            pins_available: false,
            pins_count: 0,
            evidence_pids: HashMap::new(),
            known_pids: HashMap::new(),
            tap_dedupe: HashMap::new(),
            pin_root: resolve_pin_root(),
            pin_baseline: Vec::new(),
        };
        core.attach_tap_hooks(ebpf);
        core.pin_baseline = read_pin_entries(&core.pin_root);
        core.set_state_word(true)?;
        eprintln!(
            "GeDefense cross-view verifier: enabled=1 lsm_create={} lsm_setsockopt={} kprobe={} pins={} pkgdb={}",
            core.lsm_create_attached,
            core.lsm_setsockopt_attached,
            core.kprobe_attached,
            core.pin_baseline.len(),
            core.pkgdb_token()
        );
        Ok(core)
    }

    pub(crate) fn set_bpf_guard_lsm_attached(&mut self, attached: bool) {
        self.bpf_guard_lsm_attached = attached;
    }
}

impl CrossViewCore {
    /// LSM/kprobe attach ladder. An inactive BPF LSM, missing BTF or a denied
    /// attach only sets the matching flag to 0; the verifier keeps running its
    /// userland views and reports the gap honestly in `status()`.
    pub(super) fn attach_tap_hooks(&mut self, ebpf: &mut Ebpf) {
        let bpf_lsm_active = match crate::titan_exec::bpf_lsm_active_from_sys_fs() {
            Ok(active) => active,
            Err(error) => {
                eprintln!(
                    "cross-view tap hooks: BPF LSM activation probe failed ({error}); treating BPF LSM as inactive"
                );
                false
            }
        };
        if bpf_lsm_active {
            match Btf::from_sys_fs() {
                Ok(btf) => {
                    self.lsm_create_attached =
                        attach_lsm(ebpf, LSM_CREATE_PROGRAM, LSM_CREATE_HOOK, &btf);
                    self.lsm_setsockopt_attached =
                        attach_lsm(ebpf, LSM_SETSOCKOPT_PROGRAM, LSM_SETSOCKOPT_HOOK, &btf);
                }
                Err(error) => eprintln!(
                    "cross-view tap hooks: BPF LSM BTF unavailable ({error}); socket_create/socket_setsockopt not attached"
                ),
            }
        } else {
            eprintln!(
                "cross-view tap hooks: BPF LSM is not active (`/sys/kernel/security/lsm`); socket-tap LSM hooks not attached (tap=0 unless the kprobe attaches)"
            );
        }
        self.kprobe_attached =
            attach_kprobe(ebpf, SK_ATTACH_FILTER_PROGRAM, SK_ATTACH_FILTER_SYMBOL);
    }
}

impl CrossViewCore {
    /// Writes the `CROSS_VIEW_STATE` word (epoch | armed | attach flags |
    /// magic | ABI). Armed last: the eBPF programs ignore every event until the
    /// word is magic/ABI-valid and armed.
    pub(super) fn set_state_word(&mut self, armed: bool) -> Result<(), BoxError> {
        let mut flags = 0u64;
        if self.lsm_create_attached {
            flags |= 1 << CROSS_VIEW_STATE_LSM_CREATE_BIT;
        }
        if self.lsm_setsockopt_attached {
            flags |= 1 << CROSS_VIEW_STATE_LSM_SETSOCKOPT_BIT;
        }
        if self.kprobe_attached {
            flags |= 1 << CROSS_VIEW_STATE_KPROBE_BIT;
        }
        let word = cross_view_state_word(self.epoch as u32, armed, flags);
        self.state.set(CROSS_VIEW_STATE_INDEX, word, 0)?;
        self.enabled = armed;
        Ok(())
    }
}

pub(super) fn attach_lsm(ebpf: &mut Ebpf, program: &str, hook: &str, btf: &Btf) -> bool {
    let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(program)) else {
        eprintln!("cross-view tap hooks: program {program} missing; not attached");
        return false;
    };
    let result = (|| -> Result<(), BoxError> {
        let lsm: &mut Lsm = program.try_into()?;
        lsm.load(hook, btf)?;
        lsm.attach()?;
        Ok(())
    })();
    match result {
        Ok(()) => true,
        Err(error) => {
            eprintln!("cross-view tap hooks: LSM {hook} attach failed ({error}); flag=0");
            false
        }
    }
}

pub(super) fn attach_kprobe(ebpf: &mut Ebpf, program: &str, symbol: &str) -> bool {
    let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(program)) else {
        eprintln!("cross-view tap hooks: program {program} missing; kprobe not attached");
        return false;
    };
    let result = (|| -> Result<(), BoxError> {
        let kprobe: &mut KProbe = program.try_into()?;
        kprobe.load()?;
        kprobe.attach(symbol, 0)?;
        Ok(())
    })();
    match result {
        Ok(()) => true,
        Err(error) => {
            eprintln!(
                "cross-view tap hooks: kprobe {symbol} unavailable ({error}); classic-cBPF visibility degraded (kprobe=0)"
            );
            false
        }
    }
}
