//! Wave 3a extraction of the aya load/attach seam formerly inline in `main.rs`:
//! Chameleon `ManagedEbpf` object loading, XDP/TC/cgroup/LSM program attach,
//! mandatory map extraction, BTF offset publication and the AP-0 pin-guard load.

use crate::ipc::dispatch_lockdown::{AyaLockdownWordStore, LiveLockdownCounters};
use crate::ipc::dispatch_titan::{
    encode_titan_exec_offsets_table, titan_exec_offsets_match_ebpf_slots,
};
use crate::*;

// §4 mandatory-veto seed: metadata/link-local/multicast/unspecified ranges that
// must be blocked from the moment the core is online (127/8 and ::1 stay out so
// loopback keeps working; the IPv6 ND exception is implemented in the kernel
// program and applies on top of this list).
pub(crate) const STYX_MANDATORY_VETO_V4: &[(u32, [u8; 4])] = &[
    (16, [169, 254, 0, 0]),
    (32, [100, 100, 100, 200]),
    (32, [168, 63, 129, 16]),
    (32, [192, 0, 0, 192]),
    (8, [0, 0, 0, 0]),
    (4, [224, 0, 0, 0]),
];
pub(crate) const STYX_MANDATORY_VETO_V6: &[(u32, [u8; 16])] = &[
    (128, [0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54]),
    (10, [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    (8, [0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
];

impl KernelCore {
    pub(crate) fn load(
        object: &str,
        iface: &str,
        require_cell_lsm: bool,
        lockdown_state_path: &str,
        bpf_pin_root: &str,
        chameleon_manifest: &str,
    ) -> Result<Self, BoxError> {
        // V6.3.0 AP-8: an opt-in installation profile either loads the shipped
        // object unchanged (default) or patches the neutral kernel identifiers
        // once at load time. A configured-but-invalid manifest is an error so an
        // operator never silently gets the public identity.
        let chameleon = chameleon::ChameleonProfile::from_manifest(chameleon_manifest)?;
        chameleon::install_active(chameleon.clone());
        let mut ebpf =
            chameleon::ManagedEbpf::new(chameleon.load_object(object)?);
        // V6.3.0 AP-0: pin the critical kernel maps before any feature module
        // consumes its map handle, and take the expected pin manifest. A host
        // without bpffs degrades to `pins=unavailable`, never fails the core.
        let self_defense = self_defense::SelfDefenseCore::load(&mut ebpf, bpf_pin_root);
        let xdp_mode = {
            let program: &mut Xdp = ebpf
                .program_mut("gedefense_xdp")
                .ok_or("XDP program missing")?
                .try_into()?;
            program.load()?;
            match program.attach(iface, XdpMode::Driver) {
                Ok(_) => Some("native"),
                Err(native) => {
                    eprintln!("native XDP unavailable ({native}); using generic mode");
                    match program.attach(iface, XdpMode::Skb) {
                        Ok(_) => Some("generic"),
                        Err(generic) => {
                            eprintln!(
                                "generic XDP unavailable ({generic}); using TC ingress kernel enforcement"
                            );
                            None
                        }
                    }
                }
            }
        };
        let ingress_mode: &'static str = match xdp_mode {
            Some(mode) => mode,
            None => {
                if let Err(error) = tc::qdisc_add_clsact(iface) {
                    if !matches!(error, tc::TcError::AlreadyAttached) {
                        return Err(error.into());
                    }
                }
                let program: &mut SchedClassifier = ebpf
                    .program_mut("gedefense_tc_ingress")
                    .ok_or("TC ingress program missing")?
                    .try_into()?;
                program.load()?;
                program.attach_with_options(
                    iface,
                    TcAttachType::Ingress,
                    tc::TcAttachOptions::Netlink(tc::NlOptions::default()),
                )?;
                "tc-ingress"
            }
        };
        let exec_program: &mut TracePoint = ebpf
            .program_mut("gedefense_exec")
            .ok_or("process exec tracepoint program missing")?
            .try_into()?;
        exec_program.load()?;
        if let Err(error) = exec_program.attach("sched", "sched_process_exec") {
            eprintln!("Process exec tracepoint unavailable ({error}); falling back to fanotify and procfs monitoring");
        }
        let cgroup = File::open("/sys/fs/cgroup")?;
        let egress_program: &mut CgroupSkb = ebpf
            .program_mut("gedefense_egress")
            .ok_or("cgroup egress program missing")?
            .try_into()?;
        egress_program.load()?;
        // AllowOverride, not AllowMultiple.
        //
        // The two differ in whether an attach replaces or appends, and nothing here ever
        // detaches - the core has no shutdown path, and a cgroup program outlives the
        // process that attached it. With AllowMultiple every restart appended another
        // gedefense_egress to the root cgroup's egress hook and left it there, holding
        // its maps: eleven stale programs and roughly 110 MB of kernel memory had
        // accumulated on a host that had been restarted a handful of times.
        //
        // AllowOverride replaces the previous attachment instead, so a restart leaves one
        // program rather than one more. It is preferred over Single because it still
        // permits a child cgroup to install its own program over this one, which is what
        // a container runtime expects to be able to do.
        egress_program.attach(
            cgroup,
            CgroupSkbAttachType::Egress,
            CgroupAttachMode::AllowOverride,
        )?;
        // V6.3.0 AP-6: cgroup_skb/ingress RX flow observer. Observe-only (the
        // program always returns TC_ACT_OK); an unavailable hook keeps
        // RxObservationAvailable=false in the control plane and is reported
        // honestly instead of claiming RX coverage. A fresh cgroup descriptor is
        // opened because the egress attach consumed the previous one.
        let ingress_cgroup = File::open("/sys/fs/cgroup")?;
        let styx_ingress = styx_ingress::StyxIngressCore::attach(&mut ebpf, &ingress_cgroup);
        // §0/§6/P3-Fix: an active BPF LSM is a hard precondition for any attach
        // claim. On a kernel whose `/sys/kernel/security/lsm` list lacks `bpf`,
        // `Lsm::attach` succeeds but the stubs are never called - the old code
        // still reported `bpf-lsm-cell` for that silent no-op.
        let bpf_lsm_active = match titan_exec::bpf_lsm_active_from_sys_fs() {
            Ok(active) => active,
            Err(error) => {
                eprintln!("BPF LSM activation probe failed ({error}); treating BPF LSM as inactive");
                false
            }
        };
        if !bpf_lsm_active && require_cell_lsm {
            return Err(
                "--require-bpf-lsm: /sys/kernel/security/lsm does not list the `bpf` token".into(),
            );
        }
        let lsm_btf = if bpf_lsm_active {
            match Btf::from_sys_fs() {
                Ok(btf) => Some(btf),
                Err(error) if !require_cell_lsm => {
                    eprintln!("BPF LSM BTF unavailable ({error}); LSM attach disabled");
                    None
                }
                Err(error) => return Err(format!("required BPF LSM BTF unavailable: {error}").into()),
            }
        } else {
            None
        };
        let cell_lsm_attached = match &lsm_btf {
            Some(btf) => match attach_cell_socket_lsm(&mut ebpf, btf) {
                Ok(()) => true,
                Err(error) if !require_cell_lsm => {
                    eprintln!(
                        "BPF LSM unavailable ({error}); Gaia Cell host socket reinforcement disabled"
                    );
                    false
                }
                Err(error) => {
                    return Err(format!("required Gaia Cell BPF LSM attach failed: {error}").into())
                }
            },
            None => {
                eprintln!(
                    "BPF LSM is not active (or its BTF is missing); Gaia Cell host socket reinforcement optional-unavailable, bpf-lsm-cell not claimed"
                );
                false
            }
        };
        let exec_events =
            RingBuf::try_from(ebpf.take_map("EXEC_EVENTS").ok_or("EXEC_EVENTS missing")?)?;
        let egress_events = RingBuf::try_from(
            ebpf.take_map("EGRESS_EVENTS")
                .ok_or("EGRESS_EVENTS missing")?,
        )?;
        let ingress_events = RingBuf::try_from(
            ebpf.take_map("INGRESS_EVENTS")
                .ok_or("INGRESS_EVENTS missing")?,
        )?;
        let ingress_events_emitted = PerCpuArray::try_from(
            ebpf.take_map("INGRESS_EVENTS_EMITTED")
                .ok_or("INGRESS_EVENTS_EMITTED missing")?,
        )?;
        let ingress_ring_drops = PerCpuArray::try_from(
            ebpf.take_map("INGRESS_RING_DROPS")
                .ok_or("INGRESS_RING_DROPS missing")?,
        )?;
        let ingress_track_insert_failures = PerCpuArray::try_from(
            ebpf.take_map("INGRESS_TRACK_INSERT_FAILURES")
                .ok_or("INGRESS_TRACK_INSERT_FAILURES missing")?,
        )?;
        let cell_lsm_events = RingBuf::try_from(
            ebpf.take_map("CELL_LSM_EVENTS")
                .ok_or("CELL_LSM_EVENTS missing")?,
        )?;
        let cell_lsm_policies = AyaHashMap::try_from(
            ebpf.take_map("CELL_LSM_POLICIES")
                .ok_or("CELL_LSM_POLICIES missing")?,
        )?;
        let allow_v4 = LpmTrie::try_from(
            ebpf.take_map("ALLOWLIST_V4")
                .ok_or("ALLOWLIST_V4 missing")?,
        )?;
        let allow_v6 = LpmTrie::try_from(
            ebpf.take_map("ALLOWLIST_V6")
                .ok_or("ALLOWLIST_V6 missing")?,
        )?;
        let v4 = LpmTrie::try_from(
            ebpf.take_map("BLOCKLIST_V4")
                .ok_or("BLOCKLIST_V4 missing")?,
        )?;
        let v6 = LpmTrie::try_from(
            ebpf.take_map("BLOCKLIST_V6")
                .ok_or("BLOCKLIST_V6 missing")?,
        )?;
        // Point 3: all §4 maps are taken here so a mismatched eBPF object fails
        // at startup (no silent "sensor online but blind" state).
        let mut styx_global = AyaArray::try_from(
            ebpf.take_map("STYX_GLOBAL").ok_or("STYX_GLOBAL missing")?,
        )?;
        let styx_mode = AyaHashMap::try_from(
            ebpf.take_map("CELL_EGRESS_MODE")
                .ok_or("CELL_EGRESS_MODE missing")?,
        )?;
        let styx_cell_allow_v4 = LpmTrie::try_from(
            ebpf.take_map("CELL_EGRESS_ALLOW_V4")
                .ok_or("CELL_EGRESS_ALLOW_V4 missing")?,
        )?;
        let styx_cell_allow_v6 = LpmTrie::try_from(
            ebpf.take_map("CELL_EGRESS_ALLOW_V6")
                .ok_or("CELL_EGRESS_ALLOW_V6 missing")?,
        )?;
        let styx_allow_global_v4 = LpmTrie::try_from(
            ebpf.take_map("STYX_ALLOW_GLOBAL_V4")
                .ok_or("STYX_ALLOW_GLOBAL_V4 missing")?,
        )?;
        let styx_allow_global_v6 = LpmTrie::try_from(
            ebpf.take_map("STYX_ALLOW_GLOBAL_V6")
                .ok_or("STYX_ALLOW_GLOBAL_V6 missing")?,
        )?;
        let mut styx_block_v4 = LpmTrie::try_from(
            ebpf.take_map("STYX_BLOCK_V4")
                .ok_or("STYX_BLOCK_V4 missing")?,
        )?;
        let mut styx_block_v6 = LpmTrie::try_from(
            ebpf.take_map("STYX_BLOCK_V6")
                .ok_or("STYX_BLOCK_V6 missing")?,
        )?;
        let styx_resolver_v4 = LpmTrie::try_from(
            ebpf.take_map("STYX_RESOLVER_V4")
                .ok_or("STYX_RESOLVER_V4 missing")?,
        )?;
        let styx_resolver_v6 = LpmTrie::try_from(
            ebpf.take_map("STYX_RESOLVER_V6")
                .ok_or("STYX_RESOLVER_V6 missing")?,
        )?;
        seed_styx_mandatory_veto(&mut styx_block_v4, &mut styx_block_v6)?;
        // One random epoch per core process: the Go control plane full-resyncs
        // its policy whenever this value changes (§5 resync contract). The global
        // word starts with OFF/0 so an upgraded host behaves like 5.2.0.
        let (styx_epoch, styx_epoch_hex) = random_styx_epoch()?;
        styx_global.set(
            0,
            styx_flow::encode_styx_global(styx_epoch as u32, STYX_MODE_OFF, 0),
            0,
        )?;
        let styx_flow_events = RingBuf::try_from(
            ebpf.take_map("FLOW_EVENTS").ok_or("FLOW_EVENTS missing")?,
        )?;
        let styx_flow_emitted = PerCpuArray::try_from(
            ebpf.take_map("FLOW_EVENTS_EMITTED")
                .ok_or("FLOW_EVENTS_EMITTED missing")?,
        )?;
        let styx_ring_drops = PerCpuArray::try_from(
            ebpf.take_map("FLOW_RING_DROPS")
                .ok_or("FLOW_RING_DROPS missing")?,
        )?;
        let styx_agg_insert_failures = PerCpuArray::try_from(
            ebpf.take_map("FLOW_AGG_INSERT_FAILURES")
                .ok_or("FLOW_AGG_INSERT_FAILURES missing")?,
        )?;
        let styx_egress_parse_errors = PerCpuArray::try_from(
            ebpf.take_map("EGRESS_PARSE_ERRORS")
                .ok_or("EGRESS_PARSE_ERRORS missing")?,
        )?;
        let styx_egress_drops_total = PerCpuArray::try_from(
            ebpf.take_map("EGRESS_DROPS_TOTAL")
                .ok_or("EGRESS_DROPS_TOTAL missing")?,
        )?;
        let styx_egress_policy_drops = PerCpuArray::try_from(
            ebpf.take_map("EGRESS_POLICY_DROPS")
                .ok_or("EGRESS_POLICY_DROPS missing")?,
        )?;
        let styx_resolved = ebpf.take_map("STYX_RESOLVED").ok_or("STYX_RESOLVED missing")?;
        let flow_agg_v4 = ebpf.take_map("FLOW_AGG_V4").ok_or("FLOW_AGG_V4 missing")?;
        let flow_agg_v6 = ebpf.take_map("FLOW_AGG_V6").ok_or("FLOW_AGG_V6 missing")?;
        // Point 1 (§4): Titan exec-gate maps are always taken, even while BPF
        // LSM is inactive, so a stale eBPF object fails loudly at startup.
        let titan_exec_state = AyaArray::try_from(
            ebpf.take_map("TITAN_EXEC_STATE").ok_or("TITAN_EXEC_STATE missing")?,
        )?;
        let titan_exec_offsets = AyaArray::try_from(
            ebpf.take_map("TITAN_EXEC_OFFSETS").ok_or("TITAN_EXEC_OFFSETS missing")?,
        )?;
        let titan_exec_modes = AyaHashMap::try_from(
            ebpf.take_map("TITAN_EXEC_MODE").ok_or("TITAN_EXEC_MODE missing")?,
        )?;
        let titan_exec_policy = AyaHashMap::try_from(
            ebpf.take_map("TITAN_EXEC_POLICY").ok_or("TITAN_EXEC_POLICY missing")?,
        )?;
        let titan_exec_events = RingBuf::try_from(
            ebpf.take_map("TITAN_EXEC_EVENTS").ok_or("TITAN_EXEC_EVENTS missing")?,
        )?;
        let titan_exec_emitted = PerCpuArray::try_from(
            ebpf.take_map("TITAN_EXEC_EVENTS_EMITTED")
                .ok_or("TITAN_EXEC_EVENTS_EMITTED missing")?,
        )?;
        let titan_exec_ring_drops = PerCpuArray::try_from(
            ebpf.take_map("TITAN_EXEC_RING_DROPS").ok_or("TITAN_EXEC_RING_DROPS missing")?,
        )?;
        let titan_exec_read_failures = PerCpuArray::try_from(
            ebpf.take_map("TITAN_EXEC_READ_FAILURES").ok_or("TITAN_EXEC_READ_FAILURES missing")?,
        )?;
        let titan_exec_denies = PerCpuArray::try_from(
            ebpf.take_map("TITAN_EXEC_POLICY_DENIES").ok_or("TITAN_EXEC_POLICY_DENIES missing")?,
        )?;
        let titan_exec_audits = PerCpuArray::try_from(
            ebpf.take_map("TITAN_EXEC_POLICY_AUDITS").ok_or("TITAN_EXEC_POLICY_AUDITS missing")?,
        )?;
        let titan_exec_ctime_rejects = PerCpuArray::try_from(
            ebpf.take_map("TITAN_EXEC_CTIME_REJECTS").ok_or("TITAN_EXEC_CTIME_REJECTS missing")?,
        )?;
        // Point 5 (§5/§8): the lockdown maps are mandatory like every other §4
        // map. A stale eBPF object must fail startup instead of running the
        // command surface without a kernel word to verify against.
        let lockdown_state = AyaArray::try_from(
            ebpf.take_map("LOCKDOWN_STATE").ok_or("LOCKDOWN_STATE missing")?,
        )?;
        let lockdown_drops = PerCpuArray::try_from(
            ebpf.take_map("LOCKDOWN_DROPS").ok_or("LOCKDOWN_DROPS missing")?,
        )?;
        let lockdown_witness = PerCpuArray::try_from(
            ebpf.take_map("LOCKDOWN_WITNESS_PASSES").ok_or("LOCKDOWN_WITNESS_PASSES missing")?,
        )?;
        let (titan_epoch, titan_epoch_hex) = random_epoch_word()?;
        let mut titan_exec = TitanExecGate {
            state: titan_exec_state,
            offsets: titan_exec_offsets,
            modes: titan_exec_modes,
            policy: titan_exec_policy,
            events: titan_exec_events,
            emitted: titan_exec_emitted,
            ring_drops: titan_exec_ring_drops,
            read_failures: titan_exec_read_failures,
            denies: titan_exec_denies,
            audits: titan_exec_audits,
            ctime_rejects: titan_exec_ctime_rejects,
            store: titan_exec::TitanExecPolicy::new(),
            epoch: titan_epoch as u32,
            epoch_hex: titan_epoch_hex,
            mode: TITAN_EXEC_MODE_OFF,
            flags: 0,
            lsm_active: bpf_lsm_active,
            offsets_valid: false,
            attached: false,
            last_ring_drops: 0,
            rejected_events: 0,
        };
        // §6: BTF offsets are validated before any attach; invalid offsets leave
        // STATE/OFFSETS at their fail-safe zero words and no hook is attached.
        // Valid offsets are published even when this eBPF build cannot attach
        // them (hook arity outside the hard-coded slots): the status then names
        // `offsets=valid` and `unavailable`, never a silent enforcement claim.
        let mut titan_slots_supported = false;
        match btf_offsets::resolve_vmlinux_offsets() {
            Ok(offsets) => {
                titan_exec.offsets_valid = true;
                titan_slots_supported = titan_exec_offsets_match_ebpf_slots(&offsets);
                for (index, value) in encode_titan_exec_offsets_table(&offsets).iter().enumerate() {
                    titan_exec.offsets.set(index as u32, *value, 0)?;
                }
                if !titan_slots_supported {
                    eprintln!(
                        "Titan exec gate unavailable: hook arity bprm={} mmap={} is not supported by this eBPF build; attaching nothing",
                        offsets.bprm_nargs, offsets.mmap_nargs
                    );
                }
            }
            Err(error) => eprintln!(
                "Titan exec gate unavailable: BTF offsets are invalid ({error}); attaching nothing"
            ),
        }
        if titan_exec.offsets_valid && titan_slots_supported && bpf_lsm_active {
            match &lsm_btf {
                Some(btf) => match attach_titan_exec_lsm(&mut ebpf, btf) {
                    Ok(()) => titan_exec.attached = true,
                    Err(error) if !require_cell_lsm => eprintln!(
                        "Titan exec gate attach failed ({error}); enforcement unavailable"
                    ),
                    Err(error) => {
                        return Err(format!("required Titan exec BPF LSM attach failed: {error}").into())
                    }
                },
                None => eprintln!("Titan exec gate not attached: BPF LSM BTF unavailable"),
            }
        } else if !bpf_lsm_active {
            eprintln!(
                "Titan exec gate inactive: BPF LSM is not active; no attach and no enforcement claim (activation requires `lsm=...,bpf` + reboot)"
            );
        } else if !titan_exec.offsets_valid {
            eprintln!("Titan exec gate unavailable: runtime offsets are invalid; no attach");
        }
        if titan_exec.offsets_valid {
            titan_exec.write_state()?;
        } else {
            eprintln!("Titan exec STATE/OFFSETS left at fail-safe zero words (offsets invalid)");
        }
        let mut mode = String::from(ingress_mode);
        if styx_ingress.attached() {
            mode.push_str("+styx-rx");
        }
        if cell_lsm_attached {
            mode.push_str("+bpf-lsm-cell");
        }
        mode.push_str("+titan-exec:");
        mode.push_str(titan_exec::ping_titan_exec_token(
            titan_exec.enforcement_available(),
            titan_exec.mode,
        ));
        let mut lockdown_config = lockdown::LockdownConfig::default();
        lockdown_config.state_file = Path::new(lockdown_state_path).to_path_buf();
        let lockdown = lockdown::LockdownCore::new(
            lockdown_config,
            Arc::new(AyaLockdownWordStore { map: Mutex::new(lockdown_state) }),
            Arc::new(LiveLockdownCounters {
                drops: lockdown_drops,
                witness_passes: lockdown_witness,
            }),
        )?;
        // 6.1.0 Module B: takes its mandatory maps and attaches the signal
        // tracepoint when the kernel permits it. An unavailable tracepoint is
        // reported as `attached=0`, never as enforcement.
        let worker_guard = worker_guard::WorkerGuardCore::load(&mut ebpf)?;
        // M2.2: mandatory RANSOM_* maps, optional kprobe attach, armed state.
        let ransom = ransom::RansomCore::load(&mut ebpf)?;
        // M2.4: mandatory CRED_GUARD_* maps, protected-inode policy, optional
        // file_open LSM attach (active=0 when BPF-LSM/BTF/policy are unavailable).
        let credential_guard =
            credential_guard::CredentialGuardCore::load(&mut ebpf, lsm_btf.as_ref(), bpf_lsm_active)?;
        let xdr_kernel = xdr_kernel::XdrKernelCore::load(&mut ebpf)?;
        // V6.3.0 AP-1: mandatory EXEC_INODE_* maps, BTF exe-inode offsets and the
        // default trusted path contract (fail-open when BTF is unavailable, with
        // an honest `offsets=0` status instead of a false enforcement claim).
        let exec_inode = exec_inode::ExecInodeCore::load(&mut ebpf)?;
        // V6.3.0 AP-2: mandatory BPF_GUARD_* maps, optional LSM/TP/kprobe attach;
        // unsupported hooks are reported as `attached=0`, never as enforcement.
        let bpf_guard =
            bpf_guard::BpfGuardCore::load(&mut ebpf, lsm_btf.as_ref(), bpf_lsm_active)?;
        // V6.3.0 AP-3: cross-view supports (socket-tap ring + counters); the
        // verifier itself drives the scans from the poll cadence.
        let mut cross_view = cross_view::CrossViewCore::load(&mut ebpf)?;
        cross_view.set_bpf_guard_lsm_attached(bpf_guard.lsm_attached());
        // V6.3.0 AP-4: io_uring/LKM hook ladder; unsupported hooks degrade the
        // status instead of claiming enforcement.
        let kernel_hooks =
            kernel_hooks::KernelHooksCore::load(&mut ebpf, lsm_btf.as_ref(), bpf_lsm_active)?;
        // V6.3.0 AP-5: persistence/peripheral LSM+TP hooks; same honest
        // degradation contract.
        let persistence =
            persistence::PersistenceCore::load(&mut ebpf, lsm_btf.as_ref(), bpf_lsm_active)?;
        // V6.3.0 AP-6: bounded DNS capture ring/tracepoints; unsupported
        // tracepoints degrade the status instead of claiming DNS visibility.
        let dns_capture = dns_capture::DnsCaptureCore::load(&mut ebpf)?;
        // V6.3.0 AP-9 (S12): mandatory high-priority ring, armed state and the
        // flood-bucket maps; a stale object must fail loudly.
        let sec_crit = sec_crit::SecCritCore::load(&mut ebpf)?;
        Ok(Self {
            _ebpf: ebpf.into_inner(),
            exec_events,
            egress_events,
            ingress_events,
            ingress_events_emitted,
            ingress_ring_drops,
            ingress_track_insert_failures,
            cell_lsm_events,
            cell_lsm_policies,
            allow_v4,
            allow_v6,
            v4,
            v6,
            blocked: HashSet::new(),
            mode,
            ingress_mode,
            cell_lsm_attached,
            cell_policy_epoch: random_epoch()?,
            styx_global,
            styx_mode,
            styx_cell_allow_v4,
            styx_cell_allow_v6,
            styx_allow_global_v4,
            styx_allow_global_v6,
            styx_block_v4,
            styx_block_v6,
            styx_resolver_v4,
            styx_resolver_v6,
            styx_flow_events,
            styx_flow_emitted,
            styx_ring_drops,
            styx_agg_insert_failures,
            styx_egress_parse_errors,
            styx_egress_drops_total,
            styx_egress_policy_drops,
            _styx_resolved: styx_resolved,
            _flow_agg_v4: flow_agg_v4,
            _flow_agg_v6: flow_agg_v6,
            styx_epoch,
            styx_epoch_hex,
            styx_last_ring_drops: 0,
            styx_flow_rejected: 0,
            titan_exec,
            lockdown,
            worker_guard,
            ransom,
            credential_guard,
            xdr_kernel,
            self_defense,
            exec_inode,
            bpf_guard,
            cross_view,
            kernel_hooks,
            persistence,
            styx_ingress,
            dns_capture,
            sec_crit,
        })
    }
}

/// Seeds the §4 mandatory veto. Failure is fatal at startup: the core must not
/// claim enforcement without the metadata/link-local/multicast guard.
pub(crate) fn seed_styx_mandatory_veto(
    block_v4: &mut LpmTrie<MapData, [u8; 4], u8>,
    block_v6: &mut LpmTrie<MapData, [u8; 16], u8>,
) -> Result<(), BoxError> {
    for (prefix, address) in STYX_MANDATORY_VETO_V4 {
        block_v4.insert(&Key::new(*prefix, *address), 1, 0)?;
    }
    for (prefix, address) in STYX_MANDATORY_VETO_V6 {
        block_v6.insert(&Key::new(*prefix, *address), 1, 0)?;
    }
    Ok(())
}

/// Random per-start epoch word plus its 16 lowercase hex characters; the low
/// 32 bits are what `STYX_GLOBAL`/`TITAN_EXEC_STATE` can carry.
pub(crate) fn random_epoch_word() -> Result<(u64, String), BoxError> {
    let mut bytes = [0u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let epoch = u64::from_ne_bytes(bytes);
    Ok((epoch, format!("{epoch:016x}")))
}

/// §5 `STYX_EPOCH`: random per core start.
pub(crate) fn random_styx_epoch() -> Result<(u64, String), BoxError> {
    random_epoch_word()
}

/// §0/§6: the Cell socket LSM program is only loaded with an active LSM list
/// (the caller checked `/sys/kernel/security/lsm`); BTF is parsed once per start.
pub(crate) fn attach_cell_socket_lsm(ebpf: &mut Ebpf, btf: &Btf) -> Result<(), BoxError> {
    let program: &mut Lsm = ebpf
        .program_mut(&chameleon::program_name("gedefense_cell_socket_create"))
        .ok_or("Gaia Cell socket LSM program missing")?
        .try_into()?;
    program.load("socket_create", btf)?;
    program.attach()?;
    Ok(())
}

/// §6: load and attach both Titan exec-gate hooks; only called when BPF LSM is
/// active and the BTF offsets were validated. Both attaches share one BTF.
pub(crate) fn attach_titan_exec_lsm(ebpf: &mut Ebpf, btf: &Btf) -> Result<(), BoxError> {
    for (symbol, hook) in [
        ("gedefense_titan_exec_bprm", "bprm_check_security"),
        ("gedefense_titan_exec_mmap", "mmap_file"),
    ] {
        let program: &mut Lsm = ebpf
            .program_mut(&chameleon::program_name(symbol))
            .ok_or_else(|| format!("Titan exec LSM program {symbol} missing"))?
            .try_into()?;
        program.load(hook, btf)?;
        program.attach()?;
    }
    Ok(())
}

pub(crate) fn random_epoch() -> Result<String, BoxError> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}
