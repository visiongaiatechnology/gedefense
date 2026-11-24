#![cfg(test)]
//! Wave 5a: IPC transport, dispatch-contract and hardening/IPC-admin tests
//! moved verbatim from `main_tests.rs` (structure-only split).

use super::*;

#[test]
fn target_parser_normalizes_networks() {
    match parse_target("203.0.113.77/24").expect("IPv4 target") {
        Target::V4(address, prefix) => {
            assert_eq!(address, Ipv4Addr::new(203, 0, 113, 0));
            assert_eq!(prefix, 24);
        }
        Target::V6(_, _) => panic!("unexpected IPv6 target"),
    }
    match parse_target("2001:db8::1234/64").expect("IPv6 target") {
        Target::V6(address, prefix) => {
            assert_eq!(address, "2001:db8::".parse::<Ipv6Addr>().unwrap());
            assert_eq!(prefix, 64);
        }
        Target::V4(_, _) => panic!("unexpected IPv4 target"),
    }
}

#[test]
fn target_parser_rejects_dangerous_or_invalid_networks() {
    assert!(parse_target("0.0.0.0/0").is_err());
    assert!(parse_target("::/0").is_err());
    assert!(parse_target("192.0.2.1/33").is_err());
    assert!(parse_target("2001:db8::1/129").is_err());
}

#[test]
fn protocol_tokens_are_strict() {
    assert!(valid_rule_token("XDR.MEMFD_EXEC"));
    assert!(!valid_rule_token("XDR MEMFD EXEC"));
    assert!(!valid_rule_token(""));
    assert!(valid_nonce("0123456789abcdef0123456789ABCDEF"));
    assert!(!valid_nonce("0123"));
    assert!(!valid_nonce("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
}

#[test]
fn cell_lsm_policy_tokens_are_strict() {
    assert_eq!(parse_cell_cgroup_id("42").unwrap(), 42);
    assert!(parse_cell_cgroup_id("0").is_err());
    assert!(parse_cell_cgroup_id("-1").is_err());
    assert_eq!(
        parse_cell_policy_flags("1").unwrap(),
        CELL_LSM_DENY_NON_UNIX_SOCKET
    );
    // 6.1.0: bit 0 (NON_UNIX) and bit 1 (AF_PACKET) are both known, so 3 is
    // a valid policy word. FIND-004: the old assertion still encoded the
    // pre-6.1.0 exclusive contract and failed.
    assert_eq!(
        parse_cell_policy_flags("3").unwrap(),
        CELL_LSM_DENY_NON_UNIX_SOCKET | CELL_LSM_DENY_AF_PACKET
    );
    // Every defined bit (0x7f = all seven) is accepted.
    assert_eq!(parse_cell_policy_flags("127").unwrap(), 0x7f);
    assert_eq!(parse_cell_policy_flags("127").unwrap(), CELL_LSM_DENY_ALL_KNOWN);
    assert_eq!(parse_cell_policy_flags("64").unwrap(), CELL_LSM_DENY_RDS);
    // Zero and unknown bits stay rejected.
    assert!(parse_cell_policy_flags("0").is_err());
    assert!(parse_cell_policy_flags("128").is_err());
    assert!(parse_cell_policy_flags("255").is_err());
}

#[test]
fn interface_names_reject_path_and_control_characters() {
    assert!(valid_interface_name("enp0s3"));
    assert!(valid_interface_name("veth.secure-1"));
    assert!(!valid_interface_name("../eth0"));
    assert!(!valid_interface_name("eth0/peer"));
    assert!(!valid_interface_name("eth0\n"));
    assert!(!valid_interface_name(""));
}

#[test]
fn replay_guard_rejects_duplicates_and_expires_old_entries() {
    let mut guard = ReplayGuard::new();
    let nonce = "0123456789abcdef0123456789abcdef";
    assert!(guard.accept(nonce, 100, 100));
    assert!(!guard.accept(nonce, 101, 101));
    // The same nonce with a *fresh* timestamp after the entry expired is a
    // new request, not a replay: the guard only holds nonces, not identities.
    assert!(guard.accept(
        nonce,
        100 + CLOCK_WINDOW_SECS + 1,
        100 + CLOCK_WINDOW_SECS + 1
    ));
}

#[test]
fn replay_guard_rejects_future_timestamps_and_closes_the_window_gap() {
    // The old |now - stamp| <= CLOCK_WINDOW_SECS check accepted a timestamp a
    // whole window in the future. The nonce was cached against the arrival
    // time but the timestamp stayed valid for a second window after the cache
    // entry expired, so [t+31, t+60] was a replay gap. Finding FIND-034.
    assert_eq!(request_timestamp_error(1_000, 1_000), None);
    assert_eq!(request_timestamp_error(1_000, 1_005), None);
    assert_eq!(
        request_timestamp_error(1_000, 1_000 + CLOCK_FUTURE_TOLERANCE_SECS),
        None
    );
    assert_eq!(
        request_timestamp_error(1_000, 1_001 + CLOCK_FUTURE_TOLERANCE_SECS),
        Some("future")
    );
    assert_eq!(request_timestamp_error(1_000, 1_030), Some("future"));
    assert_eq!(request_timestamp_error(1_000, 969), Some("stale"));
    assert_eq!(request_timestamp_error(1_000, 970), None);

    let nonce = "ffffffffffffffffffffffffffffffff";
    let mut guard = ReplayGuard::new();
    // A request with the maximum tolerated future stamp is accepted ...
    assert!(guard.accept(nonce, 1_000, 1_005));
    // ... and a duplicate inside the window is still a replay ...
    assert!(!guard.accept(nonce, 1_010, 1_005));
    // ... but at t+45 the request is both cache-expired and outside the
    // timestamp window: the replayed request must be refused.
    assert!(!guard.accept(nonce, 1_045, 1_005));
}

#[test]
fn replay_guard_keeps_accepting_new_requests_when_full() {
    // A burst larger than the cache must not lock the channel out.
    //
    // This is the shape the control plane produces whenever it applies a blocklist
    // larger than REPLAY_CACHE_CAPACITY: one command per entry, all inside one clock
    // window. The guard used to refuse every command past the 4096th as a replay -
    // including the health checks that decide whether the core is reachable - so the
    // platform reported its kernel channel offline while the kernel was answering,
    // and the list could never be applied in full.
    let mut guard = ReplayGuard::new();

    for i in 0..REPLAY_CACHE_CAPACITY {
        let nonce = format!("{i:032}");
        assert!(
            guard.accept(&nonce, 100, 100),
            "request {i} was refused before the cache was full"
        );
    }

    // One past the capacity. A nonce never seen before is not a replay.
    let fresh = "ffffffffffffffffffffffffffffffff";
    assert!(
        guard.accept(fresh, 100, 100),
        "a new request was refused because the cache was full"
    );

    // The duplicate check still holds at capacity, which is the property the guard
    // exists for.
    assert!(!guard.accept(fresh, 101, 101));

    // And the cache stays bounded while doing so.
    assert!(guard.set.len() <= REPLAY_CACHE_CAPACITY);
    assert!(guard.order.len() <= REPLAY_CACHE_CAPACITY);
}

#[test]
fn replay_guard_evicts_in_arrival_order() {
    // Eviction takes the oldest entry, so the window still covers the most recent
    // commands - the ones a replay would have to imitate to be useful.
    let mut guard = ReplayGuard::new();
    for i in 0..REPLAY_CACHE_CAPACITY {
        assert!(guard.accept(&format!("{i:032}"), 100, 100));
    }
    assert!(guard.accept("ffffffffffffffffffffffffffffffff", 100, 100));

    // The first nonce is the one that was evicted, so it is accepted again.
    assert!(guard.accept(&format!("{:032}", 0), 100, 100));
    // The most recently accepted one is still held, so its replay is refused.
    assert!(!guard.accept("ffffffffffffffffffffffffffffffff", 100, 100));
}

#[test]
fn cell_lsm_denials_with_af_unspec_are_skipped_not_wedged() {
    // The kernel LSM hook reports socket(2) creations verbatim; AF_UNSPEC (0)
    // is a legal family and was previously treated as invalid metadata, which
    // failed the whole event drain. One such record must be skipped only.
    let mut item = [0u8; std::mem::size_of::<CellLsmDenyEvent>()];
    item[0..8].copy_from_slice(&42u64.to_ne_bytes());
    item[8..12].copy_from_slice(&4242u32.to_ne_bytes());
    item[12..16].copy_from_slice(&1000u32.to_ne_bytes());
    item[16..20].copy_from_slice(&libc::AF_UNSPEC.to_ne_bytes());
    item[20] = ACTION_DROP;
    assert_eq!(
        decode_cell_lsm_deny_event(&item).expect("AF_UNSPEC is not corruption"),
        None
    );

    // A representable family still produces the typed record.
    item[16..20].copy_from_slice(&libc::AF_INET.to_ne_bytes());
    assert_eq!(
        decode_cell_lsm_deny_event(&item).expect("IPv4 denial"),
        Some("42:4242:1000:2".to_owned())
    );

    // AF_UNIX, unknown and negative families stay invalid metadata.
    for family in [libc::AF_UNIX, -1, i32::from(u8::MAX) + 1] {
        item[16..20].copy_from_slice(&family.to_ne_bytes());
        assert!(
            decode_cell_lsm_deny_event(&item).is_err(),
            "accepted family {family}"
        );
    }
    item[16..20].copy_from_slice(&libc::AF_INET.to_ne_bytes());
    item[20] = 0;
    assert!(decode_cell_lsm_deny_event(&item).is_err(), "accepted a non-drop action");
}

#[test]
fn sysctl_contract_is_exact_and_typed() {
    let (_, binary) =
        sysctl_spec("net.ipv4.conf.all.accept_redirects").expect("allowlisted sysctl");
    assert_eq!(binary, &["0", "1"]);
    let (_, ternary) = sysctl_spec("kernel.kptr_restrict").expect("allowlisted sysctl");
    assert_eq!(ternary, &["0", "1", "2"]);
    // The user-namespace boundary is a managed control: it must be allowlisted as a typed binary so
    // the transactional applier can set it and verify the post-state, and it must not become a way
    // to write an arbitrary path.
    let (userns_path, userns_domain) =
        sysctl_spec("kernel.unprivileged_userns_clone").expect("allowlisted userns sysctl");
    assert_eq!(userns_path, "/proc/sys/kernel/unprivileged_userns_clone");
    assert_eq!(userns_domain, &["0", "1"]);
    let (mptcp_path, mptcp_domain) =
        sysctl_spec("net.mptcp.enabled").expect("allowlisted MPTCP mitigation");
    assert_eq!(mptcp_path, "/proc/sys/net/mptcp/enabled");
    assert_eq!(mptcp_domain, &["0", "1"]);
    assert!(sysctl_spec("user.max_user_namespaces").is_none());
    assert!(sysctl_spec("kernel.core_pattern").is_none());
    assert!(sysctl_spec("../kernel/kptr_restrict").is_none());
}

#[test]
fn legacy_hardening_profiles_are_recognized_for_upgrade() {
    assert_eq!(
        recognized_hardening_state(LEGACY_HARDENING_SERVER).as_deref(),
        Some("linux-server-balanced")
    );
    assert_eq!(
        recognized_hardening_state(LEGACY_HARDENING_ASTRAEAOS).as_deref(),
        Some("astraeaos-workstation-strict")
    );
}

#[test]
fn custom_hardening_profiles_are_deterministic_and_bounded() {
    let profile = hardening_content("astraeaos-custom-0083").expect("valid custom profile");
    assert!(profile.contains("# Profile: astraeaos-custom-0083\n"));
    assert!(profile.contains("kernel.randomize_va_space = 2\n"));
    assert!(profile.contains("kernel.kptr_restrict = 2\n"));
    assert!(profile.contains("net.ipv4.tcp_syncookies = 1\n"));
    assert_eq!(
        recognized_hardening_state(&profile).as_deref(),
        Some("astraeaos-custom-0083")
    );
    for invalid in [
        "astraeaos-custom-0000",
        "astraeaos-custom-200000", // reserved bit 21 stays unassigned
        "astraeaos-custom-e00000", // above the 0x00df_ffff catalogue ceiling
        "astraeaos-custom-xyz1",
        "astraeaos-custom-001", // shorter than Go's %04x form
    ] {
        assert!(hardening_content(invalid).is_none(), "accepted {invalid}");
    }
    // The M5.1 high control bit (1 << 20) and the complete CIS profile are
    // now part of the same closed vocabulary the Go catalogue can emit.
    let high = hardening_content("astraeaos-custom-100000").expect("high custom mask");
    assert!(high.contains("net.ipv6.conf.all.disable_ipv6 = 1\n"));
    // V6.3.0 AP-4: both opt-in controls select together (bits 22 + 23 =
    // 0xc00000) and stay out of every shipped profile.
    let opt_in = hardening_content("astraeaos-custom-c00000").expect("AP-4 custom mask");
    assert!(opt_in.contains("kernel.io_uring_disabled = 1\n"));
    assert!(opt_in.contains("vm.memfd_noexec = 2\n"));
    for shipped in [
        "linux-server-balanced",
        "astraeaos-workstation-strict",
        "astraeaos-cis-l1",
    ] {
        let content = hardening_content(shipped).expect("shipped profile");
        assert!(
            !content.contains("kernel.io_uring_disabled"),
            "{shipped} must not switch io_uring hardening on"
        );
        assert!(
            !content.contains("vm.memfd_noexec"),
            "{shipped} must not switch memfd hardening on"
        );
    }
    let cis = hardening_content("astraeaos-cis-l1").expect("CIS profile");
    assert!(cis.contains("net.ipv4.conf.all.rp_filter = 1\n"));
    assert!(cis.contains("fs.protected_hardlinks = 1\n"));
    assert!(cis.contains("kernel.perf_event_paranoid = 3\n"));
    assert_eq!(
        recognized_hardening_state(&cis).as_deref(),
        Some("astraeaos-cis-l1")
    );
}

fn test_hardening_directory(label: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    path.push(format!(
        "vgt-hardening-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create hardening fixture directory");
    path
}

fn write_managed_hardening_fixture(
    directory: &Path,
    name: &str,
    profile: &str,
) -> std::path::PathBuf {
    let path = directory.join(name);
    let content = hardening_content(profile).expect("managed profile content");
    fs::write(&path, content).expect("write hardening fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("fixture permissions");
    path
}

fn directory_entries(directory: &Path) -> Vec<String> {
    fs::read_dir(directory)
        .expect("read hardening fixture directory")
        .map(|entry| {
            entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

// F-04: the exact defect the audit reproduced. A SET from absent to a
// profile must be readable back through the same GET path, and removing it
// must leave no stray files behind.
#[test]
fn hardening_compare_set_uses_one_canonical_file() {
    let directory = test_hardening_directory("roundtrip");
    assert_eq!(
        hardening_file_state_in(&directory).expect("initial state"),
        "absent"
    );
    assert_eq!(
        compare_set_hardening_file_in(&directory, "absent", "linux-server-balanced")
            .expect("create persistent hardening"),
        "linux-server-balanced"
    );
    assert_eq!(
        hardening_file_state_in(&directory).expect("post-set state"),
        "linux-server-balanced"
    );
    assert!(directory.join(HARDENING_FILE_NAME).is_file());
    assert!(!directory.join(LEGACY_HARDENING_FILE_NAMES[0]).exists());

    assert_eq!(
        compare_set_hardening_file_in(
            &directory,
            "linux-server-balanced",
            "astraeaos-workstation-strict"
        )
        .expect("replace persistent hardening"),
        "astraeaos-workstation-strict"
    );
    assert_eq!(
        hardening_file_state_in(&directory).expect("post-replace state"),
        "astraeaos-workstation-strict"
    );

    assert_eq!(
        compare_set_hardening_file_in(&directory, "astraeaos-workstation-strict", "absent")
            .expect("remove persistent hardening"),
        "absent"
    );
    assert_eq!(
        hardening_file_state_in(&directory).expect("post-remove state"),
        "absent"
    );
    assert!(!directory.join(HARDENING_FILE_NAME).exists());
    assert!(
        directory_entries(&directory).is_empty(),
        "temporary or stale files left behind: {:?}",
        directory_entries(&directory)
    );
    fs::remove_dir_all(&directory).ok();
}

// F-04 migration: a legacy 99-zzz file is migrated to the canonical path
// instead of being ignored (which made GET report absent forever).
#[test]
fn hardening_migrates_legacy_99_file() {
    let directory = test_hardening_directory("migrate");
    write_managed_hardening_fixture(
        &directory,
        LEGACY_HARDENING_FILE_NAMES[0],
        "linux-server-balanced",
    );
    assert_eq!(
        hardening_file_state_in(&directory).expect("migrated state"),
        "linux-server-balanced"
    );
    assert!(directory.join(HARDENING_FILE_NAME).is_file());
    assert!(!directory.join(LEGACY_HARDENING_FILE_NAMES[0]).exists());
    fs::remove_dir_all(&directory).ok();
}

// F-04 reconciliation: managed legacy strays are cleaned once the canonical
// file is authoritative, so they cannot win the sysctl.d sort order at boot.
#[test]
fn hardening_reconciles_managed_legacy_strays() {
    let directory = test_hardening_directory("reconcile");
    write_managed_hardening_fixture(&directory, HARDENING_FILE_NAME, "linux-server-balanced");
    write_managed_hardening_fixture(
        &directory,
        LEGACY_HARDENING_FILE_NAMES[0],
        "linux-server-balanced",
    );
    write_managed_hardening_fixture(
        &directory,
        LEGACY_HARDENING_FILE_NAMES[1],
        "linux-server-balanced",
    );
    assert_eq!(
        hardening_file_state_in(&directory).expect("reconciled state"),
        "linux-server-balanced"
    );
    assert!(!directory.join(LEGACY_HARDENING_FILE_NAMES[0]).exists());
    assert!(!directory.join(LEGACY_HARDENING_FILE_NAMES[1]).exists());
    fs::remove_dir_all(&directory).ok();
}

// F-04 negative: a stray file that GeDefense does not manage is never
// deleted and never silently ignored - the state read fails closed.
#[test]
fn hardening_rejects_unmanaged_stray_files() {
    let directory = test_hardening_directory("unmanaged");
    write_managed_hardening_fixture(&directory, HARDENING_FILE_NAME, "linux-server-balanced");
    let stray = directory.join(LEGACY_HARDENING_FILE_NAMES[0]);
    fs::write(&stray, "kernel.foo = 1\n").expect("write unmanaged stray");
    assert!(hardening_file_state_in(&directory).is_err());
    assert!(stray.exists(), "unmanaged file must not be deleted");

    let directory = test_hardening_directory("unmanaged-canonical");
    fs::write(directory.join(HARDENING_FILE_NAME), "kernel.foo = 1\n")
        .expect("write unmanaged canonical file");
    assert!(
        compare_set_hardening_file_in(&directory, "absent", "linux-server-balanced").is_err()
    );
    fs::remove_dir_all(&directory).ok();
}

#[test]
fn hardening_multiple_legacy_files_fail_closed() {
    let directory = test_hardening_directory("multiple-legacy");
    write_managed_hardening_fixture(
        &directory,
        LEGACY_HARDENING_FILE_NAMES[0],
        "linux-server-balanced",
    );
    write_managed_hardening_fixture(
        &directory,
        LEGACY_HARDENING_FILE_NAMES[1],
        "astraeaos-workstation-strict",
    );
    assert!(hardening_file_state_in(&directory).is_err());
    fs::remove_dir_all(&directory).ok();
}

#[test]
fn hardening_compare_set_precondition_mismatch_keeps_state() {
    let directory = test_hardening_directory("precondition");
    compare_set_hardening_file_in(&directory, "absent", "linux-server-balanced")
        .expect("create persistent hardening");
    assert!(compare_set_hardening_file_in(
        &directory,
        "astraeaos-workstation-strict",
        "absent"
    )
    .is_err());
    assert_eq!(
        hardening_file_state_in(&directory).expect("state after rejected compare-set"),
        "linux-server-balanced"
    );
    fs::remove_dir_all(&directory).ok();
}

// F-04 apply-on-boot support: only allowlisted, typed sysctl assignments may
// be derived from a persisted profile.
#[test]
fn hardening_assignments_are_allowlisted_and_typed() {
    let assignments =
        parse_hardening_assignments(&hardening_content("linux-server-balanced").unwrap())
            .expect("parse managed profile");
    assert!(assignments
        .iter()
        .any(|(key, value)| key == "kernel.kptr_restrict" && value == "2"));
    assert!(assignments
        .iter()
        .any(|(key, value)| key == "net.ipv4.tcp_syncookies" && value == "1"));
    for invalid in [
        "kernel.core_pattern = /tmp/evil\n",
        "kernel.kptr_restrict = 9\n",
        "kernel.kptr_restrict = 2\nkernel.kptr_restrict = 0\n",
        "# only a comment\n",
        "not an assignment\n",
    ] {
        assert!(
            parse_hardening_assignments(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
    let custom = hardening_content("astraeaos-custom-0001").expect("custom profile");
    assert_eq!(
        parse_hardening_assignments(&custom)
            .expect("custom assignments")
            .len(),
        1
    );
}

// F-20: the length-less 0x1f packing is only safe when no field contains the
// delimiter; the wire format itself stays compatible for valid fields.
#[test]
fn mac_field_packing_is_unambiguous() {
    let key = b"0123456789abcdef0123456789abcdef";
    assert_eq!(pack_mac_fields(&["a", "b"]).unwrap(), b"a\x1fb");
    assert_ne!(
        authenticated_mac(key, &["ab", "c"]).unwrap(),
        authenticated_mac(key, &["a", "bc"]).unwrap()
    );
    assert!(pack_mac_fields(&["a\x1fb", "c"]).is_err());
    assert!(authenticated_mac(key, &["a\x1fb", "c"]).is_err());
    assert!(verify_mac(key, &["a\x1fb", "c"], &"00".repeat(32)).is_err());

    // Compatibility: for delimiter-free fields the MAC is byte-identical to
    // the previous separator packing used by the control plane.
    let mut legacy = HmacSha256::new_from_slice(key).unwrap();
    legacy.update(b"VGT3");
    legacy.update(&[MAC_FIELD_SEPARATOR]);
    legacy.update(b"0123456789abcdef0123456789abcdef");
    assert_eq!(
        authenticated_mac(key, &["VGT3", "0123456789abcdef0123456789abcdef"]).unwrap(),
        legacy.finalize().into_bytes().to_vec()
    );
    let mac = authenticated_mac(key, &["safe", "fields"]).unwrap();
    verify_mac(key, &["safe", "fields"], &hex::encode(&mac)).expect("valid MAC");
    assert!(verify_mac(key, &["safe", "changed"], &hex::encode(&mac)).is_err());
}

// F-18: the root scanner's user scan socket is restricted to the control
// group and never world-accessible; a symlinked socket path is rejected.
#[test]
fn runtime_socket_permissions_are_restricted() {
    let directory = test_hardening_directory("socket");
    let path = directory.join("scan.sock");
    let listener = UnixListener::bind(&path).expect("bind test socket");
    let gid = unsafe { libc::getgid() };
    secure_runtime_socket(&path, gid, 0o660).expect("secure runtime socket");
    let mode = fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);
    assert_eq!(mode & 0o007, 0, "socket must not be accessible to other");
    drop(listener);

    let target = directory.join("target.sock");
    let target_listener = UnixListener::bind(&target).expect("bind target socket");
    let link = directory.join("link.sock");
    std::os::unix::fs::symlink(&target, &link).expect("create symlink");
    assert!(secure_runtime_socket(&link, gid, 0o660).is_err());
    drop(target_listener);
    fs::remove_dir_all(&directory).ok();
}

// FIND-034: the main control socket must take the same hardened route as the
// user scan socket - 0660, group-restricted, never world-accessible - instead
// of an inline bind + set_permissions without a symlink/ownership guard.
#[test]
fn ipc_socket_binding_is_hardened() {
    let directory = test_hardening_directory("ipc-socket");
    let path = directory.join("core.sock");
    let gid = unsafe { libc::getgid() };
    let listener =
        bind_secure_runtime_socket(&path, gid, 0o660).expect("bind hardened IPC socket");
    let metadata = fs::symlink_metadata(&path).expect("IPC socket metadata");
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);
    assert_eq!(mode & 0o007, 0, "IPC socket must not be accessible to other");
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(metadata.gid(), gid);
    drop(listener);

    // A symlink at the socket path is never accepted as the socket itself.
    let target = directory.join("target.sock");
    let target_listener = UnixListener::bind(&target).expect("bind target socket");
    let link = directory.join("linked.sock");
    std::os::unix::fs::symlink(&target, &link).expect("create symlink");
    assert!(secure_runtime_socket(&link, gid, 0o660).is_err());
    drop(target_listener);
    fs::remove_dir_all(&directory).ok();
}

// ------------------------------------------------------------------
// P3-T4: pure STYX contracts (§3.3/§4/§5) that need no live kernel map.
// ------------------------------------------------------------------
