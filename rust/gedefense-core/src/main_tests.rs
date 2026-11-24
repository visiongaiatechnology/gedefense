#![cfg(test)]
//! Wave 3a extraction: the crate-root test suite moved verbatim from the inline
//! `#[cfg(test)] mod tests` of `main.rs` (module name and `crate::tests` path
//! are preserved via `#[path]` in the crate root).


use super::*;
// 6.1.0 policy-bit expectations are test-only: the production path only
// needs the aggregate mask, so these stay out of the shipped import set.
use gedefense_common::{
    CELL_LSM_DENY_AF_PACKET, CELL_LSM_DENY_NON_UNIX_SOCKET, CELL_LSM_DENY_RDS,
};

use crate::ebpf_loader::*;
use crate::ipc::dispatch_lockdown::*;
use crate::ipc::dispatch_net::*;
use crate::ipc::dispatch_titan::*;
use crate::ipc::server::*;
use crate::poller::*;
use crate::sysctl_broker::*;

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

fn styx_cidr(family: u8, text: &str) -> styx_flow::StyxCidr {
    styx_flow::parse_cidr(family, text).expect("valid fixture cidr")
}

fn styx_allow(args: &[&str]) -> styx_flow::StyxAllowRequest {
    styx_flow::parse_allow_request(args).expect("valid fixture allow request")
}

#[test]
fn styx_cidr_parsing_accepts_canonical_forms_only() {
    assert_eq!(
        styx_cidr(4, "203.0.113.0/24").address,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0))
    );
    assert_eq!(styx_cidr(4, "203.0.113.7").prefix, 32);
    assert_eq!(styx_cidr(4, "0.0.0.0/0").prefix, 0);
    assert_eq!(styx_cidr(6, "2001:db8::/32").prefix, 32);
    assert_eq!(styx_cidr(6, "::1/128").address, IpAddr::V6(Ipv6Addr::LOCALHOST));
    for (family, token) in [
        (4u8, "203.0.113.9/24"), // host bits set
        (4, "1.2.3.4/0"),
        (4, "0.0.0.0/33"),
        (4, "2001:db8::/32"),
        (6, "203.0.113.0/24"),
        (6, "2001:db8::1/129"),
        (6, "::ffff:1.2.3.4/128"),
        (4, " 10.0.0.0/8"),
        (4, "10.0.0.0/8\n"),
        (4, "10.0.0.0/8\0"),
        (4, ""),
        (4, "10.0.0.0/"),
        (4, "10.0.0.0/8/8"),
        (5, "10.0.0.0/8"),
    ] {
        assert!(
            styx_flow::parse_cidr(family, token).is_err(),
            "{family} {token:?} was accepted"
        );
    }
    let oversized = format!("10.0.0.0/8{}", "0".repeat(140));
    assert!(styx_flow::parse_cidr(4, &oversized).is_err());
}

#[test]
fn styx_veto_cidr_enforces_the_seed_prefix_ranges() {
    for token in [
        "0.0.0.0/8",
        "169.254.0.0/16",
        "100.100.100.200/32",
        "224.0.0.0/4",
    ] {
        assert!(styx_flow::parse_prefix_cidr(4, token).is_ok(), "{token}");
    }
    for token in ["0.0.0.0/0", "10.0.0.0/1", "10.0.0.0/3"] {
        assert!(styx_flow::parse_prefix_cidr(4, token).is_err(), "{token}");
    }
    for token in ["fd00:ec2::254/128", "fe80::/10", "ff00::/8"] {
        assert!(styx_flow::parse_prefix_cidr(6, token).is_ok(), "{token}");
    }
    for token in ["::/0", "2001:db8::/7"] {
        assert!(styx_flow::parse_prefix_cidr(6, token).is_err(), "{token}");
    }
}

#[test]
fn styx_numeric_and_flag_arguments_are_strict() {
    assert_eq!(styx_flow::parse_u16("443").unwrap(), 443);
    assert_eq!(styx_flow::parse_cgroup_id("42").unwrap(), 42);
    for token in ["", " 1", "1 ", "+1", "-1", "0x10", "1_0", "\u{661}"] {
        assert!(styx_flow::parse_u16(token).is_err(), "{token:?}");
    }
    for token in ["0", "1", "2"] {
        assert_eq!(
            styx_flow::parse_mode(token).unwrap(),
            token.parse::<u8>().unwrap()
        );
    }
    for token in ["3", "7", "255", "-1"] {
        assert!(styx_flow::parse_mode(token).is_err(), "{token}");
    }
    assert_eq!(styx_flow::parse_mode_flags("120").unwrap(), 120);
    for token in ["7", "128", "255"] {
        assert!(styx_flow::parse_mode_flags(token).is_err(), "{token}");
    }
    assert_eq!(styx_flow::parse_global_flags("0").unwrap(), 0);
    assert_eq!(
        styx_flow::parse_global_flags("1").unwrap(),
        gedefense_common::STYX_FLAG_LOG_FLOWS
    );
    for token in ["2", "64", "255"] {
        assert!(styx_flow::parse_global_flags(token).is_err(), "{token}");
    }
    assert_eq!(styx_flow::parse_port_range("0", "65535").unwrap(), (0, 65535));
    assert_eq!(styx_flow::parse_port_range("443", "443").unwrap(), (443, 443));
    assert!(styx_flow::parse_port_range("443", "80").is_err());
    for token in ["0", "1", "2", "3"] {
        assert_eq!(
            styx_flow::parse_proto_mask(token).unwrap(),
            token.parse::<u8>().unwrap()
        );
    }
    assert!(styx_flow::parse_proto_mask("4").is_err());
}

#[test]
fn styx_allow_request_validates_scope_family_and_shape() {
    let request = styx_allow(&["4", "cell", "42", "203.0.113.0/24", "0", "65535", "3"]);
    assert_eq!(request.cgroup_id, 42);
    assert_eq!(request.scope, styx_flow::StyxScope::Cell);
    let request = styx_allow(&["6", "global", "0", "2001:db8::/32", "53", "53", "1"]);
    assert_eq!(request.scope, styx_flow::StyxScope::Global);
    assert_eq!(request.cidr.family, 6);
    for args in [
        &["4", "cell", "0", "203.0.113.0/24", "0", "65535", "3"][..],
        &["4", "global", "42", "203.0.113.0/24", "0", "65535", "3"],
        &["5", "cell", "42", "203.0.113.0/24", "0", "65535", "3"],
        &["4", "zone", "42", "203.0.113.0/24", "0", "65535", "3"],
        &["4", "cell", "42", "203.0.113.0/24", "65535", "0", "3"],
        &["4", "cell", "42", "203.0.113.0/24", "0", "65535", "4"],
        &["4", "cell", "42", "203.0.113.9/24", "0", "65535", "3"],
        &["4", "cell", "42"],
    ] {
        assert!(
            styx_flow::parse_allow_request(args).is_err(),
            "{args:?} was accepted"
        );
    }
    assert_eq!(
        styx_flow::parse_allow_request(&["4", "cell"]).unwrap_err(),
        styx_flow::UNKNOWN_COMMAND
    );
}

#[test]
fn styx_command_shapes_reject_unknown_arity_and_bad_values() {
    use styx_flow::UNKNOWN_COMMAND;
    assert_eq!(styx_flow::parse_global_request(&[]).unwrap_err(), UNKNOWN_COMMAND);
    assert_eq!(
        styx_flow::parse_global_request(&["1"]).unwrap_err(),
        UNKNOWN_COMMAND
    );
    assert_eq!(
        styx_flow::parse_global_request(&["1", "0", "0"]).unwrap_err(),
        UNKNOWN_COMMAND
    );
    assert_eq!(styx_flow::parse_global_request(&["1", "0"]).unwrap().mode, 1);
    assert!(styx_flow::parse_global_request(&["3", "0"]).is_err());
    assert_eq!(
        styx_flow::parse_mode_set_request(&["9", "2", "64"]).unwrap(),
        (9, 2, 64)
    );
    assert_eq!(
        styx_flow::parse_mode_set_request(&["0", "2", "0"]).unwrap_err(),
        "styx cgroup id must be non-zero"
    );
    assert_eq!(styx_flow::parse_mode_del_request(&["9"]).unwrap(), 9);
    assert_eq!(
        styx_flow::parse_mode_del_request(&["9", "9"]).unwrap_err(),
        UNKNOWN_COMMAND
    );
    assert_eq!(
        styx_flow::parse_prefix_request(&["4", "169.254.0.0/16"])
            .unwrap()
            .prefix,
        16
    );
    assert_eq!(
        styx_flow::parse_prefix_request(&["4"]).unwrap_err(),
        UNKNOWN_COMMAND
    );
}

#[test]
fn styx_cell_v4_allow_keys_follow_section_four() {
    use styx_flow::StyxAllowKey;
    let cgroup = 0x0102_0304_0506_0708u64;
    match styx_allow(&["4", "cell", "72623859790382856", "0.0.0.0/0", "0", "65535", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::CellV4(key, prefix) => {
            assert_eq!(prefix, 64);
            assert_eq!(&key[..8], &cgroup.to_le_bytes());
            assert_eq!(&key[8..], &[0u8; 8]);
        }
        other => panic!("{other:?}"),
    }
    match styx_allow(&["4", "cell", "7", "10.0.0.0/8", "0", "65535", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::CellV4(key, prefix) => {
            assert_eq!(prefix, 72);
            assert_eq!(&key[8..12], &[10, 0, 0, 0]);
        }
        other => panic!("{other:?}"),
    }
    match styx_allow(&["4", "cell", "7", "203.0.113.9/32", "443", "443", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::CellV4(key, prefix) => {
            assert_eq!(prefix, 112);
            assert_eq!(&key[12..14], &443u16.to_be_bytes());
            assert_eq!(key[14], 0);
        }
        other => panic!("{other:?}"),
    }
    match styx_allow(&["4", "cell", "7", "203.0.113.9/32", "443", "443", "1"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::CellV4(key, prefix) => {
            assert_eq!(prefix, 120);
            assert_eq!(key[14], gedefense_common::STYX_PROTO_TCP);
        }
        other => panic!("{other:?}"),
    }
    assert!(styx_allow(&["4", "cell", "7", "10.0.0.0/8", "443", "443", "3"])
        .allow_key()
        .is_err());
    assert!(styx_allow(&["4", "cell", "7", "203.0.113.9/32", "0", "65535", "1"])
        .allow_key()
        .is_err());
    assert!(styx_allow(&["4", "cell", "7", "203.0.113.9/32", "1", "2", "3"])
        .allow_key()
        .is_err());
}

#[test]
fn styx_cell_v6_and_global_keys_follow_section_four() {
    use styx_flow::StyxAllowKey;
    match styx_allow(&["6", "cell", "7", "2001:db8::/64", "53", "53", "1"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::CellV6(key, prefix) => {
            assert_eq!(prefix, 128);
            assert_eq!(&key[..8], &7u64.to_le_bytes());
            assert_eq!(&key[8..12], &[0x20, 0x01, 0x0d, 0xb8]);
        }
        other => panic!("{other:?}"),
    }
    match styx_allow(&["4", "global", "0", "203.0.113.0/24", "0", "65535", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::GlobalV4(key, prefix) => {
            assert_eq!(prefix, 24);
            assert_eq!(&key[..4], &[203, 0, 113, 0]);
        }
        other => panic!("{other:?}"),
    }
    match styx_allow(&["4", "global", "0", "203.0.113.9/32", "53", "53", "2"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::GlobalV4(key, prefix) => {
            assert_eq!(prefix, 56);
            assert_eq!(&key[4..6], &53u16.to_be_bytes());
            assert_eq!(key[6], gedefense_common::STYX_PROTO_UDP);
        }
        other => panic!("{other:?}"),
    }
    // §4 prefixes 48 (global-v4 +port) and 144/152 (global-v6) as well as
    // the full 192-bit cell-v6 lookup key must be exactly reproducible.
    match styx_allow(&["4", "global", "0", "203.0.113.9/32", "53", "53", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::GlobalV4(_, prefix) => assert_eq!(prefix, 48),
        other => panic!("{other:?}"),
    }
    match styx_allow(&["6", "cell", "7", "2001:db8::1/128", "0", "65535", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::CellV6(_, prefix) => assert_eq!(prefix, 192),
        other => panic!("{other:?}"),
    }
    match styx_allow(&["6", "global", "0", "2001:db8::1/128", "853", "853", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::GlobalV6(_, prefix) => assert_eq!(prefix, 144),
        other => panic!("{other:?}"),
    }
    match styx_allow(&["6", "global", "0", "2001:db8::/128", "853", "853", "1"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::GlobalV6(key, prefix) => {
            assert_eq!(prefix, 152);
            assert_eq!(&key[16..18], &853u16.to_be_bytes());
            assert_eq!(key[18], gedefense_common::STYX_PROTO_TCP);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn styx_policy_prefix_keys_are_bare_networks() {
    use styx_flow::StyxPrefixKey;
    assert_eq!(
        styx_flow::parse_prefix_cidr(4, "169.254.0.0/16")
            .unwrap()
            .prefix_key()
            .unwrap(),
        StyxPrefixKey::V4([169, 254, 0, 0], 16)
    );
    match styx_flow::parse_prefix_cidr(6, "fe80::/10")
        .unwrap()
        .prefix_key()
        .unwrap()
    {
        StyxPrefixKey::V6(key, prefix) => {
            assert_eq!(prefix, 10);
            assert_eq!(&key[..2], &[0xfe, 0x80]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn styx_global_word_packs_epoch_flags_and_mode() {
    let word =
        styx_flow::encode_styx_global(0xdead_beef, 2, gedefense_common::STYX_FLAG_LOG_FLOWS);
    assert_eq!(word & 0xffff_ffff, 0xdead_beef);
    assert_eq!(
        (word >> 32) as u8,
        gedefense_common::STYX_FLAG_LOG_FLOWS
    );
    assert_eq!((word >> 40) as u8, 2);
    assert_eq!(styx_flow::encode_styx_global(1, 0, 0), 1);
}

fn styx_fixture_event() -> gedefense_common::FlowEvent {
    gedefense_common::FlowEvent {
        cgroup_id: 0x0102_0304_0506_0708,
        ts_ns: 9,
        tx_bytes: 10,
        rx_bytes: 0,
        pid: 42,
        uid: 1000,
        dst: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9],
        src: [0u8; 16],
        dst_port: 443,
        src_port: 51_234,
        packets: 3,
        proto: gedefense_common::STYX_PROTO_TCP,
        family: NETWORK_FAMILY_V4,
        direction: gedefense_common::STYX_DIR_EGRESS,
        tcp_flags: 0x18,
        verdict: gedefense_common::STYX_VERDICT_ALLOW,
        reserved: [0; 3],
        comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
    }
}

#[test]
fn styx_flow_text_wire_matches_the_contract() {
    let text =
        styx_flow::encode_styx_flow_event_text(&styx_fixture_event()).expect("encodable event");
    assert_eq!(
        text,
        "0102030405060708:9:10:0:42:1000:cb007109:443:51234:3:4:6:1:24:0:6375726c"
    );
    assert_eq!(text.split(':').count(), 16);
    // A comm with bytes the Go decoder refuses degrades to an empty field ...
    let mut event = styx_fixture_event();
    event.comm = *b"Web Content\0\0\0\0\0";
    let text = styx_flow::encode_styx_flow_event_text(&event).expect("encodable event");
    assert!(text.ends_with(':'), "comm field not degraded: {text}");
    // ... while non-representable records are skipped instead of poisoning
    // an entire batch.
    let mut event = styx_fixture_event();
    event.pid = i32::MAX as u32 + 1;
    assert!(styx_flow::encode_styx_flow_event_text(&event).is_none());
    let mut event = styx_fixture_event();
    event.family = NETWORK_FAMILY_V6;
    event.dst = [0u8; 16];
    assert!(styx_flow::encode_styx_flow_event_text(&event).is_none());
    let mut event = styx_fixture_event();
    event.comm = [b'x'; 16];
    assert!(styx_flow::encode_styx_flow_event_text(&event).is_none());
}

#[test]
fn styx_flow_batch_is_bounded_and_reports_drops() {
    // 6.2.0 flow-telemetry contract: the eBPF ring grew to 16 MiB, the core
    // drains 64 records per poll and the response ceiling covers the whole
    // base64url-encoded batch. Pinning the numbers here makes an accidental
    // rollback to the 8-record/2048-byte StyX limits fail loudly.
    assert_eq!(styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE, 64);
    assert_eq!(styx_flow::MAX_STYX_FLOW_PAYLOAD_BYTES, 16 * 1024);
    assert_eq!(MAX_RESPONSE_BYTES, 24 * 1024);
    // base64url(16 KiB) plus the "VGT3R <nonce> <status> <payload> <mac>"
    // line must fit the control-plane reader after the Go-side update.
    assert!(styx_flow::MAX_STYX_FLOW_PAYLOAD_BYTES.div_ceil(3) * 4 + 128 < MAX_RESPONSE_BYTES);
    assert_eq!(styx_flow_batch_response(&[], 0), "empty");
    assert_eq!(styx_flow_batch_response(&[], 7), "7|");
    assert_eq!(
        styx_flow_batch_response(&["a".to_owned(), "b".to_owned()], 3),
        "3|a,b"
    );
    let mut event = styx_fixture_event();
    event.cgroup_id = u64::MAX;
    event.ts_ns = u64::MAX;
    event.tx_bytes = u64::MAX;
    event.rx_bytes = u64::MAX;
    event.pid = i32::MAX as u32;
    event.uid = u32::MAX;
    event.packets = u32::MAX;
    event.family = NETWORK_FAMILY_V6;
    event.dst = [0xff; 16];
    event.proto = 0;
    event.tcp_flags = 0;
    event.dst_port = 0;
    event.src_port = 0;
    event.comm = *b"fifteen-char-na\0";
    let record = styx_flow::encode_styx_flow_event_text(&event).expect("maximal record");
    let records = vec![record; styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE];
    let batch = styx_flow_batch_response(&records, u64::MAX);
    assert_eq!(
        batch.split(',').count(),
        styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE
    );
    assert!(
        batch.len() <= styx_flow::MAX_STYX_FLOW_PAYLOAD_BYTES,
        "batch of {batch:?} bytes"
    );
}

#[test]
fn styx_flow_health_has_six_decimal_fields() {
    assert_eq!(
        styx_flow::encode_styx_flow_health(&[1, 2, 3, 4, 5, 6]),
        "1:2:3:4:5:6"
    );
    let maximal = styx_flow::encode_styx_flow_health(&[u64::MAX; 6]);
    assert_eq!(maximal.split(':').count(), 6);
    assert!(maximal.len() <= 160);
}

#[test]
fn styx_epoch_is_sixteen_lowercase_hex_characters() {
    let (value, hex_epoch) = random_styx_epoch().expect("random epoch");
    assert_eq!(hex_epoch.len(), 16);
    assert!(hex_epoch
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    assert_eq!(hex_epoch, format!("{value:016x}"));
}

#[test]
fn styx_map_results_are_explicit_and_deletes_idempotent() {
    assert_eq!(styx_map_result(Ok(()), true).unwrap(), "added");
    assert_eq!(styx_map_result(Ok(()), false).unwrap(), "deleted");
    assert_eq!(
        styx_map_result(Err(MapError::KeyNotFound), false).unwrap(),
        "deleted"
    );
    assert!(styx_map_result(Err(MapError::KeyNotFound), true).is_err());
    assert!(styx_map_result(Err(MapError::InvalidMapType { map_type: 0 }), false).is_err());
}

// ---- Point 1: synthetic BTF fixtures for the mini parser (§4.1/§6). ----
//
// The parser module is capped at 500 lines, so its fixtures live here. The
// `6.18`/`7.0` layouts below use the §4.1 golden values (BTF-verified on
// those kernels); broken variants must be `Err`, never a heuristic.

struct BtfFixture {
    strings: Vec<u8>,
    types: Vec<Vec<u8>>,
}

impl BtfFixture {
    fn new() -> Self {
        Self {
            strings: vec![0],
            types: Vec::new(),
        }
    }

    fn name(&mut self, name: &str) -> u32 {
        let offset = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        offset
    }

    fn push(
        &mut self,
        name_off: u32,
        kind: u8,
        vlen: u16,
        flag: bool,
        value: u32,
        extra: &[u8],
    ) -> u32 {
        let mut info = (u32::from(kind) << 24) | u32::from(vlen);
        if flag {
            info |= 1 << 31;
        }
        let mut encoded = Vec::with_capacity(12 + extra.len());
        encoded.extend_from_slice(&name_off.to_le_bytes());
        encoded.extend_from_slice(&info.to_le_bytes());
        encoded.extend_from_slice(&value.to_le_bytes());
        encoded.extend_from_slice(extra);
        self.types.push(encoded);
        self.types.len() as u32
    }

    fn int(&mut self, name: &str, size: u32) -> u32 {
        let name_off = self.name(name);
        self.push(name_off, 1, 0, false, size, &size.to_le_bytes())
    }

    fn pointer(&mut self, pointee: u32) -> u32 {
        self.push(0, 2, 0, false, pointee, &[])
    }

    fn record(
        &mut self,
        name: &str,
        union: bool,
        flag: bool,
        size: u32,
        members: &[(u32, u32, u32)],
    ) -> u32 {
        let name_off = self.name(name);
        let mut extra = Vec::new();
        for (member_name, type_id, offset_bits) in members {
            extra.extend_from_slice(&member_name.to_le_bytes());
            extra.extend_from_slice(&type_id.to_le_bytes());
            extra.extend_from_slice(&offset_bits.to_le_bytes());
        }
        self.push(
            name_off,
            if union { 5 } else { 4 },
            members.len() as u16,
            flag,
            size,
            &extra,
        )
    }

    fn func_proto(&mut self, params: u16, param_type: u32) -> u32 {
        let mut extra = Vec::new();
        for _ in 0..params {
            extra.extend_from_slice(&0u32.to_le_bytes());
            extra.extend_from_slice(&param_type.to_le_bytes());
        }
        self.push(0, 13, params, false, 0, &extra)
    }

    fn func(&mut self, name: &str, proto: u32) -> u32 {
        let name_off = self.name(name);
        self.push(name_off, 12, 0, false, proto, &[])
    }

    fn finish(self) -> Vec<u8> {
        let type_len: u32 = self.types.iter().map(|encoded| encoded.len() as u32).sum();
        let mut data = Vec::new();
        data.extend_from_slice(&btf_offsets::BTF_MAGIC.to_le_bytes());
        data.push(btf_offsets::BTF_VERSION);
        data.push(0);
        data.extend_from_slice(&(btf_offsets::BTF_HEADER_BYTES as u32).to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&type_len.to_le_bytes());
        data.extend_from_slice(&type_len.to_le_bytes());
        data.extend_from_slice(&(self.strings.len() as u32).to_le_bytes());
        for encoded in &self.types {
            data.extend_from_slice(encoded);
        }
        data.extend_from_slice(&self.strings);
        data
    }
}

#[derive(Clone, Copy, Debug)]
struct TitanBtfSpec {
    inode_size: u32,
    file_size: u32,
    bprm_size: u32,
    super_size: u32,
    bprm_nargs: u16,
    mmap_nargs: u16,
    i_ino_off: u32,
    drop_ino: bool,
    drop_super: bool,
    duplicate_inode: bool,
    // §4.1 ctime-Layout-Vertrag: `false` = legacy timespec64, `true` =
    // modern split `i_ctime_sec`/`i_ctime_nsec`; width 2 is the invalid probe.
    ctime_split: bool,
    split_nsec_width: u32,
    drop_ctime: bool,
}

impl Default for TitanBtfSpec {
    fn default() -> Self {
        Self {
            inode_size: 600,
            file_size: 256,
            bprm_size: 128,
            super_size: 256,
            bprm_nargs: 1,
            mmap_nargs: 4,
            i_ino_off: 64,
            drop_ino: false,
            drop_super: false,
            duplicate_inode: false,
            ctime_split: false,
            split_nsec_width: 4,
            drop_ctime: false,
        }
    }
}

/// Synthetic vmlinux-BTF with the §4.1 layout: anonymous union (`i_nlink`),
/// `kind_flag` bitfield (`i_opflags`), both ctime layouts and both LSM hooks.
fn titan_btf_fixture(spec: &TitanBtfSpec) -> Vec<u8> {
    let mut fixture = BtfFixture::new();
    let u16t = fixture.int("u16", 2);
    let u32t = fixture.int("u32", 4);
    let u64t = fixture.int("u64", 8);
    let i64t = fixture.int("i64", 8);
    let ulong = fixture.int("unsigned long", 8);
    let pointer = fixture.pointer(u32t);
    let tv_sec = fixture.name("tv_sec");
    let tv_nsec = fixture.name("tv_nsec");
    let timespec = fixture.record(
        "timespec64",
        false,
        false,
        16,
        &[(tv_sec, i64t, 0), (tv_nsec, i64t, 64)],
    );
    let i_nlink = fixture.name("i_nlink");
    let alternate = fixture.name("__i_nlink");
    let anonymous_union = fixture.record("", true, false, 4, &[(i_nlink, u32t, 0), (alternate, u32t, 0)]);
    let i_uid = fixture.name("i_uid");
    let d_parent = fixture.name("d_parent");
    let d_inode = fixture.name("d_inode");
    let path_mnt = fixture.name("mnt");
    let path_dentry = fixture.name("dentry");
    let f_path = fixture.name("f_path");
    let bprm_filename = fixture.name("filename");
    let i_mode = fixture.name("i_mode");
    let i_opflags = fixture.name("i_opflags");
    let i_ino = fixture.name("i_ino");
    let i_sb = fixture.name("i_sb");
    let i_generation = fixture.name("i_generation");
    let i_ctime = fixture.name("i_ctime");
    let i_ctime_sec = fixture.name("i_ctime_sec");
    let i_ctime_nsec = fixture.name("i_ctime_nsec");
    let split_nsec = match spec.split_nsec_width {
        8 => u64t,
        4 => u32t,
        _ => u16t,
    };
    let mut inode_members = vec![
        (i_mode, u16t, 0),
        (i_opflags, u16t, 16 | (4 << 24)),
        (i_uid, u32t, 8 * 8),
        (i_sb, pointer, 40 * 8),
        (0, anonymous_union, 72 * 8),
        (i_generation, u32t, 124 * 8),
    ];
    if spec.ctime_split {
        inode_members.push((i_ctime_sec, u64t, 104 * 8));
        inode_members.push((i_ctime_nsec, split_nsec, 120 * 8));
    } else if !spec.drop_ctime {
        inode_members.push((i_ctime, timespec, 128 * 8));
    }
    if !spec.drop_ino {
        inode_members.push((i_ino, u64t, spec.i_ino_off * 8));
    }
    fixture.record("inode", false, true, spec.inode_size, &inode_members);
    if spec.duplicate_inode {
        fixture.record("inode", false, false, spec.inode_size, &[(i_mode, u16t, 0)]);
    }
    let f_inode = fixture.name("f_inode");
    // §4.1 ABI 2: the bounded `file -> f_path.dentry -> d_parent` chain for
    // the UNTRUSTED world-writable ancestor check. The dentry walk below
    // reads the inode mode of each ancestor directory.
    let _dentry = fixture.record(
        "dentry",
        false,
        false,
        256,
        &[(d_parent, pointer, 16 * 8), (d_inode, pointer, 24 * 8)],
    );
    let path = fixture.record(
        "path",
        false,
        false,
        16,
        &[(path_mnt, pointer, 0), (path_dentry, pointer, 8 * 8)],
    );
    fixture.record(
        "file",
        false,
        false,
        spec.file_size,
        &[(f_inode, pointer, 32 * 8), (f_path, path, 96 * 8)],
    );
    let bprm_file = fixture.name("file");
    fixture.record(
        "linux_binprm",
        false,
        false,
        spec.bprm_size,
        &[(bprm_file, pointer, 64 * 8), (bprm_filename, pointer, 8 * 8)],
    );
    if !spec.drop_super {
        let s_dev = fixture.name("s_dev");
        let s_magic = fixture.name("s_magic");
        fixture.record(
            "super_block",
            false,
            false,
            spec.super_size,
            &[(s_dev, u32t, 16 * 8), (s_magic, ulong, 96 * 8)],
        );
    }
    let bprm_proto = fixture.func_proto(spec.bprm_nargs, pointer);
    fixture.func("bpf_lsm_bprm_check_security", bprm_proto);
    let mmap_proto = fixture.func_proto(spec.mmap_nargs, pointer);
    fixture.func("bpf_lsm_mmap_file", mmap_proto);
    fixture.finish()
}

/// Parses a synthetic BTF image and resolves the validated §4.1 offsets.
fn resolve_titan_btf(data: Vec<u8>) -> Result<btf_offsets::TitanExecOffsets, String> {
    btf_offsets::VmlinuxBtf::parse(data)?.resolve_titan_exec()
}

fn test_titan_directory(label: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    path.push(format!("vgt-titan-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("create titan fixture directory");
    path
}

#[test]
fn titan_btf_golden_offsets_resolve_for_6_18_and_7_0() {
    // Golden values from §4.1 (x86_64, BTF-verified on 6.18/7.0); the 7.0
    // fixture only grows the inode struct, so the field offsets must stay.
    for (label, inode_size) in [("6.18", 600u32), ("7.0", 640)] {
        let spec = TitanBtfSpec {
            inode_size,
            ..Default::default()
        };
        let offsets =
            resolve_titan_btf(titan_btf_fixture(&spec)).expect(label);
        let resolved = [
            (offsets.bprm_file_off, 64),
            (offsets.file_f_inode_off, 32),
            (offsets.inode_i_ino_off, 64),
            (offsets.inode_i_sb_off, 40),
            (offsets.inode_i_nlink_off, 72),
            (offsets.inode_i_mode_off, 0),
            (offsets.inode_i_generation_off, 124),
            (offsets.super_s_dev_off, 16),
            (offsets.super_s_magic_off, 96),
            (offsets.inode_i_ctime_sec_off, 128),
            (offsets.inode_i_ctime_nsec_off, 136),
            (offsets.inode_i_ctime_nsec_width, 8),
            // §4.1 ABI 2: UNTRUSTED exec-mode facts of the golden layout.
            (offsets.bprm_filename_off, 8),
            (offsets.inode_i_uid_off, 8),
            (offsets.file_f_path_dentry_off, 104),
            (offsets.dentry_d_parent_off, 16),
            (offsets.dentry_d_inode_off, 24),
            (offsets.dentry_size, 256),
            (offsets.bprm_nargs, 1),
            (offsets.mmap_nargs, 4),
            (offsets.mmap_file_arg_idx, 0),
            (offsets.mmap_prot_arg_idx, 2),
            (offsets.mmap_flags_arg_idx, 3),
            (offsets.bprm_retval_slot, 1),
            (offsets.mmap_retval_slot, 4),
            (offsets.inode_size, inode_size),
            (offsets.file_size, 256),
            (offsets.bprm_size, 128),
        ];
        for (actual, expected) in resolved {
            assert_eq!(actual, expected, "{label}");
        }
        assert!(titan_exec_offsets_match_ebpf_slots(&offsets), "{label}");
        let table = encode_titan_exec_offsets_table(&offsets);
        assert_eq!(table.len(), btf_offsets::TITAN_EXEC_OFFSETS_TABLE_LEN);
        assert_eq!(table[btf_offsets::OFF_MAGIC], gedefense_common::TITAN_EXEC_OFFSETS_MAGIC);
        assert_eq!(table[btf_offsets::OFF_ABI], gedefense_common::TITAN_EXEC_OFFSETS_ABI);
        assert_eq!(table[btf_offsets::OFF_BPRM_FILE], 64);
        assert_eq!(table[btf_offsets::OFF_FILE_F_INODE], 32);
        assert_eq!(table[btf_offsets::OFF_TMPFS_MAGIC], btf_offsets::TMPFS_MAGIC);
        assert_eq!(table[btf_offsets::OFF_DEVTMPFS_MAGIC], btf_offsets::DEVTMPFS_MAGIC);
        assert_eq!(table[btf_offsets::OFF_PROC_MAGIC], btf_offsets::PROC_SUPER_MAGIC);
        assert_eq!(table[btf_offsets::OFF_SYSFS_MAGIC], btf_offsets::SYSFS_MAGIC);
        assert_eq!(table[btf_offsets::OFF_OVERLAY_MAGIC], btf_offsets::OVERLAYFS_SUPER_MAGIC);
        assert_eq!(table[btf_offsets::OFF_BPRM_NARGS], 1);
        assert_eq!(table[btf_offsets::OFF_MMAP_NARGS], 4);
        assert_eq!(table[btf_offsets::OFF_MMAP_PROT_ARG], 2);
        assert_eq!(table[btf_offsets::OFF_INODE_I_CTIME_SEC], 128);
        assert_eq!(table[btf_offsets::OFF_INODE_I_CTIME_NSEC], 136);
        assert_eq!(table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH], 8);
        assert_eq!(table[btf_offsets::OFF_BPRM_FILENAME], 8);
        assert_eq!(table[btf_offsets::OFF_INODE_I_UID], 8);
        assert_eq!(table[btf_offsets::OFF_FILE_F_PATH_DENTRY], 104);
        assert_eq!(table[btf_offsets::OFF_DENTRY_D_PARENT], 16);
        assert_eq!(table[btf_offsets::OFF_DENTRY_D_INODE], 24);
        assert_eq!(table[btf_offsets::OFF_DENTRY_SIZE], 256);
        assert!(
            table[btf_offsets::OFF_RESERVED_FIRST..]
                .iter()
                .all(|value| *value == 0),
            "{label}"
        );
    }
}

#[test]
fn titan_btf_split_ctime_layout_publishes_the_nsec_width() {
    // §4.1 ctime-Layout-Vertrag: modern kernels have i_ctime_sec (8 B) +
    // i_ctime_nsec (4 B) instead of a timespec64; both must resolve and the
    // width index 28 must follow the real field width.
    let legacy = resolve_titan_btf(titan_btf_fixture(&TitanBtfSpec::default()))
        .expect("legacy timespec64 layout");
    assert_eq!(
        (
            legacy.inode_i_ctime_sec_off,
            legacy.inode_i_ctime_nsec_off,
            legacy.inode_i_ctime_nsec_width
        ),
        (128, 136, 8)
    );
    let split = resolve_titan_btf(titan_btf_fixture(&TitanBtfSpec {
        ctime_split: true,
        ..Default::default()
    }))
    .expect("split modern layout");
    assert_eq!(
        (
            split.inode_i_ctime_sec_off,
            split.inode_i_ctime_nsec_off,
            split.inode_i_ctime_nsec_width
        ),
        (104, 120, 4)
    );
    assert!(titan_exec_offsets_match_ebpf_slots(&split));
    let table = encode_titan_exec_offsets_table(&split);
    assert_eq!(table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH], 4);
    // A split layout whose nsec field is 8 B is declared/reported as width 8
    // (eBPF reads u64 for 8, u32 for 4).
    let wide = resolve_titan_btf(titan_btf_fixture(&TitanBtfSpec {
        ctime_split: true,
        split_nsec_width: 8,
        ..Default::default()
    }))
    .expect("wide split layout");
    assert_eq!(wide.inode_i_ctime_nsec_width, 8);
    // Implausible width and a fully missing ctime pair are Err (fail-safe).
    for spec in [
        TitanBtfSpec {
            ctime_split: true,
            split_nsec_width: 2,
            ..Default::default()
        },
        TitanBtfSpec {
            drop_ctime: true,
            ..Default::default()
        },
    ] {
        assert!(resolve_titan_btf(titan_btf_fixture(&spec)).is_err(), "{spec:?}");
    }
}

#[test]
fn titan_btf_live_vmlinux_resolves_all_offsets() {
    // §4.1 Real-BTF-Gate: with a live /sys/kernel/btf/vmlinux every offset
    // (including the ctime variant) must resolve and validate. Without the
    // file this is a documented SKIP, never a silent pass.
    if !Path::new(btf_offsets::VMLINUX_BTF_PATH).is_file() {
        eprintln!(
            "SKIP titan_btf_live_vmlinux_resolves_all_offsets: {} is absent on this host",
            btf_offsets::VMLINUX_BTF_PATH
        );
        return;
    }
    let offsets = btf_offsets::resolve_vmlinux_offsets()
        .expect("live vmlinux BTF must resolve the §4.1 offsets");
    eprintln!("live BTF §4.1 offsets: {offsets:?}");
    assert!(titan_exec_offsets_match_ebpf_slots(&offsets));
    assert!(matches!(offsets.inode_i_ctime_nsec_width, 4 | 8));
    assert!(offsets.inode_i_ctime_nsec_off > offsets.inode_i_ctime_sec_off);
    assert!(offsets.inode_i_ctime_sec_off + 8 <= offsets.inode_size);
    assert!(
        offsets.inode_i_ctime_nsec_off + offsets.inode_i_ctime_nsec_width
            <= offsets.inode_size
    );
    // §4.1 ABI 2 (UNTRUSTED): every new field must fit its real struct.
    assert!(offsets.inode_i_uid_off + 4 <= offsets.inode_size);
    assert!(offsets.bprm_filename_off + 8 <= offsets.bprm_size);
    assert!(offsets.file_f_path_dentry_off + 8 <= offsets.file_size);
    assert!(offsets.dentry_d_parent_off + 8 <= offsets.dentry_size);
    assert!(offsets.dentry_d_inode_off + 8 <= offsets.dentry_size);
    assert!(offsets.dentry_size > 0);
    let table = encode_titan_exec_offsets_table(&offsets);
    assert_eq!(
        table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH],
        offsets.inode_i_ctime_nsec_width
    );
    assert_eq!(
        table[btf_offsets::OFF_MAGIC],
        gedefense_common::TITAN_EXEC_OFFSETS_MAGIC
    );
}

#[test]
fn titan_btf_rejects_broken_headers_truncation_and_implausible_layouts() {
    let good = titan_btf_fixture(&TitanBtfSpec::default());
    let mut wrong_magic = good.clone();
    wrong_magic[0] ^= 0xff;
    let mut wrong_version = good.clone();
    wrong_version[2] = 2;
    let mut wrong_hdr_len = good.clone();
    wrong_hdr_len[4] = 23;
    let mut oversized_hdr_len = good.clone();
    oversized_hdr_len[4..8].copy_from_slice(&(good.len() as u32 + 1).to_le_bytes());
    let broken_bodies: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("short header", good[..12].to_vec()),
        ("wrong magic", wrong_magic),
        ("wrong version", wrong_version),
        ("wrong hdr_len", wrong_hdr_len),
        ("hdr_len beyond image", oversized_hdr_len),
        ("truncated string table", good[..good.len() - 4].to_vec()),
    ];
    for (label, data) in broken_bodies {
        assert!(resolve_titan_btf(data).is_err(), "{label}");
    }
    let broken_layouts = [
        ("offset beyond inode", TitanBtfSpec { inode_size: 100, ..Default::default() }),
        ("missing i_ino", TitanBtfSpec { drop_ino: true, ..Default::default() }),
        ("missing super_block", TitanBtfSpec { drop_super: true, ..Default::default() }),
        ("ambiguous inode", TitanBtfSpec { duplicate_inode: true, ..Default::default() }),
        ("bprm arity 2", TitanBtfSpec { bprm_nargs: 2, ..Default::default() }),
        ("mmap arity 2", TitanBtfSpec { mmap_nargs: 2, ..Default::default() }),
        ("mmap arity 6", TitanBtfSpec { mmap_nargs: 6, ..Default::default() }),
    ];
    for (label, spec) in broken_layouts {
        assert!(
            resolve_titan_btf(titan_btf_fixture(&spec)).is_err(),
            "{label}"
        );
    }
    // §4.1 accepts mmap arities 3..=5 for index computation, but the eBPF
    // slots are fixed: only arity 4 may ever be attached.
    for arity in [3u16, 5] {
        let spec = TitanBtfSpec {
            mmap_nargs: arity,
            ..Default::default()
        };
        let offsets = resolve_titan_btf(titan_btf_fixture(&spec))
            .expect("arity is plausible");
        assert!(!titan_exec_offsets_match_ebpf_slots(&offsets), "arity {arity}");
    }
}

#[test]
fn titan_btf_accepts_extended_v1_header() {
    let baseline_data = titan_btf_fixture(&TitanBtfSpec::default());
    let baseline = resolve_titan_btf(baseline_data.clone()).expect("baseline BTF");
    // Kernel 7.3 grows the BTF v1 header to 32 bytes; the section offsets
    // stay relative to hdr_len, so an 8-byte extension must parse exactly
    // like the 24-byte header (and must not be mistaken for section data).
    let mut extended = baseline_data;
    extended.splice(24..24, [0u8; 8]);
    extended[4..8].copy_from_slice(&32u32.to_le_bytes());
    let offsets = resolve_titan_btf(extended).expect("32-byte BTF header");
    assert_eq!(offsets.file_f_inode_off, baseline.file_f_inode_off);
    assert_eq!(offsets.inode_i_ino_off, baseline.inode_i_ino_off);
    assert_eq!(offsets.inode_i_mode_off, baseline.inode_i_mode_off);
    assert_eq!(offsets.bprm_nargs, baseline.bprm_nargs);
    assert_eq!(offsets.mmap_nargs, baseline.mmap_nargs);
}

#[test]
fn titan_btf_from_path_is_bounded_and_strict() {
    let directory = test_titan_directory("btf");
    let path = directory.join("vmlinux.btf");
    fs::write(&path, titan_btf_fixture(&TitanBtfSpec::default())).expect("write fixture");
    let text = path.to_string_lossy().into_owned();
    let offsets = btf_offsets::VmlinuxBtf::from_path(&text)
        .expect("parse fixture file")
        .resolve_titan_exec()
        .expect("resolve fixture file");
    assert_eq!(offsets.inode_i_nlink_off, 72);
    assert!(btf_offsets::VmlinuxBtf::from_path(&directory.join("absent").to_string_lossy())
        .is_err());
    let oversized = directory.join("oversized.btf");
    fs::write(&oversized, vec![0u8; btf_offsets::MAX_VMLINUX_BTF_BYTES + 1])
        .expect("write oversized fixture");
    assert!(btf_offsets::VmlinuxBtf::from_path(&oversized.to_string_lossy()).is_err());
    fs::remove_dir_all(directory).expect("cleanup");
}

// ---- Point 1: pure Titan exec-gate helpers (§5/§6). ----

#[test]
fn titan_exec_lsm_activation_probe_is_strict() {
    assert!(!titan_exec::bpf_lsm_active_from_list(""));
    assert!(!titan_exec::bpf_lsm_active_from_list(
        "lockdown,capability,landlock,yama,apparmor,ima,evm"
    ));
    assert!(titan_exec::bpf_lsm_active_from_list("lockdown,bpf,capability,landlock"));
    assert!(titan_exec::bpf_lsm_active_from_list("bpf"));
    assert!(titan_exec::bpf_lsm_active_from_list(" bpf "));
    assert!(titan_exec::bpf_lsm_active_from_list("lockdown,bpf\n"));
    assert!(titan_exec::bpf_lsm_active_from_list("bpf,bpf,capability"));
    assert!(!titan_exec::bpf_lsm_active_from_list("bpflsm,bpf_lsm,BPF"));
    assert!(!titan_exec::bpf_lsm_active_from_list("lockdown,capability,"));
}

#[test]
fn titan_exec_arguments_are_strict() {
    assert_eq!(titan_exec::parse_mode("0").unwrap(), 0);
    assert_eq!(titan_exec::parse_mode("3").unwrap(), 3);
    // §4.2 ABI 2: UNTRUSTED (4) is a valid global mode ...
    assert_eq!(titan_exec::parse_mode("4").unwrap(), 4);
    for token in ["5", "-1", "+1", " 1", "1 ", "", "0x1", "1.0"] {
        assert!(titan_exec::parse_mode(token).is_err(), "{token:?}");
    }
    // ... but it is not representable in a per-cgroup scope value.
    assert_eq!(titan_exec::parse_scope_mode("3").unwrap(), 3);
    assert!(titan_exec::parse_scope_mode("4").is_err());
    assert_eq!(titan_exec::mode_name(4), "untrusted");
    assert_eq!(titan_exec::mode_name(3), "strict");
    assert_eq!(titan_exec::parse_global_flags("0").unwrap(), 0);
    assert_eq!(titan_exec::parse_global_flags("1").unwrap(), 1);
    for token in ["2", "255"] {
        assert!(titan_exec::parse_global_flags(token).is_err(), "{token:?}");
    }
    assert_eq!(titan_exec::parse_scope_flags("1").unwrap(), 1);
    assert!(titan_exec::parse_scope_flags("2").is_err());
    assert_eq!(titan_exec::parse_scope_cgroup("42").unwrap(), 42);
    assert!(titan_exec::parse_scope_cgroup("0").is_err());
    assert_eq!(titan_exec::parse_policy_dev("2049").unwrap(), 2049);
    assert!(titan_exec::parse_policy_dev("0").is_err());
    assert!(titan_exec::parse_policy_dev("4294967296").is_err());
    assert_eq!(titan_exec::parse_policy_ino("12345").unwrap(), 12_345);
    assert!(titan_exec::parse_policy_ino("0").is_err());
    assert_eq!(titan_exec::parse_u8("255").unwrap(), 255);
    assert!(titan_exec::parse_u8("256").is_err());
}

#[test]
fn titan_exec_policy_store_is_bounded_and_idempotent() {
    let mut store = titan_exec::TitanExecPolicy::new();
    let entry = titan_exec::PolicyEntry {
        action: titan_exec::TITAN_EXEC_ALLOW_ACTION,
        flags: 1,
        ctime_ns: 7,
    };
    assert!(store.insert(1, 2, entry).unwrap());
    assert!(!store.insert(1, 2, entry).unwrap());
    assert_eq!(store.entry(1, 2), Some(entry));
    assert_eq!(store.entry_count(), 1);
    assert_eq!(store.keys(), vec![(1, 2)]);
    assert!(store.insert(0, 2, entry).is_err());
    assert!(store.insert(1, 0, entry).is_err());
    assert!(store.insert(2, 3, titan_exec::PolicyEntry { action: 2, ..entry }).is_err());
    assert!(store.remove(1, 2));
    assert!(!store.remove(1, 2));
    assert_eq!(store.entry_count(), 0);
    for index in 0..titan_exec::TITAN_EXEC_MAX_POLICY_ENTRIES {
        store.insert(index as u32 + 1, 1, entry).unwrap();
    }
    assert!(store.insert(u32::MAX, u64::MAX, entry).is_err());
    store.clear();
    assert_eq!(store.entry_count(), 0);
    let scope_value = encode_titan_exec_scope_value(2, 1).unwrap();
    assert!(store.scope_set(7, scope_value).is_ok());
    assert_eq!(store.scope_remove(7), true);
    assert_eq!(store.scope_remove(7), false);
    assert!(store.scope_set(0, 0).is_err());
    for cgroup in 1..=titan_exec::TITAN_EXEC_MAX_SCOPES as u64 {
        store.scope_set(cgroup, 0).unwrap();
    }
    assert!(store.scope_set(u64::MAX, 0).is_err());
    assert!(store.scope_set(1, 3).is_ok());
    assert_eq!(store.scope_count(), titan_exec::TITAN_EXEC_MAX_SCOPES);
}

#[test]
fn titan_exec_path_validation_rejects_non_canonical_paths() {
    assert!(titan_exec::validate_exec_path("/usr/bin/true").is_ok());
    for path in [
        "", "relative/path", "/usr/../bin/true", "/usr/./bin/true", "/usr//bin/true",
        "/usr/bin/true/", "/", ".", "//etc/passwd", "/usr/\0x", "/usr/bin/tr\nue",
        "/usr/bin/tr\tue",
    ] {
        assert!(titan_exec::validate_exec_path(path).is_err(), "{path:?}");
    }
    let too_long = format!("/{}", "a".repeat(titan_exec::TITAN_EXEC_MAX_PATH_BYTES));
    assert!(titan_exec::validate_exec_path(&too_long).is_err());
}

#[test]
fn titan_exec_path_resolver_is_fd_safe() {
    let directory = test_titan_directory("paths");
    let executable = directory.join("tool");
    fs::write(&executable, b"#!/bin/sh\n").expect("write executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("mode");
    let path = executable.to_string_lossy().into_owned();
    let identity = titan_exec::resolve_exec_path(&path).expect("resolve executable");
    let metadata = fs::metadata(&executable).expect("stat executable");
    assert_eq!(u64::from(identity.dev), metadata.dev() & u64::from(u32::MAX));
    assert_eq!(identity.ino, metadata.ino());
    assert_ne!(identity.mode & 0o111, 0);
    let expected_ctime = u64::try_from(metadata.ctime()).expect("ctime")
        * 1_000_000_000
        + u64::try_from(metadata.ctime_nsec()).expect("ctime_nsec");
    assert_eq!(identity.ctime_ns, expected_ctime);

    // A hard link is the same inode identity; a symlink is refused without
    // being followed (O_PATH|O_NOFOLLOW + fstat on the fd).
    let hardlink = directory.join("hardlink");
    fs::hard_link(&executable, &hardlink).expect("hard link");
    let linked = titan_exec::resolve_exec_path(&hardlink.to_string_lossy()).expect("hardlink");
    assert_eq!((linked.dev, linked.ino), (identity.dev, identity.ino));
    let symlink = directory.join("symlink");
    std::os::unix::fs::symlink(&executable, &symlink).expect("symlink");
    assert_eq!(
        titan_exec::resolve_exec_path(&symlink.to_string_lossy()).unwrap_err(),
        titan_exec::PathReject::Symlink
    );

    let plain = directory.join("plain");
    fs::write(&plain, b"data").expect("write plain");
    assert_eq!(
        titan_exec::resolve_exec_path(&plain.to_string_lossy()).unwrap_err(),
        titan_exec::PathReject::NotExecutable
    );
    assert_eq!(
        titan_exec::resolve_exec_path(&directory.to_string_lossy()).unwrap_err(),
        titan_exec::PathReject::NotRegular
    );
    assert_eq!(
        titan_exec::resolve_exec_path(&directory.join("absent").to_string_lossy()).unwrap_err(),
        titan_exec::PathReject::Open
    );

    // The policy fingerprint is the fstat ctime: a rewrite changes it, which
    // is what REQUIRE_CTIME detects in the kernel (TOCTOU mitigation).
    std::thread::sleep(Duration::from_millis(20));
    fs::write(&executable, b"#!/bin/sh\necho\n").expect("rewrite executable");
    let rewritten = titan_exec::resolve_exec_path(&path).expect("resolve rewritten");
    assert_ne!(rewritten.ctime_ns, identity.ctime_ns);
    fs::remove_dir_all(directory).expect("cleanup");
}

#[test]
fn titan_exec_batch_decode_is_bounded_and_accepts_both_alphabets() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let text = "/usr/bin/true\n/usr/bin/false\n";
    assert_eq!(titan_exec::decode_allow_batch(&URL_SAFE_NO_PAD.encode(text)).unwrap().len(), 2);
    assert_eq!(titan_exec::decode_allow_batch(&STANDARD.encode(text)).unwrap().len(), 2);
    assert!(titan_exec::decode_allow_batch(&URL_SAFE_NO_PAD.encode("/usr/bin/true")).is_ok());
    assert!(titan_exec::decode_allow_batch(&URL_SAFE_NO_PAD.encode("/usr/bin/true\n\n")).is_err());
    assert!(titan_exec::decode_allow_batch("not base64 !!!").is_err());
    assert!(titan_exec::decode_allow_batch("").is_err());
    assert!(titan_exec::decode_allow_batch(&URL_SAFE_NO_PAD.encode("relative")).is_err());
    assert!(titan_exec::decode_allow_batch(
        &URL_SAFE_NO_PAD.encode("/usr/bin/true\n\n/usr/bin/false")
    )
    .is_err());
    let too_large = (0..60)
        .map(|index| format!("/usr/bin/tool-with-a-long-name-{index:03}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(titan_exec::decode_allow_batch(&URL_SAFE_NO_PAD.encode(&too_large)).is_err());
    let too_many = vec!["/a"; titan_exec::TITAN_EXEC_MAX_BATCH_PATHS + 1].join("\n");
    assert!(titan_exec::decode_allow_batch(&URL_SAFE_NO_PAD.encode(&too_many)).is_err());
    assert_eq!(
        titan_exec::encode_allow_batch_response(3, 0, titan_exec::BATCH_ERROR_NONE),
        "added:3;rejected:0;error=none"
    );
    assert_eq!(
        titan_exec::encode_allow_batch_response(1, 2, "symlink"),
        "added:1;rejected:2;error=symlink"
    );
    assert_eq!(titan_exec::PathReject::Symlink.token(), "symlink");
    assert_eq!(titan_exec::PathReject::NotExecutable.token(), "not-executable");
}

fn titan_fixture_event() -> gedefense_common::TitanExecEvent {
    gedefense_common::TitanExecEvent {
        cgroup_id: 0x0102_0304_0506_0708,
        ts_ns: 9,
        dev: 0x0801,
        inode_mode: 0o100_755,
        ino: 0x1122_3344_5566_7788,
        generation: 7,
        pid: 42,
        tgid: 41,
        uid: 1000,
        gid: 1001,
        prot: 4,
        f_flags: 0x8000,
        hook: gedefense_common::TITAN_EXEC_HOOK_BPRM,
        action: gedefense_common::TITAN_EXEC_ACTION_AUDIT,
        reason: gedefense_common::TITAN_EXEC_REASON_NOT_ALLOWLISTED,
        flags: 3,
        comm: *b"untrusted-bin\0\0\0",
        reserved: [0; 8],
    }
}

#[test]
fn titan_exec_event_text_wire_matches_section_three_three() {
    let text = titan_exec::encode_exec_event_text(&titan_fixture_event());
    assert_eq!(
        text,
        "72623859790382856:9:2049:33261:1234605616436508552:7:42:41:1000:1001:4:32768:1:1:4:756e747275737465642d62696e"
    );
    assert_eq!(text.split(':').count(), 16);
    assert_eq!(titan_exec::encode_exec_events_batch(&[], 0).unwrap(), "empty");
    assert_eq!(titan_exec::encode_exec_events_batch(&[], 7).unwrap(), "7|");
    assert_eq!(
        titan_exec::encode_exec_events_batch(&["a".to_owned(), "b".to_owned()], 3).unwrap(),
        "3|a,b"
    );
    let records = vec![text; titan_exec::TITAN_EXEC_MAX_EVENTS_PER_RESPONSE];
    let batch = titan_exec::encode_exec_events_batch(&records, u64::MAX).unwrap();
    assert_eq!(
        batch.split(',').count(),
        titan_exec::TITAN_EXEC_MAX_EVENTS_PER_RESPONSE
    );
    assert!(batch.len() <= titan_exec::TITAN_EXEC_MAX_PAYLOAD_BYTES);
    let too_many = vec!["a".to_owned(); titan_exec::TITAN_EXEC_MAX_EVENTS_PER_RESPONSE + 1];
    assert!(titan_exec::encode_exec_events_batch(&too_many, 0).is_err());
}

#[test]
fn titan_exec_health_and_status_follow_the_contract() {
    assert_eq!(
        titan_exec::encode_exec_health(&[1, 2, 3, 4, 5, 6]),
        "1:2:3:4:5:6"
    );
    let maximal = titan_exec::encode_exec_health(&[u64::MAX; 6]);
    assert_eq!(maximal.split(':').count(), 6);
    let status = titan_exec::encode_exec_status(&titan_exec::StatusView {
        state: titan_exec::ExecState::Inactive,
        mode: 0,
        flags: 0,
        path_bpf_lsm: false,
        lsm_active: false,
        offsets_valid: false,
        entries: 0,
        scopes: 0,
        epoch: "0011223344556677",
    });
    assert_eq!(
        status,
        "status=inactive;mode=0;flags=0;path=none;lsm=inactive;offsets=invalid;entries=0;scopes=0;epoch=0011223344556677"
    );
    assert_eq!(
        titan_exec::exec_state(true, true, true).text(),
        "applied"
    );
    assert_eq!(
        titan_exec::exec_state(false, true, true).text(),
        "unavailable"
    );
    assert_eq!(
        titan_exec::exec_state(false, true, false).text(),
        "unavailable"
    );
    assert_eq!(titan_exec::exec_state(false, false, true).text(), "inactive");
    assert_eq!(titan_exec::exec_state(false, false, false).text(), "inactive");
    for (mode, name) in [(0u8, "off"), (1, "observe"), (2, "contain"), (3, "strict")] {
        assert_eq!(titan_exec::ping_titan_exec_token(false, mode), "inactive");
        assert_eq!(titan_exec::ping_titan_exec_token(true, mode), name);
    }
}

#[test]
fn titan_exec_map_encoders_match_abi_one() {
    let key = encode_titan_exec_policy_key(0x0801_0002, 0x1122_3344_5566_7788);
    assert_eq!(&key[0..4], &0x0801_0002u32.to_le_bytes());
    assert_eq!(&key[4..12], &0x1122_3344_5566_7788u64.to_le_bytes());
    assert_eq!(&key[12..16], &[0u8; 4]);
    let entry = titan_exec::PolicyEntry {
        action: titan_exec::TITAN_EXEC_ALLOW_ACTION,
        flags: titan_exec::TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME,
        ctime_ns: 0x0102_0304_0506_0708,
    };
    let value = encode_titan_exec_policy_value(&entry);
    assert_eq!(value[0], 1);
    assert_eq!(value[1], 1);
    assert_eq!(&value[2..4], &[0u8; 2]);
    assert_eq!(&value[4..12], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(&value[12..16], &[0u8; 4]);
    assert_eq!(encode_titan_exec_scope_value(2, 1).unwrap(), 0b1001);
    assert_eq!(encode_titan_exec_scope_value(0, 0).unwrap(), 0);
    assert!(encode_titan_exec_scope_value(4, 0).is_err());
    assert!(encode_titan_exec_scope_value(0, 2).is_err());
    let word = encode_titan_exec_state(0xdead_beef, 2, 0b101);
    assert_eq!(word & 0xffff_ffff, 0xdead_beef);
    assert_eq!(((word >> 32) & 0xff) as u8, 2);
    assert_eq!(((word >> 40) & 0xff) as u8, 0b101);
    assert_eq!(
        ((word >> 48) & 0xff) as u8,
        gedefense_common::TITAN_EXEC_STATE_ABI
    );
    assert_eq!(
        ((word >> 56) & 0xff) as u8,
        gedefense_common::TITAN_EXEC_STATE_MAGIC
    );
    assert_eq!(encode_titan_exec_state_flags(false, false, false), 0);
    assert_eq!(
        encode_titan_exec_state_flags(true, true, true),
        titan_exec::TITAN_EXEC_STATE_FLAG_OFFSETS_VALID
            | titan_exec::TITAN_EXEC_STATE_FLAG_LSM_ACTIVE
            | titan_exec::TITAN_EXEC_STATE_FLAG_CTIME_CHECK
    );
    assert_eq!(
        encode_titan_exec_state_flags(true, false, false),
        titan_exec::TITAN_EXEC_STATE_FLAG_OFFSETS_VALID
    );
}

// ---------------------------------------------------------------------
// Point 5 (§5/§6/§10): lockdown ABI, state machine and monitor tests.
// All of these run without root: the eBPF word is an in-memory fake and
// sysfs/proc/sysctl trees are temp-dir fakes.
// ---------------------------------------------------------------------

/// Fake `LOCKDOWN_STATE` array map; `ignore_writes` simulates a write that
/// the kernel does not persist, so a read-back mismatch must be visible.
pub(crate) struct MemoryWordStore {
    word: std::sync::Mutex<u64>,
    ignore_write: std::sync::atomic::AtomicBool,
    writes: std::sync::atomic::AtomicU64,
}

impl MemoryWordStore {
    pub(crate) fn new() -> Self {
        Self {
            word: std::sync::Mutex::new(0),
            ignore_write: std::sync::atomic::AtomicBool::new(false),
            writes: std::sync::atomic::AtomicU64::new(0),
        }
    }
    pub(crate) fn word(&self) -> u64 {
        *self.word.lock().expect("fake word")
    }
    pub(crate) fn ignore_writes(&self) {
        self.ignore_write.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub(crate) fn writes(&self) -> u64 {
        self.writes.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl lockdown::LockdownWordStore for MemoryWordStore {
    fn write(&self, word: u64) -> Result<(), String> {
        self.writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.ignore_write.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        *self.word.lock().map_err(|_| "fake word".to_owned())? = word;
        Ok(())
    }
    fn read(&self) -> Result<u64, String> {
        Ok(*self.word.lock().map_err(|_| "fake word".to_owned())?)
    }
}

struct FakeNetCounters {
    drops: u64,
    witness: u64,
}

impl lockdown::NetCounters for FakeNetCounters {
    fn net_counters(&self) -> Result<(u64, u64), String> {
        Ok((self.drops, self.witness))
    }
}

fn lockdown_fixture(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir().join(format!(
        "vgt-lockdown-{label}-{}-{nanos}",
        std::process::id()
    ));
    for directory in [
        "sys/bus/usb/devices",
        "sys/bus/thunderbolt/devices",
        "sys/kernel/security",
        "proc/sys/kernel",
        "state",
    ] {
        fs::create_dir_all(root.join(directory)).expect("lockdown fixture dir");
    }
    fs::write(root.join("sys/bus/usb/drivers_autoprobe"), "1\n").expect("autoprobe");
    for (name, value) in [
        ("kexec_load_disabled", "0"),
        ("sysrq", "1"),
        ("modules_disabled", "0"),
        ("unprivileged_bpf_disabled", "2"),
    ] {
        fs::write(root.join("proc/sys/kernel").join(name), format!("{value}\n"))
            .expect("sysctl fixture");
    }
    fs::write(root.join("sys/kernel/security/lockdown"), "none [integrity] confidentiality\n")
        .expect("kernel lockdown fixture");
    root
}

fn lockdown_state_path(root: &Path) -> std::path::PathBuf {
    root.join("state/LOCKDOWN.state")
}

fn lockdown_core_with(
    root: &Path,
    word: std::sync::Arc<MemoryWordStore>,
    nets: (u64, u64),
) -> lockdown::LockdownCore {
    let config = lockdown::LockdownConfig {
        state_file: lockdown_state_path(root),
        usb: crate::lockdown_usb::UsbPaths::new(root.join("sys")),
        hardening: crate::lockdown_hardening::HardeningPaths::for_root(root),
        proc_root: root.join("proc"),
        monitors: false,
    };
    lockdown::LockdownCore::new(
        config,
        word,
        std::sync::Arc::new(FakeNetCounters { drops: nets.0, witness: nets.1 }),
    )
    .expect("lockdown core")
}

fn lockdown_core(root: &Path, word: std::sync::Arc<MemoryWordStore>) -> lockdown::LockdownCore {
    lockdown_core_with(root, word, (0, 0))
}

fn lockdown_word(store: &MemoryWordStore) -> gedefense_common::LockdownWord {
    gedefense_common::decode_lockdown_word(store.word()).expect("decoded lockdown word")
}

fn lockdown_command_raw(core: &mut lockdown::LockdownCore, parts: &[&str]) -> Result<String, BoxError> {
    lockdown_command(core, parts)
}

#[test]
fn lockdown_dispatch_arm_trigger_clear_matches_the_section_five_abi() {
    let root = lockdown_fixture("dispatch");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    let epoch = format!("{:08x}", core.epoch());
    assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_VERSION"]).unwrap(), "lockdown-v1");
    assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_EPOCH"]).unwrap(), epoch);
    let status = lockdown_command_raw(&mut core, &["LOCKDOWN_STATUS"]).unwrap();
    assert!(
        status.starts_with("state=off;epoch=") && status.ends_with(";mode=unlocked;flags=0;phases=-;unsupported=sessions,dm"),
        "{status}"
    );
    assert_eq!(core.ping_suffix(), "+lockdown:off");

    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap(),
        format!("armed:{epoch}")
    );
    assert_eq!(core.ping_suffix(), "+lockdown:armed");
    assert_eq!(lockdown_word(&store).mode, gedefense_common::LOCKDOWN_MODE_ARMED);
    assert_eq!(lockdown_word(&store).flags, 0, "arm alone must not drop");
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap(),
        format!("armed-unchanged:{epoch}")
    );
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_SET_MODE", "unlocked"]).unwrap(),
        "applied"
    );

    // TRIGGER creates a new epoch and reports applied/unsupported phases;
    // flags=5 = auto_network_drop + freeze_brokers (loopback NOT kept).
    let triggered = lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "uevent", "usb-unknown", "5"]).unwrap();
    let armed_epoch = format!("{:08x}", core.epoch());
    assert_ne!(armed_epoch, epoch, "every trigger gets a new epoch");
    assert_eq!(
        triggered,
        format!("triggered:{armed_epoch};phases=net,usb,tb,brokers,cells=delegated;unsupported=sessions,dm")
    );
    assert_eq!(core.ping_suffix(), "+lockdown:active");
    let word = lockdown_word(&store);
    assert_eq!(word.epoch, core.epoch());
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
    assert_eq!(word.flags & gedefense_common::LOCKDOWN_FLAG_ALLOW_LOOPBACK, 0);
    let status = lockdown_command_raw(&mut core, &["LOCKDOWN_STATUS"]).unwrap();
    assert!(status.starts_with("state=active;"), "{status}");
    assert!(status.contains(";mode=unlocked;flags=49;"), "{status}");
    assert!(status.contains(";phases=net,usb,tb,brokers,cells=delegated;"), "{status}");

    // ARM during an active latch never lowers it.
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap(),
        format!("armed-unchanged:{armed_epoch}")
    );
    assert_eq!(core.state_text(), "active");

    // Wrong expected epoch is a compare-set rejection, not a partial clear.
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", "deadbeef", "manual"]).is_err());
    assert_eq!(core.state_text(), "active");
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", &armed_epoch, "manual"]).unwrap(),
        "cleared"
    );
    assert_eq!(core.ping_suffix(), "+lockdown:off");
    assert_eq!(lockdown_word(&store).mode, gedefense_common::LOCKDOWN_MODE_OFF);
    assert!(!lockdown_state_path(&root).exists(), "clear removes the latch file");
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", &armed_epoch, "manual"]).unwrap(),
        "already-off"
    );
}

#[test]
fn lockdown_token_and_size_boundaries_are_rejected() {
    let root = lockdown_fixture("tokens");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "bogus", "manual", "1"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "bogus", "1"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "16"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "x"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "nope", "manual", "1"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", "123", "manual"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", "zzzzzzzz", "manual"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "bogus", "on"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "net", "toggle"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_BOGUS"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM"]).is_err());
    // Every §5 answer stays well below the 2048-byte IPC response budget.
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "tamper", "15"]).unwrap();
    lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "manual", "tamper", "15"]).unwrap();
    for parts in [
        vec!["LOCKDOWN_STATUS"],
        vec!["LOCKDOWN_EVENTS"],
        vec!["LOCKDOWN_HEALTH"],
        vec!["LOCKDOWN_EPOCH"],
    ] {
        let answer = lockdown_command_raw(&mut core, &parts).unwrap();
        assert!(answer.len() <= MAX_RESPONSE_BYTES, "{parts:?} answer too long");
    }
}

#[test]
fn lockdown_word_read_back_failures_are_never_claimed() {
    let root = lockdown_fixture("readback");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    store.ignore_writes();
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    // ARM cannot claim armed without a successful verified write.
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "1"]).is_err());
    assert_eq!(core.state_text(), "off");
    // A trigger still runs the other phases, but NET is not in the applied
    // CSV and the state is degraded: no "network down" claim without read-back.
    let triggered = lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "manual", "tamper", "1"]).unwrap();
    assert!(!triggered.contains("phases=net"), "{triggered}");
    assert_eq!(core.state_text(), "degraded");
    let status = lockdown_command_raw(&mut core, &["LOCKDOWN_STATUS"]).unwrap();
    assert!(status.contains(";phases=usb,tb,cells=delegated;"), "{status}");
    assert_eq!(store.word(), 0, "no write was persisted");
}

#[test]
fn lockdown_state_file_is_atomic_0640_and_rearms_verified() {
    let root = lockdown_fixture("rearm");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "9"]).unwrap();
    lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "policy", "boot-trust-drift", "9"]).unwrap();
    let epoch = format!("{:08x}", core.epoch());
    let path = lockdown_state_path(&root);
    let metadata = fs::metadata(&path).expect("state file");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
    let content = fs::read_to_string(&path).expect("state file content");
    let fields: Vec<&str> = content.trim_end().split('|').collect();
    assert_eq!(fields.len(), 5, "{content}");
    assert_eq!(fields[0], epoch);
    assert_eq!(fields[1], "locked");
    assert_eq!(fields[2], "09");
    assert_eq!(fields[3], "net,usb,tb,hardening", "flags=9 selects hardening");
    // Phase 1 hardening applied for real in the fake sysctl tree.
    assert_eq!(fs::read_to_string(root.join("proc/sys/kernel/kexec_load_disabled")).unwrap().trim(), "1");
    assert_eq!(fs::read_to_string(root.join("proc/sys/kernel/sysrq")).unwrap().trim(), "0");

    // Re-arm from the file applies drop/USB/TB/hardening again and verifies.
    let rearm_store = std::sync::Arc::new(MemoryWordStore::new());
    let mut rearmed = lockdown_core(&root, std::sync::Arc::clone(&rearm_store));
    assert_eq!(rearmed.startup_rearm().unwrap(), "active");
    let word = lockdown_word(&rearm_store);
    assert_eq!(word.epoch, core.epoch());
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_USB_LOCKED, 0);
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_HARDENING_APPLIED, 0);

    // Corrupt file: degraded + latched, but no unverified enforcement action.
    fs::write(&path, "garbage|not-a-state\n").expect("corrupt state");
    let corrupt_store = std::sync::Arc::new(MemoryWordStore::new());
    let mut corrupt = lockdown_core(&root, std::sync::Arc::clone(&corrupt_store));
    assert_eq!(corrupt.startup_rearm().unwrap(), "degraded");
    assert_eq!(corrupt.state_text(), "degraded");
    assert_eq!(corrupt_store.word(), 0, "corrupt state must not fake enforcement");
    assert_eq!(corrupt_store.writes(), 0);
    let epoch = format!("{:08x}", corrupt.epoch());
    assert_eq!(
        lockdown_command_raw(&mut corrupt, &["LOCKDOWN_CLEAR", &epoch, "manual"]).unwrap(),
        "cleared"
    );
    assert!(!path.exists());
}

#[test]
fn lockdown_phase_command_matrix_is_honest() {
    let root = lockdown_fixture("phases");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "net", "on"]).unwrap(),
        "failed:net:not-armed"
    );
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "8"]).unwrap();
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "cells", "on"]).unwrap(),
        "unsupported:cells:delegated-to-control"
    );
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "sessions", "on"]).unwrap(),
        "unsupported:sessions:no-dbus-session-lock"
    );
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "dm", "on"]).unwrap(),
        "unsupported:dm:no-device-mapper"
    );
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "kernel-lockdown", "on"]).unwrap(),
        "unsupported:kernel-lockdown:boot-parameter-immutable"
    );
    // Explicit single-phase command may set modules_disabled (auto never).
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "hardening", "on"]).unwrap(),
        "applied:hardening"
    );
    assert_eq!(fs::read_to_string(root.join("proc/sys/kernel/modules_disabled")).unwrap().trim(), "1");
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "hardening", "off"]).unwrap(),
        "unsupported:hardening:irreversible-until-reboot"
    );
    for phase in ["net", "usb", "tb", "brokers"] {
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", phase, "on"]).unwrap(),
            format!("applied:{phase}")
        );
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", phase, "off"]).unwrap(),
            format!("applied:{phase}")
        );
    }
    assert_eq!(core.ping_suffix(), "+lockdown:active");
}

#[test]
fn lockdown_auto_network_drop_survives_a_later_phase_refresh() {
    let root = lockdown_fixture("auto-drop-phase");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    // flags=3 = auto_network_drop + allow_loopback.
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap();
    core.shared.auto_network_drop().expect("auto drop write");
    assert!(core.shared.auto_drop(), "auto-drop ownership is recorded");
    let word = lockdown_word(&store);
    assert_eq!(word.epoch, core.epoch());
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_ALLOW_LOOPBACK, 0);
    // A later USB phase refresh must keep the drop and add its own bit.
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "usb", "on"]).unwrap(),
        "applied:usb"
    );
    let word = lockdown_word(&store);
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0, "phase refresh cleared the auto drop");
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_USB_LOCKED, 0, "USB phase bit was not persisted");
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_ALLOW_LOOPBACK, 0);
}

#[test]
fn lockdown_auto_network_drop_survives_a_startup_rearm() {
    let root = lockdown_fixture("auto-drop-rearm");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    // flags=3 = auto_network_drop + allow_loopback.
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap();
    core.shared.auto_network_drop().expect("auto drop write");
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "usb", "on"]).unwrap(),
        "applied:usb"
    );
    let before = lockdown_word(&store);
    assert_ne!(before.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);

    // A daemon restart re-arms from the persisted USB phase. The DROP_ALL
    // already verified in the kernel word must not be cleared silently.
    let mut restarted = lockdown_core(&root, std::sync::Arc::clone(&store));
    restarted.startup_rearm().expect("startup rearm");
    let after = lockdown_word(&store);
    assert_eq!(after.epoch, before.epoch);
    assert_ne!(
        after.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL,
        0,
        "startup re-arm cleared the auto-drop"
    );
    assert_ne!(after.flags & gedefense_common::LOCKDOWN_FLAG_USB_LOCKED, 0);
    assert!(restarted.shared.auto_drop(), "auto-drop ownership was not re-established");
}

#[test]
fn lockdown_auto_network_drop_is_released_by_an_explicit_net_phase_off() {        let root = lockdown_fixture("auto-drop-net-off");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "1"]).unwrap();
    core.shared.auto_network_drop().expect("auto drop write");
    assert_ne!(lockdown_word(&store).flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "net", "off"]).unwrap(),
        "applied:net"
    );
    assert!(!core.shared.auto_drop(), "explicit NET off clears the auto-drop flag");
    assert_eq!(lockdown_word(&store).flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
}

#[test]
fn lockdown_auto_network_drop_is_cleared_by_clear() {
    let root = lockdown_fixture("auto-drop-clear");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "1"]).unwrap();
    core.shared.auto_network_drop().expect("auto drop write");
    assert!(core.shared.auto_drop());
    let epoch = format!("{:08x}", core.epoch());
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", &epoch, "manual"]).unwrap(),
        "cleared"
    );
    assert!(!core.shared.auto_drop(), "CLEAR releases the auto-drop flag");
    let word = lockdown_word(&store);
    assert_eq!(word.mode, gedefense_common::LOCKDOWN_MODE_OFF);
    assert_eq!(word.flags, 0, "CLEAR writes the OFF word");
}

#[test]
fn lockdown_explicit_hardening_phase_covers_modules_disabled_only_on_request() {
    let root = lockdown_fixture("explicit-modules");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "8"]).unwrap();
    // Automatic trigger (hardening_apply flag) never writes modules_disabled.
    lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "manual", "tamper", "8"]).unwrap();
    let modules = root.join("proc/sys/kernel/modules_disabled");
    assert_eq!(fs::read_to_string(&modules).unwrap().trim(), "0");
    assert_eq!(fs::read_to_string(root.join("proc/sys/kernel/kexec_load_disabled")).unwrap().trim(), "1");
    // A failing modules_disabled write makes the explicit phase fail visibly.
    fs::write(&modules, "7\n").unwrap();
    let response = lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "hardening", "on"]).unwrap();
    assert!(response.starts_with("failed:hardening:"), "{response}");
    assert_eq!(core.state_text(), "degraded");
    // A writable knob is applied and verified by the explicit command.
    fs::write(&modules, "0\n").unwrap();
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "hardening", "on"]).unwrap(),
        "applied:hardening"
    );
    assert_eq!(fs::read_to_string(&modules).unwrap().trim(), "1");
}

#[test]
fn lockdown_events_and_health_wire_formats_are_bounded() {
    let root = lockdown_fixture("events");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core_with(&root, std::sync::Arc::clone(&store), (7, 3));
    assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_HEALTH"]).unwrap(), "7:3:0:0:0:0");
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "1"]).unwrap();
    lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "manual", "tamper", "1"]).unwrap();
    let events = lockdown_command_raw(&mut core, &["LOCKDOWN_EVENTS"]).unwrap();
    let (dropped, records) = events.split_once('|').expect("dropped|records");
    assert!(dropped.parse::<u64>().is_ok());
    let records: Vec<&str> = records.split(',').collect();
    assert!(!records.is_empty() && records.len() <= lockdown_uevent::EVENTS_PER_RESPONSE);
    let mut last_seq = 0u64;
    for record in records {
        let fields: Vec<&str> = record.split(':').collect();
        assert_eq!(fields.len(), 6, "{record}");
        for field in &fields {
            assert!(field.parse::<u64>().is_ok(), "{record}");
        }
        let seq = fields[0].parse::<u64>().unwrap();
        assert!(seq > last_seq, "sequences must increase");
        assert!(matches!(fields[5].parse::<u8>().unwrap(), 1..=5), "{record}");
        last_seq = seq;
    }
    // The queue drains: a second read is empty (no duplication/loss).
    assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_EVENTS"]).unwrap(), "empty");
    let health = lockdown_command_raw(&mut core, &["LOCKDOWN_HEALTH"]).unwrap();
    let values: Vec<&str> = health.split(':').collect();
    assert_eq!(values.len(), 6, "{health}");
    assert!(values.iter().all(|value| value.parse::<u64>().is_ok()));
    assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_HEALTH"]).unwrap().split(':').next(), Some("7"));
}

struct FakeUeventSource {
    queue: VecDeque<lockdown_uevent::Poll>,
}

impl lockdown_uevent::UeventSource for FakeUeventSource {
    fn next(&mut self) -> lockdown_uevent::Poll {
        self.queue.pop_front().unwrap_or(lockdown_uevent::Poll::Timeout)
    }
}

fn uevent_payload(devpath: &str, subsystem: &str) -> Vec<u8> {
    format!("add@{devpath}\0ACTION=add\0SUBSYSTEM={subsystem}\0DEVPATH={devpath}\0").into_bytes()
}

fn wait_for_word(store: &MemoryWordStore) -> u64 {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while store.word() == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    store.word()
}

#[test]
fn lockdown_uevent_loop_blocks_data_devices_and_drops_network() {
    let root = crate::lockdown_usb::tests::fixture("uevent-loop");
    let devpath = "/devices/pci0000:00/usb1/1-3";
    let dir = root.join("sys").join(devpath.trim_start_matches('/'));
    fs::create_dir_all(&dir).expect("uevent device");
    fs::write(dir.join("bDeviceClass"), "08\n").expect("class");
    fs::write(dir.join("bNumInterfaces"), "01\n").expect("interfaces");
    fs::write(dir.join("bNumConfigurations"), "01\n").expect("config");
    fs::write(dir.join("authorized"), "1\n").expect("authorized");
    let word = std::sync::Arc::new(MemoryWordStore::new());
    let shared_word: std::sync::Arc<dyn lockdown::LockdownWordStore> = word.clone();
    let shared = std::sync::Arc::new(LockdownShared::new(
        shared_word,
        UeventPolicy { arm: ArmMode::Locked, auto_network_drop: true, allow_loopback: true, epoch: 0x1234_5678 },
    ));
    let source = FakeUeventSource { queue: VecDeque::from([lockdown_uevent::Poll::Message(uevent_payload(devpath, "usb"))]) };
    let mut monitor = lockdown_uevent::start_with_source(
        Box::new(source),
        std::sync::Arc::clone(&shared),
        crate::lockdown_usb::UsbPaths::new(root.join("sys")),
    )
    .expect("uevent monitor thread");
    let persisted = wait_for_word(&word);
    monitor.stop();
    assert_ne!(persisted, 0, "auto_network_drop must write the kernel word");
    let decoded = gedefense_common::decode_lockdown_word(persisted).expect("drop word");
    assert_eq!(decoded.epoch, 0x1234_5678);
    assert_ne!(decoded.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
    assert_eq!(fs::read_to_string(dir.join("authorized")).unwrap().trim(), "0");
    let (uevents, usb_blocks, tb_blocks) = shared.uevent_counters();
    assert_eq!((uevents, usb_blocks, tb_blocks), (1, 1, 0));
    let (_dropped, records) = shared.take_events(lockdown_uevent::EVENTS_PER_RESPONSE);
    assert!(records.iter().any(|event| {
        event.phase == gedefense_common::LOCKDOWN_PHASE_USB
            && event.outcome == gedefense_common::LOCKDOWN_OUTCOME_APPLIED
            && event.source == gedefense_common::LOCKDOWN_SOURCE_UEVENT
    }));
}

#[test]
fn lockdown_uevent_loop_never_blocks_power_only_or_audits_while_unlocked() {
    let root = crate::lockdown_usb::tests::fixture("uevent-audit");
    let devpath = "/devices/pci0000:00/usb1/1-4";
    let dir = root.join("sys").join(devpath.trim_start_matches('/'));
    fs::create_dir_all(&dir).expect("uevent device");
    fs::write(dir.join("bDeviceClass"), "00\n").expect("class");
    fs::write(dir.join("bNumInterfaces"), "00\n").expect("interfaces");
    fs::write(dir.join("bNumConfigurations"), "01\n").expect("config");
    // Power-only charger: no block, no word write (Lade-Kabel-DoS-Schutz).
    let word = std::sync::Arc::new(MemoryWordStore::new());
    let shared_word: std::sync::Arc<dyn lockdown::LockdownWordStore> = word.clone();
    let shared = std::sync::Arc::new(LockdownShared::new(
        shared_word,
        UeventPolicy { arm: ArmMode::Locked, auto_network_drop: true, allow_loopback: true, epoch: 9 },
    ));
    let source = FakeUeventSource { queue: VecDeque::from([lockdown_uevent::Poll::Message(uevent_payload(devpath, "usb"))]) };
    let mut monitor = lockdown_uevent::start_with_source(
        Box::new(source),
        std::sync::Arc::clone(&shared),
        crate::lockdown_usb::UsbPaths::new(root.join("sys")),
    )
    .expect("uevent monitor thread");
    std::thread::sleep(std::time::Duration::from_millis(60));
    monitor.stop();
    assert_eq!(word.word(), 0, "power-only device never triggers a drop");
    assert_eq!(shared.uevent_counters().1, 0);

    // Unlocked arm mode: audit only, nothing is written or blocked.
    let unlocked = std::sync::Arc::new(LockdownShared::new(
        std::sync::Arc::new(MemoryWordStore::new()),
        UeventPolicy { arm: ArmMode::Unlocked, auto_network_drop: true, allow_loopback: true, epoch: 9 },
    ));
    let source = FakeUeventSource { queue: VecDeque::from([lockdown_uevent::Poll::Message(uevent_payload(devpath, "usb"))]) };
    let mut monitor = lockdown_uevent::start_with_source(
        Box::new(source),
        std::sync::Arc::clone(&unlocked),
        crate::lockdown_usb::UsbPaths::new(root.join("sys")),
    )
    .expect("uevent monitor thread");
    std::thread::sleep(std::time::Duration::from_millis(60));
    monitor.stop();
    let (_dropped, records) = unlocked.take_events(lockdown_uevent::EVENTS_PER_RESPONSE);
    assert!(records.iter().any(|event| event.outcome == gedefense_common::LOCKDOWN_OUTCOME_SKIPPED));
}

#[test]
fn lockdown_usb_uevent_device_paths_are_bounded_and_traversal_free() {
    let root = crate::lockdown_usb::tests::fixture("main-devpath");
    let paths = crate::lockdown_usb::UsbPaths::new(root.join("sys"));
    let dir = root.join("sys/devices/pci0000:00/usb1/1-1");
    fs::create_dir_all(&dir).expect("devpath fixture");
    fs::write(dir.join("bDeviceClass"), "08\n").expect("class");
    fs::write(dir.join("authorized"), "1\n").expect("authorized");
    assert_eq!(
        crate::lockdown_usb::apply_device(&paths, "/devices/pci0000:00/usb1/1-1"),
        Ok(crate::lockdown_usb::DevicePolicy::Block)
    );
    assert_eq!(fs::read_to_string(dir.join("authorized")).unwrap().trim(), "0");
    assert_eq!(crate::lockdown_usb::apply_device(&paths, "/devices/../etc/passwd"), Err("invalid-devpath"));
    assert_eq!(crate::lockdown_usb::apply_device(&paths, "/devices/absent"), Err("not-present"));
    assert_eq!(crate::lockdown_usb::apply_device(&paths, "relative/path"), Err("invalid-devpath"));
}

#[test]
fn lockdown_usb_release_reauthorizes_and_missing_tree_is_unsupported() {
    let root = crate::lockdown_usb::tests::fixture("main-release");
    let paths = crate::lockdown_usb::UsbPaths::new(root.join("sys"));
    let storage = crate::lockdown_usb::tests::usb_device(&root, "1-3", "08", "01", "01", Some("0"));
    assert_eq!(crate::lockdown_usb::apply_usb(&paths).outcome, gedefense_common::LOCKDOWN_OUTCOME_APPLIED);
    assert_eq!(crate::lockdown_usb::release_usb(&paths).outcome, gedefense_common::LOCKDOWN_OUTCOME_APPLIED);
    assert_eq!(fs::read_to_string(storage.join("authorized")).unwrap().trim(), "1");
    let missing = crate::lockdown_usb::UsbPaths::new(root.join("absent"));
    let report = crate::lockdown_usb::apply_usb(&missing);
    assert_eq!(report.outcome, gedefense_common::LOCKDOWN_OUTCOME_UNSUPPORTED);
    assert_eq!(report.reason, "not-present");
    assert_eq!(crate::lockdown_usb::apply_tb(&missing).outcome, gedefense_common::LOCKDOWN_OUTCOME_UNSUPPORTED);
}

#[test]
fn lockdown_modules_never_use_shell_or_kill_primitives() {
    // Adversarial guard for the "no shell, no kill" contract (§§1.1/6.4).
    for (name, source) in [
        ("lockdown.rs", include_str!("lockdown.rs")),
        ("lockdown_usb.rs", include_str!("lockdown_usb.rs")),
        ("lockdown_usb/classify.rs", include_str!("lockdown_usb/classify.rs")),
        ("lockdown_usb/policy.rs", include_str!("lockdown_usb/policy.rs")),
        ("lockdown_usb/release.rs", include_str!("lockdown_usb/release.rs")),
        ("lockdown_usb/uevent.rs", include_str!("lockdown_usb/uevent.rs")),
        ("lockdown_usb/tests.rs", include_str!("lockdown_usb/tests.rs")),
        ("lockdown_uevent.rs", include_str!("lockdown_uevent.rs")),
        ("lockdown_hardening.rs", include_str!("lockdown_hardening.rs")),
        ("lockdown_brokers.rs", include_str!("lockdown_brokers.rs")),
    ] {
        for forbidden in ["Command::new", "process::Command", "SIGKILL", "/bin/sh", "sh -c"] {
            assert!(!source.contains(forbidden), "{name} must not contain {forbidden}");
        }
    }
    let brokers = include_str!("lockdown_brokers.rs");
    assert!(brokers.contains("libc::SIGSTOP") && brokers.contains("libc::SIGCONT"));
}
