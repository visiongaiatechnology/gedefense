#![cfg(test)]
//! Wave 5a: Titan exec policy / LSM / path / wire tests moved verbatim from
//! `main_tests.rs` (structure-only split).

use super::*;

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
