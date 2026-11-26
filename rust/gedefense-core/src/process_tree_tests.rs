//! M2.3 (6.2.0): process-tree/process-group response tests.
//!
//! The tree collector, the hard protection allowlist and the strict wire
//! parsers are pure and tested against synthetic `/proc` snapshots (no real
//! process is ever signaled by the test suite). A smoke test reads the real
//! `/proc` table but only collects/validates, it never signals.

use crate::process_tree::*;

fn entry(pid: i32, ppid: i32, pgrp: i32, start: u64, comm: &str) -> ProcEntry {
    ProcEntry {
        pid,
        ppid,
        pgrp,
        start_ticks: start,
        comm: comm.to_owned(),
    }
}

/// A complete `/proc/<pid>/stat` line with a configurable comm and start time.
fn stat_line(pid: i32, comm: &str, ppid: i32, pgrp: i32, start: u64) -> String {
    format!(
        "{pid} ({comm}) S {ppid} {pgrp} {pgrp} 0 -1 4194560 1000 0 0 0 5 0 0 0 20 0 1 0 {start} 100 0 0"
    )
}

#[test]
fn proc_stat_parser_is_strict_about_comm_and_fields() {
    let parsed = parse_proc_stat(123, &stat_line(123, "web worker", 1, 123, 987_654))
        .expect("valid stat line");
    assert_eq!(parsed.pid, 123);
    assert_eq!(parsed.ppid, 1);
    assert_eq!(parsed.pgrp, 123);
    assert_eq!(parsed.start_ticks, 987_654);
    assert_eq!(parsed.comm, "web worker");
    // Parentheses inside comm are accepted: the kernel uses the LAST ')'.
    let parsed = parse_proc_stat(7, &stat_line(7, "ev)il)", 1, 7, 42)).expect("paren comm");
    assert_eq!(parsed.comm, "ev)il)");
    assert_eq!(parsed.start_ticks, 42);
    for bad in [
        String::new(),
        "123".to_owned(),
        "123 () S 1 123 123 0 -1 4194560 1000 0 0 0 5 0 0 0 20 0 1 0 7 100 0 0".to_owned(),
        "123 (x) S 1 123".to_owned(),
        stat_line(123, "bad\ncomm", 1, 123, 7),
    ] {
        assert!(parse_proc_stat(123, &bad).is_none(), "accepted {bad:?}");
    }
    assert!(parse_proc_stat(0, &stat_line(1, "init", 0, 1, 1)).is_none());
}

#[test]
fn tree_collection_walks_ppid_descendants_and_process_group_members() {
    let table = vec![
        entry(100, 1, 100, 10, "encryptor"),
        entry(101, 100, 100, 11, "worker"),
        entry(102, 101, 100, 12, "grandchild"),
        // Same process group but a different parent: still part of the scope.
        entry(103, 1, 100, 13, "pgid-sibling"),
        // Unrelated process: must never be collected.
        entry(200, 1, 200, 14, "innocent"),
    ];
    let members = collect_tree(100, &table).expect("tree collection");
    let pids: Vec<i32> = members.iter().map(|entry| entry.pid).collect();
    assert!(pids.contains(&100) && pids.contains(&101) && pids.contains(&102));
    assert!(pids.contains(&103), "process-group member missing: {pids:?}");
    assert!(!pids.contains(&200), "unrelated process collected: {pids:?}");
    // Deepest first, root last: children are killed before their parent.
    assert_eq!(members.first().map(|entry| entry.pid), Some(102));
    assert_eq!(members.last().map(|entry| entry.pid), Some(100));
}

#[test]
fn tree_collection_is_cycle_safe_and_bounded() {
    // A synthetic parent cycle (100 <-> 101) must terminate via the visited set.
    let cyclic = vec![entry(100, 101, 100, 1, "a"), entry(101, 100, 100, 2, "b")];
    let members = collect_tree(100, &cyclic).expect("cycle-safe collection");
    assert_eq!(members.len(), 2);
    // Missing root is an error, not an empty/partial scope.
    assert!(collect_tree(999, &cyclic).is_err());
    // A chain deeper than MAX_TREE_DEPTH is a bounded rejection.
    let mut deep = Vec::new();
    for depth in 0..=(u16::from(MAX_TREE_DEPTH) + 1) {
        let pid = 1000 + depth as i32;
        deep.push(entry(pid, pid - 1, 1000, u64::from(depth), "chain"));
    }
    assert!(collect_tree(1000, &deep).is_err());
    // More members than the signal budget is a bounded rejection.
    let mut wide = vec![entry(1, 0, 1, 0, "root")];
    for offset in 0..=MAX_TREE_SIGNALS {
        wide.push(entry(2_000 + offset as i32, 1, 1, 1, "flood"));
    }
    assert!(collect_tree(1, &wide).is_err());
}

#[test]
fn protection_allowlist_covers_every_documented_boundary() {
    let own = std::process::id() as i32;
    let core = std::path::Path::new("/opt/vgt/gedefense/current/libexec/gedefense-core");
    for pid in [1, 2, 3, 4] {
        assert!(protected_target(pid, "init", None, own), "pid {pid}");
    }
    assert!(protected_target(own, "gedefense-core", Some(core), own));
    for comm in [
        "systemd",
        "systemd-journal",
        "systemd-udevd",
        "(udev-worker)",
        "(systemd)",
        "sshd",
        "sshd: worker",
        "gedefense-control",
        "gedefense-core",
    ] {
        assert!(
            protected_target(1234, comm, Some(std::path::Path::new("/tmp/x")), own),
            "comm {comm}"
        );
    }
    // Kernel threads and unreadable internal tasks have no exe: never killed.
    assert!(protected_target(1234, "kworker/0:1", None, own));
    // System executables are protected by path even with a spoofable comm.
    for exe in [
        "/usr/lib/systemd/systemd-logind",
        "/usr/sbin/sshd",
        "/opt/vgt/gedefense/current/libexec/gedefense-core",
    ] {
        assert!(protected_target(
            1234,
            "innocent",
            Some(std::path::Path::new(exe)),
            own
        ));
    }
    // A normal untrusted executable is a legitimate target.
    for exe in ["/tmp/payload", "/usr/bin/python3", "/var/www/uploads/shell.php"] {
        assert!(
            !protected_target(1234, "payload", Some(std::path::Path::new(exe)), own),
            "exe {exe}"
        );
    }
}

#[test]
fn kill_tree_request_parser_is_strict() {
    let (pid, start, rule) =
        parse_kill_tree_request(&["4242", "987654", "XDR.RANSOM_ENTROPY_BURST"]).expect("valid");
    assert_eq!((pid, start, rule.as_str()), (4242, 987_654, "XDR.RANSOM_ENTROPY_BURST"));
    for args in [
        vec![],
        vec!["4242"],
        vec!["4242", "987654"],
        vec!["4", "987654", "XDR.RANSOM_ENTROPY_BURST"],
        vec!["-1", "987654", "XDR.RANSOM_ENTROPY_BURST"],
        vec!["4242", "0", "XDR.RANSOM_ENTROPY_BURST"],
        vec!["4242", "abc", "XDR.RANSOM_ENTROPY_BURST"],
        vec!["4242", "987654", "bad rule"],
        vec!["4242", "987654", ""],
    ] {
        assert!(parse_kill_tree_request(&args).is_err(), "accepted {args:?}");
    }
}

#[test]
fn group_request_parser_and_own_group_protection_are_strict() {
    let (pgid, rule) = parse_group_request(&["4242", "XDR.RANSOM_RENAME_STORM"]).expect("valid");
    assert_eq!(pgid, 4242);
    assert_eq!(rule, "XDR.RANSOM_RENAME_STORM");
    for args in [vec![], vec!["4242"], vec!["1", "XDR.RANSOM"], vec!["0", "XDR.RANSOM"]] {
        assert!(parse_group_request(&args).is_err(), "accepted {args:?}");
    }
    // The own process group is refused before any signal is sent.
    // SAFETY: getpgrp has no arguments and cannot fail.
    let own_pgrp = unsafe { libc::getpgrp() };
    assert!(stop_process_group(own_pgrp, "XDR.RANSOM_ENTROPY_BURST").is_err());
    assert!(resume_process_group(own_pgrp, "XDR.RANSOM_ENTROPY_BURST").is_err());
    assert!(stop_process_group(std::process::id() as i32, "XDR.RANSOM_ENTROPY_BURST").is_err());
    assert!(stop_process_group(1, "XDR.RANSOM_ENTROPY_BURST").is_err());
    assert!(stop_process_group(4_242, "bad rule").is_err());
}

#[test]
fn tree_kill_refuses_protected_roots_before_collecting() {
    // PID 1/self are rejected by the hard boundary before any /proc walk.
    assert!(signal_process_tree(1, 1, "XDR.MEMFD_EXEC").is_err());
    assert!(signal_process_tree(2, 1, "XDR.MEMFD_EXEC").is_err());
    let own = std::process::id() as i32;
    assert!(signal_process_tree(own, 1, "XDR.MEMFD_EXEC").is_err());
    // Invalid rule and missing objective evidence are rejected as well.
    assert!(signal_process_tree(4_242, 1, "bad rule").is_err());
}

#[test]
fn trusted_group_exemption_keeps_package_managers_and_builds_unfrozen() {
    let trusted = ["dpkg", "apt-get", "cargo", "rustc", "tar"];
    let plain_table = vec![
        entry(100, 1, 500, 10, "encryptor"),
        entry(101, 100, 500, 11, "worker"),
    ];
    assert!(!group_has_trusted_comm(500, &plain_table, &trusted));
    // A short-lived dpkg/apt child keeps the group exempt even when its own
    // comm no longer names the trusted parent (the classic apt/dpkg FP).
    let apt_table = vec![
        entry(100, 1, 500, 10, "sh"),
        entry(101, 100, 500, 11, "dpkg"),
        entry(102, 101, 500, 12, "postinst"),
    ];
    assert!(group_has_trusted_comm(500, &apt_table, &trusted));
    // Build workload (cargo/rustc children) is exempt as well.
    let build_table = vec![
        entry(200, 1, 600, 20, "cc1"),
        entry(201, 200, 600, 21, "rustc"),
    ];
    assert!(group_has_trusted_comm(600, &build_table, &trusted));
    // A group with no trusted member is still a legitimate freeze target.
    assert!(!group_has_trusted_comm(600, &plain_table, &trusted));
    // Special groups are always exempt (never a freeze target).
    assert!(group_has_trusted_comm(1, &plain_table, &trusted));
    // Built-in trusted list covers the documented package-manager set.
    for name in ["apt", "apt-get", "dpkg", "tar"] {
        assert!(crate::ransom::TRUSTED_COMMS.contains(&name), "{name}");
    }
}

#[test]
fn real_proc_snapshot_contains_the_core_and_pid_one() {
    let table = read_process_table().expect("bounded proc snapshot");
    assert!(table.len() > 1);
    assert!(table.iter().any(|entry| entry.pid == 1), "pid 1 missing");
    let own = std::process::id() as i32;
    let own_entry = table
        .iter()
        .find(|entry| entry.pid == own)
        .expect("own pid in snapshot");
    assert_eq!(
        proc_start_ticks(own).expect("own start ticks"),
        own_entry.start_ticks
    );
    let own_tree = collect_tree(own, &table).expect("own tree collection");
    assert!(own_tree.iter().any(|entry| entry.pid == own));
}

#[test]
fn protected_group_detection_covers_system_daemons_without_excluding_normal_workers() {
    let own = std::process::id() as i32;
    let table = vec![
        entry(1912, 1, 1912, 10, "systemd-udevd"),
        entry(1999, 1, 2000, 10, "su"),
        entry(2000, 1999, 2000, 11, "sh"),
        entry(2001, 2000, 2000, 12, "encryptor"),
        entry(2500, 2, 2500, 13, "kworker/0:1"),
    ];
    assert!(group_has_protected_target(1912, &table, own, |_| None));
    assert!(group_has_protected_target(1, &table, own, |_| None));
    assert!(group_has_protected_target(2500, &table, own, |_| None));
    // An unreadable `exe` on a non-kernel userspace wrapper (like setuid `su`)
    // must not grant freeze immunity to the child ransomware process group, and
    // a non-root userspace binary whose `/proc/<pid>/exe` is unreadable without
    // CAP_SYS_PTRACE remains a valid kill-tree target.
    let encryptor = entry(1881, 1880, 1880, 14, "hardred-probe");
    assert!(!protected_proc_entry(&encryptor, None, own));
    assert!(protected_proc_entry(
        &entry(2500, 2, 2500, 13, "kworker/0:1"),
        None,
        own
    ));
    assert!(!group_has_protected_target(2000, &table, own, |pid| {
        if pid == 1999 {
            None
        } else {
            Some(std::path::PathBuf::from("/usr/local/bin/encryptor"))
        }
    }));
}

#[test]
fn pooled_service_worker_collection_isolates_worker_without_killing_master_or_siblings() {
    let table = vec![
        entry(5000, 1, 5000, 10, "php-fpm"),       // master daemon (PGID leader)
        entry(5001, 5000, 5000, 11, "php-fpm"),    // compromised worker (trigger root)
        entry(5002, 5001, 5000, 12, "sh"),         // child shell spawned by compromised worker
        entry(5003, 5000, 5000, 13, "php-fpm"),    // healthy sibling worker sharing PGID 5000
    ];
    assert!(entry_is_service_pool_worker(&table[1], &table));
    assert!(!entry_is_service_pool_worker(&table[0], &table));

    let members = collect_tree(5001, &table).expect("isolated worker collection");
    let pids: Vec<i32> = members.iter().map(|item| item.pid).collect();
    assert_eq!(pids, vec![5002, 5001]);
    assert!(!pids.contains(&5000), "master daemon must not be collected");
    assert!(!pids.contains(&5003), "healthy sibling worker must not be collected");
}

#[test]
fn panel_server_exe_paths_allow_immutable_server_trees_and_reject_wwwroot() {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    assert!(is_panel_server_exe_path(Path::new("/www/server/php/86/sbin/php-fpm")));
    assert!(is_panel_server_exe_path(Path::new("/opt/plesk/php/8.3/sbin/php-fpm")));
    assert!(!is_panel_server_exe_path(Path::new("/www/wwwroot/site/php-fpm")));
    assert!(!is_panel_server_exe_path(Path::new("/tmp/www/server/php-fpm")));

    let root = std::env::temp_dir().join(format!("vgt_panel_tree_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let bin = root.join("server/php/86/sbin/php-fpm");
    std::fs::create_dir_all(bin.parent().expect("parent")).expect("create dirs");
    std::fs::write(&bin, b"elf").expect("write bin");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    // Under current uid in test sandbox, non-root check passes for 0755 chain
    // below `root`, while require_root rejects non-root owner unless uid 0.
    let expected_root = unsafe { libc::geteuid() } == 0;
    assert_eq!(path_chain_immutable_under(&root, &bin, true), expected_root);
    assert!(path_chain_immutable_under(&root, &bin, false));

    // Group-writable binary fails immutability immediately.
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o775)).expect("chmod g+w");
    assert!(!path_chain_immutable_under(&root, &bin, false));
    let _ = std::fs::remove_dir_all(&root);
}
