use super::*;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "gedefense-canary-{label}-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("test canary root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("test root mode");
        root
    }

    fn token_for(path: &Path) -> String {
        URL_SAFE_NO_PAD.encode(path.as_os_str().as_bytes())
    }

    struct TestBroker {
        root: PathBuf,
        broker: CanaryBroker,
    }

    impl TestBroker {
        fn new(label: &str) -> Self {
            let root = test_root(label);
            let broker = CanaryBroker::new(&[root.clone()]).expect("broker");
            Self { root, broker }
        }

        fn deploy(&self, relative: &str, content: &[u8]) -> Result<String, BoxError> {
            let path = self.root.join(relative);
            let content_token = URL_SAFE_NO_PAD.encode(content);
            self.broker.deploy_token_inner(
                &token_for(&path),
                "DOTENV",
                "600",
                &content_token,
                false,
            )
        }
    }

    impl Drop for TestBroker {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn deploy_and_remove_roundtrip_is_atomic_and_private() {
        let test = TestBroker::new("roundtrip");
        let content = b"DECOY=value\n";
        assert_eq!(
            test.deploy("app/.env", content).expect("deploy"),
            "deployed"
        );
        let deployed = test.root.join("app/.env");
        assert_eq!(fs::read(&deployed).expect("read decoy"), content);
        let metadata = fs::metadata(&deployed).expect("decoy metadata");
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(
            test.deploy("app/.env", content).expect("idempotent deploy"),
            "exists"
        );
        let mismatch = test
            .deploy("app/.env", b"TAMPERED=1\n")
            .expect_err("identity change");
        assert!(
            mismatch.to_string().contains("different identity"),
            "{mismatch}"
        );
        let status = test.broker.status();
        assert!(status.contains("registered=1"), "status={status}");
        assert!(test.root.join(MANIFEST_NAME).is_file());
        assert_eq!(
            test.broker
                .remove_token(&token_for(&deployed))
                .expect("remove"),
            "removed"
        );
        assert!(!deployed.exists());
        assert_eq!(
            test.broker
                .remove_token(&token_for(&deployed))
                .expect("absent"),
            "absent"
        );
    }

    #[test]
    fn manifest_reload_re_registers_verified_decoys() {
        let root = test_root("reload");
        let path = root.join("shadow.bak");
        let content = b"root:decoy\n";
        {
            let broker = CanaryBroker::new(&[root.clone()]).expect("broker");
            broker
                .deploy_token_inner(
                    &token_for(&path),
                    "SHADOW_BAK",
                    "640",
                    &URL_SAFE_NO_PAD.encode(content),
                    false,
                )
                .expect("deploy");
        }
        let reloaded = CanaryBroker::new(&[root.clone()]).expect("reload");
        let status = reloaded.status();
        assert!(status.contains("registered=1"), "status={status}");
        assert!(reloaded
            .records
            .lock()
            .expect("registry")
            .contains_key(&path));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn path_jail_rejects_traversal_outside_and_symlink_components() {
        let test = TestBroker::new("jail");
        let outside = PathBuf::from("/tmp/gedefense-canary-outside");
        let outside_token = token_for(&outside);
        assert!(test
            .broker
            .deploy_token_inner(&outside_token, "DOTENV", "600", "ZGVjb3k=", false)
            .is_err());
        let traversal = format!("{}/../escape", test.root.display());
        assert!(test
            .broker
            .deploy_token_inner(
                &token_for(Path::new(&traversal)),
                "DOTENV",
                "600",
                "ZGVjb3k=",
                false
            )
            .is_err());
        std::os::unix::fs::symlink("/tmp", test.root.join("link")).expect("symlink");
        assert!(test.deploy("link/escaped", b"nope\n").is_err());
    }

    #[test]
    fn deploy_rejects_invalid_type_mode_content_and_reserved_name() {
        let test = TestBroker::new("bounds");
        let path = test.root.join("a.env");
        let path_token = token_for(&path);
        let content = URL_SAFE_NO_PAD.encode(b"x\n");
        assert!(test
            .broker
            .deploy_token_inner(&path_token, "UNKNOWN", "600", &content, false)
            .is_err());
        assert!(test
            .broker
            .deploy_token_inner(&path_token, "DOTENV", "644", &content, false)
            .is_err());
        assert!(test
            .broker
            .deploy_token_inner(&path_token, "DOTENV", "600", "", false)
            .is_err());
        assert!(test
            .broker
            .deploy_token_inner(
                &token_for(&test.root.join(MANIFEST_NAME)),
                "DOTENV",
                "600",
                &content,
                false
            )
            .is_err());
        let oversized = URL_SAFE_NO_PAD.encode(vec![b'a'; MAX_CANARY_CONTENT_BYTES + 1]);
        assert!(test
            .broker
            .deploy_token_inner(&path_token, "DOTENV", "600", &oversized, false)
            .is_err());
    }

    #[test]
    fn event_encoding_is_bounded_and_decodable() {
        let event = CanaryEvent {
            pid: 4242,
            uid: 1000,
            path: PathBuf::from("/var/lib/vgt/gedefense/canaries/.aws_credentials"),
            canary_type: "CLOUD_CRED".to_owned(),
            exec: true,
        };
        let encoded = encode_event(&event);
        assert!(
            encoded.len() < 512,
            "encoded event too large: {}",
            encoded.len()
        );
        let fields: Vec<&str> = encoded.split(':').collect();
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0], "4242");
        assert_eq!(fields[1], "1000");
        assert_eq!(fields[2], token_for(&event.path));
        assert_eq!(fields[3], "CLOUD_CRED");
        assert_eq!(fields[4], "1");
    }

    #[test]
    fn strip_deleted_suffix_keeps_regular_paths() {
        assert_eq!(
            strip_deleted_suffix(Path::new("/run/x (deleted)")),
            PathBuf::from("/run/x")
        );
        assert_eq!(
            strip_deleted_suffix(Path::new("/run/x")),
            PathBuf::from("/run/x")
        );
    }

    // FIND-036a: the accessor UID comes from the process, not from the decoy
    // file's owner.
    #[test]
    fn accessor_uid_parsing_is_strict() {
        assert_eq!(
            parse_uid_from_status("Name:\tsleep\nUid:\t1000\t1001\t1002\t1003\n"),
            Some(1001),
            "the effective UID identifies the accessor"
        );
        assert_eq!(parse_uid_from_status("Uid:\t0\t0\t0\t0\n"), Some(0));
        assert_eq!(parse_uid_from_status("Name:\tsleep\n"), None);
        assert_eq!(parse_uid_from_status("Uid:\t1000\t\n"), None);
        assert_eq!(parse_uid_from_status("Uid:\tx\ty\tz\tw\n"), None);
        assert_eq!(parse_uid_from_status("Uid: 1000 1000 1000\n"), None);
        assert_eq!(parse_uid_from_status(""), None);
        assert_eq!(accessor_uid(-1), None);
        assert_eq!(accessor_uid(0), None);
        assert_eq!(accessor_uid(i32::MAX), None);
    }

    #[test]
    fn current_process_uid_is_attributed_from_proc() {
        let euid = unsafe { libc::geteuid() };
        assert_eq!(
            accessor_uid(std::process::id() as i32),
            Some(euid),
            "/proc/self/status must yield the effective UID"
        );
    }

    fn spawn_uid_probe(target_uid: u32) -> Option<std::process::Child> {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new("sleep");
        command.arg("30");
        if target_uid != unsafe { libc::geteuid() } {
            unsafe {
                command.pre_exec(move || {
                    if libc::setgid(target_uid) != 0 || libc::setuid(target_uid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        command.spawn().ok()
    }

    // A real non-root process must be attributed with its own UID. When the
    // harness happens to run as root the probe process is dropped to uid 65534
    // so the assertion still exercises a non-root accessor.
    #[test]
    fn accessor_uid_attributes_a_non_root_process() {
        let euid = unsafe { libc::geteuid() };
        let target_uid = if euid == 0 { 65534 } else { euid };
        let Some(mut child) = spawn_uid_probe(target_uid) else {
            return;
        };
        let pid = child.id() as i32;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut attributed = None;
        while std::time::Instant::now() < deadline {
            if let Some(uid) = accessor_uid(pid) {
                attributed = Some(uid);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        let uid = attributed.expect("probe process UID could not be attributed");
        assert_eq!(uid, target_uid, "attribution must follow /proc/<pid>/status");
        assert_ne!(uid, CANARY_UID_UNKNOWN);
        if target_uid != 0 {
            assert_ne!(uid, 0, "a non-root accessor must not be attributed as root");
        }
    }

    #[test]
    fn unknown_uid_is_not_encoded_as_root() {
        let event = CanaryEvent {
            pid: 4242,
            uid: CANARY_UID_UNKNOWN,
            path: PathBuf::from("/var/lib/vgt/gedefense/canaries/.aws_credentials"),
            canary_type: "CLOUD_CRED".to_owned(),
            exec: false,
        };
        let encoded = encode_event(&event);
        let fields: Vec<&str> = encoded.split(':').collect();
        assert_eq!(fields[1], u32::MAX.to_string());
        assert_ne!(fields[1], "0", "an unresolved accessor is never root");
        assert_eq!(CANARY_UID_UNKNOWN, u32::MAX);
    }
}
