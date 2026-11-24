use super::*;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    os::unix::{
        ffi::OsStrExt,
        fs::MetadataExt,
    },
    path::Path,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "gedefense-quarantine-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("test root");
        root
    }

    fn path_token(path: &Path) -> String {
        URL_SAFE_NO_PAD.encode(path.as_os_str().as_bytes())
    }

    fn identity_from_token(token: &str) -> FileIdentity {
        let fields: Vec<&str> = token
            .strip_prefix("v1:")
            .expect("identity version")
            .split(':')
            .collect();
        FileIdentity::parse(&fields).expect("identity")
    }

    #[test]
    fn read_only_backing_errors_are_recoverable() {
        for errno in [
            libc::EROFS,
            libc::EXDEV,
            libc::EACCES,
            libc::EPERM,
            libc::ENOSYS,
            libc::EINVAL,
        ] {
            let error = std::io::Error::from_raw_os_error(errno);
            assert!(is_read_only_backing_error(&error), "errno {errno}");
        }
        for errno in [libc::ENOENT, libc::ENOTDIR, libc::EBADF] {
            let error = std::io::Error::from_raw_os_error(errno);
            assert!(!is_read_only_backing_error(&error), "errno {errno}");
        }
    }

    #[test]
    fn copy_quarantine_stores_a_verifiable_object() {
        let root = test_root("copy-fallback");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        fs::create_dir_all(&object_dir).expect("vault directory");
        let source = source_dir.join("threat.bin");
        fs::write(&source, b"copy-fallback-quarantine-payload").expect("source file");
        let broker = QuarantineBroker::new(
            object_dir.to_str().expect("utf8 vault"),
            &[3u8; 32],
        )
        .expect("broker");
        let (parent, basename) = open_parent_and_name(&source).expect("parent descriptor");
        let identity = inspect_at(parent.as_raw_fd(), &basename).expect("identity");
        let object_id = "QV-0123456789abcdef";
        broker
            .copy_quarantine(parent.as_raw_fd(), &basename, object_id, &identity)
            .expect("copy quarantine");
        assert!(
            !source.exists(),
            "source must be removed when the directory is writable"
        );
        assert!(
            object_dir.join(format!("{object_id}.qv")).exists(),
            "vault object missing"
        );
        broker
            .verify_object(object_id, &identity)
            .expect("object verifies");
    }

    #[test]
    fn object_ids_and_identity_encoding_are_strict() {
        assert!(validate_object_id("QV-0123456789abcdef").is_ok());
        assert!(validate_object_id("QV-0123456789ABCDEf").is_err());
        assert!(validate_object_id("../0123456789abcdef").is_err());
        let identity = FileIdentity {
            size: 12,
            mode: 0o640,
            uid: 1000,
            gid: 1000,
            device: 8,
            inode: 99,
            modified_nanos: 123,
            sha256: [7u8; 32],
        };
        let encoded = identity.encode();
        let fields: Vec<&str> = encoded
            .strip_prefix("v1:")
            .expect("identity prefix")
            .split(':')
            .collect();
        assert_eq!(FileIdentity::parse(&fields).expect("identity"), identity);
    }

    #[test]
    fn chunk_nonce_is_unique_per_index() {
        let prefix = [9u8; 8];
        assert_ne!(chunk_nonce(prefix, 0), chunk_nonce(prefix, 1));
    }

    #[test]
    fn encrypted_object_round_trip_is_atomic_and_verified() {
        let root = test_root("round-trip");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source = source_dir.join("threat.bin");
        let payload = vec![0x5au8; CHUNK_BYTES + 37];
        fs::write(&source, &payload).expect("source write");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).expect("source mode");

        let broker =
            QuarantineBroker::new(object_dir.to_str().expect("object directory"), &[0x33; 32])
                .expect("broker");
        let encoded_path = path_token(&source);
        let identity =
            identity_from_token(&broker.inspect_token(&encoded_path).expect("inspect source"));
        let object_id = "QV-0123456789abcdef";

        broker
            .quarantine_token(&encoded_path, object_id, &identity)
            .expect("quarantine");
        assert!(!source.exists());
        broker
            .verify_object(object_id, &identity)
            .expect("verify object");
        broker
            .restore_token(&encoded_path, object_id, &identity)
            .expect("restore");
        assert_eq!(fs::read(&source).expect("restored payload"), payload);
        assert!(!object_dir.join(format!("{object_id}.qv")).exists());

        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn encrypted_object_tamper_and_symlink_parent_are_rejected() {
        let root = test_root("tamper");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source = source_dir.join("threat.bin");
        fs::write(&source, b"hostile payload").expect("source write");
        let broker =
            QuarantineBroker::new(object_dir.to_str().expect("object directory"), &[0x44; 32])
                .expect("broker");
        let encoded_path = path_token(&source);
        let identity =
            identity_from_token(&broker.inspect_token(&encoded_path).expect("inspect source"));
        let object_id = "QV-fedcba9876543210";
        broker
            .quarantine_token(&encoded_path, object_id, &identity)
            .expect("quarantine");

        let object = object_dir.join(format!("{object_id}.qv"));
        let mut bytes = fs::read(&object).expect("object read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;
        fs::write(&object, bytes).expect("object tamper");
        assert!(broker.verify_object(object_id, &identity).is_err());

        let real_parent = root.join("real-parent");
        let linked_parent = root.join("linked-parent");
        fs::create_dir_all(&real_parent).expect("real parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("parent symlink");
        let linked_source = linked_parent.join("target.bin");
        fs::write(real_parent.join("target.bin"), b"target").expect("linked source");
        assert!(broker.inspect_token(&path_token(&linked_source)).is_err());

        fs::remove_dir_all(&root).expect("test cleanup");
    }

    // F-15: the restore staging file is created relative to the validated parent
    // descriptor, exclusively, without following symlinks and with mode 0600.
    #[test]
    fn restore_staging_file_is_fd_relative_exclusive_and_private() {
        let root = test_root("restore-fd");
        let parent = root.join("parent");
        fs::create_dir_all(&parent).expect("parent directory");
        let directory = File::open(&parent).expect("open parent");
        let name = CString::new(".gedefense-restore-QV-0123456789abcdef").expect("staging name");

        {
            let file =
                create_restore_file_at(directory.as_raw_fd(), &name).expect("create staging");
            let metadata = file.metadata().expect("staging metadata");
            assert!(metadata.is_file());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        assert!(
            create_restore_file_at(directory.as_raw_fd(), &name).is_err(),
            "staging file must be exclusive"
        );

        let symlink_name = CString::new(".gedefense-restore-QV-fedcba9876543210").expect("name");
        let outside = root.join("outside");
        fs::write(&outside, b"outside").expect("outside file");
        std::os::unix::fs::symlink(&outside, parent.join(symlink_name.to_str().unwrap()))
            .expect("symlink staging name");
        assert!(
            create_restore_file_at(directory.as_raw_fd(), &symlink_name).is_err(),
            "symlink staging target must be refused"
        );
        unlink_at(directory.as_raw_fd(), &name).expect("fd-relative unlink");
        assert!(!parent.join(name.to_str().unwrap()).exists());

        fs::remove_dir_all(&root).expect("test cleanup");
    }

    // F-15: a failed restore must clean up its staging file through the parent
    // descriptor and must not leave attacker-influenced destinations behind.
    #[test]
    fn failed_restore_removes_fd_relative_staging_file() {
        let root = test_root("restore-failure");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source = source_dir.join("threat.bin");
        fs::write(&source, b"restore failure payload").expect("source write");
        let broker =
            QuarantineBroker::new(object_dir.to_str().expect("object directory"), &[0x55; 32])
                .expect("broker");
        let encoded_path = path_token(&source);
        let identity =
            identity_from_token(&broker.inspect_token(&encoded_path).expect("inspect source"));
        let object_id = "QV-0011223344556677";
        broker
            .quarantine_token(&encoded_path, object_id, &identity)
            .expect("quarantine");

        let object = object_dir.join(format!("{object_id}.qv"));
        let mut bytes = fs::read(&object).expect("object read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x40;
        fs::write(&object, bytes).expect("object tamper");
        assert!(broker
            .restore_token(&encoded_path, object_id, &identity)
            .is_err());
        assert!(
            !source.exists(),
            "failed restore must not install a destination"
        );
        let leftovers: Vec<String> = fs::read_dir(&source_dir)
            .expect("source directory listing")
            .map(|entry| {
                entry
                    .expect("source entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.starts_with(".gedefense-restore-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "failed restore left staging files: {leftovers:?}"
        );

        fs::remove_dir_all(&root).expect("test cleanup");
    }

    // FIND-035: captured SUID/SGID bits are never restored.
    #[test]
    fn restored_mode_masks_suid_sgid_and_sticky() {
        assert_eq!(restored_mode(0o4755), 0o755);
        assert_eq!(restored_mode(0o2755), 0o755);
        assert_eq!(restored_mode(0o6755), 0o755);
        assert_eq!(restored_mode(0o1655), 0o655);
        assert_eq!(restored_mode(0o640), 0o640);
        assert_eq!(restored_mode(0o7777), 0o777);
    }

    #[test]
    fn restore_drops_the_suid_bit_of_a_quarantined_file() {
        let root = test_root("restore-suid");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source = source_dir.join("setuid.bin");
        fs::write(&source, b"setuid payload").expect("source write");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o4755)).expect("source mode");
        let broker =
            QuarantineBroker::new(object_dir.to_str().expect("object directory"), &[0x77; 32])
                .expect("broker");
        let encoded_path = path_token(&source);
        let identity =
            identity_from_token(&broker.inspect_token(&encoded_path).expect("inspect source"));
        assert_eq!(
            identity.mode & 0o7777,
            0o4755,
            "the identity records the captured SUID bit"
        );
        let object_id = "QV-0011223344556677";
        broker
            .quarantine_token(&encoded_path, object_id, &identity)
            .expect("quarantine");
        assert!(!source.exists());
        broker
            .restore_token(&encoded_path, object_id, &identity)
            .expect("restore");
        let mode = fs::metadata(&source).expect("restored metadata").mode() & 0o7777;
        assert_eq!(mode, 0o755, "restore must drop SUID/SGID bits");
        assert_eq!(mode & 0o7000, 0, "no privilege bits may survive a restore");

        fs::remove_dir_all(&root).expect("test cleanup");
    }

    // FIND-035: a FIFO planted at the quarantine source name must be refused
    // immediately instead of blocking the single-threaded IPC loop forever.
    #[test]
    fn open_regular_at_returns_immediately_for_a_fifo() {
        let root = test_root("fifo-open");
        let parent = File::open(&root).expect("parent directory");
        let fifo = root.join("threat.fifo");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0, "mkfifo");
        let name = CString::new("threat.fifo").expect("fifo name");
        let started = std::time::Instant::now();
        let result = open_regular_at(parent.as_raw_fd(), &name);
        assert!(result.is_err(), "a FIFO must not be accepted as a source");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "open_regular_at blocked on a FIFO"
        );

        // A directory and a symlink are not regular files either.
        fs::create_dir(root.join("directory")).expect("directory fixture");
        let directory = CString::new("directory").expect("directory name");
        assert!(open_regular_at(parent.as_raw_fd(), &directory).is_err());
        let target = root.join("target.bin");
        fs::write(&target, b"target").expect("symlink target");
        std::os::unix::fs::symlink(&target, root.join("linked.bin")).expect("symlink fixture");
        let link = CString::new("linked.bin").expect("symlink name");
        assert!(open_regular_at(parent.as_raw_fd(), &link).is_err());

        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn unlink_at_propagates_missing_and_directory_failures() {
        let root = test_root("unlink-errors");
        let parent = File::open(&root).expect("parent directory");
        let missing = CString::new("missing.bin").expect("missing name");
        assert!(unlink_at(parent.as_raw_fd(), &missing).is_err());
        fs::create_dir(root.join("subdir")).expect("directory fixture");
        let directory = CString::new("subdir").expect("directory name");
        let error: BoxError = unlink_at(parent.as_raw_fd(), &directory)
            .expect_err("unlinkat on a directory must not report success");
        assert!(!error.to_string().is_empty(), "{error}");
        assert!(root.join("subdir").exists());
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    // FIND-035: the source removal is the commit point of the copy fallback.
    // This test runs in an unprivileged child process when the harness is root,
    // because root's CAP_DAC_OVERRIDE would unlink inside a read-only directory
    // and hide the defect.
    #[test]
    fn copy_quarantine_aborts_when_the_source_cannot_be_removed() {
        if std::env::var_os("GEDEFENSE_QUARANTINE_READONLY_CHILD").is_some() {
            copy_quarantine_aborts_when_the_source_cannot_be_removed_inner();
            return;
        }
        if unsafe { libc::geteuid() } == 0 {
            use std::ffi::CString;
            use std::os::unix::process::CommandExt;
            let child_tmp = PathBuf::from(format!("/tmp/gedefense-qchild-{}", std::process::id()));
            let _ = fs::remove_dir_all(&child_tmp);
            fs::create_dir_all(&child_tmp).expect("child tmp dir");
            fs::set_permissions(&child_tmp, fs::Permissions::from_mode(0o700))
                .expect("child tmp permissions");
            let c_tmp = CString::new(child_tmp.as_os_str().as_bytes()).expect("cstr child_tmp");
            if unsafe { libc::chown(c_tmp.as_ptr(), 65534, 65534) } != 0 {
                let _ = fs::remove_dir_all(&child_tmp);
                panic!("chown child_tmp failed: {}", std::io::Error::last_os_error());
            }
            let run_as_nobody = |bin: &Path| -> std::io::Result<std::process::ExitStatus> {
                let mut command = std::process::Command::new(bin);
                command.args([
                    "--exact",
                    "quarantine::tests::copy_quarantine_aborts_when_the_source_cannot_be_removed",
                    "--nocapture",
                ]);
                command.env("GEDEFENSE_QUARANTINE_READONLY_CHILD", "1");
                // Override root's inherited TMPDIR (e.g. pam_tmpdir /tmp/user/0 mode 0700)
                // because std::env::temp_dir() does not fall back when TMPDIR is unwritable.
                command.env("TMPDIR", &child_tmp);
                unsafe {
                    command.pre_exec(|| {
                        if libc::setgid(65534) != 0 || libc::setuid(65534) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                command.status()
            };
            let exe = std::env::current_exe().expect("test binary");
            let status_res = match run_as_nobody(&exe) {
                Ok(status) => Ok(status),
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    // When invoked inside an installer's 0700 WORK directory, uid 65534
                    // cannot traverse parent directories to exec `exe`; stage a transient
                    // 0755 copy inside a 0711 directory under /tmp or /var/tmp.
                    let mut result = Err(err);
                    for base in [PathBuf::from("/tmp"), PathBuf::from("/var/tmp")] {
                        let stage_dir = base.join(format!("gedefense-qtest-{}", std::process::id()));
                        let _ = fs::remove_dir_all(&stage_dir);
                        if fs::create_dir_all(&stage_dir).is_ok()
                            && fs::set_permissions(&stage_dir, fs::Permissions::from_mode(0o711)).is_ok()
                        {
                            let staged_bin = stage_dir.join("test-runner");
                            if fs::copy(&exe, &staged_bin).is_ok()
                                && fs::set_permissions(&staged_bin, fs::Permissions::from_mode(0o755)).is_ok()
                            {
                                result = run_as_nobody(&staged_bin);
                            }
                            let _ = fs::remove_dir_all(&stage_dir);
                            if let Ok(ref st) = result {
                                if st.success() {
                                    break;
                                }
                            }
                        }
                    }
                    result
                }
                Err(err) => Err(err),
            };
            let _ = fs::remove_dir_all(&child_tmp);
            let status = status_res.expect("unprivileged staged child test process");
            assert!(status.success(), "unprivileged child test failed: {status}");
            return;
        }
        copy_quarantine_aborts_when_the_source_cannot_be_removed_inner();
    }

    fn copy_quarantine_aborts_when_the_source_cannot_be_removed_inner() {
        let root = test_root("copy-abort");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source = source_dir.join("threat.bin");
        fs::write(&source, b"copy-abort payload").expect("source write");
        let broker =
            QuarantineBroker::new(object_dir.to_str().expect("object directory"), &[0x66; 32])
                .expect("broker");
        let (parent, basename) = open_parent_and_name(&source).expect("parent descriptor");
        let identity = inspect_at(parent.as_raw_fd(), &basename).expect("identity");
        // Readable but not writable: the vault copy succeeds, unlink of the
        // source fails with EACCES.
        fs::set_permissions(&source_dir, fs::Permissions::from_mode(0o555))
            .expect("read-only source directory");
        let object_id = "QV-0123456789abcdef";
        let error = broker
            .copy_quarantine(parent.as_raw_fd(), &basename, object_id, &identity)
            .expect_err("an unremovable source must fail the quarantine");
        assert!(
            error.to_string().contains("could not be removed"),
            "{error}"
        );
        assert!(source.exists(), "the source must remain at its path");
        assert!(
            !object_dir.join(format!("{object_id}.qv")).exists(),
            "the vault object must be rolled back"
        );
        let leftovers: Vec<String> = fs::read_dir(&object_dir)
            .expect("vault listing")
            .map(|entry| {
                entry
                    .expect("vault entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert!(leftovers.is_empty(), "vault leftovers: {leftovers:?}");
        fs::set_permissions(&source_dir, fs::Permissions::from_mode(0o755))
            .expect("restore directory mode");
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn quarantine_open_file_captures_already_open_descriptor_without_reopen() {
        let root = test_root("open-fd-quarantine");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source_path = source_dir.join("secret_payload.txt");
        let payload = b"open-fd-quarantine-payload";
        fs::write(&source_path, payload).expect("write source");
        let mut handle = File::open(&source_path).expect("open source");
        // Tighten permissions before capture; open_regular_at would require read
        // bits (or DAC bypass) when reopening by path, whereas the kernel-held
        // fanotify descriptor captures via the open fd + fstatat.
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o000))
            .expect("strip read bits");
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let broker =
            QuarantineBroker::new(object_dir.to_str().expect("object directory"), &[0x77; 32])
                .expect("broker");
        let encoded_path = path_token(&source_path);
        let object_id = "QV-abcdef0123456789";
        let encoded_identity = broker
            .quarantine_open_file(&encoded_path, &mut handle, object_id, digest, payload.len() as u64)
            .expect("open-fd quarantine succeeds");
        let identity = FileIdentity::decode(&encoded_identity).expect("decode identity");
        assert_eq!(identity.sha256, digest);
        assert!(!source_path.exists(), "source must be unlinked after capture");
        assert_eq!(
            broker
                .verify_object(object_id, &identity)
                .expect("verify vault object"),
            "verified"
        );
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn find_g_001_decode_path_enforces_core_allowlist_and_denylist() {
        for blocked in [
            "/etc/sysctl.d/99-gedefense.conf",
            "/etc/shadow",
            "/etc/vgt/gedefense/secrets/core-ipc.key",
            "/var/lib/vgt/gedefense/quarantine/objects/x.qv",
            "/opt/vgt/gedefense/current/bin/gedefense-control",
            "/proc/self/environ",
            "/sys/kernel/security/lsm",
            "/dev/sda1",
            "/usr/bin/bash",
            "/tmp/../etc/shadow",
            "/tmp",
            "relative/path.bin",
            "/",
        ] {
            let token = URL_SAFE_NO_PAD.encode(blocked.as_bytes());
            assert!(
                decode_path(&token).is_err(),
                "expected core path policy to reject {blocked}"
            );
        }
        for allowed in [
            "/tmp/drop.bin",
            "/var/tmp/payload.elf",
            "/dev/shm/stage.sh",
            "/var/www/html/shell.php",
            "/home/pentest/download.bin",
        ] {
            let token = URL_SAFE_NO_PAD.encode(allowed.as_bytes());
            assert_eq!(
                decode_path(&token).expect("allowed path"),
                PathBuf::from(allowed)
            );
        }
    }

    // -------------------------------------------------------------------
    // V6.3.0 AP-7: QUARANTINE_PRUNE
    // -------------------------------------------------------------------

    /// Creates one vaulted object from a temporary source file and returns the
    /// fixture alongside the broker, the encoded host path and the captured
    /// identity the prune must match.
    fn prune_fixture(
        name: &str,
        object_id: &str,
    ) -> (PathBuf, PathBuf, QuarantineBroker, String, FileIdentity) {
        let root = test_root(name);
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source = source_dir.join("false-positive.bin");
        fs::write(&source, b"prune-false-positive-payload").expect("source write");
        let broker = QuarantineBroker::new(
            object_dir.to_str().expect("object directory"),
            &[0x5a; 32],
        )
        .expect("broker");
        let encoded_path = path_token(&source);
        let identity =
            identity_from_token(&broker.inspect_token(&encoded_path).expect("inspect source"));
        broker
            .quarantine_token(&encoded_path, object_id, &identity)
            .expect("quarantine");
        (root, object_dir, broker, encoded_path, identity)
    }

    #[test]
    fn prune_removes_verified_vault_object_and_refuses_a_second_prune() {
        let object_id = "QV-0123456789abcdef";
        let (root, object_dir, broker, _encoded_path, identity) =
            prune_fixture("prune-success", object_id);
        let object = object_dir.join(format!("{object_id}.qv"));
        assert!(object.exists(), "fixture object missing before prune");

        assert_eq!(
            broker
                .prune_token(object_id, &identity)
                .expect("verified false-positive must prune"),
            "pruned"
        );
        assert!(!object.exists(), "the vault object must be removed");
        assert!(
            !object_dir.join(format!(".{object_id}.tmp")).exists(),
            "prune must not leave temporary objects behind"
        );

        // The object is gone (already pruned or restored); a replay must be
        // refused instead of reporting a second successful prune.
        let error = broker
            .prune_token(object_id, &identity)
            .expect_err("double prune must fail closed");
        assert!(error.to_string().contains("not present"), "{error}");
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn prune_refuses_identity_mismatch_without_removing_the_object() {
        let object_id = "QV-0011223344556677";
        let (root, object_dir, broker, _encoded_path, identity) =
            prune_fixture("prune-mismatch", object_id);
        let object = object_dir.join(format!("{object_id}.qv"));
        let mut wrong = identity.clone();
        wrong.sha256[0] ^= 0x01;

        let error = broker
            .prune_token(object_id, &wrong)
            .expect_err("a mismatched identity must never prune");
        assert!(
            error.to_string().contains("identity mismatch"),
            "unexpected refusal: {error}"
        );
        assert!(object.exists(), "a refused prune must not remove the object");
        // The object stays verifiable with its real identity.
        assert_eq!(
            broker
                .verify_object(object_id, &identity)
                .expect("object still verifies"),
            "verified"
        );
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn prune_refuses_an_object_that_was_already_restored() {
        let object_id = "QV-fedcba9876543210";
        let (root, object_dir, broker, encoded_path, identity) =
            prune_fixture("prune-restored", object_id);
        broker
            .restore_token(&encoded_path, object_id, &identity)
            .expect("restore");
        // A successful restore removes the vault object in every branch; the
        // explicit "not currently restored" check is exactly this absence.
        assert!(!object_dir.join(format!("{object_id}.qv")).exists());
        let error = broker
            .prune_token(object_id, &identity)
            .expect_err("a restored object cannot be pruned");
        assert!(error.to_string().contains("not present"), "{error}");
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn prune_rejects_invalid_object_ids() {
        let object_id = "QV-0123456789abcdef";
        let (root, _object_dir, broker, _encoded_path, identity) =
            prune_fixture("prune-invalid-id", object_id);
        for invalid in [
            "",
            "QV-0123",
            "QV-0123456789ABCDEF",
            "../0123456789abcdef",
            "QV-0123456789abcdeg",
        ] {
            assert!(
                broker.prune_token(invalid, &identity).is_err(),
                "invalid object id accepted for prune: {invalid:?}"
            );
        }
        // The valid object is untouched by the rejected calls.
        assert_eq!(
            broker
                .verify_object(object_id, &identity)
                .expect("object still verifies"),
            "verified"
        );
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn prune_refuses_a_symlink_planted_in_the_vault() {
        let object_id = "QV-abcdef0123456789";
        let (root, object_dir, broker, _encoded_path, identity) =
            prune_fixture("prune-symlink", object_id);
        let object = object_dir.join(format!("{object_id}.qv"));
        let outside = root.join("outside.bin");
        fs::write(&outside, b"outside").expect("outside file");
        fs::remove_file(&object).expect("remove fixture object");
        std::os::unix::fs::symlink(&outside, &object).expect("vault symlink fixture");
        assert!(
            broker.prune_token(object_id, &identity).is_err(),
            "a symlink planted in the vault must not be pruned"
        );
        assert!(outside.exists(), "the symlink target must stay untouched");
        fs::remove_dir_all(&root).expect("test cleanup");
    }
}
