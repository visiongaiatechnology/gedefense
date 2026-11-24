#[cfg(test)]
mod tests {
    use super::super::*;
use super::super::attach::*;
use super::super::drain::*;
    use gedefense_common::{
        EXEC_INODE_ACTION_DENIED_UNTRUSTED, EXEC_INODE_ACTION_FALLBACK_COMM,
        EXEC_INODE_ACTION_OBSERVED_MISMATCH, EXEC_INODE_ALLOW_RANSOM_POOL_META,
    };

    fn sample_event(action: u8) -> ExecInodeEvent {
        ExecInodeEvent {
            ts_ns: 1_700_000_000_000_000_000,
            pid: 4242,
            tgid: 4242,
            uid: 1000,
            exe_dev: 8,
            exe_ino: 123_456,
            trust_flags: 0,
            action,
            comm: *b"sshd\0\0\0\0\0\0\0\0\0\0\0\0",
            reserved: [0; 11],
        }
    }

    #[test]
    fn state_word_matches_the_shared_layout() {
        let word = encode_state_word(0xdead_beef, true);
        assert_eq!(word & u64::from(u32::MAX), 0xdead_beef);
        assert_eq!((word >> EXEC_INODE_STATE_ARMED_SHIFT) & 1, 1);
        assert_eq!(
            ((word >> EXEC_INODE_STATE_MAGIC_SHIFT) & 0xff) as u8,
            EXEC_INODE_STATE_MAGIC
        );
        assert_eq!(
            ((word >> EXEC_INODE_STATE_ABI_SHIFT) & 0xff) as u8,
            EXEC_INODE_STATE_ABI
        );
        let disarmed = encode_state_word(1, false);
        assert_eq!((disarmed >> EXEC_INODE_STATE_ARMED_SHIFT) & 1, 0);
    }

    #[test]
    fn offsets_table_publishes_only_the_documented_indices() {
        let offsets = ExecInodeOffsets {
            task_mm_off: 800,
            task_size: 8192,
            mm_exe_file_off: 320,
            mm_size: 1024,
            file_f_inode_off: 192,
            inode_i_ino_off: 512,
            inode_i_sb_off: 320,
            super_s_dev_off: 128,
            file_size: 256,
            inode_size: 600,
            super_size: 256,
        };
        let table = encode_offsets_table(&offsets);
        assert_eq!(
            table[EXEC_INODE_OFF_MAGIC as usize],
            EXEC_INODE_OFFSETS_MAGIC
        );
        assert_eq!(table[EXEC_INODE_OFF_ABI as usize], EXEC_INODE_OFFSETS_ABI);
        assert_eq!(table[EXEC_INODE_OFF_TASK_MM as usize], 800);
        assert_eq!(table[EXEC_INODE_OFF_MM_EXE_FILE as usize], 320);
        assert_eq!(table[EXEC_INODE_OFF_FILE_F_INODE as usize], 192);
        assert_eq!(table[EXEC_INODE_OFF_INODE_I_INO as usize], 512);
        assert_eq!(table[EXEC_INODE_OFF_INODE_I_SB as usize], 320);
        assert_eq!(table[EXEC_INODE_OFF_SUPER_S_DEV as usize], 128);
        assert_eq!(table[EXEC_INODE_OFF_TASK_SIZE as usize], 8192);
        assert_eq!(table[EXEC_INODE_OFF_MM_SIZE as usize], 1024);
        for index in
            gedefense_common::EXEC_INODE_OFF_RESERVED_FIRST..EXEC_INODE_OFFSETS_TABLE_LEN as u32
        {
            assert_eq!(table[index as usize], 0, "reserved index {index}");
        }
        assert!(offsets.task_size <= gedefense_common::EXEC_INODE_MAX_STRUCT_SIZE);
    }

    #[test]
    fn event_text_is_bounded_and_uses_the_shared_wire_order() {
        for action in [
            EXEC_INODE_ACTION_OBSERVED_MISMATCH,
            EXEC_INODE_ACTION_DENIED_UNTRUSTED,
            EXEC_INODE_ACTION_FALLBACK_COMM,
        ] {
            let text = encode_event_text(&sample_event(action));
            let fields: Vec<&str> = text.split(':').collect();
            assert_eq!(fields.len(), 9);
            assert_eq!(fields[0], "1700000000000000000");
            assert_eq!(fields[1], "4242");
            assert_eq!(fields[2], "4242");
            assert_eq!(fields[3], "1000");
            assert_eq!(fields[4], "8");
            assert_eq!(fields[5], "123456");
            assert_eq!(fields[6], "0");
            assert_eq!(fields[7], action.to_string().as_str());
            assert_eq!(fields[8], hex::encode(b"sshd"));
            assert!(text.len() <= 128);
        }
    }

    #[test]
    fn path_tokens_decode_plain_and_base64_and_reject_hostile_input() {
        assert_eq!(
            decode_path_token("/usr/bin/sudo").expect("plain path"),
            PathBuf::from("/usr/bin/sudo")
        );
        let encoded = URL_SAFE_NO_PAD.encode("/usr/bin/sudo");
        assert_eq!(
            decode_path_token(&encoded).expect("base64 path"),
            PathBuf::from("/usr/bin/sudo")
        );
        for hostile in [
            "",
            "relative/path",
            "../etc/passwd",
            "/usr/../etc/passwd",
            "/",
            "///",
            "aGVsbG8", // "hello": decodes but is not absolute
        ] {
            assert!(decode_path_token(hostile).is_err(), "{hostile:?}");
        }
        let with_nul = URL_SAFE_NO_PAD.encode(b"/usr/bin/\0sudo");
        assert!(decode_path_token(&with_nul).is_err());
        assert!(decode_path_token(&"A".repeat(MAX_EXEC_INODE_PATH_BYTES + 1)).is_err());
    }

    #[test]
    fn numeric_tokens_are_strict_and_bounded() {
        assert_eq!(parse_dev_token("8").expect("dev"), 8);
        assert_eq!(
            parse_ino_token("18446744073709551615").expect("ino"),
            u64::MAX
        );
        assert_eq!(parse_flags_token("7").expect("flags"), 7);
        assert_eq!(
            parse_flags_token("4").expect("flags"),
            EXEC_INODE_ALLOW_RANSOM_POOL_META
        );
        assert_eq!(parse_ttl_token("86400").expect("ttl"), 86_400);
        assert_eq!(parse_ttl_token("1").expect("ttl"), 1);
        for bad in ["", "0", "-1", "4294967296", " 8", "0x8"] {
            assert!(parse_dev_token(bad).is_err(), "dev {bad:?}");
        }
        for bad in ["", "0", "+5", "1e3"] {
            assert!(parse_ino_token(bad).is_err(), "ino {bad:?}");
        }
        for bad in ["", "0", "8", "4294967295"] {
            assert!(parse_flags_token(bad).is_err(), "flags {bad:?}");
        }
        for bad in ["", "0", "86401", "-1"] {
            assert!(parse_ttl_token(bad).is_err(), "ttl {bad:?}");
        }
    }

    #[test]
    fn trust_path_sanitisation_rejects_traversal_and_relative_paths() {
        for good in [
            "/usr/bin/sudo",
            "/usr/sbin/sshd",
            "/usr/lib/systemd/systemd",
        ] {
            assert!(validate_trust_path(Path::new(good)).is_ok(), "{good}");
        }
        for bad in ["", "sudo", "/usr/../bin/sudo", "/..", "/usr/bin/..", "//"] {
            assert!(validate_trust_path(Path::new(bad)).is_err(), "{bad:?}");
        }
    }

    /// Executes the real openat2 path resolution on a running Linux host (the
    /// unit-test host in CI is Linux; on Windows `cargo check` only typechecks
    /// this module). This is the direct verification that a resolved path yields
    /// exactly the `(st_dev low u32, st_ino)` identity the eBPF gate keys on.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_executable_identity_matches_the_descriptor_metadata_and_refuses_symlinks() {
        let known = Path::new("/usr/bin/env");
        let metadata = fs::symlink_metadata(known).expect("test host has /usr/bin/env");
        let (dev, ino) =
            resolve_executable_identity(known).expect("regular absolute path resolves");
        assert_eq!(u64::from(dev), metadata.dev() & u64::from(u32::MAX));
        assert_eq!(ino, metadata.ino());

        let directory = std::env::temp_dir();
        assert!(
            resolve_executable_identity(&directory).is_err(),
            "a directory must be refused"
        );

        let directory = directory.join(format!(
            "vgt-ap1-exec-inode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&directory).expect("create fixture directory");
        let target = directory.join("target");
        fs::write(&target, b"#!/bin/sh\n").expect("write fixture target");
        let link = directory.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("create fixture symlink");
        assert!(
            resolve_executable_identity(&link).is_err(),
            "RESOLVE_NO_SYMLINKS must refuse a symlinked executable path"
        );
        assert!(
            resolve_executable_identity(&directory.join("missing")).is_err(),
            "a missing path must be refused"
        );
        let _ = fs::remove_dir_all(&directory);
    }
}
