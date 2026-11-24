#[cfg(test)]
mod tests {
    //! V6.3.0 AP-5 core-side unit tests: the bounded BTF/tracefs parsers, the
    //! package-database index, the session sample and the baseline content
    //! hashing. The whole module is Linux-test-only because the production path
    //! resolver uses `openat2`; `cargo check` (the Windows gate) only typechecks
    //! it against the Linux musl target.

    use super::super::*;
    use std::io::Write as _;

    // -- synthetic vmlinux BTF ------------------------------------------------

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
            let offset = u32::try_from(self.strings.len()).unwrap_or(u32::MAX);
            self.strings.extend_from_slice(name.as_bytes());
            self.strings.push(0);
            offset
        }

        fn type_entry(
            &mut self,
            name_off: u32,
            kind: u8,
            vlen: u16,
            value: u32,
            extra: &[u8],
        ) -> u32 {
            let mut ty = Vec::new();
            ty.extend_from_slice(&name_off.to_le_bytes());
            let info = (u32::from(kind) << 24) | u32::from(vlen);
            ty.extend_from_slice(&info.to_le_bytes());
            ty.extend_from_slice(&value.to_le_bytes());
            ty.extend_from_slice(extra);
            self.types.push(ty);
            u32::try_from(self.types.len()).unwrap_or(u32::MAX)
        }

        fn struct_ty(&mut self, name: &str, size: u32, members: &[(&str, u32)]) -> u32 {
            let name_off = self.name(name);
            let mut extra = Vec::new();
            for (member, offset) in members {
                let member_off = self.name(member);
                // BTF encodes a member offset in bits; the fixture API speaks
                // bytes. Encoding bytes here would make the production parser
                // (which divides by 8) resolve every member as misaligned.
                let bit_offset = offset.saturating_mul(8);
                extra.extend_from_slice(&member_off.to_le_bytes());
                extra.extend_from_slice(&1u32.to_le_bytes());
                extra.extend_from_slice(&bit_offset.to_le_bytes());
            }
            self.type_entry(name_off, KIND_STRUCT, members.len() as u16, size, &extra)
        }

        fn func_proto(&mut self, params: u16) -> u32 {
            let mut extra = Vec::new();
            for _ in 0..params {
                extra.extend_from_slice(&0u32.to_le_bytes());
                extra.extend_from_slice(&1u32.to_le_bytes());
            }
            self.type_entry(0, KIND_FUNC_PROTO, params, 0, &extra)
        }

        fn func(&mut self, name: &str, proto: u32) -> u32 {
            let name_off = self.name(name);
            self.type_entry(name_off, KIND_FUNC, 0, proto, &[])
        }

        fn finish(&self) -> Vec<u8> {
            let header_len = PERSIST_BTF_HEADER_BYTES as u32;
            let type_bytes: Vec<u8> = self.types.iter().flatten().copied().collect();
            let mut image = Vec::new();
            image.extend_from_slice(&PERSIST_BTF_MAGIC.to_le_bytes());
            image.push(PERSIST_BTF_VERSION);
            image.push(0);
            image.extend_from_slice(&header_len.to_le_bytes());
            image.extend_from_slice(&0u32.to_le_bytes());
            image.extend_from_slice(&(type_bytes.len() as u32).to_le_bytes());
            image.extend_from_slice(&(type_bytes.len() as u32).to_le_bytes());
            image.extend_from_slice(&(self.strings.len() as u32).to_le_bytes());
            image.extend_from_slice(&type_bytes);
            image.extend_from_slice(&self.strings);
            image
        }
    }

    fn ap5_btf_fixture() -> BtfFixture {
        let mut fixture = BtfFixture::new();
        fixture.struct_ty(
            "file",
            64,
            &[("f_inode", 8), ("f_flags", 16), ("f_path", 24)],
        );
        fixture.struct_ty("path", 16, &[("dentry", 0)]);
        fixture.struct_ty("inode", 64, &[("i_ino", 8), ("i_sb", 16), ("i_mode", 24)]);
        fixture.struct_ty("super_block", 128, &[("s_dev", 64)]);
        fixture.struct_ty("dentry", 32, &[("d_parent", 8), ("d_inode", 16)]);
        fixture.struct_ty("task_struct", 256, &[("pid", 16), ("tgid", 20), ("mm", 24)]);
        fixture.struct_ty("mm_struct", 64, &[("exe_file", 8)]);
        let file_open = fixture.func_proto(PERSIST_FILE_OPEN_NARGS_EXPECTED as u16);
        fixture.func("bpf_lsm_file_open", file_open);
        let mmap = fixture.func_proto(4);
        fixture.func("bpf_lsm_mmap_file", mmap);
        let ptrace = fixture.func_proto(PERSIST_PTRACE_NARGS_EXPECTED as u16);
        fixture.func("bpf_lsm_ptrace_access_check", ptrace);
        fixture
    }

    #[test]
    fn btf_parser_resolves_the_ap5_members_and_hook_arities() {
        let image = ap5_btf_fixture().finish();
        let facts = parse_persistence_btf(&image).expect("synthetic BTF must parse");
        assert_eq!(facts.func_nargs.get("bpf_lsm_file_open"), Some(&1));
        assert_eq!(facts.func_nargs.get("bpf_lsm_mmap_file"), Some(&4));
        assert_eq!(
            facts.func_nargs.get("bpf_lsm_ptrace_access_check"),
            Some(&2)
        );
        assert_eq!(btf_member(&facts, "file", "f_inode", 8, 8), 8);
        assert_eq!(btf_member(&facts, "file", "f_flags", 4, 4), 16);
        assert_eq!(btf_member(&facts, "inode", "i_ino", 8, 8), 8);
        assert_eq!(btf_member(&facts, "inode", "i_sb", 8, 8), 16);
        assert_eq!(btf_member(&facts, "super_block", "s_dev", 4, 4), 64);
        assert_eq!(btf_member(&facts, "dentry", "d_parent", 8, 8), 8);
        assert_eq!(btf_member(&facts, "dentry", "d_inode", 8, 8), 16);
        assert_eq!(btf_member(&facts, "task_struct", "pid", 4, 4), 16);
        assert_eq!(btf_member(&facts, "task_struct", "tgid", 4, 4), 20);
        assert_eq!(btf_member(&facts, "task_struct", "mm", 8, 8), 24);
        assert_eq!(btf_member(&facts, "mm_struct", "exe_file", 8, 8), 8);
        // `file.f_path.dentry` is an embedded struct: the resolver adds both
        // member offsets instead of guessing a dotted member name.
        assert_eq!(
            resolve_nested_member(&facts, "file", "f_path", "path", "dentry"),
            24
        );
        // A field outside the structure size, a misaligned pointer and an unknown
        // struct are all unresolved (`u32::MAX`), never guessed.
        assert_eq!(btf_member(&facts, "file", "f_inode", 8, 128), u32::MAX);
        assert_eq!(btf_member(&facts, "inode", "i_mode", 2, 2), 24);
        assert_eq!(btf_member(&facts, "missing_struct", "x", 4, 4), u32::MAX);
    }

    #[test]
    fn btf_parser_rejects_structurally_impossible_images() {
        let mut image = ap5_btf_fixture().finish();
        image[0] ^= 0xff;
        assert!(parse_persistence_btf(&image).is_err());
        let mut image = ap5_btf_fixture().finish();
        image[2] = 9;
        assert!(parse_persistence_btf(&image).is_err());
        let image = ap5_btf_fixture().finish();
        assert!(parse_persistence_btf(&image[..16]).is_err());
        let image = ap5_btf_fixture().finish();
        assert!(parse_persistence_btf(&image[..image.len() - 8]).is_err());
    }

    // -- tracefs format -------------------------------------------------------

    #[test]
    fn tracepoint_format_parser_reads_pid_and_target_pid() {
        let format = "\
field:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
field:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;
field:int common_pid;\toffset:4;\tsize:4;\tsigned:1;
field:pid_t pid;\toffset:16;\tsize:4;\tsigned:1;
field:pid_t target_pid;\toffset:20;\tsize:4;\tsigned:1;
field:unsigned long vec;\toffset:24;\tsize:8;\tsigned:0;
field:unsigned long flags;\toffset:40;\tsize:8;\tsigned:0;
";
        assert_eq!(parse_tracepoint_format(format), Some((16, 20, 48)));
        // Missing target field: degrade (no offsets) instead of guessing.
        let without_target = format.replace("field:pid_t target_pid;", "field:pid_t other;");
        assert_eq!(parse_tracepoint_format(&without_target), None);
        // A duplicate pid slot cannot describe the ABI.
        let duplicate = format.replace("target_pid", "pid");
        assert_eq!(parse_tracepoint_format(&duplicate), None);
        // Structurally impossible offsets are refused.
        let bogus = format
            .replace("offset:16;", "offset:24;")
            .replace("offset:20;", "offset:1400;");
        assert_eq!(parse_tracepoint_format(&bogus), None);
        assert_eq!(parse_tracepoint_format("not a tracefs format"), None);
    }

    // -- package database -----------------------------------------------------

    #[test]
    fn retain_package_path_bounds_the_index_to_libraries_and_linker_files() {
        assert!(retain_package_path("/usr/lib/libc.so.6"));
        assert!(retain_package_path("/lib/x86_64-linux-gnu/libselinux.so.1"));
        assert!(retain_package_path("/etc/ld.so.conf"));
        assert!(retain_package_path("/etc/pam.d/sshd"));
        assert!(!retain_package_path("/usr/share/doc/libc6/changelog"));
        assert!(!retain_package_path("relative/path"));
        assert!(!retain_package_path(""));
        assert!(!retain_package_path(&format!("/{}", "a".repeat(5000))));
    }

    #[test]
    fn package_index_parses_dpkg_and_pacman_without_executing_anything() {
        let base = std::env::temp_dir().join(format!(
            "vgt-ap5-pkgdb-{}-{}",
            std::process::id(),
            unix_millis_now()
        ));
        let dpkg_dir = base.join("dpkg-info");
        let pacman_dir = base.join("pacman-local");
        std::fs::create_dir_all(&dpkg_dir).expect("create dpkg fixture");
        std::fs::create_dir_all(pacman_dir.join("bash-5.2.026-2")).expect("create pacman fixture");
        // The listing paths are deliberately unique absolute paths that do not
        // exist on the test host: the reverse inode index must then stay empty
        // and `ready` must be false deterministically (a real host `/etc/ld.so.conf`
        // would otherwise make this test depend on the machine it runs on).
        let unique = format!(
            "vgt-ap5-fixture-{}-{}",
            std::process::id(),
            unix_millis_now()
        );
        let libc_so = format!("/usr/lib/{unique}-libc.so.6");
        let ld_so_conf = format!("/etc/ld.so.conf.{unique}");
        let bash_so_relative = format!("usr/lib/{unique}-libbash.so.5.2");
        let bash_so = format!("/{bash_so_relative}");
        std::fs::write(
            dpkg_dir.join("libc6_2.39-0ubuntu8.list"),
            format!("{libc_so}\n/usr/share/doc/libc6/changelog\n{ld_so_conf}\n"),
        )
        .expect("write dpkg list");
        std::fs::write(
            pacman_dir.join("bash-5.2.026-2").join("files"),
            format!("usr/\nusr/lib/\n{bash_so_relative}\nusr/bin/bash\n"),
        )
        .expect("write pacman files");
        let index = PackageIndex::load_from(&dpkg_dir, &pacman_dir);
        assert_eq!(index.format, "both");
        assert_eq!(index.owned_paths.len(), 3);
        assert_eq!(
            index.owned_paths.get(&libc_so).map(String::as_str),
            Some("libc6_2.39-0ubuntu8")
        );
        assert_eq!(
            index.owned_paths.get(&ld_so_conf).map(String::as_str),
            Some("libc6_2.39-0ubuntu8")
        );
        assert_eq!(
            index.owned_paths.get(&bash_so).map(String::as_str),
            Some("bash")
        );
        assert!(!index.owned_paths.contains_key("/usr/bin/bash"));
        assert!(
            !index.ready,
            "the fixture's unique absolute paths do not exist on the test host: no ownership claim"
        );
        // Missing databases are the documented `unsupported` state.
        let missing =
            PackageIndex::load_from(&base.join("missing-dpkg"), &base.join("missing-pacman"));
        assert_eq!(missing.format, "unsupported");
        assert!(!missing.ready);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn pacman_package_names_strip_version_and_release() {
        // Pacman local directories are `<name>-<version>-<release>`; hyphens
        // inside the package name must survive while the last two components
        // (version + release) are stripped from the end.
        assert_eq!(pacman_package_name("bash-5.2.026-2"), "bash");
        assert_eq!(pacman_package_name("linux-6.8.0.arch1-1"), "linux");
        assert_eq!(
            pacman_package_name("python-requests-2.31.0-2"),
            "python-requests"
        );
        assert_eq!(
            pacman_package_name("linux-firmware-20240219.abcdef-1"),
            "linux-firmware"
        );
        assert_eq!(pacman_package_name("plain"), "plain");
    }

    // -- sessions -------------------------------------------------------------

    #[test]
    fn session_snapshot_counts_only_active_local_user_sessions() {
        let base = std::env::temp_dir().join(format!(
            "vgt-ap5-sessions-{}-{}",
            std::process::id(),
            unix_millis_now()
        ));
        let sessions = base.join("sessions");
        let seats = base.join("seats");
        std::fs::create_dir_all(&sessions).expect("create sessions fixture");
        std::fs::create_dir_all(&seats).expect("create seats fixture");
        std::fs::write(
            sessions.join("c1"),
            "UID=1000\nACTIVE=yes\nSTATE=active\nCLASS=user\nSEAT=seat0\nTYPE=tty\n",
        )
        .expect("write active session");
        std::fs::write(
            sessions.join("c2"),
            "UID=1001\nACTIVE=0\nSTATE=online\nCLASS=user\nSEAT=seat0\nTYPE=x11\n",
        )
        .expect("write inactive session");
        std::fs::write(
            sessions.join("c3"),
            "UID=0\nACTIVE=1\nSTATE=active\nCLASS=manager\nSEAT=\nTYPE=tty\n",
        )
        .expect("write manager session");
        // The real systemd-logind format on Ubuntu 24.04: `ACTIVE=1`, no SEAT
        // field for a bare TTY session. The parser must not downgrade it.
        std::fs::write(
            sessions.join("c4"),
            "UID=1002\nACTIVE=1\nSTATE=active\nTYPE=tty\nCLASS=user\n",
        )
        .expect("write real-format session");
        // A user session with neither a seat nor a local session type is not a
        // desktop-session owner: it must stay inactive.
        std::fs::write(
            sessions.join("c5"),
            "UID=1003\nACTIVE=1\nSTATE=active\nTYPE=unspecified\nCLASS=user\n",
        )
        .expect("write remote session");
        std::fs::write(sessions.join("c1.ref"), "UID=1000\nACTIVE=1\n").expect("write ref");
        std::fs::create_dir_all(seats.join("seat0")).expect("create seat");
        let snapshot = read_session_snapshot(&sessions, &seats);
        assert!(snapshot.parsed);
        assert_eq!(snapshot.total, 5);
        assert_eq!(snapshot.active, 2);
        assert_eq!(snapshot.inactive, 3);
        assert!(snapshot.active_uids.contains(&1000));
        assert!(snapshot.active_uids.contains(&1002));
        assert!(!snapshot.active_uids.contains(&1001));
        assert!(!snapshot.active_uids.contains(&1003));
        assert_eq!(snapshot.to_status_value(), "5/2/3");
        let missing = read_session_snapshot(&base.join("missing"), &base.join("missing"));
        assert!(!missing.parsed);
        assert_eq!(missing.to_status_value(), "0/0/0");
        let _ = std::fs::remove_dir_all(&base);
    }

    // -- baseline hashing -----------------------------------------------------

    #[test]
    fn baseline_hash_is_bounded_and_detects_content_changes() {
        let base = std::env::temp_dir().join(format!(
            "vgt-ap5-baseline-{}-{}",
            std::process::id(),
            unix_millis_now()
        ));
        std::fs::create_dir_all(&base).expect("create fixture dir");
        let watched = base.join("ld.so.preload");
        let mut file = std::fs::File::create(&watched).expect("create watched file");
        file.write_all(b"first").expect("write watched file");
        drop(file);
        let mut budget = MAX_BASELINE_TOTAL_BYTES;
        let first = hash_watch_file(&watched, &mut budget).expect("hash first content");
        assert_eq!(first.len(), 32);
        std::fs::write(&watched, b"second").expect("rewrite watched file");
        let mut budget = MAX_BASELINE_TOTAL_BYTES;
        let second = hash_watch_file(&watched, &mut budget).expect("hash second content");
        assert_ne!(first, second, "content change must change the SHA-256");
        assert!(budget < MAX_BASELINE_TOTAL_BYTES);
        // A zero budget must refuse instead of hashing unbounded data.
        let mut exhausted = 0u64;
        assert!(hash_watch_file(&watched, &mut exhausted).is_err());
        // A directory is not a hashable watched file.
        let mut budget = MAX_BASELINE_TOTAL_BYTES;
        assert!(hash_watch_file(&base, &mut budget).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    // -- event text -----------------------------------------------------------

    #[test]
    fn event_text_record_has_twelve_bounded_fields() {
        let event = PersistenceEvent {
            ts_ns: 1_700_000_000_000_000_000,
            ino: 123_456,
            dev: 8,
            pid: 4242,
            tgid: 4241,
            uid: 1000,
            detail_code: 2,
            class: PERSIST_CLASS_PAM,
            kind: gedefense_common::PERSIST_KIND_INTEGRITY_WRITE,
            action: PERSIST_ACTION_AUDIT,
            reserved: 0,
            comm: *b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
            detail: [0u8; 8],
        };
        let text = encode_event_text(&event);
        let fields: Vec<&str> = text.split(':').collect();
        assert_eq!(fields.len(), 12);
        assert_eq!(fields[0], "1700000000000000000");
        assert_eq!(fields[1], "4242");
        assert_eq!(fields[2], "4241");
        assert_eq!(fields[3], "1000");
        assert_eq!(fields[4], "5");
        assert_eq!(fields[5], "1");
        assert_eq!(fields[6], "1");
        assert_eq!(fields[7], "2");
        assert_eq!(fields[8], "8");
        assert_eq!(fields[9], "123456");
        assert_eq!(fields[10], hex::encode(b"bash"));
        assert_eq!(fields[11], "");
        assert!(text.len() <= 320);
        // The core-side text encoder is the inverse-direction counterpart of the
        // Go parser's 12-field contract; roundtrip the wire record through the
        // shared decoder to prove the userspace producer uses the same layout.
        let raw = encode_persistence_event(&event);
        assert_eq!(decode_persistence_event(&raw), Some(event));
    }

    #[test]
    fn drift_events_use_the_shared_userspace_encoder() {
        let event = PersistenceEvent {
            ts_ns: 1_700_000_000_000_000_000,
            ino: 42,
            dev: 8,
            pid: 99,
            tgid: 99,
            uid: 0,
            detail_code: PERSIST_DRIFT_APPEARED,
            class: PERSIST_CLASS_LD_PRELOAD,
            kind: PERSIST_KIND_DRIFT,
            action: PERSIST_ACTION_AUDIT,
            reserved: 0,
            comm: *b"gedefense-core\0\0",
            detail: [0u8; 8],
        };
        let raw = encode_persistence_event(&event);
        let decoded = decode_persistence_event(&raw).expect("userspace drift record must decode");
        assert_eq!(decoded, event);
        assert_eq!(decoded.detail_code, PERSIST_DRIFT_APPEARED);
    }

    #[test]
    fn status_attached_bitmask_is_closed_and_bounded() {
        // Every status bit the Go parser accepts is defined here and no bit is
        // set twice; the mask must stay below the documented ceiling.
        let mask = PERSIST_HOOK_FILE_OPEN
            | PERSIST_HOOK_MMAP
            | PERSIST_HOOK_PTRACE
            | PERSIST_HOOK_READV
            | PERSIST_HOOK_WRITEV
            | PERSIST_STATUS_IDENTITY_OFFSETS
            | PERSIST_STATUS_PKGDB_READY
            | PERSIST_STATUS_READV_OFFSETS
            | PERSIST_STATUS_WRITEV_OFFSETS
            | PERSIST_STATUS_READ_FAILURES
            | PERSIST_STATUS_SESSIONS_KNOWN;
        assert_eq!(mask, (1 << 11) - 1);
        assert_eq!(PERSIST_IDLEHINT_UNAVAILABLE, "unavailable");
    }
}
