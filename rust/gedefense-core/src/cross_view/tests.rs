#[cfg(test)]
mod tests {
    use super::super::*;
use super::super::modtrace::*;

    fn encode(event: &CrossViewEvent) -> [u8; 64] {
        let mut raw = [0u8; 64];
        raw[0..8].copy_from_slice(&event.ts_ns.to_ne_bytes());
        raw[8..16].copy_from_slice(&event.ino.to_ne_bytes());
        raw[16..20].copy_from_slice(&event.pid.to_ne_bytes());
        raw[20..24].copy_from_slice(&event.uid.to_ne_bytes());
        raw[24..28].copy_from_slice(&event.dev.to_ne_bytes());
        raw[28..32].copy_from_slice(&event.detail_code.to_ne_bytes());
        raw[32] = event.domain;
        raw[33] = event.kind;
        raw[34] = event.severity;
        raw[35] = event.action;
        raw[36..52].copy_from_slice(&event.comm);
        raw[52..64].copy_from_slice(&event.reserved);
        raw
    }

    fn sample_event() -> CrossViewEvent {
        CrossViewEvent {
            ts_ns: 1_700_000_000_000_000_000,
            ino: 42,
            pid: 4242,
            uid: 1000,
            dev: 0,
            detail_code: CROSS_VIEW_DETAIL_TAP_FILTER,
            domain: CROSS_VIEW_DOMAIN_NETLINK_FILTER,
            kind: CROSS_VIEW_KIND_RAW_TAP_FILTER,
            severity: CROSS_VIEW_SEVERITY_MEDIUM,
            action: CROSS_VIEW_ACTION_AUDIT,
            comm: bounded_comm("dhclient"),
            reserved: [0u8; 12],
        }
    }

    #[test]
    fn text_record_has_ten_fields_and_no_paths() {
        let record = encode_event_text(&sample_event());
        assert_eq!(record.split(':').count(), 10);
        assert_eq!(
            record,
            "1700000000000000000:4242:1000:0:42:7:12:2:2:6468636c69656e74"
        );
        assert!(!record.contains('/'));
        // Worst-case record width stays inside the bounded drain budget.
        let worst = "18446744073709551615:2147483647:4294967295:4294967295:18446744073709551615:8:12:4:4294967295:00112233445566778899aabbccddeeff";
        assert!(worst.len() <= 220);
        assert!(worst.split(':').count() == 10);
    }

    #[test]
    fn suspicious_executable_paths_match_the_documented_roots() {
        for path in [
            "/tmp/bpfd",
            "/var/tmp/.x",
            "/dev/shm/x",
            "/home/user/implant",
            "/run/user/0/payload",
            "/var/run/user/0/payload",
            "/usr/bin/tool (deleted)",
        ] {
            assert!(suspicious_executable_path(path), "{path}");
        }
        for path in [
            "",
            "/usr/bin/tcpdump",
            "/usr/sbin/suricata",
            "/opt/vendor/bin/tool",
            "/proc/self/exe",
            "relative/path",
        ] {
            assert!(!suspicious_executable_path(path), "{path}");
        }
    }

    #[test]
    fn fnv_identity_is_stable_and_distinguishes_paths() {
        assert_eq!(fnv64(b""), CROSS_VIEW_FNV64_OFFSET);
        let first = fnv64(b"/usr/lib/libc.so.6");
        assert_eq!(first, fnv64(b"/usr/lib/libc.so.6"));
        assert_ne!(first, fnv64(b"/usr/lib/libc.so.7"));
        assert_ne!(fnv64(b"a"), fnv64(b"b"));
    }

    #[test]
    fn object_name_candidates_only_accept_the_kernel_charset() {
        let mut info = [0u8; INFO_BUF_BYTES];
        info[PROG_INFO_NAME_OFF..PROG_INFO_NAME_OFF + 8].copy_from_slice(b"hide_pro");
        assert_eq!(
            object_name_str(&info_name_at(&info, PROG_INFO_NAME_OFF)),
            "hide_pro"
        );
        let mut map_info = [0u8; INFO_BUF_BYTES];
        map_info[MAP_INFO_NAME_OFF..MAP_INFO_NAME_OFF + 9].copy_from_slice(b"hidden_pi");
        assert_eq!(
            object_name_str(&info_name_at(&map_info, MAP_INFO_NAME_OFF)),
            "hidden_pi"
        );
        // A numeric neighbour (e.g. a btf id) can be charset-valid on its own,
        // which is exactly why the typed info struct name offset is used for
        // programs and the map offset for maps. It must never be used as a map
        // name (the map-info offset of these bytes is empty).
        let mut btf_id = [0u8; INFO_BUF_BYTES];
        btf_id[PROG_INFO_NAME_OFF..PROG_INFO_NAME_OFF + 4].copy_from_slice(&[0x64, 0, 0, 0]);
        assert_eq!(
            object_name_str(&info_name_at(&btf_id, PROG_INFO_NAME_OFF)),
            "d"
        );
        assert_eq!(
            object_name_str(&info_name_at(&btf_id, MAP_INFO_NAME_OFF)),
            ""
        );
        // Pinned self-defence objects are maps, so the map offset wins.
        let mut map_like = [0u8; INFO_BUF_BYTES];
        map_like[MAP_INFO_NAME_OFF..MAP_INFO_NAME_OFF + 10].copy_from_slice(b"hidden_map");
        map_like[PROG_INFO_NAME_OFF..PROG_INFO_NAME_OFF + 4].copy_from_slice(&[0x64, 0, 0, 0]);
        let pinned = ObjectInfo {
            object_type: 2,
            object_id: 11,
            prog_name: info_name_at(&map_like, PROG_INFO_NAME_OFF),
            map_name: info_name_at(&map_like, MAP_INFO_NAME_OFF),
            link_prog_id: None,
        };
        assert_eq!(
            pinned_object_candidate_name(&pinned).as_deref(),
            Some("hidden_map")
        );
        // Slash and space are outside the kernel object-name charset.
        let mut invalid = [0u8; INFO_BUF_BYTES];
        invalid[PROG_INFO_NAME_OFF..PROG_INFO_NAME_OFF + 4].copy_from_slice(b"a/b\0");
        assert_eq!(
            object_name_str(&info_name_at(&invalid, PROG_INFO_NAME_OFF)),
            ""
        );
        // A full 16-byte non-NUL field is not a valid object name.
        let full = [b'x'; INFO_BUF_BYTES];
        assert_eq!(
            object_name_str(&info_name_at(&full, PROG_INFO_NAME_OFF)),
            ""
        );
    }

    #[test]
    fn suspicious_object_names_cover_the_guide_markers() {
        for name in [
            "hidden_names",
            "hidden_pids",
            "hidden_inodes",
            "x_hide_y",
            "masq_map",
            "ROOTKIT",
        ] {
            assert!(is_suspicious_object_name(name), "{name}");
        }
        for name in [
            "",
            "EXEC_EVENTS",
            "TITAN_EXEC_STATE",
            "a_very_long_object_name",
        ] {
            assert!(!is_suspicious_object_name(name), "{name}");
        }
        assert!(ascii_contains_ci(b"Hidden_Pids", b"hidden"));
        assert!(!ascii_contains_ci(b"short", b"hidden"));
    }

    #[test]
    fn proc_net_tables_parse_strictly() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 1831 1 0000000000000000 100 0 0 10 5\n\
                   1: 0100007F:98D1 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 10468 1 0000000000000000 100 0 0 10 0\n";
        let inodes = parse_proc_net_inodes(tcp, PROC_NET_INET_INODE_INDEX).expect("tcp table");
        assert!(inodes.contains(&1831));
        assert!(inodes.contains(&10468));
        assert_eq!(inodes.len(), 2);
        let packet = "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n\
                      ffff888000000000 3      3    0003   2     1 0      1000   12345\n";
        let inodes =
            parse_proc_net_inodes(packet, PROC_NET_PACKET_INODE_INDEX).expect("packet table");
        assert_eq!(inodes.len(), 1);
        assert!(inodes.contains(&12345));
        // Strict rejection: short line or non-numeric inode invalidates the view.
        assert_eq!(
            parse_proc_net_inodes(
                "header line that is not skipped\n0: only_three\n",
                PROC_NET_INET_INODE_INDEX
            ),
            Err(ProcNetError::Unreadable)
        );
        assert_eq!(
            parse_proc_net_inodes(
                "0: a b c d e f g h not-a-number\n",
                PROC_NET_INET_INODE_INDEX
            ),
            Err(ProcNetError::Unreadable)
        );
        assert!(parse_proc_net_inodes("", PROC_NET_INET_INODE_INDEX).is_ok());
    }

    #[test]
    fn maps_paths_and_library_mappings_are_bounded() {
        let maps = "\
7f0000000000-7f0000100000 r-xp 00000000 08:01 1234 /usr/lib/x86_64-linux-gnu/libc.so.6\n\
7f0000100000-7f0000200000 r-xp 00000000 08:01 1235 /opt/vendor/lib/libx.so.1\n\
7f0000200000-7f0000300000 r-xp 00000000 08:01 1236 /tmp/a b/lib weird.so.2 (deleted)\n\
7f0000300000-7f0000400000 rw-p 00000000 00:00 0 [heap]\n\
7f0000400000-7f0000500000 r-xp 00000000 08:01 1237 /usr/lib/x86_64-linux-gnu/libc.so.6\n";
        let mappings = library_mappings(maps);
        // The parser is raw: the same library can be mapped in several regions
        // (the scan dedupes by path hash before reporting).
        assert_eq!(mappings.len(), 4);
        assert_eq!(mappings[0].0, "/usr/lib/x86_64-linux-gnu/libc.so.6");
        assert!(!mappings[0].1);
        assert_eq!(mappings[1].0, "/opt/vendor/lib/libx.so.1");
        assert_eq!(mappings[2].0, "/tmp/a b/lib weird.so.2");
        assert!(mappings[2].1);
        assert_eq!(mappings[3].0, "/usr/lib/x86_64-linux-gnu/libc.so.6");
        assert_eq!(
            maps_line_path("7f0-7f1 r-xp 00000000 08:01 1 /usr/lib/a.so"),
            Some("/usr/lib/a.so")
        );
        assert_eq!(maps_line_path("too short"), None);
        assert_eq!(maps_line_path("7f0-7f1 r-xp 00000000 08:01 1 "), None);
        assert!(system_library_path("/usr/lib/libc.so.6"));
        assert!(system_library_path("/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(!system_library_path("/usr/local/lib/libcustom.so"));
        assert!(!system_library_path("/home/user/libfoo.so"));
        assert!(!system_library_path("/tmp/libfoo.so"));
    }

    #[test]
    fn ftrace_enabled_lines_expose_only_the_function_name() {
        assert_eq!(
            ftrace_line_function("tcp4_seq_show\t(1)   tramp: x (y)"),
            Some("tcp4_seq_show")
        );
        assert_eq!(
            ftrace_line_function("__x64_sys_getdents64+0x0/0x30"),
            Some("__x64_sys_getdents64")
        );
        assert_eq!(
            ftrace_line_function("#### all functions enabled ####"),
            None
        );
        assert_eq!(ftrace_line_function("   "), None);
        assert_eq!(ftrace_line_function(""), None);
        assert!(FTRACE_SENSITIVE_TARGETS.contains(&"__x64_sys_getdents64"));
        assert!(FTRACE_SENSITIVE_TARGETS.contains(&"sk_attach_filter"));
        assert!(FTRACE_SENSITIVE_TARGETS.contains(&BPF_LSM_BPF_PROG_SYMBOL));
        assert_eq!(
            parse_proc_status_tgid("Name:\tgedefense-contr\nTgid:\t1425\nPid:\t1437\n"),
            Some(1425)
        );
        assert_eq!(parse_proc_status_tgid("Name:\tinit\nTgid:\t0\n"), None);
    }

    #[test]
    fn inet_diag_payload_decodes_inode_and_uid() {
        let mut body = [0u8; INET_DIAG_MSG_BYTES];
        body[0] = AF_INET_U8;
        body[1] = 0x0a; // TCP_LISTEN
        body[INET_DIAG_MSG_UID_OFF..INET_DIAG_MSG_UID_OFF + 4]
            .copy_from_slice(&1000u32.to_ne_bytes());
        body[INET_DIAG_MSG_INODE_OFF..INET_DIAG_MSG_INODE_OFF + 4]
            .copy_from_slice(&12345u32.to_ne_bytes());
        let socket = parse_inet_diag_msg(&body).expect("valid inet_diag_msg");
        assert_eq!(socket.inode, 12345);
        assert_eq!(socket.uid, 1000);
        let mut zero = body;
        zero[INET_DIAG_MSG_INODE_OFF..INET_DIAG_MSG_INODE_OFF + 4]
            .copy_from_slice(&0u32.to_ne_bytes());
        assert!(parse_inet_diag_msg(&zero).is_none());
        assert!(parse_inet_diag_msg(&body[..72 - 1]).is_none());
    }

    #[test]
    fn packet_diag_payload_decodes_uid_and_filter_attribute() {
        fn attr(buffer: &mut Vec<u8>, kind: u16, value: &[u8]) {
            let length = 4 + value.len();
            buffer.extend_from_slice(&(length as u16).to_ne_bytes());
            buffer.extend_from_slice(&kind.to_ne_bytes());
            buffer.extend_from_slice(value);
            while buffer.len() % 4 != 0 {
                buffer.push(0);
            }
        }
        let mut body = vec![0u8; PACKET_DIAG_MSG_BYTES];
        body[0] = AF_PACKET_U8;
        body[PACKET_DIAG_MSG_INODE_OFF..PACKET_DIAG_MSG_INODE_OFF + 4]
            .copy_from_slice(&777u32.to_ne_bytes());
        attr(&mut body, PACKET_DIAG_UID, &0u32.to_ne_bytes());
        attr(&mut body, PACKET_DIAG_FILTER, &[0u8; 8]);
        let socket = parse_packet_diag_msg(&body).expect("valid packet_diag_msg");
        assert_eq!(socket.inode, 777);
        assert_eq!(socket.uid, 0);
        assert!(socket.has_filter);
        // Without the FILTER attribute a plain packet socket is not a tap.
        let mut plain = vec![0u8; PACKET_DIAG_MSG_BYTES];
        plain[0] = AF_PACKET_U8;
        plain[PACKET_DIAG_MSG_INODE_OFF..PACKET_DIAG_MSG_INODE_OFF + 4]
            .copy_from_slice(&888u32.to_ne_bytes());
        let socket = parse_packet_diag_msg(&plain).expect("plain packet socket");
        assert!(!socket.has_filter);
        // A truncated attribute ends the parse safely.
        let mut truncated = body.clone();
        truncated.push(3);
        let _ = parse_packet_diag_msg(&truncated);
        assert!(parse_packet_diag_msg(&body[..4]).is_none());
    }

    #[test]
    fn pin_root_resolution_honours_the_cli_override_only_for_valid_roots() {
        assert_eq!(parse_pin_root_arg("gedefense-core\0--iface\0eth0"), None);
        assert_eq!(
            parse_pin_root_arg("gedefense-core\0--bpf-pin-root\0/sys/fs/bpf/custom\0"),
            Some("/sys/fs/bpf/custom".to_owned())
        );
        assert_eq!(
            parse_pin_root_arg("gedefense-core\0--bpf-pin-root=/custom/pins\0"),
            Some("/custom/pins".to_owned())
        );
        assert_eq!(
            parse_pin_root_arg("gedefense-core\0--bpf-pin-root\0relative\0"),
            None
        );
        assert_eq!(
            parse_pin_root_arg("gedefense-core\0--bpf-pin-root\0/a/../b\0"),
            None
        );
        assert_eq!(parse_pin_root_arg("gedefense-core\0--bpf-pin-root\0"), None);
        assert_eq!(
            validate_pin_root("/sys/fs/bpf/gedefense/"),
            Some("/sys/fs/bpf/gedefense".to_owned())
        );
        // Kernel bpf_map_info.name is NUL-terminated in 16 bytes (15 usable chars).
        assert!(pin_matches_kernel_object_name(
            "WORKER_CRASH_EVENTS",
            "WORKER_CRASH_EV"
        ));
        assert!(pin_matches_kernel_object_name(
            "TITAN_EXEC_POLICY",
            "TITAN_EXEC_POLI"
        ));
        assert!(pin_matches_kernel_object_name("EXEC_EVENTS", "EXEC_EVENTS"));
        assert!(!pin_matches_kernel_object_name(
            "TITAN_EXEC_POLICY",
            "EVIL_TAMPERED_M"
        ));
    }

    #[test]
    fn bounded_comm_is_printable_and_always_nul_padded() {
        let comm = bounded_comm("sshd-session");
        assert_eq!(&comm[..12], b"sshd-session");
        assert_eq!(comm[12], 0);
        let long = bounded_comm("a-very-long-comm-name");
        assert_eq!(long[15], 0);
        assert_eq!(long.len(), 16);
        let control = bounded_comm("bad\x1bname");
        assert!(!control.iter().any(|byte| *byte == 0x1b));
        let normalized = normalize_wire_comm(*b"bad\x1bname\0\0\0\0\0\0\0\0");
        assert!(normalized
            .iter()
            .all(|byte| (0x20..=0x7e).contains(byte) || *byte == 0));
        // Both producers must satisfy the shared common decoder.
        assert!(gedefense_common::decode_cross_view_event(&encode(&sample_event())).is_some());
        let long = CrossViewEvent {
            comm: bounded_comm("exactly-16-byte!!"),
            ..sample_event()
        };
        assert!(gedefense_common::decode_cross_view_event(&encode(&long)).is_some());
    }

    #[test]
    fn scan_outcome_reasons_and_degradation_are_bounded() {
        let mut outcome = ScanOutcome::new();
        assert!(outcome.bounds_ok);
        for token in ["a", "b", "c", "d", "e", "f", "g", "h", "a", "i"] {
            outcome.reason(token);
        }
        assert!(outcome.reasons.len() <= 8);
        assert_eq!(
            outcome
                .reasons
                .iter()
                .filter(|token| **token == "a")
                .count(),
            1
        );
        outcome.degrade("budget_exhausted");
        assert!(!outcome.bounds_ok);
        assert!(outcome.reasons.contains(&"budget_exhausted"));
    }

    #[test]
    fn uapi_constants_match_the_kernel_headers() {
        assert_eq!(BPF_CMD_OBJ_GET, 7);
        assert_eq!(BPF_CMD_PROG_GET_NEXT_ID, 11);
        assert_eq!(BPF_CMD_MAP_GET_NEXT_ID, 12);
        assert_eq!(BPF_CMD_PROG_GET_FD_BY_ID, 13);
        assert_eq!(BPF_CMD_MAP_GET_FD_BY_ID, 14);
        assert_eq!(BPF_CMD_OBJ_GET_INFO_BY_FD, 15);
        assert_eq!(BPF_CMD_LINK_GET_FD_BY_ID, 30);
        assert_eq!(BPF_CMD_LINK_GET_NEXT_ID, 31);
        assert_eq!(NETLINK_SOCK_DIAG, 4);
        assert_eq!(SOCK_DIAG_BY_FAMILY, 20);
        assert_eq!(NLM_F_REQUEST | NLM_F_DUMP, 0x301);
        assert_eq!(PACKET_SHOW_FILTER, 0x20);
        assert_eq!(TAINT_OOT_MODULE, 0x1000);
        assert_eq!(TAINT_UNSIGNED_MODULE, 0x2000);
        assert_eq!(TAINT_FORCED_MODULE, 0x2);
        // Inet diag offsets follow the UAPI struct, not a private layout.
        assert_eq!(INET_DIAG_MSG_UID_OFF, 64);
        assert_eq!(INET_DIAG_MSG_INODE_OFF, 68);
        assert_eq!(INET_DIAG_REQ_V2_BYTES, 56);
        assert_eq!(nlmsg_align(16), 16);
        assert_eq!(nlmsg_align(17), 20);
    }

    #[test]
    fn bpf_attr_helpers_are_bounds_checked() {
        let mut attr = BpfAttr::zeroed();
        attr.set_u32(ATTR_OBJ_ID_OFF, 4242);
        attr.set_u32(ATTR_NEXT_ID_OFF, 4243);
        assert_eq!(attr.next_id(), 4243);
        attr.set_u64(ATTR_INFO_PTR_OFF, 0x1122_3344_5566_7788);
        assert_eq!(read_u32(&attr.bytes, ATTR_NEXT_ID_OFF), Some(4243));
        // Out-of-range offsets are ignored instead of panicking.
        attr.set_u32(BPF_ATTR_BYTES - 2, 1);
        assert_eq!(read_u32(&attr.bytes, BPF_ATTR_BYTES - 2), None);
        assert_eq!(read_u16(&attr.bytes, BPF_ATTR_BYTES + 10), None);
        assert_eq!(read_i32(&attr.bytes, 0), Some(4242));
    }

    /// Real-system ABI smoke of the *actual* verifier views (not a mock): direct
    /// `NETLINK_SOCK_DIAG` inet/packet dumps, a live filtered AF_PACKET tap, and
    /// the `BPF_*_GET_NEXT_ID`/`GET_FD_BY_ID` enumeration.
    ///
    /// Ignored by default because it needs Linux root and a live kernel. WSL2
    /// (6.18) was used for the AP-3 verification run:
    /// `cargo +1.95.0 test -p gedefense-core -- --ignored ap3_real_system`.
    /// The test creates only one transient AF_PACKET socket (closed before it
    /// returns) and reads kernel surfaces; it never modifies system state.
    #[test]
    #[ignore = "real-system ABI smoke: needs Linux root and a live kernel; run explicitly with --ignored"]
    fn ap3_real_system_smoke_of_the_live_verifier_views() {
        use std::io::Read as _;
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            eprintln!("AP3 smoke SKIP: euid={euid} (needs root)");
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(10);

        // 1. NETLINK_SOCK_DIAG inet dumps (exactly the request layout the
        //    verifier sends: states=all, cookie=NOCOOKIE).
        let diag = NetlinkDiag::open().expect("root must be able to open NETLINK_SOCK_DIAG");
        for (label, family, protocol) in [
            ("tcp4", AF_INET_U8, IPPROTO_TCP_U8),
            ("tcp6", AF_INET6_U8, IPPROTO_TCP_U8),
            ("udp4", AF_INET_U8, IPPROTO_UDP_U8),
            ("udp6", AF_INET6_U8, IPPROTO_UDP_U8),
        ] {
            match diag.dump_inet(family, protocol) {
                Ok(sockets) => {
                    eprintln!("AP3 smoke inet_diag {label}: {} socket(s)", sockets.len())
                }
                Err(error) => eprintln!("AP3 smoke inet_diag {label}: honest degrade ({error:?})"),
            }
        }

        // 2. A live filtered AF_PACKET tap: prove the Rust packet_diag parser sees
        //    the PACKET_DIAG_FILTER attribute (the BPFDoor marker).
        #[repr(C)]
        struct SockFilter {
            code: u16,
            jt: u8,
            jf: u8,
            k: u32,
        }
        #[repr(C)]
        struct SockFprog {
            len: u16,
            filter: *const SockFilter,
        }
        const BPF_LD_W_ABS: u16 = 0x20;
        const BPF_RET_K: u16 = 0x06;
        const SO_ATTACH_FILTER_UAPI: i32 = 26;
        const ETH_P_ALL_BE: i32 = 0x0300; // htons(ETH_P_ALL)
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                ETH_P_ALL_BE,
            )
        };
        if raw_fd >= 0 {
            let filter = [
                SockFilter {
                    code: BPF_LD_W_ABS,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                SockFilter {
                    code: BPF_RET_K,
                    jt: 0,
                    jf: 0,
                    k: 0xffff_ffff,
                },
            ];
            let fprog = SockFprog {
                len: filter.len() as u16,
                filter: filter.as_ptr(),
            };
            let attached = unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::SOL_SOCKET,
                    SO_ATTACH_FILTER_UAPI,
                    (&fprog as *const SockFprog).cast::<libc::c_void>(),
                    core::mem::size_of::<SockFprog>() as libc::socklen_t,
                )
            } >= 0;
            if attached {
                let own_inode = std::fs::read_link(format!("/proc/self/fd/{raw_fd}"))
                    .ok()
                    .and_then(|target| {
                        let text = target.to_string_lossy();
                        text.strip_prefix("socket:[")
                            .and_then(|rest| rest.strip_suffix(']'))
                            .and_then(|inode| inode.parse::<u32>().ok())
                    });
                match diag.dump_packet() {
                    Ok(sockets) => {
                        let filtered = sockets.iter().filter(|socket| socket.has_filter).count();
                        let own_seen = own_inode.is_some_and(|inode| {
                            sockets
                                .iter()
                                .any(|socket| socket.inode == inode && socket.has_filter)
                        });
                        eprintln!(
                            "AP3 smoke packet_diag: {} packet socket(s), {filtered} filtered, own_inode={own_inode:?}, own_filter_seen={own_seen}",
                            sockets.len()
                        );
                        assert!(filtered >= 1, "the live filtered tap must be visible");
                        assert!(own_seen, "the verifier must see its own filtered tap");
                    }
                    Err(error) => eprintln!("AP3 smoke packet_diag: honest degrade ({error:?})"),
                }
            } else {
                eprintln!(
                    "AP3 smoke packet_diag: SO_ATTACH_FILTER refused; cannot exercise the tap view"
                );
            }
            unsafe {
                libc::close(raw_fd);
            }
        } else {
            eprintln!(
                "AP3 smoke packet_diag: AF_PACKET socket refused; cannot exercise the tap view"
            );
        }

        // 3. BPF id enumeration through the real syscall layer.
        let mut probes = CROSS_VIEW_MAX_BPF_PROBES;
        for (label, next_cmd, fd_cmd, is_prog) in [
            (
                "prog",
                BPF_CMD_PROG_GET_NEXT_ID,
                BPF_CMD_PROG_GET_FD_BY_ID,
                true,
            ),
            (
                "map",
                BPF_CMD_MAP_GET_NEXT_ID,
                BPF_CMD_MAP_GET_FD_BY_ID,
                false,
            ),
            (
                "link",
                BPF_CMD_LINK_GET_NEXT_ID,
                BPF_CMD_LINK_GET_FD_BY_ID,
                false,
            ),
        ] {
            match scan_object_class(next_cmd, fd_cmd, is_prog, deadline, &mut probes) {
                Ok(result) => eprintln!(
                    "AP3 smoke bpf {label}: visible={} gaps={} truncated={} name_hits={} probes_left={probes}",
                    result.visible.len(),
                    result.gaps.len(),
                    result.truncated,
                    result.name_hits.len()
                ),
                Err(error) => eprintln!("AP3 smoke bpf {label}: honest degrade ({error:?})"),
            }
        }

        // 4. File-backed views: each must either read or degrade honestly, never
        //    panic. Counts are informational; the assertions only cover the
        //    documented contract (bounded reads).
        eprintln!(
            "AP3 smoke modules: proc={:?} sys={:?} taint={:?}",
            read_proc_modules().map(|modules| modules.len()),
            read_sys_modules().map(|modules| modules.len()),
            read_tainted()
        );
        eprintln!(
            "AP3 smoke ftrace: {:?}",
            read_ftrace_enabled().map(|table| table.map(|text| text.lines().count()))
        );
        let pin_root = resolve_pin_root();
        eprintln!(
            "AP3 smoke pins: root={pin_root} entries={} available={}",
            read_pin_entries(&pin_root).len(),
            Path::new(&pin_root).is_dir()
        );
        let mut maps_probe = [0u8; 8];
        if let Ok(mut file) = fs::File::open(format!("{PROCFS_PATH}/self/maps")) {
            let _ = file.read(&mut maps_probe);
            eprintln!("AP3 smoke procfs: /proc/self/maps readable");
        }
    }

    /// Real-system smoke of the *eBPF half*: loads the compiled AP-3 object (path
    /// from `AP3_EBPF_OBJECT`), takes the mandatory `CROSS_VIEW_*` maps, runs the
    /// attach ladder and arms the state word, then exercises `status`, `report`
    /// and `take_events` against the live kernel.
    ///
    /// Ignored by default (needs Linux root). WSL2 run:
    /// `sudo AP3_EBPF_OBJECT=/tmp/.../gedefense-ebpf cargo +1.95.0 test ... -- --ignored ap3_real_system_cross_view_loads`.
    /// The object load is best-effort: a kernel that refuses the full object is
    /// reported as an honest skip, not a test failure; when the object loads, the
    /// AP-3 contract is asserted.
    #[test]
    #[ignore = "real-system eBPF load smoke: needs Linux root, a compiled eBPF object and a live kernel"]
    fn ap3_real_system_cross_view_loads_the_live_ebp_object() {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            eprintln!("AP3 eBPF smoke SKIP: euid={euid} (needs root)");
            return;
        }
        let Ok(object) = std::env::var("AP3_EBPF_OBJECT") else {
            eprintln!("AP3 eBPF smoke SKIP: AP3_EBPF_OBJECT is not set");
            return;
        };
        if !Path::new(&object).is_file() {
            eprintln!("AP3 eBPF smoke SKIP: object {object} is not a file");
            return;
        }
        let mut ebpf = match aya::Ebpf::load_file(&object) {
            Ok(ebpf) => ebpf,
            Err(error) => {
                eprintln!("AP3 eBPF smoke: full object load refused by this kernel ({error}); CrossViewCore::load not exercised");
                return;
            }
        };
        let mut core = CrossViewCore::load(&mut ebpf)
            .expect("mandatory CROSS_VIEW_* maps and the state word must work");
        assert!(core.enabled, "the verifier must arm itself after load");
        // The state word must be armed with the current epoch/magic/ABI.
        let word = core
            .state
            .get(&CROSS_VIEW_STATE_INDEX, 0)
            .expect("state word read");
        assert!(
            gedefense_common::cross_view_state_armed(word),
            "cross-view state word is not armed: {word:#x}"
        );
        let status = core.status();
        eprintln!("AP3 eBPF smoke status: {status}");
        assert!(status.starts_with("enabled=1:"));
        let report = core.report().expect("live report");
        eprintln!("AP3 eBPF smoke report: {report}");
        assert!(
            report.starts_with(CROSS_VIEW_REPORT_BOUNDS_OK)
                || report.starts_with(CROSS_VIEW_REPORT_BOUNDS_DEGRADED)
        );
        assert!(report.len() <= CROSS_VIEW_MAX_REPORT_BYTES);
        assert!(report.contains(":domains="));
        let events = core.take_events().expect("live drain");
        eprintln!("AP3 eBPF smoke events: {events}");
        assert!(events == "empty" || events.contains('|'));

        // Trigger the classic-cBPF `sk_attach_filter` path once and prove the
        // kernel → ring → core decoder → classify → text-wire pipeline end to
        // end. The temp socket is closed immediately afterwards.
        #[repr(C)]
        struct SockFilter {
            code: u16,
            jt: u8,
            jf: u8,
            k: u32,
        }
        #[repr(C)]
        struct SockFprog {
            len: u16,
            filter: *const SockFilter,
        }
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                0x0300, // htons(ETH_P_ALL)
            )
        };
        if raw_fd >= 0 {
            let filter = [
                SockFilter {
                    code: 0x20, // BPF_LD|BPF_W|BPF_ABS
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                SockFilter {
                    code: 0x06, // BPF_RET|BPF_K
                    jt: 0,
                    jf: 0,
                    k: 0xffff_ffff,
                },
            ];
            let fprog = SockFprog {
                len: filter.len() as u16,
                filter: filter.as_ptr(),
            };
            let attached = unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::SOL_SOCKET,
                    26, // SO_ATTACH_FILTER
                    (&fprog as *const SockFprog).cast::<libc::c_void>(),
                    core::mem::size_of::<SockFprog>() as libc::socklen_t,
                )
            } >= 0;
            if attached {
                std::thread::sleep(Duration::from_millis(20));
                core.poll(unix_millis());
                let triggered = core.take_events().expect("live tap drain");
                eprintln!("AP3 eBPF smoke tap events: {triggered}");
                if core.kprobe_attached || core.lsm_setsockopt_attached {
                    assert_ne!(
                        triggered, "empty",
                        "an attached cBPF filter must produce a tap record through the kernel hook"
                    );
                    assert!(triggered.contains('|'));
                    assert!(core.contradictions > 0 || core.events_total > 0);
                } else {
                    eprintln!("AP3 eBPF smoke: no tap hook attached; event pipeline not asserted");
                }
                // The socket stays open for the next scan: the netlink packet_diag
                // view must find the filtered socket, resolve its owner pid from
                // /proc/<pid>/fd and escalate the writable-path executable to
                // PORTLESS_RAW_TAP (domain 2, kind 6). This validates the
                // netlink → owner → executable-path escalation without relying on
                // the kernel hook's pid rendering.
                let scan_report = core.report().expect("live report with open tap");
                eprintln!("AP3 eBPF smoke report with open tap: {scan_report}");
                let escalated = core.take_events().expect("live escalation drain");
                eprintln!("AP3 eBPF smoke escalation events: {escalated}");
                let mut portless_seen = false;
                for record in escalated.split(',').filter(|record| !record.is_empty()) {
                    let fields: Vec<&str> = record.split(':').collect();
                    if fields.len() == 10 && fields[5] == "2" && fields[6] == "6" {
                        portless_seen = true;
                    }
                }
                assert!(
                    portless_seen,
                    "a filtered packet socket owned by a writable-path executable must escalate to PORTLESS_RAW_TAP"
                );
            } else {
                eprintln!("AP3 eBPF smoke: SO_ATTACH_FILTER refused; tap pipeline not triggered");
            }
            unsafe {
                libc::close(raw_fd);
            }
        } else {
            eprintln!("AP3 eBPF smoke: AF_PACKET socket refused; tap pipeline not triggered");
        }
        let status_again = core.status();
        eprintln!("AP3 eBPF smoke status after scan: {status_again}");
        let _ = core.poll(unix_millis());
    }

    const _: () = assert!(CROSS_VIEW_MAX_REPORT_BYTES <= 4096);
}
