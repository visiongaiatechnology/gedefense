use super::*;

/// Tap-evidence dedupe window.
pub(super) const TAP_DEDUPE_TTL_MS: u64 = 5_000;
pub(super) const TAP_DEDUPE_LIMIT: usize = 1024;
/// Owner-pid resolution for netlink-discovered packet sockets.
pub(super) const OWNER_SCAN_MAX_PIDS: usize = 8192;
pub(super) const OWNER_SCAN_MAX_UID_PIDS: usize = 256;
pub(super) const OWNER_SCAN_MAX_FDS: usize = 8192;

impl CrossViewCore {
    pub(super) fn scan_sockets(
        &mut self,
        now_ms: u64,
        deadline: Instant,
        outcome: &mut ScanOutcome,
    ) {
        let diag = match NetlinkDiag::open() {
            Ok(diag) => diag,
            Err(error) => {
                eprintln!("cross-view socket view: NETLINK_SOCK_DIAG unavailable ({error:?})");
                self.socket_available = false;
                outcome.reason("netlink_unavailable");
                return;
            }
        };

        // Netlink view: TCP/UDP v4+v6 and packet sockets with filter info.
        let mut netlink_inodes: HashSet<u32> = HashSet::new();
        let mut packet_filtered: Vec<PacketSocket> = Vec::new();
        let mut inet_ok = 0u8;
        let mut packet_ok = false;
        let inet_requests = [
            (AF_INET_U8, IPPROTO_TCP_U8),
            (AF_INET6_U8, IPPROTO_TCP_U8),
            (AF_INET_U8, IPPROTO_UDP_U8),
            (AF_INET6_U8, IPPROTO_UDP_U8),
        ];
        let mut inet_sockets: Vec<InetSocket> = Vec::new();
        for (family, protocol) in inet_requests {
            match diag.dump_inet(family, protocol) {
                Ok(sockets) => {
                    inet_ok += 1;
                    for socket in sockets {
                        netlink_inodes.insert(socket.inode);
                        inet_sockets.push(socket);
                    }
                }
                Err(ViewError::Unsupported) => {}
                Err(error) => {
                    eprintln!("cross-view inet_diag dump family={family} proto={protocol} failed ({error:?})");
                    outcome.degrade("netlink_inet_partial");
                }
            }
            if Instant::now() >= deadline {
                outcome.degrade("budget_exhausted");
                break;
            }
        }
        if Instant::now() < deadline {
            match diag.dump_packet() {
                Ok(sockets) => {
                    packet_ok = true;
                    for socket in sockets {
                        netlink_inodes.insert(socket.inode);
                        if socket.has_filter {
                            packet_filtered.push(socket);
                        }
                    }
                }
                Err(ViewError::Unsupported) => {}
                Err(error) => {
                    eprintln!("cross-view packet_diag dump failed ({error:?})");
                    outcome.degrade("netlink_packet_unavailable");
                }
            }
        }
        self.socket_available = inet_ok > 0 || packet_ok;
        if !self.socket_available {
            outcome.reason("netlink_unavailable");
            return;
        }
        outcome.domains += 1;

        // Procfs view (only the classes the netlink side produced).
        let mut proc_inodes: HashSet<u32> = HashSet::new();
        let mut proc_ok = true;
        if inet_ok > 0 {
            for path in [
                "/proc/net/tcp",
                "/proc/net/tcp6",
                "/proc/net/udp",
                "/proc/net/udp6",
            ] {
                match read_proc_net_inodes(path, PROC_NET_INET_INODE_INDEX) {
                    Ok(inodes) => proc_inodes.extend(inodes),
                    Err(ProcNetError::Missing) => {}
                    Err(ProcNetError::Unreadable) => {
                        proc_ok = false;
                        outcome.degrade("proc_net_unreadable");
                    }
                }
            }
        }
        if packet_ok {
            match read_proc_net_inodes("/proc/net/packet", PROC_NET_PACKET_INODE_INDEX) {
                Ok(inodes) => proc_inodes.extend(inodes),
                Err(ProcNetError::Missing) => {
                    proc_ok = false;
                    outcome.reason("proc_net_packet_missing");
                }
                Err(ProcNetError::Unreadable) => {
                    proc_ok = false;
                    outcome.degrade("proc_net_unreadable");
                }
            }
        }

        // Contradiction: netlink sees a socket the procfs view does not. A
        // socket can legitimately close between the two reads, so the mismatch
        // is re-confirmed with a complete second netlink pass and fresh procfs
        // reads; only an inode present in both netlink passes and absent from
        // every procfs view is reported.
        let mut candidates: Vec<u32> = netlink_inodes
            .difference(&proc_inodes)
            .copied()
            .take(64)
            .collect();
        candidates.sort_unstable();
        if !candidates.is_empty() && proc_ok {
            let mut second_netlink: HashSet<u32> = HashSet::new();
            for (family, protocol) in inet_requests {
                if let Ok(sockets) = diag.dump_inet(family, protocol) {
                    for socket in sockets {
                        second_netlink.insert(socket.inode);
                    }
                }
            }
            if packet_ok {
                if let Ok(sockets) = diag.dump_packet() {
                    for socket in sockets {
                        second_netlink.insert(socket.inode);
                    }
                }
            }
            let mut second_proc: HashSet<u32> = HashSet::new();
            let mut second_proc_ok = true;
            for path in [
                "/proc/net/tcp",
                "/proc/net/tcp6",
                "/proc/net/udp",
                "/proc/net/udp6",
            ] {
                match read_proc_net_inodes(path, PROC_NET_INET_INODE_INDEX) {
                    Ok(inodes) => second_proc.extend(inodes),
                    Err(ProcNetError::Missing) => {}
                    Err(ProcNetError::Unreadable) => second_proc_ok = false,
                }
            }
            match read_proc_net_inodes("/proc/net/packet", PROC_NET_PACKET_INODE_INDEX) {
                Ok(inodes) => second_proc.extend(inodes),
                Err(ProcNetError::Missing) => second_proc_ok = false,
                Err(ProcNetError::Unreadable) => second_proc_ok = false,
            }
            if second_proc_ok {
                let mut confirmed: Vec<u32> = candidates
                    .iter()
                    .copied()
                    .filter(|inode| second_netlink.contains(inode) && !second_proc.contains(inode))
                    .take(8)
                    .collect();
                confirmed.sort_unstable();
                for inode in confirmed.drain(..) {
                    let uid = inet_sockets
                        .iter()
                        .find(|socket| socket.inode == inode)
                        .map(|socket| socket.uid)
                        .unwrap_or(0);
                    self.enqueue(CrossViewEvent {
                        ts_ns: now_ms.saturating_mul(1_000_000),
                        ino: u64::from(inode),
                        pid: 0,
                        uid,
                        dev: 0,
                        detail_code: CROSS_VIEW_DETAIL_NETLINK_ONLY,
                        domain: CROSS_VIEW_DOMAIN_SOCKET_VIEW,
                        kind: CROSS_VIEW_KIND_HIDDEN_SOCKET,
                        severity: CROSS_VIEW_SEVERITY_HIGH,
                        action: CROSS_VIEW_ACTION_AUDIT,
                        comm: bounded_comm("socket"),
                        reserved: [0u8; 12],
                    });
                }
            }
        }

        // Pre-existing filtered packet taps: the netlink view sees them even
        // when the creation predates the core. The owner pid is resolved with a
        // bounded /proc/<pid>/fd scan; a suspicious executable escalates to
        // PORTLESS_RAW_TAP, an unattributed tap stays a medium observation (the
        // control plane shows it without inventing a verdict).
        let mut owner_resolutions = 0usize;
        for socket in packet_filtered.iter().take(16) {
            if Instant::now() >= deadline {
                outcome.degrade("budget_exhausted");
                break;
            }
            let owner = if owner_resolutions < 4 {
                owner_resolutions += 1;
                resolve_socket_owner(socket.inode, socket.uid)
            } else {
                None
            };
            let (kind, domain, severity, detail, comm) = match owner {
                Some(pid) => match read_proc_exe(pid) {
                    Some(path) if suspicious_executable_path(&path) => (
                        CROSS_VIEW_KIND_PORTLESS_RAW_TAP,
                        CROSS_VIEW_DOMAIN_SOCKET_VIEW,
                        CROSS_VIEW_SEVERITY_HIGH,
                        CROSS_VIEW_DETAIL_TAP_SUSPICIOUS_PATH,
                        read_proc_comm(pid).unwrap_or_else(|| "packet".to_owned()),
                    ),
                    _ => (
                        CROSS_VIEW_KIND_RAW_TAP_FILTER,
                        CROSS_VIEW_DOMAIN_NETLINK_FILTER,
                        CROSS_VIEW_SEVERITY_MEDIUM,
                        CROSS_VIEW_DETAIL_TAP_FILTER,
                        read_proc_comm(pid).unwrap_or_else(|| "packet".to_owned()),
                    ),
                },
                None => (
                    CROSS_VIEW_KIND_RAW_TAP_FILTER,
                    CROSS_VIEW_DOMAIN_NETLINK_FILTER,
                    CROSS_VIEW_SEVERITY_MEDIUM,
                    CROSS_VIEW_DETAIL_TAP_FILTER,
                    "packet".to_owned(),
                ),
            };
            self.enqueue(CrossViewEvent {
                ts_ns: now_ms.saturating_mul(1_000_000),
                ino: u64::from(socket.inode),
                pid: owner.unwrap_or(0),
                uid: socket.uid,
                dev: 0,
                detail_code: detail,
                domain,
                kind,
                severity,
                action: CROSS_VIEW_ACTION_AUDIT,
                comm: bounded_comm(&comm),
                reserved: [0u8; 12],
            });
        }
    }
}

/// Classifies one decoded kernel tap record: suspicious executable → a
/// `PORTLESS_RAW_TAP` contradiction (socket domain); otherwise the plain
/// `RAW_TAP_FILTER` observation (netlink-filter domain).
pub(super) fn classify_tap_event(event: &CrossViewEvent, now_ms: u64) -> Option<CrossViewEvent> {
    // The hook fires in the calling thread; the ring record carries the emitting
    // tgid in `ino` precisely so a thread that exited before the drain can still
    // be attributed through /proc/<tgid>/exe.
    let path = read_proc_exe(event.pid).or_else(|| {
        let tgid = u32::try_from(event.ino).ok()?;
        if tgid == event.pid {
            return None;
        }
        read_proc_exe(tgid)
    });
    let suspicious = path.as_deref().is_some_and(suspicious_executable_path);
    let (domain, kind, severity, detail, action) = if suspicious {
        (
            CROSS_VIEW_DOMAIN_SOCKET_VIEW,
            CROSS_VIEW_KIND_PORTLESS_RAW_TAP,
            CROSS_VIEW_SEVERITY_HIGH,
            CROSS_VIEW_DETAIL_TAP_SUSPICIOUS_PATH,
            CROSS_VIEW_ACTION_AUDIT,
        )
    } else {
        (
            CROSS_VIEW_DOMAIN_NETLINK_FILTER,
            CROSS_VIEW_KIND_RAW_TAP_FILTER,
            CROSS_VIEW_SEVERITY_MEDIUM,
            event.detail_code,
            CROSS_VIEW_ACTION_AUDIT,
        )
    };
    Some(CrossViewEvent {
        ts_ns: if event.ts_ns == 0 {
            now_ms.saturating_mul(1_000_000)
        } else {
            event.ts_ns
        },
        ino: event.ino,
        pid: event.pid,
        uid: event.uid,
        // Ring taps carry no dev; keep it zero explicitly.
        dev: 0,
        detail_code: detail,
        domain,
        kind,
        severity,
        action,
        comm: normalize_wire_comm(event.comm),
        reserved: [0u8; 12],
    })
}

// ===========================================================================
// Domain 5 — library cross-view
// ===========================================================================

/// Bounded owner-pid resolution for a packet socket inode: scans the pids that
/// share the socket's uid and matches `/proc/<pid>/fd/N -> socket:[inode]`.
pub(super) fn resolve_socket_owner(inode: u32, uid: u32) -> Option<u32> {
    let pids = read_proc_pids().ok()?;
    let mut uid_pids = 0usize;
    let mut fd_entries = 0usize;
    let needle = format!("socket:[{inode}]");
    for pid in pids.iter().take(OWNER_SCAN_MAX_PIDS) {
        if uid_pids >= OWNER_SCAN_MAX_UID_PIDS || fd_entries >= OWNER_SCAN_MAX_FDS {
            break;
        }
        if proc_uid(*pid) != Some(uid) {
            continue;
        }
        uid_pids += 1;
        let Ok(entries) = fs::read_dir(format!("{PROCFS_PATH}/{pid}/fd")) else {
            continue;
        };
        for entry in entries.flatten() {
            fd_entries += 1;
            if fd_entries > OWNER_SCAN_MAX_FDS {
                break;
            }
            let Ok(target) = fs::read_link(entry.path()) else {
                continue;
            };
            if target.as_os_str().to_string_lossy() == needle {
                return Some(*pid);
            }
        }
    }
    None
}
