use super::*;

/// 128-byte `union bpf_attr` image. All accesses are bounds-checked so a future
/// offset mistake cannot panic a privileged daemon.
#[repr(C, align(8))]
pub(super) struct BpfAttr {
    pub(super) bytes: [u8; BPF_ATTR_BYTES],
}

impl BpfAttr {
    pub(super) fn zeroed() -> Self {
        Self {
            bytes: [0u8; BPF_ATTR_BYTES],
        }
    }

    pub(super) fn set_u32(&mut self, offset: usize, value: u32) {
        if let Some(slot) = self.bytes.get_mut(offset..offset.saturating_add(4)) {
            slot.copy_from_slice(&value.to_ne_bytes());
        }
    }

    pub(super) fn set_u64(&mut self, offset: usize, value: u64) {
        if let Some(slot) = self.bytes.get_mut(offset..offset.saturating_add(8)) {
            slot.copy_from_slice(&value.to_ne_bytes());
        }
    }

    pub(super) fn next_id(&self) -> u32 {
        match self.bytes.get(ATTR_NEXT_ID_OFF..ATTR_NEXT_ID_OFF + 4) {
            Some(slot) => u32::from_ne_bytes([slot[0], slot[1], slot[2], slot[3]]),
            None => 0,
        }
    }
}

pub(super) fn bpf_syscall(cmd: u32, attr: &mut BpfAttr) -> Result<i64, i32> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as libc::c_long,
            attr.bytes.as_mut_ptr().cast::<libc::c_void>(),
            BPF_ATTR_BYTES as libc::c_long,
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(result)
    }
}

pub(super) fn bpf_fd_by_id(cmd: u32, id: u32) -> Result<OwnedFd, i32> {
    let mut attr = BpfAttr::zeroed();
    attr.set_u32(ATTR_OBJ_ID_OFF, id);
    let fd = bpf_syscall(cmd, &mut attr)?;
    let raw = i32::try_from(fd).map_err(|_| libc::EIO)?;
    // SAFETY: a successful `BPF_*_GET_FD_BY_ID` returns a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

pub(super) fn bpf_next_id(cmd: u32, start: u32) -> Result<u32, i32> {
    let mut attr = BpfAttr::zeroed();
    attr.set_u32(ATTR_OBJ_ID_OFF, start);
    bpf_syscall(cmd, &mut attr)?;
    Ok(attr.next_id())
}

pub(super) fn bpf_obj_get(path: &str) -> Result<OwnedFd, i32> {
    let c_path = CString::new(path.as_bytes()).map_err(|_| libc::EINVAL)?;
    let mut attr = BpfAttr::zeroed();
    attr.set_u64(ATTR_PATHNAME_OFF, c_path.as_ptr() as usize as u64);
    let fd = bpf_syscall(BPF_CMD_OBJ_GET, &mut attr)?;
    let raw = i32::try_from(fd).map_err(|_| libc::EIO)?;
    // SAFETY: a successful `BPF_OBJ_GET` returns a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// `BPF_OBJ_GET_INFO_BY_FD` result decoded from the fixed zero-tail buffer.
pub(super) struct ObjectInfo {
    pub(super) object_type: u32,
    pub(super) object_id: u32,
    /// `bpf_prog_info.name` (offset 64).
    pub(super) prog_name: [u8; BPF_OBJ_NAME_BYTES],
    /// `bpf_map_info.name` (offset 24).
    pub(super) map_name: [u8; BPF_OBJ_NAME_BYTES],
    pub(super) link_prog_id: Option<u32>,
}

impl ObjectInfo {
    pub(super) fn name_for_prog(&self) -> &str {
        object_name_str(&self.prog_name)
    }

    pub(super) fn name_for_map(&self) -> &str {
        object_name_str(&self.map_name)
    }
}

/// The self-defence pin root pins *maps* (critical event/policy maps), so the
/// map-info offset is authoritative for a pinned object; only a pin that is not a
/// named map falls back to the program-info offset. A candidate extracted from
/// the wrong struct offset (a numeric neighbour field or a pointer) is never
/// preferred over the struct-specific one.
pub(super) fn pinned_object_candidate_name(info: &ObjectInfo) -> Option<String> {
    let map = info.name_for_map();
    if !map.is_empty() {
        return Some(map.to_owned());
    }
    let prog = info.name_for_prog();
    if !prog.is_empty() {
        return Some(prog.to_owned());
    }
    None
}

pub(super) fn bpf_object_info(fd: i32) -> Option<ObjectInfo> {
    let mut info = [0u8; INFO_BUF_BYTES];
    let mut attr = BpfAttr::zeroed();
    attr.set_u32(ATTR_INFO_FD_OFF, u32::try_from(fd).ok()?);
    attr.set_u32(ATTR_INFO_LEN_OFF, INFO_BUF_BYTES as u32);
    attr.set_u64(ATTR_INFO_PTR_OFF, info.as_mut_ptr() as usize as u64);
    let _ = bpf_syscall(BPF_CMD_OBJ_GET_INFO_BY_FD, &mut attr).ok()?;
    let object_type = read_u32(&info, 0)?;
    let object_id = read_u32(&info, 4)?;
    let link_prog_id = read_u32(&info, 8);
    // The info struct depends on the object kind, which the caller knows for
    // programs/maps; both candidate offsets are extracted and only a strictly
    // valid BPF object name (kernel charset, NUL padded) is kept, so a numeric
    // neighbouring field can never be mistaken for a name.
    Some(ObjectInfo {
        object_type,
        object_id,
        prog_name: info_name_at(&info, PROG_INFO_NAME_OFF),
        map_name: info_name_at(&info, MAP_INFO_NAME_OFF),
        link_prog_id,
    })
}

/// Extracts one 16-byte NUL-padded BPF object name at `offset` if it satisfies
/// the kernel's object-name charset (`isalnum() || '_' || '.'`).
pub(super) fn info_name_at(info: &[u8], offset: usize) -> [u8; BPF_OBJ_NAME_BYTES] {
    let mut name = [0u8; BPF_OBJ_NAME_BYTES];
    let Some(slot) = info.get(offset..offset + BPF_OBJ_NAME_BYTES) else {
        return name;
    };
    let mut index = 0usize;
    while index < slot.len() && slot[index] != 0 {
        let byte = slot[index];
        if !(byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.') {
            return name;
        }
        index += 1;
    }
    // A valid object name is 1..=15 chars with the remaining bytes zero.
    if index == 0 || index >= slot.len() {
        return name;
    }
    if slot[index..].iter().any(|byte| *byte != 0) {
        return name;
    }
    name.copy_from_slice(slot);
    name
}

pub(super) fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slot = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_ne_bytes([slot[0], slot[1], slot[2], slot[3]]))
}

pub(super) fn object_name_str(name: &[u8; BPF_OBJ_NAME_BYTES]) -> &str {
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    core::str::from_utf8(&name[..end]).unwrap_or("")
}

/// Resolves a pin file through `BPF_OBJ_GET` + `BPF_OBJ_GET_INFO_BY_FD`.
/// `Ok(Some(name))` = live object with a name candidate; `Ok(None)` = live
/// object without a usable name; `Err(())` = the pin does not resolve
/// (dangling/replaced type).
pub(super) fn resolve_pinned_object(path: &str) -> Result<Option<String>, ()> {
    let fd = bpf_obj_get(path).map_err(|_| ())?;
    let info = bpf_object_info(fd.as_raw_fd()).ok_or(())?;
    if info.object_type == 0 && info.object_id == 0 {
        return Ok(None);
    }
    Ok(pinned_object_candidate_name(&info))
}

impl CrossViewCore {
    pub(super) fn scan_bpf_id_gap(
        &mut self,
        now_ms: u64,
        deadline: Instant,
        outcome: &mut ScanOutcome,
    ) {
        let mut probes = CROSS_VIEW_MAX_BPF_PROBES;
        let mut gaps = 0usize;
        let mut name_evidence = 0usize;
        let mut truncation = false;
        let mut denied = false;
        let mut enumerated_something = false;

        // Program ids drive the link tamper check, so they are scanned first.
        let progs = match scan_object_class(
            BPF_CMD_PROG_GET_NEXT_ID,
            BPF_CMD_PROG_GET_FD_BY_ID,
            true,
            deadline,
            &mut probes,
        ) {
            Ok(result) => result,
            Err(error) => {
                denied = error == ViewError::Denied;
                Self::note_bpf_enum_error(outcome, "prog", error);
                ClassScan::default()
            }
        };
        enumerated_something |= !progs.visible.is_empty();
        truncation |= progs.truncated;
        let visible: HashSet<u32> = progs.visible.iter().copied().collect();
        for id in progs.gaps.iter().take(8) {
            gaps += 1;
            self.enqueue(bpf_gap_event(
                now_ms,
                *id,
                "prog",
                CROSS_VIEW_KIND_HIDDEN_PROG,
            ));
        }
        for (id, domain, kind) in progs.name_hits.iter().take(8) {
            name_evidence += 1;
            self.enqueue(bpf_name_event(now_ms, *id, *domain, *kind));
        }

        let maps = match scan_object_class(
            BPF_CMD_MAP_GET_NEXT_ID,
            BPF_CMD_MAP_GET_FD_BY_ID,
            false,
            deadline,
            &mut probes,
        ) {
            Ok(result) => result,
            Err(error) => {
                denied |= error == ViewError::Denied;
                Self::note_bpf_enum_error(outcome, "map", error);
                ClassScan::default()
            }
        };
        enumerated_something |= !maps.visible.is_empty();
        truncation |= maps.truncated;
        for id in maps.gaps.iter().take(8) {
            gaps += 1;
            self.enqueue(bpf_gap_event(
                now_ms,
                *id,
                "map",
                CROSS_VIEW_KIND_HIDDEN_MAP,
            ));
        }
        for (id, domain, kind) in maps.name_hits.iter().take(8) {
            name_evidence += 1;
            self.enqueue(bpf_name_event(now_ms, *id, *domain, *kind));
        }

        let links = match scan_object_class(
            BPF_CMD_LINK_GET_NEXT_ID,
            BPF_CMD_LINK_GET_FD_BY_ID,
            false,
            deadline,
            &mut probes,
        ) {
            Ok(result) => result,
            Err(error) => {
                denied |= error == ViewError::Denied;
                Self::note_bpf_enum_error(outcome, "link", error);
                ClassScan::default()
            }
        };
        truncation |= links.truncated;
        for id in links.gaps.iter().take(8) {
            gaps += 1;
            self.enqueue(bpf_gap_event(
                now_ms,
                *id,
                "link",
                CROSS_VIEW_KIND_HIDDEN_LINK,
            ));
        }
        // Link tamper: a visible link attached to a program id that is not in
        // the visible program set is evidence of a hidden/retargeted program.
        for id in links.visible.iter().take(256) {
            if let Some(record) = link_program_tamper(now_ms, *id, &visible) {
                self.enqueue(record);
                gaps += 1;
            }
        }

        self.bpf_available = !denied && enumerated_something;
        if !self.bpf_available {
            outcome.reason(if denied {
                "bpf_enum_denied"
            } else {
                "bpf_enum_empty"
            });
        }
        if truncation {
            outcome.degrade("bpf_enum_truncated");
        }
        if gaps > 0 {
            outcome.reason("bpf_id_gap");
        }
        if self.bpf_available {
            outcome.domains += 1;
            // The bounded object-name read runs as part of the same
            // enumeration, so the map-name view (domain 8) is readable too.
            outcome.domains += 1;
        }
        if name_evidence > 0 {
            outcome.reason("bpf_name_heuristic");
        }
    }

    pub(super) fn note_bpf_enum_error(
        outcome: &mut ScanOutcome,
        class: &'static str,
        error: ViewError,
    ) {
        match error {
            ViewError::Denied => {
                eprintln!("cross-view BPF {class} id enumeration denied; capability gap (fact, not degradation)")
            }
            ViewError::Unsupported => {
                outcome.reason("bpf_enum_unsupported");
                eprintln!("cross-view BPF {class} id enumeration unsupported by this kernel");
            }
            ViewError::Failed => {
                outcome.degrade("bpf_enum_failed");
                eprintln!("cross-view BPF {class} id enumeration failed");
            }
        }
    }
}

pub(super) fn bpf_gap_event(now_ms: u64, id: u32, label: &str, kind: u8) -> CrossViewEvent {
    CrossViewEvent {
        ts_ns: now_ms.saturating_mul(1_000_000),
        ino: u64::from(id),
        pid: 0,
        uid: 0,
        dev: 0,
        detail_code: CROSS_VIEW_DETAIL_ID_GAP,
        domain: CROSS_VIEW_DOMAIN_EBPF_ID_GAP,
        kind,
        severity: CROSS_VIEW_SEVERITY_CRITICAL,
        action: CROSS_VIEW_ACTION_AUDIT,
        comm: bounded_comm(label),
        reserved: [0u8; 12],
    }
}

pub(super) fn bpf_name_event(now_ms: u64, id: u32, domain: u8, kind: u8) -> CrossViewEvent {
    CrossViewEvent {
        ts_ns: now_ms.saturating_mul(1_000_000),
        ino: u64::from(id),
        pid: 0,
        uid: 0,
        dev: 0,
        detail_code: CROSS_VIEW_DETAIL_NAME_HEURISTIC,
        domain,
        kind,
        severity: CROSS_VIEW_SEVERITY_MEDIUM,
        action: CROSS_VIEW_ACTION_OBSERVE,
        comm: bounded_comm("bpf-name"),
        reserved: [0u8; 12],
    }
}

/// Enumerates one BPF id class via `*_GET_NEXT_ID` and cross-probes it with
/// sequential `*_GET_FD_BY_ID`. Any id reachable by fd-by-id but missing from
/// the iterator list is a gap (hidden object). The probe budget is shared across
/// all classes; a hit on the budget/consecutive-miss guard marks the class
/// truncated, and the caller reports `bounds=degraded` instead of claiming a
/// clean enumeration.
pub(super) fn scan_object_class(
    get_next_cmd: u32,
    get_fd_cmd: u32,
    is_prog: bool,
    deadline: Instant,
    probes_left: &mut u64,
) -> Result<ClassScan, ViewError> {
    let mut result = ClassScan::default();
    let mut start = 0u32;
    let mut seen_ids: HashSet<u32> = HashSet::new();
    loop {
        if result.visible.len() >= CROSS_VIEW_MAX_BPF_OBJECTS {
            result.truncated = true;
            break;
        }
        match bpf_next_id(get_next_cmd, start) {
            Ok(id) => {
                if id <= start || !seen_ids.insert(id) {
                    result.truncated = true;
                    break;
                }
                result.visible.push(id);
                start = id;
            }
            Err(errno) if errno == libc::ENOENT => break,
            Err(errno) => return Err(errno_to_view_error(errno)),
        }
    }
    if result.visible.is_empty() || result.truncated {
        // An empty or truncated iterator list cannot be diffed honestly.
        return Ok(result);
    }
    let max_id = result.visible.iter().copied().max().unwrap_or(0);
    let visible_set = seen_ids;
    let mut consecutive_misses = 0u32;
    let mut info_reads = 0usize;
    for id in 1..=max_id {
        if *probes_left == 0 || Instant::now() >= deadline {
            result.truncated = true;
            break;
        }
        *probes_left -= 1;
        match bpf_fd_by_id(get_fd_cmd, id) {
            Ok(fd) => {
                consecutive_misses = 0;
                if !visible_set.contains(&id) {
                    result.gaps.push(id);
                }
                // Bounded object-name read: identity evidence for the map-name
                // view and for gap attribution.
                if info_reads < 512 {
                    info_reads += 1;
                    if let Some(info) = bpf_object_info(fd.as_raw_fd()) {
                        let name = if is_prog {
                            info.name_for_prog()
                        } else {
                            info.name_for_map()
                        };
                        if is_suspicious_object_name(name) {
                            let (domain, kind) = if is_prog {
                                (CROSS_VIEW_DOMAIN_MAP_NAME_VIEW, CROSS_VIEW_KIND_HIDDEN_PROG)
                            } else {
                                (CROSS_VIEW_DOMAIN_MAP_NAME_VIEW, CROSS_VIEW_KIND_HIDDEN_MAP)
                            };
                            result.name_hits.push((id, domain, kind));
                        }
                    }
                }
            }
            Err(errno) if errno == libc::ENOENT => {
                consecutive_misses = consecutive_misses.saturating_add(1);
                if consecutive_misses > 65_536 {
                    // A huge sparse id space (long-uptime churn): stop probing
                    // instead of spending the whole budget on empty ranges.
                    result.truncated = true;
                    break;
                }
            }
            Err(errno) if errno == libc::EPERM || errno == libc::EACCES => {
                return Err(ViewError::Denied);
            }
            Err(_) => {
                consecutive_misses = consecutive_misses.saturating_add(1);
            }
        }
    }
    Ok(result)
}

// ===========================================================================
// Domain 2 + 7 — socket / netlink filter cross-view
// ===========================================================================
