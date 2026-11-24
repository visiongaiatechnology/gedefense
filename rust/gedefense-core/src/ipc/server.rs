//! Wave 3a extraction: the VGT3 Unix-socket IPC server (SO_PEERCRED peer check,
//! HMAC authentication, replay window, request loop and command router)
//! formerly inline in `main.rs`.

use super::{dispatch_lockdown, dispatch_net, dispatch_quarantine, dispatch_titan, dispatch_xdr};
use crate::*;

pub(crate) const PROTOCOL: &str = "VGT3";
pub(crate) const MAX_REQUEST_BYTES: u64 = 4096;
// Response ceiling for the authenticated IPC wire (busybox-sized multi-record
// batches such as the 64-record StyX flow drain are the reason this is not
// 2048 anymore). The bound is enforced before the base64 URL encoding, so the
// control-plane reader limit (`maxCoreResponseBytes` in control/coreipc.go)
// must cover base64url(MAX_RESPONSE_BYTES) plus the protocol line overhead;
// the Go side is updated with the same StyX batch/payload limits.
pub(crate) const MAX_RESPONSE_BYTES: usize = 24 * 1024;
pub(crate) const CLOCK_WINDOW_SECS: u64 = 30;
// A request timestamp may lead the local clock by at most this much.
//
// The previous `|now - stamp| <= CLOCK_WINDOW_SECS` check accepted timestamps up
// to a full window in the future. The nonce was cached against the arrival time
// and evicted one window later, while such a future timestamp stayed valid for
// another window after that: a captured request could be replayed in
// [t + window + 1, t + 2 * window]. The tolerated future skew is therefore tiny
// (the control plane and the core share one host clock), and the nonce entry is
// keyed to the later of arrival and request time.
pub(crate) const CLOCK_FUTURE_TOLERANCE_SECS: u64 = 5;
pub(crate) const REPLAY_CACHE_CAPACITY: usize = 4096;

// F-18: sockets created by the root core are pinned to the control-plane group
// and never left world-accessible. A symlinked socket path is rejected before
// permissions are touched, and ownership is corrected only when the service
// manager did not already apply Group=gedefense.
pub(crate) fn secure_runtime_socket(path: &Path, group: u32, mode: u32) -> Result<(), BoxError> {
    let metadata = fs::symlink_metadata(path)?;
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink() || metadata.uid() != effective_uid {
        return Err("runtime socket ownership rejected".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    if metadata.gid() != group {
        let socket_c = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: socket_c is a valid NUL-terminated path. u32::MAX as uid leaves
        // the owner untouched and only changes the owning group.
        let rc = unsafe { libc::chown(socket_c.as_ptr(), libc::uid_t::MAX, group) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let secured = fs::symlink_metadata(path)?;
    if secured.permissions().mode() & 0o007 != 0 {
        return Err("runtime socket must not be accessible to other".into());
    }
    Ok(())
}

// Every privileged runtime socket is bound through this one path, so no caller
// can accidentally create a world-accessible or group-mismatched socket that
// escapes the F-18 hardening above.
pub(crate) fn bind_secure_runtime_socket(
    path: &Path,
    group: u32,
    mode: u32,
) -> Result<UnixListener, BoxError> {
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    secure_runtime_socket(path, group, mode)?;
    Ok(listener)
}

pub(crate) fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// F-20: the key is opened exactly once with O_NOFOLLOW and every property
// (type, mode, owner, size) is verified on that same file descriptor before the
// descriptor is read. The former symlink_metadata + path-based fs::read pair
// resolved the path twice and could be swapped between check and read.
pub(crate) fn load_secret_key(path: &str, control_gid: u32, label: &str) -> Result<Vec<u8>, BoxError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(format!("{label} must be a regular non-symlink file").into())
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(format!("{label} must be a regular non-symlink file").into());
    }
    let mode = metadata.permissions().mode() & 0o777;
    let production_profile = metadata.uid() == 0 && metadata.gid() == control_gid && mode == 0o640;
    let local_profile = metadata.uid() == 0 && mode == 0o600;
    if !production_profile && !local_profile {
        return Err(format!(
            "{label} ownership/mode invalid: uid={} gid={} mode={mode:#o}",
            metadata.uid(),
            metadata.gid()
        )
        .into());
    }
    if metadata.len() != 32 {
        return Err(format!("{label} must contain exactly 32 bytes").into());
    }
    let mut key = Vec::with_capacity(32);
    (&file).take(33).read_to_end(&mut key)?;
    if key.len() != 32 {
        return Err(format!("{label} must contain exactly 32 bytes").into());
    }
    Ok(key)
}

pub(crate) fn load_auth_key(path: &str, control_gid: u32) -> Result<Vec<u8>, BoxError> {
    load_secret_key(path, control_gid, "IPC authentication key")
}

pub(crate) fn unix_seconds() -> Result<u64, BoxError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

// F-20: the IPC MAC covers length-less fields joined by a 0x1f delimiter. That
// encoding is only unambiguous when no field itself contains the delimiter.
// Fields are therefore rejected when they do, which keeps the on-wire format
// compatible with the control plane and makes ("ab","c") and ("a","bc") - or
// any field split that smuggles the separator - impossible to conflate.
pub(crate) const MAC_FIELD_SEPARATOR: u8 = 0x1f;

pub(crate) fn pack_mac_fields(fields: &[&str]) -> Result<Vec<u8>, BoxError> {
    let mut packed = Vec::with_capacity(64);
    for (index, field) in fields.iter().enumerate() {
        if field.as_bytes().contains(&MAC_FIELD_SEPARATOR) {
            return Err("IPC field contains the MAC field separator".into());
        }
        if index > 0 {
            packed.push(MAC_FIELD_SEPARATOR);
        }
        packed.extend_from_slice(field.as_bytes());
    }
    Ok(packed)
}

pub(crate) fn authenticated_mac(key: &[u8], fields: &[&str]) -> Result<Vec<u8>, BoxError> {
    let packed = pack_mac_fields(fields)?;
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(&packed);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(crate) fn verify_mac(key: &[u8], fields: &[&str], encoded_mac: &str) -> Result<(), BoxError> {
    let supplied = hex::decode(encoded_mac)?;
    if supplied.len() != 32 {
        return Err("request authentication failed".into());
    }
    let packed = pack_mac_fields(fields)?;
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(&packed);
    mac.verify_slice(&supplied)
        .map_err(|_| "request authentication failed".into())
}

// The one timestamp policy for authenticated IPC. A timestamp may be at most
// CLOCK_WINDOW_SECS old and CLOCK_FUTURE_TOLERANCE_SECS ahead of the local
// clock. This function is used both before the MAC check (cheap filter) and as
// part of the replay decision, so the two can never drift apart.
pub(crate) fn request_timestamp_error(now: u64, stamp: u64) -> Option<&'static str> {
    if stamp > now.saturating_add(CLOCK_FUTURE_TOLERANCE_SECS) {
        return Some("future");
    }
    if now.saturating_sub(stamp) > CLOCK_WINDOW_SECS {
        return Some("stale");
    }
    None
}

pub(crate) struct ReplayGuard {
    pub(crate) set: HashSet<String>,
    // (nonce, expires_at). The expiry is derived from the later of arrival time
    // and request timestamp plus one full clock window, so a nonce is never
    // evicted while its own timestamp could still pass the window check.
    pub(crate) order: VecDeque<(String, u64)>,
}

impl ReplayGuard {
    pub(crate) fn new() -> Self {
        Self {
            set: HashSet::with_capacity(REPLAY_CACHE_CAPACITY),
            order: VecDeque::with_capacity(REPLAY_CACHE_CAPACITY),
        }
    }

    pub(crate) fn accept(&mut self, nonce: &str, now: u64, stamp: u64) -> bool {
        // A request outside its own validity window is never accepted, no matter
        // whether its nonce is still cached.
        if request_timestamp_error(now, stamp).is_some() {
            return false;
        }

        while self
            .order
            .front()
            .is_some_and(|(_, expires_at)| *expires_at < now)
        {
            let Some((old_nonce, _)) = self.order.pop_front() else {
                break;
            };
            self.set.remove(&old_nonce);
        }

        // A nonce already in the window is a replay. Nothing else is.
        if self.set.contains(nonce) {
            return false;
        }

        // At capacity, evict the oldest entry instead of refusing the request.
        //
        // The guard exists to reject duplicates, and a full cache is not evidence of one.
        // Treating it as though it were turned a burst of legitimate commands into a
        // lockout: the control plane applies its blocklist one entry at a time, so a list
        // larger than the capacity could never be applied at all. Every command past the
        // 4096th was refused as a replay, including the health checks that decide whether
        // the core is considered connected - so the platform reported its own kernel
        // channel offline while the kernel was answering it perfectly well, and the
        // entries it had already added stayed in the map.
        //
        // Eviction is safe because the nonce cache is the second line of defence, not the
        // first: every request also carries a timestamp that is rejected outright when it
        // falls outside CLOCK_WINDOW_SECS, and nonce entries outlive that window because
        // they are keyed to max(arrival, request time) + CLOCK_WINDOW_SECS.
        while self.order.len() >= REPLAY_CACHE_CAPACITY {
            match self.order.pop_front() {
                Some((old_nonce, _)) => {
                    self.set.remove(&old_nonce);
                }
                None => break,
            }
        }

        let expires_at = now.max(stamp).saturating_add(CLOCK_WINDOW_SECS);
        self.set.insert(nonce.to_owned());
        self.order.push_back((nonce.to_owned(), expires_at));
        true
    }
}

pub(crate) fn write_response(
    stream: &mut UnixStream,
    key: &[u8],
    nonce: &str,
    status: &str,
    message: &str,
) -> Result<(), BoxError> {
    let bounded = if message.len() > MAX_RESPONSE_BYTES {
        "response truncated"
    } else {
        message
    };
    let encoded = URL_SAFE_NO_PAD.encode(bounded.as_bytes());
    let response_tag = format!("{PROTOCOL}R");
    let mac = authenticated_mac(key, &[&response_tag, nonce, status, &encoded])?;
    writeln!(
        stream,
        "{} {} {} {} {}",
        response_tag,
        nonce,
        status,
        encoded,
        hex::encode(mac)
    )?;
    Ok(())
}

fn process_command(
    core: &mut KernelCore,
    quarantine: &QuarantineBroker,
    scanner: &MalwareScanner,
    canary: &CanaryBroker,
    parts: &[&str],
) -> Result<String, BoxError> {
    // V6.3.0 AP-0/AP-1: self-protection and TTL maintenance run on the
    // control-plane polling cadence. Both are bounded and never block the IPC
    // response; a slow bpffs stat is capped by the manifest size.
    core.self_defense.poll(self_defense::unix_millis());
    core.exec_inode.poll();
    // V6.3.0 AP-3/AP-5: scheduled cross-view scans and the persistence
    // integrity diff own bounded cadences; poll() never blocks the IPC path.
    core.cross_view.poll(self_defense::unix_millis());
    core.persistence.poll(self_defense::unix_millis());

    if let Some(result) = dispatch_net::dispatch(core, parts)? {
        return Ok(result);
    }
    if let Some(result) = dispatch_xdr::dispatch(core, parts)? {
        return Ok(result);
    }
    if let Some(result) = dispatch_titan::dispatch(core, parts)? {
        return Ok(result);
    }
    if let Some(result) = dispatch_quarantine::dispatch(core, quarantine, scanner, canary, parts)? {
        return Ok(result);
    }
    if let Some(result) = sysctl_broker::dispatch(parts)? {
        return Ok(result);
    }
    if let Some(result) = dispatch_lockdown::dispatch(core, parts)? {
        return Ok(result);
    }
    match parts {
        ["PING"] => Ok(core.ping_mode()),
        // 6.1.0 Module B: worker crash-storm sensor command surface.
        ["WORKER_GUARD_SET", state] => core.worker_guard.set_enabled(state),
        ["WORKER_GUARD_COMM_ADD", comm] => core.worker_guard.comm_add(comm),
        ["WORKER_GUARD_COMM_DEL", comm] => core.worker_guard.comm_del(comm),
        ["WORKER_GUARD_UID_ADD", uid] => core.worker_guard.uid_add(uid),
        ["WORKER_GUARD_UID_DEL", uid] => core.worker_guard.uid_del(uid),
        ["WORKER_GUARD_EVENTS"] => core.worker_guard.take_events(),
        ["WORKER_GUARD_STATUS"] => core.worker_guard.status(),
        // V6.3.0 AP-0: kernel sensor self-protection. Observe-only status and a
        // bounded tamper queue; the control plane owns XDR semantics.
        ["SELF_GUARD_STATUS"] => Ok(core.self_defense.status()),
        ["SELF_TAMPER_EVENTS"] => core.self_defense.take_events(),
        ["SELF_GUARD_SET", state] => core.self_defense.set_enabled_token(state),
        // V6.3.0 AP-1: executable-inode trust gate + TTL malware inode locks.
        ["EXEC_INODE_STATUS"] => Ok(core.exec_inode.status()),
        ["EXEC_INODE_ALLOW_ADD", path, flags] => core.exec_inode.allow_add(path, flags),
        ["EXEC_INODE_ALLOW_DEL", dev, ino] => core.exec_inode.allow_del(dev, ino),
        ["EXEC_INODE_CLEAR"] => core.exec_inode.clear(),
        ["EXEC_INODE_EVENTS"] => core.exec_inode.take_events(),
        // V6.3.0 AP-4: io_uring tracepoints/LSM hooks and pre-stealth LKM capture.
        ["KERNEL_HOOK_EPOCH"] => Ok(core.kernel_hooks.epoch()),
        ["KERNEL_HOOK_STATUS"] => Ok(core.kernel_hooks.status()),
        ["KERNEL_HOOK_EVENTS"] => core.kernel_hooks.take_events(),
        ["KERNEL_HOOK_SET", state] => core.kernel_hooks.set_enabled_token(state),
        // V6.3.0 AP-5: persistence/peripheral integrity guard.
        ["PERSIST_GUARD_STATUS"] => Ok(core.persistence.status()),
        ["PERSIST_GUARD_EVENTS"] => core.persistence.take_events(),
        ["PERSIST_GUARD_SET", state] => core.persistence.set_enabled_token(state),
        ["PERSIST_BASELINE"] => core.persistence.baseline(),
        // V6.3.0 AP-6: phase-2 ingress RX observer and bounded DNS capture.
        ["STYX_INGRESS_STATUS"] => Ok(core.styx_ingress.status()),
        ["DNS_SET", state] => core.dns_capture.set_enabled_token(state),
        ["DNS_EVENTS"] => core.dns_capture.take_events(),
        ["DNS_STATUS"] => Ok(core.dns_capture.status()),
        // V6.3.0 AP-9 (S12): independent high-priority security evidence ring and
        // the aggregated telemetry flood-suppression facts.
        ["SEC_CRIT_STATUS"] => Ok(core.sec_crit.status()),
        ["SEC_CRIT_EVENTS"] => core.sec_crit.take_events(),
        ["SEC_CRIT_SET", state] => core.sec_crit.set_enabled_token(state),
        _ => Err("unknown command".into()),
    }
}

pub(crate) fn handle_connection(
    mut stream: UnixStream,
    core: &mut KernelCore,
    quarantine: &QuarantineBroker,
    scanner: &MalwareScanner,
    canary: &CanaryBroker,
    control_uid: u32,
    auth_key: &[u8],
    replay: &mut ReplayGuard,
) {
    match peer_uid(&stream) {
        Ok(uid) if uid == control_uid => {}
        Ok(uid) => {
            eprintln!("rejected IPC peer uid={uid}");
            return;
        }
        Err(error) => {
            eprintln!("IPC peer credential check failed: {error}");
            return;
        }
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let cloned = match stream.try_clone() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("IPC clone failed: {error}");
            return;
        }
    };
    let mut bounded = BufReader::new(cloned).take(MAX_REQUEST_BYTES + 1);
    let mut request = Vec::with_capacity(256);
    if bounded.read_until(b'\n', &mut request).is_err()
        || request.len() as u64 > MAX_REQUEST_BYTES
        || !request.ends_with(b"\n")
        || request.contains(&0)
        || request.contains(&MAC_FIELD_SEPARATOR)
    {
        eprintln!("rejected malformed IPC request");
        return;
    }
    let line = match std::str::from_utf8(&request) {
        Ok(value) => value.trim_end(),
        Err(_) => {
            eprintln!("rejected non-UTF8 IPC request");
            return;
        }
    };
    let fields: Vec<&str> = line.split(' ').collect();
    if fields.len() < 5 || fields.len() > 20 || fields.iter().any(|field| field.is_empty()) {
        eprintln!("rejected invalid IPC field count");
        return;
    }
    let protocol = fields[0];
    let timestamp = fields[1];
    let nonce = fields[2];
    let supplied_mac = fields[fields.len() - 1];
    if protocol != PROTOCOL || !valid_nonce(nonce) {
        eprintln!("rejected invalid IPC protocol header");
        return;
    }
    let now = match unix_seconds() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("system clock unavailable: {error}");
            return;
        }
    };
    let stamp = match timestamp.parse::<u64>() {
        Ok(value) => value,
        Err(_) => {
            eprintln!("rejected invalid IPC timestamp");
            return;
        }
    };
    if let Some(reason) = request_timestamp_error(now, stamp) {
        eprintln!("rejected IPC request with a {reason} timestamp");
        return;
    }
    if verify_mac(auth_key, &fields[..fields.len() - 1], supplied_mac).is_err() {
        eprintln!("rejected unauthenticated IPC request");
        return;
    }
    if !replay.accept(nonce, now, stamp) {
        eprintln!("rejected replayed IPC request");
        let _ = write_response(&mut stream, auth_key, nonce, "ERR", "request rejected");
        return;
    }

    let command = &fields[3..fields.len() - 1];
    match process_command(core, quarantine, scanner, canary, command) {
        Ok(message) => {
            if let Err(error) = write_response(&mut stream, auth_key, nonce, "OK", &message) {
                eprintln!("IPC response failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("IPC command rejected: {error}");
            let _ = write_response(&mut stream, auth_key, nonce, "ERR", "request rejected");
        }
    }
}
