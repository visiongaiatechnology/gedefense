use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        HashMap as AyaHashMap, MapData, MapError, RingBuf,
    },
    programs::{
        tc, CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, Lsm, SchedClassifier, TcAttachType,
        TracePoint, Xdp, XdpMode,
    },
    Btf, Ebpf,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gedefense_common::{
    CellLsmDenyEvent, EgressDropEvent, ExecEvent, ACTION_DROP, CELL_LSM_DENY_NON_UNIX_SOCKET,
    EXEC_COMM_BYTES, NETWORK_ADDRESS_BYTES, NETWORK_FAMILY_V4, NETWORK_FAMILY_V6,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
mod malware;
mod process_control;
mod quarantine;
use malware::{handle_user_scan, MalwareScanner};
#[cfg(test)]
use process_control::valid_rule_token;
use process_control::{lookup_identity, peer_uid, pidfd_signal};
use quarantine::{FileIdentity, QuarantineBroker};
use std::{
    collections::{HashSet, VecDeque},
    env,
    error::Error,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;
type HmacSha256 = Hmac<Sha256>;

const PROTOCOL: &str = "VGT3";
const MAX_REQUEST_BYTES: u64 = 4096;
const MAX_RESPONSE_BYTES: usize = 2048;
const CLOCK_WINDOW_SECS: u64 = 30;
const REPLAY_CACHE_CAPACITY: usize = 4096;
const MAX_EXEC_EVENTS_PER_RESPONSE: usize = 24;
const MAX_EGRESS_EVENTS_PER_RESPONSE: usize = 24;
const MAX_CELL_LSM_EVENTS_PER_RESPONSE: usize = 24;
const HARDENING_FILE: &str = "/etc/sysctl.d/90-vgt-gedefense.conf";
const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;

const HARDENING_SERVER: &str =
    "# Managed atomically by VGT GeDefense. Manual edits are rejected.\n\
fs.protected_fifos = 2\n\
fs.protected_regular = 2\n\
fs.suid_dumpable = 0\n\
kernel.dmesg_restrict = 1\n\
kernel.kptr_restrict = 2\n\
kernel.randomize_va_space = 2\n\
net.ipv4.conf.all.accept_redirects = 0\n\
net.ipv4.conf.all.send_redirects = 0\n\
net.ipv4.conf.default.accept_redirects = 0\n\
net.ipv4.conf.default.send_redirects = 0\n\
net.ipv4.tcp_syncookies = 1\n\
net.ipv6.conf.all.accept_redirects = 0\n\
net.ipv6.conf.default.accept_redirects = 0\n";

const HARDENING_ASTRAEAOS: &str =
    "# Managed atomically by VGT GeDefense. Manual edits are rejected.\n\
fs.protected_fifos = 2\n\
fs.protected_regular = 2\n\
fs.suid_dumpable = 0\n\
kernel.dmesg_restrict = 1\n\
kernel.kptr_restrict = 2\n\
kernel.randomize_va_space = 2\n\
kernel.unprivileged_bpf_disabled = 1\n\
kernel.yama.ptrace_scope = 2\n\
net.ipv4.conf.all.accept_redirects = 0\n\
net.ipv4.conf.all.send_redirects = 0\n\
net.ipv4.conf.default.accept_redirects = 0\n\
net.ipv4.conf.default.send_redirects = 0\n\
net.ipv4.tcp_syncookies = 1\n\
net.ipv6.conf.all.accept_redirects = 0\n\
net.ipv6.conf.default.accept_redirects = 0\n";

const HARDENING_CUSTOM_MASK: u16 = 0x03ff;

fn hardening_content(profile: &str) -> Option<String> {
    match profile {
        "linux-server-balanced" => Some(HARDENING_SERVER.to_owned()),
        "astraeaos-workstation-strict" => Some(HARDENING_ASTRAEAOS.to_owned()),
        _ => custom_hardening_content(profile),
    }
}

fn custom_hardening_content(profile: &str) -> Option<String> {
    let encoded = profile.strip_prefix("astraeaos-custom-")?;
    if encoded.len() != 4 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mask = u16::from_str_radix(encoded, 16).ok()?;
    if mask == 0 || mask & !HARDENING_CUSTOM_MASK != 0 {
        return None;
    }
    let mut content = format!(
        "# Managed atomically by VGT GeDefense. Manual edits are rejected.\n# Profile: {profile}\n"
    );
    let controls: &[(u16, &[(&str, &str)])] = &[
        (1 << 0, &[("kernel.randomize_va_space", "2")]),
        (1 << 1, &[("kernel.kptr_restrict", "2")]),
        (1 << 2, &[("kernel.dmesg_restrict", "1")]),
        (1 << 3, &[("kernel.yama.ptrace_scope", "2")]),
        (1 << 4, &[("kernel.unprivileged_bpf_disabled", "1")]),
        (
            1 << 5,
            &[("fs.protected_fifos", "2"), ("fs.protected_regular", "2")],
        ),
        (1 << 6, &[("fs.suid_dumpable", "0")]),
        (1 << 7, &[("net.ipv4.tcp_syncookies", "1")]),
        (
            1 << 8,
            &[
                ("net.ipv4.conf.all.accept_redirects", "0"),
                ("net.ipv4.conf.all.send_redirects", "0"),
                ("net.ipv4.conf.default.accept_redirects", "0"),
                ("net.ipv4.conf.default.send_redirects", "0"),
            ],
        ),
        (
            1 << 9,
            &[
                ("net.ipv6.conf.all.accept_redirects", "0"),
                ("net.ipv6.conf.default.accept_redirects", "0"),
            ],
        ),
    ];
    let mut values = Vec::new();
    for (bit, entries) in controls {
        if mask & bit != 0 {
            values.extend_from_slice(entries);
        }
    }
    values.sort_unstable_by_key(|(key, _)| *key);
    for (key, value) in values {
        content.push_str(key);
        content.push_str(" = ");
        content.push_str(value);
        content.push('\n');
    }
    Some(content)
}

fn recognized_hardening_state(content: &str) -> Option<String> {
    for profile in ["linux-server-balanced", "astraeaos-workstation-strict"] {
        if hardening_content(profile).as_deref() == Some(content) {
            return Some(profile.to_owned());
        }
    }
    let profile = content
        .lines()
        .find_map(|line| line.strip_prefix("# Profile: "))?;
    if hardening_content(profile).as_deref() == Some(content) {
        return Some(profile.to_owned());
    }
    None
}

fn hardening_file_state() -> Result<String, BoxError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(HARDENING_FILE)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok("absent".to_owned())
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err("persistent hardening state is not a bounded regular file".into());
    }
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content)?;
    recognized_hardening_state(&content)
        .ok_or_else(|| "persistent hardening state is not managed by GeDefense".into())
}

fn hardening_temp_name() -> Result<CString, BoxError> {
    let mut random = [0u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(CString::new(format!(
        ".90-vgt-gedefense.conf.{}.{}",
        std::process::id(),
        hex::encode(random)
    ))?)
}

fn renameat2_names(
    directory_fd: i32,
    from: &CString,
    to: &CString,
    flags: u32,
) -> Result<(), BoxError> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory_fd,
            from.as_ptr(),
            directory_fd,
            to.as_ptr(),
            flags,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn compare_set_hardening_file(expected: &str, desired: &str) -> Result<String, BoxError> {
    if expected != "absent" && hardening_content(expected).is_none() {
        return Err("persistent hardening expected state is invalid".into());
    }
    if desired != "absent" && hardening_content(desired).is_none() {
        return Err("persistent hardening desired state is invalid".into());
    }
    if hardening_file_state()? != expected {
        return Err("persistent hardening compare-set precondition failed".into());
    }
    if expected == desired {
        return Ok(desired.to_owned());
    }
    let directory = File::open("/etc/sysctl.d")?;
    let directory_fd = std::os::fd::AsRawFd::as_raw_fd(&directory);
    let target_name = CString::new("90-vgt-gedefense.conf")?;
    let temporary_name = hardening_temp_name()?;
    let temporary_path =
        Path::new("/etc/sysctl.d").join(std::ffi::OsStr::from_bytes(temporary_name.as_bytes()));

    if desired == "absent" {
        renameat2_names(
            directory_fd,
            &target_name,
            &temporary_name,
            RENAME_NOREPLACE,
        )?;
        let captured = hardening_file_state_at(&temporary_path)?;
        if captured != expected {
            let _ = renameat2_names(
                directory_fd,
                &temporary_name,
                &target_name,
                RENAME_NOREPLACE,
            );
            return Err("persistent hardening source changed during removal".into());
        }
        fs::remove_file(&temporary_path)?;
        directory.sync_all()?;
        return Ok("absent".to_owned());
    }

    let content = hardening_content(desired).ok_or("hardening profile is invalid")?;
    {
        let mut temporary = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary_path)?;
        temporary.write_all(content.as_bytes())?;
        temporary.sync_all()?;
    }
    let result = (|| {
        if expected == "absent" {
            renameat2_names(
                directory_fd,
                &temporary_name,
                &target_name,
                RENAME_NOREPLACE,
            )?;
            if hardening_file_state().ok().as_deref() != Some(desired) {
                if hardening_file_state_at(Path::new(HARDENING_FILE))
                    .ok()
                    .as_deref()
                    == Some(desired)
                {
                    let _ = renameat2_names(
                        directory_fd,
                        &target_name,
                        &temporary_name,
                        RENAME_NOREPLACE,
                    );
                }
                return Err("persistent hardening post-state verification failed".into());
            }
        } else {
            renameat2_names(directory_fd, &temporary_name, &target_name, RENAME_EXCHANGE)?;
            let captured = hardening_file_state_at(&temporary_path)?;
            if captured != expected {
                let _ =
                    renameat2_names(directory_fd, &temporary_name, &target_name, RENAME_EXCHANGE);
                return Err("persistent hardening source changed during replacement".into());
            }
            if hardening_file_state().ok().as_deref() != Some(desired) {
                let _ =
                    renameat2_names(directory_fd, &temporary_name, &target_name, RENAME_EXCHANGE);
                return Err("persistent hardening post-state verification failed".into());
            }
            fs::remove_file(&temporary_path)?;
        }
        directory.sync_all()?;
        Ok::<(), BoxError>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result?;
    Ok(desired.to_owned())
}

fn hardening_file_state_at(path: &Path) -> Result<String, BoxError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err("captured hardening state is invalid".into());
    }
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    recognized_hardening_state(&content)
        .ok_or_else(|| "captured hardening state is unmanaged".into())
}

fn sysctl_spec(key: &str) -> Option<(&'static str, &'static [&'static str])> {
    match key {
        "kernel.kptr_restrict" => Some(("/proc/sys/kernel/kptr_restrict", &["0", "1", "2"])),
        "kernel.dmesg_restrict" => Some(("/proc/sys/kernel/dmesg_restrict", &["0", "1"])),
        "kernel.randomize_va_space" => {
            Some(("/proc/sys/kernel/randomize_va_space", &["0", "1", "2"]))
        }
        "kernel.yama.ptrace_scope" => {
            Some(("/proc/sys/kernel/yama/ptrace_scope", &["0", "1", "2", "3"]))
        }
        "kernel.unprivileged_bpf_disabled" => Some((
            "/proc/sys/kernel/unprivileged_bpf_disabled",
            &["0", "1", "2"],
        )),
        "fs.protected_fifos" => Some(("/proc/sys/fs/protected_fifos", &["0", "1", "2"])),
        "fs.protected_regular" => Some(("/proc/sys/fs/protected_regular", &["0", "1", "2"])),
        "fs.suid_dumpable" => Some(("/proc/sys/fs/suid_dumpable", &["0", "1", "2"])),
        "net.ipv4.tcp_syncookies" => Some(("/proc/sys/net/ipv4/tcp_syncookies", &["0", "1", "2"])),
        "net.ipv4.conf.all.accept_redirects" => {
            Some(("/proc/sys/net/ipv4/conf/all/accept_redirects", &["0", "1"]))
        }
        "net.ipv4.conf.default.accept_redirects" => Some((
            "/proc/sys/net/ipv4/conf/default/accept_redirects",
            &["0", "1"],
        )),
        "net.ipv4.conf.all.send_redirects" => {
            Some(("/proc/sys/net/ipv4/conf/all/send_redirects", &["0", "1"]))
        }
        "net.ipv4.conf.default.send_redirects" => Some((
            "/proc/sys/net/ipv4/conf/default/send_redirects",
            &["0", "1"],
        )),
        "net.ipv6.conf.all.accept_redirects" => {
            Some(("/proc/sys/net/ipv6/conf/all/accept_redirects", &["0", "1"]))
        }
        "net.ipv6.conf.default.accept_redirects" => Some((
            "/proc/sys/net/ipv6/conf/default/accept_redirects",
            &["0", "1"],
        )),
        _ => None,
    }
}

fn read_sysctl_value(key: &str) -> Result<String, BoxError> {
    let (path, allowed) = sysctl_spec(key).ok_or("sysctl key is not allowlisted")?;
    let value = fs::read_to_string(path)?;
    if value.len() > 32 {
        return Err("sysctl value exceeds response boundary".into());
    }
    let value = value.trim();
    if !allowed.contains(&value) {
        return Err("sysctl contains a value outside its typed domain".into());
    }
    Ok(value.to_owned())
}

fn compare_set_sysctl(key: &str, expected: &str, desired: &str) -> Result<String, BoxError> {
    let (path, allowed) = sysctl_spec(key).ok_or("sysctl key is not allowlisted")?;
    if !allowed.contains(&expected) || !allowed.contains(&desired) {
        return Err("sysctl value is outside its typed domain".into());
    }
    let current = read_sysctl_value(key)?;
    if current != expected {
        return Err("sysctl compare-set precondition failed".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(desired.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    drop(file);
    let verified = read_sysctl_value(key)?;
    if verified != desired {
        return Err("sysctl post-state verification failed".into());
    }
    Ok(verified)
}

struct KernelCore {
    _ebpf: Ebpf,
    exec_events: RingBuf<MapData>,
    egress_events: RingBuf<MapData>,
    cell_lsm_events: RingBuf<MapData>,
    cell_lsm_policies: AyaHashMap<MapData, u64, u8>,
    allow_v4: LpmTrie<MapData, [u8; 4], u8>,
    allow_v6: LpmTrie<MapData, [u8; 16], u8>,
    v4: LpmTrie<MapData, [u8; 4], u8>,
    v6: LpmTrie<MapData, [u8; 16], u8>,
    blocked: HashSet<Target>,
    mode: String,
    cell_lsm_attached: bool,
    cell_policy_epoch: String,
}

impl KernelCore {
    fn load(object: &str, iface: &str, require_cell_lsm: bool) -> Result<Self, BoxError> {
        let mut ebpf = Ebpf::load_file(object)?;
        let xdp_mode = {
            let program: &mut Xdp = ebpf
                .program_mut("gedefense_xdp")
                .ok_or("XDP program missing")?
                .try_into()?;
            program.load()?;
            match program.attach(iface, XdpMode::Driver) {
                Ok(_) => Some("native"),
                Err(native) => {
                    eprintln!("native XDP unavailable ({native}); using generic mode");
                    match program.attach(iface, XdpMode::Skb) {
                        Ok(_) => Some("generic"),
                        Err(generic) => {
                            eprintln!(
                                "generic XDP unavailable ({generic}); using TC ingress kernel enforcement"
                            );
                            None
                        }
                    }
                }
            }
        };
        let ingress_mode = match xdp_mode {
            Some(mode) => mode,
            None => {
                if let Err(error) = tc::qdisc_add_clsact(iface) {
                    if !matches!(error, tc::TcError::AlreadyAttached) {
                        return Err(error.into());
                    }
                }
                let program: &mut SchedClassifier = ebpf
                    .program_mut("gedefense_tc_ingress")
                    .ok_or("TC ingress program missing")?
                    .try_into()?;
                program.load()?;
                program.attach_with_options(
                    iface,
                    TcAttachType::Ingress,
                    tc::TcAttachOptions::Netlink(tc::NlOptions::default()),
                )?;
                "tc-ingress"
            }
        };
        let exec_program: &mut TracePoint = ebpf
            .program_mut("gedefense_exec")
            .ok_or("process exec tracepoint program missing")?
            .try_into()?;
        exec_program.load()?;
        if let Err(error) = exec_program.attach("sched", "sched_process_exec") {
            eprintln!("Process exec tracepoint unavailable ({error}); falling back to fanotify and procfs monitoring");
        }
        let cgroup = File::open("/sys/fs/cgroup")?;
        let egress_program: &mut CgroupSkb = ebpf
            .program_mut("gedefense_egress")
            .ok_or("cgroup egress program missing")?
            .try_into()?;
        egress_program.load()?;
        egress_program.attach(
            cgroup,
            CgroupSkbAttachType::Egress,
            CgroupAttachMode::AllowMultiple,
        )?;
        let cell_lsm_attached = match attach_cell_socket_lsm(&mut ebpf) {
            Ok(()) => true,
            Err(error) if !require_cell_lsm => {
                eprintln!(
                    "BPF LSM unavailable ({error}); Gaia Cell host socket reinforcement disabled"
                );
                false
            }
            Err(error) => {
                return Err(format!("required Gaia Cell BPF LSM attach failed: {error}").into())
            }
        };
        let exec_events =
            RingBuf::try_from(ebpf.take_map("EXEC_EVENTS").ok_or("EXEC_EVENTS missing")?)?;
        let egress_events = RingBuf::try_from(
            ebpf.take_map("EGRESS_EVENTS")
                .ok_or("EGRESS_EVENTS missing")?,
        )?;
        let cell_lsm_events = RingBuf::try_from(
            ebpf.take_map("CELL_LSM_EVENTS")
                .ok_or("CELL_LSM_EVENTS missing")?,
        )?;
        let cell_lsm_policies = AyaHashMap::try_from(
            ebpf.take_map("CELL_LSM_POLICIES")
                .ok_or("CELL_LSM_POLICIES missing")?,
        )?;
        let allow_v4 = LpmTrie::try_from(
            ebpf.take_map("ALLOWLIST_V4")
                .ok_or("ALLOWLIST_V4 missing")?,
        )?;
        let allow_v6 = LpmTrie::try_from(
            ebpf.take_map("ALLOWLIST_V6")
                .ok_or("ALLOWLIST_V6 missing")?,
        )?;
        let v4 = LpmTrie::try_from(
            ebpf.take_map("BLOCKLIST_V4")
                .ok_or("BLOCKLIST_V4 missing")?,
        )?;
        let v6 = LpmTrie::try_from(
            ebpf.take_map("BLOCKLIST_V6")
                .ok_or("BLOCKLIST_V6 missing")?,
        )?;
        let mode = if cell_lsm_attached {
            format!("{ingress_mode}+bpf-lsm-cell")
        } else {
            ingress_mode.to_owned()
        };
        Ok(Self {
            _ebpf: ebpf,
            exec_events,
            egress_events,
            cell_lsm_events,
            cell_lsm_policies,
            allow_v4,
            allow_v6,
            v4,
            v6,
            blocked: HashSet::new(),
            mode,
            cell_lsm_attached,
            cell_policy_epoch: random_epoch()?,
        })
    }

    fn cell_policy_epoch(&self) -> Result<String, BoxError> {
        self.require_cell_lsm()?;
        Ok(self.cell_policy_epoch.clone())
    }

    fn set_cell_policy(&mut self, cgroup_id: &str, flags: &str) -> Result<String, BoxError> {
        self.require_cell_lsm()?;
        let cgroup_id = parse_cell_cgroup_id(cgroup_id)?;
        let flags = parse_cell_policy_flags(flags)?;
        self.cell_lsm_policies.insert(cgroup_id, flags, 0)?;
        Ok("applied".to_owned())
    }

    fn delete_cell_policy(&mut self, cgroup_id: &str) -> Result<String, BoxError> {
        self.require_cell_lsm()?;
        let cgroup_id = parse_cell_cgroup_id(cgroup_id)?;
        match self.cell_lsm_policies.remove(&cgroup_id) {
            Ok(()) | Err(MapError::KeyNotFound) => Ok("deleted".to_owned()),
            Err(error) => Err(error.into()),
        }
    }

    fn take_cell_lsm_events(&mut self) -> Result<String, BoxError> {
        self.require_cell_lsm()?;
        let mut encoded = Vec::with_capacity(MAX_CELL_LSM_EVENTS_PER_RESPONSE);
        while encoded.len() < MAX_CELL_LSM_EVENTS_PER_RESPONSE {
            let Some(item) = self.cell_lsm_events.next() else {
                break;
            };
            if item.len() != std::mem::size_of::<CellLsmDenyEvent>() {
                return Err("kernel Gaia Cell LSM event has invalid size".into());
            }
            let cgroup_id = u64::from_ne_bytes(item[0..8].try_into()?);
            let pid = u32::from_ne_bytes(item[8..12].try_into()?);
            let uid = u32::from_ne_bytes(item[12..16].try_into()?);
            let family = i32::from_ne_bytes(item[16..20].try_into()?);
            let action = item[20];
            if cgroup_id == 0
                || pid == 0
                || family <= 0
                || family > i32::from(u8::MAX)
                || family == libc::AF_UNIX
                || action != ACTION_DROP
            {
                return Err("kernel Gaia Cell LSM event has invalid metadata".into());
            }
            encoded.push(format!("{cgroup_id}:{pid}:{uid}:{family}"));
        }
        if encoded.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(encoded.join(","))
        }
    }

    fn require_cell_lsm(&self) -> Result<(), BoxError> {
        if self.cell_lsm_attached {
            Ok(())
        } else {
            Err("Gaia Cell BPF LSM is unavailable".into())
        }
    }

    fn take_exec_events(&mut self) -> Result<String, BoxError> {
        let mut encoded = Vec::with_capacity(MAX_EXEC_EVENTS_PER_RESPONSE);
        while encoded.len() < MAX_EXEC_EVENTS_PER_RESPONSE {
            let Some(item) = self.exec_events.next() else {
                break;
            };
            if item.len() != std::mem::size_of::<ExecEvent>() {
                return Err("kernel exec event has invalid size".into());
            }
            let pid = u32::from_ne_bytes(item[0..4].try_into()?);
            let uid = u32::from_ne_bytes(item[4..8].try_into()?);
            let gid = u32::from_ne_bytes(item[8..12].try_into()?);
            let comm: [u8; EXEC_COMM_BYTES] = item[12..12 + EXEC_COMM_BYTES].try_into()?;
            let comm_len = comm
                .iter()
                .position(|value| *value == 0)
                .unwrap_or(EXEC_COMM_BYTES);
            encoded.push(format!(
                "{pid}:{uid}:{gid}:{}",
                hex::encode(&comm[..comm_len])
            ));
        }
        if encoded.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(encoded.join(","))
        }
    }

    fn take_egress_events(&mut self) -> Result<String, BoxError> {
        let mut encoded = Vec::with_capacity(MAX_EGRESS_EVENTS_PER_RESPONSE);
        while encoded.len() < MAX_EGRESS_EVENTS_PER_RESPONSE {
            let Some(item) = self.egress_events.next() else {
                break;
            };
            if item.len() != std::mem::size_of::<EgressDropEvent>() {
                return Err("kernel egress event has invalid size".into());
            }
            let pid = u32::from_ne_bytes(item[0..4].try_into()?);
            let uid = u32::from_ne_bytes(item[4..8].try_into()?);
            let family = item[8];
            let protocol = item[9];
            let action = item[10];
            if action != ACTION_DROP || !matches!(family, NETWORK_FAMILY_V4 | NETWORK_FAMILY_V6) {
                return Err("kernel egress event has invalid metadata".into());
            }
            let address_len = if family == NETWORK_FAMILY_V4 {
                4
            } else {
                NETWORK_ADDRESS_BYTES
            };
            let destination = &item[12..12 + address_len];
            let comm_start = 12 + NETWORK_ADDRESS_BYTES;
            let comm: [u8; EXEC_COMM_BYTES] =
                item[comm_start..comm_start + EXEC_COMM_BYTES].try_into()?;
            let comm_len = comm
                .iter()
                .position(|value| *value == 0)
                .unwrap_or(EXEC_COMM_BYTES);
            encoded.push(format!(
                "{pid}:{uid}:{family}:{protocol}:{}:{}",
                hex::encode(destination),
                hex::encode(&comm[..comm_len])
            ));
        }
        if encoded.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(encoded.join(","))
        }
    }

    fn add(&mut self, target: &str) -> Result<(), BoxError> {
        let target = parse_target(target)?;
        match target {
            Target::V4(ip, prefix) => {
                self.v4
                    .insert(&Key::new(prefix, ip.octets()), ACTION_DROP, 0)?;
            }
            Target::V6(ip, prefix) => {
                self.v6
                    .insert(&Key::new(prefix, ip.octets()), ACTION_DROP, 0)?;
            }
        }
        self.blocked.insert(target);
        Ok(())
    }

    fn del(&mut self, target: &str) -> Result<(), BoxError> {
        let target = parse_target(target)?;
        match target {
            Target::V4(ip, prefix) => self.v4.remove(&Key::new(prefix, ip.octets()))?,
            Target::V6(ip, prefix) => self.v6.remove(&Key::new(prefix, ip.octets()))?,
        }
        self.blocked.remove(&target);
        Ok(())
    }

    fn clear_blocklist(&mut self) -> Result<(), BoxError> {
        let targets: Vec<Target> = self.blocked.iter().copied().collect();
        let mut failures = 0usize;
        for target in targets {
            let result = match target {
                Target::V4(ip, prefix) => self.v4.remove(&Key::new(prefix, ip.octets())),
                Target::V6(ip, prefix) => self.v6.remove(&Key::new(prefix, ip.octets())),
            };
            match result {
                Ok(()) => {
                    self.blocked.remove(&target);
                }
                Err(error) => {
                    failures += 1;
                    eprintln!("kernel blocklist clear failed for {target:?}: {error}");
                }
            }
        }
        if failures == 0 {
            Ok(())
        } else {
            Err(format!("kernel blocklist clear retained {failures} entries").into())
        }
    }

    fn allow_add(&mut self, target: &str) -> Result<(), BoxError> {
        match parse_target(target)? {
            Target::V4(ip, prefix) => {
                self.allow_v4.insert(&Key::new(prefix, ip.octets()), 1, 0)?;
            }
            Target::V6(ip, prefix) => {
                self.allow_v6.insert(&Key::new(prefix, ip.octets()), 1, 0)?;
            }
        }
        Ok(())
    }

    fn allow_del(&mut self, target: &str) -> Result<(), BoxError> {
        match parse_target(target)? {
            Target::V4(ip, prefix) => self.allow_v4.remove(&Key::new(prefix, ip.octets()))?,
            Target::V6(ip, prefix) => self.allow_v6.remove(&Key::new(prefix, ip.octets()))?,
        }
        Ok(())
    }
}

fn attach_cell_socket_lsm(ebpf: &mut Ebpf) -> Result<(), BoxError> {
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = ebpf
        .program_mut("gedefense_cell_socket_create")
        .ok_or("Gaia Cell socket LSM program missing")?
        .try_into()?;
    program.load("socket_create", &btf)?;
    program.attach()?;
    Ok(())
}

fn random_epoch() -> Result<String, BoxError> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}

fn parse_cell_cgroup_id(value: &str) -> Result<u64, BoxError> {
    let parsed = value.parse::<u64>()?;
    if parsed == 0 {
        return Err("Gaia Cell cgroup ID must be non-zero".into());
    }
    Ok(parsed)
}

fn parse_cell_policy_flags(value: &str) -> Result<u8, BoxError> {
    let parsed = value.parse::<u8>()?;
    if parsed != CELL_LSM_DENY_NON_UNIX_SOCKET {
        return Err("Gaia Cell LSM policy flags are invalid".into());
    }
    Ok(parsed)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Target {
    V4(Ipv4Addr, u32),
    V6(Ipv6Addr, u32),
}

fn parse_target(value: &str) -> Result<Target, BoxError> {
    let (ip, prefix) = match value.split_once('/') {
        Some((address, raw_prefix)) => (address, Some(raw_prefix.parse::<u32>()?)),
        None => (value, None),
    };
    match ip.parse::<IpAddr>()? {
        IpAddr::V4(address) => {
            let prefix = prefix.unwrap_or(32);
            if prefix > 32 {
                return Err("invalid IPv4 prefix".into());
            }
            let bits = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = Ipv4Addr::from(bits & mask);
            if network.is_unspecified() {
                return Err("unspecified IPv4 network is forbidden".into());
            }
            Ok(Target::V4(network, prefix))
        }
        IpAddr::V6(address) => {
            let prefix = prefix.unwrap_or(128);
            if prefix > 128 {
                return Err("invalid IPv6 prefix".into());
            }
            let bits = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let network = Ipv6Addr::from(bits & mask);
            if network.is_unspecified() {
                return Err("unspecified IPv6 network is forbidden".into());
            }
            Ok(Target::V6(network, prefix))
        }
    }
}

fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn load_secret_key(path: &str, control_gid: u32, label: &str) -> Result<Vec<u8>, BoxError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
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
    let key = fs::read(path)?;
    if key.len() != 32 {
        return Err(format!("{label} must contain exactly 32 bytes").into());
    }
    Ok(key)
}

fn load_auth_key(path: &str, control_gid: u32) -> Result<Vec<u8>, BoxError> {
    load_secret_key(path, control_gid, "IPC authentication key")
}

fn parse_quarantine_identity(token: &str) -> Result<FileIdentity, BoxError> {
    let fields: Vec<&str> = token
        .strip_prefix("v1:")
        .ok_or("quarantine identity version is invalid")?
        .split(':')
        .collect();
    FileIdentity::parse(&fields)
}

fn unix_seconds() -> Result<u64, BoxError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn authenticated_mac(key: &[u8], fields: &[&str]) -> Result<Vec<u8>, BoxError> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            mac.update(&[0x1f]);
        }
        mac.update(field.as_bytes());
    }
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_mac(key: &[u8], fields: &[&str], encoded_mac: &str) -> Result<(), BoxError> {
    let supplied = hex::decode(encoded_mac)?;
    let mut mac = HmacSha256::new_from_slice(key)?;
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            mac.update(&[0x1f]);
        }
        mac.update(field.as_bytes());
    }
    mac.verify_slice(&supplied)
        .map_err(|_| "request authentication failed".into())
}

struct ReplayGuard {
    set: HashSet<String>,
    order: VecDeque<(String, u64)>,
}

impl ReplayGuard {
    fn new() -> Self {
        Self {
            set: HashSet::with_capacity(REPLAY_CACHE_CAPACITY),
            order: VecDeque::with_capacity(REPLAY_CACHE_CAPACITY),
        }
    }

    fn accept(&mut self, nonce: &str, now: u64) -> bool {
        while let Some((old_nonce, timestamp)) = self.order.front() {
            if now.saturating_sub(*timestamp) <= CLOCK_WINDOW_SECS {
                break;
            }
            let old_nonce = old_nonce.clone();
            self.order.pop_front();
            self.set.remove(&old_nonce);
        }
        if self.set.contains(nonce) || self.order.len() >= REPLAY_CACHE_CAPACITY {
            return false;
        }
        self.set.insert(nonce.to_owned());
        self.order.push_back((nonce.to_owned(), now));
        true
    }
}

fn write_response(
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
    parts: &[&str],
) -> Result<String, BoxError> {
    match parts {
        ["PING"] => Ok(core.mode.to_string()),
        ["CELL_POLICY_EPOCH"] => core.cell_policy_epoch(),
        ["CELL_POLICY_SET", cgroup_id, flags] => core.set_cell_policy(cgroup_id, flags),
        ["CELL_POLICY_DEL", cgroup_id] => core.delete_cell_policy(cgroup_id),
        ["CELL_LSM_EVENTS"] => core.take_cell_lsm_events(),
        ["EXEC_EVENTS"] => core.take_exec_events(),
        ["EGRESS_EVENTS"] => core.take_egress_events(),
        ["MALWARE_EVENTS"] => scanner.take_events(),
        ["CLEAR_BLOCKLIST"] => core.clear_blocklist().map(|_| "cleared".into()),
        ["VERIFY_EMPTY"] if core.blocked.is_empty() => Ok("empty".into()),
        ["VERIFY_EMPTY"] => Err("blocklist is not empty".into()),
        ["ADD", target] => core.add(target).map(|_| "added".into()),
        ["DEL", target] => core.del(target).map(|_| "deleted".into()),
        ["ALLOW_ADD", target] => core.allow_add(target).map(|_| "allowlisted".into()),
        ["ALLOW_DEL", target] => core
            .allow_del(target)
            .map(|_| "allowlist entry deleted".into()),
        ["SYSCTL_GET", key] => read_sysctl_value(key),
        ["SYSCTL_SET", key, expected, desired] => compare_set_sysctl(key, expected, desired),
        ["HARDENING_GET"] => hardening_file_state(),
        ["HARDENING_SET", expected, desired] => compare_set_hardening_file(expected, desired),
        ["MALWARE_SCAN", path] => scanner.inspect_token(path),
        ["QUARANTINE_INSPECT", path] => quarantine.inspect_token(path),
        ["QUARANTINE_APPLY", path, object_id, identity] => {
            quarantine.quarantine_token(path, object_id, &parse_quarantine_identity(identity)?)
        }
        ["QUARANTINE_VERIFY", object_id, identity] => {
            quarantine.verify_object(object_id, &parse_quarantine_identity(identity)?)
        }
        ["QUARANTINE_RESTORE", path, object_id, identity] => {
            quarantine.restore_token(path, object_id, &parse_quarantine_identity(identity)?)
        }
        ["XDR_STOP", pid, start, rule] => {
            let pid = pid.parse::<i32>()?;
            let start = start.parse::<u64>()?;
            pidfd_signal(pid, start, libc::SIGSTOP, rule).map(|_| "stopped".into())
        }
        ["XDR_CONT", pid, start, rule] | ["XDR_RESUME", pid, start, rule] => {
            let pid = pid.parse::<i32>()?;
            let start = start.parse::<u64>()?;
            pidfd_signal(pid, start, libc::SIGCONT, rule).map(|_| "resumed".into())
        }
        ["XDR_KILL", pid, start, rule] => {
            let pid = pid.parse::<i32>()?;
            let start = start.parse::<u64>()?;
            pidfd_signal(pid, start, libc::SIGKILL, rule).map(|_| "killed".into())
        }
        _ => Err("unknown command".into()),
    }
}

fn handle_connection(
    mut stream: UnixStream,
    core: &mut KernelCore,
    quarantine: &QuarantineBroker,
    scanner: &MalwareScanner,
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
    if now.abs_diff(stamp) > CLOCK_WINDOW_SECS {
        eprintln!("rejected stale IPC request");
        return;
    }
    if verify_mac(auth_key, &fields[..fields.len() - 1], supplied_mac).is_err() {
        eprintln!("rejected unauthenticated IPC request");
        return;
    }
    if !replay.accept(nonce, now) {
        eprintln!("rejected replayed IPC request");
        let _ = write_response(&mut stream, auth_key, nonce, "ERR", "request rejected");
        return;
    }

    let command = &fields[3..fields.len() - 1];
    match process_command(core, quarantine, scanner, command) {
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

fn arg(name: &str, default: &str) -> String {
    let prefix = format!("--{name}=");
    env::args()
        .find_map(|value| value.strip_prefix(&prefix).map(str::to_owned))
        .unwrap_or_else(|| default.to_owned())
}

fn flag(name: &str) -> bool {
    let expected = format!("--{name}");
    env::args().any(|value| value == expected)
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < libc::IFNAMSIZ
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn interface_exists(name: &str) -> bool {
    valid_interface_name(name) && Path::new("/sys/class/net").join(name).exists()
}

fn fallback_interface() -> Result<String, BoxError> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == "lo" || !valid_interface_name(name) {
            continue;
        }
        let state = fs::read_to_string(entry.path().join("operstate")).unwrap_or_default();
        let priority = match state.trim() {
            "up" => 0_u8,
            "unknown" | "dormant" => 1_u8,
            _ => 2_u8,
        };
        candidates.push((priority, name.to_owned()));
    }
    candidates.sort_unstable();
    if let Some((_, name)) = candidates.into_iter().next() {
        eprintln!("no active default route yet; attaching XDP to validated interface {name}");
        return Ok(name);
    }
    if interface_exists("lo") {
        eprintln!("no non-loopback interface present; using loopback fail-safe");
        return Ok("lo".to_owned());
    }
    Err("no validated network interface found".into())
}

fn detect_interface(requested: &str) -> Result<String, BoxError> {
    if requested != "auto" {
        if !interface_exists(requested) {
            return Err("invalid or unavailable interface name".into());
        }
        return Ok(requested.to_owned());
    }
    let routes = fs::read_to_string("/proc/net/route")?;
    for line in routes.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 && fields[1] == "00000000" {
            let flags = u32::from_str_radix(fields[3], 16).unwrap_or(0);
            if flags & 0x1 != 0 && interface_exists(fields[0]) {
                return Ok(fields[0].to_owned());
            }
        }
    }
    fallback_interface()
}

fn main() -> Result<(), BoxError> {
    if env::args().any(|value| value == "--version" || value == "-version") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    eprintln!("GeDefense core startup phase=interface-detection");
    let iface = detect_interface(&arg("interface", "auto"))
        .map_err(|error| std::io::Error::other(format!("interface detection: {error}")))?;
    let object = arg(
        "bpf-object",
        "/opt/vgt/gedefense/current/lib/gedefense/gedefense-ebpf",
    );
    let require_cell_lsm = flag("require-bpf-lsm");
    let socket = arg("socket", "/run/vgt-gedefense/core.sock");
    let scan_socket = arg("scan-socket", "/run/gedefense-scan/scan.sock");
    let auth_key_path = arg("auth-key", "/etc/vgt/gedefense/secrets/core-ipc.key");
    let storage_key_path = arg(
        "storage-key",
        "/etc/vgt/gedefense/secrets/storage-master.key",
    );
    let quarantine_dir = arg(
        "quarantine-dir",
        "/var/lib/vgt/gedefense/quarantine/objects",
    );
    let control_user = arg("control-user", "gedefense");
    let malware_hashes = arg("malware-hashes", "/etc/vgt/gedefense/malware-hashes.sha256");
    eprintln!("GeDefense core startup phase=control-identity");
    let (control_uid, control_gid) = lookup_identity(&control_user)
        .map_err(|error| std::io::Error::other(format!("control identity: {error}")))?;
    eprintln!("GeDefense core startup phase=auth-key");
    let auth_key = load_auth_key(&auth_key_path, control_gid)
        .map_err(|error| std::io::Error::other(format!("auth key: {error}")))?;
    eprintln!("GeDefense core startup phase=quarantine-vault");
    let mut storage_key = load_secret_key(&storage_key_path, control_gid, "storage master key")
        .map_err(|error| std::io::Error::other(format!("storage key: {error}")))?;
    let quarantine = QuarantineBroker::new(&quarantine_dir, &storage_key)
        .map_err(|error| std::io::Error::other(format!("quarantine vault: {error}")))?;
    storage_key.fill(0);
    eprintln!("GeDefense core startup phase=malware-on-access");
    let scanner = MalwareScanner::load(&malware_hashes)
        .map_err(|error| std::io::Error::other(format!("malware signatures: {error}")))?;
    scanner
        .start_on_access(&[Path::new("/home").to_path_buf()])
        .map_err(|error| std::io::Error::other(format!("on-access guard: {error}")))?;
    eprintln!("GeDefense core startup phase=user-scan-socket");
    let scan_parent = Path::new(&scan_socket)
        .parent()
        .ok_or("user scan socket parent is missing")?;
    if scan_parent != Path::new("/run/gedefense-scan") {
        return Err("user scan socket escaped runtime jail".into());
    }
    fs::create_dir_all(scan_parent)?;
    let scan_parent_metadata = fs::symlink_metadata(scan_parent)?;
    if !scan_parent_metadata.is_dir()
        || scan_parent_metadata.file_type().is_symlink()
        || scan_parent_metadata.uid() != 0
    {
        return Err("user scan runtime directory ownership rejected".into());
    }
    fs::set_permissions(scan_parent, fs::Permissions::from_mode(0o755))?;
    let _ = fs::remove_file(&scan_socket);
    let scan_listener = UnixListener::bind(&scan_socket)
        .map_err(|error| std::io::Error::other(format!("user scan IPC bind: {error}")))?;
    fs::set_permissions(&scan_socket, fs::Permissions::from_mode(0o666))
        .map_err(|error| std::io::Error::other(format!("user scan IPC permissions: {error}")))?;
    let scan_worker = scanner.clone();
    std::thread::Builder::new()
        .name("gedefense-user-scan".to_owned())
        .spawn(move || {
            for incoming in scan_listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        if let Err(error) = handle_user_scan(stream, &scan_worker) {
                            eprintln!("GeDefense user scan IPC rejected: {error}");
                        }
                    }
                    Err(error) => {
                        eprintln!("GeDefense user scan IPC fatal: {error}");
                        std::process::abort();
                    }
                }
            }
        })?;
    eprintln!("GeDefense core startup phase=ipc-socket");
    if let Some(parent) = Path::new(&socket).parent() {
        fs::create_dir_all(parent)
            .map_err(|error| std::io::Error::other(format!("IPC directory: {error}")))?;
    }
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)
        .map_err(|error| std::io::Error::other(format!("IPC bind: {error}")))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660))
        .map_err(|error| std::io::Error::other(format!("IPC permissions: {error}")))?;
    let socket_metadata = fs::symlink_metadata(&socket)
        .map_err(|error| std::io::Error::other(format!("IPC metadata: {error}")))?;
    if socket_metadata.gid() != control_gid {
        let socket_c = CString::new(socket.as_bytes())?;
        // SAFETY: socket_c is a valid NUL-terminated path. Group ownership is
        // changed only when the service manager did not already apply Group=gedefense.
        let chown_rc = unsafe { libc::chown(socket_c.as_ptr(), 0, control_gid) };
        if chown_rc != 0 {
            return Err(std::io::Error::other(format!(
                "IPC ownership: {}",
                std::io::Error::last_os_error()
            ))
            .into());
        }
    }
    eprintln!("GeDefense core startup phase=xdp-load interface={iface}");
    let mut core = KernelCore::load(&object, &iface, require_cell_lsm).map_err(|error| {
        std::io::Error::other(format!("kernel data-plane load/attach: {error}"))
    })?;
    let mut replay = ReplayGuard::new();
    eprintln!(
        "GeDefense Rust core online: interface={iface} ingress={} cgroup_egress=attached cell_lsm={} on_access=fanotify-exec user_scan=peercred-jail authenticated_ipc=VGT3 socket={socket}",
        core.mode,
        if core.cell_lsm_attached { "attached" } else { "optional-unavailable" }
    );
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => handle_connection(
                stream,
                &mut core,
                &quarantine,
                &scanner,
                control_uid,
                &auth_key,
                &mut replay,
            ),
            Err(error) => eprintln!("IPC accept error: {error}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parser_normalizes_networks() {
        match parse_target("203.0.113.77/24").expect("IPv4 target") {
            Target::V4(address, prefix) => {
                assert_eq!(address, Ipv4Addr::new(203, 0, 113, 0));
                assert_eq!(prefix, 24);
            }
            Target::V6(_, _) => panic!("unexpected IPv6 target"),
        }
        match parse_target("2001:db8::1234/64").expect("IPv6 target") {
            Target::V6(address, prefix) => {
                assert_eq!(address, "2001:db8::".parse::<Ipv6Addr>().unwrap());
                assert_eq!(prefix, 64);
            }
            Target::V4(_, _) => panic!("unexpected IPv4 target"),
        }
    }

    #[test]
    fn target_parser_rejects_dangerous_or_invalid_networks() {
        assert!(parse_target("0.0.0.0/0").is_err());
        assert!(parse_target("::/0").is_err());
        assert!(parse_target("192.0.2.1/33").is_err());
        assert!(parse_target("2001:db8::1/129").is_err());
    }

    #[test]
    fn protocol_tokens_are_strict() {
        assert!(valid_rule_token("XDR.MEMFD_EXEC"));
        assert!(!valid_rule_token("XDR MEMFD EXEC"));
        assert!(!valid_rule_token(""));
        assert!(valid_nonce("0123456789abcdef0123456789ABCDEF"));
        assert!(!valid_nonce("0123"));
        assert!(!valid_nonce("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
    }

    #[test]
    fn cell_lsm_policy_tokens_are_strict() {
        assert_eq!(parse_cell_cgroup_id("42").unwrap(), 42);
        assert!(parse_cell_cgroup_id("0").is_err());
        assert!(parse_cell_cgroup_id("-1").is_err());
        assert_eq!(
            parse_cell_policy_flags("1").unwrap(),
            CELL_LSM_DENY_NON_UNIX_SOCKET
        );
        assert!(parse_cell_policy_flags("0").is_err());
        assert!(parse_cell_policy_flags("3").is_err());
    }

    #[test]
    fn interface_names_reject_path_and_control_characters() {
        assert!(valid_interface_name("enp0s3"));
        assert!(valid_interface_name("veth.secure-1"));
        assert!(!valid_interface_name("../eth0"));
        assert!(!valid_interface_name("eth0/peer"));
        assert!(!valid_interface_name("eth0\n"));
        assert!(!valid_interface_name(""));
    }

    #[test]
    fn replay_guard_rejects_duplicates_and_expires_old_entries() {
        let mut guard = ReplayGuard::new();
        assert!(guard.accept("0123456789abcdef0123456789abcdef", 100));
        assert!(!guard.accept("0123456789abcdef0123456789abcdef", 101));
        assert!(guard.accept(
            "0123456789abcdef0123456789abcdef",
            100 + CLOCK_WINDOW_SECS + 1
        ));
    }

    #[test]
    fn sysctl_contract_is_exact_and_typed() {
        let (_, binary) =
            sysctl_spec("net.ipv4.conf.all.accept_redirects").expect("allowlisted sysctl");
        assert_eq!(binary, &["0", "1"]);
        let (_, ternary) = sysctl_spec("kernel.kptr_restrict").expect("allowlisted sysctl");
        assert_eq!(ternary, &["0", "1", "2"]);
        assert!(sysctl_spec("kernel.core_pattern").is_none());
        assert!(sysctl_spec("../kernel/kptr_restrict").is_none());
    }

    #[test]
    fn custom_hardening_profiles_are_deterministic_and_bounded() {
        let profile = hardening_content("astraeaos-custom-0083").expect("valid custom profile");
        assert!(profile.contains("# Profile: astraeaos-custom-0083\n"));
        assert!(profile.contains("kernel.randomize_va_space = 2\n"));
        assert!(profile.contains("kernel.kptr_restrict = 2\n"));
        assert!(profile.contains("net.ipv4.tcp_syncookies = 1\n"));
        assert_eq!(
            recognized_hardening_state(&profile).as_deref(),
            Some("astraeaos-custom-0083")
        );
        for invalid in [
            "astraeaos-custom-0000",
            "astraeaos-custom-0400",
            "astraeaos-custom-ffff",
            "astraeaos-custom-xyz1",
            "astraeaos-custom-001",
        ] {
            assert!(hardening_content(invalid).is_none(), "accepted {invalid}");
        }
    }
}
