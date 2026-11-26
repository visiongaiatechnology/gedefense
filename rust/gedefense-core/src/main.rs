use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        Array as AyaArray, HashMap as AyaHashMap, Map, MapData, MapError, PerCpuArray, RingBuf,
    },
    programs::{
        tc, CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, Lsm, SchedClassifier, TcAttachType,
        TracePoint, Xdp, XdpMode,
    },
    Btf, Ebpf,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gedefense_common::{
    decode_ingress_event, decode_styx_flow_event, decode_titan_exec_event, CellLsmDenyEvent,
    EgressDropEvent, ExecEvent, ACTION_DROP, CELL_LSM_DENY_ALL_KNOWN,
    EXEC_COMM_BYTES, NETWORK_ADDRESS_BYTES, NETWORK_FAMILY_V4, NETWORK_FAMILY_V6,
    STYX_FLOW_EVENT_WIRE_BYTES, STYX_MODE_OFF, TITAN_EXEC_EVENT_WIRE_BYTES,
    TITAN_EXEC_MODE_OFF, TITAN_EXEC_OFFSETS_ABI, TITAN_EXEC_OFFSETS_MAGIC, TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW,
    TITAN_EXEC_STATE_ABI, TITAN_EXEC_STATE_MAGIC,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
mod archive_deflate;
mod archive_gzip;
mod archive_scan;
mod archive_tar;
mod archive_zip;
#[cfg(test)]
mod archive_tests;
mod btf_offsets;
mod btf_validate;
mod canary;
mod lockdown;
mod lockdown_brokers;
mod lockdown_hardening;
mod lockdown_uevent;
mod lockdown_usb;
mod malware;
mod on_write;
mod on_write_policy;
#[cfg(test)]
mod on_write_tests;
mod process_control;
mod process_tree;
#[cfg(test)]
mod process_tree_tests;
mod quarantine;
mod credential_guard;
#[cfg(test)]
mod credential_guard_tests;
mod ransom;
#[cfg(test)]
mod ransom_tests;
mod styx_flow;
mod titan_exec;
mod titan_status;
mod worker_guard;
mod xdr_kernel;
// V6.3.0 AP-0/AP-1/AP-2: sensor self-protection, executable-inode trust gate and
// the attach-time eBPF guard. Each module owns its maps/rings/status; main.rs is
// only the ABI + dispatch seam.
mod self_defense;
mod exec_inode;
mod bpf_guard;
// V6.3.0 AP-3/AP-4/AP-5: cross-view verifier, io_uring/LKM hooks and the
// persistence/peripheral integrity guard.
mod cross_view;
mod kernel_hooks;
mod persistence;
// V6.3.0 AP-6: ingress RX flow observer (PCR phase 2) and bounded DNS capture.
mod styx_ingress;
mod dns_capture;
// V6.3.0 AP-8/AP-9: opt-in Chameleon install profile and the high-priority
// security evidence ring / telemetry token buckets.
mod chameleon;
mod sec_crit;
mod ebpf_loader;
mod ipc;
mod kernel_core;
mod poller;
mod sysctl_broker;
use canary::{collect_canary_roots, CanaryBroker};
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
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;
type HmacSha256 = Hmac<Sha256>;

pub(crate) use ebpf_loader::random_epoch_word;
pub(crate) use ipc::dispatch_lockdown::{
    load_lockdown_state, persist_lockdown_state, ArmMode, LoadedPhase, LockdownShared,
    LockdownStateLoad, UeventPolicy,
};
pub(crate) use ipc::dispatch_quarantine::{open_componentwise, open_componentwise_from};
pub(crate) use kernel_core::{KernelCore, TitanExecGate};
use ipc::server::{
    bind_secure_runtime_socket, handle_connection, load_auth_key, load_secret_key, ReplayGuard,
};
use sysctl_broker::reassert_persisted_hardening;

fn arg(name: &str, default: &str) -> String {
    let prefix = format!("--{name}=");
    env::args()
        .find_map(|value| value.strip_prefix(&prefix).map(str::to_owned))
        .unwrap_or_else(|| default.to_owned())
}

// Repeatable flag, e.g. `--canary-root=/var/lib/vgt/gedefense/canaries`.
fn multi_arg(name: &str) -> Vec<String> {
    let prefix = format!("--{name}=");
    env::args()
        .filter_map(|value| value.strip_prefix(&prefix).map(str::to_owned))
        .collect()
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
    let lockdown_state_path = arg("lockdown-state", lockdown::DEFAULT_STATE_FILE);
    // V6.3.0 AP-0/AP-8: neutral, install-time configurable bpffs pin root. The
    // default keeps the 6.2 layout; Chameleon Mode overrides it via the unit.
    let bpf_pin_root = arg("bpf-pin-root", "/sys/fs/bpf/gedefense");
    // V6.3.0 AP-8: opt-in Chameleon install profile. Empty = documented default
    // public identity; a manifest is only ever provided by an installation that
    // explicitly opted in.
    let chameleon_manifest = arg("chameleon-manifest", "");
    eprintln!("GeDefense core startup phase=control-identity");
    let (control_uid, control_gid) = lookup_identity(&control_user)
        .map_err(|error| std::io::Error::other(format!("control identity: {error}")))?;
    eprintln!("GeDefense core startup phase=auth-key");
    let auth_key = load_auth_key(&auth_key_path, control_gid)
        .map_err(|error| std::io::Error::other(format!("auth key: {error}")))?;
    eprintln!("GeDefense core startup phase=quarantine-vault");
    let mut storage_key = load_secret_key(&storage_key_path, control_gid, "storage master key")
        .map_err(|error| std::io::Error::other(format!("storage key: {error}")))?;
    let quarantine = Arc::new(
        QuarantineBroker::new(&quarantine_dir, &storage_key)
            .map_err(|error| std::io::Error::other(format!("quarantine vault: {error}")))?,
    );
    storage_key.fill(0);
    eprintln!("GeDefense core startup phase=malware-on-access");
    let scanner = MalwareScanner::load(&malware_hashes)
        .map_err(|error| std::io::Error::other(format!("malware signatures: {error}")))?;
    scanner
        .start_on_access(&[Path::new("/home").to_path_buf()])
        .map_err(|error| std::io::Error::other(format!("on-access guard: {error}")))?;
    // M1.1 (6.2.0): the asynchronous FAN_CLOSE_WRITE sensor for the writable
    // drop roots. It never registers a permission event, so it cannot slow down
    // or block a writer; the roots default to the four drop paths the systemd
    // unit keeps writable and can be overridden with repeated
    // `--on-write-watch-root=` flags (each value is a comma-separated list).
    eprintln!("GeDefense core startup phase=malware-on-write");
    let malware_inode_lock: credential_guard::SharedMalwareInodeLock =
        Arc::new(std::sync::Mutex::new(None));
    let on_write_roots = on_write::resolve_roots(&multi_arg("on-write-watch-root"))
        .map_err(|error| std::io::Error::other(format!("on-write watch roots: {error}")))?;
    on_write::OnWriteSensor::start(
        scanner.clone(),
        Arc::clone(&quarantine),
        Arc::clone(&malware_inode_lock),
        &on_write_roots,
    )
        .map_err(|error| std::io::Error::other(format!("on-write sensor: {error}")))?;
    eprintln!("GeDefense core startup phase=canary-broker");
    // The unprivileged control plane cannot create decoys outside its sandbox
    // (ProtectSystem=strict, PrivateTmp) and cannot observe host file accesses.
    // The broker owns both: atomic deployment inside a validated canary root and
    // a dedicated fanotify instance per registered decoy.
    let canary_roots = collect_canary_roots(&multi_arg("canary-root"))
        .map_err(|error| std::io::Error::other(format!("canary roots: {error}")))?;
    let canary = CanaryBroker::new(&canary_roots)
        .map_err(|error| std::io::Error::other(format!("canary broker: {error}")))?;
    canary
        .start_watch()
        .map_err(|error| std::io::Error::other(format!("canary fanotify sensor: {error}")))?;
    eprintln!("GeDefense core startup phase=user-scan-socket");
    // F-04: self-healing fallback - the persisted hardening profile is applied
    // to the live kernel again here, after systemd-sysctl has run. Later-sorting
    // external sysctl.d files therefore cannot silently win over the operator's
    // persisted GeDefense intent.
    reassert_persisted_hardening();
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
        || scan_parent_metadata.gid() != control_gid
    {
        return Err("user scan runtime directory ownership rejected".into());
    }
    // F-18: the user scan socket is a root-executing service surface. It is
    // restricted to the control-plane account instead of being world-writable.
    fs::set_permissions(scan_parent, fs::Permissions::from_mode(0o750))?;
    let scan_listener = bind_secure_runtime_socket(Path::new(&scan_socket), control_gid, 0o660)
        .map_err(|error| std::io::Error::other(format!("user scan IPC bind: {error}")))?;
    let scan_worker = scanner.clone();
    std::thread::Builder::new()
        .name("gedefense-user-scan".to_owned())
        .spawn(move || {
            for incoming in scan_listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        if let Err(error) = handle_user_scan(stream, &scan_worker, control_uid) {
                            eprintln!("GeDefense user scan IPC rejected: {error}");
                        }
                    }
                    Err(error) => {
                        // F-HOTFIX-1: an accept() error (EMFILE/ENFILE/ECONNABORTED)
                        // must not abort the privileged core. Back off briefly and keep
                        // the enforcement daemon and its IPC response channel online.
                        eprintln!("GeDefense user scan IPC accept error (core stays online): {error}");
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                }
            }
        })?;
    eprintln!("GeDefense core startup phase=ipc-socket");
    let socket_parent = Path::new(&socket)
        .parent()
        .ok_or("IPC socket parent is missing")?;
    fs::create_dir_all(socket_parent)
        .map_err(|error| std::io::Error::other(format!("IPC directory: {error}")))?;
    // FIND-034: the control socket is created through the same hardened helper as
    // the user scan socket. The previous inline path only set 0660: it never
    // rejected a symlinked socket path, never verified the owning group and never
    // checked that the result stayed inaccessible to "other".
    let listener = bind_secure_runtime_socket(Path::new(&socket), control_gid, 0o660)
        .map_err(|error| std::io::Error::other(format!("IPC socket hardening: {error}")))?;
    eprintln!("GeDefense core startup phase=xdp-load interface={iface}");
    let mut core = KernelCore::load(&object, &iface, require_cell_lsm, &lockdown_state_path, &bpf_pin_root, &chameleon_manifest)
        .map_err(|error| {
            std::io::Error::other(format!("kernel data-plane load/attach: {error}"))
        })?;
    // V6.3.0 AP-0: the canary broker already owns a fanotify instance per
    // registered decoy; the self-test uses it to prove the sensor chain is live.
    core.self_defense.attach_canary(canary.clone());
    if let Ok(mut slot) = malware_inode_lock.lock() {
        *slot = Some(core.credential_guard.malware_inode_lock_handle());
    }
    // Point 5 (§5): re-arm the persisted lockdown (drop/USB/TB/hardening and
    // the uevent monitor) before the IPC accept loop serves the first request.
    match core.lockdown.startup_rearm() {
        Ok(state) => eprintln!("GeDefense core startup phase=lockdown-rearm state={state}"),
        Err(error) => eprintln!("GeDefense core lockdown re-arm: {error}"),
    }
    let mut replay = ReplayGuard::new();
    eprintln!(
        "GeDefense Rust core online: interface={iface} ingress={} cgroup_egress=attached cell_lsm={} titan_exec={} titan_exec_attached={} on_access={} user_scan=peercred-jail canary=fanotify-jail authenticated_ipc=VGT3 socket={socket} lockdown={}",
        core.mode,
        if core.cell_lsm_attached { "attached" } else { "optional-unavailable" },
        core.titan_exec.state_text(),
        core.titan_exec.attached,
        scanner.on_access_label(),
        core.lockdown.state_text()
    );
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => handle_connection(
                stream,
                &mut core,
                &quarantine,
                &scanner,
                &canary,
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
#[path = "main_tests.rs"]
mod tests;
