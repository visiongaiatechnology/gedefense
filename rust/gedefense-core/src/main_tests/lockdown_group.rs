#![cfg(test)]
//! Wave 5a: lockdown / USB / uevent tests (incl. the adversarial
//! `include_str!` no-shell guard) moved verbatim from `main_tests.rs`
//! (structure-only split).

use super::*;

struct FakeNetCounters {
    drops: u64,
    witness: u64,
}

impl lockdown::NetCounters for FakeNetCounters {
    fn net_counters(&self) -> Result<(u64, u64), String> {
        Ok((self.drops, self.witness))
    }
}

fn lockdown_fixture(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir().join(format!(
        "vgt-lockdown-{label}-{}-{nanos}",
        std::process::id()
    ));
    for directory in [
        "sys/bus/usb/devices",
        "sys/bus/thunderbolt/devices",
        "sys/kernel/security",
        "proc/sys/kernel",
        "state",
    ] {
        fs::create_dir_all(root.join(directory)).expect("lockdown fixture dir");
    }
    fs::write(root.join("sys/bus/usb/drivers_autoprobe"), "1\n").expect("autoprobe");
    for (name, value) in [
        ("kexec_load_disabled", "0"),
        ("sysrq", "1"),
        ("modules_disabled", "0"),
        ("unprivileged_bpf_disabled", "2"),
    ] {
        fs::write(root.join("proc/sys/kernel").join(name), format!("{value}\n"))
            .expect("sysctl fixture");
    }
    fs::write(root.join("sys/kernel/security/lockdown"), "none [integrity] confidentiality\n")
        .expect("kernel lockdown fixture");
    root
}

fn lockdown_state_path(root: &Path) -> std::path::PathBuf {
    root.join("state/LOCKDOWN.state")
}

fn lockdown_core_with(
    root: &Path,
    word: std::sync::Arc<MemoryWordStore>,
    nets: (u64, u64),
) -> lockdown::LockdownCore {
    let config = lockdown::LockdownConfig {
        state_file: lockdown_state_path(root),
        usb: crate::lockdown_usb::UsbPaths::new(root.join("sys")),
        hardening: crate::lockdown_hardening::HardeningPaths::for_root(root),
        proc_root: root.join("proc"),
        monitors: false,
    };
    lockdown::LockdownCore::new(
        config,
        word,
        std::sync::Arc::new(FakeNetCounters { drops: nets.0, witness: nets.1 }),
    )
    .expect("lockdown core")
}

fn lockdown_core(root: &Path, word: std::sync::Arc<MemoryWordStore>) -> lockdown::LockdownCore {
    lockdown_core_with(root, word, (0, 0))
}

fn lockdown_word(store: &MemoryWordStore) -> gedefense_common::LockdownWord {
    gedefense_common::decode_lockdown_word(store.word()).expect("decoded lockdown word")
}

fn lockdown_command_raw(core: &mut lockdown::LockdownCore, parts: &[&str]) -> Result<String, BoxError> {
    lockdown_command(core, parts)
}

#[test]
fn lockdown_dispatch_arm_trigger_clear_matches_the_section_five_abi() {
    let root = lockdown_fixture("dispatch");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    let epoch = format!("{:08x}", core.epoch());
    assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_VERSION"]).unwrap(), "lockdown-v1");
    assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_EPOCH"]).unwrap(), epoch);
    let status = lockdown_command_raw(&mut core, &["LOCKDOWN_STATUS"]).unwrap();
    assert!(
        status.starts_with("state=off;epoch=") && status.ends_with(";mode=unlocked;flags=0;phases=-;unsupported=sessions,dm"),
        "{status}"
    );
    assert_eq!(core.ping_suffix(), "+lockdown:off");

    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap(),
        format!("armed:{epoch}")
    );
    assert_eq!(core.ping_suffix(), "+lockdown:armed");
    assert_eq!(lockdown_word(&store).mode, gedefense_common::LOCKDOWN_MODE_ARMED);
    assert_eq!(lockdown_word(&store).flags, 0, "arm alone must not drop");
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap(),
        format!("armed-unchanged:{epoch}")
    );
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_SET_MODE", "unlocked"]).unwrap(),
        "applied"
    );

    // TRIGGER creates a new epoch and reports applied/unsupported phases;
    // flags=5 = auto_network_drop + freeze_brokers (loopback NOT kept).
    let triggered = lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "uevent", "usb-unknown", "5"]).unwrap();
    let armed_epoch = format!("{:08x}", core.epoch());
    assert_ne!(armed_epoch, epoch, "every trigger gets a new epoch");
    assert_eq!(
        triggered,
        format!("triggered:{armed_epoch};phases=net,usb,tb,brokers,cells=delegated;unsupported=sessions,dm")
    );
    assert_eq!(core.ping_suffix(), "+lockdown:active");
    let word = lockdown_word(&store);
    assert_eq!(word.epoch, core.epoch());
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
    assert_eq!(word.flags & gedefense_common::LOCKDOWN_FLAG_ALLOW_LOOPBACK, 0);
    let status = lockdown_command_raw(&mut core, &["LOCKDOWN_STATUS"]).unwrap();
    assert!(status.starts_with("state=active;"), "{status}");
    assert!(status.contains(";mode=unlocked;flags=49;"), "{status}");
    assert!(status.contains(";phases=net,usb,tb,brokers,cells=delegated;"), "{status}");

    // ARM during an active latch never lowers it.
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap(),
        format!("armed-unchanged:{armed_epoch}")
    );
    assert_eq!(core.state_text(), "active");

    // Wrong expected epoch is a compare-set rejection, not a partial clear.
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", "deadbeef", "manual"]).is_err());
    assert_eq!(core.state_text(), "active");
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", &armed_epoch, "manual"]).unwrap(),
        "cleared"
    );
    assert_eq!(core.ping_suffix(), "+lockdown:off");
    assert_eq!(lockdown_word(&store).mode, gedefense_common::LOCKDOWN_MODE_OFF);
    assert!(!lockdown_state_path(&root).exists(), "clear removes the latch file");
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", &armed_epoch, "manual"]).unwrap(),
        "already-off"
    );
}

#[test]
fn lockdown_token_and_size_boundaries_are_rejected() {
    let root = lockdown_fixture("tokens");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "bogus", "manual", "1"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "bogus", "1"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "16"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "x"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "nope", "manual", "1"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", "123", "manual"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", "zzzzzzzz", "manual"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "bogus", "on"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "net", "toggle"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_BOGUS"]).is_err());
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM"]).is_err());
    // Every §5 answer stays well below the 2048-byte IPC response budget.
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "tamper", "15"]).unwrap();
    lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "manual", "tamper", "15"]).unwrap();
    for parts in [
        vec!["LOCKDOWN_STATUS"],
        vec!["LOCKDOWN_EVENTS"],
        vec!["LOCKDOWN_HEALTH"],
        vec!["LOCKDOWN_EPOCH"],
    ] {
        let answer = lockdown_command_raw(&mut core, &parts).unwrap();
        assert!(answer.len() <= MAX_RESPONSE_BYTES, "{parts:?} answer too long");
    }
}

#[test]
fn lockdown_word_read_back_failures_are_never_claimed() {
    let root = lockdown_fixture("readback");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    store.ignore_writes();
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    // ARM cannot claim armed without a successful verified write.
    assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "1"]).is_err());
    assert_eq!(core.state_text(), "off");
    // A trigger still runs the other phases, but NET is not in the applied
    // CSV and the state is degraded: no "network down" claim without read-back.
    let triggered = lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "manual", "tamper", "1"]).unwrap();
    assert!(!triggered.contains("phases=net"), "{triggered}");
    assert_eq!(core.state_text(), "degraded");
    let status = lockdown_command_raw(&mut core, &["LOCKDOWN_STATUS"]).unwrap();
    assert!(status.contains(";phases=usb,tb,cells=delegated;"), "{status}");
    assert_eq!(store.word(), 0, "no write was persisted");
}

#[test]
fn lockdown_state_file_is_atomic_0640_and_rearms_verified() {
    let root = lockdown_fixture("rearm");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "9"]).unwrap();
    lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "policy", "boot-trust-drift", "9"]).unwrap();
    let epoch = format!("{:08x}", core.epoch());
    let path = lockdown_state_path(&root);
    let metadata = fs::metadata(&path).expect("state file");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
    let content = fs::read_to_string(&path).expect("state file content");
    let fields: Vec<&str> = content.trim_end().split('|').collect();
    assert_eq!(fields.len(), 5, "{content}");
    assert_eq!(fields[0], epoch);
    assert_eq!(fields[1], "locked");
    assert_eq!(fields[2], "09");
    assert_eq!(fields[3], "net,usb,tb,hardening", "flags=9 selects hardening");
    // Phase 1 hardening applied for real in the fake sysctl tree.
    assert_eq!(fs::read_to_string(root.join("proc/sys/kernel/kexec_load_disabled")).unwrap().trim(), "1");
    assert_eq!(fs::read_to_string(root.join("proc/sys/kernel/sysrq")).unwrap().trim(), "0");

    // Re-arm from the file applies drop/USB/TB/hardening again and verifies.
    let rearm_store = std::sync::Arc::new(MemoryWordStore::new());
    let mut rearmed = lockdown_core(&root, std::sync::Arc::clone(&rearm_store));
    assert_eq!(rearmed.startup_rearm().unwrap(), "active");
    let word = lockdown_word(&rearm_store);
    assert_eq!(word.epoch, core.epoch());
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_USB_LOCKED, 0);
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_HARDENING_APPLIED, 0);

    // Corrupt file: degraded + latched, but no unverified enforcement action.
    fs::write(&path, "garbage|not-a-state\n").expect("corrupt state");
    let corrupt_store = std::sync::Arc::new(MemoryWordStore::new());
    let mut corrupt = lockdown_core(&root, std::sync::Arc::clone(&corrupt_store));
    assert_eq!(corrupt.startup_rearm().unwrap(), "degraded");
    assert_eq!(corrupt.state_text(), "degraded");
    assert_eq!(corrupt_store.word(), 0, "corrupt state must not fake enforcement");
    assert_eq!(corrupt_store.writes(), 0);
    let epoch = format!("{:08x}", corrupt.epoch());
    assert_eq!(
        lockdown_command_raw(&mut corrupt, &["LOCKDOWN_CLEAR", &epoch, "manual"]).unwrap(),
        "cleared"
    );
    assert!(!path.exists());
}

#[test]
fn lockdown_phase_command_matrix_is_honest() {
    let root = lockdown_fixture("phases");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "net", "on"]).unwrap(),
        "failed:net:not-armed"
    );
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "8"]).unwrap();
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "cells", "on"]).unwrap(),
        "unsupported:cells:delegated-to-control"
    );
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "sessions", "on"]).unwrap(),
        "unsupported:sessions:no-dbus-session-lock"
    );
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "dm", "on"]).unwrap(),
        "unsupported:dm:no-device-mapper"
    );
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "kernel-lockdown", "on"]).unwrap(),
        "unsupported:kernel-lockdown:boot-parameter-immutable"
    );
    // Explicit single-phase command may set modules_disabled (auto never).
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "hardening", "on"]).unwrap(),
        "applied:hardening"
    );
    assert_eq!(fs::read_to_string(root.join("proc/sys/kernel/modules_disabled")).unwrap().trim(), "1");
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "hardening", "off"]).unwrap(),
        "unsupported:hardening:irreversible-until-reboot"
    );
    for phase in ["net", "usb", "tb", "brokers"] {
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", phase, "on"]).unwrap(),
            format!("applied:{phase}")
        );
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", phase, "off"]).unwrap(),
            format!("applied:{phase}")
        );
    }
    assert_eq!(core.ping_suffix(), "+lockdown:active");
}

#[test]
fn lockdown_auto_network_drop_survives_a_later_phase_refresh() {
    let root = lockdown_fixture("auto-drop-phase");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    // flags=3 = auto_network_drop + allow_loopback.
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap();
    core.shared.auto_network_drop().expect("auto drop write");
    assert!(core.shared.auto_drop(), "auto-drop ownership is recorded");
    let word = lockdown_word(&store);
    assert_eq!(word.epoch, core.epoch());
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_ALLOW_LOOPBACK, 0);
    // A later USB phase refresh must keep the drop and add its own bit.
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "usb", "on"]).unwrap(),
        "applied:usb"
    );
    let word = lockdown_word(&store);
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0, "phase refresh cleared the auto drop");
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_USB_LOCKED, 0, "USB phase bit was not persisted");
    assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_ALLOW_LOOPBACK, 0);
}

#[test]
fn lockdown_auto_network_drop_survives_a_startup_rearm() {
    let root = lockdown_fixture("auto-drop-rearm");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    // flags=3 = auto_network_drop + allow_loopback.
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap();
    core.shared.auto_network_drop().expect("auto drop write");
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "usb", "on"]).unwrap(),
        "applied:usb"
    );
    let before = lockdown_word(&store);
    assert_ne!(before.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);

    // A daemon restart re-arms from the persisted USB phase. The DROP_ALL
    // already verified in the kernel word must not be cleared silently.
    let mut restarted = lockdown_core(&root, std::sync::Arc::clone(&store));
    restarted.startup_rearm().expect("startup rearm");
    let after = lockdown_word(&store);
    assert_eq!(after.epoch, before.epoch);
    assert_ne!(
        after.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL,
        0,
        "startup re-arm cleared the auto-drop"
    );
    assert_ne!(after.flags & gedefense_common::LOCKDOWN_FLAG_USB_LOCKED, 0);
    assert!(restarted.shared.auto_drop(), "auto-drop ownership was not re-established");
}

#[test]
fn lockdown_auto_network_drop_is_released_by_an_explicit_net_phase_off() {        let root = lockdown_fixture("auto-drop-net-off");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "1"]).unwrap();
    core.shared.auto_network_drop().expect("auto drop write");
    assert_ne!(lockdown_word(&store).flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "net", "off"]).unwrap(),
        "applied:net"
    );
    assert!(!core.shared.auto_drop(), "explicit NET off clears the auto-drop flag");
    assert_eq!(lockdown_word(&store).flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
}

#[test]
fn lockdown_auto_network_drop_is_cleared_by_clear() {
    let root = lockdown_fixture("auto-drop-clear");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "1"]).unwrap();
    core.shared.auto_network_drop().expect("auto drop write");
    assert!(core.shared.auto_drop());
    let epoch = format!("{:08x}", core.epoch());
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", &epoch, "manual"]).unwrap(),
        "cleared"
    );
    assert!(!core.shared.auto_drop(), "CLEAR releases the auto-drop flag");
    let word = lockdown_word(&store);
    assert_eq!(word.mode, gedefense_common::LOCKDOWN_MODE_OFF);
    assert_eq!(word.flags, 0, "CLEAR writes the OFF word");
}

#[test]
fn lockdown_explicit_hardening_phase_covers_modules_disabled_only_on_request() {
    let root = lockdown_fixture("explicit-modules");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "8"]).unwrap();
    // Automatic trigger (hardening_apply flag) never writes modules_disabled.
    lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "manual", "tamper", "8"]).unwrap();
    let modules = root.join("proc/sys/kernel/modules_disabled");
    assert_eq!(fs::read_to_string(&modules).unwrap().trim(), "0");
    assert_eq!(fs::read_to_string(root.join("proc/sys/kernel/kexec_load_disabled")).unwrap().trim(), "1");
    // A failing modules_disabled write makes the explicit phase fail visibly.
    fs::write(&modules, "7\n").unwrap();
    let response = lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "hardening", "on"]).unwrap();
    assert!(response.starts_with("failed:hardening:"), "{response}");
    assert_eq!(core.state_text(), "degraded");
    // A writable knob is applied and verified by the explicit command.
    fs::write(&modules, "0\n").unwrap();
    assert_eq!(
        lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "hardening", "on"]).unwrap(),
        "applied:hardening"
    );
    assert_eq!(fs::read_to_string(&modules).unwrap().trim(), "1");
}

#[test]
fn lockdown_events_and_health_wire_formats_are_bounded() {
    let root = lockdown_fixture("events");
    let store = std::sync::Arc::new(MemoryWordStore::new());
    let mut core = lockdown_core_with(&root, std::sync::Arc::clone(&store), (7, 3));
    assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_HEALTH"]).unwrap(), "7:3:0:0:0:0");
    lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "1"]).unwrap();
    lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "manual", "tamper", "1"]).unwrap();
    let events = lockdown_command_raw(&mut core, &["LOCKDOWN_EVENTS"]).unwrap();
    let (dropped, records) = events.split_once('|').expect("dropped|records");
    assert!(dropped.parse::<u64>().is_ok());
    let records: Vec<&str> = records.split(',').collect();
    assert!(!records.is_empty() && records.len() <= lockdown_uevent::EVENTS_PER_RESPONSE);
    let mut last_seq = 0u64;
    for record in records {
        let fields: Vec<&str> = record.split(':').collect();
        assert_eq!(fields.len(), 6, "{record}");
        for field in &fields {
            assert!(field.parse::<u64>().is_ok(), "{record}");
        }
        let seq = fields[0].parse::<u64>().unwrap();
        assert!(seq > last_seq, "sequences must increase");
        assert!(matches!(fields[5].parse::<u8>().unwrap(), 1..=5), "{record}");
        last_seq = seq;
    }
    // The queue drains: a second read is empty (no duplication/loss).
    assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_EVENTS"]).unwrap(), "empty");
    let health = lockdown_command_raw(&mut core, &["LOCKDOWN_HEALTH"]).unwrap();
    let values: Vec<&str> = health.split(':').collect();
    assert_eq!(values.len(), 6, "{health}");
    assert!(values.iter().all(|value| value.parse::<u64>().is_ok()));
    assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_HEALTH"]).unwrap().split(':').next(), Some("7"));
}

struct FakeUeventSource {
    queue: VecDeque<lockdown_uevent::Poll>,
}

impl lockdown_uevent::UeventSource for FakeUeventSource {
    fn next(&mut self) -> lockdown_uevent::Poll {
        self.queue.pop_front().unwrap_or(lockdown_uevent::Poll::Timeout)
    }
}

fn uevent_payload(devpath: &str, subsystem: &str) -> Vec<u8> {
    format!("add@{devpath}\0ACTION=add\0SUBSYSTEM={subsystem}\0DEVPATH={devpath}\0").into_bytes()
}

fn wait_for_word(store: &MemoryWordStore) -> u64 {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while store.word() == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    store.word()
}

#[test]
fn lockdown_uevent_loop_blocks_data_devices_and_drops_network() {
    let root = crate::lockdown_usb::tests::fixture("uevent-loop");
    let devpath = "/devices/pci0000:00/usb1/1-3";
    let dir = root.join("sys").join(devpath.trim_start_matches('/'));
    fs::create_dir_all(&dir).expect("uevent device");
    fs::write(dir.join("bDeviceClass"), "08\n").expect("class");
    fs::write(dir.join("bNumInterfaces"), "01\n").expect("interfaces");
    fs::write(dir.join("bNumConfigurations"), "01\n").expect("config");
    fs::write(dir.join("authorized"), "1\n").expect("authorized");
    let word = std::sync::Arc::new(MemoryWordStore::new());
    let shared_word: std::sync::Arc<dyn lockdown::LockdownWordStore> = word.clone();
    let shared = std::sync::Arc::new(LockdownShared::new(
        shared_word,
        UeventPolicy { arm: ArmMode::Locked, auto_network_drop: true, allow_loopback: true, epoch: 0x1234_5678 },
    ));
    let source = FakeUeventSource { queue: VecDeque::from([lockdown_uevent::Poll::Message(uevent_payload(devpath, "usb"))]) };
    let mut monitor = lockdown_uevent::start_with_source(
        Box::new(source),
        std::sync::Arc::clone(&shared),
        crate::lockdown_usb::UsbPaths::new(root.join("sys")),
    )
    .expect("uevent monitor thread");
    let persisted = wait_for_word(&word);
    monitor.stop();
    assert_ne!(persisted, 0, "auto_network_drop must write the kernel word");
    let decoded = gedefense_common::decode_lockdown_word(persisted).expect("drop word");
    assert_eq!(decoded.epoch, 0x1234_5678);
    assert_ne!(decoded.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
    assert_eq!(fs::read_to_string(dir.join("authorized")).unwrap().trim(), "0");
    let (uevents, usb_blocks, tb_blocks) = shared.uevent_counters();
    assert_eq!((uevents, usb_blocks, tb_blocks), (1, 1, 0));
    let (_dropped, records) = shared.take_events(lockdown_uevent::EVENTS_PER_RESPONSE);
    assert!(records.iter().any(|event| {
        event.phase == gedefense_common::LOCKDOWN_PHASE_USB
            && event.outcome == gedefense_common::LOCKDOWN_OUTCOME_APPLIED
            && event.source == gedefense_common::LOCKDOWN_SOURCE_UEVENT
    }));
}

#[test]
fn lockdown_uevent_loop_never_blocks_power_only_or_audits_while_unlocked() {
    let root = crate::lockdown_usb::tests::fixture("uevent-audit");
    let devpath = "/devices/pci0000:00/usb1/1-4";
    let dir = root.join("sys").join(devpath.trim_start_matches('/'));
    fs::create_dir_all(&dir).expect("uevent device");
    fs::write(dir.join("bDeviceClass"), "00\n").expect("class");
    fs::write(dir.join("bNumInterfaces"), "00\n").expect("interfaces");
    fs::write(dir.join("bNumConfigurations"), "01\n").expect("config");
    // Power-only charger: no block, no word write (Lade-Kabel-DoS-Schutz).
    let word = std::sync::Arc::new(MemoryWordStore::new());
    let shared_word: std::sync::Arc<dyn lockdown::LockdownWordStore> = word.clone();
    let shared = std::sync::Arc::new(LockdownShared::new(
        shared_word,
        UeventPolicy { arm: ArmMode::Locked, auto_network_drop: true, allow_loopback: true, epoch: 9 },
    ));
    let source = FakeUeventSource { queue: VecDeque::from([lockdown_uevent::Poll::Message(uevent_payload(devpath, "usb"))]) };
    let mut monitor = lockdown_uevent::start_with_source(
        Box::new(source),
        std::sync::Arc::clone(&shared),
        crate::lockdown_usb::UsbPaths::new(root.join("sys")),
    )
    .expect("uevent monitor thread");
    std::thread::sleep(std::time::Duration::from_millis(60));
    monitor.stop();
    assert_eq!(word.word(), 0, "power-only device never triggers a drop");
    assert_eq!(shared.uevent_counters().1, 0);

    // Unlocked arm mode: audit only, nothing is written or blocked.
    let unlocked = std::sync::Arc::new(LockdownShared::new(
        std::sync::Arc::new(MemoryWordStore::new()),
        UeventPolicy { arm: ArmMode::Unlocked, auto_network_drop: true, allow_loopback: true, epoch: 9 },
    ));
    let source = FakeUeventSource { queue: VecDeque::from([lockdown_uevent::Poll::Message(uevent_payload(devpath, "usb"))]) };
    let mut monitor = lockdown_uevent::start_with_source(
        Box::new(source),
        std::sync::Arc::clone(&unlocked),
        crate::lockdown_usb::UsbPaths::new(root.join("sys")),
    )
    .expect("uevent monitor thread");
    std::thread::sleep(std::time::Duration::from_millis(60));
    monitor.stop();
    let (_dropped, records) = unlocked.take_events(lockdown_uevent::EVENTS_PER_RESPONSE);
    assert!(records.iter().any(|event| event.outcome == gedefense_common::LOCKDOWN_OUTCOME_SKIPPED));
}

#[test]
fn lockdown_usb_uevent_device_paths_are_bounded_and_traversal_free() {
    let root = crate::lockdown_usb::tests::fixture("main-devpath");
    let paths = crate::lockdown_usb::UsbPaths::new(root.join("sys"));
    let dir = root.join("sys/devices/pci0000:00/usb1/1-1");
    fs::create_dir_all(&dir).expect("devpath fixture");
    fs::write(dir.join("bDeviceClass"), "08\n").expect("class");
    fs::write(dir.join("authorized"), "1\n").expect("authorized");
    assert_eq!(
        crate::lockdown_usb::apply_device(&paths, "/devices/pci0000:00/usb1/1-1"),
        Ok(crate::lockdown_usb::DevicePolicy::Block)
    );
    assert_eq!(fs::read_to_string(dir.join("authorized")).unwrap().trim(), "0");
    assert_eq!(crate::lockdown_usb::apply_device(&paths, "/devices/../etc/passwd"), Err("invalid-devpath"));
    assert_eq!(crate::lockdown_usb::apply_device(&paths, "/devices/absent"), Err("not-present"));
    assert_eq!(crate::lockdown_usb::apply_device(&paths, "relative/path"), Err("invalid-devpath"));
}

#[test]
fn lockdown_usb_release_reauthorizes_and_missing_tree_is_unsupported() {
    let root = crate::lockdown_usb::tests::fixture("main-release");
    let paths = crate::lockdown_usb::UsbPaths::new(root.join("sys"));
    let storage = crate::lockdown_usb::tests::usb_device(&root, "1-3", "08", "01", "01", Some("0"));
    assert_eq!(crate::lockdown_usb::apply_usb(&paths).outcome, gedefense_common::LOCKDOWN_OUTCOME_APPLIED);
    assert_eq!(crate::lockdown_usb::release_usb(&paths).outcome, gedefense_common::LOCKDOWN_OUTCOME_APPLIED);
    assert_eq!(fs::read_to_string(storage.join("authorized")).unwrap().trim(), "1");
    let missing = crate::lockdown_usb::UsbPaths::new(root.join("absent"));
    let report = crate::lockdown_usb::apply_usb(&missing);
    assert_eq!(report.outcome, gedefense_common::LOCKDOWN_OUTCOME_UNSUPPORTED);
    assert_eq!(report.reason, "not-present");
    assert_eq!(crate::lockdown_usb::apply_tb(&missing).outcome, gedefense_common::LOCKDOWN_OUTCOME_UNSUPPORTED);
}

#[test]
fn lockdown_modules_never_use_shell_or_kill_primitives() {
    // Adversarial guard for the "no shell, no kill" contract (§§1.1/6.4).
    for (name, source) in [
        ("lockdown.rs", include_str!("../lockdown.rs")),
        ("lockdown_usb.rs", include_str!("../lockdown_usb.rs")),
        ("lockdown_usb/classify.rs", include_str!("../lockdown_usb/classify.rs")),
        ("lockdown_usb/policy.rs", include_str!("../lockdown_usb/policy.rs")),
        ("lockdown_usb/release.rs", include_str!("../lockdown_usb/release.rs")),
        ("lockdown_usb/uevent.rs", include_str!("../lockdown_usb/uevent.rs")),
        ("lockdown_usb/tests.rs", include_str!("../lockdown_usb/tests.rs")),
        ("lockdown_uevent.rs", include_str!("../lockdown_uevent.rs")),
        ("lockdown_hardening.rs", include_str!("../lockdown_hardening.rs")),
        ("lockdown_brokers.rs", include_str!("../lockdown_brokers.rs")),
    ] {
        for forbidden in ["Command::new", "process::Command", "SIGKILL", "/bin/sh", "sh -c"] {
            assert!(!source.contains(forbidden), "{name} must not contain {forbidden}");
        }
    }
    let brokers = include_str!("../lockdown_brokers.rs");
    assert!(brokers.contains("libc::SIGSTOP") && brokers.contains("libc::SIGCONT"));
}
