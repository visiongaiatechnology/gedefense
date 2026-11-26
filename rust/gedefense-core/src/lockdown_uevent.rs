//! Point 5 (§2/§6.2): kernel uevent monitor.
//!
//! A bounded `AF_NETLINK`/`NETLINK_KOBJECT_UEVENT` thread (group 1) watches
//! hotplug events. In the `locked` arm mode an unknown non-power-only USB device
//! and every Thunderbolt device get `authorized=0` plus a lifecycle event; with
//! `auto_network_drop` the kernel drop word is written immediately. In the
//! `unlocked` arm mode it only audits. `ENOBUFS` triggers a bounded rescan
//! instead of silently losing devices. The source is a trait so tests drive the
//! parser/loop without root or a real netlink socket.

use crate::{lockdown_usb, ArmMode, LockdownShared};
use gedefense_common::{
    decode_lockdown_word, encode_lockdown_word, LOCKDOWN_FLAG_ALLOW_LOOPBACK,
    LOCKDOWN_FLAG_DROP_ALL, LOCKDOWN_FLAG_HARDENING_APPLIED, LOCKDOWN_FLAG_TB_LOCKED,
    LOCKDOWN_FLAG_USB_LOCKED, LOCKDOWN_MODE_ARMED, LOCKDOWN_OUTCOME_APPLIED,
    LOCKDOWN_OUTCOME_FAILED, LOCKDOWN_OUTCOME_SKIPPED, LOCKDOWN_PHASE_HARDENING,
    LOCKDOWN_PHASE_NET, LOCKDOWN_PHASE_TB, LOCKDOWN_PHASE_USB,
    LOCKDOWN_REASON_POLICY, LOCKDOWN_REASON_TB_UNKNOWN, LOCKDOWN_REASON_USB_UNKNOWN,
    LOCKDOWN_SOURCE_UEVENT,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// Netlink group 1 = kernel uevent multicast.
pub(crate) const UEVENT_GROUP: u32 = 1;
/// Bounded receive buffer.
pub(crate) const UEVENT_RECV_MAX: usize = 2048;
/// Maximum records in one `LOCKDOWN_EVENTS` response (§5).
pub(crate) const EVENTS_PER_RESPONSE: usize = 16;
const UEVENT_RCVBUF: i32 = 256 * 1024;
const UEVENT_TIMEOUT_MS: i64 = 250;

/// One decoded kernel uevent (only the closed fields the policy needs).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UeventAction {
    Add,
    Remove,
    Change,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UeventSubsystem {
    Usb,
    Thunderbolt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UeventMessage {
    pub(crate) action: UeventAction,
    pub(crate) subsystem: UeventSubsystem,
    pub(crate) devpath: String,
}

fn valid_devpath(devpath: &str) -> bool {
    devpath.len() > 8
        && devpath.len() <= 512
        && devpath.starts_with('/')
        && !devpath.contains("..")
        && devpath
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':'))
}

/// Parses the raw netlink kobject payload (no `nlmsghdr`): `action@devpath\0`
/// followed by `KEY=VALUE\0` pairs. Malformed input is `None`, never repaired.
pub(crate) fn parse_message(bytes: &[u8]) -> Option<UeventMessage> {
    if bytes.len() < 8 || bytes.len() > UEVENT_RECV_MAX {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut tokens = text.split('\0').filter(|token| !token.is_empty());
    let (action, mut devpath) = tokens.next()?.split_once('@')?;
    let action = match action {
        "add" => UeventAction::Add,
        "remove" => UeventAction::Remove,
        "change" => UeventAction::Change,
        _ => UeventAction::Other,
    };
    let mut subsystem = None;
    for token in tokens {
        let Some((key, value)) = token.split_once('=') else { continue };
        match key {
            "SUBSYSTEM" => subsystem = Some(value),
            "DEVPATH" => devpath = value,
            _ => {}
        }
    }
    let subsystem = match subsystem? {
        "usb" => UeventSubsystem::Usb,
        "thunderbolt" => UeventSubsystem::Thunderbolt,
        _ => return None,
    };
    if !valid_devpath(devpath) {
        return None;
    }
    Some(UeventMessage { action, subsystem, devpath: devpath.to_owned() })
}

/// Interface uevents (`1-1:1.0`) are not device policy targets.
fn is_interface(devpath: &str) -> bool {
    devpath.rsplit('/').next().is_some_and(|last| last.contains(':'))
}

/// One poll result; the trait makes the loop testable without root.
pub(crate) enum Poll {
    Message(Vec<u8>),
    Timeout,
    Rescan,
    Closed,
}

pub(crate) trait UeventSource {
    fn next(&mut self) -> Poll;
}

/// Real `NETLINK_KOBJECT_UEVENT` socket (group 1) with a bounded receive buffer
/// and a short timeout so the stop flag is seen promptly.
pub(crate) struct NetlinkSource {
    fd: libc::c_int,
}

impl NetlinkSource {
    pub(crate) fn open() -> Result<Self, String> {
        // SAFETY: socket() with constant, documented domain/type/protocol.
        let fd = unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_KOBJECT_UEVENT)
        };
        if fd < 0 {
            return Err(format!("netlink socket: {}", std::io::Error::last_os_error()));
        }
        let source = Self { fd };
        let rcvbuf: libc::c_int = UEVENT_RCVBUF;
        let timeout = libc::timeval { tv_sec: 0, tv_usec: UEVENT_TIMEOUT_MS * 1000 };
        // Best-effort socket tuning; a refusal keeps the bounded receive path.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&rcvbuf as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        // SAFETY: zeroed sockaddr_nl is a valid empty netlink address; the
        // family/group fields are set below before bind.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = UEVENT_GROUP;
        // SAFETY: address is a fully initialized sockaddr_nl for this socket.
        let rc = unsafe {
            libc::bind(
                fd,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            drop(source);
            return Err(format!("netlink bind: {error}"));
        }
        Ok(source)
    }
}

impl Drop for NetlinkSource {
    fn drop(&mut self) {
        // SAFETY: `fd` is owned by this source and closed exactly once here.
        unsafe { libc::close(self.fd) };
    }
}

impl UeventSource for NetlinkSource {
    fn next(&mut self) -> Poll {
        let mut buffer = [0u8; UEVENT_RECV_MAX];
        // SAFETY: zeroed sockaddr_nl receives kernel sender address to reject spoofed userspace nl_pid != 0.
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: buffer and sender are writable for their declared lengths and self.fd is open.
        let rc = unsafe {
            libc::recvfrom(
                self.fd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
                (&mut sender as *mut libc::sockaddr_nl).cast(),
                &mut addr_len,
            )
        };
        if rc >= 0 {
            if addr_len < std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t
                || sender.nl_family != libc::AF_NETLINK as u16
                || sender.nl_pid != 0
            {
                return Poll::Timeout;
            }
            let length = rc as usize;
            if length == 0 || length > buffer.len() {
                return Poll::Closed;
            }
            return Poll::Message(buffer[..length].to_vec());
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOBUFS) => Poll::Rescan,
            Some(libc::EAGAIN) | Some(libc::EINTR) => Poll::Timeout,
            _ => Poll::Closed,
        }
    }
}

/// Bounded rescan after `ENOBUFS`; re-applies the locked policy to what is
/// attached now and reports the honest outcome.
fn rescan(shared: &LockdownShared, usb_paths: &lockdown_usb::UsbPaths) {
    let policy = shared.policy();
    if policy.arm != ArmMode::Locked {
        return;
    }
    let usb = lockdown_usb::apply_usb(usb_paths);
    let tb = lockdown_usb::apply_tb(usb_paths);
    shared.add_usb_blocks(usb.blocked);
    shared.add_tb_blocks(tb.blocked);
    shared.emit(policy.epoch, LOCKDOWN_SOURCE_UEVENT, LOCKDOWN_REASON_POLICY, LOCKDOWN_PHASE_USB, usb.outcome, u64::from(usb.blocked));
    if tb.blocked > 0 || tb.outcome == LOCKDOWN_OUTCOME_APPLIED {
        shared.emit(policy.epoch, LOCKDOWN_SOURCE_UEVENT, LOCKDOWN_REASON_TB_UNKNOWN, LOCKDOWN_PHASE_TB, tb.outcome, u64::from(tb.blocked));
    }
}

fn handle_message(shared: &LockdownShared, usb_paths: &lockdown_usb::UsbPaths, message: &UeventMessage) {
    if message.action != UeventAction::Add {
        return;
    }
    // A USB interface uevent is not a policy target itself, but a late
    // interface (e.g. mass storage bound after the device was authorized) can
    // turn a benign composite device into a data device.  Resolve the parent
    // device and apply the parent policy there instead of skipping the event.
    let devpath = if message.subsystem == UeventSubsystem::Usb && is_interface(&message.devpath) {
        match lockdown_usb::parent_device_devpath(&message.devpath) {
            Some(parent) => parent,
            None => return,
        }
    } else {
        message.devpath.as_str()
    };
    let policy = shared.policy();
    shared.inc_uevent();
    // detail codes per phase (§6): 1 power-only, 2 console, 3 blocked,
    // 4 not-present, 5 denied/write failed, 6 audit (unlocked).
    let (reason, phase) = match message.subsystem {
        UeventSubsystem::Usb => (LOCKDOWN_REASON_USB_UNKNOWN, LOCKDOWN_PHASE_USB),
        UeventSubsystem::Thunderbolt => (LOCKDOWN_REASON_TB_UNKNOWN, LOCKDOWN_PHASE_TB),
    };
    if policy.arm == ArmMode::Unlocked {
        shared.emit(policy.epoch, LOCKDOWN_SOURCE_UEVENT, reason, phase, LOCKDOWN_OUTCOME_SKIPPED, 6);
        return;
    }
    let (outcome, detail, blocked) = match message.subsystem {
        UeventSubsystem::Usb => match lockdown_usb::apply_device(usb_paths, devpath) {
            Ok(lockdown_usb::DevicePolicy::Block) => (LOCKDOWN_OUTCOME_APPLIED, 3, true),
            Ok(lockdown_usb::DevicePolicy::PowerOnly) => (LOCKDOWN_OUTCOME_SKIPPED, 1, false),
            Ok(lockdown_usb::DevicePolicy::Console) => (LOCKDOWN_OUTCOME_SKIPPED, 2, false),
            Err("not-present") | Err("no-authorized-attribute") => (LOCKDOWN_OUTCOME_SKIPPED, 4, false),
            Err(_) => (LOCKDOWN_OUTCOME_FAILED, 5, false),
        },
        UeventSubsystem::Thunderbolt => match lockdown_usb::apply_tb_device(usb_paths, &message.devpath) {
            Ok(()) => (LOCKDOWN_OUTCOME_APPLIED, 3, true),
            Err("not-present") | Err("no-authorized-attribute") => (LOCKDOWN_OUTCOME_SKIPPED, 4, false),
            Err(_) => (LOCKDOWN_OUTCOME_FAILED, 5, false),
        },
    };
    if blocked {
        match message.subsystem {
            UeventSubsystem::Usb => shared.add_usb_blocks(1),
            UeventSubsystem::Thunderbolt => shared.add_tb_blocks(1),
        }
        if shared.auto_network_drop().is_err() {
            shared.emit(shared.policy().epoch, LOCKDOWN_SOURCE_UEVENT, LOCKDOWN_REASON_POLICY, LOCKDOWN_PHASE_NET, LOCKDOWN_OUTCOME_FAILED, 5);
        }
    }
    shared.emit(policy.epoch, LOCKDOWN_SOURCE_UEVENT, reason, phase, outcome, detail);
}

/// Drains a source until stopped or closed. Public for the fake-source test.
pub(crate) fn run(source: &mut dyn UeventSource, shared: &LockdownShared, usb_paths: &lockdown_usb::UsbPaths, stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        match source.next() {
            Poll::Timeout => {}
            Poll::Closed => break,
            Poll::Rescan => rescan(shared, usb_paths),
            Poll::Message(bytes) => {
                if let Some(message) = parse_message(&bytes) {
                    handle_message(shared, usb_paths, &message);
                }
            }
        }
    }
}

/// Handle of the running monitor thread; stopping is bounded by the socket
/// receive timeout.
pub(crate) struct Monitor {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Monitor {
    fn spawn(source: Box<dyn UeventSource + Send>, shared: Arc<LockdownShared>, usb_paths: lockdown_usb::UsbPaths) -> Result<Self, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let join = std::thread::Builder::new()
            .name("gedefense-lockdown-uevent".to_owned())
            .spawn(move || {
                let mut source = source;
                run(source.as_mut(), &shared, &usb_paths, &thread_stop);
            })
            .map_err(|_| "uevent-thread-spawn-failed".to_owned())?;
        Ok(Self { stop, join: Some(join) })
    }

    pub(crate) fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Starts the real kobject-uevent monitor (§2). `Err` means the capability is
/// missing; the caller reports it honestly as degraded.
pub(crate) fn start(shared: Arc<LockdownShared>, usb_paths: lockdown_usb::UsbPaths) -> Result<Monitor, String> {
    Monitor::spawn(Box::new(NetlinkSource::open()?), shared, usb_paths)
}

/// Starts a monitor from an injected source (tests, no root required).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn start_with_source(source: Box<dyn UeventSource + Send>, shared: Arc<LockdownShared>, usb_paths: lockdown_usb::UsbPaths) -> Result<Monitor, String> {
    Monitor::spawn(source, shared, usb_paths)
}

// ---------------------------------------------------------------------------
// LockdownCore bridge: monitor lifecycle, kernel state word and NET phase.
// ---------------------------------------------------------------------------

impl crate::lockdown::LockdownCore {
    /// Emits one lifecycle event with the current epoch (§5 wire source).
    pub(crate) fn emit(&self, source: u8, reason: u8, phase: u8, outcome: u8, detail: u64) {
        self.shared.emit(self.epoch, source, reason, phase, outcome, detail);
    }

    /// Publishes the arm policy/epoch the monitor acts on.
    pub(crate) fn sync_policy(&self) {
        self.shared.set_policy(crate::UeventPolicy {
            arm: self.arm_mode,
            auto_network_drop: self.policy & crate::lockdown::POLICY_AUTO_NETWORK_DROP != 0,
            allow_loopback: self.policy & crate::lockdown::POLICY_ALLOW_LOOPBACK != 0,
            epoch: self.epoch,
        });
    }

    /// §5 ARM starts/updates the uevent thread (idempotent).
    pub(crate) fn ensure_monitor(&mut self) -> Result<(), &'static str> {
        if !self.config.monitors || self.monitor.is_some() {
            return Ok(());
        }
        match start(Arc::clone(&self.shared), self.config.usb.clone()) {
            Ok(monitor) => {
                self.monitor = Some(monitor);
                Ok(())
            }
            Err(_) => {
                self.degraded = true;
                Err("uevent-monitor-unavailable")
            }
        }
    }

    /// §5 CLEAR stops the monitor thread.
    pub(crate) fn stop_monitor(&mut self) {
        if let Some(mut monitor) = self.monitor.take() {
            monitor.stop();
        }
    }

    /// Writes one §3 state word and verifies it with an array read-back.
    pub(crate) fn write_word_verified(&self, mode: u8, flags: u8) -> Result<(), &'static str> {
        let word = encode_lockdown_word(self.epoch, mode, flags);
        self.shared.word.write(word).map_err(|_| "state-map-write-failed")?;
        match decode_lockdown_word(self.shared.word.read().map_err(|_| "state-map-read-failed")?) {
            Some(decoded) if decoded.epoch == self.epoch && decoded.mode == mode && decoded.flags == flags => Ok(()),
            _ => Err("state-map-readback-mismatch"),
        }
    }

    /// Flag bits derived from applied phases, the arm policy and a hotplug
    /// auto-drop that is owned by `LockdownShared` (never by the kernel word
    /// alone).
    fn state_flags(&self) -> u8 {
        let mut flags = 0;
        if self.phases[LOCKDOWN_PHASE_NET as usize] == LOCKDOWN_OUTCOME_APPLIED
            || self.shared.auto_drop()
        {
            flags |= LOCKDOWN_FLAG_DROP_ALL;
        }
        if self.policy & crate::lockdown::POLICY_ALLOW_LOOPBACK != 0 {
            flags |= LOCKDOWN_FLAG_ALLOW_LOOPBACK;
        }
        if self.phases[LOCKDOWN_PHASE_HARDENING as usize] == LOCKDOWN_OUTCOME_APPLIED {
            flags |= LOCKDOWN_FLAG_HARDENING_APPLIED;
        }
        if self.phases[LOCKDOWN_PHASE_USB as usize] == LOCKDOWN_OUTCOME_APPLIED {
            flags |= LOCKDOWN_FLAG_USB_LOCKED;
        }
        if self.phases[LOCKDOWN_PHASE_TB as usize] == LOCKDOWN_OUTCOME_APPLIED {
            flags |= LOCKDOWN_FLAG_TB_LOCKED;
        }
        flags
    }

    /// Rewrites the word so the flag bits mirror the applied phases.
    pub(crate) fn refresh_word(&self) -> Result<(), &'static str> {
        if self.latch == crate::lockdown::Latch::Off {
            return Ok(());
        }
        self.write_word_verified(LOCKDOWN_MODE_ARMED, self.state_flags())
    }

    /// §6.1 NET phase: DROP_ALL (+ALLOW_LOOPBACK per flag) plus read-back.
    pub(crate) fn net_phase(&mut self) -> (u8, &'static str) {
        let mut flags = LOCKDOWN_FLAG_DROP_ALL;
        if self.policy & crate::lockdown::POLICY_ALLOW_LOOPBACK != 0 {
            flags |= LOCKDOWN_FLAG_ALLOW_LOOPBACK;
        }
        match self.write_word_verified(LOCKDOWN_MODE_ARMED, flags) {
            Ok(()) => (LOCKDOWN_OUTCOME_APPLIED, "applied"),
            Err(reason) => (LOCKDOWN_OUTCOME_FAILED, reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(devpath: &str, subsystem: &str, action: &str) -> Vec<u8> {
        format!("{action}@{devpath}\0ACTION={action}\0SUBSYSTEM={subsystem}\0DEVPATH={devpath}\0").into_bytes()
    }

    #[test]
    fn parser_reads_closed_fields_and_rejects_garbage() {
        let message = parse_message(&raw("/devices/pci0000:00/usb1/1-2", "usb", "add")).expect("usb add");
        assert_eq!(message.action, UeventAction::Add);
        assert_eq!(message.subsystem, UeventSubsystem::Usb);
        assert_eq!(message.devpath, "/devices/pci0000:00/usb1/1-2");
        let tb = parse_message(&raw("/devices/pci0000:00/0000:00:0d.2/domain0/0-1", "thunderbolt", "add")).expect("tb add");
        assert_eq!(tb.subsystem, UeventSubsystem::Thunderbolt);
        assert_eq!(parse_message(&raw("/devices/x", "usb", "remove")).map(|m| m.action), Some(UeventAction::Remove));
        assert!(parse_message(b"").is_none());
        // Without a DEVPATH key the first token's path is authoritative.
        assert_eq!(parse_message(b"add@/devices/x\0SUBSYSTEM=usb\0").map(|m| m.devpath), Some("/devices/x".to_owned()));
        assert!(parse_message(b"add@/devices/x\0SUBSYSTEM=net\0DEVPATH=/devices/x\0").is_none());
        assert!(parse_message(b"add@/devices/../x\0SUBSYSTEM=usb\0DEVPATH=/devices/../x\0").is_none());
        assert!(parse_message(&[0xff, 0xfe, 0, 0]).is_none());
        assert!(is_interface("/devices/pci0000:00/usb1/1-2/1-2:1.0"));
        assert!(!is_interface("/devices/pci0000:00/usb1/1-2"));
    }

    #[test]
    fn usb_interface_add_uevent_applies_the_parent_device_policy() {
        use std::fs;
        let root = lockdown_usb::tests::fixture("uevent-interface");
        let paths = lockdown_usb::UsbPaths::new(root.join("sys"));
        let shared = crate::LockdownShared::new(
            Arc::new(crate::tests::MemoryWordStore::new()),
            crate::UeventPolicy { arm: ArmMode::Locked, auto_network_drop: false, allow_loopback: true, epoch: 7 },
        );
        // Class-00 parent with a late mass-storage interface: the interface
        // uevent has to resolve and block the parent device.
        let parent = root.join("sys/devices/pci0000:00/usb1/1-9");
        fs::create_dir_all(&parent).expect("parent device dir");
        for (name, value) in
            [("bDeviceClass", "00"), ("bNumInterfaces", "01"), ("bNumConfigurations", "01"), ("authorized", "1")]
        {
            fs::write(parent.join(name), format!("{value}\n")).expect(name);
        }
        let interface = parent.join("1-9:1.0");
        fs::create_dir_all(&interface).expect("interface dir");
        fs::write(interface.join("bInterfaceClass"), "08\n").expect("interface class");
        let message = parse_message(&raw("/devices/pci0000:00/usb1/1-9/1-9:1.0", "usb", "add")).expect("interface add");
        handle_message(&shared, &paths, &message);
        assert_eq!(
            fs::read_to_string(parent.join("authorized")).unwrap().trim(),
            "0",
            "late storage interface must deauthorize the parent"
        );
        assert_eq!(shared.uevent_counters(), (1, 1, 0));
        let (_dropped, records) = shared.take_events(EVENTS_PER_RESPONSE);
        assert!(records.iter().any(|event| {
            event.phase == LOCKDOWN_PHASE_USB && event.outcome == LOCKDOWN_OUTCOME_APPLIED
        }));
        // A genuine HID console parent stays authorized: its interface list is
        // complete and the parent policy is Console, not Block.
        let console = root.join("sys/devices/pci0000:00/usb1/1-10");
        fs::create_dir_all(&console).expect("console device dir");
        for (name, value) in
            [("bDeviceClass", "03"), ("bNumInterfaces", "01"), ("bNumConfigurations", "01"), ("authorized", "1")]
        {
            fs::write(console.join(name), format!("{value}\n")).expect(name);
        }
        let console_interface = console.join("1-10:1.0");
        fs::create_dir_all(&console_interface).expect("console interface dir");
        fs::write(console_interface.join("bInterfaceClass"), "03\n").expect("console interface class");
        let console_message = parse_message(&raw("/devices/pci0000:00/usb1/1-10/1-10:1.0", "usb", "add")).expect("console iface add");
        handle_message(&shared, &paths, &console_message);
        assert_eq!(fs::read_to_string(console.join("authorized")).unwrap().trim(), "1");
        // Non-add actions on an interface are still ignored (not a policy trigger).
        let remove = parse_message(&raw("/devices/pci0000:00/usb1/1-9/1-9:1.0", "usb", "remove")).expect("interface remove");
        handle_message(&shared, &paths, &remove);
        assert_eq!(shared.uevent_counters(), (2, 1, 0));
    }

    #[test]
    fn root_gated_real_netlink_monitor_is_skipped_without_privileges() {
        // Documents an honest capability check: only a root process can bind
        // uevent group 1, otherwise the test reports SKIP and returns.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP root-gated uevent netlink test: not root");
            return;
        }
        let shared = crate::LockdownShared::new(
            Arc::new(crate::tests::MemoryWordStore::new()),
            crate::UeventPolicy::default(),
        );
        let monitor = start(Arc::new(shared), lockdown_usb::UsbPaths::system()).expect("netlink monitor");
        drop(monitor);
    }
}
