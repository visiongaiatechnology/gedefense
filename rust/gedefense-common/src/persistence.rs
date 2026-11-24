//! V6.3.0 AP-5 — persistence/peripheral integrity wire contract
//! (`PERSIST_GUARD_*`).
//!
//! The kernel half (`rust/gedefense-ebpf/src/persistence.rs`) observes, never
//! denies:
//!
//! - `lsm/file_open`: opens of linker/PAM/systemd-generator/drop-in/udev/
//!   `authorized_keys`/`sshrc`/shell-profile paths, desktop peripheral device
//!   nodes (`/dev/video*`, `/dev/snd/*`, `/dev/input/event*`) and user secret
//!   stores (`~/.ssh`, `~/.gnupg`, `~/.aws`, browser profiles, keyrings),
//! - `lsm/mmap_file`: libraries mapped into a protected executable
//!   (`sshd`, `sshd-session`, `sudo`, `su`, `login`, `curl`),
//! - `lsm/ptrace_access_check` and
//!   `tp/syscalls/sys_enter_process_vm_readv|writev`: cross-process memory
//!   access and `ptrace` attachment,
//! - the privileged core additionally injects userspace drift records
//!   (SHA-256 mismatch / disappearance / appearance of a watched exact file)
//!   into the *same* bounded queue through the same encoder.
//!
//! This module owns the ABI shared by the eBPF object, the privileged core and
//! the Go control plane:
//!
//! - [`PersistenceEvent`]: fixed 64-byte `#[repr(C)]` ring record (native
//!   endian) with a rejecting decoder (never repairs),
//! - [`encode_persistence_event`]: the single encoder used by tests and the
//!   core's userspace drift queue, so both producers share one byte layout,
//! - the path-class / event-kind / action constants and the path map value
//!   layout (`class u8 | owner_uid u32 << 8 | directory bit 63`),
//! - the `PERSIST_GUARD_STATE` word layout (epoch/armed/magic/ABI),
//! - the `PERSIST_GUARD_OFFSETS` table index/ABI contract published by the
//!   core (BTF-resolved structure offsets, LSM hook arities and syscall
//!   tracepoint field offsets). Kernel struct offsets are never hard-coded in
//!   the eBPF object.
//!
//! Observe-only by construction: the shipped producers only ever emit
//! [`PERSIST_ACTION_AUDIT`]; `DENY` exists in the ABI as a closed value for
//! future consumers but is never produced and grants no response action.
//!
//! # Wire layout (64 bytes, native endian)
//!
//! ```text
//! offset  size  field
//!      0     8  ts_ns: u64
//!      8     8  ino: u64              watched object / mapped file inode
//!     16     4  dev: u32              its st_dev (0 only for identity-less kinds)
//!     20     4  pid: u32
//!     24     4  tgid: u32
//!     28     4  uid: u32
//!     32     4  detail_code: u32      kind-specific (access mode / owner uid /
//!                                     session bits / target pid / ptrace mode /
//!                                     drift reason / baseline root count)
//!     36     1  class: u8             path class (0 = no path class)
//!     37     1  kind: u8
//!     38     1  action: u8            1=AUDIT 2=DENY 3=OBSERVE (producer: AUDIT)
//!     39     1  reserved: u8          must be zero
//!     40    16  comm: [u8; 16]        printable, NUL-padded task name
//!     56     8  detail: [u8; 8]       printable, NUL-padded bounded detail
//!     64
//! ```
//!
//! The fixed 64-byte record leaves eight bytes for the bounded `detail` slot
//! (the enumerated AP-5 contract asks for "bounded detail, e.g. `[u8;24]`");
//! the semantic payload that needs more space is carried in `detail_code` and
//! the 16-byte `comm`, so no field had to be dropped. The kind-specific split:
//!
//! - `KIND_MEMORY_SCRAPE`: `detail_code` = target pid, `detail` = `readv`/
//!   `writev`;
//! - `KIND_PTRACE_ACCESS`: `detail_code` = child tgid, `detail` = ptrace mode as
//!   decimal text;
//! - every other kind: `detail` is empty (all-zero).

mod helpers;
mod paths;

pub use self::helpers::*;
pub use self::paths::*;

/// Wire size of one [`PersistenceEvent`].
pub const PERSIST_EVENT_WIRE_BYTES: usize = 64;
/// `PERSIST_GUARD_EVENTS` ring size (128 KiB = 2048 queued 64-byte records).
pub const PERSIST_EVENT_RING_BYTES: u32 = 1 << 17;
/// Maximum records the core returns per drain (bounded control-plane response).
pub const PERSIST_MAX_EVENTS_PER_DRAIN: usize = 16;
/// Maximum text payload bytes the core returns per drain.
pub const PERSIST_MAX_DRAIN_PAYLOAD_BYTES: usize = 4096;
/// `PERSIST_GUARD_PATHS` capacity: watched file/directory inode identities.
pub const PERSIST_PATH_MAP_ENTRIES: u32 = 4_096;
/// `PERSIST_GUARD_EXECS` capacity: protected executable identities.
pub const PERSIST_EXEC_MAP_ENTRIES: u32 = 256;
/// `PERSIST_GUARD_OFFSETS` table length (37 used, 11 reserved).
pub const PERSIST_OFFSETS_TABLE_LEN: usize = 48;

// ---------------------------------------------------------------------------
// Path classes
// ---------------------------------------------------------------------------

/// No watched path class: memory-scrape / ptrace / baseline records carry no
/// file identity. Never produced by the `file_open` path-class ladder.
pub const PERSIST_CLASS_UNSPECIFIED: u8 = 0;
/// `/etc/ld.so.preload` (the classic pre-execution `LD_PRELOAD` hook).
pub const PERSIST_CLASS_LD_PRELOAD: u8 = 1;
/// `/etc/ld.so.conf` and `/etc/ld.so.conf.d/*.conf` (linker search path).
pub const PERSIST_CLASS_LD_CONF: u8 = 2;
/// `ld-linux*.so*` and the `tls` linker roots (`/lib*/tls`).
pub const PERSIST_CLASS_LD_SO: u8 = 3;
/// TLS resolution libraries below a `tls` linker root.
pub const PERSIST_CLASS_TLS: u8 = 4;
/// PAM configuration (`/etc/pam.d`) and PAM modules (`/lib*/security/pam_*.so`).
pub const PERSIST_CLASS_PAM: u8 = 5;
/// systemd system generators (`/etc|lib|usr/local/lib|usr/lib/systemd/system-generators`).
pub const PERSIST_CLASS_SYSTEMD_GENERATOR: u8 = 6;
/// systemd unit/drop-in roots (`*.d/*.conf`, `/etc/systemd/system/*.conf`).
pub const PERSIST_CLASS_SYSTEMD_DROPIN: u8 = 7;
/// udev rule and configuration roots (`/etc/udev`, `/lib/udev`).
pub const PERSIST_CLASS_UDEV: u8 = 8;
/// `~/.ssh/authorized_keys` (and `/root/.ssh/authorized_keys`).
pub const PERSIST_CLASS_AUTHORIZED_KEYS: u8 = 9;
/// `/etc/ssh/sshrc` (per-login SSH command hook).
pub const PERSIST_CLASS_SSHRC: u8 = 10;
/// Shell profile hooks (`/etc/profile*`, `~/.bashrc`, `~/.profile`, ...).
pub const PERSIST_CLASS_SHELL_PROFILE: u8 = 11;
/// Camera device nodes (`/dev/video*`).
pub const PERSIST_CLASS_DEVICE_CAMERA: u8 = 20;
/// Microphone/capture devices (`/dev/snd/pcm*`, `/dev/snd/control*`).
pub const PERSIST_CLASS_DEVICE_MIC: u8 = 21;
/// evdev input devices (`/dev/input/event*`, keyboard sniffer class).
pub const PERSIST_CLASS_DEVICE_EVDEV: u8 = 22;
/// Desktop capture sockets (Wayland/PipeWire/PulseAudio under `/run/user/<uid>`).
pub const PERSIST_CLASS_DEVICE_CAPTURE_SOCKET: u8 = 23;
/// `~/.ssh` secret store.
pub const PERSIST_CLASS_SECRET_SSH: u8 = 30;
/// `~/.gnupg` secret store.
pub const PERSIST_CLASS_SECRET_GNUPG: u8 = 31;
/// `~/.aws` cloud credential store.
pub const PERSIST_CLASS_SECRET_CLOUD: u8 = 32;
/// Browser credential/cookie stores (`Login Data`, `Cookies`, `logins.json`, ...).
pub const PERSIST_CLASS_SECRET_BROWSER: u8 = 33;
/// Desktop keyrings (`~/.local/share/keyrings`, KWallet, ...).
pub const PERSIST_CLASS_SECRET_KEYRING: u8 = 34;

// ---------------------------------------------------------------------------
// Event record
// ---------------------------------------------------------------------------

/// One persistence/peripheral observation (see the module wire layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistenceEvent {
    pub ts_ns: u64,
    pub ino: u64,
    pub dev: u32,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub detail_code: u32,
    pub class: u8,
    pub kind: u8,
    pub action: u8,
    pub reserved: u8,
    pub comm: [u8; 16],
    pub detail: [u8; 8],
}

// Compile-time coupling to the wire contract: a layout drift must fail the
// eBPF and core builds instead of silently corrupting a ring record.
const _: () = assert!(core::mem::size_of::<PersistenceEvent>() == PERSIST_EVENT_WIRE_BYTES);
const _: () = assert!(core::mem::align_of::<PersistenceEvent>() == 8);

impl PersistenceEvent {
    /// The `comm` bytes up to the first NUL (the decoder already proved the slot
    /// is NUL-padded and printable).
    pub fn comm_bytes(&self) -> &[u8] {
        let mut end = 0usize;
        while end < self.comm.len() && self.comm[end] != 0 {
            end += 1;
        }
        &self.comm[..end]
    }

    /// The `detail` bytes up to the first NUL (empty when the slot is zero).
    pub fn detail_bytes(&self) -> &[u8] {
        let mut end = 0usize;
        while end < self.detail.len() && self.detail[end] != 0 {
            end += 1;
        }
        &self.detail[..end]
    }
}

/// Encodes one record into its 64-byte wire form. This is the encoder used by
/// the core's userspace drift queue and by the tests, so the kernel producer,
/// the userspace producer and the tests cannot drift apart silently.
pub fn encode_persistence_event(event: &PersistenceEvent) -> [u8; PERSIST_EVENT_WIRE_BYTES] {
    let mut raw = [0u8; PERSIST_EVENT_WIRE_BYTES];
    raw[0..8].copy_from_slice(&event.ts_ns.to_ne_bytes());
    raw[8..16].copy_from_slice(&event.ino.to_ne_bytes());
    raw[16..20].copy_from_slice(&event.dev.to_ne_bytes());
    raw[20..24].copy_from_slice(&event.pid.to_ne_bytes());
    raw[24..28].copy_from_slice(&event.tgid.to_ne_bytes());
    raw[28..32].copy_from_slice(&event.uid.to_ne_bytes());
    raw[32..36].copy_from_slice(&event.detail_code.to_ne_bytes());
    raw[36] = event.class;
    raw[37] = event.kind;
    raw[38] = event.action;
    raw[39] = event.reserved;
    raw[40..56].copy_from_slice(&event.comm);
    raw[56..64].copy_from_slice(&event.detail);
    raw
}

/// True when the 16-byte comm slot is non-empty, printable ASCII and
/// NUL-padded. The eBPF producer normalises every non-printable byte to `?`
/// before writing, so a record that fails this check cannot have been produced.
#[inline(always)]
pub fn persistence_comm_is_valid(comm: &[u8; 16]) -> bool {
    let mut padded = false;
    let mut seen = 0usize;
    for &byte in comm.iter() {
        if padded {
            if byte != 0 {
                return false;
            }
        } else if byte == 0 {
            padded = true;
        } else {
            if !(0x20..=0x7e).contains(&byte) {
                return false;
            }
            seen += 1;
        }
    }
    padded && seen > 0
}

/// True when the 8-byte detail slot is printable ASCII and NUL-padded (the
/// all-zero slot is the normal "no detail" case).
#[inline(always)]
pub fn persistence_detail_is_valid(detail: &[u8; 8]) -> bool {
    let mut padded = false;
    for &byte in detail.iter() {
        if padded {
            if byte != 0 {
                return false;
            }
        } else if byte == 0 {
            padded = true;
        } else if !(0x20..=0x7e).contains(&byte) {
            return false;
        }
    }
    padded
}

/// Decodes one fixed-size record. Returns `None` for every record the shipped
/// producers cannot emit: wrong length, unknown action/kind/class, zero
/// producer identity (`ts_ns`/`pid`/`tgid`), reserved byte not zero, a non
/// printable or unpadded `comm`, a non printable or unpadded `detail`, a
/// half-null file identity, or a class/kind pair outside the documented matrix.
pub fn decode_persistence_event(bytes: &[u8]) -> Option<PersistenceEvent> {
    if bytes.len() != PERSIST_EVENT_WIRE_BYTES {
        return None;
    }
    let ts_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let ino = u64::from_ne_bytes(bytes[8..16].try_into().ok()?);
    let dev = u32::from_ne_bytes(bytes[16..20].try_into().ok()?);
    let pid = u32::from_ne_bytes(bytes[20..24].try_into().ok()?);
    let tgid = u32::from_ne_bytes(bytes[24..28].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[28..32].try_into().ok()?);
    let detail_code = u32::from_ne_bytes(bytes[32..36].try_into().ok()?);
    let class = bytes[36];
    let kind = bytes[37];
    let action = bytes[38];
    let reserved = bytes[39];
    let comm: [u8; 16] = bytes[40..56].try_into().ok()?;
    let detail: [u8; 8] = bytes[56..64].try_into().ok()?;

    if ts_ns == 0
        || pid == 0
        || tgid == 0
        || reserved != 0
        || !persistence_action_known(action)
        || !persistence_kind_known(kind)
        || !persistence_comm_is_valid(&comm)
        || !persistence_detail_is_valid(&detail)
        || (dev == 0) != (ino == 0)
    {
        return None;
    }

    let identity_required = match kind {
        PERSIST_KIND_INTEGRITY_WRITE => {
            // The integrity ladder may only report the eleven path classes.
            if !persistence_class_is_integrity(class) {
                return None;
            }
            true
        }
        PERSIST_KIND_LIBRARY_MMAP => {
            // Protected executables map their libraries; the class is the
            // linker `.so` class by contract.
            if class != PERSIST_CLASS_LD_SO {
                return None;
            }
            true
        }
        PERSIST_KIND_PERIPHERAL_OPEN => {
            if !persistence_class_is_device(class) {
                return None;
            }
            true
        }
        PERSIST_KIND_SECRET_OPEN => {
            if !persistence_class_is_secret(class) {
                return None;
            }
            true
        }
        PERSIST_KIND_MEMORY_SCRAPE | PERSIST_KIND_PTRACE_ACCESS => {
            // Cross-process memory access carries no file identity.
            if class != PERSIST_CLASS_UNSPECIFIED {
                return None;
            }
            false
        }
        PERSIST_KIND_DRIFT => {
            // Drift is only defined for the content-baselined integrity roots.
            if !persistence_class_is_integrity(class) {
                return None;
            }
            if !matches!(
                detail_code,
                PERSIST_DRIFT_CONTENT
                    | PERSIST_DRIFT_MISSING
                    | PERSIST_DRIFT_APPEARED
                    | PERSIST_DRIFT_REPLACED
            ) {
                return None;
            }
            true
        }
        PERSIST_KIND_BASELINE => {
            // A baseline marker names no file: it is the userspace reference
            // point for the whole root set.
            if class != PERSIST_CLASS_UNSPECIFIED {
                return None;
            }
            false
        }
        _ => return None,
    };

    if identity_required {
        if dev == 0 || ino == 0 {
            return None;
        }
    } else if dev != 0 || ino != 0 {
        return None;
    }

    Some(PersistenceEvent {
        ts_ns,
        ino,
        dev,
        pid,
        tgid,
        uid,
        detail_code,
        class,
        kind,
        action,
        reserved,
        comm,
        detail,
    })
}

#[cfg(test)]
mod tests;
