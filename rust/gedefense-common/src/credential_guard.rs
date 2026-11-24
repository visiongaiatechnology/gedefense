//! M2.4 (6.2.0): shared wire contract of the eBPF `file_open` credential guard.
//!
//! The kernel half (`rust/gedefense-ebpf/src/credential_guard.rs`) denies
//! `file_open` on the protected credential inodes for every task that is not an
//! allowlisted authentication/system binary. This module owns the ABI:
//!
//! - [`CredentialGuardEvent`]: 64-byte ring record (native endian, `repr(C)`),
//! - [`decode_credential_guard_event`]: rejecting decoder (never repairs),
//! - `CRED_GUARD_STATE` word layout (epoch/armed/flags/magic/ABI),
//! - protected-path contract and the allowlist policy mirror.
//!
//! Protected inodes are identity keys `(s_dev u32, i_ino u64)` packed as
//! 16-byte map keys (`dev` LE u32, `ino` LE u64, four zero bytes). Two maps
//! exist: exact files (`/etc/shadow`, `/etc/gshadow` and every current file in
//! `/etc/vgt/gedefense/secrets/`) and protected *directories*
//! (`/etc/vgt/gedefense/secrets`), so a secret file created after startup is
//! still covered through its immediate parent directory without an unbounded
//! path walk.
//!
//! The allowlist is a *kernel-side* exact task-name check (auth/system
//! binaries); task names are spoofable by a local attacker, which is why the
//! control plane correlates `XDR.CREDENTIAL_READ_BLOCKED` with the XDR exec
//! sensor. V6.3.0 AP-1 made the real executable identity the *primary* gate and
//! demoted this name list to the documented fallback: when the executable-inode
//! gate is available a deny carries [`CRED_GUARD_ACTION_DENY_INODE`] (the same
//! `-EACCES` verdict, decided by `TRUSTED_EXEC_INODES`), and the fallback mode is
//! audited (`FALLBACK_COMM`) instead of being silently equated with the inode
//! gate. The guard is fail-open while the policy/offsets are unavailable (a
//! broken guard must never lock out PAM/login), but it reports `active=0` in
//! `CRED_GUARD_STATUS` instead of claiming enforcement.

/// Wire size of one [`CredentialGuardEvent`].
pub const CRED_GUARD_EVENT_WIRE_BYTES: usize = 64;

/// Event action: the kernel denied the open with `-EACCES`.
pub const CRED_GUARD_ACTION_DENY: u8 = 1;
/// Event action: audit only (reserved for a future observe mode; the shipped
/// guard only emits DENY records).
pub const CRED_GUARD_ACTION_AUDIT: u8 = 2;
/// V6.3.0 AP-1: the `-EACCES` deny was decided by the executable-inode trust
/// gate (`TRUSTED_EXEC_INODES`), not by the (spoofable) comm allowlist. The
/// control plane labels such a deny as an inode-gate denial; the kernel verdict
/// is byte-for-byte the same `-EACCES` as [`CRED_GUARD_ACTION_DENY`].
pub const CRED_GUARD_ACTION_DENY_INODE: u8 = 3;

/// `CRED_GUARD_STATE` word layout (ABI 1): epoch 0..31, armed bit 32, magic
/// 40..47, ABI 48..55. A default/absent word means "not ready": the kernel hook
/// never denies, and the core reports `active=0`.
pub const CRED_GUARD_STATE_MAGIC: u8 = 0x43;
pub const CRED_GUARD_STATE_ABI: u8 = 1;
pub const CRED_GUARD_STATE_ARMED_SHIFT: u64 = 32;
pub const CRED_GUARD_STATE_MAGIC_SHIFT: u64 = 40;
pub const CRED_GUARD_STATE_ABI_SHIFT: u64 = 48;
pub const CRED_GUARD_STATE_BYTE_MASK: u64 = 0xff;

/// Exact protected files (their inodes are always protected).
pub const CRED_GUARD_PROTECTED_FILES: &[&str] = &["/etc/shadow", "/etc/gshadow"];
/// Protected directory: every direct child is treated as a credential secret.
pub const CRED_GUARD_PROTECTED_DIRS: &[&str] = &["/etc/vgt/gedefense/secrets"];
/// Bounds: files scanned from the secrets directory at startup, map capacities.
pub const CRED_GUARD_MAX_SECRET_FILES: u32 = 128;
pub const CRED_GUARD_FILE_MAP_ENTRIES: u32 = 256;
pub const CRED_GUARD_DIR_MAP_ENTRIES: u32 = 32;
/// `CRED_GUARD_EVENTS` ring size (256 KiB = 4096 queued 64-byte records).
pub const CRED_GUARD_EVENT_RING_BYTES: u32 = 1 << 18;

/// Exact task-name allowlist: PAM/login credential readers. It must include
/// the local TTY login path (`login`), cron's PAM account check, and the
/// account/group management tools used by `apt`/`dpkg` maintainer scripts;
/// otherwise a package upgrade or a local console login would receive EACCES
/// on `/etc/shadow` even though the kernel guard is otherwise working.
pub const CRED_GUARD_TRUSTED_COMMS_EXACT: &[&str] = &[
    "unix_chkpwd",
    "sshd",
    "sshd-session",
    "sudo",
    "su",
    "passwd",
    "chpasswd",
    "login",
    "cron",
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupmod",
    "groupdel",
    "gpasswd",
    "chage",
    "newgrp",
    "vipw",
    "pwck",
    "grpck",
    "(systemd)",
    "(sd-pam)",
    "(sd-executor)",
];
/// Task-name prefixes that are always allowed (`systemd-*`, `gedefense-*`).
pub const CRED_GUARD_TRUSTED_COMM_PREFIXES: &[&str] = &["systemd", "gedefense"];

/// True for the documented kernel-side allowlist (exact names and prefixes).
///
/// Matches against compile-time literal constants rather than indexing a
/// static `&[&str]` slice-of-slices table, so no `.data.rel.ro` pointer loads
/// (`R8 invalid mem access 'scalar'`) or stack-pointer bitmasks (`r1 &= -8`)
/// are emitted for the Linux eBPF verifier.
#[inline(always)]
pub fn credential_reader_allowed(comm: &[u8]) -> bool {
    if comm.is_empty() || !is_ascii_task_bytes(comm) {
        return false;
    }
    bytes_eq_constant(comm, b"unix_chkpwd")
        || bytes_eq_constant(comm, b"sshd")
        || bytes_eq_constant(comm, b"sshd-session")
        || bytes_eq_constant(comm, b"sudo")
        || bytes_eq_constant(comm, b"su")
        || bytes_eq_constant(comm, b"passwd")
        || bytes_eq_constant(comm, b"chpasswd")
        || bytes_eq_constant(comm, b"login")
        || bytes_eq_constant(comm, b"cron")
        || bytes_eq_constant(comm, b"useradd")
        || bytes_eq_constant(comm, b"usermod")
        || bytes_eq_constant(comm, b"userdel")
        || bytes_eq_constant(comm, b"groupadd")
        || bytes_eq_constant(comm, b"groupmod")
        || bytes_eq_constant(comm, b"groupdel")
        || bytes_eq_constant(comm, b"gpasswd")
        || bytes_eq_constant(comm, b"chage")
        || bytes_eq_constant(comm, b"newgrp")
        || bytes_eq_constant(comm, b"vipw")
        || bytes_eq_constant(comm, b"pwck")
        || bytes_eq_constant(comm, b"grpck")
        || bytes_eq_constant(comm, b"(systemd)")
        || bytes_eq_constant(comm, b"(sd-pam)")
        || bytes_eq_constant(comm, b"(sd-executor)")
        || bytes_starts_with_constant(comm, b"systemd")
        || bytes_starts_with_constant(comm, b"gedefense")
}

#[inline(always)]
fn is_ascii_task_bytes(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] >= 0x80 {
            return false;
        }
        i += 1;
    }
    true
}

#[inline(always)]
fn bytes_eq_constant(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    let mut i = 0;
    while i < b.len() {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

#[inline(always)]
fn bytes_starts_with_constant(haystack: &[u8], prefix: &[u8]) -> bool {
    if haystack.len() < prefix.len() {
        return false;
    }
    let mut diff = 0u8;
    let mut i = 0;
    while i < prefix.len() {
        diff |= haystack[i] ^ prefix[i];
        i += 1;
    }
    diff == 0
}

/// Converts a Linux kernel `super_block->s_dev` (`new_encode_dev`: `(major << 20) | minor`)
/// into the 32-bit low word of userspace `stat.st_dev` (`gnu_dev_makedev`), matching
/// `std::os::unix::fs::MetadataExt::dev()` across standard and high-minor filesystems.
#[inline(always)]
pub const fn kernel_s_dev_to_stat_u32(kdev: u32) -> u32 {
    let major = kdev >> 20;
    let minor = kdev & 0x000f_ffff;
    ((minor & 0x000f_ff00) << 12) | ((major & 0xfff) << 8) | (minor & 0xff)
}

/// Packs one `(s_dev, i_ino)` identity as the 16-byte map key.
pub fn credential_identity_key(dev: u32, ino: u64) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[0..4].copy_from_slice(&dev.to_le_bytes());
    key[4..12].copy_from_slice(&ino.to_le_bytes());
    key
}

/// Unpacks a 16-byte identity key; `None` for non-zero reserved bytes (a
/// producer cannot have written such a key).
pub fn decode_credential_identity_key(key: &[u8]) -> Option<(u32, u64)> {
    let mut raw = [0u8; 16];
    raw.copy_from_slice(key.get(..16)?);
    if raw[12..] != [0u8; 4] {
        return None;
    }
    let dev = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let ino = u64::from_le_bytes([
        raw[4], raw[5], raw[6], raw[7], raw[8], raw[9], raw[10], raw[11],
    ]);
    if dev == 0 || ino == 0 {
        return None;
    }
    Some((dev, ino))
}

/// One credential-read denial/audit record emitted by the eBPF hook.
///
/// Byte layout (native endian, size 64): `ts_ns` 0, `dev` 8, `ino` 16, `pid` 24,
/// `tgid` 28, `uid` 32, `inode_mode` 36, `action` 40, `reserved` 41 (3 zero
/// bytes), `comm` 44 (16 NUL-padded bytes), `reserved2` 60 (4 zero bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialGuardEvent {
    pub ts_ns: u64,
    pub dev: u32,
    pub ino: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub inode_mode: u32,
    pub action: u8,
    pub reserved: [u8; 3],
    pub comm: [u8; 16],
    pub reserved2: [u8; 4],
}

/// Decodes one fixed-size guard record; `None` for every record the producer
/// cannot have emitted (length, action, zero pid/ts/identity, reserved bytes,
/// missing `comm` NUL padding).
pub fn decode_credential_guard_event(bytes: &[u8]) -> Option<CredentialGuardEvent> {
    if bytes.len() != CRED_GUARD_EVENT_WIRE_BYTES {
        return None;
    }
    let ts_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let dev = u32::from_ne_bytes(bytes[8..12].try_into().ok()?);
    let ino = u64::from_ne_bytes(bytes[16..24].try_into().ok()?);
    let pid = u32::from_ne_bytes(bytes[24..28].try_into().ok()?);
    let tgid = u32::from_ne_bytes(bytes[28..32].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[32..36].try_into().ok()?);
    let inode_mode = u32::from_ne_bytes(bytes[36..40].try_into().ok()?);
    let action = bytes[40];
    let reserved: [u8; 3] = bytes[41..44].try_into().ok()?;
    let comm: [u8; 16] = bytes[44..60].try_into().ok()?;
    let reserved2: [u8; 4] = bytes[60..64].try_into().ok()?;
    if !matches!(
        action,
        CRED_GUARD_ACTION_DENY | CRED_GUARD_ACTION_AUDIT | CRED_GUARD_ACTION_DENY_INODE
    )
        || ts_ns == 0
        || pid == 0
        || tgid == 0
        || dev == 0
        || ino == 0
        || reserved != [0u8; 3]
        || reserved2 != [0u8; 4]
        || !comm_is_nul_padded(&comm)
    {
        return None;
    }
    Some(CredentialGuardEvent {
        ts_ns,
        dev,
        ino,
        pid,
        tgid,
        uid,
        inode_mode,
        action,
        reserved,
        comm,
        reserved2,
    })
}

fn comm_is_nul_padded(comm: &[u8; 16]) -> bool {
    let mut padded = false;
    for &byte in comm.iter() {
        if padded {
            if byte != 0 {
                return false;
            }
        } else if byte == 0 {
            padded = true;
        }
    }
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CredentialGuardEvent {
        CredentialGuardEvent {
            ts_ns: 987_654_321,
            dev: 0x0801,
            ino: 4242,
            pid: 4243,
            tgid: 4242,
            uid: 1000,
            inode_mode: 0o100640,
            action: CRED_GUARD_ACTION_DENY,
            reserved: [0; 3],
            comm: *b"cat\0\0\0\0\0\0\0\0\0\0\0\0\0",
            reserved2: [0; 4],
        }
    }

    fn encode(event: &CredentialGuardEvent) -> [u8; CRED_GUARD_EVENT_WIRE_BYTES] {
        let mut raw = [0u8; CRED_GUARD_EVENT_WIRE_BYTES];
        raw[0..8].copy_from_slice(&event.ts_ns.to_ne_bytes());
        raw[8..12].copy_from_slice(&event.dev.to_ne_bytes());
        raw[16..24].copy_from_slice(&event.ino.to_ne_bytes());
        raw[24..28].copy_from_slice(&event.pid.to_ne_bytes());
        raw[28..32].copy_from_slice(&event.tgid.to_ne_bytes());
        raw[32..36].copy_from_slice(&event.uid.to_ne_bytes());
        raw[36..40].copy_from_slice(&event.inode_mode.to_ne_bytes());
        raw[40] = event.action;
        raw[41..44].copy_from_slice(&event.reserved);
        raw[44..60].copy_from_slice(&event.comm);
        raw[60..64].copy_from_slice(&event.reserved2);
        raw
    }

    #[test]
    fn wire_layout_and_roundtrip_match_the_abi() {
        use core::mem::{align_of, offset_of, size_of};
        assert_eq!(size_of::<CredentialGuardEvent>(), CRED_GUARD_EVENT_WIRE_BYTES);
        assert_eq!(align_of::<CredentialGuardEvent>(), 8);
        assert_eq!(offset_of!(CredentialGuardEvent, ts_ns), 0);
        assert_eq!(offset_of!(CredentialGuardEvent, dev), 8);
        assert_eq!(offset_of!(CredentialGuardEvent, ino), 16);
        assert_eq!(offset_of!(CredentialGuardEvent, pid), 24);
        assert_eq!(offset_of!(CredentialGuardEvent, tgid), 28);
        assert_eq!(offset_of!(CredentialGuardEvent, uid), 32);
        assert_eq!(offset_of!(CredentialGuardEvent, inode_mode), 36);
        assert_eq!(offset_of!(CredentialGuardEvent, action), 40);
        assert_eq!(offset_of!(CredentialGuardEvent, reserved), 41);
        assert_eq!(offset_of!(CredentialGuardEvent, comm), 44);
        assert_eq!(offset_of!(CredentialGuardEvent, reserved2), 60);
        let event = sample();
        assert_eq!(decode_credential_guard_event(&encode(&event)), Some(event));
    }

    #[test]
    fn rejects_records_the_producer_cannot_have_emitted() {
        let raw = encode(&sample());
        for len in [0usize, 1, 32, 63] {
            assert!(decode_credential_guard_event(&raw[..len]).is_none(), "{len}");
        }
        let mut bad = sample();
        bad.action = 4;
        assert!(decode_credential_guard_event(&encode(&bad)).is_none());
        // V6.3.0 AP-1: the inode-gate deny is an additive action value; the
        // control plane labels it, the kernel verdict stays the same -EACCES.
        let mut inode_deny = sample();
        inode_deny.action = CRED_GUARD_ACTION_DENY_INODE;
        assert_eq!(
            decode_credential_guard_event(&encode(&inode_deny)),
            Some(inode_deny)
        );
        bad = sample();
        bad.pid = 0;
        assert!(decode_credential_guard_event(&encode(&bad)).is_none());
        bad = sample();
        bad.ino = 0;
        assert!(decode_credential_guard_event(&encode(&bad)).is_none());
        bad = sample();
        bad.reserved2 = [1, 0, 0, 0];
        assert!(decode_credential_guard_event(&encode(&bad)).is_none());
        bad = sample();
        bad.comm = [b'x'; 16];
        assert!(decode_credential_guard_event(&encode(&bad)).is_none());
    }

    #[test]
    fn identity_keys_roundtrip_and_reject_reserved_or_zero_bits() {
        let key = credential_identity_key(0x0801, 0xdead_beef_1234_5678);
        assert_eq!(decode_credential_identity_key(&key), Some((0x0801, 0xdead_beef_1234_5678)));
        let mut bad = key;
        bad[15] = 1;
        assert_eq!(decode_credential_identity_key(&bad), None);
        assert_eq!(decode_credential_identity_key(&credential_identity_key(0, 5)), None);
        assert_eq!(decode_credential_identity_key(&credential_identity_key(5, 0)), None);
        assert_eq!(decode_credential_identity_key(&[0u8; 15]), None);
        // Kernel sb->s_dev ((major << 20) | minor) -> glibc st_dev low 32 bits.
        assert_eq!(kernel_s_dev_to_stat_u32((8 << 20) | 1), 0x0801);
        assert_eq!(kernel_s_dev_to_stat_u32(27), 27);
        assert_eq!(kernel_s_dev_to_stat_u32((259 << 20) | 0), 0x0001_0300);
        assert_eq!(kernel_s_dev_to_stat_u32(300), 0x0010_002c);
    }

    #[test]
    fn allowlist_matches_auth_binaries_and_never_normal_user_commands() {
        for allowed in [
            "unix_chkpwd",
            "sshd",
            "sshd-session",
            "sudo",
            "su",
            "passwd",
            "chpasswd",
            "login",
            "cron",
            "useradd",
            "usermod",
            "userdel",
            "groupadd",
            "groupmod",
            "groupdel",
            "gpasswd",
            "chage",
            "newgrp",
            "vipw",
            "pwck",
            "grpck",
            "systemd-logind",
            "systemd-journal",
            "(systemd)",
            "(sd-pam)",
            "(sd-executor)",
            "gedefense-core",
            "gedefense-control",
        ] {
            assert!(credential_reader_allowed(allowed.as_bytes()), "{allowed}");
        }
        for denied in ["bash", "sh", "cat", "python3", "less", "encryptor", ""] {
            assert!(!credential_reader_allowed(denied.as_bytes()), "{denied}");
        }
        assert!(!credential_reader_allowed(&[0xff, 0xfe, 0]));
        assert_eq!(CRED_GUARD_STATE_MAGIC, b'C');
        assert_eq!(CRED_GUARD_EVENT_RING_BYTES as usize / CRED_GUARD_EVENT_WIRE_BYTES, 4096);
    }

    #[test]
    fn every_protected_path_is_absolute() {
        for path in CRED_GUARD_PROTECTED_FILES.iter().chain(CRED_GUARD_PROTECTED_DIRS) {
            assert!(path.starts_with('/'), "{path}");
            assert!(!path.ends_with('/'), "{path}");
        }
    }
}
