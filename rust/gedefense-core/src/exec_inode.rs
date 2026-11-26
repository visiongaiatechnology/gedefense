//! V6.3.0 AP-1 — executable-inode trust map (`TRUSTED_EXEC_INODES`).
//!
//! Replaces the spoofable `bpf_get_current_comm()` allowlists of the credential
//! guard and the ransomware sensor with `(s_dev, i_ino)` identity of
//! `current->mm->exe_file->f_inode`. Paths are resolved symlink-safely through
//! `openat2(RESOLVE_NO_SYMLINKS)`; every trusted entry carries a flag bitmask
//! (`ALLOW_CRED_READ`, `ALLOW_RANSOM_FULL`, `ALLOW_RANSOM_POOL_META`).
//!
//! Startup contract:
//! 1. take the mandatory `EXEC_INODE_*` / `TRUSTED_EXEC_INODES` /
//!    `MALWARE_TTL_INODES` maps (a stale object fails loudly),
//! 2. resolve the identity offsets from vmlinux BTF and publish them into
//!    `EXEC_INODE_OFFSETS`,
//! 3. resolve the default trusted path contract (auth binaries, system
//!    binaries, pooled web/DB daemons) into `TRUSTED_EXEC_INODES`,
//! 4. arm `EXEC_INODE_STATE` last (published offsets + populated map first).
//!
//! Fail-open contract: if BTF offsets cannot be resolved/validated the state
//! word is left disarmed and `EXEC_INODE_STATUS` reports `enabled=0:offsets=0`;
//! the kernel guards then use their documented comm fallback and emit
//! `FALLBACK_COMM` evidence. A broken gate never locks out login.
//!
//! Also owns the TTL-bounded malware inode locks (`MALWARE_TTL_INODES`) that the
//! on-write/quarantine pipeline can apply to behaviour carriers (`LD_PRELOAD`
//! libraries, `memfd` carriers, rootkit droppers) without a broad DAC override.
//! `MALWARE_INODE_LOCK <dev> <ino> <ttl>` validates the TTL (1..=86400 s),
//! rejects duplicates/over-capacity honestly, and `poll()` expires due locks.
//!
//! Observe/evidence only: this module never issues a response action and never
//! changes kill-eligibility.

mod attach;
mod policy;
mod ttl;
mod drain;

use self::policy::*;
use crate::btf_offsets::{self, ExecInodeOffsets};
use aya::{
    maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf},
    Ebpf,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gedefense_common::{
    decode_exec_inode_event, exec_inode_flags_valid, exec_inode_key, ExecInodeEvent,
    EXEC_INODE_ALLOW_CRED_READ, EXEC_INODE_ALLOW_RANSOM_FULL, EXEC_INODE_ALLOW_RANSOM_POOL_META,
    EXEC_INODE_MAX_TTL_LOCKS, EXEC_INODE_MAX_TTL_SECONDS, EXEC_INODE_MIN_TTL_SECONDS,
    EXEC_INODE_OFF_ABI, EXEC_INODE_OFF_FILE_F_INODE, EXEC_INODE_OFF_INODE_I_INO,
    EXEC_INODE_OFF_INODE_I_SB, EXEC_INODE_OFF_MAGIC, EXEC_INODE_OFF_MM_EXE_FILE,
    EXEC_INODE_OFF_MM_SIZE, EXEC_INODE_OFF_SUPER_S_DEV, EXEC_INODE_OFF_TASK_MM,
    EXEC_INODE_OFF_TASK_SIZE, EXEC_INODE_OFFSETS_ABI, EXEC_INODE_OFFSETS_MAGIC,
    EXEC_INODE_OFFSETS_TABLE_LEN, EXEC_INODE_STATE_ABI, EXEC_INODE_STATE_ABI_SHIFT,
    EXEC_INODE_STATE_ARMED_SHIFT, EXEC_INODE_STATE_MAGIC, EXEC_INODE_STATE_MAGIC_SHIFT,
};
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::{CString, OsStr},
    fs::{self, File},
    os::{
        fd::{FromRawFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Bounded event drain: same shape as the other 6.x event batches.
pub(crate) const MAX_EXEC_INODE_EVENTS_PER_RESPONSE: usize = 16;
pub(crate) const MAX_EXEC_INODE_PAYLOAD_BYTES: usize = 4096;
/// Maximum accepted path length for `EXEC_INODE_ALLOW_ADD` (single path token).
const MAX_EXEC_INODE_PATH_BYTES: usize = 4096;
/// `openat2(2)` resolve flags: never follow a symlink or magic link.
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

/// `openat2(2)` argument structure (linux/openat2.h, stable UAPI).
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Authentication binaries: credential readers and trusted full ransom tier.
///
/// This is the same documented auth/system set the pre-6.3 comm allowlist
/// carried (account management and cron's PAM account check included); leaving
/// one of these out would deny a legitimate root PAM read once the inode gate is
/// primary. Only exact packaged paths are listed; a missing path is skipped and
/// counted, never guessed by a glob.
const AUTH_EXEC_PATHS: &[&str] = &[
    "/usr/sbin/sshd",
    "/usr/sbin/sshd-session",
    "/usr/bin/sshd",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chpasswd",
    "/usr/bin/login",
    "/usr/sbin/unix_chkpwd",
    "/usr/sbin/cron",
    "/usr/sbin/useradd",
    "/usr/sbin/usermod",
    "/usr/sbin/userdel",
    "/usr/sbin/groupadd",
    "/usr/sbin/groupmod",
    "/usr/sbin/groupdel",
    "/usr/bin/gpasswd",
    "/usr/bin/chage",
    "/usr/bin/newgrp",
    "/usr/sbin/vipw",
    "/usr/sbin/pwck",
    "/usr/sbin/grpck",
    // Session/PAM helpers of systemd run as `/usr/lib/systemd/systemd`
    // (`(sd-pam)`, `(sd-executor)`): the inode is the trusted identity of that
    // packaged binary, so a local attacker cannot borrow it without root.
    "/usr/lib/systemd/systemd",
    "/usr/lib/systemd/systemd-executor",
    "/lib/systemd/systemd-executor",
    // Non-symlinked system install path for `gedefense-control` (symlinked
    // `/opt/vgt/gedefense/current/...` release binaries are registered from
    // `/proc/self/exe` sibling resolution in `populate_default_trust`).
    "/usr/bin/gedefense-control",
];
/// System binaries with the full ransom exemption (never credential readers).
const SYSTEM_RANSOM_PATHS: &[&str] = &[
    "/usr/bin/systemctl",
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/dpkg",
    "/usr/bin/dpkg-deb",
    "/usr/bin/apt-helper",
    "/usr/lib/apt/apt-helper",
    "/usr/lib/apt/methods/http",
    "/usr/lib/apt/methods/store",
    "/usr/lib/apt/methods/rred",
    "/usr/lib/apt/methods/gpgv",
];
/// Pooled web/DB service workers: skip the metadata (rename/unlink) signal only;
/// the entropy signal stays live. Exact known packager paths; a missing path is
/// skipped and counted, never guessed by a glob.
const POOL_SERVICE_PATHS: &[&str] = &[
    "/usr/sbin/php-fpm",
    "/usr/sbin/php-fpm8.1",
    "/usr/sbin/php-fpm8.2",
    "/usr/sbin/php-fpm8.3",
    "/usr/sbin/php-fpm8.4",
    "/usr/sbin/php-fpm8.5",
    "/usr/sbin/php-fpm8.6",
    // aaPanel / BT-Panel immutable server binary tree (never /www/wwwroot).
    "/www/server/php/80/sbin/php-fpm",
    "/www/server/php/81/sbin/php-fpm",
    "/www/server/php/82/sbin/php-fpm",
    "/www/server/php/83/sbin/php-fpm",
    "/www/server/php/84/sbin/php-fpm",
    "/www/server/php/85/sbin/php-fpm",
    "/www/server/php/86/sbin/php-fpm",
    "/www/server/nginx/sbin/nginx",
    "/www/server/apache/bin/httpd",
    "/www/server/mysql/bin/mysqld",
    "/www/server/mysql/bin/mariadbd",
    // Plesk / OpenLiteSpeed packaged binaries.
    "/opt/plesk/php/8.1/sbin/php-fpm",
    "/opt/plesk/php/8.2/sbin/php-fpm",
    "/opt/plesk/php/8.3/sbin/php-fpm",
    "/opt/plesk/php/8.4/sbin/php-fpm",
    "/opt/plesk/php/8.5/sbin/php-fpm",
    "/opt/plesk/php/8.6/sbin/php-fpm",
    "/usr/local/lsws/bin/openlitespeed",
    "/usr/local/lsws/bin/litespeed",
    "/usr/sbin/nginx",
    "/usr/sbin/mariadbd",
    "/usr/sbin/mysqld",
    "/usr/bin/mariadbd",
    "/usr/lib/postgresql/15/bin/postgres",
    "/usr/lib/postgresql/16/bin/postgres",
    "/usr/bin/postgres",
    "/usr/sbin/redis-server",
    "/usr/bin/redis-server",
];

/// Core-side owner of the executable-inode trust maps.
pub(crate) struct ExecInodeCore {
    events: RingBuf<MapData>,
    state: AyaArray<MapData, u64>,
    offsets: AyaArray<MapData, u32>,
    trusted: AyaHashMap<MapData, [u8; 16], u32>,
    ttl: AyaHashMap<MapData, [u8; 16], u32>,
    self_daemons: Option<AyaHashMap<MapData, [u8; 16], u8>>,
    allowed: PerCpuArray<MapData, u64>,
    denied: PerCpuArray<MapData, u64>,
    emitted: PerCpuArray<MapData, u64>,
    ring_drops: PerCpuArray<MapData, u64>,
    fallbacks: PerCpuArray<MapData, u64>,
    /// In-memory mirror of the map keys so `CLEAR`/capacity accounting are exact
    /// without iterating a BPF hash map.
    trusted_entries: BTreeMap<[u8; 16], u32>,
    /// Live TTL locks: identity -> monotonic expiry instant.
    ttl_locks: BTreeMap<[u8; 16], Instant>,
    epoch: u64,
    offsets_ok: bool,
    armed: bool,
    missing_paths: u32,
    expired_locks: u64,
    last_ring_drops: u64,
    rejected: u64,
}

fn parse_ttl_token(token: &str) -> Result<u32, BoxError> {
    if token.len() > 6 || !decimal_digits_only(token) {
        return Err("exec-inode TTL token is not a bounded decimal u32".into());
    }
    let ttl: u32 = token
        .parse()
        .map_err(|_| -> BoxError { "exec-inode TTL token is not a decimal u32".into() })?;
    if !(EXEC_INODE_MIN_TTL_SECONDS..=EXEC_INODE_MAX_TTL_SECONDS).contains(&ttl) {
        return Err("exec-inode TTL must be within 1..=86400 seconds".into());
    }
    Ok(ttl)
}

/// Resolves one executable path to its `(s_dev low u32, i_ino)` identity without
/// following symlinks. `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)` is
/// the primary probe; kernels/sandboxes that return `ENOSYS`/`EINVAL` fall back
/// to the component-wise `O_NOFOLLOW` walk already used by quarantine. The
/// opened descriptor must be a regular file; fstat is performed on the
/// descriptor, so a rename race cannot redirect the identity.
fn resolve_executable_identity(path: &Path) -> Result<(u32, u64), BoxError> {
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| -> BoxError { "exec-inode path contains a NUL byte".into() })?;
    let how = OpenHow {
        flags: u64::from((libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) as u32),
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `path_c` and `how` are valid for the duration of the syscall and
    // `size_of::<OpenHow>()` is the kernel-documented structure length.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path_c.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    } as RawFd;
    let file = if descriptor >= 0 {
        // SAFETY: the syscall returned a fresh owned descriptor.
        unsafe { File::from_raw_fd(descriptor) }
    } else {
        let error = std::io::Error::last_os_error();
        // F-HOTFIX-4: some systemd sandboxes return ENOSYS/EINVAL for openat2.
        // The component-wise O_NOFOLLOW walk refuses a symlink at every step.
        if matches!(error.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EINVAL)) {
            crate::open_componentwise(path, libc::O_RDONLY | libc::O_NONBLOCK)?
        } else {
            return Err(format!("exec-inode open {path:?} failed: {error}").into());
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| -> BoxError { format!("exec-inode fstat failed: {error}").into() })?;
    if !metadata.is_file() {
        return Err("exec-inode trusted path is not a regular file".into());
    }
    let dev = u32::try_from(metadata.dev())
        .map_err(|_| -> BoxError { "exec-inode device id does not fit u32".into() })?;
    let ino = metadata.ino();
    if dev == 0 || ino == 0 {
        return Err("exec-inode resolved a zero identity".into());
    }
    // Keep the descriptor alive until after the identity is read: the metadata
    // above is descriptor-backed, never path-backed.
    drop(file);
    Ok((dev, ino))
}

#[cfg(test)]
mod tests;
