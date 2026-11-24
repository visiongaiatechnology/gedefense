//! M2.2 thresholds, kprobe table and trusted-comm exemption policy for the
//! userspace ransomware sensor (limits are consumed by the queue, the freeze
//! broker and the core).

/// Pre-existing event batch bound (same shape as the malware/exec drains).
pub(crate) const MAX_RANSOM_EVENTS_PER_RESPONSE: usize = 8;
pub(crate) const MAX_RANSOM_PAYLOAD_BYTES: usize = 2048;
/// Bounded FIFO buffer between the <10 ms watcher thread and `RANSOM_EVENTS` IPC.
pub(crate) const MAX_PENDING_RANSOM_RECORDS: usize = 256;
/// Maximum sleep between ringbuf checks when no kernel wakeup fires.
pub(crate) const RANSOM_POLL_TIMEOUT_MS: i32 = 10;
/// Kernel-side kprobe symbols (see `rust/gedefense-ebpf/src/ransom.rs`).
pub(crate) const RANSOM_KPROBES: &[(&str, &str)] = &[
    ("gedefense_ransom_vfs_write", "vfs_write"),
    ("gedefense_ransom_vfs_rename", "vfs_rename"),
    ("gedefense_ransom_vfs_unlink", "vfs_unlink"),
];
/// Built-in trusted-comm exemptions (package managers, compilers, backup/sync
/// tools, container runtimes). Each entry is a Linux task name (≤15 bytes).
pub(crate) const TRUSTED_COMMS: &[&str] = &[
    "apt",
    "apt-get",
    "dpkg",
    "dpkg-deb",
    "apt-helper",
    "tar",
    "gzip",
    "gunzip",
    "bzip2",
    "xz",
    "zstd",
    "rsync",
    "git",
    "cargo",
    "rustc",
    "cc1",
    "cc1plus",
    "gcc",
    "clang",
    "ld",
    "ld.bfd",
    "ld.gold",
    "lld",
    "make",
    "cmake",
    "ninja",
    "python3",
    "python",
    "node",
    "npm",
    "systemd",
    "systemd-journal",
    "systemd-udevd",
    "udevadm",
    "systemd-tmpfile",
    "systemd-user-ru",
    "systemd-logind",
    "systemd-resolve",
    "systemd-timesyn",
    "systemd-network",
    "gedefense-core",
    "gedefense-contr",
    "snapd",
    "dockerd",
    "containerd",
    "runc",
];

/// Pooled web/PHP/DB service workers routinely perform rapid atomic cache
/// writes (`tempnam -> rename -> unlink`); skip `rename_storm` heuristics
/// while keeping high-entropy encryption detection (`entropy_burst`) active
/// and isolating any triggered worker without crashing its pool siblings.
pub(crate) const POOL_SERVICE_COMMS: &[&str] = &[
    "php-fpm",
    "php-fpm8.0",
    "php-fpm8.1",
    "php-fpm8.2",
    "php-fpm8.3",
    "php-fpm8.4",
    "php-fpm8.5",
    "php-fpm8.6",
    "lsphp",
    "lsphp81",
    "lsphp82",
    "lsphp83",
    "lsphp84",
    "httpd",
    "apache2",
    "nginx",
    "openlitespeed",
    "lshttpd",
    "mariadbd",
    "mysqld",
    "postgres",
    "redis-server",
    "memcached",
    "gitea",
];
