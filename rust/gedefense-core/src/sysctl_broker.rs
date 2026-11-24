//! Wave 3a extraction: the allowlisted sysctl broker and the managed hardening
//! profile (`SYSCTL_GET`/`SYSCTL_SET`/`HARDENING_GET`/`HARDENING_SET` handling)
//! formerly inline in `main.rs`.

use crate::*;

// F-04: one canonical persistence path. The product contract (BETA-TEST-PLAN,
// READMEs) names 90-vgt-gedefense.conf; read, create, replace, rollback and
// migration all derive from these constants so they can never diverge again.
pub(crate) const HARDENING_DIRECTORY: &str = "/etc/sysctl.d";
pub(crate) const HARDENING_FILE_NAME: &str = "90-vgt-gedefense.conf";
pub(crate) const HARDENING_TEMPORARY_PREFIX: &str = ".90-vgt-gedefense.conf.";
// Files written by earlier builds/attempts. They sort after the canonical file
// and would win at boot, so they are migrated or reconciled, never ignored.
pub(crate) const LEGACY_HARDENING_FILE_NAMES: &[&str] =
    &["99-zzz-vgt-gedefense.conf", "99-vgt-gedefense.conf"];
pub(crate) const RENAME_NOREPLACE: u32 = 1;
pub(crate) const RENAME_EXCHANGE: u32 = 2;

pub(crate) const HARDENING_SERVER: &str =
    "# Managed atomically by VGT GeDefense. Manual edits are rejected.\n\
fs.protected_fifos = 2\n\
fs.protected_regular = 2\n\
fs.suid_dumpable = 0\n\
kernel.dmesg_restrict = 1\n\
kernel.kptr_restrict = 2\n\
kernel.randomize_va_space = 2\n\
net.ipv4.conf.all.accept_redirects = 0\n\
net.ipv4.conf.all.log_martians = 1\n\
net.ipv4.conf.all.rp_filter = 1\n\
net.ipv4.conf.all.send_redirects = 0\n\
net.ipv4.conf.default.accept_redirects = 0\n\
net.ipv4.conf.default.log_martians = 1\n\
net.ipv4.conf.default.rp_filter = 1\n\
net.ipv4.conf.default.send_redirects = 0\n\
net.ipv4.icmp_echo_ignore_broadcasts = 1\n\
net.ipv4.icmp_ignore_bogus_error_responses = 1\n\
net.ipv4.tcp_syncookies = 1\n\
net.ipv6.conf.all.accept_redirects = 0\n\
net.ipv6.conf.default.accept_redirects = 0\n";

pub(crate) const HARDENING_ASTRAEAOS: &str =
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
net.ipv4.conf.all.log_martians = 1\n\
net.ipv4.conf.all.rp_filter = 1\n\
net.ipv4.conf.all.send_redirects = 0\n\
net.ipv4.conf.default.accept_redirects = 0\n\
net.ipv4.conf.default.log_martians = 1\n\
net.ipv4.conf.default.rp_filter = 1\n\
net.ipv4.conf.default.send_redirects = 0\n\
net.ipv4.icmp_echo_ignore_broadcasts = 1\n\
net.ipv4.icmp_ignore_bogus_error_responses = 1\n\
net.ipv4.tcp_syncookies = 1\n\
net.ipv6.conf.all.accept_redirects = 0\n\
net.ipv6.conf.default.accept_redirects = 0\n\
dev.tty.ldisc_autoload = 0\n\
vm.swappiness = 10\n";

// 6.1.x persisted-profile compatibility. Upgrades must keep recognizing the
// file written by the previous release so the first 6.2.0 HARDENING_GET does
// not fail closed; the next apply rewrites the canonical 6.2 content above.
pub(crate) const LEGACY_HARDENING_SERVER: &str =
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
pub(crate) const LEGACY_HARDENING_ASTRAEAOS: &str =
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

/// Complete CIS/Lynis Level-1 profile (M5.1, 6.2.0). It is intentionally
/// opt-in and matches the control set of `astraeaos-cis-l1` in the Go
/// `hardening_sysctl.go` catalogue, including the new CIS keys.
pub(crate) const HARDENING_CIS_L1: &str =
    "# Managed atomically by VGT GeDefense. Manual edits are rejected.\n\
dev.tty.ldisc_autoload = 0\n\
fs.protected_fifos = 2\n\
fs.protected_hardlinks = 1\n\
fs.protected_regular = 2\n\
fs.protected_symlinks = 1\n\
fs.suid_dumpable = 0\n\
kernel.dmesg_restrict = 1\n\
kernel.kptr_restrict = 2\n\
kernel.perf_event_paranoid = 3\n\
kernel.randomize_va_space = 2\n\
kernel.sysrq = 0\n\
kernel.unprivileged_bpf_disabled = 1\n\
kernel.yama.ptrace_scope = 2\n\
net.ipv4.conf.all.accept_redirects = 0\n\
net.ipv4.conf.all.log_martians = 1\n\
net.ipv4.conf.all.rp_filter = 1\n\
net.ipv4.conf.all.send_redirects = 0\n\
net.ipv4.conf.default.accept_redirects = 0\n\
net.ipv4.conf.default.log_martians = 1\n\
net.ipv4.conf.default.rp_filter = 1\n\
net.ipv4.conf.default.send_redirects = 0\n\
net.ipv4.icmp_echo_ignore_broadcasts = 1\n\
net.ipv4.icmp_ignore_bogus_error_responses = 1\n\
net.ipv4.tcp_syncookies = 1\n\
net.ipv6.conf.all.accept_redirects = 0\n\
net.ipv6.conf.default.accept_redirects = 0\n";

/// M5.1 grew the custom identity space from 10 to 21 control bits; V6.3.0 AP-4
/// adds the opt-in `kernel.io_uring_disabled` (bit 22) and `vm.memfd_noexec`
/// (bit 23) controls. Bit 21 stays intentionally unassigned so the existing
/// `astraeaos-custom-200000` negative test keeps holding. The Go catalogue uses
/// the same maximum (`0x00df_ffff`); an unknown high bit must be rejected rather
/// than silently ignored.
pub(crate) const HARDENING_CUSTOM_MASK: u32 = 0x00df_ffff;

pub(crate) fn hardening_content(profile: &str) -> Option<String> {
    match profile {
        "linux-server-balanced" => Some(HARDENING_SERVER.to_owned()),
        "astraeaos-workstation-strict" => Some(HARDENING_ASTRAEAOS.to_owned()),
        "astraeaos-cis-l1" => Some(HARDENING_CIS_L1.to_owned()),
        _ => custom_hardening_content(profile),
    }
}

pub(crate) fn custom_hardening_content(profile: &str) -> Option<String> {
    let encoded = profile.strip_prefix("astraeaos-custom-")?;
    // Go emits `%04x`, therefore a 21-bit mask has four to six hex digits
    // (`0001` … `1fffff`). Anything shorter/longer is not a Go-produced
    // profile and must not reach a persistent sysctl file.
    if !(4..=6).contains(&encoded.len()) || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mask = u32::from_str_radix(encoded, 16).ok()?;
    if mask == 0 || mask & !HARDENING_CUSTOM_MASK != 0 {
        return None;
    }
    let mut content = format!(
        "# Managed atomically by VGT GeDefense. Manual edits are rejected.\n# Profile: {profile}\n"
    );
    let controls: &[(u32, &[(&str, &str)])] = &[
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
        (1 << 10, &[("kernel.unprivileged_userns_clone", "0")]),
        (
            1 << 11,
            &[
                ("net.ipv4.conf.all.rp_filter", "1"),
                ("net.ipv4.conf.default.rp_filter", "1"),
            ],
        ),
        (
            1 << 12,
            &[
                ("net.ipv4.conf.all.log_martians", "1"),
                ("net.ipv4.conf.default.log_martians", "1"),
            ],
        ),
        (
            1 << 13,
            &[
                ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
                ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
            ],
        ),
        (1 << 14, &[("fs.protected_hardlinks", "1")]),
        (1 << 15, &[("fs.protected_symlinks", "1")]),
        (1 << 16, &[("kernel.sysrq", "0")]),
        (1 << 17, &[("kernel.perf_event_paranoid", "3")]),
        (1 << 18, &[("dev.tty.ldisc_autoload", "0")]),
        (1 << 19, &[("vm.swappiness", "10")]),
        (
            1 << 20,
            &[
                ("net.ipv6.conf.all.disable_ipv6", "1"),
                ("net.ipv6.conf.default.disable_ipv6", "1"),
            ],
        ),
        // V6.3.0 AP-4: opt-in io_uring/memfd hardening. These controls are never
        // part of a shipped profile and never selected automatically; the
        // operator must opt in. `kernel.io_uring_disabled = 1` keeps io_uring
        // available to a dedicated group instead of breaking databases/storage
        // with the global value 2.
        (1 << 22, &[("kernel.io_uring_disabled", "1")]),
        (1 << 23, &[("vm.memfd_noexec", "2")]),
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

pub(crate) fn recognized_hardening_state(content: &str) -> Option<String> {
    // 6.1.x files stay recognized for upgrade; the next apply writes the new
    // canonical content and extends the persistent policy with M5.1 controls.
    if content == LEGACY_HARDENING_SERVER {
        return Some("linux-server-balanced".to_owned());
    }
    if content == LEGACY_HARDENING_ASTRAEAOS {
        return Some("astraeaos-workstation-strict".to_owned());
    }
    for profile in [
        "linux-server-balanced",
        "astraeaos-workstation-strict",
        "astraeaos-cis-l1",
    ] {
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

// Reads a GeDefense-managed hardening file through an O_NOFOLLOW descriptor.
// Ok(None) means the file does not exist; an existing file that is unreadable,
// oversized or not managed by GeDefense is an error and never treated as state.
pub(crate) fn read_managed_hardening_file(path: &Path) -> Result<Option<String>, BoxError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(format!(
                "persistent hardening state {} must not be a symlink",
                path.display()
            )
            .into())
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
        .map(Some)
        .ok_or_else(|| {
            format!(
                "persistent hardening state {} is not managed by GeDefense",
                path.display()
            )
            .into()
        })
}

pub(crate) fn hardening_directory() -> std::path::PathBuf {
    std::path::PathBuf::from(HARDENING_DIRECTORY)
}

pub(crate) fn hardening_canonical_path(directory: &Path) -> std::path::PathBuf {
    directory.join(HARDENING_FILE_NAME)
}

// Removes temporary files left behind by an interrupted compare-set. This is
// what prevents a crashed writer from accumulating unmanaged .90-* strays.
pub(crate) fn cleanup_hardening_temporary_files(directory: &Path) -> Result<(), BoxError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.starts_with(HARDENING_TEMPORARY_PREFIX) {
            match fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

pub(crate) fn remove_managed_legacy_file(directory: &Path, name: &str) -> Result<(), BoxError> {
    let path = directory.join(name);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

// F-04 state machine: the canonical file is authoritative. A legacy file is
// migrated when the canonical file is absent, accepted-and-removed when the
// canonical file already carries the same managed state, and any unmanaged or
// ambiguous stray fails closed instead of silently overriding the profile.
pub(crate) fn hardening_file_state_in(directory: &Path) -> Result<String, BoxError> {
    let canonical = hardening_canonical_path(directory);
    let canonical_state = read_managed_hardening_file(&canonical)?;
    let mut legacy: Vec<(&'static str, String)> = Vec::new();
    for name in LEGACY_HARDENING_FILE_NAMES {
        if let Some(state) = read_managed_hardening_file(&directory.join(name))? {
            legacy.push((name, state));
        }
    }

    if let Some(state) = canonical_state {
        // Canonical state exists: reconcile every managed legacy stray so it can
        // never sort after (and override) the canonical file at boot.
        for (name, _) in &legacy {
            remove_managed_legacy_file(directory, name)?;
        }
        return Ok(state);
    }

    match legacy.len() {
        0 => Ok("absent".to_owned()),
        1 => {
            let (name, state) = &legacy[0];
            let name = *name;
            let state = state.clone();
            let directory_file = File::open(directory)?;
            let directory_fd = std::os::fd::AsRawFd::as_raw_fd(&directory_file);
            let from = CString::new(name)?;
            let to = CString::new(HARDENING_FILE_NAME)?;
            match renameat2_names(directory_fd, &from, &to, RENAME_NOREPLACE) {
                Ok(()) => {
                    directory_file.sync_all()?;
                    Ok(state)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // A concurrent writer created the canonical file between the
                    // two reads. Re-read it and reconcile the now-stale legacy file.
                    let state = read_managed_hardening_file(&hardening_canonical_path(directory))?
                        .ok_or(
                            "persistent hardening canonical state disappeared during migration",
                        )?;
                    remove_managed_legacy_file(directory, name)?;
                    Ok(state)
                }
                Err(error) => Err(format!(
                    "persistent hardening legacy migration failed for {}: {error}",
                    name
                )
                .into()),
            }
        }
        _ => Err("multiple legacy persistent hardening files present; refusing to guess".into()),
    }
}

pub(crate) fn hardening_file_state() -> Result<String, BoxError> {
    let directory = hardening_directory();
    let state = hardening_file_state_in(&directory)?;
    cleanup_hardening_temporary_files(&directory)?;
    Ok(state)
}

pub(crate) fn hardening_temp_name() -> Result<CString, BoxError> {
    let mut random = [0u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(CString::new(format!(
        "{HARDENING_TEMPORARY_PREFIX}{}.{}",
        std::process::id(),
        hex::encode(random)
    ))?)
}

pub(crate) fn renameat2_names(
    directory_fd: i32,
    from: &CString,
    to: &CString,
    flags: u32,
) -> Result<(), std::io::Error> {
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
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn compare_set_hardening_file(expected: &str, desired: &str) -> Result<String, BoxError> {
    compare_set_hardening_file_in(&hardening_directory(), expected, desired)
}

// Single canonical compare-set implementation for GET/SET/rollback. Tests run it
// against a temporary directory; production always uses /etc/sysctl.d.
pub(crate) fn compare_set_hardening_file_in(
    directory: &Path,
    expected: &str,
    desired: &str,
) -> Result<String, BoxError> {
    if expected != "absent" && hardening_content(expected).is_none() {
        return Err("persistent hardening expected state is invalid".into());
    }
    if desired != "absent" && hardening_content(desired).is_none() {
        return Err("persistent hardening desired state is invalid".into());
    }
    // Migration/reconciliation happens before the compare so a stale legacy file
    // and its canonical successor are never observed as two different states.
    cleanup_hardening_temporary_files(directory)?;
    if hardening_file_state_in(directory)? != expected {
        return Err("persistent hardening compare-set precondition failed".into());
    }
    if expected == desired {
        return Ok(desired.to_owned());
    }
    let directory_file = File::open(directory)?;
    let directory_fd = std::os::fd::AsRawFd::as_raw_fd(&directory_file);
    let target_name = CString::new(HARDENING_FILE_NAME)?;
    let temporary_name = hardening_temp_name()?;
    let temporary_path = directory.join(std::ffi::OsStr::from_bytes(temporary_name.as_bytes()));

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
        directory_file.sync_all()?;
        cleanup_hardening_temporary_files(directory)?;
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
            let observed = hardening_file_state_in(directory);
            if observed.ok().as_deref() != Some(desired) {
                // Undo the rename only if it is provably still our temporary file.
                if hardening_file_state_at(&hardening_canonical_path(directory))
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
            if hardening_file_state_in(directory).ok().as_deref() != Some(desired) {
                let _ =
                    renameat2_names(directory_fd, &temporary_name, &target_name, RENAME_EXCHANGE);
                return Err("persistent hardening post-state verification failed".into());
            }
            fs::remove_file(&temporary_path)?;
        }
        directory_file.sync_all()?;
        cleanup_hardening_temporary_files(directory)?;
        Ok::<(), BoxError>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result?;
    Ok(desired.to_owned())
}

// Parses a recognized persistent profile into (allowlisted sysctl key, value)
// assignments. Used by the boot-time self-healing pass, which re-asserts the
// persisted intent after systemd-sysctl so later-sorting 99-* files cannot
// silently override GeDefense values.
pub(crate) fn parse_hardening_assignments(content: &str) -> Result<Vec<(String, String)>, BoxError> {
    let mut assignments: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or("persistent hardening line is malformed")?;
        let key = key.trim();
        let value = value.trim();
        let (_, allowed) = sysctl_spec(key).ok_or_else(|| {
            format!("persistent hardening key {key} is not an allowlisted sysctl")
        })?;
        if !allowed.contains(&value) {
            return Err(format!(
                "persistent hardening value for {key} is outside its typed domain"
            )
            .into());
        }
        if assignments.iter().any(|(existing, _)| existing == key) {
            return Err(format!("persistent hardening profile repeats {key}").into());
        }
        assignments.push((key.to_owned(), value.to_owned()));
    }
    if assignments.is_empty() {
        return Err("persistent hardening profile has no assignments".into());
    }
    Ok(assignments)
}

// Best-effort boot-time re-assertion: the persisted profile is applied via the
// same allowlisted compare-set primitive the control plane uses. Failures are
// logged and never prevent the core from starting (availability), but they are
// visible instead of silently leaving the host on distribution defaults.
pub(crate) fn reassert_persisted_hardening() {
    let state = match hardening_file_state() {
        Ok(state) => state,
        Err(error) => {
            eprintln!("persistent hardening state unavailable at startup: {error}");
            return;
        }
    };
    if state == "absent" {
        return;
    }
    let content = match hardening_content(&state) {
        Some(content) => content,
        None => {
            eprintln!("persistent hardening profile {state} is not recognized");
            return;
        }
    };
    let assignments = match parse_hardening_assignments(&content) {
        Ok(assignments) => assignments,
        Err(error) => {
            eprintln!("persistent hardening profile {state} rejected at startup: {error}");
            return;
        }
    };
    let mut reasserted = 0usize;
    for (key, desired) in assignments {
        match read_sysctl_value(&key) {
            Ok(current) if current == desired => {}
            Ok(current) => match compare_set_sysctl(&key, &current, &desired) {
                Ok(_) => {
                    reasserted += 1;
                    eprintln!("persistent hardening re-asserted {key}={desired} (was {current})");
                }
                Err(error) => {
                    eprintln!("persistent hardening re-assertion failed for {key}: {error}")
                }
            },
            Err(error) => eprintln!("persistent hardening live read failed for {key}: {error}"),
        }
    }
    eprintln!(
        "persistent hardening profile {state} held at startup: {reasserted} value(s) re-asserted"
    );
}

pub(crate) fn hardening_file_state_at(path: &Path) -> Result<String, BoxError> {
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

pub(crate) fn sysctl_spec(key: &str) -> Option<(&'static str, &'static [&'static str])> {
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
        // V6.3.0 AP-4: io_uring is a real capability (databases, storage, some
        // HTTP stacks). The sysctl domain is exactly 0/1/2 and the operator
        // policy stays opt-in; the shipped control-plane recommendation is 1,
        // never 2 (2 disables io_uring for everyone and breaks those products).
        "kernel.io_uring_disabled" => {
            Some(("/proc/sys/kernel/io_uring_disabled", &["0", "1", "2"]))
        }
        // V6.3.0 AP-4: memfd execute hardening (kernel 6.3+: 0/1/2). The
        // hardened recommendation is documented by the control plane; this
        // typed domain only guards the privileged compare-set path.
        "vm.memfd_noexec" => Some(("/proc/sys/vm/memfd_noexec", &["0", "1", "2"])),
        // The entry point of a local metadata-trust exploit is often an unprivileged user namespace:
        // without it a process cannot hold CAP_NET_RAW in a namespace it owns, which several kernel
        // packet-socket and netfilter classes need before they are reachable at all. The kernel
        // exposes exactly 0 or 1 here, so the domain is a typed binary.
        "kernel.unprivileged_userns_clone" => {
            Some(("/proc/sys/kernel/unprivileged_userns_clone", &["0", "1"]))
        }
        // CVE-2026-98432 reaches the IPv4 request-socket UAF through MPTCP. The mitigation
        // guard must be able to read and compare-set this knob through the privileged core,
        // exactly like the user-namespace boundary above. The kernel exposes 0 or 1.
        "net.mptcp.enabled" => Some(("/proc/sys/net/mptcp/enabled", &["0", "1"])),
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
        // V6.2 CIS/Lynis M5.1 controls. The Go control plane ships these in its
        // hardening catalogue only after this typed core allowlist accepts the
        // exact key/path/value domain; an unlisted key must never reach a
        // privileged `/proc/sys` write.
        "net.ipv4.conf.all.rp_filter" => {
            Some(("/proc/sys/net/ipv4/conf/all/rp_filter", &["0", "1", "2"]))
        }
        "net.ipv4.conf.default.rp_filter" => Some((
            "/proc/sys/net/ipv4/conf/default/rp_filter",
            &["0", "1", "2"],
        )),
        "net.ipv4.conf.all.log_martians" => {
            Some(("/proc/sys/net/ipv4/conf/all/log_martians", &["0", "1"]))
        }
        "net.ipv4.conf.default.log_martians" => Some((
            "/proc/sys/net/ipv4/conf/default/log_martians",
            &["0", "1"],
        )),
        "net.ipv4.icmp_echo_ignore_broadcasts" => Some((
            "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",
            &["0", "1"],
        )),
        "net.ipv4.icmp_ignore_bogus_error_responses" => Some((
            "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses",
            &["0", "1"],
        )),
        "fs.protected_hardlinks" => Some(("/proc/sys/fs/protected_hardlinks", &["0", "1"])),
        "fs.protected_symlinks" => Some(("/proc/sys/fs/protected_symlinks", &["0", "1"])),
        // sysrq is a bitmask, not a boolean. Keep the documented safe masks the
        // provisioning profiles may compare-set and the distribution defaults
        // that can be read back before the first apply.
        "kernel.sysrq" => Some((
            "/proc/sys/kernel/sysrq",
            &["0", "1", "2", "4", "8", "16", "32", "64", "128", "176", "244", "438"],
        )),
        "kernel.perf_event_paranoid" => Some((
            "/proc/sys/kernel/perf_event_paranoid",
            // Debian/Ubuntu may expose the hardening value 4 in addition to
            // the upstream -1..=3 range; the read-back must accept what the
            // distribution actually reports before compare-set runs.
            &["-1", "0", "1", "2", "3", "4"],
        )),
        "dev.tty.ldisc_autoload" => {
            Some(("/proc/sys/dev/tty/ldisc_autoload", &["0", "1"]))
        }
        "vm.swappiness" => Some((
            "/proc/sys/vm/swappiness",
            &["0", "1", "10", "20", "30", "40", "50", "60", "70", "80", "90", "100"],
        )),
        "net.ipv6.conf.all.disable_ipv6" => {
            Some(("/proc/sys/net/ipv6/conf/all/disable_ipv6", &["0", "1"]))
        }
        "net.ipv6.conf.default.disable_ipv6" => {
            Some(("/proc/sys/net/ipv6/conf/default/disable_ipv6", &["0", "1"]))
        }
        _ => None,
    }
}

pub(crate) fn read_sysctl_value(key: &str) -> Result<String, BoxError> {
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

pub(crate) fn compare_set_sysctl(key: &str, expected: &str, desired: &str) -> Result<String, BoxError> {
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

pub(crate) fn dispatch(parts: &[&str]) -> Result<Option<String>, BoxError> {
    let result = match parts {
        ["SYSCTL_GET", key] => read_sysctl_value(key),
        ["SYSCTL_SET", key, expected, desired] => compare_set_sysctl(key, expected, desired),
        ["HARDENING_GET"] => hardening_file_state(),
        ["HARDENING_SET", expected, desired] => compare_set_hardening_file(expected, desired),
        _ => return Ok(None),
    };
    Ok(Some(result?))
}
