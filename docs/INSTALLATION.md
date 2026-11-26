# GeDefense Linux 6.3.0 — Installation Guide

> **Canonical Sources:** [`../ONECLICK-INSTALL.md`](../ONECLICK-INSTALL.md) · [`../OPERATIONS.md`](../OPERATIONS.md) · [`../TOOLCHAINS.lock`](../TOOLCHAINS.lock) · [`../RELEASE-KEYS.md`](../RELEASE-KEYS.md)

---

## 1. System Requirements

| Component | Requirement |
|---|---|
| **OS & Architecture** | Linux `x86_64` (`amd64`), `systemd` as PID 1 |
| **Package Managers** | `apt` (Debian/Ubuntu), `dnf`/`yum` (Fedora/RHEL), `pacman` (Arch), or `zypper` (openSUSE) |
| **Kernel Capabilities** | eBPF/XDP + `pidfd`; add `lsm=...,bpf` to kernel boot cmdline for full BPF-LSM `Titan Exec Gate` / `CredentialGuard` / `BPF_GUARD` enforcement |
| **Runtime Library** | `libargon2.so.1` (for `gedefense-access` Argon2id auth) |
| **Pinned Build Toolchains** | Go `1.27.4` · Rust `1.97.1` (`musl` target) · Rust `nightly-2026-07-16` · `bpf-linker` `0.10.3` · Node.js `22.16.0` (syntax audit) |

---

## 2. Recommended: Verified One-Click Installer (`v6.3.0`)

Always download artifacts alongside their `.sha256` sidecars and verify integrity before running privileged installation:

```bash
# 1. Download v6.3.0 release installer & checksum
wget https://github.com/visiongaiatechnology/gedefense/releases/download/v6.3.0/VGT_GeDefense_V6_6.3.0_OneClick.run
wget https://github.com/visiongaiatechnology/gedefense/releases/download/v6.3.0/VGT_GeDefense_V6_6.3.0_OneClick.run.sha256

# 2. Verify archive digest and inspect options non-destructively
sha256sum --check VGT_GeDefense_V6_6.3.0_OneClick.run.sha256
chmod 0700 VGT_GeDefense_V6_6.3.0_OneClick.run
./VGT_GeDefense_V6_6.3.0_OneClick.run --help

# 3. Install interactively (verifies embedded Ed25519 release index + manifest offline before extraction)
sudo ./VGT_GeDefense_V6_6.3.0_OneClick.run
```

### Desktop Tray Client (Linux Workstation · Optional)

```bash
wget https://github.com/visiongaiatechnology/gedefense/releases/download/v6.3.0/GeDefense-6.3.0-Desktop-OneClick.run
wget https://github.com/visiongaiatechnology/gedefense/releases/download/v6.3.0/GeDefense-6.3.0-Desktop-OneClick.run.sha256
sha256sum --check GeDefense-6.3.0-Desktop-OneClick.run.sha256
chmod 0700 GeDefense-6.3.0-Desktop-OneClick.run
sudo ./GeDefense-6.3.0-Desktop-OneClick.run
```

---

## 3. Source Archive Installation (`GeDefense-6.3.0-OneClick.run` / `Source.zip`)

```bash
wget https://github.com/visiongaiatechnology/gedefense/releases/download/v6.3.0/VGT_GeDefense_V6_6.3.0_Source.zip
wget https://github.com/visiongaiatechnology/gedefense/releases/download/v6.3.0/VGT_GeDefense_V6_6.3.0_Source.zip.sha256
sha256sum --check VGT_GeDefense_V6_6.3.0_Source.zip.sha256
unzip VGT_GeDefense_V6_6.3.0_Source.zip
cd VGT_GeDefense_V6_6.3.0
```

---

## 4. Filesystem & Service Layout After Install

| Path | Purpose |
|---|---|
| `/opt/vgt/gedefense/releases/<version>` | Immutable release directory (`bin/`, `libexec/`, `lib/gedefense/`, `share/`) |
| `/opt/vgt/gedefense/current` | Atomic active symlink |
| `/etc/vgt/gedefense/` | Configuration (`gedefense.toml`), TLS certificates, XDR baseline, feed/policy keys |
| `/var/lib/vgt/gedefense/` | Encrypted operational state, FIM DB, AES-256-GCM Quarantine Vault (`quarantine/objects`) |
| `/run/vgt-gedefense/` & `/run/vgt-gedefense-l7/` | Signed Unix IPC sockets (`core.sock`, `inspect.sock`, `edge.sock`) |
| `/sys/fs/bpf/gedefense` | Persistent BPF filesystem pins managed by `gedefense-bpffs.service` |
| `/var/log/vgt-gedefense-install.log` | Installation diagnostics (`0600`) |

---

## 5. Post-Install Verification & Rollback

```bash
# 1. Verify active systemd units and bpffs mount
systemctl status gedefense-bpffs gedefense-core gedefense-control gedefense-access --no-pager
mountpoint /sys/fs/bpf

# 2. Check liveness and health endpoints
curl --fail http://127.0.0.1:9844/livez
curl --fail http://127.0.0.1:9844/readyz

# 3. Verify BPF LSM availability for AP-1..AP-5 & Titan Exec Gate
cat /sys/kernel/security/lsm

# Rollback to prior verified immutable release if host qualification fails
sudo /opt/vgt/gedefense/current/scripts/rollback-beta.sh
```
