<div align="center">

```
 ██████╗ ███████╗██████╗ ███████╗███████╗███╗   ██╗███████╗███████╗
██╔════╝ ██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝
██║  ███╗█████╗  ██║  ██║█████╗  █████╗  ██╔██╗ ██║███████╗█████╗
██║   ██║██╔══╝  ██║  ██║██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██╔══╝
╚██████╔╝███████╗██████╔╝███████╗██║     ██║ ╚████║███████║███████╗
 ╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚═╝     ╚═╝  ╚═══╝╚══════╝╚══════╝
```

# VGT GeDefense
### Linux Security Fabric

[![License](https://img.shields.io/badge/License-AGPL--3.0--only-blue?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)
[![Version](https://img.shields.io/badge/Version-1.0.0--beta.5-orange?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-CompleteBeta-yellow?style=for-the-badge)](#)
[![Installer](https://img.shields.io/badge/Installer-3.5.1_CompleteBeta-green?style=for-the-badge)](#-quick-start)
[![Platform](https://img.shields.io/badge/Platform-Linux_x86__64-lightgrey?style=for-the-badge&logo=linux)](#)
[![Data Plane](https://img.shields.io/badge/Data_Plane-Rust_eBPF%2FXDP-red?style=for-the-badge&logo=rust)](#-architecture)
[![Control Plane](https://img.shields.io/badge/Control_Plane-Go-00ADD8?style=for-the-badge&logo=go)](#-architecture)
[![Crypto](https://img.shields.io/badge/Evidence-Ed25519%2FAES--256--GCM-gold?style=for-the-badge)](#-cryptography)
[![Sovereign](https://img.shields.io/badge/Control_Plane-Local%2FSovereign-brightgreen?style=for-the-badge)](#)
[![GaiaOS](https://img.shields.io/badge/GaiaOS-Native_Ready-cyan?style=for-the-badge)](#-gaiaos-integration)
[![VGT](https://img.shields.io/badge/VGT-VisionGaiaTechnology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

**KERNEL-NEAR NETWORK DEFENSE · HOST XDR · ENCRYPTED EVIDENCE · REVERSIBLE HARDENING · NO CLOUD CONTROL PLANE**

</div>

---

## ⚠️ BETA SOFTWARE — COMPLETE BETA · APPLICABLE AND TESTABLE

VGT GeDefense 1.0.0-beta.5 is a **Complete Beta** — the defense chain is functionally complete and testable. It is **not** a certified or production-ready product.

**Production clearance is deliberately a property of the concretely audited target host — not just the source code.**

Initial deployment: **Observe mode only.** Canary and Enforce exclusively after documented gates have been passed.

Found a vulnerability or have an improvement? **Open an issue or contact us.**

---

## 🔍 What is VGT GeDefense?

GeDefense is not a firewall rule manager. It is a **local sovereign Linux Security Fabric** — kernel-near network defense, Host XDR, encrypted evidence ledger, reversible system hardening and GaiaOS-native isolation in one system, operated without any cloud control plane.

```
Conventional Linux Security Stacks:
  Uncoordinated tools (iptables + auditd + fail2ban)  → no shared state
  Config-as-trust                                      → custom rules auto-enforce
  No evidence chain                                    → incidents not provable
  No rollback                                          → hardening changes irreversible
  Cloud SIEM / control plane                           → data leaves the host

VGT GeDefense:
  Rust eBPF/XDP Data Plane                → kernel-near, up to 250,000 block entries
  Go Control Plane (XDR, Policy, FIM)     → separated trust domain, loopback-only
  Rust Response Core (pidfd, SIGKILL)     → broker-verified before any kill signal
  Separated trust domains                 → Public Gateway · Control · Core · Data Plane
  Ed25519-signed Evidence Ledger          → monotone sequence + predecessor hash
  AES-256-GCM encrypted FIM baselines     → fail-closed on integrity breach
  Reversible hardening                    → compare-and-set, atomic persist, auto-reverse
  Encrypted Response Vault (AES-256-GCM) → quarantine with SHA-256 identity
  No cloud control plane                  → sensitive state never leaves the host
  GaiaOS-native                           → 147 byte-identical source files, same security chain
```

A single regex, feed, behavioral or masquerading hit **cannot authorize process termination**. Enforce requires at minimum two independent authorized categories, objective broker evidence and a non-degraded system state.

---

## 🏛️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    PUBLIC ACCESS GATEWAY                      │
│   Go · TLS 1.3 · Argon2id · Host/Origin/CSRF · Session      │
│   unprivileged · Port 9843 (configurable 1024–65535)         │
├──────────────────────────────────────────────────────────────┤
│                      CONTROL PLANE                            │
│   Go · XDR · Policy · Telemetry · FIM · Evidence · Cases    │
│   user: gedefense · loopback-only (TCP 9844)                 │
├──────────────────────────────────────────────────────────────┤
│                      RESPONSE CORE                            │
│   Rust · VGT3 IPC · pidfd · Quarantine · Sysctl mutations   │
│   UID 0 · Capability Bounding · HMAC-authenticated IPC       │
│   /run/vgt-gedefense/core.sock                               │
├──────────────────────────────────────────────────────────────┤
│                       DATA PLANE                              │
│   eBPF/XDP · IPv4/IPv6 · LPM Allow/Blocklists at interface  │
│   Kernel/XDP · up to 250,000 block entries                   │
└──────────────────────────────────────────────────────────────┘
```

### Trust Domain Separation

| Domain | Role | Privilege |
|---|---|---|
| **Public Gateway** | TLS 1.3, Argon2id, Host/Origin/CSRF, session auth | Unprivileged |
| **Control Plane** | XDR, Policy, Telemetry, FIM, Evidence, Cases, Dashboard | `gedefense` user |
| **Response Core** | XDP maps, pidfd reaction, quarantine, typed sysctl mutations | UID 0, Capability Bounding |
| **Data Plane** | IPv4/IPv6 parsing, LPM allow/blocklists at interface | Kernel/XDP |

### Deployment Modes

**Standalone** — One-click install on systemd Linux. Rust Core and eBPF compiled for target kernel and target NIC, verified before atomic activation.

**GaiaOS-native** — Identical core binaries, native provisioning, GaiaOS hardening profile, boot trust evidence, optional Gaia Cells integration. GeDefense is the **single security authority** in GaiaOS. Sentinel serves exclusively as migration and audit source — no competing runtime daemon.

---

## 🛡️ Defense Fabric

### Network Defense (Rust eBPF/XDP)

| Feature | Detail |
|---|---|
| **Data Plane** | Rust eBPF/XDP — native XDP with Generic-XDP fallback |
| **Protocol Coverage** | IPv4 and IPv6 |
| **Matching** | LPM Tries — Longest Prefix Match |
| **Capacity** | Up to 250,000 block entries |
| **Management Allowlist** | Applied before blocklist — management access always preserved |
| **CIDR Rules** | Signed with TTL |
| **Feed Auto-Apply** | Off by default — public feeds require explicit operator authorization |
| **Empty Verification** | Authoritative `VERIFY_EMPTY` check — no silent residual rules |

### Host XDR

| Feature | Detail |
|---|---|
| **Signals** | Process, command, lineage, origin, masquerading, network, threat intel |
| **Profiles** | Adaptive, cardinality-bounded per process |
| **Custom Rules** | RE2 regex — strictly Alert-only, never auto-enforce |
| **Multi-Signal Gates** | Evidence gates required before any escalation |
| **PID Identity** | PID + pidfd binding — immune to PID reuse |
| **Canary Response** | Evidence-checked SIGSTOP |
| **Enforce Response** | Broker-verified SIGKILL only |

**XDR Default Limits**

| Parameter | Value |
|---|---|
| Process Scan Interval | 750 ms |
| Network / Integrity Check | 3 s / 3 s |
| Alert / Contain / Kill Threshold | 40 / 80 / 120 |
| Worker / Queue | 4 / 2,048 |
| Evaluations per Scan | 4,096 |
| Incident Log Cap | 64 MiB |

### Evidence & Integrity

| Feature | Detail |
|---|---|
| **Evidence Ledger** | Encrypted + Ed25519-signed |
| **Chain Structure** | Monotone sequence + predecessor hash |
| **Truncation Protection** | Separate Head Checkpoint |
| **FIM Baselines** | AES-GCM protected |
| **Traversal** | Bounded + streaming SHA-256 |
| **Safety Checks** | Race, symlink and mode verification |
| **Integrity Breach** | Fail-closed — no silent degradation |

### Cases & Transactions

| Feature | Detail |
|---|---|
| **Case Correlation** | Encrypted case contexts |
| **Recurrence** | Recurrence handling with ledger obligation |
| **Hardening Flow** | Preview → Authorize → Apply |
| **Audit Flow** | Verify → Audit → Reverse |
| **Startup** | Reconciliation — drift quarantine instead of blind overwrite |

---

## 🔒 Operational Safety — Promotion Gates

```
Observe ──→ Canary ──→ Enforce
   │            │           │
   │       Evidence-    Signed CIDR
   │       checked       + Allowlist
   │       SIGSTOP        sync
   │
 XDP active, no block rule
 verified empty kernel state
```

| State | Network | Process Reaction | Release Condition |
|---|---|---|---|
| **Observe** | XDP active, no block rule | Recording | Verified empty kernel state |
| **Canary** | Continued observation | Evidence-checked SIGSTOP | Policy, soak and health gates |
| **Enforce** | Signed CIDR rules | Broker-verified SIGKILL | Synchronized management allowlist |
| **Degraded** | Fail-safe / unconfirmed | Active reaction suspended | Visible recovery required |

**Emergency Stop sequence:** Response deactivate → block rules remove → authenticated `VERIFY_EMPTY` → signed Observe policy persist → only then: verified-empty. No intermediate error is reported as safe.

---

## 🔐 Cryptography

| Purpose | Method | Profile |
|---|---|---|
| **Operator Password** | Argon2id | 64 MiB · t=3 · p=1 · 128-bit salt · 256-bit output |
| **Control ↔ Core IPC** | HMAC-SHA-256 | 32-byte key · time window · nonce · replay cache · SO_PEERCRED |
| **Operational Storage** | AES-256-GCM | Random nonces · purpose-separated subkeys · AAD binding |
| **Policy / Evidence** | Ed25519 | Local sign and verify |
| **Content Identity** | SHA-256 | Streaming hash with identity recheck |
| **Public Gateway** | TLS 1.3 | Local or provided certificate |

AAD context: schema · node · purpose · canonical path · sequence.
Legacy PBKDF2 accepted only for migration — atomically upgraded to Argon2id on successful login.

### Browser & API Hardening

| Control | Status |
|---|---|
| No CDN, tracker or webfont dependencies | ✓ |
| No dynamic HTML sinks or eval | ✓ |
| Strict CSP and framing prohibition | ✓ |
| Synchronizer CSRF + exact origin check | ✓ |
| Secure, HttpOnly, SameSite=Strict | ✓ |
| Server-side Bearer injection | ✓ |
| Request-ID, TTL and replay protection | ✓ |
| HTTPS feeds with DNS/SSRF defense | ✓ |
| No runtime command execution in Go services | ✓ |
| Backend exclusively on loopback | ✓ |

**Sensitive state and keys never leave the protected host.**

---

## 🔧 Reversible Hardening

Profiles: `Generic Linux Server` and `GaiaOS Workstation` — fixed key/value allowlist.

Kernel values are changed via compare-and-set, read back and atomically persisted to `/etc/sysctl.d/90-vgt-gedefense.conf`.

The Rust Core has **no generic shell, filesystem or sysctl interface**. Partial profile errors trigger an automatic reverse in reverse order.

### Encrypted Response Vault

| Feature | Detail |
|---|---|
| **Encryption** | AES-256-GCM |
| **Chunk Size** | 1 MiB |
| **Max Source File** | 256 MiB |
| **Identity** | SHA-256 + complete file identity |
| **Capture** | Atomic — restore-verified |
| **Symlink Defense** | openat2, O_NOFOLLOW |
| **Vault Permissions** | root:gedefense 0700 — no CAP_DAC_OVERRIDE |

---

## 🌐 GaiaOS Integration

| Feature | Status |
|---|---|
| Native provisioning / systemd | ✅ Implemented — same security chain as Standalone |
| GeDefense source mirror | ✅ Implemented — 147 byte-identical source files |
| GaiaOS hardening profile | ✅ Implemented — reversible and persistent |
| Boot trust evidence | ✅ Implemented — Evidence-only, no false attestation claim |
| Gaia Cells VGTGC1 Adapter | ✅ Implemented — Runtime optional |
| UUID / Generation / cgroup ID binding | ✅ Implemented — immutable action binding |
| Freeze / Network Reverse | ✅ Implemented — evidence-bound transaction |
| Gaia Cells Lifecycle Daemon | — Not included — GaiaOS-owned runtime |
| Isolated Deception Service | — Deferred — outside Beta authority |

Cell actions are bound to UUID, lifecycle generation and kernel cgroup ID. Peer UID, HMAC, time window and nonce are verified.

If the Gaia Cells runtime is **not present**, the adapter reports `runtime_not_installed`. Generic host defense remains active and is **not degraded**.

> **Single Authority:** In GaiaOS, GeDefense is the only security authority. Sentinel serves exclusively as migration and audit source.

---

## ⚙️ Runtime Contract

### System Requirements (Standalone)

| Requirement | Value |
|---|---|
| **OS** | Linux |
| **Architecture** | x86_64 / amd64 |
| **Init** | systemd |
| **Kernel** | BPF/XDP + pidfd |
| **Package Manager** | apt-get, dnf or yum |
| **Install** | Root + build internet access |
| **Gateway Runtime** | libargon2.so.1 |

> No blanket minimum kernel version or guaranteed NIC list is declared for this beta. The target host is qualified through build, kernel verifier, XDP attachment, IPC and health gates.

### Toolchain Pins

| Component | Version |
|---|---|
| **Go** | 1.23.2 |
| **Rust Core** | 1.97.1 |
| **Rust eBPF** | nightly-2026-07-16 |
| **Rust Component** | rust-src |
| **bpf-linker** | 0.10.3 |
| **Cargo Resolution** | `Cargo.lock --locked` |

### Interfaces

| Interface | Default | Exposure |
|---|---|---|
| **HTTPS Gateway** | TCP 9843 | Administrative / public — configurable 1024–65535 |
| **Go Control Backend** | TCP 9844 | Loopback only |
| **Rust Core IPC** | `/run/vgt-gedefense/core.sock` | HMAC-VGT3 + SO_PEERCRED |
| **Gaia Cells** | `/run/gaia-cells/control.sock` | Optional — VGTGC1 |
| **Threat Feeds** | HTTPS outbound | Optional — public IP only |

### Filesystem Layout

| Path | Purpose |
|---|---|
| `/opt/vgt/gedefense/releases/<version>` | Immutable release |
| `/opt/vgt/gedefense/current` | Atomic active symlink |
| `/etc/vgt/gedefense/` | Configuration, TLS and secrets |
| `/var/lib/vgt/gedefense/` | Encrypted operational state |
| `/var/lib/vgt/gedefense/quarantine/objects` | Encrypted Response Vault |
| `/sys/fs/bpf` | BPF filesystem |
| `/var/log/vgt-gedefense-install.log` | Install diagnostics — mode 0600 |

---

## 🚀 Quick Start

```bash
# Download installer
wget https://releases.visiongaiatechnology.de/gedefense/VGT_GeDefense_Beta_1.0.0-beta.5_OneClick_CompleteBeta.run

# Verify SHA-256
sha256sum VGT_GeDefense_Beta_1.0.0-beta.5_OneClick_CompleteBeta.run
# ba32a441804f1ef1d25232ababcc781b35b2bfbfd8701ff95ca8f3dc5d9b7e8c

# Install (root required)
chmod +x VGT_GeDefense_Beta_1.0.0-beta.5_OneClick_CompleteBeta.run
sudo ./VGT_GeDefense_Beta_1.0.0-beta.5_OneClick_CompleteBeta.run
```

The installer succeeds only after passing: **Build → Kernel Verifier → XDP Attachment → IPC → Backend → TLS Gates**.

The firewall rule for the HTTPS gateway port (TCP 9843) can be configured via UFW, firewalld or iptables by the installer.

**Start in Observe mode. Canary and Enforce only after documented gate passage.**

---

## ✅ Validation Matrix (Complete Beta)

| Test | Status |
|---|---|
| Go Unit & Integration Tests | ✅ |
| go vet (Control + Gateway) | ✅ |
| Go Race Detector | ✅ |
| JavaScript Syntax Check | ✅ |
| Static Security Regression Audit | ✅ |
| Native Rust Common/Core Tests | ✅ |
| Rust Core Release Build | ✅ |
| eBPF Release Build | ✅ |
| Arch Package Build — GeDefense | ✅ |
| Arch Package Build — GaiaOS Integration | ✅ |
| Isolated systemd Validation | ✅ |
| GaiaOS Installer / Hardening Tests | ✅ |
| DAC Test without Bypass Capabilities | ✅ |
| 147-File Mirror Verification | ✅ |
| Installer Payload Verification | ✅ |
| SHA-256 Artifact Check | ✅ |

**Remaining release gate:** real target host smoke test for the concrete kernel, kernel verifier, XDP mode, network interface and network driver.

---

## 🚧 Known Limitations (1.0.0-beta.5)

- No Swarm / Mesh support
- No QUIC offloading
- No provider-level DDoS absorption
- No TLS decryption
- No Feed Auto-Enforce
- No guarantee against root compromise
- No complete Measured Boot attestation
- Gaia Cells Lifecycle Daemon external (GaiaOS runtime)
- Isolated Deception Service deferred

---

## 📋 Changelog

### v1.0.0-beta.5 — Complete Beta *(Current)*

Complete Beta designation — defense chain functionally complete and testable. Installer 3.5.1 with full gate sequence (build, kernel verifier, XDP attachment, IPC, backend, TLS). 147-file byte-identical GaiaOS source mirror. Full validation matrix passed. Production clearance remains a per-host property.

---

## 🔗 VGT Ecosystem

| Tool | Type | Purpose |
|---|---|---|
| 🛡️ **VGT GeDefense** | **Linux Security Fabric** | Kernel-near defense, XDR, encrypted evidence — you are here |
| 🧠 **[VGT AETHEL](https://github.com/visiongaiatechnology/aethel)** | **Sovereign AI OS** | Local AI intelligence OS with operator governance |
| 🖥️ **[VGT WP-Desk](https://github.com/visiongaiatechnology/vgtdesk)** | **OS-Layer / UX** | Hardened WordPress operator workspace |
| ⚔️ **[VGT Sentinel](https://github.com/visiongaiatechnology/sentinelcom)** | **WAF / IDS** | Zero-Trust WordPress WAF |
| ⚡ **[VGT Auto-Punisher](https://github.com/visiongaiatechnology/vgt-auto-punisher)** | **IDS** | L4+L7 Hybrid IDS |
| 🔐 **[VGT Omega Vault](https://github.com/visiongaiatechnology/vgt-omega-vault)** | **Encrypted Forms** | AES-256-GCM WordPress form vault |
| 🌐 **[GaiaCom](https://github.com/visiongaiatechnology/GaiaCom)** | **Communication** | Post-quantum federated E2EE platform |
| 📊 **[VGT Dattrack](https://github.com/visiongaiatechnology/dattrack)** | **Analytics** | Sovereign local analytics |

---

## 💙 Support the Mission

[![Donate](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal)](https://paypal.me/dergoldenelotus)

| Method | Address |
|---|---|
| **PayPal** | [paypal.me/dergoldenelotus](https://paypal.me/dergoldenelotus) |
| **Bitcoin** | `bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm` |
| **ETH / USDT (ERC-20)** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |

---

## 📄 License

**AGPL-3.0-only · © 2026 VisionGaia Technology · Cologne, Germany**

VGT GeDefense is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, version 3 only. Any derivative work or network-deployed modification must be published under the same license.

Enterprise deployments, TIER-0 audits (VGT SafetySys™) and commercial exception licenses: [visiongaiatechnology.de](https://visiongaiatechnology.de)

---

<div align="center">

**VISIONGAIATECHNOLOGY – WE ARCHITECT THE FUTURE OF SECURITY.**

[![VGT](https://img.shields.io/badge/VisionGaia-Technology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

*VGT GeDefense 1.0.0-beta.5 — Linux Security Fabric // Rust eBPF/XDP Data Plane // Go Control Plane // Host XDR // Ed25519 Evidence Ledger // AES-256-GCM Encrypted Vault // Reversible Hardening // GaiaOS-Native // Separated Trust Domains // No Cloud Control Plane // AGPL-3.0-only // Linux x86_64*

</div>
