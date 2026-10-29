<div align="center">

<img width="256" height="256" alt="GeDefense" src="https://github.com/user-attachments/assets/978d2835-c915-473d-9995-d315efaa869c" />


# VGT GeDefense
### Linux Security Fabric - Your Entenprise System

[![License](https://img.shields.io/badge/License-AGPL--3.0--only-blue?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)
[![Version](https://img.shields.io/badge/Version-5.1.0--beta.2-orange?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-Release_v5.1.0--beta.2-yellow?style=for-the-badge)](#)
[![Installer](https://img.shields.io/badge/Installer-Universal_Linux-green?style=for-the-badge)](#-quick-start)
[![Platform](https://img.shields.io/badge/Platform-Linux_x86__64-lightgrey?style=for-the-badge&logo=linux)](#)
[![Data Plane](https://img.shields.io/badge/Data_Plane-Rust_eBPF%2FXDP-red?style=for-the-badge&logo=rust)](#-architecture)
[![Control Plane](https://img.shields.io/badge/Control_Plane-Go-00ADD8?style=for-the-badge&logo=go)](#-architecture)
[![Crypto](https://img.shields.io/badge/Evidence-Ed25519%2FAES--256--GCM-gold?style=for-the-badge)](#-cryptography)
[![Sovereign](https://img.shields.io/badge/Control_Plane-Local%2FSovereign-brightgreen?style=for-the-badge)](#)
[![Linux](https://img.shields.io/badge/Linux-APT%20%7C%20DNF%20%7C%20pacman%20%7C%20Zypper-cyan?style=for-the-badge&logo=linux)](#-universal-linux-integration)
[![AstraeaOS](https://img.shields.io/badge/AstraeaOS-Native_Ready-7de3ff?style=for-the-badge)](#-astraeaos-integration)
[![Architecture](https://img.shields.io/badge/Architecture-Specification-9cf?style=for-the-badge&logo=blueprint)](ARCHITECTURE.md)
[![Security Audit](https://img.shields.io/badge/Security-Audit_Beta_5-success?style=for-the-badge&logo=shield)](SECURITY.md)
[![VGT](https://img.shields.io/badge/VGT-VisionGaiaTechnology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

**KERNEL-NEAR NETWORK DEFENSE · HOST XDR · ENCRYPTED EVIDENCE · REVERSIBLE HARDENING · NO CLOUD CONTROL PLANE**

<br />

🌐 **Languages / Sprachen / Языки / 语言:**  
**English** · [Deutsch](README.de.md) · [Русский](README.ru.md) · [中文 (简体)](README.zh.md)

</div>

> **GeDefense Ecosystem / Ökosystem / Экосистема / 生态系统:** [GeDefense WP](https://github.com/visiongaiatechnology/gedefensewp) — the WordPress side of the same security fabric.


<img width="1536" height="1024" alt="GeDefense_ Real Security, Many Feathers" src="https://github.com/user-attachments/assets/dc56735e-b2b2-45c9-a363-97554a92ae0a" />


---

## 🌐 The GeDefense universe

GeDefense is one local-first security fabric — for Linux, Windows, Android and WordPress. Every sibling project follows the same philosophy: local-only control, honest visibility, no silent telemetry.

| Project | Focus |
| --- | --- |
| [![Android TV](https://img.shields.io/badge/Android_TV-3DDC84?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense_androidtv) **GeDefense TV** | Security console for Android TV / Google TV: loopback VPN, traffic map, XDR-Light and reversible Kinetic-Lite containment. |
| [![Linux](https://img.shields.io/badge/Linux-D4AF37?style=flat-square&logo=linux&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense) **GeDefense Linux** *(this repository)* | Kernel-near network defense: eBPF/XDP enforcement, L7 WAF, host XDR with signed evidence and reversible hardening (Rust/Go, fully local). |
| [![Windows](https://img.shields.io/badge/Windows-8B5CF6?style=flat-square&logo=windows&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewin) **GeDefense Windows** | Local sovereign Windows 11 security console: Defender/ASR/WFP/App Control, hardening, MHX EDR/XDR, local threat intelligence and HMAC-chained evidence. |
| [![Android](https://img.shields.io/badge/Android-22D3EE?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefenseandroid) **GeDefense Android** | Native Android security platform: local VPN enforcement, endpoint telemetry, XDR/EDR correlation, threat intelligence, app-risk analysis and encrypted evidence. |
| [![WordPress](https://img.shields.io/badge/WordPress-1F8FFF?style=flat-square&logo=wordpress&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewp) **GeDefense WordPress** | AGPL-3.0 open-core suite for WordPress: ZEUS WAF, AEGIS deep-packet inspection, TRINITY XDR, ThroneGuard lockdown and HADES admin cloaking. |

## 🆕 Release 5.1.0-beta.2 — Security Hardening (2026-10-27)

Security hotfix for the 5.1.0-beta.1 CMS/bridge release. **Update is recommended before exposing the bridge.**

- **Trusted editor scope narrowed:** only exact VGT preview/save actions and post save routes may suppress the XSS false-positive family. SQLi, LFI, PHP-tag and all other pattern families remain active; protocol, encoding, upload and response checks remain active.
- **Sensitive L7 limits remain active for master leases:** login/XML-RPC and other sensitive-route buckets are no longer bypassed. The configured relaxed CMS client budget is now actually applied instead of an unconditional client bypass.
- **Revocation/replay hardening:** revocation is persisted across control restarts; bridge events older than the revoke watermark are ignored; loopback master leases are rejected; lease/profile/event bounds and fail-closed settings were tightened.
- **WordPress bridge hardening:** requires an unlocked ThroneGuard master session, rejects weak/default/duplicate salts, emits logout revocation and rejects loopback master events; normal administrators cannot claim a master when one already exists.
- **Installer hardening:** gateway access directories are created before secrets/TLS, python3 is installed before trust verification, only `prebuilt`/`source-signed` trust modes are accepted, and rollback ownership is corrected.
- **ALPHA:** the GeDefense WP ↔ Linux bridge remains an alpha test feature, not production-ready. See `SECURITY.md` and `CHANGELOG.md`.

---

> [!WARNING]
> **PUBLIC BETA — NOT PRODUCTION-READY (Version 5.1.0-beta.2).**  
> GeDefense Titan and the Linux security fabric are in active development. This
> beta is for test and qualification hosts only. The core architecture is
> exercised by automated release gates, but public-CA release authenticity,
> RFC3161 timestamps, revocation, externally anchored anti-rollback and feed
> signing keys are still missing. **This public beta may contain errors and
> security defects; we are actively working on fixes and welcome feedback
> through GitHub Issues.** Do not deploy this beta as a production security
> control; review `SECURITY.md` and `CHANGELOG.md` first.

## GeDefense Titan — Unauthorized File Manipulation and Contraband Injection Defense

**GeDefense Titan** is the native Linux protection module for a threat class that
classic network filters cannot see: an object is placed, replaced or modified
directly on the host — often by an actor who already has a foothold, a supply-chain
implant, a criminal tool, an APT or a state-access toolkit. Typical examples are
**remote file planting**, **contraband injection** and **silent dropping** of a
payload into a protected location without an approved deployment.

Titan asks a different question from “who was the attacker?” It deliberately does
**not attribute an actor**. For every observed file change it evaluates what was
observed, whether the change was authorized, how strong the independent evidence
is, and which response is safe:

- bounded inotify observation of configured protected roots and product paths;
- authorization from an explicit allowlist, a content-matched FIM baseline and
  real package ownership from the local dpkg/pacman databases — without executing
  package-manager commands from the production control plane;
- trust states `AUTHORIZED`, `TOLERATED`, `UNEXPECTED` and `COMPROMISED`;
- policy modes `OBSERVE`, `CONTAIN` and `STRICT`, with correlation quality
  `OBSERVED`, `TEMPORAL` or `NONE`;
- containment only through the existing encrypted, reversible quarantine
  transaction pipeline — never an arbitrary delete — with explicit refusal when a
  path or transaction is unsafe;
- bounded, signed evidence and an operator review path for every finding.

A missing authorization signal is not presented as safe. A sensor failure is
reported as degraded instead of fabricating coverage. Titan’s automatic
containment is opt-in and is off/unarmed in the safe default; an operator must
arm it, and every containment remains reviewable and reversible.

Titan is not a replacement for patching, least privilege, secure boot or a public
CA trust chain. This beta includes the module, its dashboard and its API, and is
not production-certified until the external trust anchors listed below are
available.

---

<img width="2492" height="1277" alt="image_2026-10-11_09-45-50" src="https://github.com/user-attachments/assets/9cfc5baf-ea41-454e-bc35-ef959a58d3d2" />


## Third-Party Licenses and Data Attribution

GeDefense includes third-party components and public data sets. Their licenses
are separate from the AGPL-3.0-only license of GeDefense itself. The full texts
and further details are in [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).

| Component / data | Original source | License |
|---|---|---|
| **jsVectorMap 1.7.0** — vendored SVG world map (`world-merc.js`) and dashboard map library | [themustafaomar/jsvectormap](https://github.com/themustafaomar/jsvectormap) · [world-merc.js 1.7.0](https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/maps/world-merc.js) | **MIT**, Copyright © 2020 Mustafa Omar ([license](https://github.com/themustafaomar/jsvectormap/blob/main/LICENSE)) |
| **IP-to-Country / IP-to-ASN data** — transformed into the offline `geoip.csv` | [iplocate/ip-address-databases](https://github.com/iplocate/ip-address-databases) | **CC BY-SA 4.0** ([license](https://creativecommons.org/licenses/by-sa/4.0/)); attribution: *IP-to-Country and IP-to-ASN databases by iplocate, licensed CC BY-SA 4.0; changes were made by VisionGaia Technology for GeDefense.* The transformed database is shared under the same CC BY-SA 4.0 terms. |
| **DB-IP Lite** — City GeoIP data used by the updater | [db-ip.com](https://db-ip.com/) | **CC BY 4.0**, attribution required |
| **Origin-ASN data** — used by the updater | [sapics/ip-location-db](https://github.com/sapics/ip-location-db) | **PDDL** |
| **Qt 6** — desktop tray runtime and build dependencies | [qt.io](https://www.qt.io/) | **LGPL-3.0 / commercial Qt terms**; the tray client links dynamically against the distribution Qt packages |

No third-party maintainer endorses or sponsors GeDefense. The dashboard loads
these assets locally; no runtime CDN or cloud lookup is used.


---

## 🏛️ Security Architecture & Technical Specification

> [!IMPORTANT]
> **For Security Researchers, System Architects & Auditors:**
> GeDefense maintains an exhaustive, formal technical architecture specification, trust boundary model, and symbol data tree:
> 
> ### ➔ [📘 ARCHITECTURE.md — Complete Technical Architecture & Specification](ARCHITECTURE.md)
> 
> *Over 4,400 lines specifying the 7-tier architecture tree, kernel eBPF/XDP data plane, Go control plane, typed Rust response core, native L7 WAF engine, cryptographic evidence ledger, and reversible posture engine.*

---

## 🧪 Verify Yourself — Full Test Suite & Independent Self-Audit

> [!TIP]
> **"Don't Trust, Verify" — Complete Transparency & Reproducibility**
> GeDefense is engineered for zero-trust environments. Every claim, security boundary, parser, cryptographic invariant, and wire-speed kernel filter is backed by an automated test suite. You can run all **634+ native test functions** and **19 security audit gates** locally with a single command.

### 📊 Test Suite & Coverage Breakdown

| Test Suite / Component | Location | Tests / Scenarios | Target Capabilities & Assurances | Direct Execution Command |
| :--- | :--- | :---: | :--- | :--- |
| **Control Plane Unit & Integration** | [`control/*_test.go`](control/) | **574 Tests**<br>*(108 files + 25 subtests)* | XDR DAG correlation, L7 WAF multi-pass decoding, FIM SHA-256 baselines, fail-closed release gates, dual ledger rotation (90% threshold), self-artifact updates | `cd control && go test -v ./...` |
| **Security Fuzzing Suite** | [`control/*fuzz_test.go`](control/) | **8 Fuzz Targets** | Memory safety & panic resistance under malformed inputs: L7 normalizer, TLS ClientHello, encrypted envelope, Core IPC responses, `/proc/stat` | `make fuzz-smoke` |
| **Gateway & Perimeter Auth** | [`gateway/*_test.go`](gateway/) | **28 Tests**<br>*(6 files)* | TLS 1.3 Post-Quantum ML-KEM curves, Argon2id password verification, `__Host-` cookie isolation, CSRF synchronizer tokens, origin stripping | `cd gateway && go test -v ./...` |
| **Rust Kernel Protocol & Data Plane** | [`rust/gedefense-common`](rust/gedefense-common/) | **6 Tests** | Zero-copy packet header parsing, IPv4/IPv6 VLAN/QinQ bounds, wire event decoders | `cargo test --locked --manifest-path rust/Cargo.toml -p gedefense-common` |
| **Rust Privileged Response Core** | [`rust/gedefense-core`](rust/gedefense-core/) | **18 Tests** | Replay guard eviction, sysctl compare-and-set contract, streaming malware scanner (polyglot/EICAR), AES-256-GCM quarantine vault | `cargo test --locked --manifest-path rust/Cargo.toml -p gedefense-core` |
| **GeDefense Titan (Linux)** | [`control/titan*`](control/) | **68 test cases** | Trust ladder, OBSERVE/CONTAIN/STRICT, bounded inotify, FIM/package evidence without command execution, reversible containment gates, API auth/replay/bounds, sensor degradation | `cd control && go test -run Titan ./...` |
| **Automated Security Audit** | [`scripts/security-audit.sh`](scripts/security-audit.sh) | **19 Audit Gates** | Zero unsafe DOM sinks (`innerHTML`, `eval`), strict CSP validation, I18N 4-language key parity, socket DAC file modes (`0700`/`0600`), no command execution / Titan evidence boundary | `bash scripts/security-audit.sh` |
| **Kinetic Wire-Speed Acceptance** | [`scripts/validate-kinetic-release-candidate.sh`](scripts/validate-kinetic-release-candidate.sh) | **Suite** | Ingress burst soak testing, invariant sliding windows, LPM trie drop benchmark | `bash scripts/validate-kinetic-release-candidate.sh` |
| **Linux Distro Integration** | [`scripts/validate-distro-integration.sh`](scripts/validate-distro-integration.sh) | **Suite** | Multi-distribution verification (Arch, Debian, Fedora, SUSE systemd contracts) | `bash scripts/validate-distro-integration.sh` |
| **Quarantine DAC & Vault Permissions** | [`scripts/validate-quarantine-dac.sh`](scripts/validate-quarantine-dac.sh) | **Suite** | Verifies root-only permissions, non-executable bits, directory boundary traversal traps | `bash scripts/validate-quarantine-dac.sh` |
| **Systemd Sandbox Validation** | [`scripts/validate-systemd.sh`](scripts/validate-systemd.sh) | **Suite** | Audits `DynamicUser`, `ProtectSystem=strict`, capability dropping across all service units | `bash scripts/validate-systemd.sh` |
| **Quad-Lingual I18N Parity** | [`scripts/validate-i18n.mjs`](scripts/validate-i18n.mjs) | **Suite** | 100% key synchronization check across DE, EN, RU, and ZH-CN catalogs | `node scripts/validate-i18n.mjs` |

### ⚡ Quick-Start: Run the Tests on Your Machine

```bash
# 1. Run all Go tests, static analysis, JS syntax checks & security audit (One-Click)
make test

# 2. Run Go tests with Go race detector enabled
make test-race

# 3. Run all native Rust tests (Kernel Common & Response Core)
cargo test --locked --manifest-path rust/Cargo.toml -p gedefense-common -p gedefense-core

# 4. Run the 8 Go security fuzzing smoke tests
make fuzz-smoke

# 5. Run the comprehensive static security audit script
bash scripts/security-audit.sh

# 6. Run the complete end-to-end repository validation
bash scripts/validate.sh
```

> 📖 **Formal Beta Test Plan:** For the full operational verification matrix across Observe, Canary, Enforce, and AstraeaOS, refer to [**BETA-TEST-PLAN.md**](BETA-TEST-PLAN.md).

---

### 7-Tier Sovereign Defense Fabric Overview

```text
1. PUBLIC ACCESS GATEWAY       Go · Port 9843 (TLS 1.3, ML-KEM PQ hybrid, Argon2id, CSRF sync-tokens)
2. COMMAND CENTER DASHBOARD   ESNext / Vanilla JS / Native CSS · 0 dependencies · CSP-hardened
3. CONTROL PLANE               Go · Port 9844 (Loopback only · XDR, L7 WAF, FIM, Evidence Ledger, Cases)
4. PRIVILEGED RESPONSE CORE   Rust · /run/vgt-gedefense/core.sock (HMAC VGT3, pidfd_open, sysctl CAS, fanotify)
5. KERNEL DATA PLANE           Rust no_std eBPF/XDP + cgroup-skb + LSM (LPM Trie 250k rules, RingBuf EDR)
6. INTEGRATION FABRIC          Universal Linux (APT/DNF/pacman/Zypper) · AstraeaOS Native Ring-1 Cells
7. RELEASE ENGINEERING         Toolchains.lock · Reproducible Builds · Cryptographic Mirror Manifests
```

### Core Security Invariants
- **No Cloud Control Plane:** Threat intelligence, behavioral baselines, operational keys, and forensic evidence remain 100% on the local host.
- **Kernel-Speed Data Plane:** Ingress network attacks are dropped at the NIC driver level via Rust eBPF/XDP before socket buffer (`sk_buff`) allocation.
- **Native L7 Plane (Go Standard Library Only):** Bounded HTTP normalization, anti-evasion decoding, and RE2 regex scanning with zero third-party dependencies, zero CGO, and zero scripting runtimes.
- **Web-Evidence Isolation Barrier:** Web findings carry `AlertOnly: true` (`ResponseScore: 0`). A web-tier finding can never autonomously trigger host-level process termination (`SIGKILL`/`SIGSTOP`); destructive containment strictly requires independent host/kernel evidence.
- **Cryptographic Evidence Ledger:** Tamper-evident, monotone sequence with predecessor hashing (`AES-256-GCM` + `Ed25519`).
- **Reversible Sysctl Hardening:** Atomic compare-and-set with kernel readback and automatic rollback on partial failure.

---

## 🔍 What is VGT GeDefense?

GeDefense is not a firewall rule manager. It is a **local sovereign Linux Security Fabric** — kernel-near network defense, Host XDR, encrypted evidence ledger, reversible system hardening and optional AstraeaOS-native isolation in one system, operated without any cloud control plane.

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
  Universal Linux                        → APT · DNF/YUM · pacman · Zypper integration
  AstraeaOS-native                       → verified source mirror, same security chain
```

A single regex, feed, behavioral or masquerading hit **cannot authorize process termination**. Enforce requires at minimum two independent authorized categories, objective broker evidence and a non-degraded system state.

---

<img width="2492" height="1277" alt="image_2026-10-11_10-43-44" src="https://github.com/user-attachments/assets/6ecbd910-1367-4418-824f-10c80159aff8" />


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

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/0712a990-f3ad-4b4a-8d18-8e0a60395fe1" />


### Trust Domain Separation

| Domain | Role | Privilege |
|---|---|---|
| **Public Gateway** | TLS 1.3, Argon2id, Host/Origin/CSRF, session auth | Unprivileged |
| **Control Plane** | XDR, Policy, Telemetry, FIM, Evidence, Cases, Dashboard | `gedefense` user |
| **Response Core** | XDP maps, pidfd reaction, quarantine, typed sysctl mutations | UID 0, Capability Bounding |
| **Data Plane** | IPv4/IPv6 parsing, LPM allow/blocklists at interface | Kernel/XDP |

### Deployment Modes

**Universal Linux** — One-click install on x86_64 systemd Linux with APT, DNF/YUM, pacman or Zypper. Rust Core and eBPF are compiled for the target kernel and NIC, then verified before atomic activation.

**AstraeaOS-native** — Identical core binaries, native provisioning, AstraeaOS hardening profile, boot trust evidence and optional Gaia Cells integration. GeDefense is the **single security authority** in AstraeaOS. Sentinel serves exclusively as migration and audit source — no competing runtime daemon.

---

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/57feccc5-75ab-46a1-a575-3a5ec3402087" />


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
| Native L7/AppSec plane with bounded normalization | ✓ |
| L7 implementation adds zero Go/runtime dependencies | ✓ |
| No runtime command execution in Go services | ✓ |
| Backend exclusively on loopback | ✓ |

**Sensitive state and keys never leave the protected host.**

---

## 🔧 Reversible Hardening

Profiles: `Generic Linux Server` and `AstraeaOS Workstation` — fixed key/value allowlist.

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

## 🐧 Universal Linux Integration

| Layer | Beta v4 integration |
|---|---|
| Package managers | APT · DNF/YUM · pacman · Zypper |
| Init | Hardened systemd units with syntax and runtime gates |
| Privilege boundary | Polkit-scoped readiness helper — no generic root shell |
| Desktop | Local Chromium application profile with exact SPKI pinning |
| TLS identity | Public host plus `localhost`, `127.0.0.1` and `::1` SANs |
| Release CI | Go race/fuzz/security · Rust Core · eBPF · artifact digests |
| Distribution contracts | Ubuntu/Debian · Fedora/RHEL · Arch · openSUSE |
| Concrete host gate | bpffs · verifier-visible eBPF · NIC XDP · IPC · TLS |

Distribution containers validate portable packaging and integration contracts.
They do not claim to qualify their host kernel. Every binary release still
requires the privileged test on the concrete kernel, driver and network device.

---

## 🌐 AstraeaOS Integration

| Feature | Status |
|---|---|
| Native provisioning / systemd | ✅ Implemented — same security chain as Standalone |
| GeDefense source mirror | ✅ Implemented — SHA-256 manifest verified |
| AstraeaOS hardening profile | ✅ Implemented — reversible and persistent |
| Boot trust evidence | ✅ Implemented — Evidence-only, no false attestation claim |
| Gaia Cells VGTGC1 Adapter | ✅ Implemented — Runtime optional |
| UUID / Generation / cgroup ID binding | ✅ Implemented — immutable action binding |
| Freeze / Network Reverse | ✅ Implemented — evidence-bound transaction |
| Gaia Cells Lifecycle Daemon | — Not included — AstraeaOS-owned runtime |
| Isolated Deception Service | — Deferred — outside Beta authority |

Cell actions are bound to UUID, lifecycle generation and kernel cgroup ID. Peer UID, HMAC, time window and nonce are verified.

If the Gaia Cells runtime is **not present**, the adapter reports `runtime_not_installed`. Generic host defense remains active and is **not degraded**.

> **Single Authority:** In AstraeaOS, GeDefense is the only security authority. Sentinel serves exclusively as migration and audit source.

---

## ⚙️ Runtime Contract

### System Requirements (Standalone)

| Requirement | Value |
|---|---|
| **OS** | Linux |
| **Architecture** | x86_64 / amd64 |
| **Init** | systemd |
| **Kernel** | BPF/XDP + pidfd |
| **Package Manager** | apt-get, dnf/yum, pacman or zypper |
| **Install** | Root + build internet access |
| **Gateway Runtime** | libargon2.so.1 |

> No blanket minimum kernel version or guaranteed NIC list is declared for this beta. The target host is qualified through build, kernel verifier, XDP attachment, IPC and health gates.

### Toolchain Pins

| Component | Version |
|---|---|
| **Go** | 1.27.3 |
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
| **L7 Inspection API** | `/run/vgt-gedefense-l7/inspect.sock` | Local Unix socket · bounded · optional SO_PEERCRED |
| **L7 Inline Edge** | `/run/vgt-gedefense-l7/edge.sock` | Optional local Unix reverse-proxy boundary |
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
| `/run/vgt-gedefense-l7/` | Ephemeral L7 Unix sockets only |
| `/sys/fs/bpf` | BPF filesystem |
| `/var/log/vgt-gedefense-install.log` | Install diagnostics — mode 0600 |

---

## 🚀 Quick Start

### One-Click installer

```bash
wget https://github.com/visiongaiatechnology/gedefense/releases/download/v5.1.0-beta.2/GeDefense-5.1.0-beta.2-OneClick.run
sha256sum --check GeDefense-5.1.0-beta.2-OneClick.run.sha256
chmod 700 GeDefense-5.1.0-beta.2-OneClick.run
sudo ./GeDefense-5.1.0-beta.2-OneClick.run
```

The installer is source-self-contained and verifies its signed release index,
payload manifest and anti-rollback floor before any privileged action. It
installs the control plane, gateway and Rust core; host-level qualification still
has to pass kernel verifier, XDP attachment, IPC, backend and TLS gates.


## ✅ Release Gates

| Gate | State | Release rule |
|---|---:|---|
| Source and upload manifests | ✅ Implemented | Zero digest drift |
| Secret/private-key marker scan | ✅ Implemented | Zero findings |
| GitHub Actions and container digest pinning | ✅ Implemented | Immutable identities only |
| Go unit, integration and vet | 🔒 Required CI | Must pass |
| Go race detector and security fuzz smoke | 🔒 Required CI | Must pass |
| JavaScript and shell syntax | ✅ Local + CI | Must pass |
| Static security regression audit | 🔒 Required CI | Must pass |
| Native Rust Common/Core tests | 🔒 Required CI | Must pass |
| Rust Core and eBPF release builds | 🔒 Required CI | Must pass |
| Ubuntu, Fedora, Arch and openSUSE contracts | 🔒 Required CI | All matrix jobs pass |
| Installer payload and SHA-256 verification | 🔒 Required CI | Must pass |
| Concrete kernel verifier and NIC XDP attach | ⏳ Host qualification | Required per release host |
| systemd, IPC, backend, TLS, Polkit and desktop | ⏳ Host qualification | Required per release host |

**Remaining release gate:** real target host smoke test for the concrete kernel, kernel verifier, XDP mode, network interface and network driver.

---

## 🚧 Known Limitations (5.1.0-beta.1)

- No Swarm / Mesh support
- No QUIC offloading
- No provider-level DDoS absorption
- No TLS decryption
- No Feed Auto-Enforce
- No guarantee against root compromise
- No complete Measured Boot attestation
- Gaia Cells Lifecycle Daemon external (AstraeaOS runtime)
- Isolated Deception Service deferred
- Replacing a protected release component is reported at high severity and does not disarm the platform; ledger rotation requires its archive directory to belong to the service with mode `0700` and refuses to run rather than writing into a shared directory
- The Rust core counts and logs skipped ingress samples but does not yet report the count in its health response, so the figure is visible in the service log rather than in the panel
- The FIM byte-hash baseline covers stable configuration, persistence and product files. Volatile log trees (`/var/log`, `/var/log/journal`) and root-only SSH host private keys are excluded: normal log growth cannot be a stable byte baseline, log tampering remains covered by the XDR `KD.LINUX.LOG_TAMPER` rules, and host-key custody remains with root and the package-integrity database

---

## 📋 Changelog

### v5.0.0-beta.1 — Automatic Gaia-Cell Isolation, Guarded Kernel Mitigation & Operational PHP/L7 Hardening *(Previous release)*

- **Automatic and manual Gaia-Cell isolation:** incidents at or above `cells.auto_confine_score` isolate the owning cell through the reversible transaction engine; manual isolation is available on each incident row. APIs: `POST /api/v1/xdr/incidents/{id}/confine`, `GET /api/v1/cells/confinement`.
- **Kernel mitigation guard:** opt-in sysctl mitigation with a bounded probation window, host-service verification and automatic rollback; the hardening view exposes dry-run, apply and rollback with a written reason.
- **PHP upload-progress mitigation:** the critical L7 rule `L7.PHP.SESSION_UPLOAD_PROGRESS` (score 110) and the hardening control `web.php-upload-progress`; `session.upload_progress.enabled = Off` is verified against the effective web SAPI.
- **Rule-scoped L7 enforcement:** `l7.enforce_rules` limits blocking to named rules/families; the inline edge self-test passes and the origin is loopback-only, so direct origin access cannot bypass inspection.

### v4.3.0 — Kernel Advisory Exposure: Detect, Score and Block What the Sensors Cannot See

- Runtime release/channel exposure against the shipped advisory catalogue, with `unknown` never presented as safe.
- Reachability-weighted exposure scoring and the kernel-risk dashboard panel (dry-run, apply, rollback).


### v4.2.5 — Real-Time Multi-Vector Threat Map, Immediate Post-Update Re-Arm & Self-Healing Telemetry

A visualization and platform resilience release. It brings a unified real-time detection overview across all attack vectors, immediate re-arm following software upgrades, and autonomous sensor self-healing.

* **Unified real-time attack map on the overview page:**
  * **All detection paths visualized simultaneously:** The overview dashboard now features an interactive, animated global threat map consolidating packet-level eBPF/XDP drops, Layer-7 application attacks, and post-exploitation/host XDR telemetry in a single pane.
  * **Sovereign host origin & geodesic attack arcs:** Attack flight paths curve directly towards this host's real resolved geographic position (via local offline GeoIP). Unplaceable records and `0,0` coordinates are safely suppressed to prevent misplacement artifacts.
  * **Seven path-segmented counters:** Live telemetry split across Sources, Placed, Blocked, Countries, and independent counts for Kinetic, L7, and XDR vectors.
  * **Real-time activity ledger:** A chronological activity band below the map displays the 10 newest incident ledger entries with timestamps, detection vector, origin IP/country, security finding, and blocking status.
  * **Strict zero-cloud & zero-external asset architecture:** Powered by a locally vendored MIT SVG geometry and an on-host 950,000-entry GeoIP database. Full accessibility support with keyboard controls and automatic suppression under `prefers-reduced-motion`. Fully localized in German, English, Russian, and Chinese.
* **Instant protection re-arm following updates (6-7 seconds):**
  * **Separation of host qualification from release version:** The startup supervisor separates host identity (kernel version, node name, network interface) from the software release string. An upgrade on a qualified machine no longer forces a 20-minute canary soak ladder; verified protection re-engages in 6-7 seconds.
* **Autonomous sensor self-healing & systemd resilience:**
  * **Traffic-derived sensor self-repair:** The `l7_application` sensor coverage no longer stalls in "awaiting traffic" across restarts. The `sensor_coverage` module autonomously executes a canonical self-test probe through the live inspection pipeline (bounded to 3 attempts).
  * **Pre-tick kernel health checks:** Kernel state is queried prior to the first checklist tick, eliminating transient false-positive degradation on process start.
  * **Strict gateway TLS certificate-key pairing:** Systemd units enforce matching certificate and key directories, verified by validation gates to permanently eliminate `ERR_CONNECTION_REFUSED` regressions.

### v4.2.4 — Fail-Closed Enforcement, Ledger Rotation and an Honest Panel

A hardening release. It removes the paths on which the platform could lose its own protection, and it makes every surface state what the kernel is actually doing.

* **Fail-closed enforcement (the disarmament):**
  * **An automatic degradation never releases the verified kernel policy.** A single kernel sample the core could not interpret - a mixed UDP/TCP aggregate, which the producer labels with the protocol of the packet that flushed it, so a TCP record can carry more attempts than SYNs - aborted the whole drain; the control plane read the failed drain as a lost kernel hook, and the release gate answered an unavailable sensor by reconciling the kernel policy to `observe`. Every block was removed from the kernel, and a production host ran unprotected for twenty hours because nothing brought it back. The gate now confirms and retains what it verified (`verified-enforce`), and a state it could not confirm is reported as `verified-empty` instead of being treated as the same thing.
  * **A restart keeps the enforcement the signed policy carries** instead of initialising to `observe`.
  * **A promotion never lowers verified enforcement.** Only an explicit operator action does, and a retention is reported as its own action (`automatic_response_paused`) rather than as an enforcement change.
  * **A drain or parser failure is separated from the loss of enforcement capability,** so a sensor that cannot deliver samples is no longer read as a kernel that cannot block.
  * **The platform re-arms itself** once the gates pass and the calm holds, and logs the transition together with the cause that had held it.
  * **A verification that succeeds clears the cause it replaced.** Causes were one-way: only a rotation or an operator recovery removed one, so a transient fault kept XDR degraded - and the automatic response paused - until somebody restarted the control plane.
  * **A deployment by the operator is no longer treated as an intrusion.** Replacing one of GeDefense's own components degraded XDR and paused the automatic response, so shipping a fix quietly switched part of the protection off. It is now a high-severity record with no response attached; third-party objects keep the full reaction.
  * **Recovering the incident ledger no longer requires giving up the protection,** which under retention was unreachable - the ledger could only be repaired by first disarming the host whose protection it exists to preserve.
  * **The Rust core tolerates an inconsistent aggregate.** A record whose TCP label contradicts its counters is kept with a neutralised protocol and its counters untouched; a record that still cannot be decoded is skipped and named instead of aborting the drain; only a batch in which many samples are undecodable - the signature of a wrong wire format - is reported as a fault.
* **Ledger retention:**
  * **Both forensic ledgers rotate instead of filling up.** Reaching the budget stopped the recording, degraded XDR and paused the automatic response until an operator archived the segment by hand - twice on one production host in one day. At ninety percent the sealed chain is archived with a manifest carrying sizes, digests, sequence, head hash and scope, and a fresh chain continues.
  * **The rotation survives a crash.** It copies before it replaces, so an interrupted run is completed at the next start from a rotation marker; a marker whose manifest does not match is refused rather than trusted.
  * **The evidence ledger verifies itself within bounds.** Startup verified the whole ledger - around 260 MB at roughly 6.7 seconds per megabyte - and exceeded the unit's start timeout, so the platform could not come up and neither could the gateway. Startup now checks the authenticated checkpoint and a bounded tail; the history is covered incrementally in the background against an authenticated watermark; the complete verification stays available to the operator. An unauthenticated watermark is refused, because accepting one let a forged file skip the entire history.
  * **An interrupted append is recovered** - verified and sealed, or dropped when it is a partial write - instead of preventing the service from starting.
* **Interface verification:**
  * **Every state-bearing sentence is checked against the payload that produced it.** A headless render of the dashboard - eleven payload and view combinations, eighty rules - compares what the operator reads with what the API reported. It found three statements that contradicted the state they described, all three introduced by this release's own corrections.
  * **The checker proves it can fail.** A self-test with deliberately wrong payloads, and a regression mode that removes the guards again: eighteen of the eighty rules then go red, including SYSTEM NOMINAL in the badge.

### v4.2.1 — Stability, Evidence and Interface Fixes

A fix release. It introduces no new subsystem; it makes the ones already present tell the truth about themselves and stay out of the operator's way.

* **Evidence ledger:**
  * **Capacity is no longer treated as corruption.** Reaching the retention budget set the ledger's integrity error, which quarantined it permanently and reported XDR as degraded with "mandatory evidence ledger unavailable". A full ledger is not a damaged one.
  * **One budget, read the same way from every side.** Construction is permissive and runtime strict, so a ledger that legitimately grew under a raised budget is accepted after a restart instead of the service refusing to start.
  * **The budget the operator raises is the budget the ledger enforces.** The constructor seeded its policy with the compiled-in 64 MiB default, which the append path prefers, so a budget raised to 256 MiB was discarded at every start: the ledger stopped at 64 MiB and then refused every append while still reporting itself healthy. The platform had silently stopped recording evidence. Both budgets now start out equal, and a budget lowered afterwards still takes effect.
  * **The condition names itself.** "Retention budget reached" and "integrity unavailable" are separate messages with separate figures and separate remedies.
* **Release gate:**
  * **A fail-safe keeps its reason.** The cause was overwritten by the live blocker list on the next refresh, so a platform still sitting in Observe eventually read "release gates satisfied".
  * **A fail-safe is forensic evidence.** A fall-back is the most consequential thing the platform does on its own, and it left no incident behind.
* **L7 Application Defense:**
  * **A passing self-test clears a stale degradation,** bounded to fifteen minutes so a stale pass cannot mask a path that has since broken.
  * **The generated nginx configuration could never be applied.** It emitted a server block with `listen ... ssl` and a comment where the certificate directives belong - rejected outright by nginx - and named a host that already had a server block. It is now two insertable pieces, validated against the real nginx parser in the test suite.
  * **The enforcement path is reported.** `INGRESS_HEALTH` states which hook the kernel attached - native XDP, generic XDP or TC ingress - instead of describing all three as a verified kernel ingress producer, though they behave very differently under load.
  * **The operator can see whether HTTP traffic exists while L7 is not in its path.** Web-surface discovery reports whether a web server runs on this host and on which ports - read-only, bounded, and never presented as protection, because detection is not protection.
  * **Guided web-server integration generates configuration text and nothing else.** It never writes to a web server's configuration, never reloads a service and never claims that a generated snippet is in effect; the operator applies it, and the self-test then observes whether it worked. Every interpolated value is validated against a closed grammar first, because the output is a configuration file for a privileged daemon.
  * **Inspected requests are both counters, not one of them.** The panel displayed the request counter alone, so a host whose inline listener had inspected 174 requests reported "0 geprüfte Requests" directly beneath its own "TRAFFIC ACTIVE" badge - the panel contradicting itself and hiding the evidence that its verdict was right. The figure is now the sum the verdict is computed from.
* **Kinetic Defense:**
  * **Enforcement and effect are visible.** The panel states the hook in use, the kernel channel's health and what the engine detected and did. In Observe mode it says so: a column of zeros means the response stage was never entered, not that nothing was seen.
  * **The overview carries the figures,** grouped by the question each one answers.
  * **The coverage summary explains the sensor it names.** The sentence beneath it was bound to one sensor name, so a summary reading "Mandatory sensors degraded: l7_application" was explained by the healthy ingress producer's sentence - a degraded headline over a positive explanation, on a page that contradicted the Application Defense page in the same session while both read the same snapshot. The reason now belongs to the sensor that made the platform non-nominal, using the server's precedence, and the fallback is a translated key instead of a German literal.
  * **The summary is deterministic.** It states that it determines the status deterministically, but it joined the sensor names in map iteration order, so the same state produced a differently ordered sentence on every refresh.
* **Hardening and integrity:**
  * **A tamper finding on GeDefense's own components no longer arms the response.** A digest mismatch on one of the product's own binaries cannot be told apart from an approved update, and the response engine contained on it: over a hundred recorded incidents show the product freezing its own access gateway, a denial of service any attacker can trigger by touching a single file. The finding survives at full severity - same rule, same score, same category - and only the response is withheld; third-party binaries keep theirs. The product's own components are recognised through one shared root that follows `VGT_RELEASE_ROOT`.
  * **Ten hardening switches were inert** on an already-hardened host, because a switch was disabled whenever its control was already PROTECTED; the preflight verifies a selection, it does not apply one.
  * **The posture cannot overstate itself.** A host where two of twenty-two controls were readable and both passed scored 100 and read HARDENED. The level is now capped when the evidence cannot support it, and coverage is stated beside the score.
  * **A changed protected object is reported as the object, once.** The protected set reaches the same release binary through `/current/bin/...` and `/releases/<version>/bin/...`, so one replacement produced two critical incidents - and an unremediated change was announced again every dedupe interval until the service restarted, so one fact buried the ledger it was recorded in. Reporting is now keyed by the resolved object and its observed state, and the reason names every object that changed.
  * **The integrity panel names the subsystem that is actually degraded,** instead of showing `INTEGRITY_FAILURE` while the incident ledger it points at is healthy and has nothing to do with it.
* **Threat Intelligence:**
  * **FireHOL Level 1 is enforced, not correlated.** A recorded schema migration raises the stored value on existing nodes, matched by feed ID and never lowered, because an operator's setting is being changed on their behalf.
* **Control plane lifecycle:**
  * **An internal restart,** reachable from the interface, activates the RESTART-class values that were persisted but never applied. It refuses when no supervisor would bring the process back, because exiting there would stop the product and leave it stopped.
* **Access gateway and interface:**
  * **The sign-in form no longer invalidates itself.** Every page view minted a fresh CSRF token and overwrote the cookie, so the cookie was a single shared slot rather than a property of the form on screen. The page carries its own language links, browsers prefetch and prerender them, and that second request was enough to leave the visible form holding a token the cookie no longer matched - which is why an operator who did nothing wrong could not sign in however often they reloaded. A second tab, a back/forward restore and a third-party `<img>` pointing at the endpoint did the same. The token a browser is given is now reused until it expires; the protection is unchanged, being 24 random bytes in an HttpOnly, Secure, SameSite=Strict, host-only cookie that no other site can read or set.
  * **An expired sign-in form no longer ends in a dead end.** It was a bare `403 request rejected` that named neither the cause nor a way out. The rejection itself is unchanged - without a matching token nothing is authenticated and no password is read - but a stale form is now returned to a fresh one carrying an explanation in all four languages, and the lifetime is one hour.
  * **The refusal reason is shown once.** It travelled in the query string, which made it a property of the address instead of the event: reloading, or returning to the page from history, repeated "this sign-in page had expired" over a form that had just been issued and was valid. It now rides a one-shot cookie that the page consumes.
  * **Gateway rejections are diagnosable.** The log records the reason, the fingerprint of the token that was expected and of the one that arrived, and which cookies were present - never a token value.
  * **The sign-in page was recomposed** around the facts the host can actually attest before any credential exists, with the product mark embedded rather than drawn in CSS.
  * **The dashboard authentication surface** states what the host attests and verifies a key against the control plane before claiming a session was authorised.
  * **Protection Center and navigation:** a headline that repeated the status pill verbatim, a button that promised navigation and did nothing, a permanently solid-red emergency stop beside the primary action, a dollar-sign navigation icon and a duplicated shield.
* **Translations:**
  * **58 keys existed only in German,** so operators reading English, Russian or Chinese saw raw key identifiers across the enforcement panel, the evidence notice and the restart surface. Coverage is now a per-catalogue property, and `t()` call sites are checked as well as document attributes.

### v4.2.0 — Security Fabric Control Plane

* **Comprehensive Security Audit Remediation & Hardening:**
  * **Critical:** Remediated symlink-traversal vulnerability in canary deployment (arbitrary file write / root privilege escalation) via component-by-component `openat(2)` resolution with `O_NOFOLLOW|O_DIRECTORY` and deterministic `ELOOP` enforcement.
  * **High:** Replaced information disclosure leaks with typed, opaque error responses across 5 API handlers; structural decoupling replaces incomplete substring blacklists.
  * **High:** Fail-closed CSPRNG (`log.Fatalf`) prevents fallback to predictable timestamp IDs for evidence, incidents, quarantine, and blocks.
  * **High:** Resolved remote panic in settings import preview via fail-closed ephemeral key derivation.
  * **High:** Import tokens are cryptographically bound to the verified payload digest (preventing token collisions).
  * **Medium:** Crash-safe atomic writer (`atomicWriteFile`) for policies, feeds, and Chronos checkpoints with symlink rejection, `O_EXCL`, and parent-directory `fsync`.
  * **Medium:** `unsafe-inline` styles eliminated from Content Security Policy; HSTS strictly enforced over TLS.
* **Security Fabric Control Plane:**
  * 12 administrable modules (`kinetic`, `network`, `protection`, `xdr`, `l7`, `threat_intel`, `hardening`, `integrity`, `boot_trust`, `policy_trust`, `forensics`, `system`).
  * Server-authoritative schema, immutable snapshots on hot paths, persisted `restart_required` semantics.
  * Non-administrable security invariants: kernel maps, core auth, private key secrecy, management self-lockout prevention, feed anti-poisoning.
* **Control-Plane Workbench & Telemetry:**
  * Deterministic settings search (`GET /api/v1/settings/search`) with live values and match rationale.
  * Cryptographically signed, secret-sanitized settings export (`POST /api/v1/settings/export`).
  * True two-stage import (`/import/preview` + `/import/apply`) with diff analysis and single-use tokens.
  * Continuous drift detection (`GET /api/v1/settings/drift`) raising `CONFIG_DRIFT`.
* **Vendored Offline SVG World Map (jsVectorMap 1.7.0):**
  * 100% local rendering without external CDNs or tile servers; native buttons guarantee strict compliance with `require-trusted-types-for 'script'`.
  * Local GeoIP/ASN resolution, choropleth density display, live threat markers, and traffic pulse.
* **UI/UX Supreme — Modern Dashboard Design:**
  * Card grids eliminated; semantic `<dl>` data ribbons with hairline separators.
  * Pure state-driven color palette, WCAG AA accessibility, native keyboard controls (`<button>`), and full `prefers-reduced-motion` support.
* **Runtime & Engine Fixes:**
  * Resolved deadlock in `CaseEngine.Status`.
  * Eliminated fail-open states in Airlock inspector and CaseEngine.
  * Corrected route `GET /assets/{name...}` for multi-segment path resolution.
  * Raised toolchain security floor to Go ≥ 1.26.6 (remediating 6 standard-library CVEs).

### v4.0.1 — Chinese Localization, Dedicated XDR Kernel Recovery Tab & Startscreen Expansion

- **Simplified Chinese (`zh-CN` / `ZH`) Localization:** Complete Command Center translation across all tabs, dialogs, operations, UI text, and runtime toasts (743 keys, 100% parity across DE, EN, RU, zh-CN). Added Chinese language selector and localized copy to public Access Gateway Startscreen.
- **Dedicated XDR Kernel Recovery Tab:** Added dedicated `#xdr` recovery interface tab and `/api/v1/xdr/recovery` endpoint with `ARCHIVE_AND_REINITIALIZE_XDR` confirmation gate to inspect degraded ledger state, archive corrupted chains with cryptographic SHA-256 manifests, and safely re-initialize kernel eBPF sensors and maps directly from the UI.
- **Ledger Hash Domain Separation:** Dedicated `evidence_root` field for attack-story Merkle trees and `record_hash` for the HMAC incident ledger chain, preventing false degradation upon daemon restart.
- **Version Alignment:** Updated all binaries, access gateway, web UI, integration contracts, Rust workspace, and packaging manifests to `4.0.1`.

### v4.0.0-beta.1 — Native L7 Application Security & Correlation Hardening

**L7 Application Security Plane (WAF & API Gateway)**

- **Go Standard Library Implementation:** Built-in L7 inspection engine integrated directly inside the unprivileged Go control plane (`gedefense-control`). 100% CGO-free, zero third-party dependencies, and zero auxiliary scripting engines (no Lua, WASM, or Node.js runtime).
- **Dual-Mode Deployment Architecture:**
  - *Advisory / Standalone Socket:* Mode `0660` Unix socket (`/run/vgt-gedefense-l7/inspect.sock`) providing a structured JSON evaluation API (`POST /v1/inspect`) with strict envelope validation (`DisallowUnknownFields`) for external reverse proxies (nginx, Caddy, Envoy, Apache).
  - *Native Inline Reverse-Proxy Gate:* Transparent inline filter (`/run/vgt-gedefense-l7/edge.sock`) positioned directly between TLS termination and backend applications with bounded concurrency and fail-closed admission budgets.
- **Strict Upstream Confinement (Anti-SSRF):** Inline forwarding target is restricted strictly to clean absolute Unix sockets or explicit loopback IP literals (`127.0.0.1`, `[::1]`). Request-controlled routing and DNS resolution are architecturally impossible.
- **Bounded Normalization & Anti-Evasion Engine:**
  - Multi-pass recursive unescaping (URL path and query unescaping, HTML entities, `\uXXXX` and `\xXX` escape sequences).
  - Unicode Fullwidth Fold (`\uff01`–`\uff5e` folded into ASCII) eliminating filter bypasses using wide Asian glyphs.
  - Automatic detection and decoding of unpadded and URL-safe Base64 payloads inside parameter values.
  - Streaming JSON parser with strict recursion limits (`max_json_depth = 32`) and token budgets.
  - Bounded Gzip and Deflate decompression via `io.LimitReader` preventing zip-bomb / decompression DoS.
  - 16 KB overlapping chunking (256-byte overlap) for unstructured text bodies, preventing signature evasion across chunk boundaries without duplicate memory allocations.
- **Exhaustive Attack Detector Suite (RE2 Linear Execution, Zero ReDoS):**
  - *SQL Injection (SQLi):* UNION SELECT syntax, boolean tautologies (`' OR 1=1`), time delays (`pg_sleep`, `benchmark`, `waitfor delay`), and stacked query statements.
  - *Cross-Site Scripting (XSS):* Executable script tags, inline DOM event handlers (`onerror=`, `onload=`), dangerous active schemes (`javascript:`, `data:text/html`), and `iframe srcdoc` payloads.
  - *Command Injection / RCE:* Shell chaining (`;`, `&&`, `||`, `|`), substitution syntax (`$(...)`, backticks), and Windows/PowerShell execution chains.
  - *Path Traversal & LFI:* Traversal sequences (`../`, `..\`), sensitive Linux paths (`/etc/passwd`, `/proc/self/environ`), and dangerous stream wrappers (`php://`, `phar://`, `data://`).
  - *SSTI, XXE & Deserialization:* Server-side template expressions (Jinja, Twig, Smarty, Spring), external XML entity declarations (`SYSTEM`/`PUBLIC`), PHP serialized objects, Java serialization magic (`rO0AB`), and JNDI/Log4j lookups.
  - *HTTP Request Smuggling & Framing Anomalies:* Duplicate or invalid `Content-Length`, simultaneous `Content-Length` and `Transfer-Encoding` (CL.TE / TE.CL), non-chunked transfer encodings, and `TRACE` method requests.
- **Evasive SSRF Defense with Flexible IP Normalization:**
  - Decodes and normalizes alternative IPv4 representations: hexadecimal, octal, decimal DWORD integer, and 2-/3-part dotted notations.
  - Enforces mandatory jails against loopback, link-local, private, and all major cloud metadata endpoints (AWS IMDSv2, GCP, Azure, Alibaba, Oracle Cloud).
- **In-Memory Airlock Upload Inspection (`InspectBytes`):**
  - Multipart file uploads are inspected directly in RAM prior to touching persistent storage.
  - Enforces strict part count and file size limits; validates Magic Bytes (ELF, PNG, JPEG, GIF, PDF, ZIP), MIME cross-checks, double extensions (`.php.jpg`), null-byte injections, and SHA-256 blacklists.
- **3-Tier Sharded Token-Bucket Rate Limiter:**
  - 64 independent shards using FNV-1a hashing, eliminating lock contention under high-volume concurrent traffic.
  - Per-client volume rate limiting.
  - Per-route sensitive endpoint protection (`/login`, `/wp-login.php`, `/api/login`) against brute-force attacks.
  - Global route rate limiting protecting against distributed botnets and credential-stuffing pools.
- **Response Data-Leak Prevention (DLP):**
  - Monitors upstream response bodies for database errors (`SQLSTATE`), server-side source code leaks (`<?php`, `<jsp:`), application stack traces, and private key disclosures (`BEGIN RSA PRIVATE KEY`).
  - Strict wire-byte preservation: responses are inspected via non-destructive prefix buffering while wire bytes are streamed unaltered to the client.

**XDR Correlation & Host Integrity**

- **Web-Evidence Isolation (Anti-False-Positive Barrier):** L7 findings carry `AlertOnly: true` and `ResponseScore: 0`. Web signals alone can **never** trigger autonomous destructive host containment (SIGKILL / SIGSTOP); destructive actions strictly require independent host kernel evidence.
- **Trinity XDR 2.0 DAG Integration:** L7 events are ingested as causal graph nodes (`HTTP_REQUEST`, `HTTP_RESPONSE`) with Merkle-root cryptographic proof chaining.
- **Host Network Correlation:** Real-time correlation connects incoming hostile HTTP requests with local Linux socket connections (`SO_PEERCRED` PID/UID/GID and `NetConnection` remote tracking).
- **Release-Gate Gated Enforcement:** Inline blocking is active only when the release gate reaches `Enforce` with a verified, healthy Core; otherwise, traffic defaults safely to `Observe`.

**Systemd, Linux DAC & Release Hardening**

- Dedicated system group `gedefense-l7` and pre-provisioned runtime directory `/run/vgt-gedefense-l7` (mode `0750`) via `systemd-tmpfiles`.
- Unix sockets created with mode `0660` and authenticated peer credentials (`SO_PEERCRED`).
- Pinned Go 1.27.3 release toolchain verified by AST security audit.
- 3 new continuous fuzzing test suites in CI verifying normalizer safety, response byte preservation, and upstream jail confinement.

### v3.0.0-beta.1 — Universal Linux Integration

**Integration and deployment**

- Promoted the portable AstraeaOS readiness and privilege contracts into the
  generic Linux release instead of keeping them OS-specific.
- Added installer dependency resolution for APT, DNF/YUM, pacman and Zypper.
- Added a generic Polkit authorization boundary and systemd readiness helper.
- Added a desktop launcher using a dedicated Chromium application profile and
  an exact certificate SPKI pin without changing the global trust store.
- Kept SDDM, ArchISO and Gaia Cells behavior conditional to AstraeaOS hosts.

**Security and correctness**

- Added `localhost`, `127.0.0.1` and `::1` to generated gateway certificate SANs
  while retaining the configured public host identity.
- Added the malware reputation hash database to source staging, release payload
  generation, protected installer configuration and rollback state.
- Added fail-closed source/upload manifests, forbidden-secret marker scanning,
  symlink rejection and strict source size boundaries.
- Added LF normalization and explicit Unix executable modes for Linux scripts.

**Release engineering**

- Added mandatory Go unit/vet/race/fuzz and static security gates.
- Added pinned Rust userspace tests, Rust Core release build and no_std eBPF build.
- Added digest-pinned Ubuntu, Fedora, Arch and openSUSE integration jobs.
- Pinned GitHub Actions to immutable 40-character commit identities.
- Added a privileged host workflow for bpffs, kernel-visible eBPF programs,
  concrete NIC XDP attachment, authenticated IPC/TLS, systemd, Polkit and desktop.
- Added deterministic Beta v4 source/installer artifact names and SHA-256 checks.

**Unchanged security foundation**

- The separated Go Control Plane, Rust Response Core and Rust eBPF/XDP Data
  Plane remain the Beta 5 security foundation.
- Observe → Canary → Enforce, Evidence Ledger, encrypted Response Vault,
  reversible hardening and evidence-gated response semantics remain intact.

### v1.0.0-beta.5 — Complete Beta

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

### 🗺️ Data Attribution & Local GeoIP / ASN Database

GeDefense includes a 100% offline, locally evaluated GeoIP and Origin-ASN database (`/var/lib/vgt/gedefense/geoip.csv`) guaranteeing zero runtime cloud lookups or external telemetry:

* **DB-IP Lite:** This product includes GeoLite2 or DB-IP Lite data created by DB-IP, available from [https://db-ip.com/](https://db-ip.com/) under the Creative Commons Attribution 4.0 International License (CC BY 4.0). Attribution required.
* **Origin ASN Data:** Origin ASN mapping data provided by [sapics/ip-location-db](https://github.com/sapics/ip-location-db) under the Public Domain Dedication and License (PDDL).

#### Updating the Local GeoIP Database

You can refresh, LPM-merge, and atomically install the local GeoIP database anytime using the included updater script:

```bash
# Downloads latest DB-IP City and Origin-ASN datasets, compiles < 128 MiB / < 1,000,000 prefix CSV, and atomically updates /var/lib/vgt/gedefense/geoip.csv
sudo python3 scripts/update-geoip-db.py /var/lib/vgt/gedefense/geoip.csv
```

### Third-Party Licenses

The following components and data sets are included in GeDefense and remain
under their own licenses. Full texts are in
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).

| Component / data | Source | License |
|---|---|---|
| **jsVectorMap 1.7.0** — vendored SVG world map (`world-merc.js`) and dashboard map library | [themustafaomar/jsvectormap](https://github.com/themustafaomar/jsvectormap) · [world-merc.js 1.7.0](https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/maps/world-merc.js) | **MIT** ([LICENSE](https://github.com/themustafaomar/jsvectormap/blob/main/LICENSE)), Copyright © 2020 Mustafa Omar |
| **IP-to-Country / IP-to-ASN data** — transformed into the offline `geoip.csv` | [iplocate/ip-address-databases](https://github.com/iplocate/ip-address-databases) | **CC BY-SA 4.0** ([license](https://creativecommons.org/licenses/by-sa/4.0/)); attribution: *IP-to-Country and IP-to-ASN databases by iplocate, licensed CC BY-SA 4.0; changes were made by VisionGaia Technology for GeDefense.* The transformed database is shared under the same CC BY-SA 4.0 terms. |
| **DB-IP Lite** — City GeoIP data used by the updater | [db-ip.com](https://db-ip.com/) | **CC BY 4.0**; attribution required |
| **Origin-ASN data** — used by the updater | [sapics/ip-location-db](https://github.com/sapics/ip-location-db) | **PDDL** |

No third-party maintainer endorses or sponsors GeDefense. The dashboard loads
these assets locally; no runtime CDN or cloud lookup is used.

---

<div align="center">

**VISIONGAIATECHNOLOGY – WE ARCHITECT THE FUTURE OF SECURITY.**

[![VGT](https://img.shields.io/badge/VisionGaia-Technology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

*VGT GeDefense 5.1.0-beta.2 — Universal Linux Security Fabric // Rust eBPF/XDP Data Plane // Go Control Plane // Host XDR // Ed25519 Evidence Ledger // AES-256-GCM Encrypted Vault // Reversible Hardening // AstraeaOS-Native Adapter // Separated Trust Domains // No Cloud Control Plane // AGPL-3.0-only // Linux x86_64*

</div>
