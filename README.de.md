<div align="center">

<img width="256" height="256" alt="GeDefense" src="https://github.com/user-attachments/assets/978d2835-c915-473d-9995-d315efaa869c" />


# VGT GeDefense
### Linux Security Fabric - Your Entenprise System

[![License](https://img.shields.io/badge/License-AGPL--3.0--only-blue?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)
[![Version](https://img.shields.io/badge/Version-6.2.1-orange?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-Release_V6_(6.2.1)-brightgreen?style=for-the-badge)](#)
[![Installer](https://img.shields.io/badge/Installer-Universal_Linux-green?style=for-the-badge)](#-schnellstart)
[![Platform](https://img.shields.io/badge/Platform-Linux_x86__64-lightgrey?style=for-the-badge&logo=linux)](#)
[![Data Plane](https://img.shields.io/badge/Data_Plane-Rust_eBPF%2FXDP-red?style=for-the-badge&logo=rust)](#-architektur)
[![Control Plane](https://img.shields.io/badge/Control_Plane-Go-00ADD8?style=for-the-badge&logo=go)](#-architektur)
[![Crypto](https://img.shields.io/badge/Evidence-Ed25519%2FAES--256--GCM-gold?style=for-the-badge)](#-kryptografie)
[![Sovereign](https://img.shields.io/badge/Control_Plane-Local%2FSovereign-brightgreen?style=for-the-badge)](#)
[![Linux](https://img.shields.io/badge/Linux-APT%20%7C%20DNF%20%7C%20pacman%20%7C%20Zypper-cyan?style=for-the-badge&logo=linux)](#-universelle-linux-integration)
[![AstraeaOS](https://img.shields.io/badge/AstraeaOS-Native_Ready-7de3ff?style=for-the-badge)](#-astraeaos-integration)
[![Architecture](https://img.shields.io/badge/Architecture-Specification-9cf?style=for-the-badge&logo=blueprint)](ARCHITECTURE.md)
[![Security Audit](https://img.shields.io/badge/Security-Audit_V6-success?style=for-the-badge&logo=shield)](SECURITY.md)
[![VGT](https://img.shields.io/badge/VGT-VisionGaiaTechnology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

**KERNELNAHE NETZWERKVERTEIDIGUNG · HOST-XDR · VERSCHLÜSSELTE EVIDENZ · REVERSIBLE HÄRTUNG · KEINE CLOUD-CONTROL-PLANE**

<br />

🌐 **Languages / Sprachen / Языки / 语言:**  
[English](README.md) · **Deutsch** · [Русский](README.ru.md) · [中文 (简体)](README.zh.md)

<br />

⬇️ **Direkt-Installer (v6.2.1 / V6):**
[**OneClick-Installer (`.run`)**](https://github.com/visiongaiatechnology/gedefense/releases/download/v6.2.1/VGT_GeDefense_V6_6.2.1_OneClick.run) · [`.sha256`](https://github.com/visiongaiatechnology/gedefense/releases/download/v6.2.1/VGT_GeDefense_V6_6.2.1_OneClick.run.sha256) · [**Desktop-Tray (`.run`)**](https://github.com/visiongaiatechnology/gedefense/releases/download/v6.2.1/GeDefense-6.2.1-Desktop-OneClick.run) · [`.sha256`](https://github.com/visiongaiatechnology/gedefense/releases/download/v6.2.1/GeDefense-6.2.1-Desktop-OneClick.run.sha256) · [**Quellarchiv (`.zip`)**](https://github.com/visiongaiatechnology/gedefense/releases/download/v6.2.1/VGT_GeDefense_V6_6.2.1_Source.zip) · [**Release v6.2.1**](https://github.com/visiongaiatechnology/gedefense/releases/tag/v6.2.1) · [**Benchmark-Ergebnisse (`94.73 / PASS`)**](benchmarks/vgt-hardred-6.2.1/) · [Schnellstart](#-schnellstart)

</div>

---

## 🧭 Schnellnavigation

| Bereich | Inhalt | Sprung |
|---|---|---|
| 📊 **VGT HardRed Benchmark** | `94.73 / 100 · PASS` vs. OSS+SafeLine (`59.28 / PASS`), OSS+ModSec (`55.40 / FAIL`), SafeLine (`52.92`), Wazuh & CrowdSec | [Ergebnisse](#-vgt-hardred-benchmark--v621-vs-oss-stack-evaluation) |
| 📂 **Rohdaten & Nachweise** | Alle HardRed- & ARES-Dashboards, SARIF-, ATT&CK-, OCSF- & GoTestWAF-Reports | [`benchmarks/vgt-hardred-6.2.1/`](benchmarks/vgt-hardred-6.2.1/) |
| ⚙️ **Reproduktion & Settings** | Exakte `EDR/Hardened Max`-Konfiguration & `6.2.0 → 6.2.1`-Delta | [Konfiguration](#-reproduktion-des-benchmark-profils-max-hardness) |
| 🔍 **Was ist VGT GeDefense?** | V6.2.1-Stack, Module A–E, Titan, Setup-Wizard & PC vs. Server | [Überblick](#-was-ist-vgt-gedefense) |
| 🧪 **Verify Yourself** | Native Go/Rust-Testsuiten & 19 Sicherheits-Audit-Gates | [Selbstprüfung](#-verify-yourself--vollständige-test-suite--selbstaudit-leitfaden) |
| 🏛️ **Architektur & Fabric** | Vertrauensdomänen, eBPF/XDP, Host-XDR, StyX & Kryptografie | [Architektur](#-architektur) |
| 🚀 **Schnellstart & Gates** | OneClick-Installer, Release-Gates & bekannte Grenzen | [Schnellstart](#-schnellstart) |
| 📋 **Changelog** | Vollständige Historie (`v6.2.1` → `v1.0.0-beta.5`) | [Changelog](#-changelog) |
| 📄 **Lizenz & Attributionen** | `AGPL-3.0-only`, GeoIP/ASN & Drittanbieter-Lizenzen | [Lizenz](#-lizenz) |

---

## 📊 VGT HardRed Benchmark — V6.2.1 vs. OSS-Stack-Evaluation

Gemessen mit dem Open-Source-Multi-Domänen-Benchmark **[VGT HardRed (`RedHard`)](https://github.com/visiongaiatechnology/redhard)** (`2026-11-24T00:28:34Z`) auf einer Snapshot-isolierten **Ubuntu 24.04 (Linux HWE 7.0, NGINX + PHP 8.3-FPM)** Ziel-VM (`eth0` Out-of-Band Control-Plane, `eth1` nicht-allowlistete Host-Only Attack-Plane; 4-Achsen-Modell: Efficacy 45 % · FP-Resilienz 20 % · Latenz & Eindämmung 20 % · System-Overhead 15 %). Dieser erweiterte Lauf vergleicht **GeDefense Linux 6.2.1** direkt gegen **OSS Best-of-Breed + SafeLine WAF**, **OSS Best-of-Breed (ModSecurity CRS + Suricata IPS + Tetragon + ClamAV)**, **Chaitin SafeLine WAF CE 9.4.7 (Solo)**, **Wazuh**, **CrowdSec** und die saubere **Baseline**:

| Rang | Sicherheitssystem | Gesamt (0–100) | Achse 1: Effektivität | Achse 2: FP-Resilienz | Achse 3: Latenz & Eindämmung | Achse 4: Overhead | Gate |
|---:|---|---:|---:|---:|---:|---:|---|
| 1 | **GeDefense Linux 6.2.1 (`EDR/Hardened Max`)** | **94.73** | **95.88** | **100.00** | **92.20** | **87.63** | **`PASS`** |
| 2 | **OSS Best-of-Breed + SafeLine WAF (`SafeLine + Suricata + Tetragon + ClamAV`)** | **59.28** | 69.31 | 100.00 | 38.14 | 3.08 | `PASS` |
| 3 | **OSS Best-of-Breed (`ModSec CRS + Suricata IPS + Tetragon + ClamAV`)** | **55.40** | 76.27 | 38.46 | 38.91 | 37.35 | `FAIL` |
| 4 | **Chaitin SafeLine WAF CE 9.4.7 (`Max Strict Semantics + ACL`)** | **52.92** | 41.09 | 100.00 | 28.23 | 58.59 | `PASS` |
| 5 | **Wazuh (`Max Rules + FIM + Auditd + Active Response`)** | **46.70** | 32.66 | 69.23 | 22.14 | 91.53 | `CONDITIONAL` |
| Ref | **Baseline (`Clean Ubuntu HWE 7.0 WebStack`)** | **46.23** | 17.86 | 100.00 | 15.97 | 100.00 | `CONDITIONAL` |
| 6 | **CrowdSec (`Max Collections + Bouncers + AppSec WAF`)** | **36.58** | 44.56 | 0.00 | 28.38 | 72.37 | `FAIL` |

> **Versions-Progression (`6.2.0 → 6.2.1`):** Der Gesamt-Score steigt von **`86.16`** auf **`94.73 / 100 (PASS)`** (`+8,57`), getrieben durch die Kernel-BPF-LSM-Malware-Inode-Sperre (`hardred-malware`: `65,6 → 95,6`, Prevention-TPR `33,3 % → 100,0 %`) sowie Kernel Behavioral XDR (`hardred-endpoint`: `59,0 → 94,4`, Detection-TPR `53,3 % → 93,3 %`, Prevention-TPR `53,3 % → 100,0 %`, Schadensquote von `18,1 %` auf **`8,6 %`** halbiert) bei `0,0 %` Fehlalarmen.

### Direkter Domänen-Vergleich: GeDefense 6.2.1 vs. OSS Best-of-Breed-Stack

| Domäne | GeDefense 6.2.1 (Det / Prev / FPR / Score) | OSS Best-of-Breed (Det / Prev / FPR / Score) | Zentraler Laufzeit-Vorteil |
|---|---|---|---|
| `hardred-waf` | 100,0 % / 100,0 % / **0,0 %** / **100,0** | 100,0 % / 92,9 % / 12,5 % / **92,8** | Null Fehlalarme (`FAIL`-Gate beim OSS-Stack durch `12,50 %` WAF-Prot-FPR) |
| `hardred-netids` | 100,0 % / 100,0 % / 0,0 % / **98,3** | 100,0 % / 75,0 % / 0,0 % / **86,2** | Kinetic XDP blockt Velocity-Floods (`196/240`) & Portscans zuverlässig |
| `hardred-endpoint` | **93,3 %** / **100,0 %** / 0,0 % / **94,4** | 33,3 % / 50,0 % / 0,0 % / **51,9** | **Schadensquote `8,6 %` vs. OSS `100,0 %`** (OSS ließ Ransomware-AES/Storm & `memfd` durch) |
| `hardred-malware` | 100,0 % / 100,0 % / 0,0 % / **95,6** | 100,0 % / 100,0 % / 0,0 % / **96,7** | BPF-LSM `MALWARE_DENIED_INODES` + AES-256-GCM-Vault |
| `hardred-compliance` | 100,0 % / 86,0 % / 0,0 % / **86,0** | 100,0 % / 80,0 % / 0,0 % / **80,0** | Lynis Hardening Index **`71`** (OSS `65`, Baseline `63`) |

- **Gemessener System-Overhead (`GeDefense 6.2.1` vs. `OSS Best-of-Breed` vs. Clean Baseline):**
  - **GeDefense Linux 6.2.1:** `525,0` HTTP RPS (`14,07 ms` p50 · `23,65 ms` p95) · `86.682,7` Sysbench EPS · `211,8` FIO IOPS · **`88,4 MiB`** Security RSS · **`7,4 %`** Security CPU · Lynis `71`.
  - **OSS Best-of-Breed (`ModSec + Suricata + Tetragon + ClamAV`):** `452,4` HTTP RPS (`13,85 ms` p50 · `29,93 ms` p95) · `84.829,5` Sysbench EPS · `237,4` FIO IOPS · **`1.761,0 MiB`** Security RSS (`~20×` mehr RAM) · **`57,3 %`** Security CPU (`~13×` mehr CPU) · Lynis `65`.
  - **Chaitin SafeLine WAF CE 9.4.7 (Solo `07-safeline-max` & `OSS+SafeLine`):** `0,0 %` Fehlalarme (`PASS`-Gate, hebt `OSS+SafeLine` auf `59.28`), erreicht in `hardred-waf` aber nur **`79,0`** (`11/14` blockiert; `WAF-LFI-02` Double-Encoded, `WAF-XXE-01` & `WAF-SCAN-01` `sqlmap` + `/.env` gingen durch) bei **`1.040,5 MiB` RSS / `48,1 %` CPU** solo (`484,9` RPS) bzw. **`2.614,7 MiB` RSS / `60,6 %` CPU / `175,2` RPS (`67,45 ms` p95)** im Verbund.

### Adaptiver Multi-Stage-Benchmark (`VGT HardRed 1.2 / REDHARD ARES`)

| System | ARES Design Resilience | ARES Runtime Resilience | ARES Adaptive Resilience | Ketten unterbrochen | Ø Pre-Kill Damage | Multi-Seed Ø (3 Seeds × 3 Runden) | Fehlalarme |
|---|---:|---:|---:|---:|---:|---:|---:|
| **GeDefense Linux 6.2.1** | **78.40** | **96.68** | **93.46** | **36 / 36** | **11,1 %** | **93.64** (σ = `0,0918`) | **0** |
| **OSS Best-of-Breed + SafeLine WAF** | 58.20 | 56.25 | 61.33 | 27 / 36 | 100,0 % | 61.52 | 0 |
| **Chaitin SafeLine WAF CE 9.4.7** | 53.60 | 51.67 | 42.69 | 24 / 36 | 100,0 % | 42.88 | 0 |
| **Wazuh HIDS/SIEM** | 65.10 | 15.42 | 27.78 | 3 / 36 | 100,0 % | 27.96 | 3 |
| **CrowdSec IPS/CTI** | 59.80 | 51.67 | 42.25 | 24 / 36 | 100,0 % | 42.44 | 0 |

### 📂 Direkter Zugriff auf alle Testergebnisse im Repository

Alle vollständigen Scorecards, Einzeltest-Urteile (über alle 7 Contender), SARIF-Berichte, MITRE ATT&CK Layer, OCSF-Exporte und interaktiven HTML-Dashboards liegen direkt prüfbar im Repository:
- 📁 **[Benchmark-Ergebnisordner (`benchmarks/vgt-hardred-6.2.1/`)](benchmarks/vgt-hardred-6.2.1/)**
- 📄 **[Vollständiger Benchmark-Bericht (`FINAL_BENCHMARK_REPORT.md`)](benchmarks/vgt-hardred-6.2.1/FINAL_BENCHMARK_REPORT.md)** · **[Vergleichs-CSV](benchmarks/vgt-hardred-6.2.1/VGT_HardRed_Comparison.csv)** · **[Interaktives HTML-Dashboard](benchmarks/vgt-hardred-6.2.1/VGT_HardRed_Dashboard.html)**
- 🤖 **[REDHARD ARES Hybrid-Bericht](benchmarks/vgt-hardred-6.2.1/ares/FINAL_ARES_HYBRID_REPORT.md)** · **[ARES CSV](benchmarks/vgt-hardred-6.2.1/ares/VGT_HardRed_ARES_Comparison.csv)** · **[ARES HTML-Dashboard](benchmarks/vgt-hardred-6.2.1/ares/VGT_HardRed_ARES_Dashboard.html)**
- 🔎 **Contender-Rohdaten:** [`gedefense/`](benchmarks/vgt-hardred-6.2.1/gedefense/) · [`oss-safeline/`](benchmarks/vgt-hardred-6.2.1/oss-safeline/) · [`oss-stack/`](benchmarks/vgt-hardred-6.2.1/oss-stack/) · [`safeline/`](benchmarks/vgt-hardred-6.2.1/safeline/) · [`wazuh/`](benchmarks/vgt-hardred-6.2.1/wazuh/) · [`crowdsec/`](benchmarks/vgt-hardred-6.2.1/crowdsec/) · [`baseline/`](benchmarks/vgt-hardred-6.2.1/baseline/)

### ⚙️ Reproduktion des Benchmark-Profils (`Max-Hardness`)

Um dieses Evaluationsprofil auf einem Linux-Host nachzustellen (die Standardinstallation startet bewusst konservativ im `observe`-Modus und hält optionale Lockdowns deaktiviert):

1. **Kernel-LSM-Bootparameter:** Sicherstellen, dass `bpf` in `/sys/kernel/security/lsm` aktiv ist (Kernel-Cmdline `lsm=...,bpf` + Reboot), damit **Titan Exec Gate**, **LPE `socket_create`** und **Credential Guard `file_open`** aktiv im Kernel hängen.
2. **Release-Phase promoten:** Übergang `observe` → `canary` → **`enforce`** (`POST /api/v1/release/transition` mit `PROMOTE:CANARY` und `PROMOTE:ENFORCE`) und `release`-FIM-Baseline versiegeln (`POST /api/v1/fim/baseline`, `"scope": "release"`).
3. **Kern-Einstellungen der Module (`PUT /api/v1/settings/{module}`):**
   - `kinetic`: `enabled=true`, `enforcement_mode="block"`, `ip_threshold=20`, `velocity_limit=10`, `range_threshold=35`, `portscan_threshold=3`, `syn_threshold=15`, `syn_ack_ratio=3`, `auto_contain_single_ip=true`, `auto_contain_ipv4_subnet=true`, `auto_contain_ipv6_subnet=true`.
   - `l7`: `enabled=true`, `mode="block"`, `inline_enabled=true` (NGINX-`auth_request` / Edge-Socket eingebunden), `alert_score=30`, `block_score=70`, `sensitive_rate_per_minute=20`, `sensitive_rate_burst=5`, `client_rate_per_minute=180`, `client_rate_burst=40`, `tls_enabled=true`, `tls_anti_spoof=true`.
   - `xdr`: `enabled=true`, `network_sensor_enabled=true`, `behavior_enabled=true`, `alert_score=30`, `contain_score=60`, `kill_score=90`, `enabled_rule_modules=["baseline","command","lineage","masquerading","origin","threat-intel"]`, `advanced.malware_correlation=true`.
   - `titan` (FIM / Contraband): `mode="STRICT"`, `armed=true`, `auto_contain=true` (`POST /api/v1/titan/policy`).
   - `titan_exec` (6.2.0 ABI-2): `enabled=true`, **`mode="untrusted"`** (Global-Modus `4` — blockiert Nicht-root-/world-writable-Drop-Pfade ohne Systempakete zu beeinträchtigen), `require_ctime=true`.
4. **V6- & Modul-A–E-Härtung:**
   - `worker_guard`: `enabled=true`, `strict_exec=true`, `strict_mmap=true`, `auto_apply_strict=true`, `correlate_peers=true`, `storm_threshold=3`.
   - `tls_sensor`: `enabled=true`, Ziel-Interfaces + `"lo"`, `ports=[443,8443,9843]`, `alert_only=false`.
   - `lpe_guard`: `enabled=true`, Deny für `AF_PACKET`/`AF_TIPC`/`AF_VSOCK`/`SCTP`/`DCCP`/`RDS`, `styx_profile=true`, `enforce_aslr=true`, `block_lpe_modules=true` (`POST /api/v1/lpe-guard/apply`).
   - `styx`: `enabled=true`, global `mode="monitor"`, `log_flows=true`, zusätzlich **`per_cell` `mode="enforce"`** auf der Web-Worker-Cgroup (z. B. `php8.3-fpm.service` über symbolisches `cgroup_path`), um unautorisierten C2-/Egress-Traffic direkt im Kernel zu droppen.
   - `parser_cells`: `enabled=true`, `burn_on_incident=true`, `incident_score=60`; `lockdown`: `enabled=true`, `auto_arm=true`, `allow_loopback=true`, `drop_loopback=false`, `network_lockdown=true`, `freeze_processes=true`, `freeze_brokers=true` (`POST /api/v1/lockdown/arm`, `mode="locked"`); `threat_intel`: `enabled=true`, `auto_sync=true`.
5. **CIS- / Lynis-Härtungsprofil:** Transaktionales Sysctl-Profil **`astraeaos-cis-l1`** über `/api/v1/transactions/preview` → `/apply` (`type: "hardening.sysctl-profile"`) aktivieren und optional den expliziten Userland-Helper `gedefense-cis-baseline --apply` (SSHD-Drop-in, `UMASK 027`, Banner, Modul-Blacklist, Auditd-Basis) ausführen.

> [!NOTE]
> **Umgebungshinweis & ehrliche Entwicklungsnotiz (`6.2.0 → 6.2.1`):** Benchmark-Werte verändern sich abhängig von Kernel-Version und aktiven LSM-Boot-Flags (`lsm=...,bpf`), CPU-/I-O-Leistung, Netzwerktopologie, individuellen Workload-Allowlists (etwa ausgehenden Zahlungs-/API-Zielen bei PHP-/Node-Workloads) sowie der eingesetzten Test-Suite. Konkrete Lücken aus den ersten Testläufen wurden über `6.2.0` und `6.2.1` sauber im Kern behoben: neben der `6.2.0`-Basis ergänzt `6.2.1` die Kernel-BPF-LSM-Malware-Inode-Sperre (`MALWARE_DENIED_INODES` + `CORE_QUARANTINE_ALLOWED_ROOTS`), tiefes Kernel Behavioral XDR (`EXEC_ARGV_EVENTS`, `KERNEL_PROBE_EVENTS`, `getname_flags`-Kretprobe und Multi-CPU-Tracepoints in `aya`), feinjustierte Ransomware-Schwellen (`15→6` / `25→18`) mit PPID-isolierter Service-Pool-Abwehr (`RANSOM_TRUST_POOL_METADATA`), StyX-Non-External-Flow-Filterung (`isIgnoredNonExternalFlow`) und asynchrones `ChronosScanner`-Scanning.

---

<img width="1536" height="1024" alt="GeDefense_ Real Security, Many Feathers" src="https://github.com/user-attachments/assets/dc56735e-b2b2-45c9-a363-97554a92ae0a" />

## 🌐 Das GeDefense-Universum

GeDefense ist eine lokal-first Security-Fabric – für Linux, Windows, Android und WordPress. Alle Schwesterprojekte teilen dieselbe Philosophie: lokale Kontrolle, ehrliche Sichtbarkeit, keine stille Telemetrie.

| Projekt | Schwerpunkt |
| --- | --- |
| [![Android TV](https://img.shields.io/badge/Android_TV-3DDC84?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense_androidtv) **GeDefense TV** | Sicherheitskonsole für Android TV / Google TV: Loopback-VPN, Traffic-Map, XDR-Light und reversibles Kinetic-Lite-Containment. |
| [![Linux](https://img.shields.io/badge/Linux-D4AF37?style=flat-square&logo=linux&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense) **GeDefense Linux** *(dieses Repository)* | Kernel-nahe Netzwerkverteidigung: eBPF/XDP-Durchsetzung, L7-WAF, Host-XDR mit signierter Evidenz und reversible Härtung (Rust/Go, vollständig lokal). |
| [![Windows](https://img.shields.io/badge/Windows-8B5CF6?style=flat-square&logo=windows&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewin) **GeDefense Windows** | Lokale, souveräne Windows-11-Sicherheitskonsole: Defender/ASR/WFP/App Control, Härtung, MHX EDR/XDR, lokale Threat Intelligence und HMAC-verkettete Evidenz. |
| [![Android](https://img.shields.io/badge/Android-22D3EE?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefenseandroid) **GeDefense Android** | Native Android-Sicherheitsplattform: lokale VPN-Durchsetzung, Endpoint-Telemetrie, XDR/EDR-Korrelation, Threat Intelligence, App-Risikoanalyse und verschlüsselte Evidenz. |
| [![WordPress](https://img.shields.io/badge/WordPress-1F8FFF?style=flat-square&logo=wordpress&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewp) **GeDefense WordPress** | AGPL-3.0-Open-Core-Suite für WordPress: ZEUS-WAF, AEGIS-Deep-Packet-Inspection, TRINITY-XDR, ThroneGuard-Lockdown und HADES-Admin-Cloaking. |

---

## Drittanbieter-Lizenzen und Datenherkunft

GeDefense enthält Drittanbieter-Komponenten und öffentliche Datensätze. Deren
Lizenzen sind von der AGPL-3.0-only-Lizenz von GeDefense selbst getrennt.
Vollständige Texte und Details stehen in
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).

| Komponente / Daten | Originalquelle | Lizenz |
|---|---|---|
| **jsVectorMap 1.7.0** — eingebundene SVG-Weltkarte (`world-merc.js`) und Dashboard-Kartenbibliothek | [themustafaomar/jsvectormap](https://github.com/themustafaomar/jsvectormap) · [world-merc.js 1.7.0](https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/maps/world-merc.js) | **MIT**, Copyright © 2020 Mustafa Omar ([Lizenz](https://github.com/themustafaomar/jsvectormap/blob/main/LICENSE)) |
| **IP-to-Country-/IP-to-ASN-Daten** — transformiert in die Offline-Datei `geoip.csv` | [iplocate/ip-address-databases](https://github.com/iplocate/ip-address-databases) | **CC BY-SA 4.0** ([Lizenz](https://creativecommons.org/licenses/by-sa/4.0/)); Namensnennung: *IP-to-Country and IP-to-ASN databases by iplocate, licensed CC BY-SA 4.0; changes were made by VisionGaia Technology for GeDefense.* Die transformierte Datenbank wird unter denselben CC-BY-SA-4.0-Bedingungen weitergegeben. |
| **DB-IP Lite** — City-GeoIP-Daten für den Updater | [db-ip.com](https://db-ip.com/) | **CC BY 4.0**, Namensnennung erforderlich |
| **Origin-ASN-Daten** — für den Updater | [sapics/ip-location-db](https://github.com/sapics/ip-location-db) | **PDDL** |
| **Qt 6** — Laufzeit und Build-Abhängigkeiten des Desktop-Tray-Clients | [qt.io](https://www.qt.io/) | **LGPL-3.0 / kommerzielle Qt-Bedingungen**; der Tray-Client linkt dynamisch gegen die Qt-Pakete der Distribution |

Kein Drittanbieter unterstützt oder sponsert GeDefense. Das Dashboard lädt diese
Assets lokal; es gibt keinen Laufzeit-CDN- oder Cloud-Lookup.


---

## 🏛️ Sicherheitsarchitektur & Technische Spezifikation

> [!IMPORTANT]
> **Für Sicherheitsforscher, Systemarchitekten & Auditoren:**
> GeDefense führt eine vollständige, formale Spezifikation der technischen Architektur, des Vertrauensgrenzenmodells und des Symboldatenbaums:
> 
> ### ➔ [📘 ARCHITECTURE.md — Vollständige technische Architektur & Spezifikation](ARCHITECTURE.md)
> 
> *Über 4.400 Zeilen zur Spezifikation des 7-stufigen Architekturbaums, der Kernel-eBPF/XDP-Data-Plane, der Go-Control-Plane, des typisierten Rust-Response-Cores, der nativen L7-WAF-Engine, des kryptografischen Evidenz-Ledgers und der reversiblen Härtungs-Engine.*

---

## 🧪 Verify Yourself — Vollständige Test-Suite & Selbstaudit-Leitfaden

> [!TIP]
> **„Don't Trust, Verify“ — Maximale Transparenz & Reproduzierbarkeit**
> GeDefense wurde für Zero-Trust-Umgebungen entwickelt. Jedes Sicherheitsversprechen, jede Vertrauensgrenze, jeder Parser, jede kryptografische Invariante und jeder Kernel-Wire-Speed-Filter ist durch eine automatisierte Test-Suite abgesichert. Sie können alle **634+ nativen Testfunktionen** und **19 Sicherheits-Audit-Gates** mit einem einzigen Befehl lokal selbst durchtesten.

### 📊 Übersicht der Test-Suites & Testabdeckung

| Test-Suite / Komponente | Pfad / Datei | Tests / Szenarien | Getestete Fähigkeiten & Zusicherungen | Direkter Ausführungsbefehl |
| :--- | :--- | :---: | :--- | :--- |
| **Control Plane Unit & Integration** | [`control/*_test.go`](control/) | **574 Tests**<br>*(108 Dateien + 25 Subtests)* | XDR-DAG-Korrelation, L7-WAF Multi-Pass-Dekodierung, FIM SHA-256-Baselines, Fail-Closed Release-Gates, duale Ledger-Rotation (90%-Schwelle), Self-Artifact-Updates | `cd control && go test -v ./...` |
| **Sicherheits-Fuzzing-Suite** | [`control/*fuzz_test.go`](control/) | **8 Fuzz-Targets** | Speichersicherheit & Panik-Resistenz bei fehlerhaften Eingaben: L7-Normalisierer, TLS ClientHello, verschlüsselte Umschläge, Core-IPC-Antworten, `/proc/stat` | `make fuzz-smoke` |
| **Gateway & Perimeter-Authentifizierung** | [`gateway/*_test.go`](gateway/) | **28 Tests**<br>*(6 Dateien)* | TLS 1.3 Post-Quantum ML-KEM-Kurven, Argon2id-Passwortprüfung, `__Host-`-Cookie-Isolation, CSRF-Synchronizer-Tokens, Origin-Scrubbing | `cd gateway && go test -v ./...` |
| **Rust Kernel-Protokoll & Data Plane** | [`rust/gedefense-common`](rust/gedefense-common/) | **6 Tests** | Zero-Copy-Netzwerk-Header-Parsing, IPv4/IPv6 VLAN/QinQ-Grenzen, Wire-Event-Dekoder | `cargo test --locked --manifest-path rust/Cargo.toml -p gedefense-common` |
| **Rust Privileged Response Core** | [`rust/gedefense-core`](rust/gedefense-core/) | **18 Tests** | Replay-Guard-LRU/Eviction, Sysctl Compare-and-Set-Vertrag, Streaming-Malware-Scanner (Polyglot/EICAR), AES-256-GCM Quarantäne-Tresor | `cargo test --locked --manifest-path rust/Cargo.toml -p gedefense-core` |
| **Automatisierter Sicherheitsaudit** | [`scripts/security-audit.sh`](scripts/security-audit.sh) | **19 Audit-Gates** | Keine unsicheren DOM-Sinks (`innerHTML`, `eval`), strikte CSP-Validierung, I18N 4-Sprachen-Schlüsselparität, Socket-/Dateiberechtigungen (`0700`/`0600`) | `bash scripts/security-audit.sh` |
| **Kinetic Wire-Speed Lastakzeptanz** | [`scripts/validate-kinetic-release-candidate.sh`](scripts/validate-kinetic-release-candidate.sh) | **Suite** | Ingress-Burst-Dauertests, gleitende Telemetriefenster, LPM-Trie Drop-Benchmark | `bash scripts/validate-kinetic-release-candidate.sh` |
| **Linux-Distributionsintegration** | [`scripts/validate-distro-integration.sh`](scripts/validate-distro-integration.sh) | **Suite** | Multi-Distributions-Prüfung (Systemd-Verträge für Arch, Debian, Fedora, SUSE) | `bash scripts/validate-distro-integration.sh` |
| **Quarantäne-DAC & Tresorberechtigungen** | [`scripts/validate-quarantine-dac.sh`](scripts/validate-quarantine-dac.sh) | **Suite** | Prüfung auf Root-Exklusivrechte, Non-Executable-Flags, Verzeichnisausbruchsfallen | `bash scripts/validate-quarantine-dac.sh` |
| **Systemd-Sandbox-Validierung** | [`scripts/validate-systemd.sh`](scripts/validate-systemd.sh) | **Suite** | Prüfung auf `DynamicUser`, `ProtectSystem=strict` und Capability-Dropping aller Services | `bash scripts/validate-systemd.sh` |
| **Viersprachige I18N-Parität** | [`scripts/validate-i18n.mjs`](scripts/validate-i18n.mjs) | **Suite** | 100%ige Übersetzungsschlüssel-Synchronisation für DE, EN, RU und ZH-CN | `node scripts/validate-i18n.mjs` |

### ⚡ Schnellstart: Tests lokal auf dem eigenen System ausführen

```bash
# 1. Alle Go-Tests, statische Analysen, JS-Syntax-Checks & Sicherheitsaudits ausführen
make test

# 2. Go-Tests mit aktivem Race-Detector durchlaufen lassen
make test-race

# 3. Alle nativen Rust-Tests (Kernel Common & Response Core) ausführen
cargo test --locked --manifest-path rust/Cargo.toml -p gedefense-common -p gedefense-core

# 4. Die 8 Go-Sicherheits-Fuzzing-Tests starten
make fuzz-smoke

# 5. Den vollständigen statischen Sicherheits-Audit durchführen
bash scripts/security-audit.sh

# 6. Die vollständige End-to-End-Repository-Validierung starten
bash scripts/validate.sh
```

> 📖 **Formaler Beta-Testplan:** Die vollständige Matrix für operative Testphasen (Observe, Canary, Enforce, AstraeaOS) finden Sie in [**BETA-TEST-PLAN.md**](BETA-TEST-PLAN.md).

---

### Übersicht: 7-stufiges souveränes Verteidigungsgewebe

```text
1. PUBLIC ACCESS GATEWAY       Go · Port 9843 (TLS 1.3, ML-KEM PQ-Hybrid, Argon2id, CSRF-Sync-Tokens)
2. COMMAND CENTER DASHBOARD   ESNext / Vanilla JS / Natives CSS · 0 Abhängigkeiten · CSP-gehärtet
3. CONTROL PLANE               Go · Port 9844 (Nur Loopback · XDR, L7-WAF, FIM, Evidenz-Ledger, Fälle)
4. PRIVILEGED RESPONSE CORE   Rust · /run/vgt-gedefense/core.sock (HMAC VGT3, pidfd_open, sysctl CAS, fanotify)
5. KERNEL DATA PLANE           Rust no_std eBPF/XDP + cgroup-skb + LSM (LPM-Trie 250k Regeln, RingBuf EDR)
6. INTEGRATION FABRIC          Universelles Linux (APT/DNF/pacman/Zypper) · AstraeaOS Native Ring-1 Cells
7. RELEASE ENGINEERING         Toolchains.lock · Reproduzierbare Builds · Kryptografische Spiegel-Manifeste
```

### Kern-Sicherheitsinvarianten
- **Keine Cloud-Control-Plane:** Threat Intelligence, Verhaltens-Baselines, operative Schlüssel und forensische Evidenzen verbleiben zu 100% auf dem lokalen Host.
- **Kernel-Speed Data Plane:** Eingehende Netzwerkangriffe werden auf Treiberebene via Rust eBPF/XDP verworfen, noch vor der Socket-Puffer-Allokation (`sk_buff`).
- **Native L7-Ebene (Nur Go-Standardbibliothek):** Begrenzte HTTP-Normalisierung, Anti-Evasions-Dekodierung und RE2-Regex-Scans ohne Drittanbieter-Abhängigkeiten, ohne CGO und ohne Skript-Runtimes.
- **Web-Evidenz-Isolationsbarriere:** Web-Befunde tragen `AlertOnly: true` (`ResponseScore: 0`). Ein Web-Tier-Befund kann niemals autonom Prozesse auf Host-Ebene beenden (`SIGKILL`/`SIGSTOP`); destruktive Eindämmung erfordert zwingend unabhängige Host-/Kernel-Evidenz.
- **Kryptografischer Evidenz-Ledger:** Manipulationssichere, monotone Sequenz mit Vorgänger-Hashing (`AES-256-GCM` + `Ed25519`).
- **Reversible Sysctl-Härtung:** Atomares Compare-and-Set mit Kernel-Rücklesung und automatischem Rollback bei partiellem Fehlschlag.

---

## 🔍 Was ist VGT GeDefense?

GeDefense ist kein einfacher Firewall-Regelmanager. Es ist ein **lokales, souveränes Linux-Sicherheitsgewebe** — kernelnahe Netzwerkverteidigung, Host-XDR, verschlüsselter Evidenz-Ledger, reversible Systemhärtung und optionale AstraeaOS-native Isolation in einem System, betrieben ohne jede Cloud-Control-Plane.

```
Herkömmliche Linux-Sicherheits-Stacks:
  Unkoordinierte Tools (iptables + auditd + fail2ban)  → kein geteilter Status
  Konfiguration als Vertrauensbasis                     → eigene Regeln erzwingen sofort
  Keine Evidenzkette                                   → Vorfälle nicht beweisbar
  Kein Rollback                                        → Härtungsänderungen irreversibel
  Cloud-SIEM / Control-Plane                           → Daten verlassen den Host

VGT GeDefense:
  Rust eBPF/XDP Data Plane                → kernelnah, bis zu 250.000 Blockeinträge
  Go Control Plane (XDR, Policy, FIM)     → getrennte Vertrauensdomäne, nur Loopback
  Rust Response Core (pidfd, SIGKILL)     → Broker-geprüft vor jedem Kill-Signal
  Getrennte Vertrauensdomänen             → Public Gateway · Control · Core · Data Plane
  Ed25519-signierter Evidenz-Ledger       → monotone Sequenz + Vorgänger-Hash
  AES-256-GCM geschützte FIM-Baselines    → Fail-closed bei Integritätsverletzung
  Reversible Härtung                      → Compare-and-Set, atomare Persistenz, Auto-Rollback
  Verschlüsselter Response Vault (AES-GCM)→ Quarantäne mit SHA-256-Identität
  Keine Cloud-Control-Plane               → sensibler Zustand verlässt niemals den Host
  Universelles Linux                      → APT · DNF/YUM · pacman · Zypper Integration
  AstraeaOS-nativ                         → verifizierter Quellspiegel, identische Kette
```

Ein einzelner Regex-, Feed-, Verhaltens- oder Maskierungs-Treffer **kann niemals eine Prozessbeendigung autorisieren**. Enforce erfordert mindestens zwei unabhängige autorisierte Kategorien, objektive Broker-Evidenz und einen nicht-degradierten Systemzustand.

### 🛡️ Vollständiger V6.2.1-Funktionsumfang & Module A–E

Alle Subsysteme teilen sich getrennte Vertrauensdomänen, REST-APIs und Dashboard-Panels. In `observe`/`canary` bleibt aktives V6-Blocking deaktiviert; beim Wechsel auf `enforce` greift automatisch die sichere Basis (`styx=monitor`, `titan_exec=contain`, `parser_cells=enabled`), während strengere Stufen (**Emergency Lockdown**, **Witness**, `titan_exec=untrusted`, Per-Cell-StyX `enforce` und CIS-Userland-Baseline) bewusste Operator-Entscheidungen bleiben:

- **Module A–E (Web- & Perimeter-Stack):**
  - **Modul A — Web-Exposure & Posture:** Erkennt Web-Daemons read-only über `/proc/<pid>/exe` ELF-`.rodata` (ohne `os/exec`), parst NGINX-/Apache-Listener, führt begrenzte Loopback-ALPN-Probes durch und meldet CVEs nur bei realer Erreichbarkeit.
  - **Modul B — Worker-Integritätswächter:** Überwacht registrierte Web-Worker (`signal:signal_deliver`-Tracepoint + Netlink-Fallback), eskaliert ≥ 3 tödliche Signale in 60 s (`XDR.WORKER_CRASH_STORM`) und sperrt auf Opt-in Worker-Cgroups (`JIT_ALLOW = 0`) unter Schutz von Master-/Control-Units.
  - **Modul C — TLS-/ALPN-Sensor & h2-Control-Storm-Budget:** Passive `AF_PACKET`-Erfassung über den getrennten `gedefense-capture-helper.service` mit Kernel-`INET_DIAG`-Zählern, um HTTP/2-Control-Storms sauber von großen Uploads zu trennen.
  - **Modul D — LPE-Kill-Chain-Blocker:** `socket_create`-BPF-LSM blockiert `AF_PACKET`, `AF_TIPC`, `AF_VSOCK`, `SCTP`, `DCCP` und `RDS` in Web-Worker-Cgroups inklusive ASLR- und Modul-Blacklist-Basis.
  - **Modul E — Memory-Safe Edge Terminator:** Optionaler Go-`crypto/tls`- + `net/http`-Terminator mit harten RFC-9113-Limits, struktureller Inline-WAF (SQL-Kanonik, Secret-Config-Scanner, Raw-Body-Prüfung auf `POST`/`PUT`, `780 KB–1,5 MB`-Fast-Pass, deterministisches `429 + Retry-After`) und HTTP/1.1-Upstream.
- **Kernel- & Host-XDR (Punkte 1–5 + V6.2-Max-Härtung):**
  - **Titan Exec Gate (ABI-2) & GeDefense Titan Contraband-Schutz:** Erzwingt `bprm_check_security` / `mmap_file(PROT_EXEC)` im Modus `contain` bzw. global `untrusted` (Modus `4`) gegen Nicht-root-/world-writable-Drop-Pfade (`memfd_create`, `/tmp`, `/dev/shm`), während GeDefense Titan Dateimanipulationen per begrenztem Inotify, FIM-Baselines und lokaler `dpkg`/`pacman`-Paketeigentümerschaft (`AUTHORIZED` / `TOLERATED` / `UNEXPECTED` / `COMPROMISED`) bewertet — strikt ohne Akteurs-Attribution und mit reversibler AES-256-GCM-Quarantäne.
  - **eBPF-Ransomware-Sensor & Process-Tree-Kill:** Kprobes auf `vfs_write`/`vfs_rename`/`vfs_unlink` erkennen Entropy-Bursts und Rename-Storms; der Rust-Core friert die PGID per `100 ms`-Tick reversibel mit `SIGSTOP` ein (Paket-/Build-Tools wie `apt`, `dpkg`, `tar`, `cargo` bleiben geschützt), und Control eskaliert `pidfd`-verifiziert via `XDR_KILL_TREE` oder entfriert per `GROUP_CONT`.
  - **Asynchroner On-Write-Malware- & Archiv-Scanner:** `FAN_CLOSE_WRITE`-Sensor auf `/tmp`, `/var/tmp`, `/dev/shm` und `/var/www` (`PrivateTmp=false`, enge Pfadrechte, begrenzte rekursive ZIP/GZIP/TAR-Prüfung bis Tiefe 8 / `16 MiB` Probe-Budget) mit fd-verankerter Quarantäne.
  - **BPF-LSM Credential Guard:** `file_open`-Hook schützt `/etc/shadow`, `/etc/gshadow` und Secret-Stores (Allowlist u. a. für `sshd`, `sudo`, `su`, `login`, `cron`, `passwd`, `useradd`/`usermod`/`groupadd`), ohne unbewaffnet Login-Pfade zu blockieren.
  - **StyX Egress & Beacon-Erkennung + 16-MiB-Flow-Telemetrie:** Symbolische `cgroup_path`-Identitäten mit cgroup2-Inode-Auflösung bei Reboot/Restart (`degraded` bei Drift statt leisem Fail-Open), `16 MiB` `FLOW_EVENTS`-Ring und getrennte Anzeige von `enforcement_active` vs. `telemetry_state`.
  - **Ephemere Parser-Zellen (`gedefense-cell-helper.service`), Witness & Emergency Lockdown:** Isolierte Einweg-Sandboxes (`VGTGC2`), off-host Ed25519-Checkpoints, XDP/TC-Notaus und Composite-BadUSB-Filter (`HID+Storage`/`HID+CDC`).
- **Geführter Setup-Wizard (`00`–`08`) & Offline-`AGENTS.md`-Workflow:** Integrierte Checkliste im Dashboard plus Read-only-first-`AGENTS.md` für lokale CLI-Agenten über SSH (`POST /api/v1/settings/{module}/preview` → `PUT`) — bewusst ohne Remote-KI-API.

### 💻 Desktop-PC / Workstation vs. 🖥️ Linux-Server — Was V6.2 schützt

| Einsatzszenario | Zentrale abgewehrte Bedrohungen | Aktive Kontrollen unter `enforce` |
|---|---|---|
| **Linux-PC / Workstation** | Zero-Click-Parser-Exploits, BadUSB-Composite-Implantate, Secret-Broker-Dumps, dateilose Payloads (`memfd`/`PROT_EXEC`), stille C2-Callbacks | **Parser-Zellen** isolieren unsichere Parser; **Lockdown** blockt Composite-BadUSB & friert Broker ein; **StyX (`monitor`)** meldet Beacons; **Titan Exec (`contain`/`untrusted`)** blockt/auditiert Drop-Pfad-Execs |
| **Linux-Server (Web / API / Compute)** | L7-SQLi/RCE/Webshell-Ingress, ausgehende C2-/Exfiltration aus Web-Cgroups, `/tmp`-/`/var/www`-Drops, Ransomware-Bursts, `/etc/shadow`-Zugriffe | **L7 Edge/WAF + Kinetic XDP** droppen Netz-/HTTP-Angriffe; **StyX (`per_cell enforce`)** blockt kompromittierten Worker-Egress; **Titan Exec + Ransomware + On-Write + Credential Guard** stoppen Post-Exploitation; **Witness** ankert Evidenz extern |

> [!WARNING]
> **RELEASE- & QUALIFIKATIONSSTATUS (Version 6.2.1 / V6).**  
> GeDefense V6 befindet sich in aktiver Weiterentwicklung für Test- und Qualifizierungsumgebungen. Automatisierte Gates prüfen Build-Provenance, Ed25519-Signaturen, Go-/Rust-Suites und statische Sicherheitsinvarianten; externe Vertrauensanker (öffentliche CA-Signatur, RFC3161-Zeitstempel, CRL/OCSP, Feed-Signatur-PKI) sowie zielkernel-spezifische Verifier-/NIC-XDP-Tests bleiben Host-Qualifikationsschritte. Bitte vor produktivem `enforce`-Einsatz [SECURITY.md](SECURITY.md), [RELEASE-NOTES.md](RELEASE-NOTES.md) und [CHANGELOG.md](CHANGELOG.md) prüfen.

---

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/1f5cf6ae-ee59-498d-9c5b-e06e8efc9ef2" />


## 🏛️ Architektur

```
┌──────────────────────────────────────────────────────────────┐
│                    PUBLIC ACCESS GATEWAY                      │
│   Go · TLS 1.3 · Argon2id · Host/Origin/CSRF · Session       │
│   unprivilegiert · Port 9843 (konfigurierbar 1024–65535)     │
├──────────────────────────────────────────────────────────────┤
│                      CONTROL PLANE                            │
│   Go · XDR · Policy · Telemetrie · FIM · Evidenz · Fälle     │
│   Benutzer: gedefense · nur Loopback (TCP 9844)              │
├──────────────────────────────────────────────────────────────┤
│                      RESPONSE CORE                            │
│   Rust · VGT3 IPC · pidfd · Quarantäne · Sysctl-Mutationen   │
│   UID 0 · Capability Bounding · HMAC-authentifizierte IPC    │
│   /run/vgt-gedefense/core.sock                               │
├──────────────────────────────────────────────────────────────┤
│                       DATA PLANE                              │
│   eBPF/XDP · IPv4/IPv6 · LPM Allow-/Blocklisten am Interface │
│   Kernel/XDP · bis zu 250.000 Blockeinträge                  │
└──────────────────────────────────────────────────────────────┘
```

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/0712a990-f3ad-4b4a-8d18-8e0a60395fe1" />


### Trennung der Vertrauensdomänen

| Domäne | Rolle | Privilegien |
|---|---|---|
| **Public Gateway** | TLS 1.3, Argon2id, Host/Origin/CSRF, Sitzungs-Auth | Unprivilegiert |
| **Control Plane** | XDR, Policy, Telemetrie, FIM, Evidenz, Fälle, Dashboard | Benutzer `gedefense` |
| **Response Core** | XDP-Maps, pidfd-Reaktion, Quarantäne, typisierte Sysctl-Mutationen | UID 0, Capability Bounding |
| **Data Plane** | IPv4/IPv6-Parsing, LPM Allow-/Blocklisten am Interface | Kernel/XDP |

### Bereitstellungsmodi

**Universelles Linux** — Ein-Klick-Installation auf x86_64 systemd Linux mit APT, DNF/YUM, pacman oder Zypper. Rust Core und eBPF werden für den Zielkernel und die Netzwerkkarte kompiliert und vor der atomaren Aktivierung verifiziert.

**AstraeaOS-nativ** — Identische Kern-Binärdateien, natives Provisioning, AstraeaOS-Härtungsprofil, Boot-Trust-Evidenz und optionale Gaia Cells-Integration. GeDefense ist die **einzige Sicherheitsautorität** in AstraeaOS. Sentinel dient ausschließlich als Migrations- und Auditquelle — kein konkurrierender Laufzeit-Daemon.

---

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/57feccc5-75ab-46a1-a575-3a5ec3402087" />


## 🛡️ Verteidigungsgewebe

### Netzwerkverteidigung (Rust eBPF/XDP)

| Funktion | Detail |
|---|---|
| **Data Plane** | Rust eBPF/XDP — natives XDP mit Generic-XDP-Fallback |
| **Protokollabdeckung** | IPv4 und IPv6 |
| **Matching** | LPM Tries — Longest Prefix Match |
| **Kapazität** | Bis zu 250.000 Blockeinträge |
| **Management-Allowlist** | Wird vor der Blockliste angewendet — Management-Zugriff bleibt stets erhalten |
| **CIDR-Regeln** | Signiert mit TTL |
| **Feed Auto-Apply** | Standardmäßig deaktiviert — öffentliche Feeds erfordern explizite Betreiberautorisierung |
| **Leer-Verifikation** | Autoritative `VERIFY_EMPTY`-Prüfung — keine stillen Restregeln |

### Host-XDR

| Funktion | Detail |
|---|---|
| **Signale** | Prozess, Befehl, Abstammung, Herkunft, Maskierung, Netzwerk, Threat Intel |
| **Profile** | Adaptiv, kardinalitätsbegrenzt pro Prozess |
| **Benutzerdefinierte Regeln** | RE2-Regex — strikt Alert-only, niemals Auto-Enforce |
| **Multi-Signal-Gates** | Evidenzschranken vor jeder Eskalation erforderlich |
| **PID-Identität** | PID + pidfd-Bindung — immun gegen PID-Wiederverwendung |
| **Canary-Reaktion** | Evidenzgeprüftes SIGSTOP |
| **Enforce-Reaktion** | Ausschließlich Broker-geprüftes SIGKILL |

**XDR-Standardgrenzen**

| Parameter | Wert |
|---|---|
| Prozess-Scan-Intervall | 750 ms |
| Netzwerk- / Integritätsprüfung | 3 s / 3 s |
| Alert- / Contain- / Kill-Schwellenwert | 40 / 80 / 120 |
| Worker / Warteschlange | 4 / 2.048 |
| Auswertungen pro Scan | 4.096 |
| Vorfalls-Log-Obergrenze | 64 MiB |

### Evidenz & Integrität

| Funktion | Detail |
|---|---|
| **Evidenz-Ledger** | Verschlüsselt + Ed25519-signiert |
| **Kettenstruktur** | Monotone Sequenz + Vorgänger-Hash |
| **Kürzungs-Schutz** | Separater Head-Checkpoint |
| **FIM-Baselines** | AES-GCM geschützt |
| **Traversierung** | Begrenzt + Streaming SHA-256 |
| **Sicherheitsprüfungen** | Race-, Symlink- und Modus-Verifikation |
| **Integritätsverletzung** | Fail-closed — keine stille Degradierung |

### Fälle & Transaktionen

| Funktion | Detail |
|---|---|
| **Fallkorrelation** | Verschlüsselte Fallkontexte |
| **Wiederauftreten** | Wiederauftretens-Handling mit Ledger-Verpflichtung |
| **Härtungsablauf** | Vorschau → Autorisieren → Anwenden |
| **Auditablauf** | Verifizieren → Auditieren → Zurücksetzen |
| **Start** | Abstimmung — Drift-Quarantäne statt blindem Überschreiben |

---

## 🔒 Betriebssicherheit — Promotions-Gates

```
Observe ──→ Canary ──→ Enforce
   │            │           │
   │       Evidenz-      Signierte CIDR
   │       geprüftes     + Allowlist
   │       SIGSTOP        Sync
   │
 XDP aktiv, keine Blockregel
 verifizierter leerer Kernelzustand
```

| Zustand | Netzwerk | Prozessreaktion | Freigabebedingung |
|---|---|---|---|
| **Observe** | XDP aktiv, keine Blockregel | Aufzeichnung | Verifizierter leerer Kernelzustand |
| **Canary** | Fortgesetzte Beobachtung | Evidenzgeprüftes SIGSTOP | Policy-, Soak- und Health-Gates |
| **Enforce** | Signierte CIDR-Regeln | Broker-geprüftes SIGKILL | Synchronisierte Management-Allowlist |
| **Degraded** | Fail-safe / unbestätigt | Aktive Reaktion ausgesetzt | Sichtbare Wiederherstellung erforderlich |

**Not-Aus-Sequenz:** Reaktion deaktivieren → Blockregeln entfernen → authentifiziertes `VERIFY_EMPTY` → signierte Observe-Policy persistieren → erst dann: verified-empty. Kein Zwischenfehler wird als sicher gemeldet.

---

## 🔐 Kryptografie

| Zweck | Methode | Profil |
|---|---|---|
| **Betreiber-Passwort** | Argon2id | 64 MiB · t=3 · p=1 · 128-Bit-Salt · 256-Bit-Output |
| **Control ↔ Core IPC** | HMAC-SHA-256 | 32-Byte-Schlüssel · Zeitfenster · Nonce · Replay-Cache · SO_PEERCRED |
| **Operativer Speicher** | AES-256-GCM | Zufällige Nonces · zweckgetrennte Unterschlüssel · AAD-Bindung |
| **Policy / Evidenz** | Ed25519 | Lokales Signieren und Verifizieren |
| **Inhaltsidentität** | SHA-256 | Streaming-Hash mit Identitäts-Recheck |
| **Public Gateway** | TLS 1.3 | Lokales oder bereitgestelltes Zertifikat |

AAD-Kontext: Schema · Knoten · Zweck · kanonischer Pfad · Sequenz.
Legacy PBKDF2 wird nur für Migration akzeptiert — wird bei erfolgreicher Anmeldung atomar auf Argon2id aktualisiert.

### Browser- & API-Härtung

| Maßnahme | Status |
|---|---|
| Keine CDN-, Tracker- oder Webfont-Abhängigkeiten | ✓ |
| Keine dynamischen HTML-Sinks oder eval | ✓ |
| Strikte CSP und Framing-Verbot | ✓ |
| Synchronizer CSRF + exakte Origin-Prüfung | ✓ |
| Secure, HttpOnly, SameSite=Strict | ✓ |
| Serverseitige Bearer-Injektion | ✓ |
| Request-ID, TTL und Replay-Schutz | ✓ |
| HTTPS-Feeds mit DNS-/SSRF-Schutz | ✓ |
| Native L7/AppSec-Ebene mit begrenzter Normalisierung | ✓ |
| L7-Implementierung fügt null Go-/Laufzeit-Abhängigkeiten hinzu | ✓ |
| Keine Befehlsausführung zur Laufzeit in Go-Diensten | ✓ |
| Backend ausschließlich auf Loopback | ✓ |

**Sensibler Zustand und Schlüssel verlassen niemals den geschützten Host.**

---

## 🔧 Reversible Härtung

Profile: `Generic Linux Server` und `AstraeaOS Workstation` — feste Key/Value-Allowlist.

Kernelwerte werden per Compare-and-Set geändert, zurückgelesen und atomar in `/etc/sysctl.d/90-vgt-gedefense.conf` persistiert.

Der Rust Core verfügt über **keine generische Shell-, Dateisystem- oder Sysctl-Schnittstelle**. Partielle Profilfehler lösen ein automatisches Zurücksetzen in umgekehrter Reihenfolge aus.

### Verschlüsselter Response Vault

| Funktion | Detail |
|---|---|
| **Verschlüsselung** | AES-256-GCM |
| **Blockgröße** | 1 MiB |
| **Max. Quelldatei** | 256 MiB |
| **Identität** | SHA-256 + vollständige Dateiidentität |
| **Erfassung** | Atomar — wiederherstellungsgeprüft |
| **Symlink-Abwehr** | openat2, O_NOFOLLOW |
| **Vault-Berechtigungen** | root:gedefense 0700 — kein CAP_DAC_OVERRIDE |

---

## 🐧 Universelle Linux-Integration

| Schicht | Beta v4 Integration |
|---|---|
| Paketmanager | APT · DNF/YUM · pacman · Zypper |
| Init | Gehärtete systemd-Units mit Syntax- und Laufzeit-Gates |
| Privilegiengrenze | Polkit-gestützter Readiness-Helper — keine generische Root-Shell |
| Desktop | Lokales Chromium-Anwendungsprofil mit exaktem SPKI-Pinning |
| TLS-Identität | Öffentlicher Host plus `localhost`-, `127.0.0.1`- und `::1`-SANs |
| Release-CI | Go Race/Fuzz/Security · Rust Core · eBPF · Artefakt-Digests |
| Distributionsverträge | Ubuntu/Debian · Fedora/RHEL · Arch · openSUSE |
| Konkretes Host-Gate | bpffs · verifier-sichtbares eBPF · NIC XDP · IPC · TLS |

Distributions-Container validieren portable Paketierungs- und Integrationsverträge. Sie qualifizieren nicht den Host-Kernel. Jeder binäre Release erfordert weiterhin den privilegierten Test auf dem konkreten Kernel, Treiber und Netzwerkgerät.

---

## 🌐 AstraeaOS-Integration

| Funktion | Status |
|---|---|
| Natives Provisioning / systemd | ✅ Implementiert — identische Sicherheitskette wie Standalone |
| GeDefense Quellspiegel | ✅ Implementiert — SHA-256-Manifest verifiziert |
| AstraeaOS Härtungsprofil | ✅ Implementiert — reversibel und persistent |
| Boot-Trust-Evidenz | ✅ Implementiert — rein Evidenz, keine falsche Attestierungsbehauptung |
| Gaia Cells VGTGC1 Adapter | ✅ Implementiert — Laufzeit optional |
| UUID / Generation / cgroup-ID-Bindung | ✅ Implementiert — unveränderliche Aktionsbindung |
| Freeze / Netzwerk-Rollback | ✅ Implementiert — evidenzgebundene Transaktion |
| Gaia Cells Lifecycle Daemon | — Nicht enthalten — AstraeaOS-eigene Laufzeit |
| Isolierter Deception Service | — Zurückgestellt — außerhalb der Beta-Zuständigkeit |

Cell-Aktionen sind an UUID, Lebenszyklus-Generation und Kernel-cgroup-ID gebunden. Peer-UID, HMAC, Zeitfenster und Nonce werden verifiziert.

Ist die Gaia Cells-Laufzeit **nicht vorhanden**, meldet der Adapter `runtime_not_installed`. Die generische Host-Verteidigung bleibt aktiv und ist **nicht degradiert**.

> **Einzige Autorität:** In AstraeaOS ist GeDefense die einzige Sicherheitsautorität. Sentinel dient ausschließlich als Migrations- und Auditquelle.

---

## ⚙️ Laufzeitvertrag

### Systemanforderungen (Standalone)

| Anforderung | Wert |
|---|---|
| **Betriebssystem** | Linux |
| **Architektur** | x86_64 / amd64 |
| **Init** | systemd |
| **Kernel** | BPF/XDP + pidfd |
| **Paketmanager** | apt-get, dnf/yum, pacman oder zypper |
| **Installation** | Root + Internetzugriff für den Build |
| **Gateway-Laufzeit** | libargon2.so.1 |

> Für diese Beta wird keine pauschale Mindest-Kernelversion oder garantierte NIC-Liste deklariert. Der Ziel-Host wird durch Build-, Kernel-Verifier-, XDP-Attachment-, IPC- und Health-Gates qualifiziert.

### Toolchain-Pins

| Komponente | Version |
|---|---|
| **Go** | 1.27.4 |
| **Rust Core** | 1.97.1 |
| **Rust eBPF** | nightly-2026-07-16 |
| **Rust-Komponente** | rust-src |
| **bpf-linker** | 0.10.3 |
| **Cargo-Auflösung** | `Cargo.lock --locked` |

### Schnittstellen

| Schnittstelle | Standard | Exposition |
|---|---|---|
| **HTTPS Gateway** | TCP 9843 | Administrativ / öffentlich — konfigurierbar 1024–65535 |
| **Go Control Backend** | TCP 9844 | Nur Loopback |
| **Rust Core IPC** | `/run/vgt-gedefense/core.sock` | HMAC-VGT3 + SO_PEERCRED |
| **L7-Inspektions-API** | `/run/vgt-gedefense-l7/inspect.sock` | Lokaler Unix-Socket · begrenzt · optional SO_PEERCRED |
| **L7-Inline-Edge** | `/run/vgt-gedefense-l7/edge.sock` | Optionale lokale Unix-Reverse-Proxy-Grenze |
| **Gaia Cells** | `/run/gaia-cells/control.sock` | Optional — VGTGC1 |
| **Threat Feeds** | HTTPS ausgehend | Optional — nur öffentliche IPs |

### Dateisystem-Layout

| Pfad | Zweck |
|---|---|
| `/opt/vgt/gedefense/releases/<version>` | Unveränderlicher Release |
| `/opt/vgt/gedefense/current` | Atomarer aktiver Symlink |
| `/etc/vgt/gedefense/` | Konfiguration, TLS und Geheimnisse |
| `/var/lib/vgt/gedefense/` | Verschlüsselter operativer Zustand |
| `/var/lib/vgt/gedefense/quarantine/objects` | Verschlüsselter Response Vault |
| `/run/vgt-gedefense-l7/` | Ausschließlich flüchtige L7-Unix-Sockets |
| `/sys/fs/bpf` | BPF-Dateisystem |
| `/var/log/vgt-gedefense-install.log` | Installationsdiagnose — Modus 0600 |

---

## 🚀 Schnellstart

```bash
# Installer herunterladen
wget https://github.com/visiongaiatechnology/gedefense/releases/download/v6.2.1/VGT_GeDefense_V6_6.2.1_OneClick.run

# SHA-256 verifizieren
sha256sum --check VGT_GeDefense_V6_6.2.1_OneClick.run.sha256

# Installieren (Root erforderlich)
chmod 700 VGT_GeDefense_V6_6.2.1_OneClick.run
sudo ./VGT_GeDefense_V6_6.2.1_OneClick.run
```

> **Installer-Verfügbarkeit:** Die offiziellen v6.2.1 Self-Contained-Installer-Assets (`VGT_GeDefense_V6_6.2.1_OneClick.run` & `GeDefense-6.2.1-Desktop-OneClick.run`) werden mit dem signierten GitHub Release bereitgestellt.

> Der Installer und die Prüfsumme werden erst veröffentlicht, nachdem alle GitHub-CI- und konkreten Linux-Host-Qualifikations-Gates bestanden wurden. Führe niemals eine nicht verifizierte RUN-Datei aus.

Der Installer ist erst erfolgreich nach Bestehen von: **Build → Kernel Verifier → XDP Attachment → IPC → Backend → TLS Gates**.

Die Firewall-Regel für den HTTPS-Gateway-Port (TCP 9843) kann während der Installation via UFW, firewalld oder iptables eingerichtet werden.

**Starte im Observe-Modus. Canary und Enforce erst nach dokumentiertem Durchlaufen der Gates.**

---

## ✅ Release-Gates

| Gate | Zustand | Release-Regel |
|---|---:|---|
| Quell- und Upload-Manifeste | ✅ Implementiert | Keine Prüfsummen-Abweichung |
| Scan auf Geheimnisse/Schlüssel | ✅ Implementiert | Null Befunde |
| GitHub Actions & Container Digest Pinning | ✅ Implementiert | Ausschließlich unveränderliche Identitäten |
| Go Unit, Integration und Vet | 🔒 Erforderliche CI | Muss bestehen |
| Go Race Detector & Security Fuzz Smoke | 🔒 Erforderliche CI | Muss bestehen |
| JavaScript- und Shell-Syntax | ✅ Lokal + CI | Muss bestehen |
| Statisches Sicherheits-Regressions-Audit | 🔒 Erforderliche CI | Muss bestehen |
| Native Rust Common/Core-Tests | 🔒 Erforderliche CI | Muss bestehen |
| Rust Core und eBPF Release-Builds | 🔒 Erforderliche CI | Muss bestehen |
| Ubuntu, Fedora, Arch und openSUSE Verträge | 🔒 Erforderliche CI | Alle Matrix-Jobs müssen bestehen |
| Installer-Payload und SHA-256 Verifikation | 🔒 Erforderliche CI | Muss bestehen |
| Konkreter Kernel-Verifier und NIC XDP Attach | ⏳ Host-Qualifikation | Erforderlich pro Release-Host |
| systemd, IPC, Backend, TLS, Polkit und Desktop | ⏳ Host-Qualifikation | Erforderlich pro Release-Host |

**Verbleibendes Release-Gate:** Realer Ziel-Host-Smoketest für konkreten Kernel, Kernel-Verifier, XDP-Modus, Netzwerkschnittstelle und Netzwerktreiber.

---

## 🚧 Bekannte Einschränkungen (6.2.1 / V6)

- Keine Swarm- / Mesh-Unterstützung
- Kein QUIC-Offloading
- Keine DDoS-Absorption auf Provider-Ebene
- Keine TLS-Entschlüsselung
- Kein automatisches Erzwingen von Feeds (Feed Auto-Enforce)
- Keine Garantie gegen Root-Kompromittierung
- Keine vollständige Measured-Boot-Attestierung
- Gaia Cells Lifecycle Daemon extern (AstraeaOS-Laufzeit)
- Isolierter Deception Service zurückgestellt
- Wird eine geschützte Release-Komponente ersetzt, wird das mit hoher Schwere gemeldet und entwaffnet die Plattform nicht; die Ledger-Rotation setzt voraus, dass ihr Archivverzeichnis dem Dienst gehört und `0700` trägt, und verweigert den Lauf, statt in ein gemeinsames Verzeichnis zu schreiben
- Der Rust-Kern zählt und protokolliert übersprungene Ingress-Datensätze, meldet die Zahl aber noch nicht in seiner Health-Antwort; die Zahl steht daher im Dienstprotokoll und nicht im Panel
- **V6-Panels und Modul-Oberflächen sind vorhanden, aber an Kernel-Fähigkeiten gebunden:** StyX, Titan Exec Gate, Parser-Zellen, Emergency Lockdown und Witness haben eigene Views und Settings-Tabs; Web Exposure, Worker Guard, TLS Sensor, LPE Guard und Edge Proxy ebenso. Echte Kernel-Blockaden bleiben an `bpf`-LSM, den 6.1.0-eBPF-Tracepoint bzw. `AF_PACKET`-Rechte gebunden und werden sonst ehrlich als `inactive`/`error` mit Grund gemeldet. Beim Scharfschalten (`enforce`) greift weiterhin automatisch die sichere Basis-Aktivierung (`styx`, `titan_exec`, `parser_cells`), während Emergency Lockdown und Witness Opt-in bleiben.
- **Modul E (Edge-Terminator) ist Phase 1:** TLS-Terminierung mit HTTP/2-Grenzen, struktureller WAF und HTTP/1.1-Upstream; NGINX bleibt der produktive HTTP/2-/QUIC-Pfad, bis der V7-Rust-Edge (rustls + h2/quinn) folgt. Standard aus, nur Loopback, Zertifikatspflicht.
- **Worker-Crash-Erkennung:** Der eBPF-`signal_deliver`-Tracepoint ist die Primärquelle; ohne ihn arbeitet der Netlink-Proc-Connector als Fallback. Beide melden nur tödliche Signale registrierter Worker, keine Panel-Reloads (`SIGTERM`/`SIGKILL`).
- **Voraussetzung `bpf`-LSM (Punkt 1 & Cell-Socket-LSM):** Echte Kernel-Blockaden (`bprm_check_security` / `mmap_file`) erfordern `bpf` in `/sys/kernel/security/lsm` (`lsm=...,bpf` + Reboot); ohne `bpf`-LSM meldet GeDefense ehrlich `inactive`.
- **Parser-Zellen (Punkt 2):** Werden standardmäßig mit leerer Profil-Allowlist ausgeliefert (Operator legt Parser-Profile fest); Wayland-/PipeWire-Broker-Passthrough folgt in Phase 2.
- **Witness & Hardware-Attestierung (Punkt 4):** Enthält den gehärteten Mode-A-Client und Offline-Bundles (`vgtw1`), aber keinen externen Witness-Server/Quorum im Repo; ohne TPM2/UEFI wird ehrlich `quote_kind="none"` und `key_binding="software"` gemeldet.
- **Emergency Lockdown Phase-2-Grenzen (Punkt 5):** LUKS-Suspend, grafischer Session-Lock und RAM-Zeroization folgen in Phase 2 (`unsupported` bei fehlender Plattform-Integration); USB-/TB-Sysfs-Schreibzugriffe erfordern die entsprechenden Rechte auf `gedefense-core.service`.

---

## 📋 Changelog

### v6.2.1 — Kernel Behavioral XDR, Inode-Quarantäne-Sperre & Service-Pool-Isolation *(Aktueller Release — 23.11.2026)*

- **Malware-Inode-Sperre & Core-Pfadgrenzen (`FIND-G-001`):** BPF-LSM `MALWARE_DENIED_INODES` (`4.096` Einträge) blockiert bestätigte Malware-Inodes direkt bei `file_open` (`-EACCES`) selbst in Nicht-root-`0755`-Drop-Verzeichnissen ohne breite DAC-Override-Rechte, flankiert von `CORE_QUARANTINE_ALLOWED_ROOTS` / `FORBIDDEN_ROOTS` sowie `capture_open_fd_only()` für den verschlüsselten Vault.
- **Kernel Behavioral XDR & Multi-CPU-Tracepoints:** Neue Ringbuffer `EXEC_ARGV_EVENTS` (`512` B Subshell-Argumente) und `KERNEL_PROBE_EVENTS` (`XDR.PTRACE_ATTEMPT`, `XDR.KERNEL_PROTOCOL_PROBE`, `XDR.CREDENTIAL_PROBE`, `XDR.SYMLINK_OVER_SENSITIVE`), `PENDING_COLD_OPEN` + `getname_flags`-Kretprobe, Discovery-Regeln (`KD.LINUX.DISCOVERY.ACCOUNT`, `KD.LINUX.DISCOVERY.SUID`) und Multi-CPU-Perf-Aktivierung in `rust/vendor/aya`.
- **Service-Pool-Isolation & Telemetrie-Hygiene:** Geschärfte Ransomware-Schwellen (`15 → 6` Entropy-Inodes, `25 → 18` Metadaten-Burst) mit `RANSOM_TRUST_POOL_METADATA` (`php-fpm`, `lsphp`, `nginx`, `httpd`, `apache2`, `mariadbd`, `postgres`, `redis-server` usw.) sowie PPID-beschränkter `stop_process_descendants` / `collect_tree`-Isolation (Master und gesunde Pool-Worker laufen weiter); `isIgnoredNonExternalFlow` (`127.0.0.0/8`, `::1`, Link-Local, `pid=0`/`swapper/*`) im StyX-Beacon, asynchrones `ChronosScanner` und `1s`-Health-Polling.
- **Erweiterter VGT HardRed & ARES 1.2 Benchmark (`86.16 → 94.73`):** Verifizierte **`94.73 / 100 (PASS)`** sowie 5-Contender ARES 1.2 (`78.40 / 96.68 / 93.46`, `177/177` Code-Zitate) gegen OSS Best-of-Breed + SafeLine WAF (`59.28 / PASS` · ARES `58.20 / 56.25 / 61.33`), OSS Best-of-Breed (`55.40 / FAIL`), SafeLine WAF (`52.92 / PASS` · ARES `53.60 / 51.67 / 42.69`), Wazuh (`46.70`), CrowdSec (`36.58`) und REDHARD-ARES-Hybriddaten vollständig unter [`benchmarks/vgt-hardred-6.2.1/`](benchmarks/vgt-hardred-6.2.1/) veröffentlicht (`docs/V6.2.1-RELEASE.md`).

### v6.2.0 — Defense-Maximization & Telemetrie-Resilienz *(22.11.2026)*

- **Malware- & Archiv-Inspektion (`M1.1`–`M1.3`):** Asynchroner `FAN_CLOSE_WRITE`-Watcher auf `/tmp`, `/var/tmp`, `/dev/shm`, `/var/www` (UID-unabhängiges Scanning bis `16 MiB` Probe- / `64 MiB` Full-Scan-Budget), rekursive ZIP/GZIP/TAR-Prüfung (Tiefe 8, fail-closed bei Zip-Slip), `PrivateTmp=false` mit engen Grants, fd-verankerte Quarantäne und HTTP-Raw-Body-Scanning für `POST`/`PUT`.
- **Endpoint-Containment & Kernel-Wächter (`M2.1`–`M2.4`):** TITAN-Exec-Globalmodus `untrusted` (`4`) via ABI-2; `pidfd`-verifiziertes `XDR_KILL_TREE` / `GROUP_STOP` / `GROUP_CONT`; eBPF-Ransomware-Sensor (`vfs_write`/`vfs_rename`/`vfs_unlink`) direkt bei Attach scharfgeschaltet mit `100 ms`-Drain-Takt und reversiblem `SIGSTOP`; `file_open`-BPF-LSM Credential Guard für `/etc/shadow`, `/etc/gshadow` und Secrets (inkl. TTY-`login`/`cron`/`useradd`/`dpkg`-Allowlist).
- **StyX symbolische Identitäten & 16-MiB-Flow-Telemetrie (`M3.1`–`M3.2`):** Symbolische `cgroup_path`-Auflösung über Reboots/Restarts (`degraded` statt leisem Fail-Open), `16 MiB` `FLOW_EVENTS`-Ring / 64er-Batches sowie getrennte Meldung von `enforcement_active` vs. `telemetry_state`.
- **WAF, Härtung & Kontext (`M4.1`–`M4.5`, `M5.1`–`M5.2`):** SQL-Kommentar-/Whitespace-Normalisierung, Secret-Config-Scanner (`/.env`, `.git/config`, Backups), Semikolon-Ketten, `780 KB–1,5 MB`-Fast-Pass, deterministisches `429 + Retry-After`, `astraeaos-cis-l1` (21-Bit Go/Rust-Katalog) + opt-in `gedefense-cis-baseline` sowie Kinetic→XDR-Attack-Stories.
- **Benchmark-Verifikation:** Mit **`86.16 / 100 (PASS)`** im VGT HardRed Benchmark (`0,0 %` Det/Prot FPR) nach Behebung aller Post-Audit-Befunde verifiziert (`docs/V6.2.0-RELEASE.md`).

### v6.1.2 — Installer-Vorbedingungen & Feed-Signing-Hotfix *(20.11.2026)*

- **Erstinstallations-Vorbedingungen (`scripts/oneclick-installer-header.sh`):** Legt `gedefense-desktop` (`systemd-sysusers` + `groupadd`) sowie `/run/gedefense-scan`, `/run/gedefense` und `/sys/fs/cgroup/vgt-cells` vor dem Unit-Start ohne Reboot-Zwang an, pinnt `CERT_FILE` auf `${TLS_DIR}/access.crt` und schützt `reconcile_post_upgrade_posture()`.
- **Ed25519 Feed-Schlüsselparser (`control/feed_signing.go`):** Verhindert das Abschneiden des letzten Bytes bei 32/64-Byte-Schlüsseln auf `0x0d` + `
`.

### v6.1.1 — Sicherheits- & Kernel-Kompatibilitäts-Hotfix *(19.11.2026)*

- **Audit-Remediation (`VGT-AUDIT-20261118-GD61` R2/R3 & `VGT-AUDIT-2026-11-19` `FIND-001`–`FIND-005`):** Privilegiertes `AF_PACKET`/`CN_PROC`-Capture in `gedefense-capture-helper.service` isoliert (`gedefense-control.service` bleibt ohne Capabilities), Seccomp `__X32_SYSCALL_BIT`-Schutz (`FIND-001`), begrenzte TLS-Sensor-ALPN-/Peer-Maps (`FIND-002`), Lockdown-`auto_network_drop`-Ownership (`FIND-003`), USB-Composite-`bNumInterfaces` + Parent-De-Auth (`FIND-004`) und Gateway-`Connection`-Header-Scrubbing (`FIND-005`).
- **Kernel 7.3 BTF & Cockpit-Auto-Cooldown:** Akzeptiert 32-Byte-BTF-v1-Header (`24 <= hdr_len <= data.len()`) und ergänzt zweistufiges Ampel-Cooldown (`0–15 Min.` Rot → `15–60 Min.` Gelb → `> 60 Min.` Grün).

### v6.1.0 — Web-Exposure, Worker-Integrität, TLS-Sensor, LPE-Guard & Edge-Terminator *(Aktueller Release — 18.11.2026)*

- **Module A–E:** Web-Exposure-Engine (`/proc` + ELF-`.rodata` + Config-Reachability + Loopback-ALPN, CVEs nur bei Erreichbarkeit), Worker-Crash-Storm-Wächter (eBPF-Tracepoint + Netlink-Fallback, `XDR.WORKER_CRASH_STORM`, strikte Worker-Cgroups mit `JIT_ALLOW = 0`), TLS-/ALPN-Sensor mit Kernel-Socket-Budget und fehlalarmfreiem Control-Storm-Prädikat, LPE-Blocker (Socket-Familien, StyX `web-ingress-only`, ASLR/Modul-Baseline) und optionaler Memory-Safe-Edge.
- **Zehn neue Dashboard-Views:** Web Exposure, Worker Guard, TLS Sensor, LPE Guard, Edge Proxy, StyX, Titan Exec, Parser Cells, Emergency Lockdown, Witness — jeweils mit Live-Status, Aktionen und eigenem Settings-Tab. Sämtliche Werte sind nachträglich änderbar, abschaltbar und serverseitig validiert.
- **Runtime Settings v18:** Fünf additive Namespaces (`web_exposure`, `worker_guard`, `tls_sensor`, `lpe_guard`, `edge_proxy`); ein v17-Dokument wird unverändert übernommen, alle neuen Funktionen starten sicher (deaktiviert bzw. Sensor only). Migration nennt jeden Seed.
- **Kernel & Toolchain:** 6.1.0-eBPF-Modul `worker_guard` (`signal:signal_deliver`, `WorkerCrashEvent`), LSM-Policy-Bits 1–6 mit abwärtskompatibler Validierung, `WORKER_GUARD_*`-Core-Kommandos und Go-Client mit Capability-Klassifikation; Go-Sprachlevel 1.24 für `http.HTTP2Config`, Toolchain-Floor bleibt `go1.27.4`.
- **Ehrlichkeit:** Fehlender Tracepoint, LSM-Hook, `AF_PACKET`-Recht, Zertifikat oder Core-Befehlssatz wird als `inactive`/`error` mit Grund gemeldet.
- **Audit-Remediation `VGT-AUDIT-20261118-GD61`:** FIND-001–007 und CHAIN-001/002 behoben — RDS-Family-Check, Dual-Stack-/Port-Filter, ehrlicher Worker-Quellstatus mit Master-Cgroup-Ausschluss, minimale Control-Capabilities (`CAP_NET_RAW`/`CAP_NET_ADMIN` + `AF_PACKET`, als exakte Allowlist in den Gates), XFF-Scrub + Edge-Start beim Boot, 503/409 bei LPE-Teilfehlern, echte ASLR-Durchsetzung und UTF-8-korrekte V6.1-Panels. Details und Restrisiko: `docs/V6.1.0-AUDIT-REMEDIATION.md`, `SECURITY.md`.

### v6.0.3 — Case-Pipeline Fail-Visible-Fix & Audit-Gate-Härtung *(Vorheriger Release — 17.11.2026)*

- **Durchgängig kleingeschriebene Incident-Severities (`GD-SEV-001`):** Producer (`morpheus_rasp`, `styx_egress`, `styx_beacon`, `deception`) auf kleingeschriebene Kanonik umgestellt, Normalisierung in `appendIncident`, `emitStyxBeaconIncident` und `State.AddIncident` verankert sowie `CaseEngine.IngestIncident` bei unbekannten Severities fail-visible gemacht, damit kritische Incidents nie wieder stillschweigend aus der Case-Engine fallen.
- **Einheitliche UI-Severity-Klassen:** `.toLowerCase()`-Normalisierung über `xdr.js`, `l7.js`, `render.js` und `app.js` samt Protection-Overview-Verbesserungen.
- **Deterministisches Audit-Gate:** Den Point-4-Anker in `scripts/security-audit.sh` auf die versionierte Datei `docs/POINT4-PHASE1-REPORT.md` statt der gitignorierten `Next.md` gelegt.

### v6.0.1 — Server-Safe Auto-Arm & AIDE-/Scanner-Kalibrierung *(16.11.2026)*

- **Emergency Lockdown bleibt Opt-in:** `ApplySafeV6DefaultsOnEnforce()` aktiviert beim Wechsel auf `enforce` keinen automatischen Emergency Lockdown (`network_lockdown=true`, `require_sources=1`) mehr; **StyX** (`monitor`), **Titan Exec Gate** (`contain`) und **Parser-Zellen** (`enabled`) bleiben automatisch aktiv, während **Emergency Lockdown** und **Witness** explizites Operator-Opt-in bleiben.
- **AIDE- & Integritätsscanner-Kalibrierung:** `aide`, `aide.wrapper`, `updatedb.*`, `tripwire`, `samhain`, `rkhunter`, `chkrootkit`, `clamscan`, `clamd`, `freshclam` und `osqueryd` werden in `isSystemOrScannerAccessor` als System-Scanner eingestuft (`CANARY_SUSPICIOUS_SYSTEM_ACCESS` / `HIGH` statt `CRITICAL / CANARY_UNAUTHORIZED_PROBE` durch Service-Accounts wie `_aide`).
- **Relative `.sha256`-Sidecars:** `VGT_GeDefense_V6_6.0.1_OneClick.run.sha256` enthält ausschließlich den relativen Dateinamen.

### v6.0.0 — GeDefense V6 Anti-Spyware- & Souveränitäts-Architektur *(15.11.2026)*

- **5-Punkte-Anti-Spyware-Blueprint:** Integration von StyX Egress + C2/Beacon-Erkennung (Punkt 3), Titan + eBPF-LSM Exec-/Library-Gate inkl. dynamischer BTF-Offsets & Kernel-7.0-Split-`ctime` (Punkt 1), ephemeren Parser-Zellen über `gedefense-cell-helper.service` (Punkt 2), Out-of-Band Witness Client mit monotoner `ledger_epoch` & SSRF-Schutz (Punkt 4) sowie Emergency Lockdown mit XDP/TC-Drop-Latch, Composite-BadUSB-Gate und 15-Zeichen-`comm`-Broker-Freeze (Punkt 5).
- **Sichere Auto-Aktivierung bei `enforce`:** Da noch keine dedizierten V6-UI-Panels enthalten sind, aktiviert das Scharfschalten (`enforce`) automatisch die sichere V6-Basis (`styx=monitor`, `titan_exec=contain`, `parser_cells=enabled`); `lockdown` und `witness` bleiben Opt-in und manuelle API-Overrides bleiben persistent.
- **Gehärtetes 5.2.0-Fundament integriert:** Beinhaltet alle 36 behobenen Findings aus `VGT-AUDIT-20261114-GD51`, Ed25519-OneClick-Signaturprüfung, Argon2id-Admission-Gate/-Migration, striktes Storage-AEAD sowie signierte Release-Artefakte.

### v5.0.0-beta.1 — Automatische Gaia-Cell-Isolation, bewachte Kernel-Mitigation & operatives PHP/L7-Hardening *(Vorherige Version)*

- **Automatische und manuelle Gaia-Cell-Isolation:** Incidents ab `cells.auto_confine_score` isolieren die zugehörige Cell über die reversible Transaction-Engine; die manuelle Isolation steht pro Incident-Zeile bereit. APIs: `POST /api/v1/xdr/incidents/{id}/confine`, `GET /api/v1/cells/confinement`.
- **Kernel-Mitigation-Guard:** opt-in sysctl-Mitigation mit begrenztem Probation-Fenster, Host-Service-Verifikation und automatischem Rollback; die Hardening-Ansicht bietet Dry-Run, Apply und Rollback mit Begründung.
- **PHP-Upload-Progress-Mitigation:** kritische L7-Regel `L7.PHP.SESSION_UPLOAD_PROGRESS` (Score 110) und Hardening-Kontrolle `web.php-upload-progress`; `session.upload_progress.enabled = Off` wird gegen den effektiven Web-SAPI verifiziert.
- **Regelbasiertes L7-Enforcement:** `l7.enforce_rules` begrenzt Blocking auf benannte Regeln/Familien; der Inline-Edge-Self-Test ist PASS und der Origin nur auf Loopback gebunden, sodass direkter Origin-Zugriff die Inspektion nicht umgeht.

### v4.3.0 — Kernel-Advisory-Exposition: erkennen, bewerten und blocken, was die Sensoren nicht sehen

- Laufzeit-Exposition von Release/Channel gegen den mitgelieferten Advisory-Katalog; `unknown` wird nie als sicher dargestellt.
- Erreichbarkeitsgewichtete Exposition und Kernel-Risk-Panel im Dashboard (Dry-Run, Apply, Rollback).


### v4.2.5 — Multi-Vektor-Echtzeit-Bedrohungskarte, sofortige Reaktivierung nach Updates & selbstheilende Sensorik

Ein Visualisierungs- und Resilienz-Release. Es bringt eine konsolidierte Echtzeit-Angriffskarte über alle Erkennungspfade, blitzschnelle Schutz-Reaktivierung nach Software-Updates und autonome Sensor-Selbstheilung.

* **Konsolidierte Echtzeit-Bedrohungskarte auf der Übersichtsseite:**
  * **Alle Erkennungspfade auf einen Blick:** Das Übersichts-Dashboard visualisiert nun gleichzeitig Paketfilter-Drops (eBPF/XDP), Layer-7-Anwendungsangriffe und Post-Exploitation-/Host-XDR-Vorfälle in einer interaktiven Weltkarte.
  * **Souveräner Host-Ursprung & Bézier-Angriffsbögen:** Animierte Flugbögen zielen präzise auf die echte aufgelöste Geo-Position des Ziel-Hosts (via lokaler GeoIP-Datenbank). Nicht lokalisierbare IPs und Null-Koordinaten werden unterdrückt, um Fehlplatzierungen zu verhindern.
  * **Sieben pfadbezogene Zähler:** Separate Zähler für Quellen, platzierte Knoten, geblockte Angriffe, Länder sowie individuelle Metriken für Kinetic-, L7- und XDR-Pfade.
  * **Echtzeit-Aktivitätsband:** Ein tabellarisches Band unterhalb der Karte zeigt die 10 neuesten Einträge des Vorfalls-Ledgers mit Zeitstempel, Erkennungspfad, Quell-IP/Land, Befund und Blockierstatus.
  * **100 % lokal & datensouverän:** Lokales MIT-SVG-Modul, 950.000 GeoIP-Einträge verbleiben auf dem Host, keine externen Requests. Barrierefrei mit Tastatursteuerung und automatischer Abschaltung von Animationen bei `prefers-reduced-motion`. Vollständig lokalisiert in Deutsch, Englisch, Russisch und Chinesisch.
* **Sofortige Schutz-Reaktivierung nach Updates (6–7 Sekunden):**
  * **Trennung von Host-Qualifikation und Release-Version:** Der Startup-Supervisor trennt die Hardware-/Kernel-Identität von der Software-Release-Nummer. Bei geplanten Updates auf einem bereits qualifizierten Host entfällt die künstliche 20-minütige Canary-Warteleiter; der volle Schutz (`enforce`) steht nach 6–7 Sekunden wieder bereit.
* **Autonome Sensor-Selbstheilung & Gateway-Härtung:**
  * **Selbstreparierende L7-Sensorabdeckung:** Der Sensor `l7_application` verharrt nach Neustarts nicht mehr im Status „auf Traffic warten“. Das Modul `sensor_coverage` führt automatisch einen kanonischen Test-Probe durch die Inspektionspipeline aus (max. 3 Versuche).
  * **Kernel-Gesundheitsabfrage vor erstem Tick:** Verhindert Fehlalarme beim Hochfahren.
  * **Strikte TLS-Zertifikats- und Schlüsselpaarung:** Systemd-Templates erzwingen identische Verzeichnisse für Zertifikat und Key, wodurch Verbindungsabbrüche (`ERR_CONNECTION_REFUSED`) zuverlässig verhindert werden.

### v4.2.4 — Fail-Closed-Durchsetzung, Ledger-Rotation und ein ehrliches Panel

Eine Härtungsversion. Sie entfernt die Wege, auf denen die Plattform ihren eigenen Schutz verlieren konnte, und bringt jede Oberfläche dazu, zu sagen, was der Kernel tatsächlich tut.

* **Fail-Closed-Durchsetzung (die Entwaffnung):**
  * **Eine automatische Degradierung gibt die verifizierte Kernel-Policy nicht mehr frei.** Ein einzelner Kernel-Datensatz, den der Kern nicht interpretieren konnte — ein gemischtes UDP/TCP-Aggregat, das der Producer mit dem Protokoll des auslösenden Pakets etikettiert, sodass ein TCP-Satz mehr Versuche als SYNs tragen kann — brach den ganzen Drain ab; die Kontrollplane las den fehlgeschlagenen Drain als verlorenen Kernel-Hook, und das Release-Gate beantwortete einen nicht verfügbaren Sensor mit einem Abgleich der Kernel-Policy auf `observe`. Jeder Block wurde aus dem Kernel entfernt, und ein Produktionshost lief zwanzig Stunden ungeschützt, weil nichts ihn zurückholte. Das Gate bestätigt und behält jetzt, was es verifiziert hat (`verified-enforce`), und ein nicht bestätigbarer Zustand wird als `verified-empty` gemeldet, statt als dasselbe zu gelten.
  * **Ein Neustart behält die Enforcement der signierten Policy** statt auf `observe` zu initialisieren.
  * **Eine Promotion senkt eine verifizierte Enforcement nicht.** Das tut nur ein ausdrücklicher Betreiber-Eingriff, und eine Beibehaltung wird als eigene Aktion gemeldet (`automatic_response_paused`), nicht als Änderung der Enforcement.
  * **Ein Drain- oder Parserfehler ist vom Verlust der Durchsetzungsfähigkeit getrennt,** sodass ein Sensor, der keine Daten liefern kann, nicht länger als ein Kernel gelesen wird, der nicht blockieren kann.
  * **Die Plattform bewaffnet sich selbst neu,** sobald die Gates bestehen und die Ruhe hält, und protokolliert den Übergang mit dem Grund, der ihn aufgehalten hatte.
  * **Ein erfolgreicher Verifikationslauf löscht den Grund, den er ersetzt hat.** Gründe waren einseitig: nur eine Rotation oder eine Betreiber-Wiederherstellung entfernte sie, sodass ein transienter Fehler XDR degradiert ließ — und die automatische Antwort pausiert — bis jemand die Kontrollplane neu startete.
  * **Ein Deployment des Betreibers gilt nicht mehr als Eindringen.** Der Austausch einer eigenen Komponente degradierte XDR und pausierte die automatische Antwort; jeder ausgelieferte Fix schaltete damit stillschweigend einen Teil des Schutzes ab. Jetzt ist es ein Ereignis hoher Schwere ohne Reaktion; Fremdobjekte behalten die volle Antwort.
  * **Die Wiederherstellung des Incident-Ledgers verlangt nicht mehr, den Schutz aufzugeben** — unter Beibehaltung war das unerreichbar; das Ledger ließ sich nur reparieren, indem man zuvor den Host entwaffnete, dessen Schutz es erhalten soll.
  * **Der Rust-Kern behält ein TCP-Label nur für ein konsistentes Aggregat.** Ein homogenes TCP-Batch behält sein `protocol`/`tcp_flags` und seine exakten Zähler — ein großes ACK- oder SYN-Batch wird nicht mehr als Widerspruch missverstanden. Ein Batch, der TCP mit Nicht-TCP-Paketen mischt, wird mit dem expliziten Neutral-Marker (`protocol = 0`, `tcp_flags = 0`) und exakten Zählern emittiert, statt das Label des auslösenden Pakets zu erben. Ein Datensatz, der der Batch-Länge widerspricht, wird verworfen und als verlorener Sample gezählt (mit Drain-Alarm, sobald zu viele auflaufen), nie in ein neutrales Label umgeschrieben. Der eBPF-Produzent flusht höchstens 255 Pakete pro Batch (das Wire-Feld `attempt_count` ist ein `u8`), und sein LSM-Walk deckt die vollständige cgroup-v2-Ahnenkette ab der Wurzel ab, sodass eine auf einer Gaia-Cell-Cgroup installierte Policy auch nachgelagerte Leaf-Cgroups erfasst. Siehe `rust/gedefense-common/src/lib.rs` (Wire-Decoder) und `rust/gedefense-ebpf/src/main.rs` (Produzent).
* **Ledger-Aufbewahrung:**
  * **Beide Forensik-Ledger rotieren, statt sich zu füllen.** Das Erreichen des Budgets stoppte die Aufzeichnung, degradierte XDR und pausierte die automatische Antwort, bis ein Betreiber das Segment von Hand archivierte — zweimal an einem Tag auf einem Produktionshost. Bei neunzig Prozent wird die versiegelte Kette mit einem Manifest archiviert, das Größen, Digests, Sequenz, Head-Hash und Prüfumfang trägt, und eine frische Kette beginnt.
  * **Die Rotation übersteht einen Absturz.** Sie kopiert, bevor sie ersetzt; ein unterbrochener Lauf wird beim nächsten Start aus einer Rotationsmarkierung vervollständigt, und eine Markierung, deren Manifest nicht passt, wird abgelehnt statt geglaubt.
  * **Das Evidenz-Ledger verifiziert sich in Grenzen.** Der Start prüfte das ganze Ledger — rund 260 MB bei etwa 6,7 Sekunden pro Megabyte — und überschritt das Start-Timeout der Unit, sodass weder die Plattform noch das Gateway hochkamen. Der Start prüft jetzt den authentifizierten Checkpoint und ein begrenztes Tail-Fenster; die Historie wird im Hintergrund inkrementell gegen einen authentifizierten Wasserstand abgedeckt; die vollständige Verifikation bleibt dem Betreiber verfügbar. Ein nicht authentifizierter Wasserstand wird abgelehnt, weil eine gefälschte Datei damit die ganze Historie übersprang.
  * **Ein unterbrochener Append wird wiederhergestellt** — verifiziert und versiegelt oder als partieller Schreibvorgang verworfen — statt den Dienststart zu verhindern.
* **Oberflächen-Verifikation:**
  * **Jeder zustandstragende Satz wird gegen die Nutzlast geprüft, aus der er stammt.** Ein Headless-Rendering des Dashboards — elf Nutzlast- und Ansichtskombinationen, achtzig Regeln — vergleicht, was der Betreiber liest, mit dem, was die API gemeldet hat. Es fand drei Aussagen, die dem Zustand widersprachen, den sie beschrieben; alle drei stammten aus den Korrekturen dieser Version.
  * **Der Prüfer belegt, dass er fehlschlagen kann.** Ein Selbsttest mit absichtlich falschen Nutzlasten und ein Regressionsmodus, der die Wächter wieder entfernt: achtzehn der achtzig Regeln werden dann rot, darunter SYSTEM NOMINAL im Badge.

### v4.2.1 — Stabilität, Evidenz und Oberfläche

Eine Fehlerbehebungsversion. Sie bringt kein neues Teilsystem; sie bringt die vorhandenen dazu, die Wahrheit über sich zu sagen und dem Betreiber nicht im Weg zu stehen.

* **Evidence-Ledger:**
  * **Kapazität ist kein Datenverlust mehr.** Das Erreichen des Aufbewahrungsbudgets setzte den Integritätsfehler des Ledgers, quarantänisierte ihn dauerhaft und meldete XDR als degradiert mit „mandatory evidence ledger unavailable". Ein volles Ledger ist kein beschädigtes.
  * **Ein Budget, von jeder Seite gleich gelesen.** Die Konstruktion ist nachsichtig, die Laufzeit streng: Ein Ledger, das unter einem erhöhten Budget berechtigt gewachsen ist, wird nach einem Neustart akzeptiert, statt den Dienststart zu verweigern.
  * **Das Budget, das der Betreiber erhöht, ist das Budget, das der Ledger durchsetzt.** Der Konstruktor setzte seine Policy auf den kompilierten Default von 64 MiB, den der Schreibpfad bevorzugt — ein auf 256 MiB erhöhtes Budget wurde damit bei jedem Start verworfen: Der Ledger stoppte bei 64 MiB und lehnte danach jeden Schreibvorgang ab, während er sich weiter als gesund meldete. Die Plattform hatte stillschweigend aufgehört, Evidenz aufzuzeichnen. Beide Budgets starten nun gleich, und ein später erniedrigtes Budget wirkt weiterhin.
  * **Der Zustand benennt sich selbst.** „Retention budget reached" und „integrity unavailable" sind getrennte Meldungen mit getrennten Zahlen und getrennten Abhilfen.
* **Release-Gate:**
  * **Ein Fail-Safe behält seinen Grund.** Der Grund wurde beim nächsten Refresh von der Liste der aktuellen Blocker überschrieben, sodass eine Plattform, die noch im Observe-Modus stand, schließlich „release gates satisfied" anzeigte.
  * **Ein Fail-Safe ist forensische Evidenz.** Ein Rückfall ist das folgenreichste, was die Plattform von sich aus tut — und er hinterließ keinen Incident.
* **L7 Application Defense:**
  * **Ein bestandener Selbsttest räumt eine veraltete Degradierung ab,** begrenzt auf fünfzehn Minuten, damit ein alter Erfolg keinen Pfad verdeckt, der seither gebrochen ist.
  * **Die erzeugte nginx-Konfiguration konnte nie angewendet werden.** Sie erzeugte einen Server-Block mit `listen ... ssl` und einem Kommentar dort, wo die Zertifikatsdirektiven hingehören — von nginx rundheraus abgelehnt — und nannte einen Host, der bereits einen Server-Block hatte. Sie besteht jetzt aus zwei einfügbaren Teilen, im Testlauf gegen den echten nginx-Parser geprüft.
  * **Der Durchsetzungspfad wird berichtet.** `INGRESS_HEALTH` nennt, welchen Hook der Kernel eingehängt hat — natives XDP, generisches XDP oder TC-Ingress —, statt alle drei als „verified kernel ingress producer" zu bezeichnen, obwohl sie sich unter Last sehr unterschiedlich verhalten.
  * **Der Betreiber sieht, ob HTTP-Verkehr existiert, während L7 nicht in seinem Pfad liegt.** Die Web-Oberflächen-Erkennung meldet, ob auf diesem Host ein Webserver läuft und auf welchen Ports — nur lesend, begrenzt und niemals als Schutz dargestellt, denn Erkennung ist kein Schutz.
  * **Die geführte Webserver-Integration erzeugt Konfigurationstext und sonst nichts.** Sie schreibt nie in die Konfiguration eines Webservers, lädt keinen Dienst neu und behauptet nie, ein erzeugtes Fragment sei in Kraft; der Betreiber wendet es an, und der Selbsttest beobachtet anschließend, ob es gewirkt hat. Jeder eingesetzte Wert wird vorher gegen eine geschlossene Grammatik geprüft, denn die Ausgabe ist eine Konfigurationsdatei für einen privilegierten Dienst.
  * **Geprüfte Requests umfassen beide Zähler, nicht einen.** Das Panel zeigte nur den Request-Zähler, sodass ein Host, dessen Inline-Listener 174 Requests inspiziert hatte, „0 geprüfte Requests" direkt unter seinem eigenen „TRAFFIC AKTIV"-Abzeichen meldete — das Panel widersprach sich selbst und verbarg damit den Beleg, dass sein Urteil richtig war. Die Zahl ist jetzt die Summe, aus der das Urteil berechnet wird.
* **Kinetic Defense:**
  * **Durchsetzung und Wirkung sind sichtbar.** Das Panel nennt den verwendeten Hook, die Gesundheit des Kernelkanals und was die Engine erkannt und getan hat. Im Observe-Modus sagt es das auch: Eine Spalte voller Nullen heißt, dass die Antwortstufe nie betreten wurde — nicht, dass nichts gesehen wurde.
  * **Die Übersicht trägt die Zahlen,** gruppiert nach der Frage, die sie beantworten.
  * **Die Abdeckungs-Zusammenfassung erklärt den Sensor, den sie nennt.** Die Begründungszeile war an einen festen Sensornamen gebunden, sodass eine Zusammenfassung „Mandatory sensors degraded: l7_application" mit dem Satz des gesunden Ingress-Producers erklärt wurde — eine degradierte Überschrift über einer positiven Erklärung, auf einer Seite, die im selben Moment der Application-Defense-Seite widersprach, obwohl beide denselben Snapshot lasen. Die Begründung gehört jetzt dem Sensor, der die Plattform nicht-nominal gemacht hat, mit der Rangfolge des Servers, und der Rückfall ist ein übersetzter Schlüssel statt eines deutschen Literals.
  * **Die Zusammenfassung ist deterministisch.** Sie behauptet, den Status deterministisch zu bestimmen, verknüpfte die Sensornamen aber in Map-Iterationsreihenfolge — derselbe Zustand ergab bei jedem Refresh einen anders geordneten Satz.
* **Härtung und Integrität:**
  * **Ein Manipulationsbefund an GeDefense-eigenen Komponenten bewaffnet nicht mehr die Antwort.** Ein Digest-Konflikt an einer der eigenen Binaries ist von einem genehmigten Update nicht zu unterscheiden, und die Antwort-Engine griff deshalb ein: Über hundert aufgezeichnete Incidents zeigen das Produkt, wie es sein eigenes Zugangsgateway einfriert — eine Dienstblockade, die jeder Angreifer durch das Berühren einer einzigen Datei auslösen kann. Der Befund bleibt in voller Schwere bestehen — dieselbe Regel, dieselbe Bewertung, dieselbe Kategorie — und nur die Antwort wird zurückgehalten; fremde Binaries behalten ihre. Die eigenen Komponenten werden über eine gemeinsame Wurzel erkannt, die `VGT_RELEASE_ROOT` folgt.
  * **Zehn Härtungsschalter waren wirkungslos** auf einem bereits gehärteten Host, weil ein Schalter deaktiviert wurde, sobald seine Kontrolle bereits PROTECTED war; der Preflight prüft eine Auswahl, er wendet sie nicht an.
  * **Die Härtungsstufe kann sich nicht überzeichnen.** Ein Host, auf dem zwei von zweiundzwanzig Kontrollen lesbar waren und beide bestanden, erreichte 100 Punkte und meldete HARDENED. Die Stufe ist jetzt gedeckelt, wenn die Evidenz sie nicht trägt, und die Abdeckung steht neben dem Wert.
  * **Ein geändertes geschütztes Objekt wird als Objekt gemeldet, und zwar einmal.** Die geschützte Menge erreicht dieselbe Release-Binary über `/current/bin/...` und `/releases/<version>/bin/...`, sodass ein Austausch zwei kritische Incidents erzeugte — und eine nicht behobene Änderung wurde in jedem Dedupe-Intervall erneut gemeldet, bis der Dienst neu startete; eine einzige Tatsache begrub das Ledger, in dem sie aufgezeichnet wurde. Die Meldung ist jetzt am aufgelösten Objekt und seinem beobachteten Zustand verankert, und der Grund nennt jedes geänderte Objekt.
  * **Das Integritätspanel benennt das Teilsystem, das tatsächlich degradiert ist,** statt `INTEGRITY_FAILURE` anzuzeigen, während der Incident-Ledger, auf den es zeigt, gesund ist und damit nichts zu tun hat.
* **Threat Intelligence:**
  * **FireHOL Level 1 wird durchgesetzt, nicht korreliert.** Eine protokollierte Schema-Migration hebt den gespeicherten Wert auf bestehenden Knoten an, abgeglichen über die Feed-ID und niemals abgesenkt, weil hier eine Betreibereinstellung in dessen Namen geändert wird.
* **Lebenszyklus der Kontrollplane:**
  * **Ein interner Neustart,** aus der Oberfläche erreichbar, aktiviert die RESTART-Klasse von Werten, die persistiert, aber nie angewendet worden waren. Er verweigert sich, wenn kein Supervisor den Prozess zurückbringen würde, weil ein Beenden dort das Produkt stoppen und gestoppt zurücklassen würde.
* **Zugangsgateway und Oberfläche:**
  * **Das Anmeldeformular macht sich nicht mehr selbst ungültig.** Jeder Seitenaufruf erzeugte ein frisches CSRF-Token und überschrieb das Cookie, sodass das Cookie ein einzelner gemeinsamer Platz war statt eine Eigenschaft des angezeigten Formulars. Die Seite trägt ihre eigenen Sprachlinks, Browser prefetchen und prerendern sie, und diese zweite Anfrage genügte, damit das sichtbare Formular ein Token hielt, zu dem das Cookie nicht mehr passte — deshalb konnte sich ein Betreiber, der nichts falsch gemacht hatte, nicht anmelden, so oft er auch neu lud. Eine zweite Registerkarte, eine Zurück-Navigation und ein fremdes `<img>` auf den Endpunkt taten dasselbe. Das Token, das ein Browser erhält, wird jetzt bis zu seinem Ablauf wiederverwendet; der Schutz ist unverändert: 24 Zufallsbytes in einem host-only gesetzten Cookie mit HttpOnly, Secure und SameSite=Strict, das keine andere Seite lesen oder setzen kann.
  * **Ein abgelaufenes Anmeldeformular endet nicht mehr in einer Sackgasse.** Es war eine nackte `403 request rejected`, die weder Ursache noch Ausweg nannte. Die Ablehnung selbst ist unverändert — ohne passendes Token wird nichts authentifiziert und kein Passwort gelesen —, aber ein veraltetes Formular führt jetzt auf ein frisches mit einer Erklärung in allen vier Sprachen, und die Lebensdauer beträgt eine Stunde.
  * **Der Ablehnungsgrund wird genau einmal gezeigt.** Er reiste in der Query und war damit eine Eigenschaft der Adresse statt des Ereignisses: Ein Neuladen — oder die Rückkehr aus dem Verlauf — wiederholte „Diese Anmeldeseite war abgelaufen" über einem Formular, das gerade frisch ausgestellt und gültig war. Jetzt reist er in einem Einmal-Cookie, das die Seite verbraucht.
  * **Ablehnungen am Gateway sind diagnostizierbar.** Das Log hält den Grund fest, den Fingerabdruck des erwarteten und des eingegangenen Tokens und welche Cookies ankamen — niemals einen Tokenwert.
  * **Die Anmeldeseite wurde neu komponiert** um die Tatsachen, die dieser Host vor jeder Anmeldung bezeugen kann, mit eingebetteter statt in CSS gezeichneter Produktmarke.
  * **Die Authentifizierungsoberfläche des Dashboards** sagt, was der Host bezeugt, und prüft einen Schlüssel gegen die Kontrollplane, bevor sie behauptet, eine Sitzung sei autorisiert.
  * **Protection Center und Navigation:** eine Überschrift, die die Statuspille wiederholte, ein Knopf, der Navigation versprach und nichts tat, ein dauerhaft rot leuchtender Not-Aus neben der Hauptaktion, ein Dollarzeichen als Navigationssymbol und ein doppeltes Schild.
* **Übersetzungen:**
  * **58 Schlüssel existierten nur auf Deutsch,** sodass Betreiber, die Englisch, Russisch oder Chinesisch lesen, rohe Schlüsselbezeichner über das Durchsetzungspanel, den Evidenzhinweis und die Neustart-Oberfläche sahen. Die Abdeckung ist jetzt eine Eigenschaft je Katalog, und `t()`-Aufrufstellen werden ebenso geprüft wie Dokumentattribute.

### v4.2.0 — Security Fabric Control Plane

* **Vollständige Behebung des Sicherheits-Audits & Härtung:**
  * **Kritisch:** Beseitigung der Symlink-Traversal-Schwachstelle im Canary-Deployment (willkürliches Dateischreiben / Root-Privilege-Escalation) via komponentenweiser `openat(2)`-Auflösung mit `O_NOFOLLOW|O_DIRECTORY` und `ELOOP`-Erzwingung.
  * **Hoch:** Ersatz von Information-Disclosure-Lecks durch typisierte, opake Fehlerantworten bei 5 API-Handlern; strukturelle Entkopplung statt unvollständiger Wort-Blacklists.
  * **Hoch:** Fail-Closed CSPRNG (`log.Fatalf`) verhindert vorhersagbare Zeitstempel-IDs für Incidents, Quarantäne und Blöcke.
  * **Hoch:** Remote-Panic im Settings-Import-Preview durch Fail-Closed-Schlüsselerzeugung behoben.
  * **Hoch:** Import-Token sind kryptografisch an den geprüften Inhalt gebunden (verhindert Token-Kollisionen).
  * **Mittel:** Crash-sicherer atomarer Writer (`atomicWriteFile`) für Policy, Feeds und Chronos mit Symlink-Ablehnung und `fsync`.
  * **Mittel:** `unsafe-inline` Styles aus der Content Security Policy verbannt; HSTS ausschließlich über TLS.
* **Security Fabric Control Plane:**
  * 12 administrierbare Module (`kinetic`, `network`, `protection`, `xdr`, `l7`, `threat_intel`, `hardening`, `integrity`, `boot_trust`, `policy_trust`, `forensics`, `system`).
  * Server-authoritatives Schema, unveränderliche Snapshots auf heißen Pfaden, persistierte `restart_required`-Semantik.
  * Nicht-administrierbare Sicherheitsinvarianten: Kernel-Maps, Core-Auth, Private-Key-Geheimhaltung, Management-Self-Lockout, Feed-Anti-Poisoning.
* **Control-Plane Workbench & Telemetrie:**
  * Deterministische Settings-Suche (`GET /api/v1/settings/search`) mit Live-Werten und Trefferbegründung.
  * Kryptografisch signierter, geheimnisfreier Settings-Export (`POST /api/v1/settings/export`).
  * Echter zweistufiger Import (`/import/preview` + `/import/apply`) mit Diff-Analyse und Einmal-Tokens.
  * Kontinuierliche Drift-Erkennung (`GET /api/v1/settings/drift`) signalisiert `CONFIG_DRIFT`.
* **Vendorte Offline-SVG-Weltkarte (jsVectorMap 1.7.0):**
  * 100% lokales Rendern ohne CDN oder Kachelserver; native Buttons gewährleisten vollständige Konformität mit `require-trusted-types-for 'script'`.
  * Lokale GeoIP/ASN-Auflösung, Choropleth-Dichteanzeige, Live-Marker und Traffic-Puls.
* **UI/UX Supreme — Modernes Dashboard-Design:**
  * Kartenraster eliminiert; semantische `<dl>`-Datenbänder mit Haarlinien-Trennern.
  * Reine Zustandsfarben, Barrierefreiheit (WCAG AA), echte Tastatur-Controls (`<button>`) und Unterstützung für `prefers-reduced-motion`.
* **Laufzeit- und Engine-Fixes:**
  * Deadlock in `CaseEngine.Status` behoben.
  * Fail-Open im Airlock-Inspektor und in der CaseEngine beseitigt.
  * Route `GET /assets/{name...}` für mehrstufige Pfade korrigiert.
  * Toolchain-Sicherheitsboden auf Go ≥ 1.26.6 angehoben (behebt 6 Standardbibliothek-CVEs).

### v4.0.1 — Chinesische Lokalisierung, Dedizierter XDR-Kernel-Recovery-Tab & Erweiterung des Startbildschirms

- **Lokalisierung für vereinfachtes Chinesisch (`zh-CN` / `ZH`):** Vollständige Übersetzung des Command Centers über alle Tabs, Dialoge, Operationen, Platzhalter und Laufzeit-Toasts (743 Schlüssel, 100% Parität zu DE, EN, RU). Chinesische Sprachauswahl und lokalisierte Texte auf dem öffentlichen Access Gateway Startbildschirm hinzugefügt.
- **Dedizierter XDR-Kernel-Recovery-Tab:** Eigener Wiederherstellungs-Tab `#xdr` und Endpunkt `/api/v1/xdr/recovery` mit `ARCHIVE_AND_REINITIALIZE_XDR`-Bestätigungsschranke zur Inspektion degradierter Ledger-Zustände, Archivierung beschädigter Ketten mit kryptografischen SHA-256-Manifesten und sicheren Re-Initialisierung von Kernel-eBPF-Sensoren und Maps direkt aus dem Dashboard.
- **Trennung der Ledger-Hash-Domänen:** Eigenständiges `evidence_root`-Feld für Angriffs-Merkle-Bäume und `record_hash` für die HMAC-Vorfallskette, wodurch fälschliche Degradierungen beim Daemon-Neustart verhindert werden.
- **Versionsabgleich:** Alle Binaries, Access Gateway, Web-UI, Integrationsverträge, Rust-Workspace und Paketierungsmanifeste auf `4.0.1` aktualisiert.

### v4.0.0-beta.1 — Native L7-Anwendungssicherheit & Korrelationshärtung

**L7-Anwendungssicherheitsebene (WAF & API Gateway)**

- **Implementierung in der Go-Standardbibliothek:** Integrierte L7-Inspektions-Engine direkt im unprivilegierten Go Control Daemon (`gedefense-control`). 100% CGO-frei, null Drittanbieter-Abhängigkeiten und null Hilfsskript-Engines (kein Lua, WASM oder Node.js).
- **Dual-Mode Bereitstellungsarchitektur:**
  - *Advisory / Standalone Socket:* Unix-Socket im Modus `0660` (`/run/vgt-gedefense-l7/inspect.sock`) mit strukturierter JSON-Evaluierungs-API (`POST /v1/inspect`) und strikter Validierung (`DisallowUnknownFields`) für externe Reverse Proxies (nginx, Caddy, Envoy, Apache).
  - *Natives Inline Reverse-Proxy-Gate:* Transparentes Inline-Filter (`/run/vgt-gedefense-l7/edge.sock`) direkt zwischen TLS-Terminierung und Backend-Anwendungen mit begrenzter Nebenläufigkeit und Fail-Closed-Budgets.
- **Strikte Upstream-Einsperrung (Anti-SSRF):** Inline-Weiterleitungsziele sind strikt auf saubere absolute Unix-Sockets oder explizite Loopback-IP-Literale (`127.0.0.1`, `[::1]`) beschränkt. Anfragegesteuertes Routing und DNS-Auflösung sind architektonisch unmöglich.
- **Begrenzte Normalisierungs- & Anti-Evasions-Engine:**
  - Mehrstufiges rekursives Unescaping (URL-Pfad und Query, HTML-Entities, `\uXXXX` und `\xXX` Escape-Sequenzen).
  - Unicode Fullwidth Fold (`\uff01`–`\uff5e` auf ASCII gefaltet), eliminiert Filter-Bypässe mit breiten asiatischen Zeichen.
  - Automatische Erkennung und Dekodierung von unpadded und URL-sicherem Base64 in Parametern.
  - Streaming-JSON-Parser mit Rekursionsbegrenzung (`max_json_depth = 32`) und Token-Budgets.
  - Begrenzte Gzip- und Deflate-Dekomprimierung via `io.LimitReader` (Schutz vor Zip-Bomben).
  - 16 KB überlappendes Chunking (256 Byte Überlappung) für Fließtext, verhindert Umgehung an Blockgrenzen ohne doppelte Allokation.
- **Vollständige Angriffserkennungs-Suite (Lineare RE2-Ausführung, Null ReDoS):**
  - *SQL Injection (SQLi):* UNION SELECT Syntax, boolesche Tautologien (`' OR 1=1`), Zeitverzögerungen (`pg_sleep`, `benchmark`, `waitfor delay`), gestapelte Queries.
  - *Cross-Site Scripting (XSS):* Ausführbare Script-Tags, Inline-Event-Handler (`onerror=`, `onload=`), gefährliche Schemata (`javascript:`, `data:text/html`), `iframe srcdoc`.
  - *Command Injection / RCE:* Shell-Verkettung (`;`, `&&`, `||`, `|`), Substitution (`$(...)`, Backticks), Windows/PowerShell-Befehlsketten.
  - *Path Traversal & LFI:* Traversal-Sequenzen (`../`, `..\`), sensible Pfade (`/etc/passwd`, `/proc/self/environ`), Stream-Wrapper (`php://`, `phar://`, `data://`).
  - *SSTI, XXE & Deserialisierung:* Server-Side-Template-Ausdrücke (Jinja, Twig, Smarty, Spring), externe XML-Entitäten (`SYSTEM`/`PUBLIC`), PHP-Objektserialisierung, Java-Serialisierungs-Magic (`rO0AB`), JNDI/Log4j.
  - *HTTP Request Smuggling & Framing-Anomalien:* Doppelte oder ungültige `Content-Length`, gleichzeitige `Content-Length` und `Transfer-Encoding` (CL.TE / TE.CL), blockierte `TRACE`-Methode.
- **Evasive SSRF-Abwehr mit flexibler IP-Normalisierung:**
  - Dekodiert und normalisiert alternative IPv4-Darstellungen: hexadezimal, oktal, dezimale DWORD-Ganzzahlen, 2-/3-teilige Punktnotationen.
  - Erzwingt Schutzbereiche gegen Loopback, Link-Local, private Netze und alle gängigen Cloud-Metadaten-Endpunkte (AWS IMDSv2, GCP, Azure, Alibaba, Oracle Cloud).
- **In-Memory Airlock Upload-Inspektion (`InspectBytes`):**
  - Multipart-Uploads werden vor dem Schreiben auf die Festplatte direkt im RAM analysiert.
  - Strikte Begrenzung von Part-Zahl und Dateigröße; Prüfung von Magic Bytes (ELF, PNG, JPEG, GIF, PDF, ZIP), MIME-Cross-Checks, doppelten Endungen (`.php.jpg`), Null-Byte-Injektionen und SHA-256-Blacklists.
- **3-stufiges geshardetes Token-Bucket Rate Limiting:**
  * 64 unabhängige Shards mit FNV-1a Hashing eliminieren Lock-Contention unter hoher Last.
  * Client-spezifisches Volumen-Rate-Limiting.
  * Routenspezifischer Schutz sensibler Endpunkte (`/login`, `/wp-login.php`, `/api/login`) vor Brute-Force.
  * Globales Rate Limiting zum Schutz vor verteilten Botnetzen und Credential-Stuffing.
- **Response Data-Leak Prevention (DLP):**
  * Überwacht Upstream-Antworten auf Datenbankfehler (`SQLSTATE`), Quellcode-Leaks (`<?php`, `<jsp:`), Stacktraces und private Schlüssel (`BEGIN RSA PRIVATE KEY`).
  * Exakte Wire-Byte-Erhaltung: Antworten werden zerstörungsfrei gepuffert und unverändert gestreamt.

**XDR-Korrelation & Host-Integrität**

- **Web-Evidenz-Isolation (Anti-False-Positive-Barriere):** L7-Befunde tragen `AlertOnly: true` und `ResponseScore: 0`. Websignale allein können **niemals** autonome destruktive Prozesseindämmung (SIGKILL / SIGSTOP) auslösen; destruktive Aktionen erfordern stets unabhängige Kernel-Evidenz.
- **Trinity XDR 2.0 DAG-Integration:** L7-Ereignisse werden als Kausalgraphen-Knoten (`HTTP_REQUEST`, `HTTP_RESPONSE`) mit kryptografischer Merkle-Beweiskette erfasst.
- **Host-Netzwerk-Korrelation:** Echtzeit-Korrelation verbindet eingehende feindliche HTTP-Requests mit lokalen Linux-Sockets (`SO_PEERCRED` PID/UID/GID und `NetConnection` Remote-Tracking).
- **Gegatete Durchsetzung:** Inline-Blockierung ist erst aktiv, wenn das Release-Gate `Enforce` mit einem gesunden Core erreicht; andernfalls verbleibt der Verkehr sicher in `Observe`.

**Systemd, Linux DAC & Release-Härtung**

- Dedizierte Systemgruppe `gedefense-l7` und Laufzeitverzeichnis `/run/vgt-gedefense-l7` (Modus `0750`) via `systemd-tmpfiles`.
- Unix-Sockets mit Modus `0660` und authentifizierten Peer-Credentials (`SO_PEERCRED`).
- Gepinnte Go 1.27.4 Release-Toolchain, verifiziert durch AST-Sicherheitsaudit.
- 3 neue Fuzzing-Testsuiten in CI zur Verifikation von Normalisierer-Sicherheit, Response-Byte-Erhaltung und Upstream-Jail.

### v3.0.0-beta.1 — Universelle Linux-Integration

**Integration und Bereitstellung**

- Übernahme der portablen AstraeaOS-Readiness- und Privilegien-Verträge in den generischen Linux-Release.
- Paketmanager-Auflösung für APT, DNF/YUM, pacman und Zypper.
- Generische Polkit-Autorisierungsgrenze und systemd-Readiness-Helper hinzugefügt.
- Desktop-Launcher mit dediziertem Chromium-Profil und exaktem SPKI-Pin ohne Änderung des globalen Trust-Stores.
- SDDM-, ArchISO- und Gaia-Cells-Verhalten bleibt AstraeaOS-Hosts vorbehalten.

**Sicherheit und Korrektheit**

- SANs der Gateway-Zertifikate um `localhost`, `127.0.0.1` und `::1` erweitert.
- Malware-Reputations-Hash-Datenbank in Staging, Release-Payload, geschützte Konfiguration und Rollback integriert.
- Fail-closed Manifeste, Scan nach verbotenen Geheimnis-Markern, Symlink-Ablehnung und strikte Größenlimits.
- LF-Normalisierung und explizite Ausführungsrechte für Linux-Skripte.

**Release Engineering**

- Obligatorische Go Unit/Vet/Race/Fuzz und statische Sicherheits-Gates.
- Gepinnte Rust-Tests, Rust Core Release-Build und no_std eBPF-Build.
- Digest-gepinnte Ubuntu, Fedora, Arch und openSUSE Integrations-Jobs.
- GitHub Actions an unveränderliche 40-Zeichen Commit-IDs gebunden.
- Privilegierter Host-Workflow für bpffs, eBPF-Programme, NIC XDP, IPC/TLS, systemd, Polkit und Desktop.
- Deterministische Artefaktnamen und SHA-256-Prüfungen.

**Unverändertes Sicherheitsfundament**

- Getrennte Go Control Plane, Rust Response Core und Rust eBPF/XDP Data Plane bleiben das V6-Sicherheitsfundament.
- Observe → Canary → Enforce, Evidenz-Ledger, verschlüsselter Response Vault und reversible Härtung bleiben unverändert.

### v1.0.0-beta.5 — Vollständige Beta

Auszeichnung als vollständige Beta — Verteidigungskette funktional komplett und testbar. Installer 3.5.1 mit voller Gate-Sequenz (Build, Kernel-Verifier, XDP-Attach, IPC, Backend, TLS). Byte-identischer Quellspiegel. Volle Validierungsmatrix bestanden.

---

## 🔗 VGT-Ökosystem

| Werkzeug | Typ | Zweck |
|---|---|---|
| 🛡️ **VGT GeDefense** | **Linux Security Fabric** | Kernelnahe Verteidigung, XDR, verschlüsselte Evidenz — du bist hier |
| 🧠 **[VGT AETHEL](https://github.com/visiongaiatechnology/aethel)** | **Souveränes KI-Betriebssystem** | Lokale KI mit Betreiber-Governance |
| 🖥️ **[VGT WP-Desk](https://github.com/visiongaiatechnology/vgtdesk)** | **OS-Ebene / UX** | Gehärteter WordPress-Arbeitsbereich |
| ⚔️ **[VGT Sentinel](https://github.com/visiongaiatechnology/sentinelcom)** | **WAF / IDS** | Zero-Trust WordPress WAF |
| ⚡ **[VGT Auto-Punisher](https://github.com/visiongaiatechnology/vgt-auto-punisher)** | **IDS** | L4+L7 Hybrides IDS |
| 🔐 **[VGT Omega Vault](https://github.com/visiongaiatechnology/vgt-omega-vault)** | **Verschlüsselte Formulare** | AES-256-GCM WordPress Formular-Tresor |
| 🌐 **[GaiaCom](https://github.com/visiongaiatechnology/GaiaCom)** | **Kommunikation** | Post-Quanten föderierte E2EE-Plattform |
| 📊 **[VGT Dattrack](https://github.com/visiongaiatechnology/dattrack)** | **Analytik** | Souveräne lokale Analytik |

---

## 💙 Unterstütze die Mission

[![Donate](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal)](https://paypal.me/dergoldenelotus)

| Methode | Adresse |
|---|---|
| **PayPal** | [paypal.me/dergoldenelotus](https://paypal.me/dergoldenelotus) |
| **Bitcoin** | `bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm` |
| **ETH / USDT (ERC-20)** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |

---

## 📄 Lizenz

**AGPL-3.0-only · © 2026 VisionGaia Technology · Köln, Deutschland**

VGT GeDefense ist freie Software: Sie können sie unter den Bedingungen der GNU Affero General Public License weitergeben und/oder modifizieren, wie sie von der Free Software Foundation veröffentlicht wurde, ausschließlich Version 3. Jedes abgeleitete Werk oder netzwerkbasierte Modifikation muss unter derselben Lizenz veröffentlicht werden.

Enterprise-Bereitstellungen, TIER-0-Audits (VGT SafetySys™) und kommerzielle Ausnahmelizenzen: [visiongaiatechnology.de](https://visiongaiatechnology.de)

### 🗺️ Daten-Attribution & Lokale GeoIP / ASN Datenbank

GeDefense beinhaltet eine vollständig offline betriebene, lokal ausgewertete GeoIP- und Origin-ASN-Datenbank (`/var/lib/vgt/gedefense/geoip.csv`), die null Cloud-Laufzeitabfragen oder externe Telemetrie garantiert:

* **DB-IP Lite:** Dieses Produkt enthält GeoLite2- oder DB-IP Lite-Daten von DB-IP, verfügbar unter [https://db-ip.com/](https://db-ip.com/) unter der Creative Commons Attribution 4.0 International License (CC BY 4.0). Namensnennung / Attribution erforderlich.
* **Origin-ASN-Daten:** Origin-ASN-Zuordnungsdaten bereitgestellt von [sapics/ip-location-db](https://github.com/sapics/ip-location-db) unter der Public Domain Dedication and License (PDDL).

#### Aktualisierung der lokalen GeoIP-Datenbank

Sie können die lokale GeoIP-Datenbank jederzeit mit dem beiliegenden Updater-Skript aktualisieren und per Longest-Prefix-Match atomar einspielen:

```bash
# Lädt die neuesten DB-IP City und Origin-ASN Datensätze herunter, kompiliert eine < 128 MiB / < 1.000.000 Prefixe CSV und ersetzt /var/lib/vgt/gedefense/geoip.csv atomar
sudo python3 scripts/update-geoip-db.py /var/lib/vgt/gedefense/geoip.csv
```

---

### Drittanbieter-Lizenzen

Die Karte verwendet **jsVectorMap 1.7.0** (MIT, Copyright © 2020 Mustafa Omar; Weltkarte `world-merc.js`). Die Offline-Daten in `geoip.csv` basieren auf **iplocate/ip-address-databases** (CC BY-SA 4.0; Änderungen durch VisionGaia Technology) sowie DB-IP Lite (CC BY 4.0) und Origin-ASN-Daten von `sapics/ip-location-db` (PDDL). Vollständige Hinweise: [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).


<div align="center">

**VISIONGAIATECHNOLOGY – WE ARCHITECT THE FUTURE OF SECURITY.**

[![VGT](https://img.shields.io/badge/VisionGaia-Technology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

*VGT GeDefense 6.2.1 (V6) — Universelles Linux Sicherheitsgewebe // Rust eBPF/XDP Data Plane // Go Control Plane // Host XDR // Ed25519 Evidenz-Ledger // AES-256-GCM verschlüsselter Vault // Reversible Härtung // AstraeaOS-nativer Adapter // Getrennte Vertrauensdomänen // Keine Cloud-Control-Plane // AGPL-3.0-only // Linux x86_64*

</div>
