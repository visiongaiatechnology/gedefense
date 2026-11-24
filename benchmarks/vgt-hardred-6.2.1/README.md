# VGT HardRed Benchmark Results — GeDefense Linux 6.2.1 vs. OSS Stack, SafeLine WAF, Wazuh & CrowdSec

**Run timestamp (UTC):** `2026-11-24T00:28:34Z` (HardRed 4-Axis) · `2026-11-24T00:29:18Z` (REDHARD ARES 1.2)  
**Methodology:** VGT HardRed (`RedHard`) 4-axis security benchmark (`45%` Efficacy · `20%` FP Resilience · `20%` Latency & Containment · `15%` System Overhead) + VGT HardRed 1.2 (`REDHARD ARES`) 3-pillar adaptive triad benchmark on a snapshot-isolated **Ubuntu 24.04 (Linux HWE 7.0, NGINX + PHP 8.3-FPM)** target VM.

## Executive Summary (HardRed 4-Axis Benchmark)

| Rank | Contender | Snapshot ID | Overall (0–100) | Efficacy (45%) | FP Resilience (20%) | Latency & Containment (20%) | Overhead (15%) | Gate |
|---:|---|---|---:|---:|---:|---:|---:|---|
| 1 | **GeDefense Linux 6.2.1 (`EDR/Hardened Max`)** | `03f-gedefense-6.2.1-final-max` | **94.73** | **95.88** | **100.00** | **92.20** | **87.63** | **`PASS`** |
| 2 | **OSS Best-of-Breed + SafeLine WAF (`SafeLine + Suricata + Tetragon + ClamAV`)** | `08-oss-safeline-max` | **59.28** | 69.31 | 100.00 | 38.14 | 3.08 | `PASS` |
| 3 | **OSS Best-of-Breed (`ModSec CRS + Suricata IPS + Tetragon + ClamAV`)** | `06-oss-bestofbreed-max` | **55.40** | 76.27 | 38.46 | 38.91 | 37.35 | `FAIL` |
| 4 | **Chaitin SafeLine WAF CE 9.4.7 (`Max Strict Semantics + ACL`)** | `07-safeline-max` | **52.92** | 41.09 | 100.00 | 28.23 | 58.59 | `PASS` |
| 5 | **Wazuh (`Max Rules + FIM + Auditd + Active Response`)** | `05-wazuh-max` | **46.70** | 32.66 | 69.23 | 22.14 | 91.53 | `CONDITIONAL` |
| Ref | **Baseline (`Clean Ubuntu HWE 7.0 WebStack`)** | `01b-target-webstack-hwe7` | **46.23** | 17.86 | 100.00 | 15.97 | 100.00 | `CONDITIONAL` |
| 6 | **CrowdSec (`Max Collections + Bouncers + AppSec WAF`)** | `04-crowdsec-max` | **36.58** | 44.56 | 0.00 | 28.38 | 72.37 | `FAIL` |

## REDHARD ARES 1.2 Three-Pillar Summary (3 Seeds × 3 Adaptive Rounds)

| System | ARES Design Resilience | ARES Runtime Resilience | ARES Adaptive Resilience | Chains Interrupted | Ø Pre-Kill Damage | Verified E1 Citations | False Positives |
|---|---:|---:|---:|---:|---:|---:|---:|
| **GeDefense Linux 6.2.1** | **78.40** | **96.68** | **93.46** | **36/36** | **11.1%** | **177/177** | **0** |
| **OSS Best-of-Breed + SafeLine WAF** | 58.20 | 56.25 | 61.33 | 27/36 | 100.0% | 108/108 | 0 |
| **Chaitin SafeLine WAF CE 9.4.7** | 53.60 | 51.67 | 42.69 | 24/36 | 100.0% | 129/129 | 0 |
| **Wazuh HIDS/SIEM** | 65.10 | 15.42 | 27.78 | 3/36 | 100.0% | 123/123 | 3 |
| **CrowdSec IPS/CTI** | 59.80 | 51.67 | 42.25 | 24/36 | 100.0% | 153/153 | 0 |

### Key Highlights (`GeDefense 6.2.1` vs. `SafeLine` & `OSS+SafeLine`)
- **GeDefense 6.2.1 (`94.73 / PASS`):** Final signed `6.2.1` binaries (`03f-gedefense-6.2.1-final-max`) delivered **`17.8 ms`** median WAF TTFA, **`52.3 ms`** NetIDS TTFA, **`8.6%`** average ransomware damage ratio (`7/120` AES files, `50/600` wiper files, `7/60` lineage files), `525.0` HTTP RPS (`23.65 ms` p95), and **`88.4 MiB` RSS / `7.4%` CPU**. In REDHARD ARES 1.2, `FIND-G-001` is confirmed **REMEDIATED** (`CORE_QUARANTINE_ALLOWED_ROOTS`/`FORBIDDEN_ROOTS` in `decode_path()`), lifting ARES Design Resilience to **`78.40`** with **`177/177`** live-verified source citations.
- **Chaitin SafeLine WAF CE 9.4.7 (`52.92` Solo / `59.28` `OSS+SafeLine`):** `0.0%` benign FP (`PASS`), blocking `11/14` WAF attacks (`403`), but passing `WAF-LFI-02` (`..%252f`), `WAF-XXE-01`, `WAF-SCAN-01`, and `MAL-EICAR-HTTP-01` (`200 OK`), while consuming **`1,040.5 MiB` RSS / `48.1%` CPU** solo and **`2,614.7 MiB` RSS / `60.6%` CPU / `175.2` RPS** (`67.45 ms` p95) in `OSS+SafeLine`. In ARES 1.2 (`129/129` verified SafeLine Management citations), SafeLine scores **`53.60`** Design / **`51.67`** Runtime / **`42.69`** Adaptive (`24/36` chains stopped; closed-source C++ `safeline-detector` container images & single-SuperUser model without RBAC).

## Primary Reports & Dashboards

- [`FINAL_BENCHMARK_REPORT.md`](FINAL_BENCHMARK_REPORT.md) — Full markdown report with 4-axis scores, per-domain TPR/FPR/TTFA breakdown, system overhead, and every individual test case (`hardred-waf`, `hardred-netids`, `hardred-endpoint`, `hardred-malware`, `hardred-compliance`).
- [`VGT_HardRed_Comparison.csv`](VGT_HardRed_Comparison.csv) — Machine-readable summary comparison table.
- [`VGT_HardRed_Dashboard.html`](VGT_HardRed_Dashboard.html) — Self-contained interactive HTML results dashboard.
- [`ares/FINAL_ARES_HYBRID_REPORT.md`](ares/FINAL_ARES_HYBRID_REPORT.md) — VGT HardRed 1.2 (`REDHARD ARES`) 3-pillar hybrid adversarial evaluation (5 contenders, `690/690` verified citations).
- [`ares/VGT_HardRed_ARES_Dashboard.html`](ares/VGT_HardRed_ARES_Dashboard.html) & [`ares/VGT_HardRed_ARES_Comparison.csv`](ares/VGT_HardRed_ARES_Comparison.csv) — Interactive ARES HTML dashboard & CSV.

## Contender Raw Evidence Directories

- [`gedefense/`](gedefense/) — **GeDefense Linux 6.2.1 (`EDR/Hardened Max`)** (`94.73 / 100`, `PASS`, `88.4 MiB` RSS, `7.4%` CPU)
- [`oss-safeline/`](oss-safeline/) — **OSS Best-of-Breed + SafeLine WAF (`SafeLine + Suricata + Tetragon + ClamAV`)** (`59.28 / 100`, `PASS`, `2,614.7 MiB` RSS, `60.6%` CPU)
- [`oss-stack/`](oss-stack/) — **OSS Best-of-Breed (`ModSec CRS + Suricata IPS + Tetragon + ClamAV`)** (`55.40 / 100`, `FAIL` — `12.50%` WAF Protection FPR `> 1%` gate, `1,761.0 MiB` RSS, `57.3%` CPU)
- [`safeline/`](safeline/) — **Chaitin SafeLine WAF CE 9.4.7 (`Max Strict Semantics + ACL`)** (`52.92 / 100`, `PASS`, `1,040.5 MiB` RSS, `48.1%` CPU)
- [`wazuh/`](wazuh/) — **Wazuh (`Max Rules + FIM + Auditd + Active Response`)** (`46.70 / 100`, `CONDITIONAL`)
- [`crowdsec/`](crowdsec/) — **CrowdSec (`Max Collections + Bouncers + AppSec WAF`)** (`36.58 / 100`, `FAIL`)
- [`baseline/`](baseline/) — **Baseline (`Clean Ubuntu HWE 7.0 WebStack`)** (`46.23 / 100`, `CONDITIONAL`)

> **Public Hygiene Note:** Local runner filesystem paths inside `meta.json` and `gotestwaf_report.json` were normalized to `<hardred-harness-root>`, and OCSF JSON-lines streams were normalized to `.ocsf.json` JSON arrays so release archive integrity and path-hygiene checks remain strict without altering any score, verdict, or telemetry measurement.
