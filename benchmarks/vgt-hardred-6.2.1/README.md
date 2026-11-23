# VGT HardRed Benchmark Results — GeDefense Linux 6.2.1 vs. OSS Stack, Wazuh & CrowdSec

**Run timestamp (UTC):** `2026-11-23T09:32:48Z`  
**Methodology:** VGT HardRed (`RedHard`) 4-axis security benchmark (`45%` Efficacy · `20%` FP Resilience · `20%` Latency & Containment · `15%` System Overhead) + VGT HardRed 1.2 (`REDHARD ARES`) adaptive triad benchmark on a snapshot-isolated **Ubuntu 24.04 (Linux HWE 7.0, NGINX + PHP 8.3-FPM)** target VM.

## Executive Summary

| Rank | Contender | Snapshot ID | Overall (0–100) | Efficacy (45%) | FP Resilience (20%) | Latency & Containment (20%) | Overhead (15%) | Gate |
|---:|---|---|---:|---:|---:|---:|---:|---|
| 1 | **GeDefense Linux 6.2.1 (`EDR/Hardened Max`)** | `03e-gedefense-6.2.1-edr-max` | **93.31** | 95.78 | 100.00 | 86.13 | 86.54 | `PASS` |
| 2 | **OSS Best-of-Breed (`ModSec CRS + Suricata IPS + Tetragon + ClamAV`)** | `06-oss-bestofbreed-max` | **55.40** | 76.27 | 38.46 | 38.91 | 37.35 | `FAIL` |
| 3 | **Wazuh (`Max Rules + FIM + Auditd + Active Response`)** | `05-wazuh-max` | **46.70** | 32.66 | 69.23 | 22.14 | 91.53 | `CONDITIONAL` |
| Ref | **Baseline (`Clean Ubuntu HWE 7.0 WebStack`)** | `01b-target-webstack-hwe7` | **46.23** | 17.86 | 100.00 | 15.97 | 100.00 | `CONDITIONAL` |
| 4 | **CrowdSec (`Max Collections + Bouncers + AppSec WAF`)** | `04-crowdsec-max` | **36.58** | 44.56 | 0.00 | 28.38 | 72.37 | `FAIL` |

## Primary Reports & Dashboards

- [`FINAL_BENCHMARK_REPORT.md`](FINAL_BENCHMARK_REPORT.md) — Full markdown report with 4-axis scores, per-domain TPR/FPR/TTFA breakdown, system overhead, and every individual test case (`hardred-waf`, `hardred-netids`, `hardred-endpoint`, `hardred-malware`, `hardred-compliance`).
- [`VGT_HardRed_Comparison.csv`](VGT_HardRed_Comparison.csv) — Machine-readable summary comparison table.
- [`VGT_HardRed_Dashboard.html`](VGT_HardRed_Dashboard.html) — Self-contained interactive HTML results dashboard.
- [`ares/FINAL_ARES_HYBRID_REPORT.md`](ares/FINAL_ARES_HYBRID_REPORT.md) — VGT HardRed 1.2 (`REDHARD ARES`) 3-pillar hybrid adversarial evaluation (Design `68.20` · Runtime `96.68` · Adaptive `93.46`, `36/36` chains interrupted).
- [`ares/VGT_HardRed_ARES_Dashboard.html`](ares/VGT_HardRed_ARES_Dashboard.html) & [`ares/VGT_HardRed_ARES_Comparison.csv`](ares/VGT_HardRed_ARES_Comparison.csv) — Interactive ARES HTML dashboard & CSV.

## Contender Raw Evidence Directories

Each contender directory contains its full `scorecard.json`, harness `meta.json`, MITRE ATT&CK Navigator layer (`*.attack_layer.json`), SARIF report (`*.sarif.json`), OCSF findings (`*.ocsf.json`), and `gotestwaf/` outputs where applicable:

- [`gedefense/`](gedefense/) — **GeDefense Linux 6.2.1 (`EDR/Hardened Max`)** (`93.31 / 100`, `PASS`, `88.4 MiB` RSS, `4.3%` CPU)
- [`oss-stack/`](oss-stack/) — **OSS Best-of-Breed (`ModSec CRS + Suricata IPS + Tetragon + ClamAV`)** (`55.40 / 100`, `FAIL` — `12.50%` WAF Protection FPR `> 1%` gate, `1,761.0 MiB` RSS, `57.3%` CPU)
- [`wazuh/`](wazuh/) — **Wazuh (`Max Rules + FIM + Auditd + Active Response`)** (`46.70 / 100`, `CONDITIONAL`)
- [`crowdsec/`](crowdsec/) — **CrowdSec (`Max Collections + Bouncers + AppSec WAF`)** (`36.58 / 100`, `FAIL`)
- [`baseline/`](baseline/) — **Baseline (`Clean Ubuntu HWE 7.0 WebStack`)** (`46.23 / 100`, `CONDITIONAL`)

> **Public Hygiene Note:** Local runner filesystem paths inside `meta.json` and `gotestwaf_report.json` were normalized to `<hardred-harness-root>`, and OCSF JSON-lines streams were normalized to `.ocsf.json` JSON arrays so release archive integrity and path-hygiene checks remain strict without altering any score, verdict, or telemetry measurement.
