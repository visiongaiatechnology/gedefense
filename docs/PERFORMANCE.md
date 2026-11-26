# GeDefense Linux 6.3.0 — Performance & System Overhead

> **Source:** VGT HardRed 1.3 Live Benchmark (`Ubuntu 24.04 Linux HWE 7.0`, `4 vCPU`, `4 GiB RAM`, NGINX + PHP 8.3-FPM) · [`../benchmarks/vgt-hardred-6.3.0/reports/FINAL_BENCHMARK_REPORT_1.3.md`](../benchmarks/vgt-hardred-6.3.0/reports/FINAL_BENCHMARK_REPORT_1.3.md)

---

## 1. Head-to-Head System Overhead Matrix (RedHard 1.3 · `03j`)

| Security Stack | HTTP RPS | p50 (ms) | p95 (ms) | p99 (ms) | Sysbench EPS | FIO IOPS | Security RSS (MiB) | Security CPU (%) | Lynis Index | Overhead Score (Axis 4) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **GeDefense Linux 6.3.0 (`03j`)** | **648.8** | **11.28** | **20.59** | **20.59** | **91,559.4** | 222.6 | **70.8** | **7.1%** | **71** | **96.27** |
| **OSS + SafeLine WAF** | 220.8 | 30.86 | 50.61 | 51.64 | 89,094.2 | 197.2 | 2,510.7 | 32.9% | — | 29.17 |
| **Chaitin SafeLine WAF CE 9.4.7** | 381.9 | 16.74 | 37.94 | 39.74 | 71,550.1 | **225.1** | 967.1 | 29.9% | 62 | 58.50 |
| **OSS Best-of-Breed** (`ModSec+Suricata+Tetragon+ClamAV`) | 190.0 | 36.25 | 66.52 | 67.07 | 41,993.7 | 152.9 | 1,789.1 | 56.2% | 65 | 6.83 |
| **Wazuh HIDS/SIEM** | 444.3 | 16.05 | 26.32 | 33.50 | 53,775.6 | 132.8 | 71.7 | 22.5% | 65 | 77.47 |
| **CrowdSec IPS/AppSec** | 3.6 | 62.50 | 5,000.55 | 5,000.55 | 69,437.4 | 180.1 | 341.1 | 27.0% | 63 | 44.88 |
| **Baseline (`Unprotected`)** | 462.2 | 15.73 | 24.30 | 26.21 | 88,710.4 | 213.3 | 35.4 | 0.0% | 63 | 100.00 |

---

## 2. Key Engineering Drivers Behind Low Overhead

- **Compiled Static-PIE Rust + Zero-CGO Go:** Eliminates JVM/Python/Docker-WAF memory footprints (`70.8 MiB` RSS vs. `1,789–2,511 MiB` on modular container/proxy OSS stacks).
- **In-Kernel eBPF/XDP Drops Prior to `sk_buff` Allocation:** Flood and scanner packets drop at the driver/XDP path rather than traversing userland IPS/proxy sockets.
- **256 KiB High-Priority `SEC_CRIT_EVENTS` Ring + Flood Token Buckets:** Telemetry spikes hit per-`(class, cgroup, uid)` rate budgets cleanly without waking heavy userspace parsing paths or starving critical evidence.
- **Symmetric TTFA Containment Latency (RedHard 1.3, VM-calibrated):**
  - `hardred-waf` median TTFA: **`41.6 ms`**
  - `hardred-malware` median TTFA: **`47.3 ms`**
  - `hardred-netids` median TTFA: **`91.5 ms`**
  - `hardred-endpoint` median TTFA: **`227.5 ms`** (`11.4%` ransomware pre-kill damage ratio)
