# VGT HardRed Test — Gesamtbericht, Ranking & Gewinner

**Erstellt (UTC):** 2026-11-26T16:15:36.442731+00:00  
**Methodik:** VGT HardRed Test (4-Achsen-Modell: Efficacy 45% · FP-Resilienz 20% · TTFA/Schadensbegrenzung 20% · Overhead 15%; strikte Trennung Detection vs. Prevention TPR/FPR)  

## Gesamtsieger: **GeDefense Linux 6.3.0 (EDR/Hardened Max)** (90.09 / 100 · Gate `PASS`)

## 1. Gesamt-Ranking & 4-Achsen-Matrix

| Rang | Sicherheitssystem | Kategorie | Gesamt (0-100) | Scope Coverage | In-Scope Eff. | Achse 1: Effektivität | Achse 2: FP-Resilienz | Achse 3: Latenz & Eindämmung | Achse 4: System-Overhead | Gate |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | **GeDefense Linux 6.3.0 (EDR/Hardened Max)** (`03j-gedefense-6.3.0-max`) | Full-Stack XDR + WAF + Anti-Spyware | **90.09** | 100.0% | 90.06 | 90.06 | 85.71 | 89.90 | 96.27 | `PASS` |
| 2 | **OSS Best-of-Breed + SafeLine WAF (SafeLine + Suricata IPS + Tetragon + ClamAV)** (`08-oss-safeline-max`) | Modular OSS Stack (SafeLine WAF + Suricata + Tetragon + ClamAV) | **56.41** | 90.9% | 55.02 | 55.02 | 100.00 | 36.39 | 29.17 | `PASS` |
| 3 | **Chaitin SafeLine WAF CE 9.4.7 (Max Strict Semantics + ACL)** (`07-safeline-max`) | Edge Web Application Firewall & HTTP ACL | **50.41** | 45.5% | 56.79 | 35.78 | 100.00 | 27.69 | 58.50 | `PASS` |
| 4 | **OSS Best-of-Breed (ModSec CRS + Suricata IPS + Tetragon + ClamAV)** (`06-oss-bestofbreed-max`) | Modular OSS Stack (ModSecurity CRS + Suricata + Tetragon + ClamAV) | **47.87** | 90.9% | 67.98 | 67.98 | 42.86 | 38.40 | 6.83 | `FAIL` |
| 5 | **Wazuh (Max Rules + FIM + Auditd + Active Response)** (`05-wazuh-max`) | Host IDS / SIEM / Rootcheck / FIM | **47.72** | 81.8% | 35.90 | 35.90 | 71.43 | 28.28 | 77.47 | `CONDITIONAL` |
| 6 | **CrowdSec (Max Collections + Bouncers + AppSec WAF)** (`04-crowdsec-max`) | Crowd IPS Bouncer + Log Engine + AppSec WAF | **24.73** | 36.4% | 51.66 | 31.77 | 0.00 | 18.53 | 44.88 | `FAIL` |
| Ref | **Baseline (Clean Ubuntu HWE 7.0 WebStack)** (`01b-target-webstack-hwe7`) | Unprotected Reference Target | **46.01** | 100.0% | 17.20 | 17.20 | 100.00 | 16.37 | 100.00 | `CONDITIONAL` |

## 1b. Two-Tier Capability & Scope Matrix (IN_SCOPE vs. NOT_IN_SCOPE / NOT_IMPLEMENTED)

| System | Scope Coverage | In-Scope Efficacy | S16 (eBPF/LKM) | S17 (io_uring) | S18 (Cred/Mem) | S19 (Cross-View) | S20 (Self-Integrity) |
|---|---:|---:|---|---|---|---|---|
| **gedefense** | 100.0% | 90.06 | `DETECTED_ONLY` (IN_SCOPE) | `DETECTED_ONLY` (IN_SCOPE) | `PREVENTED` (IN_SCOPE) | `PREVENTED` (IN_SCOPE) | `PREVENTED` (IN_SCOPE) |
| **oss-safeline** | 90.9% | 55.02 | `NO_DETECTION` (IN_SCOPE) | `NO_DETECTION` (IN_SCOPE) | `DETECTED_ONLY` (IN_SCOPE) | `DETECTED_ONLY` (NOT_IMPLEMENTED) | `NO_DETECTION` (IN_SCOPE) |
| **safeline** | 45.5% | 56.79 | `NOT_IN_SCOPE` (NOT_IN_SCOPE) | `NOT_IN_SCOPE` (NOT_IN_SCOPE) | `NOT_IN_SCOPE` (NOT_IN_SCOPE) | `NOT_IN_SCOPE` (NOT_IN_SCOPE) | `NO_DETECTION` (IN_SCOPE) |
| **oss-stack** | 90.9% | 67.98 | `NO_DETECTION` (IN_SCOPE) | `NO_DETECTION` (IN_SCOPE) | `DETECTED_ONLY` (IN_SCOPE) | `DETECTED_ONLY` (NOT_IMPLEMENTED) | `NO_DETECTION` (IN_SCOPE) |
| **wazuh** | 81.8% | 35.90 | `DETECTED_ONLY` (NOT_IMPLEMENTED) | `DETECTED_ONLY` (NOT_IMPLEMENTED) | `DETECTED_ONLY` (IN_SCOPE) | `DETECTED_ONLY` (IN_SCOPE) | `NO_DETECTION` (IN_SCOPE) |
| **crowdsec** | 36.4% | 51.66 | `NOT_IN_SCOPE` (NOT_IN_SCOPE) | `NOT_IN_SCOPE` (NOT_IN_SCOPE) | `NOT_IN_SCOPE` (NOT_IN_SCOPE) | `NOT_IN_SCOPE` (NOT_IN_SCOPE) | `NO_DETECTION` (IN_SCOPE) |
| **baseline** | 100.0% | 17.20 | `NO_DETECTION` (IN_SCOPE) | `NO_DETECTION` (IN_SCOPE) | `NO_DETECTION` (IN_SCOPE) | `NO_DETECTION` (IN_SCOPE) | `NO_DETECTION` (IN_SCOPE) |

## 2. Domänen-Vergleich (Detection TPR vs. Prevention TPR · FPR · TTFA)

| System | Domäne | Det TPR | Prev TPR | Det FPR | Prot FPR | Context (0-3) | Median TTFA (ms) | Damage Ratio | Score |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| gedefense | `hardred-waf` | 100.0% | 100.0% | 0.0% | 0.0% | 3.00 | 41.6 | — | **100.0** |
| gedefense | `hardred-netids` | 75.0% | 75.0% | 0.0% | 0.0% | 3.00 | 91.5 | — | **79.4** |
| gedefense | `hardred-endpoint` | 93.3% | 100.0% | 0.0% | 0.0% | 1.93 | 227.5 | 11.4% | **94.4** |
| gedefense | `hardred-antispyware` | 100.0% | 75.0% | 0.0% | 0.0% | 1.80 | 1010.9 | — | **84.8** |
| gedefense | `hardred-malware` | 100.0% | 100.0% | 100.0% | 0.0% | 1.67 | 47.3 | — | **88.1** |
| gedefense | `hardred-compliance` | 100.0% | 86.0% | 0.0% | 0.0% | 3.00 | — | — | **86.0** |
| oss-safeline | `hardred-waf` | 92.9% | 78.6% | 0.0% | 0.0% | 2.08 | 250.0 | — | **84.6** |
| oss-safeline | `hardred-netids` | 100.0% | 50.0% | 0.0% | 0.0% | 2.25 | 487.1 | — | **75.0** |
| oss-safeline | `hardred-endpoint` | 33.3% | 50.0% | 0.0% | 0.0% | 2.67 | 48.0 | 100.0% | **51.9** |
| oss-safeline | `hardred-antispyware` | 40.0% | 0.0% | 0.0% | 0.0% | 3.00 | 408.0 | — | **32.5** |
| oss-safeline | `hardred-malware` | 66.7% | 50.0% | 0.0% | 0.0% | 2.00 | 250.0 | — | **61.7** |
| oss-safeline | `hardred-compliance` | 15.0% | 15.0% | 0.0% | 0.0% | 2.00 | — | — | **15.0** |
| safeline | `hardred-waf` | 71.4% | 71.4% | 0.0% | 0.0% | 2.00 | 250.0 | — | **73.1** |
| safeline | `hardred-netids` | 50.0% | 0.0% | 0.0% | 0.0% | 2.00 | 969.9 | — | **32.9** |
| safeline | `hardred-endpoint` | 0.0% | 12.5% | 0.0% | 0.0% | 1.00 | 460.6 | 100.0% | **17.0** |
| safeline | `hardred-antispyware` | 0.0% | 0.0% | 0.0% | 0.0% | 0.00 | — | — | **7.5** |
| safeline | `hardred-malware` | 0.0% | 50.0% | 0.0% | 0.0% | 0.00 | — | — | **32.5** |
| safeline | `hardred-compliance` | 100.0% | 77.0% | 0.0% | 0.0% | 2.00 | — | — | **77.0** |
| oss-stack | `hardred-waf` | 100.0% | 92.9% | 12.5% | 12.5% | 2.00 | 250.0 | — | **92.5** |
| oss-stack | `hardred-netids` | 100.0% | 75.0% | 0.0% | 0.0% | 2.25 | 39.5 | — | **86.2** |
| oss-stack | `hardred-endpoint` | 40.0% | 50.0% | 0.0% | 0.0% | 2.71 | 91.5 | 100.0% | **54.5** |
| oss-stack | `hardred-antispyware` | 40.0% | 0.0% | 0.0% | 0.0% | 3.00 | 421.9 | — | **32.5** |
| oss-stack | `hardred-malware` | 100.0% | 100.0% | 0.0% | 0.0% | 2.00 | 250.0 | — | **96.7** |
| oss-stack | `hardred-compliance` | 100.0% | 80.0% | 0.0% | 0.0% | 3.00 | — | — | **80.0** |
| wazuh | `hardred-waf` | 0.0% | 0.0% | 0.0% | 0.0% | 0.00 | — | — | **7.5** |
| wazuh | `hardred-netids` | 25.0% | 25.0% | 0.0% | 0.0% | 2.00 | 874.6 | — | **34.8** |
| wazuh | `hardred-endpoint` | 53.3% | 12.5% | 50.0% | 0.0% | 1.89 | 443.4 | 100.0% | **36.2** |
| wazuh | `hardred-antispyware` | 80.0% | 0.0% | 0.0% | 0.0% | 2.00 | 613.3 | — | **44.2** |
| wazuh | `hardred-malware` | 66.7% | 0.0% | 100.0% | 0.0% | 2.00 | 20.2 | — | **31.7** |
| wazuh | `hardred-compliance` | 100.0% | 80.0% | 0.0% | 0.0% | 3.00 | — | — | **80.0** |
| crowdsec | `hardred-waf` | 0.0% | 100.0% | 12.5% | 12.5% | 1.00 | 5035.9 | — | **62.4** |
| crowdsec | `hardred-netids` | 25.0% | 0.0% | 50.0% | 50.0% | 2.00 | 785.6 | — | **19.8** |
| crowdsec | `hardred-endpoint` | 0.0% | 12.5% | 0.0% | 0.0% | 1.00 | 428.8 | 100.0% | **17.0** |
| crowdsec | `hardred-antispyware` | 0.0% | 0.0% | 0.0% | 0.0% | 0.00 | — | — | **7.5** |
| crowdsec | `hardred-malware` | 0.0% | 50.0% | 0.0% | 0.0% | 0.00 | — | — | **32.5** |
| crowdsec | `hardred-compliance` | 100.0% | 78.0% | 0.0% | 0.0% | 2.00 | — | — | **78.0** |
| baseline | `hardred-waf` | 0.0% | 0.0% | 0.0% | 0.0% | 0.00 | — | — | **7.5** |
| baseline | `hardred-netids` | 0.0% | 0.0% | 0.0% | 0.0% | 0.00 | — | — | **7.5** |
| baseline | `hardred-endpoint` | 0.0% | 12.5% | 0.0% | 0.0% | 1.00 | 749.0 | 100.0% | **17.0** |
| baseline | `hardred-antispyware` | 0.0% | 0.0% | 0.0% | 0.0% | 0.00 | — | — | **7.5** |
| baseline | `hardred-malware` | 0.0% | 0.0% | 0.0% | 0.0% | 0.00 | — | — | **7.5** |
| baseline | `hardred-compliance` | 100.0% | 78.0% | 0.0% | 0.0% | 2.00 | — | — | **78.0** |

## 3. System-Overhead, Durchsatz & Compliance-Posture

| System | HTTP RPS | HTTP p50 (ms) | HTTP p95 (ms) | HTTP p99 (ms) | Sysbench EPS | FIO IOPS | Security RSS (MiB) | Security CPU (%) | Lynis Index | Aktive LSMs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| gedefense | 648.8 | 11.28 | 20.59 | 20.59 | 91559.4 | 222.6 | 70.8 | 7.1% | 71 | lockdown, capability, landlock, yama, apparmor, bpf, ima, evm |
| oss-safeline | 220.8 | 30.86 | 50.61 | 51.64 | 89094.2 | 197.2 | 2510.7 | 32.9% | 0 | lockdown, capability, landlock, yama, apparmor, bpf, ima, evm |
| safeline | 381.9 | 16.74 | 37.94 | 39.74 | 71550.1 | 225.1 | 967.1 | 29.9% | 62 | lockdown, capability, landlock, yama, apparmor, bpf, ima, evm |
| oss-stack | 190.0 | 36.25 | 66.52 | 67.07 | 41993.7 | 152.9 | 1789.1 | 56.2% | 65 | lockdown, capability, landlock, yama, apparmor, bpf, ima, evm |
| wazuh | 444.3 | 16.05 | 26.32 | 33.50 | 53775.6 | 132.8 | 71.7 | 22.5% | 65 | lockdown, capability, landlock, yama, apparmor, bpf, ima, evm |
| crowdsec | 3.6 | 62.50 | 5000.55 | 5000.55 | 69437.4 | 180.1 | 341.1 | 27.0% | 63 | lockdown, capability, landlock, yama, apparmor, bpf, ima, evm |
| baseline | 462.2 | 15.73 | 24.30 | 26.21 | 88710.4 | 213.3 | 35.4 | 0.0% | 63 | lockdown, capability, landlock, yama, apparmor, bpf, ima, evm |

## 4. Gate-Bewertungen & Begründungen

- **GeDefense Linux 6.3.0 (EDR/Hardened Max)** (`PASS`): All AMTSO/WCP false-positive gates passed
- **OSS Best-of-Breed + SafeLine WAF (SafeLine + Suricata IPS + Tetragon + ClamAV)** (`PASS`): All AMTSO/WCP false-positive gates passed
- **Chaitin SafeLine WAF CE 9.4.7 (Max Strict Semantics + ACL)** (`PASS`): All AMTSO/WCP false-positive gates passed
- **OSS Best-of-Breed (ModSec CRS + Suricata IPS + Tetragon + ClamAV)** (`FAIL`): WAF Protection FPR 12.50% > 1% gate; Detection FPR elevated (EP=0.0%, WAF=12.5%, AS=0.0%)
- **Wazuh (Max Rules + FIM + Auditd + Active Response)** (`CONDITIONAL`): Detection FPR elevated (EP=50.0%, WAF=0.0%, AS=0.0%)
- **CrowdSec (Max Collections + Bouncers + AppSec WAF)** (`FAIL`): WAF Protection FPR 12.50% > 1% gate; Detection FPR elevated (EP=0.0%, WAF=12.5%, AS=0.0%)
- **Baseline (Clean Ubuntu HWE 7.0 WebStack)** (`CONDITIONAL`): Unprotected baseline control target

## 5. Einzeltest-Matrix (Ground Truth vs. Ist-Ergebnis)

| System | Case-ID | Domäne | Polarität | MITRE | Detected | Prevented | Context | TTFA (ms) | Damage | Evidenz |
|---|---|---|---|---|---|---|---|---:|---|---|
| gedefense | `WAF-BENIGN-01` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-02` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-03` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-04` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-05` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-06` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-07` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `WAF-BENIGN-08` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| gedefense | `NET-BENIGN-01` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `ok=6/6 blocked=0; none` |
| gedefense | `NET-BENIGN-02` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `tls_ok=4/4 blocked=0; none` |
| gedefense | `MAL-BENIGN-01` | `hardred-malware` | benign | `NONE` | YES | NO | 1/3 | 250.0 | — | `rc=0; xdr.memory_scrape_probe` |
| gedefense | `MAL-EICAR-DISK-01` | `hardred-malware` | attack | `T1027` | YES | YES | 1/3 | 108.8 | — | `disk=BLOCKED_INODE; xdr.credential_read_blocked, xdr.sec_crit_evidence, xdr.witness_priori` |
| gedefense | `MAL-EICAR-HTTP-01` | `hardred-malware` | attack | `T1105` | YES | YES | 3/3 | 47.3 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `MAL-NESTED-ARCHIVE-01` | `hardred-malware` | attack | `T1027.002` | YES | NO | 1/3 | 41.8 | — | `nested=WROTE 808; malware.execution_blocked` |
| gedefense | `EP-BENIGN-01` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true, "sha256": "5dcee1d66c49e929"}; none` |
| gedefense | `EP-BENIGN-02` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true}; none` |
| gedefense | `EP-FILELESS-MEMFD-01` | `hardred-endpoint` | attack | `T1620` | YES | YES | 3/3 | 250.0 | — | `rc=0, out={"probe": "memfd-exec", "target": "/proc/self/fd/3", "ok": false, "errno": "EPER` |
| gedefense | `EP-SHM-EXEC-01` | `hardred-endpoint` | attack | `T1059.004` | NO | YES | 1/3 | 351.0 | — | `rc=0, out={"probe": "shm-exec", "target": "/dev/shm/hardred-sandbox/shm_exec_test.sh", "ok` |
| gedefense | `EP-TMP-ELF-01` | `hardred-endpoint` | attack | `T1204.002` | YES | YES | 3/3 | 250.0 | — | `rc=0, out={"probe": "tmp-exec", "target": "/tmp/hardred-sandbox/tmpexec/untrusted_exec_tes` |
| gedefense | `EP-LPE-KERNEL-01` | `hardred-endpoint` | attack | `T1068` | YES | YES | 1/3 | 61.7 | — | `rc=0, out={"probe": "lpe-probe", "sctp_socket": {"attempted": true, "ok": false, "errno": ` |
| gedefense | `EP-RANSOM-AES-01` | `hardred-endpoint` | attack | `T1486` | YES | YES | 1/3 | 355.1 | 7/120 | `rc=4294967295, out={}; xdr.XDR.RANSOM_ENTROPY_BURST` |
| gedefense | `EP-RANSOM-STORM-01` | `hardred-endpoint` | attack | `T1485` | YES | YES | 1/3 | 144.1 | 100/600 | `rc=4294967295, out={}; xdr.XDR.RANSOM_RENAME_STORM` |
| gedefense | `EP-LINEAGE-CHILD-01` | `hardred-endpoint` | attack | `T1059` | YES | YES | 1/3 | 251.7 | 7/60 | `rc=4294967295, out={}; xdr.XDR.RANSOM_ENTROPY_BURST` |
| gedefense | `EP-C2-EGRESS-01` | `hardred-endpoint` | attack | `T1071.001` | YES | YES | 3/3 | 250.0 | — | `rc=28, out={}; STYX.POLICY_DROP` |
| gedefense | `EP-FALCO-01` | `hardred-endpoint` | attack | `T1003.008` | YES | NO | 1/3 | 220.5 | — | `rc=0, out={}; xdr.memory_scrape_probe, xdr.credential_read_blocked` |
| gedefense | `EP-FALCO-02` | `hardred-endpoint` | attack | `T1036` | YES | NO | 1/3 | 311.2 | — | `rc=0, out={}; xdr.symlink_over_sensitive` |
| gedefense | `EP-FALCO-03` | `hardred-endpoint` | attack | `T1055.008` | YES | NO | 1/3 | 176.2 | — | `rc=0, out={}; xdr.ptrace_attempt` |
| gedefense | `EP-ART-T1087` | `hardred-endpoint` | attack | `T1087.001` | YES | NO | 3/3 | 193.8 | — | `rc=0, out={}; xdr.alert, xdr.alert, xdr.alert, xdr-dag, xdr-dag` |
| gedefense | `EP-ART-T1059` | `hardred-endpoint` | attack | `T1059.004` | YES | NO | 3/3 | 227.5 | — | `rc=0, out={}; xdr.contain, xdr-dag` |
| gedefense | `EP-ART-T1053` | `hardred-endpoint` | attack | `T1053.003` | YES | NO | 3/3 | 98.9 | — | `rc=0, out={}; xdr.alert, xdr.contain, xdr.contain, xdr.alert, xdr.alert` |
| gedefense | `EP-ART-T1548` | `hardred-endpoint` | attack | `T1548.001` | YES | NO | 3/3 | 102.0 | — | `rc=0, out={}; xdr.alert, xdr.alert, xdr.alert, xdr-dag, xdr-dag` |
| gedefense | `AS-BENIGN-01` | `hardred-antispyware` | benign | `NONE` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=PREVENTED, rc=0, probe={"probe": "as-benign-control", "sandbox": "` |
| gedefense | `AS-S16-KERNEL-EBPF-01` | `hardred-antispyware` | attack | `T1014` | YES | NO | 1/3 | 990.8 | — | `scope=IN_SCOPE, outcome=DETECTED_ONLY, rc=0, probe={"probe": "as-ebpf-probe", "unpriv_bpf_` |
| gedefense | `AS-S17-IOURING-ASYNC-01` | `hardred-antispyware` | attack | `T1059` | YES | NO | 1/3 | 1083.7 | — | `scope=IN_SCOPE, outcome=DETECTED_ONLY, rc=0, probe={"probe": "as-io-uring-probe", "sandbox` |
| gedefense | `AS-S18-CRED-MEM-01` | `hardred-antispyware` | attack | `T1003.007` | YES | YES | 1/3 | 1923.7 | — | `scope=IN_SCOPE, outcome=PREVENTED, rc=0, probe={"probe": "as-cred-mem-probe", "sandbox": "` |
| gedefense | `AS-S19-CROSSVIEW-01` | `hardred-antispyware` | attack | `T1036.004` | YES | YES | 3/3 | 1010.9 | — | `scope=IN_SCOPE, outcome=PREVENTED, rc=0, probe={"probe": "as-crossview-probe", "sandbox": ` |
| gedefense | `AS-S20-SELFINTEGRITY-01` | `hardred-antispyware` | attack | `T1562.001` | YES | YES | 3/3 | 117.3 | — | `scope=IN_SCOPE, outcome=PREVENTED, rc=0, probe={"probe": "as-selfintegrity-probe", "checke` |
| gedefense | `WAF-SQLI-01` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 40.7 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-SQLI-02` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 33.9 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-SQLI-03` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 46.2 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-XSS-01` | `hardred-waf` | attack | `T1059.007` | YES | YES | 3/3 | 42.5 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-XSS-02` | `hardred-waf` | attack | `T1059.007` | YES | YES | 3/3 | 48.9 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-LFI-01` | `hardred-waf` | attack | `T1083` | YES | YES | 3/3 | 44.8 | — | `http=403; xdr.memory_scrape_probe, l7.block, L7, xdr-dag` |
| gedefense | `WAF-LFI-02` | `hardred-waf` | attack | `T1083` | YES | YES | 3/3 | 38.5 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-RCE-01` | `hardred-waf` | attack | `T1059.004` | YES | YES | 3/3 | 45.0 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-RCE-02` | `hardred-waf` | attack | `T1505.003` | YES | YES | 3/3 | 102.6 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-SSTI-01` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 34.2 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-XXE-01` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 34.3 | — | `http=None; xdr.egress_blocked, xdr.egress_blocked, xdr.egress_blocked, xdr.kinetic_block, ` |
| gedefense | `WAF-SSRF-01` | `hardred-waf` | attack | `T1552.005` | YES | YES | 3/3 | 36.6 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-SCAN-01` | `hardred-waf` | attack | `T1595.002` | YES | YES | 3/3 | 33.7 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `WAF-FAILOPEN-01` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 127.6 | — | `http=403; l7.block, L7, xdr-dag` |
| gedefense | `NET-BRUTE-HTTP-01` | `hardred-netids` | attack | `T1110.001` | YES | YES | 3/3 | 43.9 | — | `blocked_or_dropped=20/25; xdr.kinetic_block, kinetic.block_applied, l7.block, kinetic_stri` |
| gedefense | `NET-BRUTE-SSH-01` | `hardred-netids` | attack | `T1110.001` | NO | NO | 0/3 | — | — | `ssh_spray={'probe': 'ssh-spray', 'addr': '192.168.56.50:22', 'attempts': 18, 'auth_failed'` |
| gedefense | `NET-VELOCITY-01` | `hardred-netids` | attack | `T1499.002` | YES | YES | 3/3 | 91.5 | — | `blocked_or_dropped=192/240; xdr.memory_scrape_probe, xdr.egress_blocked, xdr.egress_blocke` |
| gedefense | `NET-PORTSCAN-01` | `hardred-netids` | attack | `T1046` | YES | YES | 3/3 | 106.4 | — | `post_scan_banned=True, open_blocked=True; xdr.kinetic_block, kinetic.block_applied, kineti` |
| oss-safeline | `WAF-BENIGN-01` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-safeline | `WAF-BENIGN-02` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-safeline | `WAF-BENIGN-03` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-safeline | `WAF-BENIGN-04` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-safeline | `WAF-BENIGN-05` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-safeline | `WAF-BENIGN-06` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-safeline | `WAF-BENIGN-07` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-safeline | `WAF-BENIGN-08` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-safeline | `NET-BENIGN-01` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `ok=6/6 blocked=0; none` |
| oss-safeline | `NET-BENIGN-02` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `tls_ok=4/4 blocked=0; none` |
| oss-safeline | `MAL-BENIGN-01` | `hardred-malware` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0; none` |
| oss-safeline | `MAL-EICAR-DISK-01` | `hardred-malware` | attack | `T1027` | YES | YES | 2/3 | 250.0 | — | `disk=QUARANTINED; clamav.onaccess.malware, clamav.onaccess.malware, clamav.onaccess.malwar` |
| oss-safeline | `MAL-EICAR-HTTP-01` | `hardred-malware` | attack | `T1105` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-safeline | `MAL-NESTED-ARCHIVE-01` | `hardred-malware` | attack | `T1027.002` | YES | NO | 2/3 | 250.0 | — | `nested=WROTE 810; clamav.onaccess.malware, clamav.onaccess.malware, clamav.onaccess.malwar` |
| oss-safeline | `EP-BENIGN-01` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true, "sha256": "5dcee1d66c49e929"}; none` |
| oss-safeline | `EP-BENIGN-02` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true}; none` |
| oss-safeline | `EP-FILELESS-MEMFD-01` | `hardred-endpoint` | attack | `T1620` | YES | NO | 3/3 | 18.2 | — | `rc=0, out={"probe": "memfd-exec", "target": "/proc/self/fd/3", "ok": true, "exit_code": 0,` |
| oss-safeline | `EP-SHM-EXEC-01` | `hardred-endpoint` | attack | `T1059.004` | YES | YES | 3/3 | 22.7 | — | `rc=0, out={"probe": "shm-exec", "target": "/dev/shm/hardred-sandbox/shm_exec_test.sh", "ok` |
| oss-safeline | `EP-TMP-ELF-01` | `hardred-endpoint` | attack | `T1204.002` | YES | YES | 3/3 | 18.1 | — | `rc=0, out={"probe": "tmp-exec", "target": "/tmp/hardred-sandbox/tmpexec/untrusted_exec_tes` |
| oss-safeline | `EP-LPE-KERNEL-01` | `hardred-endpoint` | attack | `T1068` | YES | YES | 3/3 | 73.3 | — | `rc=0, out={"probe": "lpe-probe", "sctp_socket": {"attempted": true, "ok": false, "errno": ` |
| oss-safeline | `EP-RANSOM-AES-01` | `hardred-endpoint` | attack | `T1486` | NO | NO | 0/3 | — | 120/120 | `rc=0, out={"probe": "aes-ransom", "sandbox": "/tmp/hardred-sandbox/aes", "requested_count"` |
| oss-safeline | `EP-RANSOM-STORM-01` | `hardred-endpoint` | attack | `T1485` | NO | NO | 0/3 | — | 600/600 | `rc=0, out={"probe": "rename-storm", "sandbox": "/tmp/hardred-sandbox/storm", "requested_co` |
| oss-safeline | `EP-LINEAGE-CHILD-01` | `hardred-endpoint` | attack | `T1059` | NO | NO | 0/3 | — | 60/60 | `rc=0, out={"probe": "child-kill-test", "sandbox": "/tmp/hardred-sandbox/child", "child_pid` |
| oss-safeline | `EP-C2-EGRESS-01` | `hardred-endpoint` | attack | `T1071.001` | NO | YES | 1/3 | 473.1 | — | `rc=7, out={}; none` |
| oss-safeline | `EP-FALCO-01` | `hardred-endpoint` | attack | `T1003.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| oss-safeline | `EP-FALCO-02` | `hardred-endpoint` | attack | `T1036` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| oss-safeline | `EP-FALCO-03` | `hardred-endpoint` | attack | `T1055.008` | YES | NO | 3/3 | 467.9 | — | `rc=0, out={}; hardred-kernel-network-surface/__x64_sys_ptrace` |
| oss-safeline | `EP-ART-T1087` | `hardred-endpoint` | attack | `T1087.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| oss-safeline | `EP-ART-T1059` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| oss-safeline | `EP-ART-T1053` | `hardred-endpoint` | attack | `T1053.003` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| oss-safeline | `EP-ART-T1548` | `hardred-endpoint` | attack | `T1548.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| oss-safeline | `AS-BENIGN-01` | `hardred-antispyware` | benign | `NONE` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=PREVENTED, rc=0, probe={"probe": "as-benign-control", "sandbox": "` |
| oss-safeline | `AS-S16-KERNEL-EBPF-01` | `hardred-antispyware` | attack | `T1014` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-ebpf-probe", "unpriv_bpf_l` |
| oss-safeline | `AS-S17-IOURING-ASYNC-01` | `hardred-antispyware` | attack | `T1059` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-io-uring-probe", "sandbox"` |
| oss-safeline | `AS-S18-CRED-MEM-01` | `hardred-antispyware` | attack | `T1003.007` | YES | NO | 3/3 | 55.0 | — | `scope=IN_SCOPE, outcome=DETECTED_ONLY, rc=0, probe={"probe": "as-cred-mem-probe", "sandbox` |
| oss-safeline | `AS-S19-CROSSVIEW-01` | `hardred-antispyware` | attack | `T1036.004` | YES | NO | 3/3 | 761.0 | — | `scope=NOT_IMPLEMENTED, outcome=DETECTED_ONLY, rc=0, probe={"probe": "as-crossview-probe", ` |
| oss-safeline | `AS-S20-SELFINTEGRITY-01` | `hardred-antispyware` | attack | `T1562.001` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-selfintegrity-probe", "che` |
| oss-safeline | `WAF-SQLI-01` | `hardred-waf` | attack | `T1190` | YES | YES | 3/3 | 526.1 | — | `http=403; m_sqli, hardred-sensitive-files/security_file_open, hardred-kernel-network-surfa` |
| oss-safeline | `WAF-SQLI-02` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 250.0 | — | `http=403; m_sqli` |
| oss-safeline | `WAF-SQLI-03` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 250.0 | — | `http=403; m_sqli` |
| oss-safeline | `WAF-XSS-01` | `hardred-waf` | attack | `T1059.007` | YES | YES | 2/3 | 168.8 | — | `http=403; m_xss` |
| oss-safeline | `WAF-XSS-02` | `hardred-waf` | attack | `T1059.007` | YES | YES | 2/3 | 250.0 | — | `http=403; m_xss` |
| oss-safeline | `WAF-LFI-01` | `hardred-waf` | attack | `T1083` | YES | YES | 2/3 | 250.0 | — | `http=403; m_file_include` |
| oss-safeline | `WAF-LFI-02` | `hardred-waf` | attack | `T1083` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-safeline | `WAF-RCE-01` | `hardred-waf` | attack | `T1059.004` | YES | YES | 2/3 | 250.0 | — | `http=403; m_cmd_injection` |
| oss-safeline | `WAF-RCE-02` | `hardred-waf` | attack | `T1505.003` | YES | YES | 2/3 | 112.1 | — | `http=403; m_php_code_injection` |
| oss-safeline | `WAF-SSTI-01` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 24.0 | — | `http=403; m_ssti` |
| oss-safeline | `WAF-XXE-01` | `hardred-waf` | attack | `T1190` | YES | NO | 2/3 | 38.6 | — | `http=200; suricata:2066044` |
| oss-safeline | `WAF-SSRF-01` | `hardred-waf` | attack | `T1552.005` | YES | YES | 2/3 | 250.0 | — | `http=403; m_ssrf` |
| oss-safeline | `WAF-SCAN-01` | `hardred-waf` | attack | `T1595.002` | YES | NO | 2/3 | 50.6 | — | `http=200; suricata:2031502` |
| oss-safeline | `WAF-FAILOPEN-01` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 1.0 | — | `http=403; m_php_code_injection` |
| oss-safeline | `NET-BRUTE-HTTP-01` | `hardred-netids` | attack | `T1110.001` | YES | YES | 3/3 | 6.7 | — | `blocked_or_dropped=6/25; safeline/acl/block, suricata:2012888, suricata:2012888, suricata:` |
| oss-safeline | `NET-BRUTE-SSH-01` | `hardred-netids` | attack | `T1110.001` | YES | YES | 2/3 | 26.7 | — | `ssh_spray={'probe': 'ssh-spray', 'addr': '192.168.56.50:22', 'attempts': 18, 'auth_failed'` |
| oss-safeline | `NET-VELOCITY-01` | `hardred-netids` | attack | `T1499.002` | YES | NO | 2/3 | 947.4 | — | `blocked_or_dropped=0/240; safeline/acl/block, suricata:9100001, suricata:9100001, suricata` |
| oss-safeline | `NET-PORTSCAN-01` | `hardred-netids` | attack | `T1046` | YES | NO | 2/3 | 3387.7 | — | `post_scan_banned=False, open_blocked=False; suricata:9100001, suricata:9100001, suricata:9` |
| safeline | `WAF-BENIGN-01` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| safeline | `WAF-BENIGN-02` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| safeline | `WAF-BENIGN-03` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| safeline | `WAF-BENIGN-04` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| safeline | `WAF-BENIGN-05` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| safeline | `WAF-BENIGN-06` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| safeline | `WAF-BENIGN-07` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| safeline | `WAF-BENIGN-08` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| safeline | `NET-BENIGN-01` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `ok=6/6 blocked=0; none` |
| safeline | `NET-BENIGN-02` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `tls_ok=4/4 blocked=0; none` |
| safeline | `MAL-BENIGN-01` | `hardred-malware` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0; none` |
| safeline | `MAL-EICAR-DISK-01` | `hardred-malware` | attack | `T1027` | NO | NO | 0/3 | — | — | `disk=STILL_PRESENT; none` |
| safeline | `MAL-EICAR-HTTP-01` | `hardred-malware` | attack | `T1105` | NO | YES | 0/3 | — | — | `http=429; none` |
| safeline | `MAL-NESTED-ARCHIVE-01` | `hardred-malware` | attack | `T1027.002` | NO | NO | 0/3 | — | — | `nested=WROTE 806; none` |
| safeline | `EP-BENIGN-01` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true, "sha256": "5dcee1d66c49e929"}; none` |
| safeline | `EP-BENIGN-02` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true}; none` |
| safeline | `EP-FILELESS-MEMFD-01` | `hardred-endpoint` | attack | `T1620` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "memfd-exec", "target": "/proc/self/fd/3", "ok": true, "exit_code": 0,` |
| safeline | `EP-SHM-EXEC-01` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "shm-exec", "target": "/dev/shm/hardred-sandbox/shm_exec_test.sh", "ok` |
| safeline | `EP-TMP-ELF-01` | `hardred-endpoint` | attack | `T1204.002` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "tmp-exec", "target": "/tmp/hardred-sandbox/tmpexec/untrusted_exec_tes` |
| safeline | `EP-LPE-KERNEL-01` | `hardred-endpoint` | attack | `T1068` | NO | YES | 1/3 | 460.6 | — | `rc=0, out={"probe": "lpe-probe", "sctp_socket": {"attempted": true, "ok": true, "detail": ` |
| safeline | `EP-RANSOM-AES-01` | `hardred-endpoint` | attack | `T1486` | NO | NO | 0/3 | — | 120/120 | `rc=0, out={"probe": "aes-ransom", "sandbox": "/tmp/hardred-sandbox/aes", "requested_count"` |
| safeline | `EP-RANSOM-STORM-01` | `hardred-endpoint` | attack | `T1485` | NO | NO | 0/3 | — | 600/600 | `rc=0, out={"probe": "rename-storm", "sandbox": "/tmp/hardred-sandbox/storm", "requested_co` |
| safeline | `EP-LINEAGE-CHILD-01` | `hardred-endpoint` | attack | `T1059` | NO | NO | 0/3 | — | 60/60 | `rc=0, out={"probe": "child-kill-test", "sandbox": "/tmp/hardred-sandbox/child", "child_pid` |
| safeline | `EP-C2-EGRESS-01` | `hardred-endpoint` | attack | `T1071.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| safeline | `EP-FALCO-01` | `hardred-endpoint` | attack | `T1003.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| safeline | `EP-FALCO-02` | `hardred-endpoint` | attack | `T1036` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| safeline | `EP-FALCO-03` | `hardred-endpoint` | attack | `T1055.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| safeline | `EP-ART-T1087` | `hardred-endpoint` | attack | `T1087.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| safeline | `EP-ART-T1059` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| safeline | `EP-ART-T1053` | `hardred-endpoint` | attack | `T1053.003` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| safeline | `EP-ART-T1548` | `hardred-endpoint` | attack | `T1548.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| safeline | `AS-BENIGN-01` | `hardred-antispyware` | benign | `NONE` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=PREVENTED, rc=0, probe={"probe": "as-benign-control", "sandbox": "` |
| safeline | `AS-S16-KERNEL-EBPF-01` | `hardred-antispyware` | attack | `T1014` | NO | NO | 0/3 | — | — | `scope=NOT_IN_SCOPE, outcome=NOT_IN_SCOPE, rc=0, probe={"probe": "as-ebpf-probe", "unpriv_b` |
| safeline | `AS-S17-IOURING-ASYNC-01` | `hardred-antispyware` | attack | `T1059` | NO | NO | 0/3 | — | — | `scope=NOT_IN_SCOPE, outcome=NOT_IN_SCOPE, rc=0, probe={"probe": "as-io-uring-probe", "sand` |
| safeline | `AS-S18-CRED-MEM-01` | `hardred-antispyware` | attack | `T1003.007` | NO | NO | 0/3 | — | — | `scope=NOT_IN_SCOPE, outcome=NOT_IN_SCOPE, rc=0, probe={"probe": "as-cred-mem-probe", "sand` |
| safeline | `AS-S19-CROSSVIEW-01` | `hardred-antispyware` | attack | `T1036.004` | NO | NO | 0/3 | — | — | `scope=NOT_IN_SCOPE, outcome=NOT_IN_SCOPE, rc=0, probe={"probe": "as-crossview-probe", "san` |
| safeline | `AS-S20-SELFINTEGRITY-01` | `hardred-antispyware` | attack | `T1562.001` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-selfintegrity-probe", "che` |
| safeline | `WAF-SQLI-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| safeline | `WAF-SQLI-02` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 250.0 | — | `http=403; m_sqli` |
| safeline | `WAF-SQLI-03` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 250.0 | — | `http=403; m_sqli` |
| safeline | `WAF-XSS-01` | `hardred-waf` | attack | `T1059.007` | YES | YES | 2/3 | 122.4 | — | `http=403; m_xss` |
| safeline | `WAF-XSS-02` | `hardred-waf` | attack | `T1059.007` | YES | YES | 2/3 | 250.0 | — | `http=403; m_xss` |
| safeline | `WAF-LFI-01` | `hardred-waf` | attack | `T1083` | YES | YES | 2/3 | 25.0 | — | `http=403; m_file_include` |
| safeline | `WAF-LFI-02` | `hardred-waf` | attack | `T1083` | NO | NO | 0/3 | — | — | `http=200; none` |
| safeline | `WAF-RCE-01` | `hardred-waf` | attack | `T1059.004` | YES | YES | 2/3 | 250.0 | — | `http=403; m_cmd_injection` |
| safeline | `WAF-RCE-02` | `hardred-waf` | attack | `T1505.003` | YES | YES | 2/3 | 63.4 | — | `http=403; m_php_code_injection` |
| safeline | `WAF-SSTI-01` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 250.0 | — | `http=403; m_ssti` |
| safeline | `WAF-XXE-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| safeline | `WAF-SSRF-01` | `hardred-waf` | attack | `T1552.005` | YES | YES | 2/3 | 28.8 | — | `http=403; m_ssrf` |
| safeline | `WAF-SCAN-01` | `hardred-waf` | attack | `T1595.002` | NO | NO | 0/3 | — | — | `http=200; none` |
| safeline | `WAF-FAILOPEN-01` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 250.0 | — | `http=403; m_php_code_injection` |
| safeline | `NET-BRUTE-HTTP-01` | `hardred-netids` | attack | `T1110.001` | YES | NO | 2/3 | 1246.6 | — | `blocked_or_dropped=0/25; safeline/acl/block` |
| safeline | `NET-BRUTE-SSH-01` | `hardred-netids` | attack | `T1110.001` | NO | NO | 0/3 | — | — | `ssh_spray={'probe': 'ssh-spray', 'addr': '192.168.56.50:22', 'attempts': 18, 'auth_failed'` |
| safeline | `NET-VELOCITY-01` | `hardred-netids` | attack | `T1499.002` | YES | NO | 2/3 | 693.1 | — | `blocked_or_dropped=0/240; safeline/acl/block` |
| safeline | `NET-PORTSCAN-01` | `hardred-netids` | attack | `T1046` | NO | NO | 0/3 | — | — | `post_scan_banned=False, open_blocked=False; none` |
| oss-stack | `WAF-BENIGN-01` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-stack | `WAF-BENIGN-02` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-stack | `WAF-BENIGN-03` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-stack | `WAF-BENIGN-04` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-stack | `WAF-BENIGN-05` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-stack | `WAF-BENIGN-06` | `hardred-waf` | benign | `NONE` | YES | YES | 2/3 | 250.0 | — | `http=403; 942100` |
| oss-stack | `WAF-BENIGN-07` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-stack | `WAF-BENIGN-08` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| oss-stack | `NET-BENIGN-01` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `ok=6/6 blocked=0; none` |
| oss-stack | `NET-BENIGN-02` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `tls_ok=4/4 blocked=0; none` |
| oss-stack | `MAL-BENIGN-01` | `hardred-malware` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0; none` |
| oss-stack | `MAL-EICAR-DISK-01` | `hardred-malware` | attack | `T1027` | YES | YES | 2/3 | 250.0 | — | `disk=QUARANTINED; clamav.onaccess.malware, clamav.onaccess.malware, clamav.onaccess.malwar` |
| oss-stack | `MAL-EICAR-HTTP-01` | `hardred-malware` | attack | `T1105` | YES | YES | 2/3 | 250.0 | — | `http=403; 920420` |
| oss-stack | `MAL-NESTED-ARCHIVE-01` | `hardred-malware` | attack | `T1027.002` | YES | NO | 2/3 | 250.0 | — | `nested=WROTE 809; clamav.onaccess.malware, clamav.onaccess.malware, clamav.onaccess.malwar` |
| oss-stack | `EP-BENIGN-01` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true, "sha256": "5dcee1d66c49e929"}; none` |
| oss-stack | `EP-BENIGN-02` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true}; none` |
| oss-stack | `EP-FILELESS-MEMFD-01` | `hardred-endpoint` | attack | `T1620` | YES | NO | 3/3 | 13.7 | — | `rc=0, out={"probe": "memfd-exec", "target": "/proc/self/fd/3", "ok": true, "exit_code": 0,` |
| oss-stack | `EP-SHM-EXEC-01` | `hardred-endpoint` | attack | `T1059.004` | YES | YES | 3/3 | 21.3 | — | `rc=0, out={"probe": "shm-exec", "target": "/dev/shm/hardred-sandbox/shm_exec_test.sh", "ok` |
| oss-stack | `EP-TMP-ELF-01` | `hardred-endpoint` | attack | `T1204.002` | YES | YES | 3/3 | 18.2 | — | `rc=0, out={"probe": "tmp-exec", "target": "/tmp/hardred-sandbox/tmpexec/untrusted_exec_tes` |
| oss-stack | `EP-LPE-KERNEL-01` | `hardred-endpoint` | attack | `T1068` | YES | YES | 3/3 | 91.5 | — | `rc=0, out={"probe": "lpe-probe", "sctp_socket": {"attempted": true, "ok": false, "errno": ` |
| oss-stack | `EP-RANSOM-AES-01` | `hardred-endpoint` | attack | `T1486` | NO | NO | 0/3 | — | 120/120 | `rc=0, out={"probe": "aes-ransom", "sandbox": "/tmp/hardred-sandbox/aes", "requested_count"` |
| oss-stack | `EP-RANSOM-STORM-01` | `hardred-endpoint` | attack | `T1485` | NO | NO | 0/3 | — | 600/600 | `rc=0, out={"probe": "rename-storm", "sandbox": "/tmp/hardred-sandbox/storm", "requested_co` |
| oss-stack | `EP-LINEAGE-CHILD-01` | `hardred-endpoint` | attack | `T1059` | NO | NO | 0/3 | — | 60/60 | `rc=0, out={"probe": "child-kill-test", "sandbox": "/tmp/hardred-sandbox/child", "child_pid` |
| oss-stack | `EP-C2-EGRESS-01` | `hardred-endpoint` | attack | `T1071.001` | NO | YES | 1/3 | 576.4 | — | `rc=7, out={}; none` |
| oss-stack | `EP-FALCO-01` | `hardred-endpoint` | attack | `T1003.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| oss-stack | `EP-FALCO-02` | `hardred-endpoint` | attack | `T1036` | YES | NO | 3/3 | 250.0 | — | `rc=0, out={}; hardred-sensitive-files/security_file_open` |
| oss-stack | `EP-FALCO-03` | `hardred-endpoint` | attack | `T1055.008` | YES | NO | 3/3 | 192.3 | — | `rc=0, out={}; hardred-kernel-network-surface/__x64_sys_ptrace` |
| oss-stack | `EP-ART-T1087` | `hardred-endpoint` | attack | `T1087.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| oss-stack | `EP-ART-T1059` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| oss-stack | `EP-ART-T1053` | `hardred-endpoint` | attack | `T1053.003` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| oss-stack | `EP-ART-T1548` | `hardred-endpoint` | attack | `T1548.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| oss-stack | `AS-BENIGN-01` | `hardred-antispyware` | benign | `NONE` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=PREVENTED, rc=0, probe={"probe": "as-benign-control", "sandbox": "` |
| oss-stack | `AS-S16-KERNEL-EBPF-01` | `hardred-antispyware` | attack | `T1014` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-ebpf-probe", "unpriv_bpf_l` |
| oss-stack | `AS-S17-IOURING-ASYNC-01` | `hardred-antispyware` | attack | `T1059` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-io-uring-probe", "sandbox"` |
| oss-stack | `AS-S18-CRED-MEM-01` | `hardred-antispyware` | attack | `T1003.007` | YES | NO | 3/3 | 55.2 | — | `scope=IN_SCOPE, outcome=DETECTED_ONLY, rc=0, probe={"probe": "as-cred-mem-probe", "sandbox` |
| oss-stack | `AS-S19-CROSSVIEW-01` | `hardred-antispyware` | attack | `T1036.004` | YES | NO | 3/3 | 788.5 | — | `scope=NOT_IMPLEMENTED, outcome=DETECTED_ONLY, rc=0, probe={"probe": "as-crossview-probe", ` |
| oss-stack | `AS-S20-SELFINTEGRITY-01` | `hardred-antispyware` | attack | `T1562.001` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-selfintegrity-probe", "che` |
| oss-stack | `WAF-SQLI-01` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 250.0 | — | `http=403; 942100` |
| oss-stack | `WAF-SQLI-02` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 250.0 | — | `http=403; 942100` |
| oss-stack | `WAF-SQLI-03` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 250.0 | — | `http=403; 942100` |
| oss-stack | `WAF-XSS-01` | `hardred-waf` | attack | `T1059.007` | YES | YES | 2/3 | 250.0 | — | `http=403; 941100` |
| oss-stack | `WAF-XSS-02` | `hardred-waf` | attack | `T1059.007` | YES | YES | 2/3 | 250.0 | — | `http=403; 941100` |
| oss-stack | `WAF-LFI-01` | `hardred-waf` | attack | `T1083` | YES | YES | 2/3 | 32.7 | — | `http=None; suricata:9100001, suricata:9100001, suricata:9100001` |
| oss-stack | `WAF-LFI-02` | `hardred-waf` | attack | `T1083` | YES | YES | 2/3 | 250.0 | — | `http=403; 930100` |
| oss-stack | `WAF-RCE-01` | `hardred-waf` | attack | `T1059.004` | YES | YES | 2/3 | 250.0 | — | `http=403; 930120` |
| oss-stack | `WAF-RCE-02` | `hardred-waf` | attack | `T1505.003` | YES | YES | 2/3 | 250.0 | — | `http=403; 920420` |
| oss-stack | `WAF-SSTI-01` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 250.0 | — | `http=403; 920220` |
| oss-stack | `WAF-XXE-01` | `hardred-waf` | attack | `T1190` | YES | NO | 2/3 | 46.5 | — | `http=200; suricata:2066044` |
| oss-stack | `WAF-SSRF-01` | `hardred-waf` | attack | `T1552.005` | YES | YES | 2/3 | 28.9 | — | `http=None; suricata:9100001, suricata:9100001, suricata:9100001` |
| oss-stack | `WAF-SCAN-01` | `hardred-waf` | attack | `T1595.002` | YES | YES | 2/3 | 195.2 | — | `http=403; 913100, suricata:2031502` |
| oss-stack | `WAF-FAILOPEN-01` | `hardred-waf` | attack | `T1190` | YES | YES | 2/3 | 250.0 | — | `http=403; 920420` |
| oss-stack | `NET-BRUTE-HTTP-01` | `hardred-netids` | attack | `T1110.001` | YES | YES | 3/3 | 5.8 | — | `blocked_or_dropped=6/25; 920350, 920350, 920350, 920350, 920350` |
| oss-stack | `NET-BRUTE-SSH-01` | `hardred-netids` | attack | `T1110.001` | YES | YES | 2/3 | 43.9 | — | `ssh_spray={'probe': 'ssh-spray', 'addr': '192.168.56.50:22', 'attempts': 18, 'auth_failed'` |
| oss-stack | `NET-VELOCITY-01` | `hardred-netids` | attack | `T1499.002` | YES | NO | 2/3 | 1027.5 | — | `blocked_or_dropped=0/240; suricata:9100001, suricata:9100001, suricata:9100001, suricata:9` |
| oss-stack | `NET-PORTSCAN-01` | `hardred-netids` | attack | `T1046` | YES | YES | 2/3 | 35.1 | — | `post_scan_banned=False, open_blocked=True; suricata:9100001, suricata:9100001, suricata:91` |
| wazuh | `WAF-BENIGN-01` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-02` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-03` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-04` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-05` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-06` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-07` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-BENIGN-08` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `NET-BENIGN-01` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `ok=6/6 blocked=0; none` |
| wazuh | `NET-BENIGN-02` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `tls_ok=4/4 blocked=0; none` |
| wazuh | `MAL-BENIGN-01` | `hardred-malware` | benign | `NONE` | YES | NO | 2/3 | 31.9 | — | `rc=0; 554:File added to the system.` |
| wazuh | `MAL-EICAR-DISK-01` | `hardred-malware` | attack | `T1027` | YES | NO | 2/3 | 22.9 | — | `disk=STILL_PRESENT; 554:File added to the system.` |
| wazuh | `MAL-EICAR-HTTP-01` | `hardred-malware` | attack | `T1105` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `MAL-NESTED-ARCHIVE-01` | `hardred-malware` | attack | `T1027.002` | YES | NO | 2/3 | 17.6 | — | `nested=WROTE 813; 554:File added to the system.` |
| wazuh | `EP-BENIGN-01` | `hardred-endpoint` | benign | `NONE` | YES | NO | 2/3 | 606.1 | — | `rc=0, out={"ok": true, "sha256": "5dcee1d66c49e929"}; 554:File added to the system., 554:F` |
| wazuh | `EP-BENIGN-02` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true}; none` |
| wazuh | `EP-FILELESS-MEMFD-01` | `hardred-endpoint` | attack | `T1620` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "memfd-exec", "target": "/proc/self/fd/3", "ok": true, "exit_code": 0,` |
| wazuh | `EP-SHM-EXEC-01` | `hardred-endpoint` | attack | `T1059.004` | YES | NO | 2/3 | 110.2 | — | `rc=0, out={"probe": "shm-exec", "target": "/dev/shm/hardred-sandbox/shm_exec_test.sh", "ok` |
| wazuh | `EP-TMP-ELF-01` | `hardred-endpoint` | attack | `T1204.002` | YES | NO | 2/3 | 45.4 | — | `rc=0, out={"probe": "tmp-exec", "target": "/tmp/hardred-sandbox/tmpexec/untrusted_exec_tes` |
| wazuh | `EP-LPE-KERNEL-01` | `hardred-endpoint` | attack | `T1068` | NO | YES | 1/3 | 1043.3 | — | `rc=0, out={"probe": "lpe-probe", "sctp_socket": {"attempted": true, "ok": true, "detail": ` |
| wazuh | `EP-RANSOM-AES-01` | `hardred-endpoint` | attack | `T1486` | YES | NO | 2/3 | 170.8 | 120/120 | `rc=0, out={"probe": "aes-ransom", "sandbox": "/tmp/hardred-sandbox/aes", "requested_count"` |
| wazuh | `EP-RANSOM-STORM-01` | `hardred-endpoint` | attack | `T1485` | YES | NO | 2/3 | 164.0 | 600/600 | `rc=0, out={"probe": "rename-storm", "sandbox": "/tmp/hardred-sandbox/storm", "requested_co` |
| wazuh | `EP-LINEAGE-CHILD-01` | `hardred-endpoint` | attack | `T1059` | YES | NO | 2/3 | 3306.3 | 60/60 | `rc=0, out={"probe": "child-kill-test", "sandbox": "/tmp/hardred-sandbox/child", "child_pid` |
| wazuh | `EP-C2-EGRESS-01` | `hardred-endpoint` | attack | `T1071.001` | YES | NO | 2/3 | 750.0 | — | `rc=0, out={}; 554:File added to the system., 554:File added to the system.` |
| wazuh | `EP-FALCO-01` | `hardred-endpoint` | attack | `T1003.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| wazuh | `EP-FALCO-02` | `hardred-endpoint` | attack | `T1036` | YES | NO | 2/3 | 2885.3 | — | `rc=0, out={}; 554:File added to the system., 554:File added to the system., 554:File added` |
| wazuh | `EP-FALCO-03` | `hardred-endpoint` | attack | `T1055.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| wazuh | `EP-ART-T1087` | `hardred-endpoint` | attack | `T1087.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| wazuh | `EP-ART-T1059` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| wazuh | `EP-ART-T1053` | `hardred-endpoint` | attack | `T1053.003` | YES | NO | 2/3 | 443.4 | — | `rc=0, out={}; 2832:Crontab entry changed., 2832:Crontab entry changed.` |
| wazuh | `EP-ART-T1548` | `hardred-endpoint` | attack | `T1548.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| wazuh | `AS-BENIGN-01` | `hardred-antispyware` | benign | `NONE` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=PREVENTED, rc=0, probe={"probe": "as-benign-control", "sandbox": "` |
| wazuh | `AS-S16-KERNEL-EBPF-01` | `hardred-antispyware` | attack | `T1014` | YES | NO | 2/3 | 1249.5 | — | `scope=NOT_IMPLEMENTED, outcome=DETECTED_ONLY, rc=0, probe={"probe": "as-ebpf-probe", "unpr` |
| wazuh | `AS-S17-IOURING-ASYNC-01` | `hardred-antispyware` | attack | `T1059` | YES | NO | 2/3 | 66.4 | — | `scope=NOT_IMPLEMENTED, outcome=DETECTED_ONLY, rc=0, probe={"probe": "as-io-uring-probe", "` |
| wazuh | `AS-S18-CRED-MEM-01` | `hardred-antispyware` | attack | `T1003.007` | YES | NO | 2/3 | 70.8 | — | `scope=IN_SCOPE, outcome=DETECTED_ONLY, rc=0, probe={"probe": "as-cred-mem-probe", "sandbox` |
| wazuh | `AS-S19-CROSSVIEW-01` | `hardred-antispyware` | attack | `T1036.004` | YES | NO | 2/3 | 1155.7 | — | `scope=IN_SCOPE, outcome=DETECTED_ONLY, rc=0, probe={"probe": "as-crossview-probe", "sandbo` |
| wazuh | `AS-S20-SELFINTEGRITY-01` | `hardred-antispyware` | attack | `T1562.001` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-selfintegrity-probe", "che` |
| wazuh | `WAF-SQLI-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-SQLI-02` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-SQLI-03` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-XSS-01` | `hardred-waf` | attack | `T1059.007` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-XSS-02` | `hardred-waf` | attack | `T1059.007` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-LFI-01` | `hardred-waf` | attack | `T1083` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-LFI-02` | `hardred-waf` | attack | `T1083` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-RCE-01` | `hardred-waf` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-RCE-02` | `hardred-waf` | attack | `T1505.003` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-SSTI-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-XXE-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-SSRF-01` | `hardred-waf` | attack | `T1552.005` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-SCAN-01` | `hardred-waf` | attack | `T1595.002` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `WAF-FAILOPEN-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; none` |
| wazuh | `NET-BRUTE-HTTP-01` | `hardred-netids` | attack | `T1110.001` | NO | NO | 0/3 | — | — | `blocked_or_dropped=0/25; none` |
| wazuh | `NET-BRUTE-SSH-01` | `hardred-netids` | attack | `T1110.001` | YES | YES | 2/3 | 874.6 | — | `ssh_spray={'probe': 'ssh-spray', 'addr': '192.168.56.50:22', 'attempts': 18, 'auth_failed'` |
| wazuh | `NET-VELOCITY-01` | `hardred-netids` | attack | `T1499.002` | NO | NO | 0/3 | — | — | `blocked_or_dropped=0/240; none` |
| wazuh | `NET-PORTSCAN-01` | `hardred-netids` | attack | `T1046` | NO | NO | 0/3 | — | — | `post_scan_banned=False, open_blocked=False; none` |
| crowdsec | `WAF-BENIGN-01` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-BENIGN-02` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-BENIGN-03` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-BENIGN-04` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-BENIGN-05` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-BENIGN-06` | `hardred-waf` | benign | `NONE` | YES | YES | 2/3 | 419.6 | — | `http=403; anomaly score block: sql_injection: 10, anomaly: 13, ` |
| crowdsec | `WAF-BENIGN-07` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `WAF-BENIGN-08` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; none` |
| crowdsec | `NET-BENIGN-01` | `hardred-netids` | benign | `NONE` | YES | NO | 2/3 | 4210.7 | — | `ok=6/6 blocked=0; crowdsecurity/crowdsec-appsec-outofband, crowdsecurity/crowdsec-appsec-o` |
| crowdsec | `NET-BENIGN-02` | `hardred-netids` | benign | `NONE` | NO | YES | 0/3 | — | — | `tls_ok=0/4 blocked=4; none` |
| crowdsec | `MAL-BENIGN-01` | `hardred-malware` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0; none` |
| crowdsec | `MAL-EICAR-DISK-01` | `hardred-malware` | attack | `T1027` | NO | NO | 0/3 | — | — | `disk=STILL_PRESENT; none` |
| crowdsec | `MAL-EICAR-HTTP-01` | `hardred-malware` | attack | `T1105` | NO | YES | 0/3 | — | — | `http=None; none` |
| crowdsec | `MAL-NESTED-ARCHIVE-01` | `hardred-malware` | attack | `T1027.002` | NO | NO | 0/3 | — | — | `nested=WROTE 807; none` |
| crowdsec | `EP-BENIGN-01` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true, "sha256": "5dcee1d66c49e929"}; none` |
| crowdsec | `EP-BENIGN-02` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true}; none` |
| crowdsec | `EP-FILELESS-MEMFD-01` | `hardred-endpoint` | attack | `T1620` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "memfd-exec", "target": "/proc/self/fd/3", "ok": true, "exit_code": 0,` |
| crowdsec | `EP-SHM-EXEC-01` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "shm-exec", "target": "/dev/shm/hardred-sandbox/shm_exec_test.sh", "ok` |
| crowdsec | `EP-TMP-ELF-01` | `hardred-endpoint` | attack | `T1204.002` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "tmp-exec", "target": "/tmp/hardred-sandbox/tmpexec/untrusted_exec_tes` |
| crowdsec | `EP-LPE-KERNEL-01` | `hardred-endpoint` | attack | `T1068` | NO | YES | 1/3 | 428.8 | — | `rc=0, out={"probe": "lpe-probe", "sctp_socket": {"attempted": true, "ok": true, "detail": ` |
| crowdsec | `EP-RANSOM-AES-01` | `hardred-endpoint` | attack | `T1486` | NO | NO | 0/3 | — | 120/120 | `rc=0, out={"probe": "aes-ransom", "sandbox": "/tmp/hardred-sandbox/aes", "requested_count"` |
| crowdsec | `EP-RANSOM-STORM-01` | `hardred-endpoint` | attack | `T1485` | NO | NO | 0/3 | — | 600/600 | `rc=0, out={"probe": "rename-storm", "sandbox": "/tmp/hardred-sandbox/storm", "requested_co` |
| crowdsec | `EP-LINEAGE-CHILD-01` | `hardred-endpoint` | attack | `T1059` | NO | NO | 0/3 | — | 60/60 | `rc=0, out={"probe": "child-kill-test", "sandbox": "/tmp/hardred-sandbox/child", "child_pid` |
| crowdsec | `EP-C2-EGRESS-01` | `hardred-endpoint` | attack | `T1071.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-FALCO-01` | `hardred-endpoint` | attack | `T1003.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-FALCO-02` | `hardred-endpoint` | attack | `T1036` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-FALCO-03` | `hardred-endpoint` | attack | `T1055.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-ART-T1087` | `hardred-endpoint` | attack | `T1087.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-ART-T1059` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-ART-T1053` | `hardred-endpoint` | attack | `T1053.003` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `EP-ART-T1548` | `hardred-endpoint` | attack | `T1548.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; none` |
| crowdsec | `AS-BENIGN-01` | `hardred-antispyware` | benign | `NONE` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=PREVENTED, rc=0, probe={"probe": "as-benign-control", "sandbox": "` |
| crowdsec | `AS-S16-KERNEL-EBPF-01` | `hardred-antispyware` | attack | `T1014` | NO | NO | 0/3 | — | — | `scope=NOT_IN_SCOPE, outcome=NOT_IN_SCOPE, rc=0, probe={"probe": "as-ebpf-probe", "unpriv_b` |
| crowdsec | `AS-S17-IOURING-ASYNC-01` | `hardred-antispyware` | attack | `T1059` | NO | NO | 0/3 | — | — | `scope=NOT_IN_SCOPE, outcome=NOT_IN_SCOPE, rc=0, probe={"probe": "as-io-uring-probe", "sand` |
| crowdsec | `AS-S18-CRED-MEM-01` | `hardred-antispyware` | attack | `T1003.007` | NO | NO | 0/3 | — | — | `scope=NOT_IN_SCOPE, outcome=NOT_IN_SCOPE, rc=0, probe={"probe": "as-cred-mem-probe", "sand` |
| crowdsec | `AS-S19-CROSSVIEW-01` | `hardred-antispyware` | attack | `T1036.004` | NO | NO | 0/3 | — | — | `scope=NOT_IN_SCOPE, outcome=NOT_IN_SCOPE, rc=0, probe={"probe": "as-crossview-probe", "san` |
| crowdsec | `AS-S20-SELFINTEGRITY-01` | `hardred-antispyware` | attack | `T1562.001` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-selfintegrity-probe", "che` |
| crowdsec | `WAF-SQLI-01` | `hardred-waf` | attack | `T1190` | NO | YES | 1/3 | 5034.5 | — | `http=None; none` |
| crowdsec | `WAF-SQLI-02` | `hardred-waf` | attack | `T1190` | NO | YES | 1/3 | 5039.3 | — | `http=None; none` |
| crowdsec | `WAF-SQLI-03` | `hardred-waf` | attack | `T1190` | NO | YES | 1/3 | 5038.9 | — | `http=None; none` |
| crowdsec | `WAF-XSS-01` | `hardred-waf` | attack | `T1059.007` | NO | YES | 1/3 | 5036.3 | — | `http=None; none` |
| crowdsec | `WAF-XSS-02` | `hardred-waf` | attack | `T1059.007` | NO | YES | 1/3 | 5035.7 | — | `http=None; none` |
| crowdsec | `WAF-LFI-01` | `hardred-waf` | attack | `T1083` | NO | YES | 1/3 | 5030.3 | — | `http=None; none` |
| crowdsec | `WAF-LFI-02` | `hardred-waf` | attack | `T1083` | NO | YES | 1/3 | 5032.8 | — | `http=None; none` |
| crowdsec | `WAF-RCE-01` | `hardred-waf` | attack | `T1059.004` | NO | YES | 1/3 | 5032.4 | — | `http=None; none` |
| crowdsec | `WAF-RCE-02` | `hardred-waf` | attack | `T1505.003` | NO | YES | 1/3 | 5051.3 | — | `http=None; none` |
| crowdsec | `WAF-SSTI-01` | `hardred-waf` | attack | `T1190` | NO | YES | 1/3 | 5033.9 | — | `http=None; none` |
| crowdsec | `WAF-XXE-01` | `hardred-waf` | attack | `T1190` | NO | YES | 1/3 | 5037.3 | — | `http=None; none` |
| crowdsec | `WAF-SSRF-01` | `hardred-waf` | attack | `T1552.005` | NO | YES | 1/3 | 5031.2 | — | `http=None; none` |
| crowdsec | `WAF-SCAN-01` | `hardred-waf` | attack | `T1595.002` | NO | YES | 1/3 | 5036.1 | — | `http=None; none` |
| crowdsec | `WAF-FAILOPEN-01` | `hardred-waf` | attack | `T1190` | NO | YES | 1/3 | 8040.7 | — | `http=None; none` |
| crowdsec | `NET-BRUTE-HTTP-01` | `hardred-netids` | attack | `T1110.001` | NO | NO | 0/3 | — | — | `blocked_or_dropped=0/25; none` |
| crowdsec | `NET-BRUTE-SSH-01` | `hardred-netids` | attack | `T1110.001` | YES | NO | 2/3 | 785.6 | — | `ssh_spray={'probe': 'ssh-spray', 'addr': '192.168.56.50:22', 'attempts': 18, 'auth_failed'` |
| crowdsec | `NET-VELOCITY-01` | `hardred-netids` | attack | `T1499.002` | NO | NO | 0/3 | — | — | `blocked_or_dropped=0/240; none` |
| crowdsec | `NET-PORTSCAN-01` | `hardred-netids` | attack | `T1046` | NO | NO | 0/3 | — | — | `post_scan_banned=False, open_blocked=False; none` |
| baseline | `WAF-BENIGN-01` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-02` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-03` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-04` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-05` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-06` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-07` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-BENIGN-08` | `hardred-waf` | benign | `NONE` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `NET-BENIGN-01` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `ok=6/6 blocked=0; baseline unprotected webstack (no security daemon)` |
| baseline | `NET-BENIGN-02` | `hardred-netids` | benign | `NONE` | NO | NO | 0/3 | — | — | `tls_ok=4/4 blocked=0; baseline unprotected webstack (no security daemon)` |
| baseline | `MAL-BENIGN-01` | `hardred-malware` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0; baseline unprotected webstack (no security daemon)` |
| baseline | `MAL-EICAR-DISK-01` | `hardred-malware` | attack | `T1027` | NO | NO | 0/3 | — | — | `disk=STILL_PRESENT; baseline unprotected webstack (no security daemon)` |
| baseline | `MAL-EICAR-HTTP-01` | `hardred-malware` | attack | `T1105` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `MAL-NESTED-ARCHIVE-01` | `hardred-malware` | attack | `T1027.002` | NO | NO | 0/3 | — | — | `nested=WROTE 807; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-BENIGN-01` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true, "sha256": "5dcee1d66c49e929"}; baseline unprotected webstack (no se` |
| baseline | `EP-BENIGN-02` | `hardred-endpoint` | benign | `NONE` | NO | NO | 0/3 | — | — | `rc=0, out={"ok": true}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-FILELESS-MEMFD-01` | `hardred-endpoint` | attack | `T1620` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "memfd-exec", "target": "/proc/self/fd/3", "ok": true, "exit_code": 0,` |
| baseline | `EP-SHM-EXEC-01` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "shm-exec", "target": "/dev/shm/hardred-sandbox/shm_exec_test.sh", "ok` |
| baseline | `EP-TMP-ELF-01` | `hardred-endpoint` | attack | `T1204.002` | NO | NO | 0/3 | — | — | `rc=0, out={"probe": "tmp-exec", "target": "/tmp/hardred-sandbox/tmpexec/untrusted_exec_tes` |
| baseline | `EP-LPE-KERNEL-01` | `hardred-endpoint` | attack | `T1068` | NO | YES | 1/3 | 749.0 | — | `rc=0, out={"probe": "lpe-probe", "sctp_socket": {"attempted": true, "ok": true, "detail": ` |
| baseline | `EP-RANSOM-AES-01` | `hardred-endpoint` | attack | `T1486` | NO | NO | 0/3 | — | 120/120 | `rc=0, out={"probe": "aes-ransom", "sandbox": "/tmp/hardred-sandbox/aes", "requested_count"` |
| baseline | `EP-RANSOM-STORM-01` | `hardred-endpoint` | attack | `T1485` | NO | NO | 0/3 | — | 600/600 | `rc=0, out={"probe": "rename-storm", "sandbox": "/tmp/hardred-sandbox/storm", "requested_co` |
| baseline | `EP-LINEAGE-CHILD-01` | `hardred-endpoint` | attack | `T1059` | NO | NO | 0/3 | — | 60/60 | `rc=0, out={"probe": "child-kill-test", "sandbox": "/tmp/hardred-sandbox/child", "child_pid` |
| baseline | `EP-C2-EGRESS-01` | `hardred-endpoint` | attack | `T1071.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-FALCO-01` | `hardred-endpoint` | attack | `T1003.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-FALCO-02` | `hardred-endpoint` | attack | `T1036` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-FALCO-03` | `hardred-endpoint` | attack | `T1055.008` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-ART-T1087` | `hardred-endpoint` | attack | `T1087.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-ART-T1059` | `hardred-endpoint` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-ART-T1053` | `hardred-endpoint` | attack | `T1053.003` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `EP-ART-T1548` | `hardred-endpoint` | attack | `T1548.001` | NO | NO | 0/3 | — | — | `rc=0, out={}; baseline unprotected webstack (no security daemon)` |
| baseline | `AS-BENIGN-01` | `hardred-antispyware` | benign | `NONE` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=PREVENTED, rc=0, probe={"probe": "as-benign-control", "sandbox": "` |
| baseline | `AS-S16-KERNEL-EBPF-01` | `hardred-antispyware` | attack | `T1014` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-ebpf-probe", "unpriv_bpf_l` |
| baseline | `AS-S17-IOURING-ASYNC-01` | `hardred-antispyware` | attack | `T1059` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-io-uring-probe", "sandbox"` |
| baseline | `AS-S18-CRED-MEM-01` | `hardred-antispyware` | attack | `T1003.007` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-cred-mem-probe", "sandbox"` |
| baseline | `AS-S19-CROSSVIEW-01` | `hardred-antispyware` | attack | `T1036.004` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-crossview-probe", "sandbox` |
| baseline | `AS-S20-SELFINTEGRITY-01` | `hardred-antispyware` | attack | `T1562.001` | NO | NO | 0/3 | — | — | `scope=IN_SCOPE, outcome=NO_DETECTION, rc=0, probe={"probe": "as-selfintegrity-probe", "che` |
| baseline | `WAF-SQLI-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-SQLI-02` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-SQLI-03` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-XSS-01` | `hardred-waf` | attack | `T1059.007` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-XSS-02` | `hardred-waf` | attack | `T1059.007` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-LFI-01` | `hardred-waf` | attack | `T1083` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-LFI-02` | `hardred-waf` | attack | `T1083` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-RCE-01` | `hardred-waf` | attack | `T1059.004` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-RCE-02` | `hardred-waf` | attack | `T1505.003` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-SSTI-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-XXE-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-SSRF-01` | `hardred-waf` | attack | `T1552.005` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-SCAN-01` | `hardred-waf` | attack | `T1595.002` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `WAF-FAILOPEN-01` | `hardred-waf` | attack | `T1190` | NO | NO | 0/3 | — | — | `http=200; baseline unprotected webstack (no security daemon)` |
| baseline | `NET-BRUTE-HTTP-01` | `hardred-netids` | attack | `T1110.001` | NO | NO | 0/3 | — | — | `blocked_or_dropped=0/25; baseline unprotected webstack (no security daemon)` |
| baseline | `NET-BRUTE-SSH-01` | `hardred-netids` | attack | `T1110.001` | NO | NO | 0/3 | — | — | `ssh_spray={'probe': 'ssh-spray', 'addr': '192.168.56.50:22', 'attempts': 18, 'auth_failed'` |
| baseline | `NET-VELOCITY-01` | `hardred-netids` | attack | `T1499.002` | NO | NO | 0/3 | — | — | `blocked_or_dropped=0/240; baseline unprotected webstack (no security daemon)` |
| baseline | `NET-PORTSCAN-01` | `hardred-netids` | attack | `T1046` | NO | NO | 0/3 | — | — | `post_scan_banned=False, open_blocked=False; baseline unprotected webstack (no security dae` |
