# VGT HardRed 1.3 Anti-Spyware Campaigns (S16–S20)

Evaluates `S16` (eBPF/LKM), `S17` (`io_uring`), `S18` (Credential/Process Memory), `S19` (CrossView Masquerading/Raw Tap/`LD_PRELOAD`), `S20` (Self-Integrity & 200-Event Flood Burst) plus `AS-BENIGN-01` (`0%` Protection-FPR gate).


| Contender | Domain Score | Det TPR | Prev TPR | Det FPR | Prot FPR | Median TTFA (ms) | S16 | S17 | S18 | S19 | S20 |
|---|---:|---:|---:|---:|---:|---:|---|---|---|---|---|
| **gedefense** | 84.8 | 100.0% | 75.0% | 0.0% | 0.0% | 1010.9 | `DETECTED_ONLY` | `DETECTED_ONLY` | `PREVENTED` | `PREVENTED` | `PREVENTED` |
| **oss-safeline** | 32.5 | 40.0% | 0.0% | 0.0% | 0.0% | 408.0 | `NO_DETECTION` | `NO_DETECTION` | `DETECTED_ONLY` | `DETECTED_ONLY` | `NO_DETECTION` |
| **safeline** | 7.5 | 0.0% | 0.0% | 0.0% | 0.0% | — | `NOT_IN_SCOPE` | `NOT_IN_SCOPE` | `NOT_IN_SCOPE` | `NOT_IN_SCOPE` | `NO_DETECTION` |
| **oss-stack** | 32.5 | 40.0% | 0.0% | 0.0% | 0.0% | 421.9 | `NO_DETECTION` | `NO_DETECTION` | `DETECTED_ONLY` | `DETECTED_ONLY` | `NO_DETECTION` |
| **wazuh** | 44.2 | 80.0% | 0.0% | 0.0% | 0.0% | 613.3 | `DETECTED_ONLY` | `DETECTED_ONLY` | `DETECTED_ONLY` | `DETECTED_ONLY` | `NO_DETECTION` |
| **crowdsec** | 7.5 | 0.0% | 0.0% | 0.0% | 0.0% | — | `NOT_IN_SCOPE` | `NOT_IN_SCOPE` | `NOT_IN_SCOPE` | `NOT_IN_SCOPE` | `NO_DETECTION` |
| **baseline** | 7.5 | 0.0% | 0.0% | 0.0% | 0.0% | — | `NO_DETECTION` | `NO_DETECTION` | `NO_DETECTION` | `NO_DETECTION` | `NO_DETECTION` |
