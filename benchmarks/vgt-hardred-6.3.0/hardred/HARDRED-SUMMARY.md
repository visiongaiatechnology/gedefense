# VGT HardRed 1.2 & 1.3 Comparison Summary

- **Attribution:** VGT-owned, reproducible open-source benchmark harness (`Ubuntu 24.04 HWE 7.0`, 4 vCPU, 4 GiB RAM) — not external third-party certification.
- **HardRed 1.2 (Baseline Suite):** GeDefense `6.2.1` (`94.73 / PASS`, Efficacy `95.88`, FP-Resilience `100.00`) vs. GeDefense `6.3.0` (`94.95 / PASS`, Efficacy `96.73`, FP-Resilience `100.00`).
- **HardRed 1.3 (Full Anti-Spyware S16–S20 + Clock Calibration Fix):** GeDefense `6.3.0` (`03j-gedefense-6.3.0-max`) **`90.09 / 100 · PASS`** vs. `oss-safeline` `56.41 · PASS`, `safeline` `50.41 · PASS`, `oss-stack` `47.87 · FAIL`, `wazuh` `47.72 · CONDITIONAL`, `crowdsec` `24.73 · FAIL`, `baseline` `46.01`.

Files: `hardred-1.2-comparison.csv`, `hardred-1.3-comparison.csv`.
