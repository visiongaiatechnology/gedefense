# VGT HardRed & ARES Benchmark Evidence (`GeDefense Linux 6.3.0`)

> **Methodology Disclosure:** These results were produced using the VGT-owned, open-source **[VGT HardRed (`RedHard`)](https://github.com/visiongaiatechnology/redhard)** harness (`HardRed 1.2` / `HardRed 1.3` + `REDHARD ARES`) on snapshot-isolated Ubuntu 24.04 Linux HWE 7.0 targets. They document reproducible internal engineering benchmarks — **not** an external third-party certification.

## Directory Layout
- [`hardred/`](hardred/) — Standard `HardRed 1.2` (`6.2.1` vs `6.3.0`) & full `HardRed 1.3` (`90.09 / PASS`) summary and CSV comparisons
- [`ares/`](ares/) — `ARES 1.2` (`86.90 / 96.68 / 93.46` + Self-Protection `90.00`) & `ARES 1.3` (`86.90 / 96.52 / 87.70`) dossiers and CSV comparisons
- [`antispyware/`](antispyware/) — Standardized `S16`–`S20` Anti-Spyware campaign matrix across all 7 contenders
- [`reports/`](reports/) — Full Markdown & interactive VGT Glass HTML dashboards
- [`raw-evidence/`](raw-evidence/) — Raw per-contender `scorecard.json`, `meta.json`, `.sarif.json`, `.ocsf.json`, ATT&CK layers, GoTestWAF summaries, and `ares_campaign` exports
