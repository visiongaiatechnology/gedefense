# Roadmap after GeDefense Beta v3 (3.0.0-beta.1)

## 1.0 beta hardening

- wider kernel/NIC qualification matrix;
- signed binary release channel and reproducible vendored Rust builds;
- richer XDP counters and per-rule telemetry;
- fork/exit lifecycle events, cgroup socket telemetry and selected BPF-LSM
  enforcement after kernel compatibility qualification;
- signed offline rule-feed updates and a bounded YARA-compatible rule engine;
- isolated document/macro analysis in a disposable GaiaCell or MicroVM;
- atomic auto-quarantine for non-browser on-access findings after race-safe identity binding;
- isolated deception services and the native Gaia Cells runtime;
- nftables/aaPanel firewall integration without ad-hoc persistence;
- dashboard-driven update and rollback workflow;
- optional AF_XDP flow metadata inspection without TLS interception.

## 1.1

- multi-node private federation identity;
- signed threat-vector exchange;
- hybrid post-quantum authenticated transport;
- replay-safe node admission and revocation.

## Later

- Swarm/Mesh coordination and provider-aware traffic offloading after independent protocol and cryptography review.
