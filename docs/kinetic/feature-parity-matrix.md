# Feature-Parity-Matrix: Auto-Punisher → GeDefense 4.1 Kinetic Defense

**Status date:** 2026-10-07  
**Release state:** Source-level Release Candidate. Production certification requires the target-host gates in `docs/kinetic/release-candidate-status.md`.

This matrix describes **functional migration**, not a promise that the Auto-Punisher implementation was copied literally. Shell/AWK/iptables behavior is replaced by bounded eBPF/Rust/Go paths, signed policy transactions and evidence-gated response. A status of `LOCAL_PASS` means the locally executable Go/API/UI/security tests passed. It does **not** mean the target kernel, NIC, eBPF verifier or a real production traffic path has been verified.

## Status vocabulary

- `LOCAL_PASS`: implementation and locally executable regression/security tests pass.
- `LOCAL_PASS / TARGET_GATE_PENDING`: local behavior passes, but privileged Rust/eBPF/kernel/live-network proof remains mandatory.
- `LOCAL_PASS / TLS_PRODUCER_PENDING`: parser/rule behavior passes, but actual TLS coverage requires a trusted local ClientHello producer in the deployed traffic path.
- `SAFE_REPLACE`: the dangerous legacy behavior was intentionally replaced with a stricter evidence/policy model rather than copied exactly.
- `VERIFIED_ON_TARGET`: reserved for a target host after the privileged release gate passes. This repository checkpoint does not claim it.

## Parity matrix

| ID | Auto-Punisher capability | GeDefense 4.1 outcome | Primary implementation | Enforcement / safety model | Local evidence | Status |
|---|---|---|---|---|---|---|
| **K-01** | Single-IP threshold (`IP_THRESHOLD=35`) | Connection-attempt based per-source rate windows, established TCP data does not inflate attempts | `control/kinetic_engine.go`, eBPF ingress metadata | Response engine → signed `/32`/`/128` policy → kernel LPM map | `TestKineticSingleIPRateTrigger`, B13 corpus | `LOCAL_PASS / TARGET_GATE_PENDING` |
| **K-02** | Burst / velocity (`VELOCITY_LIMIT=15`) | Exact kernel-second attempt/SYN windows and burst rule | eBPF ingress + `NET.INGRESS.IP_VELOCITY` | Evidence/policy gated containment | velocity/kernel-window regressions | `LOCAL_PASS / TARGET_GATE_PENDING` |
| **K-03** | IPv4 `/24` aggregation (`RANGE_THRESHOLD=45`) | Bounded `/24` campaign aggregation with independent-source requirement | `control/kinetic_engine.go` | Automatic `/24` only with multi-source evidence and allowlist checks | subnet + B13 corpus + B07 response tests | `LOCAL_PASS / TARGET_GATE_PENDING` |
| **K-04** | IPv6 `/64` aggregation (`IPV6_SUB_THRESHOLD=55`) | Bounded normalized IPv6 `/64` aggregation | `control/kinetic_engine.go` | Automatic `/64` only with multi-source evidence | IPv6 subnet + B13 corpus | `LOCAL_PASS / TARGET_GATE_PENDING` |
| **K-05** | Broad IPv4 `/16` strike (`WIDE_RANGE_THRESHOLD=77`) | `/16` retained as campaign correlation only | `NET.INGRESS.WIDE_V4` | **SAFE_REPLACE:** automatic `/16` blocking prohibited | `TestKineticWideV4Aggregation`, broad-sector response rejection | `LOCAL_PASS / SAFE_REPLACE` |
| **K-06** | Scanner / dark-port punishment | Fast and low-and-slow portscan detection plus protected-service probes | exact bounded port tracking in `control/kinetic_engine.go` | Rule score + release/policy gate, no unconditional first-packet execution | B13 fast/slow scan corpus | `LOCAL_PASS / TARGET_GATE_PENDING` |
| **K-07** | Per-source port diversity | Exact bounded destination-port set, no modulo collisions | `IPTrackingBucket.PortsSeen`, max 64 ports/source | escalates to scan evidence | port collision + scan regressions | `LOCAL_PASS / TARGET_GATE_PENDING` |
| **K-08** | TCP flag sanity / legacy iptables hard drops | eBPF exports TCP flags; Go detects NULL/XMAS/SYN-RST style malformed combinations | eBPF metadata + `NET.INGRESS.MALFORMED_TCP` | **SAFE_REPLACE:** repeated/evidence-gated containment instead of broad legacy iptables rules | malformed TCP regressions | `LOCAL_PASS / TARGET_GATE_PENDING` |
| **K-09** | Missing/malformed/direct-IP SNI strikes | Bounded TLS parser and repeated invalid-SNI strike state | `control/l7_tls.go` | only repeated strong signal becomes containment eligible | B12 TLS tests/fuzz | `LOCAL_PASS / TLS_PRODUCER_PENDING` |
| **K-10** | Foreign SNI hostname | Allowed-domain normalization and foreign-SNI evidence | `TLS.SNI.FOREIGN` + repeated strike correlation | single foreign SNI is evidence; repeated strong signal can escalate | B12 foreign-SNI tests | `LOCAL_PASS / TLS_PRODUCER_PENDING` |
| **K-11** | Malicious JA3 list | Versioned local JA3 signature set with duplicate/permission/TOCTOU hardening | `control/l7_tls.go` | signature match is high-confidence network evidence | B12 fingerprint tests | `LOCAL_PASS / TLS_PRODUCER_PENDING` |
| **K-12** | JA3 structural spoof heuristic | JA3 profile expectations for ALPN/GREASE consistency | `TLS.JA3.STRUCTURAL_SPOOF` | correlation signal, not a process-kill authority | B12 parser/profile tests | `LOCAL_PASS / TLS_PRODUCER_PENDING` |
| **K-13** | TLS handshake velocity | Ratio-aware handshake flood detection, not bypassable by one HTTP request | `TLS.HANDSHAKE.FLOOD` | network containment only, response gated | B12 handshake flood tests | `LOCAL_PASS / TLS_PRODUCER_PENDING` |
| **K-14** | Fixed 24h bans | TTL profiles + repeat-offender backoff + deterministic expiry transaction | `control/kinetic_response.go`, `block_expiry.go` | signed policy and kernel rollback on failure | B07 + B13 signed-policy E2E | `LOCAL_PASS` |
| **K-15** | Executor rate limit (`MAX_STRIKES_PER_SEC=100`) | Bounded response token bucket | `KineticResponseEngine` | throttled actions are observable/suppressed | response rate-limit tests | `LOCAL_PASS` |
| **K-16** | Whitelist immunity | Central IPv4/IPv6/CIDR management allowlist, including overlap protection | engine + response + release gates | immutable before automatic single-IP/subnet action | B07/B13 allowlist tests | `LOCAL_PASS` |
| **K-17** | Prometheus exporter | Integrated `/metrics` includes Kinetic activity, pressure, kernel drops and response counters | `control/server.go` | loopback-only when remote dashboard exposure is enabled | `TestB14MetricsExposeKineticPressureAndResponseTruth` | `LOCAL_PASS` |
| **K-18** | Realtime terminal matrix | Consolidated bounded live API + Kinetic operator UI + local GeoIP/ASN world map | `kinetic_live.go`, `server.go`, `control/web/kinetic.js` | bounded source/event windows; completeness flags expose eviction/drop history | B08-B10 API/UI contracts | `LOCAL_PASS / TARGET_GATE_PENDING` |

## Additional 4.1 guarantees beyond Auto-Punisher

- Signed and encrypted network policy persistence.
- Evidence ledger for detection, containment, rollback and expiry.
- Separate Detection vs Enforcement state and explicit Sensor Coverage.
- Kernel/userspace transaction rollback and divergence detection.
- Threat Intelligence actions split into BLOCK, CORRELATE_ONLY and ANNOTATE_ONLY.
- Bounded IP, subnet, wide-sector, event and GeoIP cache state with explicit pressure counters.
- Consolidated live API with true server-side windows and bounded-history truth metadata.
- Local-only GeoIP/ASN enrichment and world map, with special-use addresses excluded from geographic attribution.
- L7/TLS coverage is never inferred merely from an enabled engine. A real producer must verify the traffic path.

## Target-host proof still required

No row becomes `VERIFIED_ON_TARGET` until all applicable privileged checks pass:

1. pinned Rust common/core tests and release build;
2. release eBPF build;
3. target-kernel verifier acceptance and XDP attach;
4. TC fallback attach/verifier parity on a qualified host;
5. authenticated Rust Core ingress health and RingBuf transport;
6. authorized external live containment proving packets are actually dropped;
7. 24h Observe/Canary soak with resource/pressure trends;
8. if TLS protection is required, a trusted local ClientHello producer with verified traffic coverage.
