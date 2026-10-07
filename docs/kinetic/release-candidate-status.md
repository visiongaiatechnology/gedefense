# GeDefense 4.1 Kinetic Defense – Release Candidate Status

**Checkpoint class:** Source-level Release Candidate  
**Production certification:** **BLOCKED until target-host gates pass**  
**Date:** 2026-10-07

## Locally verified

The rework batches B00–B14 cover control-plane recovery, truthful telemetry, bounded kernel/userspace ingress structures, Rust-Core IPC contracts, Auto-Punisher functional migration, safe containment, live APIs, operator UI, GeoIP/ASN map, Threat Intelligence operations, TLS/L7 parser/rules, deterministic attack/false-positive testing and release-gate hardening.

Locally executable gates include:

- Go control-plane unit/integration suite
- Go vet
- race detector
- deterministic Kinetic attack and false-positive corpus
- signed Ed25519 policy containment/expiry E2E
- Threat-Intel API/UI contracts
- Kinetic live API contracts and bounded-history semantics
- DOM sink/static security audit
- DE/EN/RU/zh-CN catalog parity
- JavaScript syntax checks
- Linux integration/release contract validators
- deterministic high-cardinality Kinetic boundedness tests


## Latest recorded local RC gate

On 2026-10-07, the final worktree produced:

```text
PASS=10  PENDING=6  FAIL=0  MODE=local
TLS ClientHello fuzz: 128719 executions / 5s / PASS
```

The `PENDING` count is intentional and keeps production certification blocked until the unavailable privileged/toolchain/elapsed-time gates are run on the qualified target/dev host.

## Mandatory target-host gates still pending in this checkpoint

These cannot be truthfully certified inside the current work container:

| Gate | Why target host is required | Required evidence |
|---|---|---|
| Gateway Go 1.26 build/test | local environment has older Go toolchain and no toolchain download | `gateway` tests/vet/build with repository-pinned Go version |
| Rust common/core | `cargo`/`rustc` unavailable locally | pinned Rust tests and release build |
| eBPF release object | BPF Rust toolchain unavailable locally | pinned nightly BPF build + object inspection |
| Kernel verifier/XDP attach | requires supported Linux kernel/NIC/root | successful verifier load and attached GeDefense XDP program |
| TC fallback parity | requires privileged host and intentional XDP-unavailable scenario | TC attach + equivalent ingress health/telemetry behavior |
| Rust Core live transport | requires loaded BPF maps/ring and authenticated core socket | `xdp_ingress=online`, health counters valid, real events drained |
| Live packet drop | requires an authorized external/staging source | signed `/32`, `/24`, `/64` containment followed by observed drop and expiry |
| 24h soak | elapsed real deployment time cannot be simulated by unit tests | Observe/Canary resource trend, zero unexplained restarts, stable SSE/control plane |
| TLS coverage, when enabled | a parser alone is not traffic coverage | trusted local ClientHello producer and nonzero verified request/handshake flow |

## How to run the release gate

Source/RC check:

```bash
./scripts/validate-kinetic-release-candidate.sh --local
```

Privileged target-host qualification:

```bash
sudo ./scripts/validate-kinetic-release-candidate.sh --target-host <interface>
```

The target-host mode is deliberately strict. Pending privileged gates keep production certification blocked rather than being silently converted to PASS.

## Release language

Until the target-host table above is complete, use:

> **GeDefense 4.1 Kinetic Defense – Source-level Release Candidate. Local security gates passed; privileged target-host/kernel/soak certification pending.**

Do **not** use `100% release certified`, `production verified`, `kernel verified`, or `SYSTEM NOMINAL` as a build-time claim. `SYSTEM NOMINAL` is exclusively a runtime state derived from verified required sensors.
