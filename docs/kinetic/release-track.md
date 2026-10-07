# GeDefense 4.1 Release Track: Kinetic Defense Verification & Release Gates

**Release Track:** `4.1 Kinetic Defense`  
**Governing Operating Rules:** Rule 4, Rule 28, Rule 29, Rule 30  
**Version:** 4.1.0  
**Classification:** Mandatory Release Quality Contract  

---

## 1. Release Track Definition

The GeDefense 4.1.0 release introduces the Kinetic Defense subsystem. This represents a foundational capability expansion transforming GeDefense from an integrity and host-XDR agent into an active, self-protecting Linux security fabric.

Because of the critical fail-safe requirements surrounding automated network containment, promotion between release phases (`observe` -> `canary` -> `enforce`) is governed by deterministic release gates enforced in `control/release.go`.

---

## 2. Release Gates Matrix

| Gate ID | Gate Name | Requirement for Promotion to Canary | Requirement for Promotion to Enforce | Verification Method | Enforcement In Code |
|:---|:---|:---|:---|:---|:---|
| **GATE-01** | **Signed Policy Verification** | Signed snapshot present and cryptographically verified | Verified against active root public keys | Ed25519 signature audit | `release.go` (`signed policy is not verified`) |
| **GATE-02** | **Evidence Ledger Health** | Evidence ledger initialized and writeable | Ledger healthy with verified chain hashes | Disk write test + Hash chain check | `release.go` (`mandatory evidence ledger is unavailable`) |
| **GATE-03** | **Management Allowlist Immunity** | Allowlist defined with at least 1 CIDR | Kernel LPM allowlist map verified synchronized | Core IPC map query | `release.go` (`management network allowlist is empty` / `kernel management allowlist is not synchronized`) |
| **GATE-04** | **Ingress Sensor Coverage** | Ingress network sensor status `ONLINE` or `DEGRADED` (observe only) | Ingress network sensor status strictly `ONLINE` | Heartbeat & self-test probe | `release.go` (`Kinetic ingress sensor is unavailable`) |
| **GATE-05** | **XDR Evaluation Drop Threshold** | Drop rate <= 50 permille (5%) | Drop rate <= 10 permille (1%) | Metric calculation: `EvaluationDrops * 1000 / EvaluationsTotal` | `release.go` (`XDR evaluation drop rate is X permille`) |
| **GATE-06** | **Zero False-Positive Management Lockout** | Synthetic verification test suite PASS | Synthetic verification test suite PASS | Test suite running automated ban test against allowlisted IP | `release_readiness_test.go` |
| **GATE-07** | **Soak Time Requirements** | Observe soak duration >= 300s (5m) | Canary soak duration >= 900s (15m) | Elapsed timer check against `Since` timestamp | `release.go` (`observe soak time remaining` / `canary soak time remaining`) |
| **GATE-08** | **Reconciliation & Stale Rule Gate** | Zero un-reconciled kernel rules | Zero un-reconciled kernel rules | Kernel block map comparison with Go block state | `release.go` (`kernel policy reconciliation is pending`) |
| **GATE-09** | **Threat Intel Semantic Integrity** | Feed status != `ERROR` | Feed status in (`OK`, `PARTIAL`) with kernel apply verified | Strict feed manager state inspection | `release.go` |
| **GATE-10** | **L7 Coverage Alignment** | L7 healthcheck OK (if enabled) | L7 healthcheck OK and traffic active (if inline) | Request counter & process heartbeat | `release.go` (`L7 inspection service is unavailable` / `L7 inline service is unavailable`) |

---

## 3. Automation & Verification Commands

The canonical GeDefense 4.1 gate is:

```bash
./scripts/validate-kinetic-release-candidate.sh --local
```

This validates all source-level gates executable on the current machine and reports unavailable privileged/toolchain gates as `PENDING`. A local `PENDING` must never be relabeled `PASS`.

Production qualification is performed on the supported Linux target host:

```bash
sudo ./scripts/validate-kinetic-release-candidate.sh --target-host <interface>
```

Target-host mode is deliberately strict. Production certification remains blocked until the pinned Gateway/Rust/eBPF builds, kernel verifier/XDP attach, authenticated Rust Core ingress path, live packet-drop proof, TC fallback parity and real deployment soak have been completed as applicable.

See `docs/kinetic/release-candidate-status.md` for the current source-vs-target truth table.

## 4. Release-state vocabulary

- `LOCAL_PASS`: locally executable source/API/UI/security gates passed.
- `TARGET_GATE_PENDING`: privileged or unavailable toolchain/host proof has not run yet.
- `VERIFIED_ON_TARGET`: reserved for a qualified target host after the strict target-host gate passes.
- `SYSTEM NOMINAL`: runtime-derived state only. It is never a build-time certification label.

GeDefense 4.1 must not be described as production/kernel verified solely because unit, race, static-security or source-level integration tests pass.
