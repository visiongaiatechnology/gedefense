# Full-Stack Beta Gates

GeDefense becomes ready in Observe only after the privileged core has authoritatively cleared and authenticated the XDP blocklist state and the control plane has persisted a signed Observe policy.

## Installation gates

Activation is refused and rolled back unless all of the following succeed:

1. target-host Rust core build;
2. target-host eBPF build;
3. target-kernel verifier acceptance and XDP attachment;
4. permission-restricted core IPC socket;
5. authenticated VGT3 ping from the Go control plane;
6. control-plane preflight and liveness;
7. API reports `core_connected=true` and native or generic XDP mode;
8. gateway backend-authentication preflight;
9. public TLS gateway liveness.

## Runtime gates

Observe → Canary requires verified policy, online Rust core, healthy XDR and the configured soak period.

Canary → Enforce additionally requires a non-empty management allowlist, successful kernel allowlist synchronization and the Canary soak period. Signed block rules are reconciled atomically during the transition.

Any core, policy, XDR or kernel inconsistency triggers automatic degradation when Auto-Degrade is enabled. Emergency Stop disables new response immediately, then succeeds only after authoritative blocklist clearing, authenticated empty-state verification and signed Observe persistence. Otherwise the node remains explicitly Degraded/Unverified and retries after authenticated core recovery.

## GeDefense 4.1 Kinetic Defense final qualification

The canonical release-candidate validator is:

```bash
./scripts/validate-kinetic-release-candidate.sh --local
```

Local mode may report privileged/toolchain checks as `PENDING`; this is an honest source-level Release Candidate state and **not** production certification.

Before a production package/tag is certified on a supported Linux host, run:

```bash
sudo ./scripts/validate-kinetic-release-candidate.sh --target-host <interface>
```

Production certification is blocked until the strict target-host qualification has proved, as applicable:

1. repository-required Gateway Go toolchain tests/vet;
2. pinned Rust common/core tests and release build;
3. release eBPF object build;
4. target-kernel verifier acceptance and XDP attachment;
5. authenticated Rust Core ingress health and live RingBuf event transport;
6. verified signed policy and required sensor coverage;
7. authorized external live packet-drop/expiry proof for automatic containment;
8. TC fallback verifier/telemetry parity when XDP is intentionally unavailable;
9. a real 24-hour Observe/Canary soak with restart/resource/pressure/SSE trends;
10. trusted local TLS ClientHello producer coverage when TLS protection is enabled.

The machine-readable/operator-readable truth table is maintained in `docs/kinetic/release-candidate-status.md`. No source-only test may upgrade a pending target-host item to PASS.

