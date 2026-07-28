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
