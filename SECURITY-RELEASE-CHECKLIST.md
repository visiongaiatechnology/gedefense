# Security Release Checklist — 1.0.0-beta.5

- [x] Go control and gateway tests pass.
- [x] Go race detector and vet pass.
- [x] Frontend modules pass syntax validation.
- [x] Gateway session/origin integration path passes.
- [x] Runtime settings are HMAC-authenticated and tamper-tested.
- [x] IPC uses HMAC, timestamp, nonce replay guard and peer UID verification.
- [x] Rust socket is group-owned for the unprivileged control plane.
- [x] XDP allowlist precedes blocklist.
- [x] Public feeds are staged only.
- [x] Enforce requires management allowlist and target-host core health.
- [x] Startup and Emergency Stop require authoritative blocklist clearing, authenticated `VERIFY_EMPTY` and signed Observe persistence.
- [x] Operator RE2 rules are bounded, revision-gated and excluded from active-response scoring.
- [x] Rust dependencies are committed in `Cargo.lock` and every release build uses `--locked`.
- [x] One-click activation rolls back on build, verifier, IPC, API or gateway failure.
- [ ] Wider external kernel/NIC beta matrix.
- [ ] Reproducible offline vendor build and signed release provenance.
- [ ] Independent security audit before stable release.
