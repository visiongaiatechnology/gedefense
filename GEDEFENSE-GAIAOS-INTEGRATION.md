# GeDefense × GaiaOS — Master Integration Architecture

**Status:** DIAMANT VGT SUPREME architecture baseline  
**Decision:** GeDefense becomes the single Linux security platform. GaiaOS consumes it as a native operating-system service; generic Linux servers use the same engine without GaiaOS dependencies.

## 0. Repository topology and source ownership

Both GitHub projects contain a complete GeDefense development tree:

```text
GeDefense repository/
  control/ gateway/ rust/ packaging/ scripts/ integration/ ...

GaiaOS repository/
  gedefense/
    control/ gateway/ rust/ packaging/ scripts/ integration/ ...
  integration/gedefense/
    GaiaOS package profile and authority contract
```

The trees are independent at build and runtime: neither repository references
the developer's local path to the other repository. During joint development,
the standalone GeDefense tree is synchronized into `GaiaOS/gedefense` using
`scripts/sync-gaiaos-gedefense.py`. A SHA-256 manifest and byte verification
prevent silent drift. The GaiaOS mirror is a full source mirror, not a reduced
SDK, binary drop or independently modified fork.

Only the GeDefense integration boundary inside GaiaOS is changed by this work.
Gaia Core, KDE, image construction and the Gaia Cells lifecycle implementation
remain GaiaOS-owned.

## 1. Evidence-based starting point

GaiaOS currently defines this layer model:

```text
Gaia Experience
  → AETHEL / GaiaCom
  → Sentinel security control plane
  → Gaia Cells isolation
  → Gaia Core
  → Linux kernel
```

The repository state differs from the long-term diagram:

- Sentinel is implemented and tested as a Go core/agent split.
- Gaia Cells is currently a design stub targeted for GaiaOS 0.3; no cell runtime or stable IPC exists yet.
- Gaia Core is currently image, recovery and system-identity scaffolding.
- GeDefense already has the stronger kernel enforcement plane: Rust broker, authenticated IPC, XDP/eBPF, signed policy generations, encrypted state, bounded XDR and gated Observe/Canary/Enforce promotion.

Therefore Sentinel is not installed beside GeDefense. Its proven concepts are re-engineered as GeDefense modules. Two concurrent security authorities would create firewall conflicts, contradictory response state and an unprovable audit history.

## 2. Non-negotiable trust boundaries

| Ring | Component | Authority |
|---|---|---|
| Kernel | Linux, LSM, cgroup v2, nftables, XDP/eBPF, KVM | Final isolation and packet enforcement |
| Privileged broker | `gedefense-core` (Rust) | Narrow typed kernel, process, quarantine and cell-response actions |
| Control plane | `gedefense-control` (Go, unprivileged) | Correlation, policy, evidence, transactions and UI-safe state |
| Access plane | `gedefense-access` (Go, unprivileged) | TLS, operator authentication, same-origin gateway |
| Gaia integration | GaiaOS package/profile and optional Gaia Cells adapter | OS identity, cell metadata and local desktop presentation |
| Workloads | Services, applications and Gaia Cells | No control-plane authority |

Invariants:

1. No long-running root UI or root HTTP server.
2. The Go control plane never receives a generic shell-execution primitive.
3. Every privileged mutation is a typed broker command with peer credentials, MAC, nonce, replay protection and bounded input.
4. A mutation follows `Preview → Authorize → Apply → Verify → Audit → Reverse`.
5. Failure to persist mandatory audit evidence blocks new mutations.
6. GaiaOS integration is optional. Missing Gaia components must degrade to a generic Linux host, never disable GeDefense.
7. AETHEL may explain or correlate evidence but never authorize enforcement.

## 3. Sentinel capability disposition

| Sentinel capability | GeDefense destination | Decision |
|---|---|---|
| Aegis socket inventory | XDR network sensor | Merge process/socket enrichment; retain XDP as enforcement authority |
| Local EDR | XDR rule and behavior engines | Merge only non-duplicate deterministic signals |
| Prometheus FIM | Integrity domain | Implemented hardened successor with bounded traversal, race-aware non-symlink reads, encrypted authenticated baselines, periodic verification and Evidence-Ledger-gated operator actions. Broker `openat2` reads remain a defense-in-depth upgrade. |
| GaiaShield audit chain | Evidence ledger | Combine Ed25519 verification with GeDefense encrypted storage, sequence anchoring and truncation detection |
| Change Engine | Transaction domain | Rebuild as durable state machine; broker performs privileged actions and verifies post-state |
| Quarantine | Response domain | Rebuild as content-addressed encrypted vault; no unbounded `ReadFile`, no path races, reversible release |
| Declarative policy | Signed policy fabric | Extend GeDefense signed policies with posture, FIM, exposure and cell constraints |
| Boot Trust | Evidence domain | Import first as evidence-only reporting; never label mere hardware presence as verified trust |
| Cases | Incident domain | Correlate GeDefense incidents into durable cases with observation/inference separation |
| Nemesis deception | Deception domain | Run decoys in a dedicated restricted service or Gaia Cell, never inside the control plane |
| VIS Vault | Secret backend | Do not expose a general secret-retrieval API from the security control plane; use only scoped internal secrets with TPM/system credential backends where available |
| Service/process inventory | Telemetry domain | Merge into bounded host telemetry |

## 4. Gaia Cells contract

GeDefense must not own cell lifecycle. Gaia Cells creates, starts, stops and destroys isolation domains. GeDefense observes and enforces security policy for them.

### Stable identity

Each cell receives:

- immutable UUID;
- human-readable label treated as untrusted display data;
- cell class: `application`, `workspace`, `vault` or future versioned class;
- cgroup v2 path and kernel cgroup ID;
- policy profile digest;
- lifecycle generation counter.

The kernel cgroup ID is the enforcement key. A PID alone is never a durable cell identity.

### Isolation profiles

| Profile | Minimum isolation |
|---|---|
| Application Cell | user/mount/PID/network namespaces, cgroup v2, seccomp, Landlock, per-cell network policy |
| Workspace Cell | Application controls plus private writable workspace and explicit device grants |
| Vault Cell | KVM-backed boundary where available; otherwise a visibly degraded strong-container profile with no network by default |

### Versioned IPC v1

The implemented GeDefense Gaia Cells adapter uses an `AF_UNIX` socket under
`/run/gaia-cells/`. Peers are authenticated with `SO_PEERCRED` plus HMAC;
messages are versioned, length-bounded, timestamped and nonce-bound. GeDefense
consumes cell identity/state and issues only typed response requests such as:

- freeze/unfreeze cell;
- revoke network;
- snapshot evidence;
- terminate generation;
- quarantine exported artifact.

Until that protocol exists, GeDefense reports Gaia Cells as `not_available` or `runtime_not_installed`. It must not infer a Gaia Cell from arbitrary cgroup names.

## 5. Deployment profiles

### Generic Linux server

- headless access gateway and dashboard;
- XDP/eBPF network defense;
- XDR, integrity, audit, policy, response and cases;
- no dependency on Gaia Experience, Gaia Core or Gaia Cells.

### GaiaOS

- identical GeDefense binaries;
- GaiaOS policy and FIM profile;
- local desktop integration through the unprivileged access plane;
- Gaia Core boot/update/recovery evidence provider;
- Gaia Cells provider when the runtime becomes real;
- optional notification bridge, with no mutation authority.

## 6. Security findings in the current Sentinel implementation

These findings define porting requirements; they are not copied into GeDefense.

- **CRITICAL:** Audit append errors are ignored while in-memory state advances. A mutation can appear audited although no durable record exists.
- **HIGH:** Audit replay trusts stored hash heads without verifying the chain during startup.
- **HIGH:** Change-history persistence errors are ignored, and the writable probe checks the change directory rather than durable audit commit.
- **HIGH:** Quarantine uses path resolution followed by separate file operations, permitting time-of-check/time-of-use races. Cross-filesystem fallback reads the entire file into memory.
- **HIGH:** Quarantine metadata persistence errors can be ignored after the original file has moved.
- **HIGH:** nftables state is represented by an in-memory profile name, not a verified kernel transaction snapshot.
- **MEDIUM:** Vault and baseline files lack the full GeDefense regular-file, symlink, permission, size, AAD and sequence protections.
- **MEDIUM:** Boot Trust labels TPM device presence as `VERIFIED`; presence is evidence, not proof of measured boot.
- **MEDIUM:** Port traps execute inside the privileged Sentinel runtime and add network attack surface to the control process.

## 7. Delivery sequence

Delivery status: phases 1–6 and 8 are implemented in the shared GeDefense
beta. Phase 7 remains deliberately outside the beta authority because a decoy
listener must ship as a separately confined service or real Gaia Cell.
Transaction Engine v2 includes encrypted durable state,
preview/authorize/apply/verify/audit/reverse transitions, a typed Rust sysctl
broker, reboot reconciliation and runtime-drift quarantine. Integrity v2
includes encrypted authenticated FIM baselines, bounded traversal and
race-resistant file evidence.

1. **Host and Boot Evidence** — GaiaOS identity, Secure Boot state, lockdown, TPM presence, cgroup v2 and Gaia Cells runtime presence.
2. **Evidence Ledger v2** — durable signed/encrypted audit records and fail-closed mutation gate.
3. **Transaction Engine — implemented** — encrypted durable state machine with
   typed broker actions, reboot reconciliation and runtime-drift quarantine.
4. **Integrity v2 — implemented** — encrypted authenticated FIM baselines,
   bounded traversal and race-resistant file evidence.
5. **Response Vault — implemented** — chunked AES-256-GCM quarantine with
   atomic source capture, bound identity, tamper verification and reversible
   restore.
6. **Cases and Policy — implemented** — encrypted recurrence correlation,
   evidence-gated status transitions and signed policy/transaction authority.
7. **Deception Service — post-beta** — isolated decoy runtime remains separate
   from the privileged broker and network-facing control plane.
8. **Gaia Cells Adapter — implemented** — authenticated `VGTGC1` discovery and
   identity-bound reversible response. It reports `runtime_not_installed`
   without degrading host protection until GaiaOS supplies `gaia-cellsd`.

Each phase ships with unit tests, Linux integration tests, hostile-input tests, migration tests and installer rollback coverage.
