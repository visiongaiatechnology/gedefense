# Release Notes

## 6.0.1 — 2026-11-16 — GeDefense V6 Hotfix (Server-Safe Auto-Arm & AIDE Calibration)

- **Emergency Lockdown remains opt-in:** `ApplySafeV6DefaultsOnEnforce()` no longer auto-arms Emergency Lockdown (`network_lockdown=true`, `require_sources=1`) when transitioning to `enforce`. **StyX** (`monitor`), **Titan Exec Gate** (`contain`), and **Parser Cells** (`enabled`) remain active automatically on `enforce`, while both **Emergency Lockdown** and **Witness** require explicit operator activation.
- **Canary scanner calibration:** Scheduled integrity/AV scanners running under dedicated service accounts (including Debian/Ubuntu `aide` / `_aide`, `updatedb.*`, `tripwire`, `samhain`, `rkhunter`, `chkrootkit`, `clamscan`, `clamd`, `freshclam`, `osqueryd`) are classified as `CANARY_SUSPICIOUS_SYSTEM_ACCESS` (`HIGH`) rather than `CRITICAL` unauthorized probes.
- **V6 OneClick installer & host verification:** Accepted V6 `core_mode` tokens (`+titan-exec:*`, `+lockdown:*`) during live activation checks, and fixed two `gedefense-core` unit tests (`lockdown_hardening::tests::untyped_values_are_never_claimed`, `quarantine::tests::copy_quarantine_aborts_when_the_source_cannot_be_removed`) for `root` / `pam_tmpdir` installer environments.
- **Release packaging hygiene:** `VGT_GeDefense_V6_6.0.1_OneClick.run.sha256` records only the relative archive basename.

## 6.0.0 — 2026-11-15 — GeDefense V6 (5-Point Anti-Spyware Architecture)

**GeDefense V6 (`6.0.0`)** promotes the 5-point anti-spyware blueprint into the V6 release line (Settings v17). In `observe` and `canary` phases all five planes remain **off** so baseline qualification preserves 5.2.0 behavior; once GeDefense is armed (**`enforce`**), `gedefense-control` automatically activates the safe V6 baseline (**StyX** `monitor`, **Titan Exec Gate** `contain`, **Parser Cells** `enabled`, **Emergency Lockdown** `enabled` + `auto_arm`) since no dedicated V6 UI panels are shipped yet, while **Witness** remains opt-in and operator API overrides stay sticky across restarts:

### Highlights
- **Point 1 — Titan Exec/Library Gate:** eBPF LSM hooks (`bprm_check_security`, `mmap_file`, `task_fix_setuid`) and Go-Control policy sync over VGT3, reporting honest `inactive` status when the running kernel omits `bpf` from `/sys/kernel/security/lsm`.
- **Point 2 — Ephemeral Parser Cells (`gedefense-cell-helper.service`):** optional root helper spawner isolating untrusted parser workloads inside namespaces/tmpfs/seccomp/cgroup-v2 sandboxes with burn-on-completion ledgers, `VGTGC2` HMAC IPC, loader-env blocking (`LD_*`, etc.), and control-owned import staging.
- **Point 3 — StyX Egress & C2/Beacon Detection:** kernel egress enforcement + flow correlation with zero overhead bypass in default `mode=off`.
- **Point 4 — Out-of-Band Witness Client:** Ed25519-signed ledger checkpoints, `ledger_epoch` rotation guard, and SSRF/DNS-rebinding-protected outbound dialing.
- **Point 5 — Emergency Lockdown:** XDP/TC egress lockdown latch, hardened composite USB BadUSB classification, broker freeze (including 15-char `comm` truncation), and operator-latched recovery.
- **UI & Release Alignment:** updated dashboard shell/i18n branding (`LINUX DEFENSE // V6`), artifact naming (`VGT_GeDefense_V6_6.0.0_*`), and host validation checks.

## 5.2.0 — 2026-11-14 — Security Release

This is the security release for the independent deep audit
**VGT-AUDIT-20261114-GD51**. The audit reported 36 findings in six attack chains
and blocked the 5.1.0-beta.3 release gate; 5.2.0 fixes all 36 findings. The
release is deliberately fail-closed: several behaviors that previously
continued silently now stop and name the condition.

### Highlights

- **Installer and supply chain:** the desktop and server OneClick installers
  verify the Ed25519 release signature and the payload hash before extraction or
  any state change; state and secret paths keep their documented ownership and
  modes (atomic `0600` files); the release-toolchain gate, the SCA status, the
  canonical signed GeoIP sidecar contract and the release-key rotation are
  enforced.
- **Boot attestation:** the boot-trust probe verifies the detached Ed25519
  signature, the live TPM2 PCR values against the pinned policy key and the
  signed fs-verity manifest instead of trusting the JSON document shape.
- **Gateway and authentication:** step-up password change, a process-wide
  Argon2id admission gate, no session-registry leak on rotation, and the
  anonymous `/gateway/version` surface removed.
- **Policy and forensics:** an unverifiable signed policy is quarantined
  unmodified and never re-signed; blocker evaluation no longer disappears when
  Auto-Degrade is off; strict storage AEAD/HistoryMAC; authenticated rotation
  marker; consistent incremental ledger verification.
- **API, L7, feeds and Airlock:** single-decode allowlist removal, a replay
  guard that stays available without forgetting, bounded inline admission slots,
  a finite static-asset rate budget, visible TLS-policy deactivation, the
  ephemeral self-test token, an authenticated threat-intelligence state and a
  staging-root-bound Airlock.
- **Self-protection and response:** own-artifact mismatches are `XDR.SELF_TAMPER`
  and release-blocking unless a signed update window covers the exact bytes;
  RASP exemptions are bound to identity; behavior/FIM/mitigation postures and
  response capacity no longer misreport or lock out.
- **Desktop tray, Rust core and eBPF:** Qt rich-text injection is closed; the
  scan socket, control socket, IPC timestamp window, quarantine commit point and
  canary attribution are hardened; the eBPF producer keeps every wire counter
  exact, uses the explicit neutral marker for mixed batches and walks the full
  cgroup-v2 ancestry for LSM policies.

### Behavior and breaking changes

- An unverifiable startup policy is quarantined unmodified and is **not**
  re-signed automatically. Promotion stays refused until an explicit operator
  recovery re-establishes the signed policy via the documented `RETURN:OBSERVE`
  transition.
- Legacy plaintext operational histories/runtime settings are **refused**, not
  migrated; strict AEAD/HistoryMAC is required.
- Changing the gateway password requires the current password (step-up) and
  interactive sudo/polkit re-authentication; the `NOPASSWD` rule for the helper
  was removed.
- An unauthenticated evidence-rotation marker from an older version is refused;
  an interrupted rotation needs out-of-band verification/operator action.
- External scripts using the former static L7 self-test header are rejected; the
  reserved path requires the process-local ephemeral token.
- `GET /gateway/version` returns 404. `/gateway/livez` remains the only anonymous
  health answer and contains no build metadata.
- Boot trust without the pinned keys and signed fs-verity manifest reports
  `NOT_AVAILABLE`/`WARNING`, never a positive claim; a missing GeoIP sidecar
  makes the resolver unavailable (fail-closed).
- The eBPF object and the Rust core implement one wire contract (batch ≤ 255,
  neutral marker `protocol = 0`) and must come from the same release.
- **Gateway password migration under the shipped sandbox (carry-over fix):** the
  `gedefense-access` unit keeps `ProtectSystem=strict` and a read-only release
  tree, but lists its own `/etc/vgt/gedefense-access` credential directory as a
  documented writable path. A legacy PBKDF2 password record is therefore
  atomically replaced with Argon2id after the first successful login. No other
  sandbox directive is relaxed; run `systemctl daemon-reload` after installing
  the unit.

### Upgrade steps

1. Back up the operational state directory and the signed policy document.
   Do not delete a quarantined policy: the unmodified document and its forensic
   copy are the evidence an operator recovery needs.
2. Install 5.2.0 with the signed OneClick installer / signed source archive and
   verify the asset hash and Ed25519 release signature first.
3. Install the systemd units shipped with this release and run
   `systemctl daemon-reload`. The units keep `ProtectSystem=strict`,
   `ReadOnlyPaths` and only the documented `ReadWritePaths` (for example
   `/run/gedefense`, `/run/vgt-gedefense-l7`, `/sys/fs/cgroup/vgt-cells`,
   `/var/lib/vgt/gedefense`, `/etc/vgt/gedefense-access`); do not widen the
   sandbox to work around a path.
4. Deploy the Rust core and the eBPF object from this same release. A mixed
   core/eBPF pair is refused or loses samples, because the wire contract
   changed.
5. **Boot-trust anchors:** on AstraeaOS, provision the pinned Ed25519
   attestation/TPM public keys and the operator-signed fs-verity manifest under
   `/usr/share/astraeaos/boot-trust/`, and enable the updated
   `astraeaos-boot-attestation` producer that writes
   `/run/astraeaos/boot-attestation.json` and its `.sig`. Without them boot
   trust is reported as unavailable/warning. On non-AstraeaOS hosts boot trust
   stays explicitly unavailable and is never presented as verified.
6. **GeoIP:** after the upgrade, re-generate and re-sign the local dataset with
   `sudo python3 scripts/update-geoip-db.py /var/lib/vgt/gedefense/geoip.csv` so
   `geoip.csv.sha256` (canonical `vgt.gedefense.geoip-integrity.v1` JSON) and,
   for signed deployments, `geoip.csv.sig` match the installed CSV. A copied
   legacy CSV without a matching sidecar is refused.
7. **Rotation marker migration:** if a rotation marker from a pre-5.2.0 start
   exists and is unauthenticated, the start refuses it. Verify the sealed
   archive/evidence chain out of band, then let the documented operator recovery
   path finish or discard the pending rotation.
8. **Operator recovery after policy tamper:** investigate the quarantined policy
   document and its forensic copy, then re-establish the signed policy with the
   explicit `RETURN:OBSERVE` transition. Automatic promotion remains blocked
   while the quarantine is active.
9. **Release toolchain host:** build/validate the release on a host with
   **Node.js 22.16.0** and **Go 1.27.3** (Rust stable 1.97.1, eBPF nightly
   `nightly-2026-07-16`, bpf-linker 0.10.3 per `TOOLCHAINS.lock`). Older host
   toolchains are refused by the release gate.
10. Run `scripts/tests/run_release_tests.sh` and the target-host qualification
    gates; treat SKIP lines as "not executed", never as PASS.

### Known residual risks

- **Not testable in this offline environment (NOT_TESTED/BLOCKED):** live
  TPM2/fTPM and fs-verity measurements, the target-kernel eBPF verifier/XDP
  attachment, and the offline SCA scanners (scanner binaries/network not
  available). These remain mandatory target-host qualification items and are not
  claimed as verified here.
- **Core and eBPF must ship together:** the batch limit/neutral-marker wire
  contract changed; pairing a 5.2.0 core with an older eBPF object (or the
  reverse) is unsupported.
- **Quarantine under a read-only sandbox:** a file on a path the service may
  read but not modify (`ProtectSystem=strict`, `ReadOnlyPaths`, read-only
  mounts) cannot have its source removed. The quarantine transaction aborts
  fail-closed with an explicit error instead of reporting success while the
  object stays in place; an operator with write access is required.
- **ReplayGuard capacity:** the bounded cache stays available under pressure,
  but more than `maxEntries + maxRetained` distinct identifiers inside one
  replay window can push the oldest fingerprint out of the retained table; the
  residual is bounded by the window and the per-scope quota.
- The 70 VGT-100 controls that were already `NOT_TESTED` remain open (see
  `SECURITY.md` and `PRODUCTION-BETA-GATE.md`); this release does not claim full
  VGT-100 coverage.

## 5.1.0-beta.3 — 2026-10-29 — Feed self-healing and CVE response

This release makes the signed threat-intelligence feed recover itself from the bootstrap failure that previously required an operator:
`feeds.local_signing=true` + an existing operator key + no pinned public key now self-pins through a rotation-safe marker. A changed key with the old marker fails closed and needs an explicit pin.

It also ships the CVE-2026-98432 advisory and MPTCP/TCP exposure probes, a managed MPTCP mitigation target that the guard actively re-asserts alongside the user-namespace record, and the permission-aware mitigation-probe fix. Permission-limited probes are reported as `UNOBSERVED` instead of being silently skipped. Kernel exposure remains visible; a kernel update is still the only fix for the UAF.

## 5.1.0-beta.2 — 2026-10-27 — Security hardening

Security hotfix for 5.1.0-beta.1. Trusted editor scope is limited to exact VGT actions and XSS findings only; sensitive L7 limits remain active; revocation persists across restarts; loopback/weak-salt/fail-open bridge states are rejected; installer ordering/trust/rollback are corrected.

> **ALPHA:** The WordPress bridge is an alpha feature, not production-ready. Update before exposing it. A compromised WordPress holding the shared secret can forge records; see SECURITY.md.


# Release Notes

## 5.1.0-beta.1 — 2026-10-27

- CMS detection and configurable CMS Defense relaxation (WordPress / Joomla! / TYPO3 / Laravel).
- Encrypted GeDefense WP ↔ Linux bridge (ALPHA): secret encrypted in the WordPress database, authenticated records in the existing PHP log, two-hour IP/host-bound L7 lease.
- Verified ThroneGuard editor false-positive fix; WAF/protocol/upload/kernel enforcement remains active.
- Updated signed installer and release context; no custom WordPress write path outside its webroot.
- Ecosystem: GeDefense WP — https://github.com/visiongaiatechnology/gedefensewp

> **ALPHA SECURITY NOTICE:** The bridge is an alpha test feature. A compromised WordPress holding the shared secret can forge records. Use only in test/qualification environments; the lease is limited to two hours and admin IP/host. Do not treat this release as production-ready.


# VGT GeDefense 5.0.0-beta.2-hotfix6 — Clean installable Entenprise release

This is the clean installable 5.0.0-beta.2 release. The source OneClick
installer now hands a fully rendered signed release context to its embedded
full-stack installer, so an actual upgrade no longer stops at the bootstrap
handoff. It contains all hotfix2–5 content:

- inline-L7 POST gate fix,
- WordPress admin rate-limit correction for media-heavy page editing,
- Sir Du / Entenprise mascot and clean four-language READMEs,
- installer toolchain checksum and live-host test-isolation corrections.

The signed installer, release index, SBOM, build provenance, source manifest
and public release key are attached.

# VGT GeDefense 5.0.0-beta.2-hotfix5 — Clean Entenprise release

This is the clean, deployable 5.0.0-beta.2 release. It includes:

- the inline-L7 POST gate fix,
- the WordPress admin rate-limit correction (static/assets do not exhaust the
  dynamic client bucket; preview and save requests are no longer blocked by a
  normal media-heavy page load),
- the official Sir Du / Entenprise mascot on the gateway sign-in page,
- the clean Entenprise READMEs in all four languages with the language image
  preserved and obsolete security advisories removed,
- the corrected installer toolchain checksum and live-host test isolation.

The signed installer, release index, SBOM, build provenance, source manifest
and public release key are attached.

# VGT GeDefense 5.0.0-beta.2-hotfix4 — Installer test isolation correction

This release makes the source OneClick installer buildable and testable on a
host that already runs GeDefense. The control test suite no longer inherits the
live dashboard token path from `defaultConfig()`; it uses an isolated absolute
test path, so upgrades do not fail with spurious 401 responses. Production
configuration and authorization are unchanged.

The release contains the hotfix3 installer checksum correction together with
the hotfix2 L7 POST fix, the Sir Du / Entenprise mascot, the clean Entenprise
READMEs and the embedded gateway asset. Full control tests pass on the live
host without masking.

# VGT GeDefense 5.0.0-beta.2-hotfix3 — Clean release build correction

This release corrects the source-self-contained OneClick installer build. The
pinned Go 1.27.3 archive checksum now matches the official immutable archive, so
a clean installation can download and verify the toolchain without failing
closed. The release contains the same product changes as hotfix2: the L7 POST
gate fix, the official Sir Du / Entenprise mascot, the clean Entenprise READMEs
and the embedded self-hosted gateway asset.

The signed installer, release index, SBOM, build provenance, source manifest
and public release key are attached.

# VGT GeDefense 5.0.0-beta.2-hotfix2 — Entenprise clean release

This is the clean 5.0.0-beta.2 release: it consolidates the inline-L7
duplicate-Content-Length fix, the official Sir Du / Entenprise mascot on the
gateway sign-in page, the unified **Linux Security Fabric - Your Entenprise
System** product line, and cleaned public READMEs in all four languages.

- **L7 gate fix:** ordinary POST bodies reach the upstream again; request
  smuggling detection remains active and is not weakened.
- **Entenprise identity:** the embedded mascot is served from the gateway itself
  (no external runtime asset), with a responsive identity-plane composition and
  an accessible description.
- **Clean documentation:** the obsolete 5.0.0-beta.2 critical advisory and the
  historical 4.x caution block are removed; the "Real Security, Many Feathers"
  language image is preserved in every README.
- **Installer:** the signed `GeDefense-5.0.0-beta.2-OneClick.run` asset is
  rebuilt from this release tag and referenced by all READMEs.

The signed release index, SBOM, build provenance, source manifest and public
release key are attached to the GitHub release.

# VGT GeDefense 5.0.0-beta.2-hotfix1 — Version-label and branding correction

This release corrects the public surface labels of the 5.0.0-beta.2 source tree:
README version/status badges now state 5.0.0-beta.2, the dashboard sidebar
branding states V5 instead of V4, and the installer asset referenced by the
READMEs is rebuilt from this corrected tag. No runtime protection logic changed
relative to 5.0.0-beta.2; the security fixes, signed feeds, deception sensor,
L7 inline producer, truthful protection status and all validation results of
5.0.0-beta.2 remain in force.

# VGT GeDefense 5.0.0-beta.2 — Hotfixes 1–9 Consolidated

This release consolidates nine security and functional hotfixes into the public
source tree. It is a public beta for test and qualification hosts, not a
production certification.

Highlights:

- **Deception:** privileged core-deployed, fanotify-watched canaries with
  automatic incident creation and reversible TTL-bound containment; the core
  ignores its own deployment/verification opens.
- **Threat intelligence:** operator-provisioned Ed25519 signing pipeline,
  exact-byte snapshots, detached manifest verification with TTL/anti-rollback,
  and verified BLOCK-only kernel application that survives release
  reconciliation and control-plane restarts.
- **Application defense:** the inline Unix-socket edge is a first-class
  producer; benign traffic reaches the upstream, SQLi/XSS/LFI/command-injection
  payloads are blocked before it, and the full built-in enforcement scope is
  active.
- **Truthful status:** `protection.effective` is derived from actual kernel,
  XDR, core, Kinetic, L7 and evidence enforcement. The dashboard no longer
  claims full protection from a single release flag.
- **Integrity and platform fallbacks:** FIM/Titan release rebaseline, startup
  self-check status API, local cgroup-v2 Gaia-Cells registry, operator-signed
  local boot-trust baseline and a post-update rebaseline script.
- **Validation:** Go control test suite green, Rust 40/40 tests green, signed
  installer self-test and payload verification pass.

Known limitations remain: public-CA/RFC3161/CRL/OCSP release authenticity and an
externally anchored anti-rollback channel are outside this beta; threat-feed
authenticity is operator-provisioned with a local Ed25519 key, not a public CA.

# VGT GeDefense 5.0.0-beta.1 — Titan Ingress Defense & V5 Beta

**GeDefense powered by VisionGaiaTechnology** enters the V5 Beta line with Titan, a
native Linux module for unauthorized manipulation and contraband injection
(Remote File Planting / Silent Dropping). Titan asks whether a change was
authorized, how it was observed, what response is safe and which independent
evidence exists. It deliberately does not attribute changes to a criminal, an
APT or a state actor.

Highlights:

- trust-aware ingress observations with AUTHORIZED/TOLERATED/UNEXPECTED/COMPROMISED
  and OBSERVE/CONTAIN/STRICT policy;
- bounded inotify coverage, FIM baseline and package-ownership evidence without
  runtime command execution;
- containment only through the encrypted, reversible quarantine transaction path;
- Titan dashboard page with trust distribution, correlation quality, policy,
  review/contain actions and honest unavailable states;
- strengthened security regression gate (19/19 checks), full Go/race suite green,
  V5 version metadata and deterministic source packaging.

Certificate/public-CA, RFC3161 timestamp, CRL/OCSP, externally anchored
anti-rollback and feed-signing trust remain external release blockers and are not
claimed as completed. This beta is a code-and-runtime candidate, not a public
certification.

# VGT GeDefense 4.0.1 — Universal Linux Release

**GeDefense powered by VisionGaiaTechnology** promotes the encrypted full-stack
security fabric into a universal systemd Linux integration. The Go control
plane, Rust response core and Rust eBPF/XDP data plane retain the Beta 5 trust
separation while the installer, local application, readiness boundary and
release gates become distribution-aware.

The supported integration families are Debian/Ubuntu, Fedora/RHEL-compatible,
Arch Linux and openSUSE. AstraeaOS-specific Gaia Cells, SDDM and boot adapters
remain conditional and are never imposed on another distribution.

This release also adds a native L7 application-security plane implemented inside the existing Go control plane with standard-library facilities only. It can operate as a local inspection service or as an explicitly enabled Unix-socket inline gate in front of a statically configured local application upstream. No additional scripting engine, plugin runtime, database, WAF service or third-party Go module is introduced.

The L7 pipeline applies bounded canonicalization and structured parsing before modular detection, enforces shared host-wide admission and memory budgets, excludes authentication secrets from inspection state, routes uploaded files through the existing Airlock path, and emits hashed evidence into XDR. Web-only evidence remains alert-only for destructive host-response scoring; active process containment still requires independent process/network evidence under the existing release gate.

XDR incident-ledger integrity now has an explicit fail-closed recovery path. A damaged HMAC-linked incident chain is never silently truncated or deleted: GeDefense archives the raw chain and head checkpoint under root-only storage, emits a SHA-256 recovery manifest, rechecks that the source did not change during archival, preserves the existing authentication/storage keys, creates a fresh empty chain crash-safely and verifies it from disk. XDR leaves `DEGRADED` only when the incident ledger was the sole XDR degradation and all mandatory Evidence Ledger commits succeed; Canary/Enforce promotion remains a separate operator action.

The same hardening pass fixes the underlying incident-authentication edge case observed in beta testing: attack-story Merkle roots and incident-ledger chain hashes no longer share `record_hash`. Attack-story proof material is stored as `evidence_root`; the ledger `record_hash` is computed from a canonical incident with that chain field blank, making append and later verification deterministic.

The release preserves the existing Command Center design and gives the public login the same visual identity, versioning and security language. German, English, Russian and Simplified Chinese (`zh-CN`) are available without loading external assets. The localization layer validates exact catalog-key and interpolation-placeholder parity at startup, and the release includes a dependency-free static i18n audit for all Command Center tabs, dialogs and operation feedback. The optional support panel contains only operator-visible addresses and a direct PayPal link; no payment SDK or tracker is embedded.

Sensitive operational state is encrypted at rest with AES-256-GCM. AAD binds every envelope to its schema, node, purpose, canonical storage path and sequence. Separate HMAC-derived subkeys prevent cross-purpose ciphertext reuse. New gateway credentials use Argon2id; valid legacy PBKDF2 records are upgraded after successful login.

The security pass covers browser XSS sinks, CSP, CSRF, login/session bypass, Host-header routing, reverse-proxy header leakage, backend bearer isolation, SSRF, path handling, RCE primitives and encrypted-state tampering. Automated regression tests and `scripts/security-audit.sh` enforce the critical properties.

The release still reports full-stack installation success only after the target host compiles the Rust core and eBPF object, the destination kernel verifier accepts XDP, the interface attachment succeeds and authenticated Go/Rust IPC reports the core online.

Swarm/Mesh remains intentionally outside this beta. A public source tag is not
a host qualification: the concrete kernel, verifier, NIC/XDP mode and systemd
activation must pass the privileged Beta v4 host gate before binary release.
