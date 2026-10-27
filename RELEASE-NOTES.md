# Release Notes

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
