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
