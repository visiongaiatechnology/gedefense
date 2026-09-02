# VGT GeDefense Beta v3 — 3.0.0-beta.1

**GeDefense powered by VisionGaiaTechnology** promotes the encrypted full-stack
security fabric into a universal systemd Linux integration. The Go control
plane, Rust response core and Rust eBPF/XDP data plane retain the Beta 5 trust
separation while the installer, local application, readiness boundary and
release gates become distribution-aware.

The supported integration families are Debian/Ubuntu, Fedora/RHEL-compatible,
Arch Linux and openSUSE. AstraeaOS-specific Gaia Cells, SDDM and boot adapters
remain conditional and are never imposed on another distribution.

The release preserves the existing Command Center design and gives the public login the same visual identity, versioning and security language. German, English and Russian are available without loading external assets. The optional support panel contains only operator-visible addresses and a direct PayPal link; no payment SDK or tracker is embedded.

Sensitive operational state is encrypted at rest with AES-256-GCM. AAD binds every envelope to its schema, node, purpose, canonical storage path and sequence. Separate HMAC-derived subkeys prevent cross-purpose ciphertext reuse. New gateway credentials use Argon2id; valid legacy PBKDF2 records are upgraded after successful login.

The security pass covers browser XSS sinks, CSP, CSRF, login/session bypass, Host-header routing, reverse-proxy header leakage, backend bearer isolation, SSRF, path handling, RCE primitives and encrypted-state tampering. Automated regression tests and `scripts/security-audit.sh` enforce the critical properties.

The release still reports full-stack installation success only after the target host compiles the Rust core and eBPF object, the destination kernel verifier accepts XDP, the interface attachment succeeds and authenticated Go/Rust IPC reports the core online.

Swarm/Mesh remains intentionally outside this beta. A public source tag is not
a host qualification: the concrete kernel, verifier, NIC/XDP mode and systemd
activation must pass the privileged Beta v3 host gate before binary release.
