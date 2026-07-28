# Changelog

## 1.0.0-beta.5 Complete Beta

- Installer 3.5.1 korrigiert die DAC-Kette des verschlüsselten
  Quarantäne-Vaults bei Upgrades: `/var/lib/vgt/gedefense` ist nun `0710`
  (`gedefense:gedefense`). Der privilegierte Core kann dadurch mit seiner
  expliziten `gedefense`-Gruppe zum root-eigenen `0700`-Vault traversieren,
  ohne `CAP_DAC_OVERRIDE` oder Verzeichnis-Listing zu erhalten.
- Installer und Security-Audit prüfen die Vault-Eigentümer und Modi vor der
  Service-Aktivierung fail-closed.

- Added chunked AES-256-GCM quarantine with atomic capture, verification and
  restore through the typed Rust broker.
- Added encrypted durable cases with deterministic recurrence correlation and
  Evidence Ledger-gated status transitions.
- Added authenticated Gaia Cells v1 discovery and reversible isolation
  transactions bound to UUID, generation and kernel cgroup ID.
- Added atomically persisted server/GaiaOS hardening profiles with runtime and
  boot-state rollback.
- Replaced the GaiaOS Sentinel runtime package path with native GeDefense
  packages, provisioning, systemd activation and a pinned local TLS launcher.
- Added privacy-safe installer prompts and actionable activation diagnostics.

## 1.0.0-beta.5 hardening continuation

- added the encrypted durable Transaction Engine with exact preview binding, confirmation-gated apply/reverse, crash recovery, reboot reconciliation and runtime-drift quarantine;
- added typed Rust broker commands for allowlisted sysctl reads and compare-and-set writes with post-state verification;
- added reversible generic Linux server and GaiaOS workstation hardening profiles without a shell or generic privileged file-write primitive;
- added the hardened Prometheus FIM successor with bounded traversal, race-aware regular-file hashing, SHA-256 content and mode verification, encrypted authenticated baselines and tamper quarantine;
- added authenticated FIM status, scan and baseline APIs whose operator mutations pass through the mandatory Evidence Ledger gate;
- added a complete manifest-verified GeDefense source mirror under `GaiaOS/gedefense` plus local Arch package builds without developer-path dependencies;
- added Evidence Ledger v2 with per-record Ed25519 signatures, AES-256-GCM record encryption, sequence-bound AAD, durable head checkpoints, truncation detection, bounded replay and fail-closed mutation gates;
- added mandatory pre-action evidence intents for authenticated operator mutations and automated XDR response;
- added a versioned GaiaOS integration contract, strict GaiaOS runtime profile and byte-level cross-repository synchronization verifier;
- established the GaiaOS/Sentinel fusion architecture with GeDefense as the single security authority for generic Linux and GaiaOS;
- added an authenticated evidence-only Boot Trust API covering GaiaOS identity, Secure Boot state, kernel lockdown, redacted boot-parameter evidence, TPM presence, cgroup v2, Gaia Cells runtime presence and bounded kernel-image hashing;
- added strict bounds, non-symlink evidence reads, kernel command-line secret redaction, cache isolation and Linux regression tests for host-trust collection;
- fixed authenticated runtime-settings upgrades by omitting absent post-upgrade rule fields from the legacy MAC input;
- removed public-host and management-CIDR values from installer prompts and the final console summary;
- added automatic `systemctl` and `journalctl` capture before activation rollback;
- made Emergency Stop a verified fail-safe transaction with authenticated empty-kernel confirmation, signed Observe persistence and automatic recovery reconciliation;
- added configurable XDR signal modules and bounded dashboard-managed RE2 rules with strict separation between alert score and active-response score;
- added native Go fuzz targets plus a shared Rust eBPF packet-prefix parser and host-side fuzz harness;
- committed the Rust dependency lockfile and enforced locked builds across CI, Makefile, installer and source packaging;
- split settings handlers, TLS file operations and privileged process control into isolated modules;
- bounded privileged-core IPC responses and removed ignored rollback errors.

## 1.0.0-beta.5

### Product and interface

- unified the public login and embedded Command Center under the product identity **GeDefense powered by VisionGaiaTechnology**;
- added consistent version labels to login, navigation, hero, footer and operational dialogs;
- added complete browser-language switching for German, English and Russian, including dynamic status text, forms, dialogs, tables, notifications, dates and number formatting;
- added an optional VGT support panel for PayPal, Bitcoin, ETH and USDT (ERC-20), without external scripts, trackers or payment SDKs;
- retained the existing dashboard visual system while making branding, navigation and responsive layouts deterministic across login and authenticated views.

### Data-at-rest protection

- added a 32-byte installation-specific storage master key under `/etc/vgt/gedefense/secrets/storage-master.key`;
- added AES-256-GCM envelopes with random nonces, per-purpose HMAC-SHA-256 subkeys and AAD binding to schema, node identity, storage purpose, canonical path and record sequence;
- encrypted runtime settings, policy snapshots, the local Ed25519 policy private key, behavior profiles, incident records and incident-chain checkpoints;
- added authenticated migration from supported legacy plaintext records to encrypted storage;
- retained policy signatures and incident MAC chains inside the encrypted envelopes for defense in depth.

### Authentication

- new password records use Argon2id with 64 MiB memory, three iterations, one lane, a random 128-bit salt and a 256-bit output;
- existing PBKDF2-HMAC-SHA-256 password records remain accepted and migrate to Argon2id after successful authentication;
- added strict private-file validation for password records and runtime verification of `libargon2.so.1`.

### Security hardening

- added fail-closed same-origin enforcement for authenticated mutating requests and logout;
- retained synchronizer-token login CSRF protection and explicit cross-site request rejection;
- hardened Host validation, session validation, security headers and reverse-proxy trust-boundary resets;
- removed browser forwarding identity from internal backend requests, including explicit suppression of automatic `X-Forwarded-For` injection;
- added HTTPS-only threat-feed validation and dial-time SSRF protection against loopback, private, link-local, multicast and unspecified networks;
- added a static security regression audit that rejects unsafe DOM HTML sinks, inline handlers, runtime command execution primitives and missing cryptographic/security anchors;
- added security tests for CSRF failure, origin mismatch, auth/session forgery, Host bypass, backend bearer protection, asset traversal and strict header presence.

### Full-stack base retained from Beta 4

- Rust response core, authenticated VGT3 IPC and Rust `no_std` eBPF/XDP data plane;
- target-kernel compilation and verifier-gated activation;
- fixed-header IPv4/IPv6 parser accepted for source-CIDR filtering without attacker-controlled pointer arithmetic;
- Observe → Canary → Enforce safety gates, management allowlist, Emergency Stop, automatic degradation, XDR and signed policy generations;
- Swarm/Mesh remains deliberately deferred.
