# Changelog

## 4.0.1 — Chinese Localization, Dedicated XDR Kernel Recovery Tab & Startscreen Expansion

- **Simplified Chinese (`zh-CN` / `ZH`) Localization**:
  - Added complete Simplified Chinese translation catalog across all Command Center tabs, dialogs, operations, placeholders, and runtime toasts (743 keys, 100% parity across DE, EN, RU, and zh-CN).
  - Integrated Chinese (`ZH` / `zh-CN`) on the public Access Gateway Startscreen (`gateway/main.go`) with localized copy (`主权安全控制平面`, `操作员访问`, etc.) and cookie/query language switching.
  - Added automatic `Accept-Language` detection for `zh`, `zh-CN`, and `zh-Hans`.
- **Dedicated XDR Kernel Recovery Tab & Safe State Reset**:
  - Added a dedicated XDR Kernel Recovery interface tab and workflow (`#xdr` recovery view) allowing operators to inspect, recover, and re-initialize the kernel sensor stack directly from the UI if issues arise after installation.
  - Implemented authenticated `/api/v1/xdr/recovery` endpoint with strict `ARCHIVE_AND_REINITIALIZE_XDR` confirmation gating.
  - Byte-for-byte archiving of corrupted or degraded incident ledger chains into `/var/lib/vgt/gedefense/xdr-recovery/` with cryptographic SHA-256 manifests.
  - Crash-safe initialization of fresh incident chains while strictly preserving storage master keys, sensor IPC tokens, and operator credentials.
  - Re-initializes kernel eBPF sensors, BPF-LSM hooks, ring buffer attachments, and process monitors.
  - Requires disk verification and an immutable signed Evidence Ledger commit before transitioning out of sticky `DEGRADED` status.
- **Correlation & Ledger Hash Integrity**:
  - Separated attack-story Merkle evidence root (`evidence_root`) from incident ledger MAC chain hashes (`record_hash`), preventing valid correlated incidents from becoming unverifiable across reboots.
  - Hardened XDR status propagation to prevent routine telemetry polling from masking degraded kernel states.
- **Version 4.0.1 Release Alignment**:
  - Updated all core binaries, access gateway, web UI assets, Rust workspace crates, packaging manifests, and integration contracts to version `4.0.1`.

## 4.0.0-beta.1 — Native L7 Application Security & Correlation Hardening

- Added complete Simplified Chinese (`zh-CN`) Command Center localization and browser-language detection for `zh-CN`/`zh-Hans`, while preserving German, English and Russian.
- Audited all Command Center tabs, dialogs, operations, placeholders and runtime toasts for translation coverage; moved remaining user-facing hardcoded strings behind the shared i18n catalog and added catalog/placeholder parity validation.
- Corrected the operator-key privacy text to match implementation: the key remains in volatile tab memory and is discarded on reload; it is not persisted in browser storage.
- Added a native, standard-library-only L7 application-security plane with bounded HTTP normalization, deterministic candidate extraction and fail-closed resource budgets.
- Added optional Unix-socket inline enforcement with static local upstreams only; no scripting runtime, plugin engine, dynamic upstream resolution or new third-party dependency is required.
- Added request detection for SQL injection, XSS, command injection, path traversal/file inclusion, SSTI, XXE, unsafe deserialization/JNDI patterns, scanner probes, protocol ambiguity, SSRF and upload abuse.
- Added bounded gzip/deflate inspection, encoded-input canonicalization and evasive IPv4/URL representation handling without changing forwarded request bytes.
- Added response leak inspection that preserves the exact response wire body while emitting bounded, hashed evidence only.
- Connected L7 findings to XDR attack-story correlation while keeping web-only evidence alert-only for destructive host-response scoring.
- Added shared global admission, candidate, memory, parser and cardinality budgets across inspection and inline paths.
- Hardened local trust boundaries with pre-provisioned runtime directories, restrictive Unix-socket DAC, Linux peer credentials, forwarding-header reconstruction and removal of authentication secrets from inspection state.
- Added route/host canonicalization for policy and rate decisions while retaining original request paths for forensic evidence.
- Extended release gates with L7 unit, race, fuzz, static-security, packaging and dependency invariants.
- Added an explicit fail-closed XDR incident-ledger recovery workflow: corrupt chains are archived byte-for-byte with SHA-256 manifests, source stability is rechecked before replacement, authentication/storage keys are preserved, a fresh empty chain is created crash-safely, and XDR leaves `DEGRADED` only after disk verification plus mandatory Evidence Ledger commits.
- Hardened XDR status propagation so routine sensor refreshes cannot accidentally erase a sticky degraded state; only an explicit verified recovery path may clear it.
- Fixed a semantic hash-domain collision in XDR incidents: attack-story Merkle evidence now uses the dedicated `evidence_root` field while `record_hash` is reserved exclusively for the authenticated incident-ledger chain. Pre-populated caller hashes are explicitly cleared before ledger MAC calculation, preventing otherwise valid correlated incidents from becoming unverifiable on restart.

## 3.0.0-beta.1 — Beta v3 Universal Linux & AstraeaOS Deep Integration (VGT Doktrin DIAMANT)

- Integrated TRINITY XDR 2.0 Directed Acyclic Graph (DAG) for causal attack stories with Merkle-root cryptographic proof chaining.
- Integrated Reversible Response Engine with semantic TTL presets (300s, 900s, 3600s), 4x repeat offender escalation, and automatic background rollback.
- Integrated Nemesis & Ghost Trap Linux Deception Grid with canary file placement, path jailing, and zero-false-positive process freeze.
- Added Dynamic Capability Detection (Dual-Mode) for transparent runtime detection of AstraeaOS native enclaves vs. generic Linux distributions.

## 3.0.0-beta.1 — Beta v3 universal Linux integration

- Promoted portable AstraeaOS readiness, desktop and privilege-boundary
  contracts into the generic Linux release payload.
- Added APT, DNF/YUM, pacman and Zypper installer coverage.
- Added a local SPKI-pinned Chromium application profile without changing the
  global trust store.
- Preserved AstraeaOS-only SDDM, ArchISO and Gaia Cells behavior as conditional
  adapters instead of imposing those assumptions on other distributions.
- Added mandatory Go race/fuzz/security, pinned Rust/eBPF release-build and
  cryptographic artifact gates to the Beta v3 CI.
- Added containerized Ubuntu, Fedora, Arch and openSUSE integration contracts.
- Added a privileged installed-host gate for systemd, authenticated readiness,
  bpffs, verifier-visible eBPF programs, concrete NIC XDP attachment, polkit and
  desktop metadata.
- Added loopback and localhost SAN identities to generated gateway certificates
  so the local pinned desktop application and the configured remote identity
  share one explicitly scoped leaf certificate.

## 1.0.0-beta.5 Complete Beta

- Added root-cgroup IPv4/IPv6 egress enforcement and bounded, authenticated
  XDR drop telemetry for signed CIDR policy targets.
- Added a real `sched_process_exec` eBPF sensor, bounded Ring Buffer,
  authenticated event retrieval and procfs identity enrichment/fallback.
- Added bounded local Pacman `.MTREE` SHA-256 package integrity scanning with
  asynchronous API, hardening-posture integration and dedicated UI findings.
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
- Added atomically persisted server/AstraeaOS hardening profiles with runtime and
  boot-state rollback.
- Replaced the AstraeaOS Sentinel runtime package path with native GeDefense
  packages, provisioning, systemd activation and a pinned local TLS launcher.
- Added privacy-safe installer prompts and actionable activation diagnostics.

## 1.0.0-beta.5 hardening continuation

- added the encrypted durable Transaction Engine with exact preview binding, confirmation-gated apply/reverse, crash recovery, reboot reconciliation and runtime-drift quarantine;
- added typed Rust broker commands for allowlisted sysctl reads and compare-and-set writes with post-state verification;
- added reversible generic Linux server and AstraeaOS workstation hardening profiles without a shell or generic privileged file-write primitive;
- added the hardened Prometheus FIM successor with bounded traversal, race-aware regular-file hashing, SHA-256 content and mode verification, encrypted authenticated baselines and tamper quarantine;
- added authenticated FIM status, scan and baseline APIs whose operator mutations pass through the mandatory Evidence Ledger gate;
- added a complete manifest-verified GeDefense source mirror under `AstraeaOS/gedefense` plus local Arch package builds without developer-path dependencies;
- added Evidence Ledger v2 with per-record Ed25519 signatures, AES-256-GCM record encryption, sequence-bound AAD, durable head checkpoints, truncation detection, bounded replay and fail-closed mutation gates;
- added mandatory pre-action evidence intents for authenticated operator mutations and automated XDR response;
- added a versioned AstraeaOS integration contract, strict AstraeaOS runtime profile and byte-level cross-repository synchronization verifier;
- established the AstraeaOS/Sentinel fusion architecture with GeDefense as the single security authority for generic Linux and AstraeaOS;
- added an authenticated evidence-only Boot Trust API covering AstraeaOS identity, Secure Boot state, kernel lockdown, redacted boot-parameter evidence, TPM presence, cgroup v2, Gaia Cells runtime presence and bounded kernel-image hashing;
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
