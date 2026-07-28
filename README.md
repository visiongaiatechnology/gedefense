# GeDefense 1.0.0-beta.5

**GeDefense powered by VisionGaiaTechnology** is a sovereign Linux network-defense and XDR stack. This beta connects the complete local defense chain except for the deliberately deferred Swarm/Mesh layer:

```text
Browser / TLS Gateway
          ↓ authenticated operator session
Go Control Plane + embedded Command Center
          ↓ HMAC-authenticated VGT3 IPC + SO_PEERCRED
Privileged Rust Response Core
          ↓ Aya
Rust no_std eBPF/XDP Data Plane
          ↓
Linux network interface
```

## Product experience

- unified login and Command Center branding;
- consistent GeDefense and VisionGaiaTechnology identity and version display;
- German, English and Russian UI for static and dynamic content;
- local responsive interface with no CDN, remote script, webfont or frontend framework;
- optional support dialog containing the published VGT PayPal, Bitcoin, ETH and USDT addresses;
- no payment SDK, tracker or automatic wallet interaction.

## Included and operational

- Rust XDP program with IPv4/IPv6 LPM management allowlists and blocklists;
- Rust core with native-XDP first and generic-XDP fallback;
- HMAC-authenticated IPC, replay protection and peer-UID verification;
- PID-identity-safe `pidfd` containment and evidence-gated kill path;
- Go XDR process, network, integrity and adaptive-behavior correlation;
- Ed25519-signed policy generations and authenticated incident history;
- public TLS password gateway with server-side bearer-token injection;
- runtime controls for XDR, network correlation, behavior learning, feeds, automatic feed sync, auto-degrade, intervals and thresholds;
- individually switchable command, lineage, masquerading, origin and threat-intelligence signal modules;
- dashboard-managed RE2 custom rules with bounded alert scoring and no direct active-response authority;
- dashboard-managed management allowlist, block rules, staged release promotion, Emergency Stop and recovery;
- authenticated evidence-only host and boot trust reporting for generic Linux and GaiaOS;
- encrypted Ed25519 Evidence Ledger with truncation detection and fail-closed operator/XDR mutation intents;
- encrypted protected-path FIM baselines with bounded traversal, race-aware
  hashing and explicit verified/tampered/quarantined state;
- durable encrypted security transactions with
  `Preview → Authorize → Apply → Verify → Audit → Reverse`, startup
  reconciliation and runtime-drift quarantine;
- brokered generic-server and GaiaOS-workstation sysctl hardening profiles
  using an exact key/value allowlist, atomic boot persistence and reversible
  compare-and-set kernel mutations;
- bounded AES-256-GCM quarantine with content identity, atomic source capture,
  tamper verification and identity-preserving restore;
- encrypted durable case correlation with recurrence handling, evidence-gated
  status transitions and fail-closed integrity state;
- authenticated Gaia Cells v1 discovery and reversible freeze/network-response
  transaction adapter bound to UUID, generation and kernel cgroup ID;
- native GaiaOS provisioning, systemd activation and local HTTPS application
  launcher while retaining identical control, broker and eBPF binaries;

The GaiaOS integration and Sentinel capability migration are governed by
[`GEDEFENSE-GAIAOS-INTEGRATION.md`](GEDEFENSE-GAIAOS-INTEGRATION.md). GaiaOS
contains a byte-verified, independently buildable GeDefense source mirror and
uses the same engine as a generic Linux server. Boot Trust, the Evidence
Ledger, hardened FIM, Transaction Engine, encrypted Response Vault and Case
Engine are Sentinel capabilities already re-engineered into the shared core.
Optional Gaia Core and Gaia Cells providers extend evidence and isolation
context without becoming hard runtime dependencies.

GaiaOS consumes the exact versioned files under `integration/gaiaos/` and the
complete mirrored tree under `GaiaOS/gedefense`.
`scripts/sync-gaiaos-gedefense.py` rejects source drift; `verify_sync.py`
rejects version, authority, profile or integration-file digest drift.
- Observe → Canary → Enforce safety gates and automatic degradation.

## Authentication and encrypted storage

New operator passwords are stored with Argon2id:

```text
memory: 64 MiB
iterations: 3
parallelism: 1
salt: 128 random bits
output: 256 bits
```

Valid PBKDF2 records from earlier releases are accepted only for migration and are atomically upgraded after successful authentication.

Sensitive operational state is stored in AES-256-GCM envelopes with random nonces and purpose-separated keys. AAD binds each record to its schema, node, purpose, canonical path and sequence. Runtime settings, policy snapshots, the policy private key, behavior profiles, incident records and chain checkpoints are encrypted. Public certificates, public verification keys and the minimum unattended-start secrets remain permission-protected rather than self-encrypted.

## Browser and backend security

- synchronizer-token login CSRF protection;
- explicit cross-site rejection and exact-origin requirements for authenticated mutations;
- `Secure`, `HttpOnly`, `SameSite=Strict`, `__Host-` session cookie;
- strict Host allowlisting and TLS 1.3 gateway;
- server-side backend bearer injection; browser Authorization, cookies, Origin, Referer and forwarding identity are discarded;
- strict CSP, framing prohibition, MIME sniffing protection and cross-origin isolation headers;
- no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, Function constructor or inline event handlers;
- HTTPS-only feed downloads with proxy disabled and dial-time SSRF rejection of local/private/link-local/multicast destinations;
- no runtime command execution primitive in the network-facing Go services;
- optional direct-loopback bearer keys remain only in volatile tab memory and are discarded on reload.

Run the security regression audit with:

```bash
./scripts/security-audit.sh
```

The detailed review is documented in `SECURITY-AUDIT-BETA5.md`.

## Deliberately not included

- Swarm/Mesh federation;
- QUIC offloading or distributed attack absorption;
- automatic enforcement of public threat feeds;
- TLS payload interception or decryption;
- claims of provider-level DDoS absorption beyond the bandwidth reaching the host.

## Safety model

Installation attaches an empty XDP policy and starts in **Observe** only after the privileged core has authoritatively cleared and authenticated the blocklist state and the control plane has persisted a signed Observe policy. A failed startup verification remains Degraded/Unverified. Traffic is passed unless the operator later promotes the node and creates signed block rules. Enforce remains unavailable while the management allowlist is empty or unsynchronized.

Canary permits evidence-checked process containment while network rules remain observational. Enforce activates signed CIDR rules and the independently checked response path.

Emergency Stop is a verified fail-safe transaction. It first disables active response, removes every block known to the privileged core, requires an authenticated `VERIFY_EMPTY` confirmation and durably persists a signed Observe policy. The dashboard reports `verified-empty` only after every step succeeds. Any failure remains explicitly `unverified`, returns an error and is retried when the core heartbeat recovers.

## Operator rule workspace

Operators can enable or disable individual built-in signal modules and define up to 64 bounded RE2 rules with stable IDs, categories, summaries and scores. Patterns are compiled only when the signed runtime-settings revision changes. Custom-rule matches remain visible in incident scoring, but are excluded from `response_score` and cannot authorize containment or termination. Module and custom-rule mutations are accepted only in Observe or Degraded mode.

## One-click installation

```bash
chmod 700 VGT_GeDefense_Beta_1.0.0-beta.5_OneClick.run
sudo bash VGT_GeDefense_Beta_1.0.0-beta.5_OneClick.run
```

The installer compiles the Rust core and eBPF object on the target host because verifier compatibility depends on the destination kernel and NIC. It does not replace the active release unless compilation, service startup, authenticated IPC, XDP attachment, control-plane health and HTTPS gateway checks succeed.

Supported beta target: Linux x86_64, systemd, BPF-capable kernel and internet access during the pinned Rust dependency/toolchain build.

## Source validation and packaging

```bash
make test
make test-race
make go gateway
./scripts/security-audit.sh
./scripts/package-artifacts.sh ./release
```

The source ZIP excludes binaries, target directories, local keys, tokens, logs and VCS state and includes `SOURCE-MANIFEST.sha256`. The committed Rust lockfile is included and enforced with `--locked`. The RUN payload includes the validated Go executables plus Rust/eBPF source; privileged artifacts are rebuilt and verified on the destination.

## Source build

```bash
make test
make go
make gateway
```

The gateway requires `libargon2.so.1` and is built with CGO enabled. The control plane remains a static CGO-disabled binary.

Rust target build:

```bash
rustup toolchain install 1.97.1 --profile minimal
rustup toolchain install nightly-2026-07-16 --profile minimal --component rust-src
cargo +1.97.1 install bpf-linker --version 0.10.3 --locked
make rust
```

## License

AGPL-3.0-only. Copyright VisionGaia Technology.
