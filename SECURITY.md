# Security Policy

GeDefense 1.0.0-beta.5 is a security-sensitive full-stack beta. It starts in Observe and requires explicit, gated operator action before Canary or Enforce.

## Security invariants

- The public gateway and control plane run as the unprivileged `gedefense` user.
- The Rust core accepts IPC only from the configured control UID and verifies HMAC, timestamp and nonce replay state.
- Service-private keys and password records must be regular non-symlink files with mode `0600`; the root-owned core IPC key uses the narrowly shared `root:gedefense 0640` profile.
- The management allowlist is evaluated before the blocklist in XDP.
- Enforce is unavailable while that allowlist is empty or not synchronized.
- Public feeds enrich local correlation but are never automatically applied to XDP.
- Policy state is Ed25519-signed. Runtime settings and behavior/incident state are authenticated separately.
- Process actions use PID identity checks and pidfds. Kill requires objective evidence revalidation in the Rust broker.
- Emergency Stop is reported successful only after authoritative core-ledger clearing, authenticated empty-map verification and signed Observe-policy persistence; every intermediate failure remains Degraded/Unverified.

## Reporting

Do not publish a suspected vulnerability before coordinated review. Include version, Linux distribution/kernel, reproduction steps, expected behavior, observed behavior and relevant redacted logs. Never include dashboard passwords, bearer tokens, private keys or unredacted customer data.

## Beta limitation

XDP protects only within the capacity of the host's network path. Upstream link saturation still requires provider or edge capacity. This software does not replace provider-scale volumetric DDoS mitigation.
