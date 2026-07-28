# GeDefense 1.0.0-beta.5 — Architecture

## Trust domains

1. **Public access gateway — Go, unprivileged**  
   TLS 1.3, Argon2id password verification, synchronizer-token login CSRF, strict session/origin policy, Host allowlist and reverse-proxy trust-boundary cleanup. Browser credentials and forwarding headers never reach the backend.

2. **Control plane — Go, unprivileged**  
   Command Center, telemetry, encrypted operational state, signed policy generations, XDR, behavior profiles, feed staging, forensic exports, evidence-only boot trust and release gates. It binds to loopback and requires a private bearer token injected by the gateway.

3. **Response core — Rust, privileged and capability-bounded**  
   Loads XDP, owns maps, authenticates VGT3 IPC with HMAC/replay protection, verifies peer UID with `SO_PEERCRED`, rechecks process identity and performs narrowly typed kernel/process actions.

4. **Kernel data plane — Rust no_std eBPF/XDP**  
   Bounded Ethernet/VLAN/IPv4/IPv6 parsing, management allowlist before blocklist, longest-prefix CIDR matching and fail-open handling of malformed/truncated headers.

## Runtime flow

```text
HTTPS operator session
  → same-origin control mutation
  → gateway strips browser trust metadata
  → backend bearer + replay ID validation
  → normalized state mutation
  → encrypted storage + signed policy generation
  → HMAC VGT3 command over mode-0660 Unix socket
  → Rust map update or pidfd action
  → result and signed evidence returned to dashboard
```

## Storage trust model

```text
/etc/vgt/gedefense/secrets/storage-master.key
  → HMAC-SHA-256 purpose subkey
  → AES-256-GCM envelope
  → AAD(schema,node,purpose,path,sequence)
```

The storage key never leaves the host. Operational stores are private regular files and reject symlinks, excessive permissions, oversized contents, malformed envelopes, wrong AAD and failed GCM authentication. Supported legacy plaintext is migrated atomically.

## Evidence Ledger v2

Security events use an independent append-only ledger. Every canonical record
contains a monotonic sequence, predecessor hash and bounded event fields. Its
domain-separated SHA-256 digest is signed with Ed25519, then the complete record
is encrypted with the node storage key and sequence-bound AAD. A separately
encrypted, atomically committed head checkpoint detects tail truncation.

Authenticated operator mutations and automated XDR responses must durably
commit an intent before executing. A missing, externally modified, oversized or
unverifiable ledger disables new active response and blocks release readiness.
Emergency Stop remains executable because a safety shutdown must never depend
on audit storage availability.

## Protected-path integrity plane

The hardened successor to Sentinel Prometheus FIM monitors the configured XDR
protected paths. Directory traversal, file cardinality, per-file size and total
bytes are bounded. Symlinks and non-regular objects are never trusted. The
engine compares file identity before and after streaming SHA-256 hashing to
detect replacement races and verifies both content and permission mode.

Baselines are stored as AES-256-GCM envelopes bound to node, path, purpose and
generation. Authentication failure quarantines the baseline. Baseline creation
and manual scanning are authenticated operator mutations and therefore commit
an Evidence Ledger intent before execution.

## Durable security transactions

Every reversible hardening action follows
`Preview → Authorize → Apply → Verify → Audit → Reverse`. Preview captures the
live before-state and hashes it with the typed plan. The complete transaction
history is stored in a generation-bound AES-256-GCM envelope. Apply and reverse
require exact transaction-specific confirmation strings and mandatory Evidence
Ledger intents.

The privileged Rust broker exposes no generic sysctl or filesystem primitive.
It accepts only exact allowlisted sysctl keys and typed scalar domains. Each
write is a compare-and-set operation followed by a kernel read-back. A partial
profile failure reverses already-applied keys in reverse order.

An interrupted `applying` or `reversing` state becomes `recovery_required` at
startup and blocks new mutations. Applied profiles are reconciled after reboot
and verified periodically; external drift quarantines the transaction instead
of silently overwriting an administrator- or attacker-controlled state.

## Authentication model

The public gateway owns operator authentication. Sessions are stateless HMAC-authenticated values with bounded expiry and random nonce, placed in a `Secure`, `HttpOnly`, `SameSite=Strict`, `__Host-` cookie. The browser never receives the backend token. Authenticated mutations require an exact HTTPS Origin; login additionally requires the synchronizer CSRF token and rejects explicit cross-site fetch metadata.

## XDR and response

The XDR engine samples `/proc` and Linux network tables with bounded queues and cardinality budgets. Independent signal categories include command behavior, executable location, lineage, remote endpoints, integrity baselines and adaptive behavior. Adaptive deviation cannot independently authorize a kill.

Canary uses `pidfd_send_signal(SIGSTOP)`. Enforce permits `SIGKILL` only when the Rust core independently rechecks objective evidence and PID start identity.

## Release states

- **Observe:** XDP attached, no signed block rule placed in the kernel, XDR records only.
- **Canary:** network remains observational; eligible process incidents may be contained.
- **Enforce:** signed CIDR rules are reconciled into XDP and evidence-gated response is active.
- **Degraded:** fail-safe state; active response is disabled while kernel-policy verification is pending or failed.

Emergency Stop and automatic degradation use one verified transaction:

```text
disable new response
  → mark kernel state unverified
  → remove every ledgered kernel block
  → authenticated VERIFY_EMPTY against the Rust core
  → persist a signed Observe policy
  → publish verified-empty
```

The same transaction gates startup Observe before the node becomes ready. No intermediate failure is reported as safe. A recovered authenticated core heartbeat retries unfinished reconciliation.

## Configurable signal fabric

Built-in command, lineage, masquerading, origin and threat-intelligence evaluators are isolated modules selected by signed runtime settings. Operator-defined RE2 rules are bounded by count, expression length and score, compiled once per settings revision and evaluated as alert-only signals. Their scores are deliberately excluded from the independently calculated response score, so configuration cannot manufacture process-kill authority.

## GaiaOS integration

GeDefense is the single security authority on generic Linux and GaiaOS. GaiaOS
adds optional platform evidence and, once a real versioned runtime exists, Gaia
Cells metadata. The integration never introduces a second firewall or response
daemon. Cell lifecycle remains owned by Gaia Cells; GeDefense policy and
response bind to immutable cell generations and kernel cgroup IDs.

The current host-trust collector reports evidence only. Secure Boot variables,
kernel lockdown, TPM device presence, cgroup v2, GaiaOS identity and a kernel
image digest are observations rather than an unsupported claim of a complete
measured-boot chain.

See `GEDEFENSE-GAIAOS-INTEGRATION.md` for the capability migration matrix,
trust boundaries and delivery sequence.

## Deferred layer

Swarm/Mesh federation and QUIC offloading are intentionally outside 1.0.0-beta.5.
