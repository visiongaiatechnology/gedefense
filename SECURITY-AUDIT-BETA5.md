# Security Audit — GeDefense 1.0.0-beta.5

## Result

The Beta 5 codebase underwent a focused source, unit and integration review for the requested classes: XSS, CSRF, authentication bypass, backend authorization, RCE, SSRF and encrypted-state handling. The automated regression gate is `scripts/security-audit.sh`.

This is an engineering security review, not an external certification or mathematical proof.

## XSS and browser injection

### Controls

- dashboard rendering uses `textContent`, DOM creation and property assignment;
- no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, Function constructor, `javascript:` URLs, `srcdoc` or inline event handlers;
- dashboard CSP permits scripts/styles only from the same embedded origin and disables objects, frames, workers, fonts and foreign connections;
- login HTML is rendered with `html/template`; its only inline CSS is authorized by a per-response random nonce;
- all operational values are returned as JSON and rendered as text.

### Regression checks

The audit scans every browser JS/HTML file and fails packaging if a forbidden sink is introduced.

## CSRF and Origin handling

### Login

- random 192-bit synchronizer token;
- token mirrored in an HttpOnly, Secure, SameSite=Strict cookie and hidden form field;
- constant-time equality check;
- explicit `Sec-Fetch-Site: cross-site` rejection;
- non-empty, non-opaque Origin must match the exact public HTTPS host;
- request body limited to 4 KiB.

An opaque `Origin: null` is accepted only at login because some browsers use it after a self-signed certificate exception. It does not bypass the synchronizer token.

### Authenticated mutations

- exact non-empty HTTPS Origin required by the gateway;
- `Origin: null`, missing Origin, HTTP Origin and foreign Origin rejected;
- backend mutation also requires a private bearer token and unique replay-resistant request ID;
- logout uses the same strict Origin gate.

## Authentication and session bypass

- new passwords use Argon2id (`64 MiB`, `t=3`, `p=1`);
- legacy PBKDF2 only supports controlled migration after a successful verification;
- password record must be a private regular non-symlink file;
- five failed attempts per source identity trigger a 15-minute lockout;
- lockout/session maps have hard cardinality bounds;
- sessions are HMAC-SHA-256 authenticated, include random nonce and bounded expiry, and use a `__Host-`, Secure, HttpOnly, SameSite=Strict cookie;
- forged, malformed, expired or implausibly long-lived sessions are rejected;
- session keys rotate when the gateway secret is replaced and sessions naturally invalidate on gateway secret change;
- optional direct-loopback bearer input remains only in volatile JavaScript memory and is discarded on reload, never written to Web Storage.

## Gateway/backend isolation

- backend accepts loopback binding only;
- browser bearer values are discarded;
- gateway injects the private backend token server-side;
- Origin, Referer, Cookie, Forwarded, X-Forwarded-* and fetch-metadata headers are removed;
- automatic ReverseProxy `X-Forwarded-For` insertion is explicitly suppressed;
- internal Host is rewritten to the fixed loopback backend;
- public Host header is allowlisted before routing;
- backend sensitive endpoints require bearer authentication;
- foreign Origin is rejected by the backend as a second layer.

## SSRF

Threat-feed retrieval:

- accepts absolute HTTPS URLs only;
- rejects userinfo, fragments, local pseudo-TLDs and non-443 ports;
- disables environment/system proxy use;
- resolves the destination immediately before dialing;
- rejects loopback, RFC1918/ULA, link-local, multicast and unspecified addresses;
- refuses cross-host and non-HTTPS redirects;
- applies timeouts, entry bounds and redirect bounds.

This mitigates URL parser abuse, direct IP SSRF, DNS rebinding to forbidden networks and proxy-based bypass for the feed subsystem.

## RCE and command execution

- no `os/exec`, `exec.Command` or `syscall.Exec` in the network-facing Go control plane or gateway;
- no `std::process::Command`, `Command::new`, `exec*`, `system()` or shell invocation in the Rust core/eBPF source;
- no user-controlled shell invocation;
- Rust-core actions are a closed typed VGT3 protocol, authenticated with HMAC, replay controls and peer credentials;
- process actions use validated numeric identity and `pidfd`, not command strings;
- feed content is parsed as bounded CIDR text and never executed;
- file paths are configuration-owned and validated as absolute/private where security-sensitive.

## Data at rest

Protected operational stores use AES-256-GCM with:

- random nonce per write;
- per-purpose HMAC-SHA-256 subkeys;
- AAD binding to schema, node, purpose, canonical path and sequence;
- strict JSON envelopes and trailing-data rejection;
- bounded private regular-file reads;
- authenticated legacy migration;
- atomic replacement.

GCM authentication failure, path/purpose relocation, sequence mismatch and ciphertext modification fail closed. Existing Ed25519 signatures and HMAC chains remain inside encryption.

## Security headers

Public gateway and control plane set appropriate combinations of:

- HSTS;
- CSP;
- X-Content-Type-Options;
- X-Frame-Options / frame-ancestors;
- Referrer-Policy;
- Permissions-Policy;
- Cross-Origin-Opener-Policy;
- Cross-Origin-Resource-Policy;
- Cross-Origin-Embedder-Policy on the dashboard;
- Origin-Agent-Cluster;
- X-Permitted-Cross-Domain-Policies.

## Known boundaries

- a host-root attacker can read locally available service keys and process memory;
- the self-signed default certificate warns browsers until replaced by a trusted certificate;
- feed ownership/authenticity still depends on HTTPS and the configured publisher unless separately signed feed formats are added;
- target-kernel eBPF acceptance and driver attachment can only be verified on the destination host;
- independent third-party audit and fuzzing remain advisable before a stable production release;
- Swarm/Mesh is not included or audited in this beta.

## Beta 5 hardening continuation

- Emergency Stop now fails closed: deletion failures, authenticated empty-map verification failures and signed-policy persistence failures remain visible as `unverified` and return errors.
- The Rust core maintains a mutation ledger and exposes an HMAC-authenticated `VERIFY_EMPTY` command; the Go client also bounds IPC responses to 4096 bytes.
- Operator-defined RE2 rules are strictly bounded, normalized and alert-only. Their scores cannot influence response thresholds or kill evidence.
- Built-in XDR evaluators can be switched independently only while the node is Observe or Degraded.
- The Ethernet/VLAN prefix parser is shared between the eBPF program and its host-side exhaustive tests and stdin fuzz harness.
- Native Go fuzz targets cover IPC responses, signed policy documents, encrypted storage envelopes and Linux `/proc` parsing.
- Rust dependencies are frozen by the committed `Cargo.lock`; CI, Makefile and installer builds enforce `--locked`.
