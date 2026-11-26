# Security Policy

> [!CAUTION]
> **ALPHA TEST — GeDefense WP ↔ Linux Bridge.** The new WordPress bridge is an alpha preview, not production-ready. A fully compromised WordPress can forge bridge records while it holds the shared secret. The Linux lease is limited to two hours, IP/host-bound and only relaxes L7 rate limits/content-pattern checks on verified admin write surfaces. WAF, protocol, upload and kernel enforcement remain active. Do not use the bridge in unsupervised production and do not treat a passing test as a security certification.


GeDefense 6.3.0 (V6) is a security-sensitive universal Linux security fabric.
It starts in Observe with all new V6 subsystems (StyX Egress, Titan Exec-Gate, Ephemeral Parser Cells, Witness Client, Emergency Lockdown) **off by default** (Settings v17) and requires explicit, gated operator action before Canary or Enforce or activating Phase-1 defense planes. External trust-anchor and per-host qualification items remain documented in [CHANGELOG.md](CHANGELOG.md).

## Security invariants

- The public gateway runs as the dedicated unprivileged `gedefense-access` user. The control plane runs as `gedefense` with **zero** Linux capabilities (`CapabilityBoundingSet=`, no `AmbientCapabilities`, no `AF_PACKET`).
- Passive `AF_PACKET` capture (Module C) and `NETLINK_CONNECTOR` `CN_IDX_PROC` fallback (Module B) are isolated into the dedicated `gedefense-capture-helper.service` unit (`IPAddressDeny=any`, no `AF_INET`/`AF_INET6`, zero access to `/etc/vgt/gedefense`, `/var/lib/vgt/gedefense`, or `/run/vgt-gedefense`).
- The Rust core accepts IPC only from the configured control UID and verifies HMAC, timestamp and nonce replay state.
- Service-private keys and password records must be regular non-symlink files with mode `0600`; the root-owned core IPC key uses the narrowly shared `root:gedefense 0640` profile.
- The management allowlist is evaluated before the blocklist in XDP.
- Enforce is unavailable while that allowlist is empty or not synchronized.
- Public feeds enrich local correlation but are never automatically applied to XDP.
- Policy state is Ed25519-signed. Runtime settings and behavior/incident state are authenticated separately.
- Process actions use PID identity checks and pidfds. Kill requires objective evidence revalidation in the Rust broker.
- Emergency Stop is reported successful only after authoritative core-ledger clearing, authenticated empty-map verification and signed Observe-policy persistence; every intermediate failure remains Degraded/Unverified.

## Isolated capture-helper capability boundary (6.1.0, FIND-001 / FIND-008)

`gedefense-control.service` runs as the unprivileged `gedefense` user with
**zero Linux capabilities** (`CapabilityBoundingSet=`, no `AmbientCapabilities`)
and without `AF_PACKET`. Two 6.1.0 telemetry inputs require elevated network
privileges that are deliberately kept outside the control plane:

- **Module C (TLS sensor)** captures ClientHello/QUIC metadata with an
  `AF_PACKET` socket (`CAP_NET_RAW`).
- **Module B (worker guard)** falls back to `NETLINK_CONNECTOR` `CN_IDX_PROC`
  events when the eBPF crash source is unavailable (`CAP_NET_ADMIN`).

Both sockets live exclusively inside the dedicated
`gedefense-capture-helper.service` unit (`gedefense-control --capture-helper`):

- Runs as `User=gedefense`, `Group=gedefense`, `NoNewPrivileges=true`,
  `ProtectSystem=strict`, `ProtectHome=true`, `PrivateDevices=true`,
  `IPAddressDeny=any`, `RuntimeDirectory=vgt-gedefense-capture` (`0700`).
- Holds **only** `CAP_NET_RAW CAP_NET_ADMIN` (`CapabilityBoundingSet` +
  `AmbientCapabilities`) and `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_PACKET`
  (no `AF_INET`/`AF_INET6`).
- Has **zero** filesystem access to `/etc/vgt/gedefense`, `/var/lib/vgt/gedefense`,
  or `/run/vgt-gedefense` (cannot read keys, secrets, state, or talk to
  `core.sock` / `cell-helper.sock`).
- Streams strictly read-only bounded telemetry records (`Packet` / `ExitRecord`)
  to the control plane over `/run/vgt-gedefense-capture/capture.sock` (`0600`,
  `SO_PEERCRED` verified against `gedefense`/root UID, symlink-refused,
  bounded to 4 concurrent connections). Raw socket FDs are never passed.

Both units are pinned as exact allowlists in `scripts/security-audit.sh` and
`scripts/validate-systemd.sh`: adding capabilities or `AF_PACKET` back to
`gedefense-control.service`, or widening `gedefense-capture-helper.service`,
fails both gates.

## Reporting

Do not publish a suspected vulnerability before coordinated review. Include version, Linux distribution/kernel, reproduction steps, expected behavior, observed behavior and relevant redacted logs. Never include dashboard passwords, bearer tokens, private keys or unredacted customer data.

## Beta limitation

XDP protects only within the capacity of the host's network path. Upstream link saturation still requires provider or edge capacity. This software does not replace provider-scale volumetric DDoS mitigation.
