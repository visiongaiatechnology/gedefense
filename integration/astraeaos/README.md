# GeDefense native AstraeaOS integration

This directory is the AstraeaOS integration surface shipped from the independent
GeDefense repository.

GeDefense and AstraeaOS remain separate GitHub projects:

- GeDefense owns the security engine, modules, APIs, broker, eBPF programs,
  release gates and generic Linux installer.
- AstraeaOS owns the Arch image, KDE experience, recovery system and Gaia Cells
  lifecycle runtime.
- AstraeaOS contains a complete, independently buildable source mirror at
  `AstraeaOS/gedefense`. The mirror is byte-verified and may not diverge into a
  separate security-core fork.

`contract.json` is copied unchanged to
`AstraeaOS/integration/gedefense/contract.json`. The integration verifier fails
when product version, schema or profile-file digests diverge. The full-source
mirror is synchronized and verified with:

```bash
python3 scripts/sync-astraeaos-gedefense.py sync /path/to/AstraeaOS
python3 scripts/sync-astraeaos-gedefense.py verify /path/to/AstraeaOS
```

The mirror contains the Go control/access planes, Rust broker and eBPF code,
web interface, tests, packaging, CI configuration, security documentation and
AstraeaOS adapter contract. Generated binaries, installer artifacts, build caches
and repository-private metadata are deliberately excluded.

## Runtime authority

Only GeDefense may enforce security policy. Sentinel remains a migration source
until every selected module has passed the GeDefense security gates. The final
AstraeaOS image must not enable Sentinel and GeDefense as concurrent firewall or
response authorities.

## AstraeaOS profile

`astraeaos-profile.toml` and the native integration package extend the generic
GeDefense deployment with:

- AstraeaOS system identity;
- linux-hardened boot artifacts;
- AstraeaOS sysctl, nftables and AppArmor policy files;
- the AstraeaOS package database;
- authenticated Gaia Cells v1 runtime discovery and response;
- idempotent key, TLS, baseline and first-login provisioning;
- a local HTTPS application launcher with Chromium SPKI pinning and a managed
  Firefox certificate policy.

During first provisioning, an untouched packaged generic profile is replaced
atomically with the AstraeaOS profile. Operator-modified configurations are never
overwritten. The AstraeaOS systemd drop-in binds the authenticated TLS gateway
exclusively to `127.0.0.1:9843`; the internal control plane remains isolated on
`127.0.0.1:9844`.

The profile remains valid when Gaia Cells is absent. Cell identity is accepted
only from the authenticated, versioned `VGTGC1` runtime contract. The adapter never infers cells from arbitrary process or cgroup names. Networked cells remain guarded until GeDefense issues a short-lived HMAC-authenticated lease for an allowlisted profile and the exact `(UUID, generation, cgroup inode, policy digest)` identity.

## Synchronization gate

From the GeDefense repository, verify the profile contract:

```bash
python3 integration/astraeaos/verify_sync.py /path/to/AstraeaOS
```

The check is read-only and suitable for both projects' CI pipelines.
