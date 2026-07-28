# GeDefense native GaiaOS integration

This directory is the GaiaOS integration surface shipped from the independent
GeDefense repository.

GeDefense and GaiaOS remain separate GitHub projects:

- GeDefense owns the security engine, modules, APIs, broker, eBPF programs,
  release gates and generic Linux installer.
- GaiaOS owns the Arch image, KDE experience, recovery system and Gaia Cells
  lifecycle runtime.
- GaiaOS contains a complete, independently buildable source mirror at
  `GaiaOS/gedefense`. The mirror is byte-verified and may not diverge into a
  separate security-core fork.

`contract.json` is copied unchanged to
`GaiaOS/integration/gedefense/contract.json`. The integration verifier fails
when product version, schema or profile-file digests diverge. The full-source
mirror is synchronized and verified with:

```bash
python3 scripts/sync-gaiaos-gedefense.py sync /path/to/GaiaOS
python3 scripts/sync-gaiaos-gedefense.py verify /path/to/GaiaOS
```

The mirror contains the Go control/access planes, Rust broker and eBPF code,
web interface, tests, packaging, CI configuration, security documentation and
GaiaOS adapter contract. Generated binaries, installer artifacts, build caches
and repository-private metadata are deliberately excluded.

## Runtime authority

Only GeDefense may enforce security policy. Sentinel remains a migration source
until every selected module has passed the GeDefense security gates. The final
GaiaOS image must not enable Sentinel and GeDefense as concurrent firewall or
response authorities.

## GaiaOS profile

`gaiaos-profile.toml` and the native integration package extend the generic
GeDefense deployment with:

- GaiaOS system identity;
- linux-hardened boot artifacts;
- GaiaOS sysctl, nftables and AppArmor policy files;
- the GaiaOS package database;
- authenticated Gaia Cells v1 runtime discovery and response;
- idempotent key, TLS, baseline and first-login provisioning;
- a local HTTPS application launcher with a certificate-SPKI pin.

The profile remains valid when Gaia Cells is absent. Cell identity is accepted
only from the authenticated, versioned `VGTGC1` runtime contract. The adapter
never infers cells from arbitrary process or cgroup names.

## Synchronization gate

From the GeDefense repository, verify the profile contract:

```bash
python3 integration/gaiaos/verify_sync.py /path/to/GaiaOS
```

The check is read-only and suitable for both projects' CI pipelines.
