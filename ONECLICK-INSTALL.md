# GeDefense 5.1.0-beta.3 One-Click Installer

## Install / Upgrade

```bash
chmod +x VGT_GeDefense_Beta_v5_5.1.0-beta.3_OneClick.run
sudo ./VGT_GeDefense_Beta_v5_5.1.0-beta.3_OneClick.run
```

The signed installer verifies its embedded Ed25519-signed release index,
release manifest and payload SHA-256 bindings before any privileged action. It
then hands off to the transactional GeDefense full-stack installer, which stages
a versioned release, validates systemd and authenticated health paths, and rolls
back the previous installation if activation fails.

The published 5.1.0-beta.3 installer is a prebuilt, signed release: the control,
gateway, Rust core and eBPF artifacts are the exact binaries covered by the
signed release manifest and SBOM.

Fresh installations prompt for the public host/port, optional management CIDR,
and a dashboard password. Existing compatible configuration and secrets are
preserved transactionally.

## Non-destructive verification

```bash
sha256sum --check VGT_GeDefense_Beta_v5_5.1.0-beta.3_OneClick.run.sha256
./VGT_GeDefense_Beta_v5_5.1.0-beta.3_OneClick.run --help
```

The installer verifies its signed release index and manifest internally before
any privileged action; `--help` prints the supported options without modifying
the host. The build pipeline's final offline verification is the authoritative
artifact check (signed manifest/index, SBOM, provenance and SHA256SUMS).

## Supported install target

- Linux x86_64
- systemd as active init system
- APT, DNF/YUM, pacman or Zypper
- Internet access during first install for pinned Go/Rust toolchains
- Kernel/NIC capable of the GeDefense XDP/eBPF feature set

The target-host kernel/XDP qualification remains authoritative. A container or
source-level self-test cannot legitimately claim a real NIC attach or kernel
verifier PASS.
