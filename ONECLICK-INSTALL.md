# GeDefense 4.1.0 One-Click Installer

## Install / Upgrade

```bash
chmod +x GeDefense-4.1.0-OneClick.run
sudo ./GeDefense-4.1.0-OneClick.run
```

The installer is source-self-contained. It verifies the embedded payload and its
per-file SHA-256 manifest, downloads the pinned Go 1.26.8 Linux/x86_64 toolchain
when necessary and verifies its official SHA-256 checksum, builds and tests the
Go control/gateway binaries, and then hands off to the existing transactional
GeDefense full-stack installer.

The transactional stage installs the pinned Rust toolchains, builds/tests the
Rust broker and eBPF program on the destination host, stages a versioned release,
validates systemd and authenticated health paths, and rolls back the previous
installation if activation fails.

Fresh installations prompt for the public host/port, optional management CIDR,
and a dashboard password. Existing compatible configuration and secrets are
preserved transactionally.

## Non-destructive verification

```bash
./GeDefense-4.1.0-OneClick.run --self-test
```

This verifies the embedded archive, per-file payload manifest, installer shell
syntax and Linux integration contract. It also reports host readiness without
changing packages, services, firewall state or files under `/opt`, `/etc` or
`/var/lib`.

`PENDING` is not a failure. It means a capability such as active systemd, bpffs,
bpftool, Rust or the pinned Go toolchain is not available in the environment
running the self-test and will need to be provided/installed for a real install.

## Supported install target

- Linux x86_64
- systemd as active init system
- APT, DNF/YUM, pacman or Zypper
- Internet access during first install for pinned Go/Rust toolchains
- Kernel/NIC capable of the GeDefense XDP/eBPF feature set

The target-host kernel/XDP qualification remains authoritative. A container or
source-level self-test cannot legitimately claim a real NIC attach or kernel
verifier PASS.
