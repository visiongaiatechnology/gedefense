# Build Runbook — VGT GeDefense Beta v3 (3.0.0-beta.1)

## Go and frontend validation

```bash
make test
make test-race
make go gateway
```

Validated release environment: Go 1.23.2 and Node.js 22.16.0.

## Rust/XDP target build

```bash
rustup toolchain install 1.97.1 --profile minimal
rustup toolchain install nightly-2026-07-16 --profile minimal --component rust-src
cargo +1.97.1 install bpf-linker --version 0.10.3 --locked
cargo +nightly-2026-07-16 build --locked --manifest-path rust/Cargo.toml -p gedefense-ebpf --release --target bpfel-unknown-none -Z build-std=core
cargo +1.97.1 test --locked --manifest-path rust/Cargo.toml -p gedefense-common -p gedefense-core
cargo +1.97.1 build --locked --manifest-path rust/Cargo.toml -p gedefense-core --release
```

The eBPF verifier and NIC attach result can only be qualified on the destination Linux host. The RUN installer performs that qualification transactionally and rolls back before replacing a working installation when any gate fails.

## Beta v3 mandatory release gates

The default CI workflow blocks release unless all Go unit/vet/race gates,
security fuzz smoke tests, the static security audit, Rust userspace tests, the
release eBPF build, the four-family distribution contract matrix and release
artifact verification pass.

The distribution matrix covers Ubuntu/Debian, Fedora/RHEL-compatible systems,
Arch Linux and openSUSE. Containers validate package-manager dependencies,
shell contracts, desktop metadata and the polkit policy. Containers do not
claim to qualify their host kernel.

After installing the generated RUN artifact on each release-candidate host,
execute the privileged concrete-host gate:

```bash
sudo ./scripts/validate-installed-linux-host.sh <network-interface>
```

This gate fails unless systemd units are valid, enabled and active; the HMAC
core socket and authenticated control/TLS endpoints respond; XDP is attached to
the selected NIC; bpffs is mounted; GeDefense programs are visible to bpftool;
and the installed polkit and desktop contracts parse correctly.

The same gate can be dispatched through
`.github/workflows/linux-host-qualification.yml` to a dedicated self-hosted
runner labeled `gedefense-kernel-test`. A release must retain the resulting job
log as kernel/NIC qualification evidence for every supported distribution and
kernel class.
