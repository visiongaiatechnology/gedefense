# Build Runbook — VGT GeDefense 1.0.0-beta.5

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
