# Dependency Policy — VGT GeDefense 1.0.0-beta.5

## Go Control Plane

```text
Go 1.23.2
CGO_ENABLED=0
```

The control plane uses only the Go standard library and is emitted as a stripped static Linux/amd64 executable with trim paths, disabled VCS stamping and an empty build ID.

## HTTPS Gateway and Argon2id

```text
Go 1.23.2
CGO_ENABLED=1
libargon2.so.1
```

The gateway otherwise uses the Go standard library. Its only native runtime dependency is the system Argon2 implementation used for password hashing and verification. The installer installs `libargon2-1` on Debian/Ubuntu or `libargon2` on RPM-based systems, checks the ELF dependency and refuses activation if a linked library is unresolved.

No JavaScript, CSS, font, payment or localization dependency is downloaded at runtime.

## Rust Core and eBPF

Pinned direct dependencies:

```text
aya          0.14.0
aya-ebpf     0.2.1
libc         0.2.189
base64       0.22.1
hex          0.4.3
hmac         0.12.1
sha2         0.10.9
```

Pinned target-host toolchains:

```text
Rust Core       1.97.1
Rust eBPF       nightly-2026-07-16 + rust-src
bpf-linker      0.10.3
```

The one-click installer compiles the privileged artifacts on the target host because verifier acceptance and XDP attachment depend on the destination kernel and network driver. Activation is refused unless compilation, verifier acceptance, attachment and authenticated VGT3 IPC all succeed.

This beta ships and enforces a committed `Cargo.lock`; CI, packaging and the
target-host installer use `--locked`, so dependency resolution cannot drift.
A stable release should additionally ship a reviewed offline `cargo vendor`
tree, signed provenance and SPDX/CycloneDX SBOM. This beta does not claim those
remaining stable-release supply-chain gates are complete.

## Frontend validation

```text
Node.js 22.16.0
```

Node is used only for syntax validation. Browser execution is native HTML, CSS and ES modules embedded into the Go control binary.
