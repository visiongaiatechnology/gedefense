# GeDefense Linux 6.3.0 — Developer & Release Verification Guide

> **Canonical Sources:** [`../Makefile`](../Makefile) · [`../BUILD-RUNBOOK.md`](../BUILD-RUNBOOK.md) · [`../CI-POLICY.md`](../CI-POLICY.md) · [`../TOOLCHAINS.lock`](../TOOLCHAINS.lock) · [`../BETA-TEST-PLAN.md`](../BETA-TEST-PLAN.md)

---

## 1. Repository Layout

```text
├── control/        # Go control plane, XDR/SBC, L7 WAF, FIM, Ledger, WebUI embed
├── gateway/        # Go public HTTPS perimeter, Argon2id, RBAC, CSRF, Step-Up
├── rust/
│   ├── gedefense-common/       # Shared no_std/wire protocol decoders & flood buckets
│   ├── gedefense-ebpf/         # Kernel XDP, BPF-LSM, kprobe, tracepoint objects
│   ├── gedefense-core/         # Static-PIE musl privileged core & Vault
│   └── gedefense-cell-helper/  # Isolated ephemeral parser cell binary
├── desktop/        # Optional Qt 6 Linux desktop tray client
├── packaging/      # Arch/Fedora/Debian systemd units, sysusers, tmpfiles, templates
├── integration/    # AstraeaOS, universal Linux helpers & NGINX edge example
├── scripts/        # 10-stage security audit, validators, reproducible release tooling
├── docs/           # User, architecture, API, security & AP-0..AP-9 documentation
└── benchmarks/     # VGT HardRed 1.2 / 1.3 & REDHARD ARES evidence bundles
```

---

## 2. Running Test Suites & Static Security Audits

All security gates and tests are runnable directly on Linux (`WSL2` or native Ubuntu/Fedora/Arch host):

```bash
# 1. Go unit/integration tests + go vet + JS syntax check + 10-stage static audit
make test

# 2. Go race-detector suite (control + gateway)
make test-race

# 3. 24 security fuzz targets (smoke tests across IPC, L7, TUF, Witness, AP-0..AP-9)
make fuzz-smoke

# 4. Native Rust tests (common + core) and static-PIE musl + eBPF builds
make rust

# 5. Full Linux distribution, systemd, quarantine DAC & i18n validators
bash scripts/validate.sh
bash scripts/security-audit.sh
node scripts/validate-i18n.mjs
bash scripts/validate-systemd.sh
```

---

## 3. Reproducible Release Packaging (`6.3.0`)

Release archives and self-verifying `.run` installers are built with `scripts/package-artifacts.sh`, `scripts/build-source-oneclick.sh`, and `scripts/build-desktop-oneclick.sh` using an **offline Ed25519 signing key** outside the repository:

```bash
export RELEASE_SIGNING_PRIVATE_KEY=/path/to/offline/release-private.key
export RELEASE_SIGNING_PUBLIC_KEY=/path/to/offline/release-public.key

make full
bash scripts/package-artifacts.sh /tmp/gedefense-6.3.0-release-assets
bash scripts/build-source-oneclick.sh /tmp/gedefense-6.3.0-release-assets
bash scripts/build-desktop-oneclick.sh /tmp/gedefense-6.3.0-release-assets
```

Each generated release directory contains verified binary digests (`SHA256SUMS`), SPDX 2.3 SBOM (`sbom.spdx.json`), build provenance (`build-provenance.json`), signed Go manifest (`release-manifest.signed.json`), signed release index (`release-index.signed.json`), `.run` installers, and deterministic `Source.zip`.
