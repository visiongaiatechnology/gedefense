# GeDefense Linux 6.3.0 — Security Model, Cryptography & Known Limitations

> **Reference Policies:** [`../SECURITY.md`](../SECURITY.md) · [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) · [`../THREAT-MODEL.md`](../THREAT-MODEL.md) · [`../RELEASE-KEYS.md`](../RELEASE-KEYS.md)

---

## 1. Security Model & Core Invariants

GeDefense enforces strict privilege separation so a parser flaw, web payload, or compromised telemetry source cannot escalate directly to destructive host actions:

| Property | Enforcement Mechanism |
|---|---|
| **Unprivileged Perimeter** | `gedefense-access` (`:9843`) runs unprivileged, validates `Host`/`Origin`/CSRF, Argon2id (`64 MiB · t=3 · p=1`), server-side sessions (`__Host-vgt_gedefense_session`), and injects `.gateway-claim` HMAC headers + Bearer auth toward loopback `:9844`. |
| **Capability-Free Control Plane** | `gedefense-control` runs as `User=gedefense` on loopback `127.0.0.1:9844` with empty `CapabilityBoundingSet=` and zero `AF_PACKET`. |
| **Isolated Capture Helper** | `gedefense-capture-helper` isolates `CAP_NET_RAW` (`AF_PACKET`) and `CAP_NET_ADMIN` (`NETLINK_CONNECTOR`) with `IPAddressDeny=any`, zero `AF_INET`/`AF_INET6`, and zero access to keys/state/`core.sock`. |
| **Static-PIE musl Core** | `gedefense-core` (`UID 0` + bounded capabilities) links zero dynamic `NEEDED` libraries, closing `LD_PRELOAD`/glibc injection vectors (`AP-0`). IPC uses `/run/vgt-gedefense/core.sock` with `SO_PEERCRED`, HMAC-SHA-256 (`VGT3`), timestamp windows, and nonce replay protection. |
| **Web-Evidence Isolation Barrier** | Web/L7 findings carry `AlertOnly: true` (`ResponseScore: 0`). Host `SIGKILL`/`XDR_KILL_TREE` strictly requires independent host/kernel corroboration validated inside the Rust broker via `pidfd_open`. |
| **Management Allowlist Precedence** | XDP evaluates the operator allowlist before any blocklist. Transitioning to `enforce` fails closed if the allowlist is empty or unsynchronized. |
| **Monotone Forensic Ledger & Vault** | Incidents are stored in AES-256-GCM AEAD + Ed25519-signed chains with monotone sequences, predecessor hashes, and a detached head checkpoint. Quarantined binaries are locked via `MALWARE_DENIED_INODES` and stored encrypted (`root:gedefense 0700`, `openat2`/`O_NOFOLLOW`, max `256 MiB`). |
| **Release & Artifact Trust** | Installers embed the trusted Ed25519 public key (`ed25519:e011a96c7c6ab4f6`) and verify `release-index.signed.json`, `release-manifest.signed.json`, and SHA-256 digests offline before executing any privileged action. |

---

## 2. Production Qualification & Host Requirements

- **OS & Architecture:** Linux `x86_64` (`amd64`), `systemd`, supported package managers (`apt`, `dnf`/`yum`, `pacman`, `zypper`), `libargon2.so.1` for `gedefense-access`.
- **Kernel Capability Dependency (`lsm=...,bpf`):** Full BPF-LSM enforcement (**Titan Exec Gate** `bprm_check_security`/`mmap_file`, **Credential Guard** `file_open`, **LPE Guard** `socket_create`, **Attach-Time BPF_GUARD** `bpf_prog`, `ptrace_access_check`, and `io_uring` LSM hooks) requires `bpf` active in `/sys/kernel/security/lsm` (`lsm=...,bpf` kernel cmdline + reboot). Without active BPF-LSM, GeDefense reports `inactive` honestly rather than faking protection.
- **Target-Host Gate:** Every binary release still requires on-host verification of the concrete kernel verifier, NIC XDP mode (`native` vs. `generic`), systemd units, IPC, and TLS readiness before switching production workloads to `enforce`.

---

## 3. Verified Limitations & Boundaries (`6.3.0`)

*(Resolved items from `6.1.x` / `6.2.x` — such as capture-helper isolation, non-root `0755` drop-dir inode quarantine locks, pooled worker PPID isolation, SMP multi-CPU `sec_crit` skew, 15-char BPF object name comparison in `cross_view`, and benign root `PTRACE_MODE_NOAUDIT` procfs status reads — are no longer limitations in `6.3.0`.)*

1. **Network & Protocol Boundaries:** No cluster swarm/mesh coordination, no inline QUIC offloading, no TLS man-in-the-middle decryption, and no upstream ISP-link DDoS absorption beyond host NIC/XDP capacity.
2. **Edge Terminator (`Module E`):** Phase-1 TLS terminator handles HTTP/1.1/2 limits and raw-body WAF (`POST`/`PUT`) on opt-in; NGINX remains recommended for high-concurrency HTTP/2/QUIC termination.
3. **Host Compromise Floor:** GeDefense cannot guarantee integrity after an attacker already holds unrestricted root kernel execution (`CAP_SYS_MODULE` / physical DMA / compromised boot chain without full Measured Boot attestation; hosts without TPM2/UEFI carry `quote_kind="none"` / `key_binding="software"`).
4. **Telemetry & Anti-Spyware Current Scope (`S16`–`S17`):** Under active `6.3.0` policy, `AS-S16` (Kernel/eBPF probes) and `AS-S17` (`io_uring` async ring operations) detect reliably (`DETECTED_ONLY` at `0%` FP), while strict system-wide syscall blocking remains opt-in (`kernel.io_uring_disabled` via sysctl hardening).
5. **Opt-In / Phase-2 Features:**
   - **Feed Auto-Enforce** stays off by default (`observe`/correlation only unless operator-authorized with TUF keys).
   - **Emergency Lockdown** & **Out-of-Band Witness** remain opt-in; LUKS volume suspend, graphical session lock, and RAM zeroization remain Phase 2 (`unsupported` reported when unavailable).
   - **Parser Cells (`gedefense-cell-helper`)** ship with an empty profile list until configured; Wayland/PipeWire passthrough is deferred.
   - **Chameleon Mode (`AP-8`)** is opt-in via a signed installation manifest (`apply-chameleon-profile.sh`).
   - **AstraeaOS Gaia Cells Daemon:** Expected externally on AstraeaOS hosts (graceful `runtime_not_installed` fallback on standard Linux).
   - **WordPress Bridge Alpha Notice:** See [`../SECURITY.md`](../SECURITY.md) — preview bridge must not be exposed to untrusted multi-tenant admin surfaces without strict review.
6. **External Release Infrastructure Items:** Public-CA code signing (OS trust store), RFC 3161 timestamps, CRL/OCSP endpoints, and externally anchored network anti-rollback channels remain documented external items outside the self-contained repository release key (`RELEASE-MANIFEST.txt`).
