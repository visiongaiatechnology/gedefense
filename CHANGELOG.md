# Changelog

## 6.2.1 — 2026-11-23 — Kernel Behavioral XDR, Inode Quarantine Lock & Service-Pool Isolation

Security, kernel behavioral XDR, and service-pool isolation release on top of `6.2.0`, lifting GeDefense Linux from `86.16` to **`93.31 / 100 (PASS)`** in the VGT HardRed benchmark while cutting average endpoint damage ratio to **`8.6%`** and beating the OSS Best-of-Breed stack (**`55.40 / FAIL`**) across efficacy, FP resilience, containment latency, and memory/CPU efficiency (`88.4 MiB` vs. `1,761.0 MiB` RSS). Release note: `docs/V6.2.1-RELEASE.md` · Raw results: `benchmarks/vgt-hardred-6.2.1/`.

### Kernel behavioral XDR & malware inode lock
- **Core quarantine boundary (`FIND-G-001`, `rust/gedefense-core/src/quarantine.rs`):** Enforced explicit path allowlists (`CORE_QUARANTINE_ALLOWED_ROOTS`) and forbidden-root denylists (`CORE_QUARANTINE_FORBIDDEN_ROOTS`, covering `/proc`, `/sys`, `/run`, `/boot`, `/bin`, `/sbin`, `/lib*`, `/usr`, `/etc`, `/var/lib/vgt`, `/etc/vgt`, `/opt/vgt`, and `/dev` except `/dev/shm`) directly in `decode_path()`, plus `capture_open_fd_only()` for post-inode-lock Vault encryption without broad `CAP_DAC_OVERRIDE` privileges.
- **BPF-LSM malware inode quarantine lock (`rust/gedefense-ebpf/src/credential_guard.rs`, `rust/gedefense-core/src/{credential_guard.rs, on_write.rs}`):** Added `MALWARE_DENIED_INODES` (`4,096` entries) to enforce `-EACCES` at `file_open` for non-`gedefense-` processes even inside non-root `0755` drop directories where unlinking returns `EACCES`, while archiving the sample encrypted (`"on-write-inode-locked"`).
- **Kernel behavioral XDR & subshell `argv` capture (`rust/gedefense-*/src/xdr_kernel.rs`, `control/{coreipc_xdr_kernel.go, xdr_kernel.go, xdr_rules.go}`):** Added `EXEC_ARGV_EVENTS` (`512`-byte ring capture across `sys_enter_execve`/`execveat` + `sched_process_exec`), `KERNEL_PROBE_EVENTS` (`64`-byte capture for `sys_enter_ptrace` `XDR.PTRACE_ATTEMPT`, `socket_create` `SCTP`/`DCCP`/`RDS` `XDR.KERNEL_PROTOCOL_PROBE`, `openat`/`openat2` `XDR.CREDENTIAL_PROBE`, and sensitive `/etc` symlink attempts `XDR.SYMLINK_OVER_SENSITIVE`), `PENDING_COLD_OPEN` + `getname_flags` `kretprobe` fallback, and `KD.LINUX.DISCOVERY.ACCOUNT` / `KD.LINUX.DISCOVERY.SUID`.
- **Multi-CPU tracepoint activation (`rust/vendor/aya/src/programs/trace_point.rs`, `mod.rs`, `sys/perf_event.rs`):** Enables per-CPU perf tracepoint file descriptors across `online_cpus()` while maintaining a single BPF program entry.

### Service-pool isolation & control-plane responsiveness
- **Ransomware thresholds & pooled worker isolation (`rust/gedefense-common/src/ransom.rs`, `rust/gedefense-core/src/{process_tree.rs, ransom.rs}`, `rust/gedefense-ebpf/src/ransom.rs`):** Tightened `RANSOM_ENTROPY_DISTINCT_THRESHOLD` (`15 -> 6`) and `RANSOM_META_THRESHOLD` (`25 -> 18`), added `RANSOM_TRUST_POOL_METADATA` (`2u8`) for pooled web/DB daemons (`php-fpm*`, `lsphp*`, `httpd`, `apache2`, `nginx`, `openlitespeed`, `lshttpd`, `mariadbd`, `mysqld`, `postgres`, `redis-server`, `memcached`, `gitea`) to prevent routine cache-rename false positives while preserving high-entropy burst protection, and isolated compromised pooled workers via PPID-only `stop_process_descendants` / `collect_tree` (keeping pool masters and sibling workers online).
- **StyX beacon filter, async Chronos FIM & health cadence (`control/styx_beacon.go`, `control/xdr.go`):** Filtered loopback (`127.0.0.0/8`, `::1`), link-local/multicast, and unattributable kernel softirq flows (`pid=0` / `swapper/*` / `DstPort=0`) via `isIgnoredNonExternalFlow`; moved `ChronosScanner.Scan` onto an atomic-guarded background goroutine (`chronosRunning`); and tightened healthy `StyxFlowHealth` polling to `1s`.

### Version, benchmark archive & artifacts
- Product version bumped to **6.2.1** across `VERSION`, Control (`6.2.1`), Gateway (`6.2.1-access`), Rust workspace/`Cargo.lock`, AstraeaOS contract, Arch `PKGBUILD`, OneClick headers, READMEs, and `VGT_GeDefense_V6_6.2.1_*` / `GeDefense-6.2.1-*` release assets.
- Published sanitized VGT HardRed + REDHARD ARES results (incl. OSS Best-of-Breed comparison) in [`benchmarks/vgt-hardred-6.2.1/`](benchmarks/vgt-hardred-6.2.1/).

## 6.2.0 — 2026-11-21 — Defense Maximization & Telemetry Resilience

Major hardening release on top of `6.1.2`, driven by the VGT HardRed 6.1.2 evidence review. It closes the malware, endpoint-containment, StyX reboot-drift and flow-telemetry findings without weakening the `0.0 %` protection-FPR gate. Release note: `docs/V6.2.0-RELEASE.md`.

### Malware & artifacts
- **On-write malware sensor (M1.1):** an asynchronous fanotify `FAN_CLOSE_WRITE` watcher now covers the host drop paths `/tmp`, `/var/tmp`, `/dev/shm` and `/var/www` (configurable with repeated `--on-write-watch-root=`). It never registers a blocking `FAN_*_PERM` class, stays bounded (`sync_channel(256)`, file ≤64 MiB, signature probe ≤1 MiB), re-checks the SHA-256 under the quarantine broker lock and moves only confirmed-malicious files into the encrypted quarantine; XDR events `on-write-quarantined/-failed/-unavailable` and `on-write-scan-error` are emitted.
- **Bounded recursive archive inspection (M1.2):** ZIP (stored + deflate), GZIP (multi-member) and TAR (ustar/GNU, checksum, PAX/GNU long names) are inspected recursively with hard limits: depth 8, entry ≤16 MiB, total expanded ≤64 MiB, ≤10 000 entries, ratio 200:1; zip-slip/absolute/backslash/Windows paths are rejected fail-closed, malformed/unsupported members never silently pass. EICAR/signature hits inside members are reported as malicious.
- **Tmp visibility (M1.3):** `gedefense-core.service` runs with `PrivateTmp=false` and explicit read/write grants for exactly `/tmp`, `/var/tmp`, `/dev/shm`, `/var/www`; `/home` and `/opt` stay read-only and every quarantine operation remains fd-anchored (`openat2`/`O_NOFOLLOW`).
- **HTTP raw-body malware inspection (M1.3):** `POST`/`PUT` bodies with `application/octet-stream` or unknown content types now pass the Airlock byte/signature path (EICAR/webshell markers, score 110 → HTTP 403), not only multipart uploads; size/fast-pass bounds avoid the previous 503 timeout.

### Endpoint, ransomware containment & TITAN
- **TITAN Exec `untrusted` mode (M2.1):** global mode 4 blocks non-root-owned or world-writable untrusted exec paths; per-scope modes remain 0..3. eBPF ABI-2 adds inode-owner, dentry-parent and filename offsets; `TITAN_EXEC_REASON_UNTRUSTED_PATH`/`NON_ROOT_OWNER`/`WORLD_WRITABLE_PATH` (11–13) are parsed by the control plane. No allowlisted system binary and no system package tree is affected.
- **Process-tree/PGID kill (M2.3):** `XDR_KILL_TREE <pid> <start_ticks> <rule>`, `XDR_GROUP_STOP` and `XDR_GROUP_CONT` are implemented in the core. The bounded `/proc` snapshot (≤4096 processes, depth 64, ≤1024 signals) walks PPID descendants plus the process group, verifies every target with a before/after start-time check and `pidfd_send_signal(SIGKILL)`; PID 1–4, systemd/sshd/gedefense tasks and kernel threads are hard-protected. `XDR.RANSOM_*` rules are accepted as objective evidence.
- **eBPF ransomware sensor (M2.2):** `vfs_write`, `vfs_rename` and `vfs_unlink` kprobes feed a per-TGID tracker with integer-only entropy (distinct-byte SWAR popcount) and rename/unlink windows. Signal A (≥15 distinct high-entropy inodes/500 ms) and Signal B (≥25 rename+unlink/250 ms) emit bounded `RANSOM_ENTROPY_BURST`/`RANSOM_RENAME_STORM` events; the core resolves the real PGID and freezes the whole group immediately with reversible `SIGSTOP`, skipping trusted package/compiler comms to protect `apt`, `dpkg`, `tar`, `cargo` and builds. Control can later escalate with `KILL_TREE` or release with `GROUP_CONT`.
- **Credential-access guard (M2.4):** a `file_open` BPF-LSM program protects the inodes of `/etc/shadow`, `/etc/gshadow` and the bound secret files in `/etc/vgt/gedefense/secrets/`; only allowlisted auth/system comms (`unix_chkpwd`, `sshd`, `sudo`, `su`, `passwd`, `chpasswd`, `systemd*`, `gedefense*`) may read them, otherwise `-EACCES` + `CRED_GUARD` event. Fail-safe: an unarmed/unattached guard never blocks PAM/login paths, and the status reports `active=0` instead of a false claim.

### StyX & flow telemetry
- **Symbolic cgroup identities (M3.1/M3.2):** StyX cell modes and allow rules accept `cgroup_path` (and retain legacy numeric IDs); the control plane resolves the current cgroup2 inode from `/sys/fs/cgroup` on every sync, detects service-restart/reboot drift, atomically re-applies mode/allow rules and marks unresolved paths `degraded` instead of silently failing open. Legacy numeric IDs remain supported and are marked as such.
- **Flow-ring resilience:** `FLOW_EVENTS` grows from 4 MiB to 16 MiB; the core drains 64 records per poll (was 8) with a 16 KiB payload ceiling and the control plane raises its independent parser limit to 64/16 KiB/64 KiB response. This removes the observed `FLOW_RING_DROPS` starvation without touching the egress enforcement path.
- **Honest telemetry status:** `STYX_FLOW_HEALTH` is surfaced as emitted/dropped deltas, drop ratio, drain lag and a `telemetry_state` (`healthy/degraded/stale/unavailable/disabled`), explicitly separated from `enforcement_active`. The dashboard/overview shows “telemetry degraded” instead of an unqualified “active” when ring drops persist; degraded/recovered XDR events are emitted.

### WAF & inline edge
- SQL comment/whitespace normalization catches `1/**/oR/**/1=1--` and equivalent operator obfuscation; semicolon-chained query/form values are parsed as individual segments instead of a generic 400.
- New `L7.SQLI.SCHEMA_PROBE`, `L7.SQLI.COMMENT_OBFUSCATION`, `L7.SCANNER.RECON`/`USER_AGENT` and `L7.MALWARE.EICAR` rules; `L7.SCANNER.PROBE` (score 95) blocks secret-config probes such as `/.env`, `.git/config` and `wp-config.php.bak`.
- Large bodies (780 KB–1.5 MB) use a bounded shallow fast-pass (16 head/tail text chunks, at most 8 decode chunks) so benign large requests no longer hit the 503 timeout; deep mid-body encoded payloads beyond the bound are a documented trade-off.
- Pure rate-limit decisions now return deterministic `429` with `Retry-After` and consistent JSON; security blocks remain `403` with the socket verdict `block` (no fail-open).

### Hardening, context & packaging
- **CIS/Lynis hardening (M5.1):** the sysctl control catalog/preview/rollback covers `rp_filter`, `log_martians`, `icmp_echo_ignore_broadcasts`, `protected_hardlinks/symlinks`, `sysrq`, `perf_event_paranoid`, `tty.ldisc_autoload`, `tcp_syncookies`, `dmesg_restrict`, `kptr_restrict`, `yama.ptrace_scope` and `vm.swappiness`; `gedefense-provision` gains an opt-in, reversible CIS-L1 baseline for SSHD (`99-gedefense.conf`), `login.defs` UMASK, legal banners, module blacklist (`dccp`, `sctp`, `rds`, `tipc`, `cramfs`, `usb-storage`) and base auditd rules. Live SSHD/PAM changes are opt-in and never silently forced.
- **Kinetic→XDR attack stories (M5.2):** on `kinetic.block_applied` events (`PORT_SCAN`, `SYN_FLOOD`, `LOW_SLOW_SCAN`, `IP_RATE`) the control plane resolves the local service port from `/proc/net/tcp*`, attaches the MITRE technique and emits an `AttackStoryNode` with `has_lineage_or_chain=true`, closing the previously incomplete `NET-*` context.
- **Canary decoys:** the existing privileged canary root/broker remains the only deployment path; automatic distribution into `/home/*`, `/var/www`, `/srv` or `/tmp` is not enabled in 6.2.0. It requires a separate fd-anchored core deployer plus per-root write grants and is documented as a follow-up rather than silently widening the canary boundary.

### Audit follow-up fixes (2026-11-22)
- **On-write sensor no longer ignores non-root writers:** `classify_write()` no longer returns `None` for `owner_uid != 0`. Webserver (www-data), benchmark-user and attacker drops under `/tmp`, `/var/tmp`, `/dev/shm` and `/var/www` are now scanned and quarantined independent of the writer's UID. The non-executable signature/archive probe budget rises from 1 MiB to 16 MiB; the root boundary remains the watch root plus fd-anchored quarantine checks.
- **Persistent hardening state accepts the M5.1 vocabulary:** `HARDENING_SET` now recognizes `astraeaos-cis-l1`, a 21-bit custom mask (`astraeaos-custom-xxxxxx`) and all new CIS keys. The three shipped profiles were extended to the Go catalogue content (balanced/strict migrated from the 6.1 legacy content, which is still recognized on upgrade). `gedefense-core.service` gets exact `ReadWritePaths` grants for the new `/proc/sys` controls; `ProtectKernelTunables=true` remains.
- **Ransomware freeze is armed at core load and drained on the 100 ms tick:** `RansomCore` arms as soon as at least one kprobe attached; the control-plane drain cadence changed from 1 s to 100 ms so the core's `SIGSTOP` is not delayed by an idle IPC gap.
- **Credential guard allowlist covers local login and account tooling:** `login`, `cron`, `useradd`, `usermod`, `userdel`, `groupadd`, `groupmod`, `groupdel`, `gpasswd`, `chage`, `newgrp`, `vipw`, `pwck` and `grpck` were added; `apt`/`dpkg` maintainer scripts and local TTY/PAM logins no longer receive `EACCES` on `/etc/shadow`.

### Version and artifacts
- Product version **6.2.0** across `VERSION`, Control (`6.2.0`), Gateway (`6.2.0-access`), Rust workspace/`Cargo.lock`, AstraeaOS contract, Arch `PKGBUILD`, OneClick installer headers and README release links/badges. Artifact names are `VGT_GeDefense_V6_6.2.0_*`, `GeDefense-6.2.0-*`.

### Verification
- See `docs/V6.2.0-RELEASE.md` for the exact test ledger, WSL toolchain versions and the live-load items that remain release gates.

## 6.1.2 — 2026-11-20 — Installer Preconditions & Feed-Signing Hotfix

Targeted hotfix on top of `6.1.1`. Fixes four missing fresh-install `systemd` unit preconditions in the OneClick installer so all six service units start cleanly without requiring an intervening reboot, hardens post-upgrade status polling against non-JSON payloads, and fixes a 1-in-256 Ed25519 feed-signing key parser flake when a raw key ends in `0x0d`. Release note: `docs/V6.1.2-HOTFIX.md`.

- **OneClick installer (`scripts/oneclick-installer-header.sh`):**
  - `ensure_service_accounts()` now creates and verifies the `gedefense-desktop` system group in both `systemd-sysusers` and the `groupadd --system` fallback (required by `gedefense-control.service` `SupplementaryGroups=` and `vgt-gedefense.conf`).
  - `ensure_user_and_dirs()` now pre-creates and asserts `/run/gedefense-scan` (`0750 root:gedefense`), `/run/gedefense` (`2750 gedefense:gedefense-desktop`), and `/sys/fs/cgroup/vgt-cells` (`0775 gedefense:gedefense` when `/sys/fs/cgroup` exists) before `activate_release()` starts `gedefense-cell-helper.service`, `gedefense-core.service`, or `gedefense-control.service`.
  - `CERT_FILE` now uses the canonical `"${TLS_DIR}/access.crt"` (`/etc/vgt/gedefense/tls/access.crt`, migrating any legacy `${ACCESS_DIR}/access.crt` on upgrade and installing the served copy for `gedefense-access`), so `gedefense-access.service` `ExecStartPre` succeeds on fresh installs; `--help` now prints before the `root` check while installs remain root-only.
  - `reconcile_post_upgrade_posture()` guards non-JSON/empty responses cleanly in Python instead of printing a `JSONDecodeError` traceback during service restart.
- **Desktop packaging (`scripts/build-desktop-oneclick.sh`):** emits a portable basename entry in `GeDefense-*.run.sha256`.
- **Control (`control/feed_signing.go`, `control/feed_signing_test.go`):** `feedSigningKeyFileBytes()` checks single-`\n` terminated raw key sizes (`32`/`64` bytes + `\n`) before trimming `\r\n`, preventing valid binary Ed25519 keys ending in `0x0d` from losing their last byte.
- **Regression & release gates:** `scripts/tests/check_installer_templates.sh` verifies all four installer preconditions; version bumped to **6.1.2** across `VERSION`, Control (`6.1.2`), Gateway (`6.1.2-access`), Rust/`Cargo.lock`, AstraeaOS contract/PKGBUILD, Arch `PKGBUILD`, installers, and documentation.

## 6.1.1 — 2026-11-19 — Security & Kernel-Compatibility Hotfix

Hotfix release for the 6.1 line. It closes the confirmed findings of the 2026-11-18 and 2026-11-19 audits (including the findings that blocked the 6.1.0 deployment gate), isolates the privileged packet capture from the control plane, and adds Kernel 7.3 BTF compatibility. Deploy 6.1.1 instead of 6.1.0. Release note: `docs/V6.1.1-HOTFIX.md`.

### Security fixes
- **`VGT-AUDIT-20261118-GD61` (FIND-001…007, CHAIN-001/002):** RDS is denied on `family == AF_RDS` (tested shared predicate) instead of `protocol == 21`; `INET_DIAG` covers `AF_INET`+`AF_INET6` and the cBPF prefilter is generated from the configured ports for IPv4/IPv6; the worker guard no longer reports `active` with an unattached tracepoint, resyncs registry changes and excludes cgroups shared with the nginx master; the edge proxy strips inbound `X-Forwarded-For` and starts at boot; the LPE apply reports 503/409 on partial failure and enforces ASLR through the core sysctl path; the dashboard reads `catalogue`, surfaces LPE errors, and the V6.1 JS is mojibake-free.
- **`VGT-AUDIT-20261118-GD61-R2` (FIND-008, FIND-009):** privileged `AF_PACKET`/`CN_PROC` capture moved into the isolated `gedefense-capture-helper.service`; `gedefense-control.service` is back to zero capabilities and `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`. The helper is a separate account/unit with a `0600` `SO_PEERCRED` Unix socket, no `AF_INET`/`AF_INET6`, no config/state access and an isolated runtime directory. Also fixed the undefined `renderAdvisoryRows` path in `exposure.js`, stripped `X-Real-IP` in the edge proxy, surfaced `strict_reason` in the Worker Guard UI, and corrected the Arch `PKGBUILD` version. Evidence: `docs/V6.1.0-AUDIT-REMEDIATION.md` §5.
- **`VGT-AUDIT-2026-11-19` quick profile (FIND-001…005):** parser-cell seccomp rejects every x32 syscall (`__X32_SYSCALL_BIT`) before the deny/socket rules; TLS sensor ALPN counters are bounded (32 keys + `(other)`) and the peer set is capped at 4096; lockdown auto-network-drop merges with the phase flags under shared ownership and survives `LOCKDOWN_PHASE`/`startup_rearm` refreshes (cleared by trigger/new epoch, `CLEAR` or explicit NET-off); USB console/hub/power-only classification requires complete interface counts and interface uevents de-authorize the parent device; the gateway strips every header nominated in the client `Connection` header before setting the attested Authorization/session headers. Evidence: `docs/V6.1.0-AUDIT-REMEDIATION-20261119.md`.

### Kernel compatibility & Cockpit
- **Kernel 7.3 BTF v1 extended header:** the Titan BTF parser accepts `24 <= hdr_len <= data.len()` instead of requiring exactly 24 bytes, so the 32-byte header of Kernel 7.3 no longer rejects the vmlinux BTF. Section starts use overflow-checked `hdr_len + offset`; undersized, truncated and out-of-image headers stay fail-closed. A 32-byte fixture test and an out-of-image rejection test cover the contract.
- **Two-stage traffic-light auto-cooldown (`control/overview_situation.go`):** worker crash storms and unmitigated critical/high alerts keep the hero cockpit on RED during the active `15m` escalation window, step down to YELLOW for `15m–60m` cooldown, and automatically return to GREEN (`calm_mitigated`) after `> 60m` without new storms/alerts while keeping 24h counters. Covered by `TestBuildOverviewSituationTrafficLights`.

### Version and artifacts
- Product version **6.1.1** across `VERSION`, Go Control (`6.1.1`), Access Gateway (`6.1.1-access`), Rust workspace/`Cargo.lock` (`6.1.1`), AstraeaOS contract, Arch `PKGBUILD`, OneClick installer headers and the README release links/badges. Artifact names are `VGT_GeDefense_V6_6.1.1_*`, `GeDefense-6.1.1-*`.

### Verification
- Linux: `go test -count=1 -timeout 1800s ./...` (control) and the gateway suite pass; Rust `cargo +1.97.1 test --locked -p gedefense-common -p gedefense-core -p gedefense-cell-helper` passes (common 43, core 121, cell-helper 41 + 1 root-gated ignored); `cargo +1.97.1 build --release` and the nightly eBPF `bpfel` build pass; `scripts/security-audit.sh` PASS, `validate-systemd.sh`/`validate-i18n.mjs`/install-smoke pass. See `docs/V6.1.0-VERIFICATION.md`, `docs/V6.1.0-AUDIT-REMEDIATION.md` and `docs/V6.1.0-AUDIT-REMEDIATION-20261119.md`.

## 6.1.0 — 2026-11-18 — Web Exposure, Worker Guard, TLS Sensor, LPE Guard & Edge Terminator (Module A–E)

- **Module A — Web exposure & posture engine (`control/internal/webposture`, `control/web_exposure.go`):** discovers running web daemons through `/proc` (no `os/exec`, no shell), inspects `/proc/<pid>/exe` ELF `.rodata` read-only for the nginx/Apache version, compile flags and static-OpenSSL evidence, parses nginx/Apache configuration roots for `listen … ssl`, `http2`, `quic`/`http3` and loopback reachability, and performs one bounded passive loopback ALPN probe (`crypto/tls`, `NextProtos: ["h2","http/1.1"]`) per listener. Advisory matches are version-range checked **and** reachability-gated, so an installed-but-unreachable server is never reported as exposed. API: `GET /api/v1/web-exposure/status`, `POST /api/v1/web-exposure/scan`, `GET /api/v1/web-exposure/advisories`.
- **Module B — Worker integrity guard (`control/internal/workerguard`, `control/worker_guard.go`, kernel `worker_guard.rs`):** watches only registered web-worker comm/uid identities for fatal `SIGSEGV`/`SIGBUS`/`SIGILL`/`SIGABRT`, distinguishes a single crash (medium audit event) from a crash storm (≥ `storm_threshold` in `storm_window_seconds` → CRITICAL incident + case `XDR.WORKER_CRASH_STORM`), correlates storms with the currently open :443 peers of the TLS sensor, and classifies worker cgroups for the existing Titan exec/mmap gate with `JIT_ALLOW = 0`. Master/control units are excluded by a built-in denylist and the operator exclusion list. The eBPF tracepoint source is additive (`WORKER_GUARD_*` command family); the netlink proc-connector source keeps the feature working on cores without the 6.1.0 object, and the status names which source is live.
- **Module C — TLS/ALPN sensor & h2 control-storm budget (`control/internal/flowguard`, `control/tls_sensor.go`):** userspace `AF_PACKET` sensor with a classic BPF filter (TCP 443/8443 payload starting `0x16`, QUIC UDP/443 long header), first ≤1536 bytes fed to the existing `ParseClientHello`/`TLSSecurityEngine` (SNI, ALPN offer, JA3/JA4, cipher suites) for every TLS stack, including static-OpenSSL NGINX builds where a `libssl.so` uprobe would see nothing. TCP byte accounting reads the kernel-maintained per-socket counters (`INET_DIAG` `bytes_received`/`bytes_acked`, `segs_in`/`segs_out`) in a bounded LRU — no XDP ingress-only ratio, no port-spoof map eviction. The storm predicate is `rx_bytes > threshold ∧ rx > ratio·tx ∧ avg_pkt_len < limit ∧ segs_in ≫ segs_out`, so a multi-GB upload with 1300–1460 B packets never triggers; response is staged alert → throttle plan → ban TTL only on persistence or worker-SIGSEGV correlation.
- **Module D — LPE kill-chain blocker (`control/internal/lpeguard`, `control/lpe_guard.go`, eBPF `socket_create`):** per web-worker cgroup socket policy denies `AF_PACKET`, `AF_TIPC`, `AF_VSOCK`, `SCTP`, `DCCP` and `RDS` in the existing LSM hook (policy bits 1..6, bit 0 = the pre-existing non-UNIX deny), plus a StyX `web-ingress-only` profile (loopback, configured backend CIDRs and DNS only) and a hardening baseline for `kernel.randomize_va_space = 2` and the `sctp`/`dccp`/`rds` module blacklist. Every apply path reports the kernel capability it actually got.
- **Module E — Memory-safe edge terminator (`control/internal/edgeproxy`, `control/edge_proxy.go`):** optional Go `crypto/tls` + `net/http` ingress terminator in front of NGINX/Apache, with explicit RFC-9113 limits (`MaxConcurrentStreams`, `MaxReadFrameSize`, header/body budgets), structural inline WAF (traversal, control bytes, ambiguous framing, header/body ceilings — no signature false positives), bounded per-peer rate budget and HTTP/1.1-only upstream. Default off, loopback-only, refuses to start without a valid certificate; backend HTTP/2 remains the hardened NGINX path until the V7 edge lands.
- **Dashboard (10 new views):** Web Exposure, Worker Guard, TLS Sensor, LPE Guard, Edge Proxy and the five formerly API-only V6 panels **StyX**, **Titan Exec**, **Parser Cells**, **Emergency Lockdown** and **Witness**. Each view has live status, its own Settings tab rendered from the server-side fabric schema, and confirmation dialogs for destructive actions. Every value is editable, can be disabled again, and is validated server-side.
- **Settings v18:** five additive namespaces (`web_exposure`, `worker_guard`, `tls_sensor`, `lpe_guard`, `edge_proxy`). A v17 document upgrades unchanged with all new features off (sensor defaults safe), and the migration names every seeded namespace. Existing StyX/Titan/Parser/Lockdown/Witness namespaces are unchanged.
- **Kernel/toolchain:** `WorkerCrashEvent` wire record + `signal:signal_deliver` tracepoint in a separate eBPF module, LSM policy bit extension with backward-compatible flag validation, `WORKER_GUARD_*` core commands and a capability-classifying Go client (`coreipc_worker.go`). Go module language level raised to 1.24 for the standard-library `http.HTTP2Config`; the toolchain floor remains `go1.27.4`.
- **Honesty:** a missing tracepoint, LSM hook, `AF_PACKET` capability, certificate or core command family is reported as `inactive`/`error` with the concrete reason, never as enforced.

## 6.0.3 — 2026-11-17 — Case-Pipeline Fail-Visible Normalization & Audit Gate Hardening

- **End-to-end lowercase incident severity normalization (GD-SEV-001):** Fixed silent high/critical case suppression where `morpheus_rasp`, `styx_egress`, `styx_beacon`, and `deception` emitted uppercase `"CRITICAL"`/`"HIGH"` severities that `CaseEngine.IngestIncident` skipped with `return nil` while `State.AddIncident` reported case history healthy (`noteCaseHistorySuccess()`). Normalized severities across all producers, `emitStyxBeaconIncident`, `State.AddIncident`, `appendIncident`, and made `CaseEngine.IngestIncident` fail-visible on unknown severities (`info`/`low` stay silent no-op without error; `warning`/`high`/`critical` always ingest).
- **Dashboard severity class normalization (`control/web/xdr.js`, `l7.js`, `render.js`, `app.js`):** Normalized CSS severity class names via `.toLowerCase()` across modern XDR, L7 findings/drawers/attack-story nodes, events/incidents tables, and case rows so `.severity-badge.critical`/`.high` styling renders consistently.
- **Deterministic audit gate on clean checkouts (`scripts/security-audit.sh`):** Removed the conditional `if (root / 'Next.md').is_file()` gate dependency on gitignored `Next.md` and bound the Point-4 verification anchor directly to tracked `docs/POINT4-PHASE1-REPORT.md`.
- **UI & installer refinements:** Protection overview styling/i18n updates (`control/web/app.css`, `i18n.js`, `index.html`, `protection.js`, `v4.css`) and OneClick installer header improvements (`scripts/oneclick-installer-header.sh`).

## 6.0.1 — 2026-11-16 — GeDefense V6 Server-Safe Auto-Arm & Scanner Calibration Hotfix

- **Emergency Lockdown stays opt-in (`control/runtime_settings.go`):** Removed automatic activation of **Emergency Lockdown** (`lockdown.enabled` + `lockdown.auto_arm` with `network_lockdown=true` and `require_sources=1`) from `ApplySafeV6DefaultsOnEnforce()`. On `enforce`, GeDefense V6 continues to auto-enable **StyX** (`monitor`), **Titan Exec Gate** (`contain`), and **Ephemeral Parser Cells** (`enabled`), while both **Emergency Lockdown** and **Witness** stay explicit operator opt-in so a single host scanner/maintenance event cannot unexpectedly cut off remote SSH/HTTPS connectivity via `XDP_DROP`.
- **AIDE & Linux integrity/AV scanner canary calibration (`control/deception.go`):** Added `aide`, `aide.wrapper`, `updatedb.*`, `tripwire`, `samhain`, `rkhunter`, `chkrootkit`, `clamscan`, `clamd`, `freshclam`, and `osqueryd` to `isSystemOrScannerAccessor` so scheduled integrity checks running under dedicated unprivileged service accounts (such as Ubuntu/Debian `_aide`) are classified as `CANARY_SUSPICIOUS_SYSTEM_ACCESS` (`HIGH`) instead of `CRITICAL` / `CANARY_UNAUTHORIZED_PROBE`.
- **V6 OneClick post-activation `core_mode` validation (`scripts/oneclick-installer-header.sh`, `scripts/validate-installed-linux-host.sh`):** Updated the live status check to accept V6 capability suffixes (`+titan-exec:*`, `+lockdown:*`) alongside `native`/`generic` and `+bpf-lsm-cell`.
- **Root-mode OneClick Rust test fixes (`rust/gedefense-core/src/lockdown_hardening.rs`, `rust/gedefense-core/src/quarantine.rs`):** Fixed `untyped_values_are_never_claimed` and `copy_quarantine_aborts_when_the_source_cannot_be_removed` so `cargo test` inside `0700` `root`-owned OneClick installation workspaces succeeds reliably.
- **Relative `.sha256` sidecars (`scripts/package-artifacts.sh`):** Generated `VGT_GeDefense_V6_${VERSION}_OneClick.run.sha256` with a basename path instead of an absolute build host path.

## 6.0.0 — 2026-11-15 — GeDefense V6 Anti-Spyware & Sovereignty Architecture

GeDefense **V6 (6.0.0)** introduces the 5-point anti-spyware defense-in-depth architecture on top of the hardened V5/5.2.0 foundation (Runtime Settings **v17**). During `observe` and `canary` phases all five subsystems stay **off / fail-closed**; once GeDefense is armed (**`enforce`**), because no dedicated V6 Web UI panel ships yet, `gedefense-control` automatically activates the safe V6 baseline (**StyX** `monitor`, **Titan Exec Gate** `contain`, **Ephemeral Parser Cells** `enabled`, **Emergency Lockdown** `enabled` + `auto_arm`), while **Witness** stays **opt-in** (requires external peer endpoint/pinning) and explicit operator API overrides remain sticky:

### New Subsystems (Phase 1, Default-Off)
- **Point 1 — Titan + eBPF-LSM Exec & Shared-Library Gate (`docs/POINT1-TITAN-EXEC-GATE.md`):** kernel eBPF LSM execution/mmap path enforcement (`bprm_check_security`, `mmap_file`, `task_fix_setuid`) paired with split-BTF / ctime awareness and unprivileged Go-Control policy synchronization over VGT3. Reports honest `inactive` host layer state when `/sys/kernel/security/lsm` lacks `bpf`.
- **Point 2 — Ephemeral Parser Cells (`docs/POINT2-PARSER-CELLS.md`):** Qubes-light sandboxed parser worker lifecycle managed exclusively by the dedicated root helper unit `gedefense-cell-helper.service` over an HMAC-authenticated `VGTGC2` Unix socket (private namespaces, tmpfs/pivot_root, seccomp, cgroup-v2 bounds, TTL/burn ledger, unprivileged import/export split).
- **Point 3 — StyX Egress & C2/Beacon Detection (`docs/POINT3-EGRESS-BEACON.md`):** eBPF egress enforcement + periodic beacon/exfiltration correlation (`styx_flow`) while keeping default `mode=off` behavior byte-identical to 5.2.0.
- **Point 4 — Out-of-Band Witness Client (`docs/POINT4-WITNESS.md`):** signed checkpoint witness publishing with privacy-preserving digests, `ledger_epoch` rotation guard, SSRF/DNS-rebinding-hardened dialer (blocking loopback/link-local/cloud metadata), and honest `quote_kind=none` reporting on hosts without TPM/UEFI attestation.
- **Point 5 — Emergency Lockdown (`docs/POINT5-LOCKDOWN.md`):** XDP/TC egress drop latch, strict USB/Thunderbolt BadUSB composite-class fail-safe policy (`bDeviceClass=00` requires all interfaces to be HID and count-complete), broker freeze (`astraea-key-broker` + 15-char `/proc/*/comm` truncation match `astraea-key-bro`), and latched operator clear.

### Branding, Packaging & Audit Hardening
- Bumped product release to **GeDefense V6 (`6.0.0`, stable channel)** across Go Control (`6.0.0`), Access Gateway (`6.0.0-access`), Rust Workspace (`6.0.0`), AstraeaOS integration contract, packaging scripts, CI workflows, and dashboard branding (`LINUX DEFENSE // V6`).
- Fixed audit findings in composite BadUSB classification (`rust/gedefense-core/src/lockdown_usb.rs`), 15-byte Linux `comm` broker matching (`rust/gedefense-core/src/lockdown_brokers.rs`), Witness SSRF/DNS-rebinding validation (`control/witness_settings.go`, `control/witness_client.go`), loader environment variable filtering and strict UID resolution in `gedefense-cell-helper`, and aligned `scripts/validate-installed-linux-host.sh` `parser-inputs` ownership check (`gedefense:gedefense:730`) with the runtime helper contract.

## 5.2.0 — 2026-11-14 — Security Release

The independent deep audit **VGT-AUDIT-20261114-GD51** of 5.1.0-beta.3 reported
**36 findings in six attack chains** and blocked the 5.1.0-beta.3 release gate.
5.2.0 fixes all 36 findings. The changes are deliberately fail-closed and may
require explicit operator action during an upgrade.

### Fixed findings

- **Installer and supply chain (FIND-001 – FIND-007):** desktop and server
  OneClick installers verify the Ed25519 release signature and the payload hash
  before extraction or any state change, and the server installer runs the
  release-trust check before it touches state; state and secret paths keep their
  documented ownership/modes with atomic `0600` files instead of predictable
  temp paths; the release-toolchain gate, the SCA status derivation, the
  canonical signed GeoIP sidecar contract and the release-key rotation are
  enforced (fail closed) instead of being reported optimistically.
- **Boot attestation (FIND-008):** the AstraeaOS boot-trust probe no longer
  derives a positive claim from the JSON shape alone; it requires the detached
  Ed25519 signature over the attestation document, the live TPM2 PCR values
  against the pinned policy key and the signed fs-verity manifest.
- **Gateway and authentication (FIND-009 – FIND-012):** the privileged
  set-password helper keeps interactive sudo/polkit re-authentication and
  requires the current operator password (step-up); password verification runs
  behind a process-wide Argon2id admission gate with backpressure instead of
  unbounded concurrent KDF allocations; session rotation no longer leaks
  registry aliases; the anonymous `/gateway/version` build surface is retired
  and answered as a plain 404 while `/gateway/livez` stays the only anonymous
  health answer.
- **Policy, forensics and storage (FIND-013 – FIND-017):** an unverifiable
  signed policy is quarantined unmodified and is never re-signed by an
  automatic path - promotion is refused until an explicit operator recovery;
  blocker evaluation and reporting are no longer suppressed when Auto-Degrade
  is disabled; operational histories and runtime settings are read through
  strict AEAD/HistoryMAC (structurally valid plaintext is refused rather than
  migrated); the interrupted-rotation marker is authenticated with the node
  storage key; incremental ledger verification stays consistent under
  concurrent appends and no longer quarantines a valid chain.
- **API and L7 (FIND-018 – FIND-022):** allowlist removal decodes the request
  body once; the replay guard stays available under cache pressure without
  forgetting replays inside the window and the trust-fabric data race is
  closed; the inline admission slot bounds the inspection engine instead of the
  upstream; static-asset reads draw from a separate finite per-IP budget
  instead of a blanket exemption; an unconfigured TLS hostname policy is
  reported as disabled instead of silently inactive, and the reserved L7
  self-test path requires the process-local ephemeral token instead of the
  historical static header.
- **Feeds and Airlock (FIND-023 – FIND-024):** the persisted
  threat-intelligence state carries an authenticated envelope (Ed25519 or
  detached signed manifest anchor) and is rebuilt in memory when unverifiable;
  Airlock inspection is bound to the staging root, refuses symlinks and
  traversal, and scans beyond the former 64 KiB sample.
- **XDR, self-protection, RASP, behavior, FIM and response (FIND-025 – FIND-031):**
  a mismatch on the product's own artifacts is no longer downgraded to
  alert-only - it is `XDR.SELF_TAMPER` with a release-blocking degradation
  unless a verified signed update window covers the exact new bytes, while kill
  eligibility stays off; the RASP debugger exemption is bound to root plus the
  signed system binary; a manipulated behavior profile is never overwritten and
  Persist stays fail-closed until an operator resets the model; the hardening
  posture consumes the FIM `VERIFIED` contract; response capacity counts active
  containments only, so sequential containments no longer lock a host out; the
  mitigation guard no longer reports a revert that never happened, attributes
  only typed previous values and re-asserts an adopted mitigation; Gaia Cell
  identity is stable across listings and Titan sensor restarts use a mandatory
  backoff.
- **Desktop tray (FIND-032):** control-plane payloads are rendered as plain text
  in the Qt flyout and tray tooltip, so `<b>`, `<img>` and `<a>` cannot inject
  rich text.
- **Rust core (FIND-033 – FIND-036):** the user scan socket accepts only plain
  path components inside the browser quarantine directory and reopens the file
  beneath an anchor; the privileged control socket uses the hardened binder
  (symlink refusal, owning-group and "other" permission check) and the IPC
  timestamp window closes the replay gap; a copy-only quarantine removes the
  source as its commit point and fails the transaction when it cannot, restore
  never reproduces setuid/setgid/sticky bits, and a FIFO is refused instead of
  blocking the IPC loop; unknown canary accessors are encoded as `u32::MAX`
  instead of being attributed to UID 0.
- **eBPF data plane (FIND-036):** the producer flushes at most 255 packets per
  batch so every wire counter stays exact, emits mixed TCP/non-TCP aggregates
  with the explicit neutral marker (`protocol = 0`, `tcp_flags = 0`) instead of
  inheriting an unrelated packet label, and the LSM policy walk covers the full
  cgroup-v2 ancestry so a policy on a Gaia Cell cgroup reaches descendant leaf
  cgroups.

### Behavior changes and upgrade notes

- **Policy tamper is fail-closed and never self-healing:** an unverifiable
  policy document is quarantined unmodified, the confirmed kernel enforcement is
  retained, and nothing re-signs the document. Only an explicit operator
  recovery (investigate the document and its forensic copy, then re-establish
  the signed policy via the documented `RETURN:OBSERVE` transition) clears the
  quarantine; automatic promotion stays blocked until then.
- **Strict storage AEAD:** legacy plaintext operational histories are refused
  with an explicit error instead of being migrated. There is no automatic
  plaintext-to-ciphertext upgrade path for those documents.
- **Step-up password change:** changing the gateway operator password now
  requires the current password and an interactive sudo/polkit
  re-authentication; the former `NOPASSWD` rule for the helper is gone.
- **Authenticated rotation marker:** an unauthenticated rotation marker written
  by an older version is refused; an interrupted evidence rotation requires
  out-of-band verification/operator action before the next start completes it.
- **Self-test token:** external scripts that used the former static self-test
  header value are rejected; the reserved path is admitted only for the owning
  process with its ephemeral token.
- **`GET /gateway/version` is removed** and answers 404. Build information is
  available only through authenticated session surfaces; `/gateway/livez` stays
  a minimal `{"ok":true}`.
- **Boot trust must be provisioned:** without the pinned Ed25519 attestation/TPM
  keys and the signed fs-verity manifest, boot trust reports
  `NOT_AVAILABLE`/`WARNING` - never a positive verdict. Install the AstraeaOS
  attestation producer and its pinned trust anchors before evaluating boot
  trust.
- **GeoIP is verified at load:** the dataset must match the canonical
  `vgt.gedefense.geoip-integrity.v1` sidecar and, in signed deployments, its
  Ed25519 signature. A missing or mismatching sidecar makes the resolver
  unavailable (fail-closed); re-generate and re-sign the dataset with
  `scripts/update-geoip-db.py` instead of copying a CSV.
- **eBPF object and Rust core share one wire contract** (batch ≤ 255, explicit
  neutral marker); they must be upgraded together from the same release.
- **systemd:** the shipped units keep `ProtectSystem=strict`, `ReadOnlyPaths`
  and only the documented `ReadWritePaths` (e.g. `/run/gedefense`,
  `/run/vgt-gedefense-l7`, `/sys/fs/cgroup/vgt-cells`,
  `/etc/vgt/gedefense-access`). An in-place upgrade requires the matching unit
  files and `systemctl daemon-reload`.
- **Carry-over fix — gateway password migration under the sandbox:** the
  `gedefense-access` unit no longer pins `/etc/vgt/gedefense-access` read-only.
  That directory is a documented `ReadWritePaths` entry, so a legacy PBKDF2
  record is atomically replaced with Argon2id after the first successful login.
  `ProtectSystem=strict` and the read-only release tree are unchanged; no other
  sandbox directive is relaxed.
- **Release toolchain host:** the release validation expects Node.js 22.16.0 and
  Go 1.27.3; an older host toolchain is refused by the gate.

### Verification

- Regression tests for the findings were added for every group: Go control,
  Go gateway, Rust core/eBPF, the Qt tray offscreen render harness, and the
  Python/shell release tests. The release runner `scripts/tests/run_release_tests.sh`
  covers the offline signing rehearsal, anti-rollback/floor checks, the
  installer FIND-003 gate and the shell regression tests; its SKIP contract
  reports missing git metadata or prebuilt binaries explicitly and never as
  PASS.
- Executable test evidence, counts and per-finding acceptance results are
  maintained by the release lead in the audit deliverable/security report; this
  changelog does not restate unverified figures.
- Live TPM2/TPM hardware, fs-verity, the target-kernel eBPF verifier and the
  offline SCA scanners are **NOT_TESTED/BLOCKED in this environment**. They
  remain mandatory target-host qualification items and are not claimed as
  passed here.

### Known residual risks

- A quarantine of a file that lives on a path the service can read but not
  modify (`ProtectSystem=strict`, `ReadOnlyPaths`, read-only mounts) cannot
  remove the source. The transaction aborts fail-closed with an explicit error
  and the control plane must not record success while the object stays in
  place; such files need an operator with write access.
- The bounded replay guard keeps a full cache available, but an attacker who
  spends more than `maxEntries + maxRetained` distinct identifiers inside one
  replay window can push the oldest fingerprint out of the retained table. The
  residual is bounded by the window and the per-scope quota.
- The 70 VGT-100 controls that were already `NOT_TESTED` in the previous
  checkpoint remain open; see `SECURITY.md` and `PRODUCTION-BETA-GATE.md`.

## 5.1.0-beta.3 - 2026-10-29 - Feed self-healing, CVE-2026-98432 response and mitigation hardening

- Threat-intelligence feed signing self-heals the documented bootstrap case: with `feeds.local_signing=true`, an operator key and no pinned public key, the local key is pinned via a rotation-safe self-heal marker; a changed key with an old marker fails closed and requires an explicit pin.
- CVE-2026-98432 (`ipv4: free inet_opt and ireq_opt after an RCU grace period`) added to the kernel advisory catalogue with Debian fixed builds, the Ubuntu HWE "known unfixed through 7.0.0-42" bound, MPTCP/TCP listener probes and a managed MPTCP mitigation.
- Mitigation guard no longer treats a permission-limited runtime probe (`EACCES` on a root-owned socket) as a host regression; unobservable probes are logged and do not auto-revert a valid mitigation.
- Mitigation guard now adopts a second reachable, catalogue-managed control (MPTCP) and re-asserts it on every watch cycle; the privileged core exposes a typed MPTCP sysctl allowlist.
- Permission-limited health probes are surfaced as `UNOBSERVED` warnings in the mitigation status/event stream instead of being silently skipped.
- Version, control/gateway/core binaries, Rust crate metadata, installer headers, packaging and integration contracts aligned to 5.1.0-beta.3.

## 5.1.0-beta.2 - 2026-10-27 - Security hardening for CMS bridge and L7

- Trusted editor exception narrowed to exact VGT preview/save surfaces; only the XSS finding family is suppressed, while SQLi/LFI/PHP-tag and all other pattern families remain active.
- Master leases no longer bypass sensitive-route rate limits; the configured relaxed CMS client budget is applied.
- Revocation is persisted across control restarts; loopback master leases, oversized events/leases/profiles and fail-open bridge settings are rejected.
- WordPress bridge now requires an unlocked ThroneGuard master session, strong distinct wp-config salts, emits logout revocation and rejects loopback master events.
- Installer: access directories created before secrets/TLS, python3 before trust verification, strict prebuilt/source-signed trust modes, corrected rollback ownership.
- ALPHA bridge remains non-production; read SECURITY.md and CHANGELOG.md.


## 5.1.0-beta.1 - 2026-10-27 - CMS Defense & encrypted WordPress bridge (Alpha)

### Added

- CMS detection for WordPress, Joomla!, TYPO3 and Laravel with a dedicated **CMS Defense** dashboard view.
- Per-operator CMS relaxation policy for static assets and CMS administration paths.
- Encrypted WordPress bridge (alpha): Linux key generation, WordPress AES-256-GCM secret-at-rest, authenticated records through the existing PHP log, two-hour IP/host-bound leases, API status and revoke.
- Trusted ThroneGuard editor handling: verified master write surfaces skip only the L7 content-pattern detector for legitimate builder previews/page saves; protocol, encoding, upload, SSRF and response checks remain active.
- Regression tests for PHP-log parsing, encrypted lease/tamper handling, CMS detection, rate-limiter exemptions and trusted-editor behavior.

### Changed

- WordPress admin assets/loaders no longer consume the dynamic L7 client bucket.
- Full-stack installer: bounded Python replacement for large release blobs (ARG_MAX), correct gateway password/session-key ownership, and release context in the embedded installer.
- Linux product version 5.1.0-beta.1; gateway, feeds User-Agent, packaging, tray metadata and installer version aligned.
- README ecosystem links to GeDefense WP: https://github.com/visiongaiatechnology/gedefensewp

### Security

- **ALPHA TEST:** the GeDefense WP ↔ Linux bridge is not production-ready. The shared secret means a fully compromised WordPress can forge bridge records. Mitigations are a two-hour TTL, IP/host binding, bounded lease acceptance, read-only log consumption and a content-pattern skip only on verified admin write surfaces. WAF and kernel enforcement are not disabled. Do not deploy this bridge in unsupervised production.

### Validation

- Full Go control suite with testdata: PASS.
- Focused CMS/bridge/L7 tests: PASS.
- Encrypted lease end-to-end test and live server acceptance: PASS; test records removed.


All notable public changes to GeDefense Linux. The project is a beta; entries
describe verified source changes, not a production certification.

## 5.0.0-beta.2-hotfix6 - 2026-10-27 - Inner installer release context

- Fixed the source OneClick installer handoff to its embedded full-stack
  installer. The inner header was generated with unresolved
  `__RELEASE_PUBKEY_HEX__`, `__RELEASE_INDEX_B64__`, `__RELEASE_VERIFIER_B64__`
  and `__RELEASE_TRUST_MODE__` placeholders, so a real install stopped after the
  bootstrap gates with "Installer wurde ohne signierten Release-Kontext
  gebaut".
- The bootstrap now substitutes the already-rendered release context into the
  inner header and fails closed if any release or payload placeholder remains.
- Includes all hotfix2–5 content: Entenprise mascot and READMEs, installer
  checksum/test-isolation corrections, L7 POST gate fix and WordPress admin
  client-rate-limit correction. README installer links target this tag.

## 5.0.0-beta.2-hotfix5 - 2026-10-27 - WordPress admin rate-limit and clean release

- Fixed aggressive `L7.RATE_LIMIT.CLIENT` blocks on normal WordPress admin
  traffic. Static assets under `/storage/`, `/wp-content/` and `/wp-includes/`,
  common static extensions and the WordPress admin loader endpoints
  (`load-styles.php`, `load-scripts.php`) no longer consume the dynamic client
  token bucket. State-changing POST/PUT/PATCH/DELETE and dynamic reads remain
  rate-limited.
- Added regression coverage proving a burst of media/asset reads cannot exhaust
  the bucket, while the next dynamic POST is allowed and the following one is
  still rate-limited.
- This fixes media-heavy page editing where the editor's asset burst exhausted
  the client bucket before preview/save requests, producing 403 responses and
  `request rejected` on `/wp-admin/post.php`.
- Includes all previous hotfix2–4 content: Entenprise mascot and READMEs,
  installer checksum correction and test isolation. README installer links now
  target this clean release tag.

## 5.0.0-beta.2-hotfix4 - 2026-10-27 - Installer test isolation on installed hosts

- Isolated the default dashboard credential path from the Go test suite. Tests
  constructing `defaultConfig()` previously inherited the live host token path;
  on a host with an existing installation the authenticated API tests then read
  the production token and failed with 401, which made the OneClick installer
  fail closed before upgrading.
- The test binary now uses an absolute, non-existent `/tmp` token path by
  default, while production still uses `/var/lib/vgt/gedefense/dashboard.token`
  and explicit token-rotation tests keep their own temp file. This is a
  test-isolation correction, not a production authorization change.
- Verified the full control suite on the target reference host without
  filesystem masking: PASS (117.965 s).
- Updated README installer links to this release tag. No product, L7, gateway,
  UI or documentation content changed relative to hotfix3.

## 5.0.0-beta.2-hotfix3 - 2026-10-27 - Clean release build correction

- Corrected the pinned Go 1.27.3 linux-amd64 checksum in the source
  self-contained OneClick installer. The previous value did not match the
  official immutable archive (official SHA-256:
  `65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`), so a
  clean install failed closed after downloading the toolchain.
- Updated every README installer link to this corrected release tag. No
  application, L7, gateway, UI or documentation content changed relative to
  hotfix2.

## 5.0.0-beta.2-hotfix2 - 2026-10-27 - Entenprise release, L7 gate fix, clean docs

- Fixed a false-positive `L7.HTTP.DUPLICATE_CONTENT_LENGTH` block on every
  normal POST body handled by the inline L7 edge. Go's server-side parser
  retains an incoming `Content-Length` in `Request.Header`; the edge forwarded
  that header and appended a second framing header, so the request-smuggling
  detector correctly rejected the resulting duplicate — but the duplicate was
  generated by GeDefense itself.
- The edge now synthesizes a `Content-Length` header only when the request does
  not already expose one, preserving request-smuggling detection while allowing
  ordinary POST requests (including WordPress login forms) to reach the
  upstream.
- Added regression coverage proving a normal body request passes the edge in
  block mode and reaches the upstream without being counted as a security
  block.
- Added the official **Sir Du / Entenprise** mascot to the gateway login page as
  an embedded, self-hosted asset with a descriptive alternative text, an
  Entenprise signature caption, responsive composition and zero external
  runtime assets.
- Unified the public product line to **Linux Security Fabric - Your Entenprise
  System** in all four READMEs.
- Removed the obsolete 5.0.0-beta.2 critical security advisory and the historical
  4.x caution block from all four READMEs; the current beta guidance remains.
- Restored the same "Real Security, Many Feathers" image under the language
  selector in every README, preserving the English source image URL.
- Updated installer references to the clean `v5.0.0-beta.2-hotfix2` release.

## 5.0.0-beta.2-hotfix1 - 2026-10-25 - Version labels and UI branding

- Corrected the README version/status badges from `5.0.0-beta.1` to
  `5.0.0-beta.2` in English, German, Russian and Simplified Chinese.
- Corrected the control-plane dashboard sidebar label from `LINUX DEFENSE // V4`
  to `LINUX DEFENSE // V5` in the shell and in all four UI catalogues.
- Rebuilt the signed OneClick installer from this corrective tag. No runtime
  protection logic changed relative to 5.0.0-beta.2.

## 5.0.0-beta.2 - 2026-10-25 - Hotfixes 1–9 consolidated

### Added

- **Real deception canaries:** the privileged Rust core deploys root-owned
  decoy files inside a dedicated jail (fd-relative path validation, atomic
  O_EXCL/rename, identity verification, manifest recovery), watches them with a
  bounded fanotify permission-class sensor and exposes bounded events over the
  authenticated IPC channel. The control plane turns unauthorized access into an
  incident and a reversible, TTL-bound response automatically. The core ignores
  its own deployment and identity-verification opens.
- **Signed threat-feed pipeline:** `feeds.local_signing`, `signing_key_file` and
  `snapshot_dir` plus `--init-feed-signing`; exact-byte snapshots, detached
  Ed25519 manifest, pinned public key, TTL and anti-rollback checks, `file://`
  snapshot fetch and verified kernel application. Feed-generated blocks are
  republished after release reconciliation and control-plane restarts.
- **L7 inline producer support:** real Unix-socket producer traffic is
  first-class; aggregated request/finding/blocked counters, producer and traffic
  path attachment/verification flags, explicit header limits, hop-by-hop header
  stripping and end-to-end tests for benign traffic and SQLi/XSS/LFI/command
  injection.
- **Truthful protection status:** `protection.effective`, `level`, `domains`
  and `gaps` are derived from kernel, XDR, core, Kinetic, L7 and evidence
  enforcement. The dashboard only claims full protection when every layer
  enforces.
- **Release/integrity maintenance:** FIM release rebaseline limited to the
  release root and the deployed unit/configuration allowlist; Titan finding
  acceptance for rebaselined paths; startup self-check status API
  (`GET /api/v1/startup`); local cgroup-v2 Gaia-Cells registry; operator-signed
  local boot-trust baseline; `scripts/post-update-rebaseline.sh`.
- **Ubuntu boot evidence:** the versioned `/boot/vmlinuz-<release>` image is
  read for the local boot-trust baseline.

### Fixed

- XDR could silently fall back to `observe` because the engine cached its
  startup mode and its status refresh overwrote the release-owned mode. The
  release mode is now the single owner (`F-HOTFIX-5`).
- Canary deployment previously ran with the unprivileged control identity and
  could not write host paths; canaries are now deployed by the privileged core.
- Canary staging files could remain in the canary root after an existing
  identical decoy was re-deployed; staging is removed on every outcome.
- Fanotify canary events generated by the core's own decoy deployment could
  freeze the core; self-PID events are ignored.
- Feed-generated kernel blocks disappeared on every release reconciliation or
  restart; a reconcile hook and startup republication now restore them.
- The L7 enforcement scope was limited to one legacy PHP rule; the unchanged
  legacy singleton is migrated to the full non-alert-only built-in rule set.
- The dashboard inferred "full protection" from the release phase alone; the
  backend now publishes the effective per-domain state.
- FIM reported `TAMPERED` after an authorized release update because unit files
  and configuration were outside the rebaseline scope; the release scope now
  includes the shipped systemd units.
- Boot-trust evidence was unavailable on Ubuntu because only
  `/boot/vmlinuz-linux*` was considered; the versioned image is now read.
- Package-integrity and Gaia-Cells modules now report honest
  unsupported/fallback states on hosts without pacman or the AstraeaOS runtime
  instead of a misleading red or disabled state.

### Changed

- Protection status, startup self-check and L7 attachment semantics are exposed
  as bounded JSON fields for the dashboard and API consumers.
- Local Gaia-Cells fallback uses `/sys/fs/cgroup/vgt-cells`; the control unit
  creates and delegates that subtree.
- Version `5.0.0-beta.2` is the central version for control, gateway, Rust
  workspace, packaging, AstraeaOS contract, desktop tray, READMEs and the
  one-click installer.
- Public release signing for this release uses a freshly generated Ed25519 key;
  the public key and fingerprint are published in `RELEASE-KEYS.md`.

### Validation

- Go control suite: `go test ./...` PASS.
- Rust core/workspace: `cargo test -p gedefense-core` PASS (40 tests).
- UI catalog parity: German, English, Russian and Simplified Chinese (zh-CN)
  define the same keys and interpolation placeholders; desktop tray `.ts`
  catalogs complete.
- Installer: signed payload and index, self-test and payload verification PASS.

### Known limitations

- Public-CA, RFC3161 timestamp, CRL/OCSP, externally anchored anti-rollback and
  a public CA for feed authenticity remain outside this beta. Feed authenticity
  is operator-provisioned with a local Ed25519 key.
- The beta is for test and qualification hosts; kernel/NIC/XDP qualification is
  host-specific.

## 5.0.0-beta.1 - 2026-10-23 - Titan Ingress Defense & V5 Beta

- Titan trust engine (AUTHORIZED/TOLERATED/UNEXPECTED/COMPROMISED) with
  OBSERVE/CONTAIN/STRICT policy, bounded inotify sensor, FIM/package ownership
  evidence and reversible quarantine-only containment.
- Native L7 application-security plane, encrypted evidence ledger, reversible
  hardening and the Security Fabric control plane.
- Signed release/index and installer verification, archive leak gates, feed
  signing support, mandatory L7 peer credentials and fail-closed policy startup.
- Public beta only; external release trust anchors remain outstanding.

## 4.0.1 - Universal Linux Release

- Distribution-aware installer and service integration for Debian/Ubuntu,
  Fedora/RHEL, Arch and openSUSE; native L7 plane and encrypted evidence state.

## 4.0.0-beta.1

- V4 security fabric: Rust eBPF/XDP data plane, Go control plane, XDR,
  encrypted evidence and reversible hardening.
