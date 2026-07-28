# VGT GeDefense 1.0 Full-Stack Beta Test Plan

## Installer and recovery

- build Rust core and eBPF on the target host;
- reject a damaged embedded payload;
- force an eBPF verifier or service failure and confirm automatic rollback;
- reboot and confirm the three services recover;
- confirm an activation failure prints control/core status and journal evidence
  before automatic release rollback;
- confirm installer prompts and logs contain no detected public or management
  IP address unless the operator explicitly enters it;
- validate native-XDP and generic-XDP hosts.

## Observe

- normal web, SSH, update, backup and monitoring traffic;
- IPv4/IPv6 and VLAN/QinQ parsing;
- feed synchronization without automatic XDP application;
- process/network correlation, integrity watcher and behavior persistence;
- Rust-core restart with management-allowlist resynchronization;
- startup refusal of Ready while the authoritative blocklist state is unverified;
- enable/disable every built-in signal module and confirm only its evidence path changes;
- create, disable, re-enable and remove bounded custom RE2 rules;
- confirm custom-rule score is recorded while `response_score` and active response remain unaffected;
- confirm no traffic drops with an empty blocklist.
- quarantine multiple bounded files, verify encrypted-vault tamper rejection,
  restore exact ownership/mode/content, and reject protected paths;
- correlate recurring incidents into one encrypted case and require durable
  Evidence Ledger commit for every case status change;
- apply and reverse both persistent hardening profiles; reboot and verify the
  runtime values match `/etc/sysctl.d/90-vgt-gedefense.conf`;
- run the authenticated Gaia Cells mock runtime and verify UUID/generation/
  cgroup-ID mismatch and replay/MAC failures are rejected.

## GaiaOS

- build `gedefense` and `gaiaos-gedefense-integration` from the byte-verified
  `GaiaOS/gedefense` mirror;
- verify the ISO package list contains no `gaiasentinel` runtime package;
- verify provision → bpffs → core → control → access ordering;
- set the operator password through the first-launch flow and open the local
  TLS application with the generated certificate SPKI pin;
- confirm absent Gaia Cells reports `runtime_not_installed` without degrading
  generic host protection;
- confirm a conforming `VGTGC1` runtime exposes cells and freeze/reverse is
  evidence-gated and identity-bound.

## Canary

- controlled temporary-file, deleted-executable and memfd samples in a disposable lab process;
- PID reuse and start-time mismatch rejection;
- `SIGSTOP` only when the configured correlation score and evidence gates pass;
- Emergency Stop and core-failure Auto-Degrade;
- simulate `CLEAR_BLOCKLIST`, `VERIFY_EMPTY` and signed Observe persistence failures and confirm the state remains Unverified.

## Enforce

Only on a noncritical host with console access:

- management allowlist synchronized before promotion;
- controlled source CIDR block and TTL expiry;
- allowlist-before-blocklist collision;
- signed-policy persistence failure and rollback;
- objective kill-evidence test using a disposable process;
- Emergency Stop while rules are active, including an orphaned ledger entry absent from the Go snapshot.

Public beta promotion requires no unresolved critical or high findings from this matrix.
