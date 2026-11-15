# GeDefense V6 (6.0.0) — Umsetzung der 5-Punkte-Sicherheits-Blueprint (Abschlussbericht)

**Stand:** 2026-11-15 · Release: GeDefense V6 (`6.0.0`)
**Aktivierungsprofil V6:** Im Auslieferungszustand der Go-Control-Plane werden bei aktiviertem Release-Gate (`enforce`) die sicheren V6-Modi (`styx=monitor`, `titan_exec=contain`, `parser_cells=enabled`, `lockdown=auto_arm`) automatisch aktiviert, während `witness` bewusst Opt-in bleibt (s. `CHANGELOG.md` / `README.md`).

## 1. Ergebnisübersicht

| Punkt | Status | Spec | Phase-1-Report | Review |
|---|---|---|---|---|
| 1 Titan + eBPF-LSM Exec/Library-Gate | IMPLEMENTIERT (Phase 1) | `docs/POINT1-TITAN-EXEC-GATE.md` | `docs/POINT1-PHASE1-REPORT.md` | adversarial PASS nach Fixes |
| 2 Ephemere Parser-Zellen (Qubes-light) | IMPLEMENTIERT (Phase 1) | `docs/POINT2-PARSER-CELLS.md` | `docs/POINT2-PHASE1-REPORT.md` | adversarial PASS nach Fixes |
| 3 Styx Egress-Enforcement + Beacon/Exfil | IMPLEMENTIERT (Phase 1) | `docs/POINT3-EGRESS-BEACON.md` | `docs/POINT3-PHASE1-REPORT.md` | adversarial PASS nach Fixes |
| 4 Out-of-Band Witness-Attestation | IMPLEMENTIERT (Phase 1) | `docs/POINT4-WITNESS.md` | `docs/POINT4-PHASE1-REPORT.md` | adversarial PASS/GO, 1 dokumentierte Einschränkung |
| 5 Anti-Physical-Extraction / Emergency Lockdown | IMPLEMENTIERT (Phase 1) | `docs/POINT5-LOCKDOWN.md` | `docs/POINT5-PHASE1-REPORT.md` | adversarial PASS nach Fixes |

Reihenfolge der Umsetzung wie vorgegeben: **Punkt 3 → 1 → 2 → 5 → 4**. Alle Punkte folgen den Leitplanken: Go-Control unprivilegiert, Kernel-/eBPF-/sysfs-/TPM-nahe Eingriffe nur im privilegierten Rust-Core (bzw. beim Parser-Zellen-Spawner im neuen root-Helper `gedefense-cell-helper`), Fail-Closed-Status statt Attrappen, reversible Forensik über TransactionEngine/EvidenceLedger, Default **off** nach Upgrade.

## 2. Was je Punkt geliefert wurde (Kurzfassung)

**P3 — Styx:** per-Cgroup Default-Deny im `cgroup_skb/egress` (LPM-Allow/Block, Pflicht-Veto, DNS-Pinning, IPv4-mapped-Bypass-Schutz, Flow-Aggregation/RingBuf), Rust-Core-Policy-Sync (11 `STYX_*`-Kommandos, Epoch/Resync, Health), Go-Beacon-Detektor (Periodizität/Welford-CV, Exfil-Volumen ehrlich ohne rx-Telemetrie, Canary-Korrelation), XDR-/CellGuard-Anbindung, Default-off. Ehrlichkeits-Refinement: ohne rx-Telemetrie keine „Asymmetrie"-Behauptung.

**P1 — Titan Exec-Gate:** eBPF-LSM-Hooks `bprm_check_security` + `mmap_file` mit Runtime-BTF-Offsets (Mini-BTF-Parser, ctime-Split-Layout moderner Kernel, `TITAN_EXEC_*`-Maps), Modi OFF/OBSERVE/CONTAIN/STRICT, JIT-Scope, W^X/unlinked/tmpfs-Regeln; Core-Aktivierungscheck (`bpf` in `/sys/kernel/security/lsm`), sonst ehrlich `inactive`; Go-Policy-Compiler/Syncer/Events/API. **Nebenbefund korrigiert:** der bisherige P3-Socket-LSM-Claim war ohne aktives bpf-LSM wirkungslos und wird jetzt ehrlich nicht mehr behauptet.

**P2 — Parser-Zellen:** neuer root-Helper `rust/gedefense-cell-helper` (eigenes Binary/Unit, nicht Core/Control umgebaut): echte Sandbox mit user/mount/pid/net/ipc/uts-Namespace-Isolation, tmpfs-Wurzel, read-only Input, Export nur per FD, Seccomp-Deny-Liste (AF_UNIX-only, ptrace/bpf/io_uring/…), X11-verweigert, TTL/Burn/Orphan-Sweep/Burn-Ledger, sealed-memfd-Export; Go-Settings v15/Manager/Admission/Evidence-first-Burn/API/Kernel-Layer; Packaging/Profile-Default leer. Root-gated Sandbox-Test real ausgeführt.

**P5 — Emergency Lockdown:** `LOCKDOWN_STATE`-Global-Drop in XDP/TC/egress (Loopback-Recoverability konfigurierbar), Core-ABI (`ARM/TRIGGER/CLEAR/STATUS/EVENTS/HEALTH/PHASE`), State-Persistenz/Re-Arm, USB/Thunderbolt-sysfs-Policy + Netlink-UEVENT (Power-only/HID-Console-Heuristik), Hardening-Observe/Opt-Write, Broker-SIGSTOP/SIGCONT; Go-Engine (Trigger Morpheus/Canary/Boot-Trust/Operator, Latch, Evidence-first, Zell-Freeze, API); LUKS/Session-Lock/Kernel-Lockdown-Toggle ehrlich `unsupported`.

**P4 — Witness:** persistentes `ledger_epoch` (Rotation zählt hoch, kein Rollback-Fehlalarm), signierter Checkpoint (Privacy: nur Hashes/Fingerprints/Enums), gehärteter HTTPS-Client (Port 443, Proxy aus, Redirects aus, SPKI-/Ed25519-Pinning, optional mTLS), Challenge/Nonce, signierte Receipts mit strenger Monotonie/CID-Bindung, AEAD-Outbox bounded/fail-closed, Modus B Export/Import (`vgtw1`, offline verifizierbar), Equivocation/Rollback-Erkennung + optionaler P5-Lockdown-Trigger, Settings v17 Default off. `quote_kind="none"`/`key_binding="software"` ehrlich (Zielhost ohne TPM/UEFI; keine Hardware-Claims).

## 3. Gesamt-Gate-Evidenz (letzte Lead-Läufe)

- Rust: **191 passed / 0 failed / 1 root-gated ignored** (common 38+2, core 111, helper 40+1); root-gated Sandbox-Test **1 passed**; eBPF-Nightly-Build Exit 0, `dist/gedefense-ebpf` 112.176 B mit `lsm/socket_create|bprm_check_security|mmap_file`, `cgroup_skb/egress`, xdp/classifier, P3/P5-Maps.
- Go: voller Lauf **Exit 0**, `-v` **1519 PASS / 0 FAIL / 2 vorbestehende SKIP**, Race-Subsets (Styx/Titan/Lockdown/Witness/Zellen) Exit 0 ohne Data Races, `go vet` Exit 0.
- Gates: `security-audit.sh` **SECURITY AUDIT PASS (30 PASS)**, `install-smoke.sh` **71 passed/0 failed** (6 dokumentierte NOT_TESTED), `validate-systemd.sh` Exit 0, `node --check` 19 Dateien Exit 0, Helper-`--check` non-root fail-safe.
- Adversariale Reviews je Punkt durchgeführt; alle gefundenen echten Befunde behoben und fokussiert nachgeprüft (u. a. CAP_CHOWN-Unit-Lücke, cgroup.kill-Root-Probe, Export-Import-UMask, Adopt-Reassert, ctime-Split-BTF, hostile-comm-Batch-Suppression, USB-sysfs-Symlink-Grant, Hardening-Phase-Sichtbarkeit, Signal-2-Ehrlichkeit).

## 4. Ehrliche Grenzen / Restrisiken (dokumentiert in den Reports)

- **Deployment/Activation:** Nichts deployt. P1/P2-LSM-Wirkung setzt `lsm=...,bpf` + Reboot voraus; aktueller Host hat kein bpf-LSM. P2-Helper ist nicht installiert; P4-Witness-Server existiert nur als Vertrag/Client (kein Fake-Server im Repo); echtes TPM/Nonce-Quote und mTLS sind NOT_TESTED (Zielhost ohne TPM/UEFI).
- **P5:** LUKS/DM-Suspend und Session-Lock sind Phase 2 (kein D-Bus/`/dev/mapper`); Broker werden eingefroren, nicht gelockt/zeroized; USB/TB-sysfs-Write real NOT_TESTED (Unit-Grant auf `/sys/devices` nötig/dokumentiert).
- **P4:** enges Rotation-Crashfenster quarantäniert das Ledger fail-closed (Operator-Recovery dokumentiert, kein Auto-Claim); Import-CID ist prozesslokal; Single-Witness = Single Point of Trust (Cross-Epoch-/Quorum-Erkennung Phase 2).
- **P2:** Wayland/PipeWire Phase 2; Classic-BPF kann `connect`/`bind`-Adressen nicht filtern (kompensiert durch AF_UNIX-only + leeres netns); echte systemd-Unit-/USB-Live-Tests NOT_TESTED.
- **P3/P1:** kein Live-Verifier-/Attach-Test in dieser Umgebung; Core-Restart-/Map-Verlust-Fenster dokumentiert; ctime-Mitigation nur bei `REQUIRE_CTIME`.
- **Server:** unverändert V5/5.2.0-Basis; Argon2id-Migration des Gateway-Passworts ist armiert und greift beim nächsten erfolgreichen Dashboard-Login.

## 5. Nächste Schritte (nicht Teil der Blueprint-Umsetzung)

1. Deploy-Plan/Change-Fenster für diesen Stand (Build + Hashes + Migration Settings v12→v17 + neue Units `gedefense-cell-helper`/erneuerte Core-Unit; Reboot-Fenster für `lsm=...,bpf` separat entscheiden).
2. Betriebliche Aktivierung stufenweise: P3 monitor→enforce, P1 observe→contain/strict, P2 Parser-Profile definieren, P5 Lockdown arm/clear üben, P4 Witness-Endpoint/Keys bereitstellen.
3. Offene Vorarbeiten: echter Witness-Server/Quorum, TPM-Quote-Provider, LUKS/Session-Lock-Helper, P2-Wayland-Bind-Whitelist, Live-Hardware-/Verifier-Tests.
