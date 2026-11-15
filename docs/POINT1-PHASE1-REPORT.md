# POINT 1 — Titan + eBPF-LSM Exec-/Library-Gate · Phase-1-Implementierungsbericht

**Status:** IMPLEMENTIERT (Phase 1) und Gate-verifiziert · 2026-11-15 · GeDefense V6 (`6.0.0`) · **T7-Review PARTIAL, zwei Befunde behoben (ctime-Split-BTF, comm-Härtung), eine Präzisierung (Inert-Policy)**
**Verbindliche Spec:** `docs/POINT1-TITAN-EXEC-GATE.md` (dort §13: Umsetzungsabweichungen/Präzisierungen)
**Planung:** Phase-1-Umsetzung und Gate-Abnahme (Kernel-Cmdline `lsm=...,bpf` optional je Zielsystem).

## 1. Scope

Phase 1 präventiver Exec-/Bibliotheks-Schutz: Der Kernel blockiert auf Basis einer von
Titan kompilierten Inode-Policy bei `execve` (`bprm_check_security`) und beim
`PROT_EXEC`-Datei-Mapping (`mmap_file`) — vor bzw. statt der nachgelagerten
Fanotify-/inotify-Quarantäne. Zusätzlich wird der bestehende Gaia-Cells-Socket-LSM-
Status ehrlich korrigiert (P3-Fix). Default nach Upgrade unverändert:
`titan_exec.enabled=false, mode=off`; ohne aktive `bpf`-LSM-Liste wird **nichts
attached** und **keine Enforcement-Wirkung** behauptet.

Gelieferte Tasks: P1-T1 (Rust-Common-Wire), P1-T2 (Go-Settings/Plan/Syncer), P1-T3
(Rust-Core inkl. P3-Fix), P1-T4 (eBPF-Hooks/Maps), P1-T5 (Go-Events/XDR/API), P1-T6
(Gates/Anker/Doku, dieser Bericht). **P1-T7 (read-only Review, 2026-11-15): PARTIAL,
kein offener FAIL** — behoben: (a) ctime-BTF-Split/NSEC-Width (§13.13), (b)
comm-Härtung (§13.14), (c) Inert-Policy-Grenze präzisiert (§13.15). Kein Code/Test
durch diese Doku-Runde geändert.

## 2. Architektur/ABI (implementiert)

- **ABI-1 Wire** (`rust/gedefense-common/src/titan_exec.rs`): `TitanExecEvent`
  `repr(C)`, native-endian, exakt **88 Byte**; rejecting `decode_titan_exec_event`
  (Länge, Hook/Action/Reason, `pid>0`, `ts_ns>0`, MMAP-Prot, DENY-Grund, NUL-Padding,
  Null-Identitäts-Ausnahmen READ_FAILURE+AUDIT bzw. MMAP+ANON_NO_JIT+PROT_EXEC);
  Text-Wire ≤ 8 Records/2048 B/16 Felder; `f_flags` Phase 1 immer 0. **comm (T7):**
  Kernel-Name via `PR_SET_NAME` prozesskontrolliert ⇒ Go akzeptiert jede Hex-Folge
  ≤16 B (nur NUL-Padding) und sanitisiert nur die Anzeige (`sanitizeTitanExecComm`,
  nicht druckbar ⇒ `?`); ein hostile comm unterdrückt keinen Batch.
- **ABI-2 eBPF** (`rust/gedefense-ebpf/src/main.rs`): `#[lsm(hook =
  "bprm_check_security")]` + `#[lsm(hook = "mmap_file")]`; Maps `TITAN_EXEC_STATE`
  (1), `TITAN_EXEC_OFFSETS` (48, Index 28 = ctime-NSEC-Width), `TITAN_EXEC_MODE`
  (4096), `TITAN_EXEC_POLICY` (65536), `TITAN_EXEC_EVENTS` (RingBuf 1 MiB) + 6
  PerCpu-Zähler; Modi OFF/OBSERVE/CONTAIN/STRICT, Per-Cgroup-Scopes, JIT-Ausnahme,
  Fail-safe-Allow bei Read-Fehlern; keine Shell-/Exec-Primitive (Audit-Gate).
- **ABI-3 VGT3** (`rust/gedefense-core/src/main.rs`): `TITAN_EXEC_VERSION/EPOCH/
  STATUS/SET_GLOBAL/ALLOW_ADD/ALLOW_ADD_BATCH/ALLOW_DEL/CLEAR/SCOPE_SET/SCOPE_DEL/
  EVENTS/HEALTH` mit Validierung vor dem ersten Map-Write; Status
  `applied|pending|failed|inactive|unavailable`; `SET_GLOBAL(mode>0)` ohne
  enforcement-fähiges Gate ⇒ `ERR enforcement-unavailable`.
- **BTF/Offsets** (`rust/gedefense-core/src/btf_offsets.rs`): bounded Mini-BTF-Parser
  (Little-Endian-only, max. 64 MiB, Version 1, `hdr_len=24`, anonyme Unions,
  Tiefenlimit 16). **ctime (T7-Fix):** bevorzugt Split-Layout `i_ctime_sec` (8 B) +
  `i_ctime_nsec` (Width 4|8 aus realem BTF-Feldtyp), sonst Legacy-timespec64; Width
  nach OFFSETS[28]; eBPF liest nsec als u32/u64, sec als u64, saturierend;
  unplausibel ⇒ `offsets=invalid`/`unavailable`, kein Attach. Golden-Werte durch
  **synthetische Fixtures + Real-BTF-Host-Test** belegt; Attach **nur** bei
  `bprm_nargs==1` und `mmap_nargs==4` (`titan_exec_offsets_match_ebpf_slots`).
- **Go-Control** (unprivilegiert): Settings-Namespace `titan_exec` (Schema v14,
  Default disabled/off), purer Plan-Compiler, fail-safe Syncer/Push-Order
  (`SET_GLOBAL(0,0)` → Adds → Scopes → `SET_GLOBAL(mode,flags)`), Event-Parser +
  XDR (Evidence-first, `TITAN.EXEC_DENIED`/`TITAN.MMAP_DENIED`/`TITAN.EXEC_AUDIT`),
  read-only `GET /api/v1/titan/exec/status|events`. `ErrTitanExecUnavailable` =
  Capability-Fakt, keine XDR-Degradierung.

## 3. Aktivierungsbefund und Runbook

**Referenz-Testserver (Ubuntu 24.04):** `uname` `7.0.0-38-generic`, `CONFIG_BPF_LSM=y`,
BTF + `bpftool` vorhanden, **aber** `/sys/kernel/security/lsm` =
`lockdown,capability,landlock,yama,apparmor,ima,evm` (kein `bpf`),
`CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"`, kein `lsm=` in
`/proc/cmdline`. Ein `attach()` liefert dort Erfolg **ohne Wirkung** (die
`bpf_lsm_*`-Stubs werden nie aufgerufen). Konsequenz der Implementierung: Der
Aktivierungs-Check prüft das `bpf`-Token vor jedem Attach; auf dem Server ist der
Status ehrlich `inactive`/`path=none`, `SET_GLOBAL(mode>0)` ⇒
`ERR enforcement-unavailable`, Go-Sync `inactive` (nie `applied`). **P3-Fix:** Der
frühere `+bpf-lsm-cell`-Claim eines wirkungslosen Socket-LSM-Attach ist entfernt
(Core: Attach-Claim nur nach echtem Attach; Go: `cell-lsm-unavailable`).

**Runbook (Operator, nicht automatisiert):** (1) aktuelle LSM-Liste aus
`/sys/kernel/security/lsm` ablesen; (2) exakt diese Liste plus `bpf` als
`lsm=<liste>,bpf` in die Boot-Cmdline eintragen (Reihenfolge/Gesamtliste vorher auf
einem Test-Reboot verifizieren, Rettungs-Kernel/Recovery-Eintrag bereithalten);
(3) Reboot; (4) prüfen: LSM-Liste enthält `bpf`, `TITAN_EXEC_STATUS` liefert
`path=bpf-lsm`/`lsm=active`; (5) `titan_exec.enabled=true, mode=observe` →
Evidenz/Health beobachten → Allowlist planen → `contain`/`strict` nur zellweise.
Ohne (1)–(4) gibt es keine Wirkung; die Cmdline wird nie automatisch geändert.

## 4. Datei-Inventar (Zeilen, neue Dateien ≤ 500)

Neu: `rust/gedefense-common/src/titan_exec.rs` 499 · `rust/gedefense-core/src/
btf_offsets.rs` 499 · `rust/gedefense-core/src/titan_exec.rs` 499 ·
`control/titan_exec_settings.go` 307 · `titan_exec_plan.go` 486 ·
`titan_exec_syncer.go` 472 · `titan_exec_syncer_status.go` 462 ·
`titan_exec_events.go` 489 · Tests: `titan_exec_settings_test.go` 390,
`titan_exec_plan_test.go` 337, `titan_exec_syncer_test.go` 368,
`titan_exec_syncer_status_test.go` 249, `titan_exec_events_test.go` 488,
`titan_exec_api_test.go` 485, `titan_exec_coreipc_test.go` 195.

Additiv geändert: `rust/gedefense-common/src/lib.rs` (Re-Export), `rust/gedefense-core/
src/main.rs` (Gate/Attach/Dispatch/ctime-Split), `rust/gedefense-ebpf/src/main.rs`
(Hooks/Maps/Events/ctime-Width), `control/coreipc.go`, `runtime_settings.go`,
`fabric_settings.go`, `fabric_schema.go`, `server_settings.go`, `server.go`,
`xdr.go`, `xdr_types.go`, `state.go`, `security_fuzz_test.go`, `Makefile`
(Fuzz-Target). Keine bestehende Datei > 500 Zeilen wurde strukturell umgebaut; die
VGT-≤-500-Regel gilt für die neuen Dateien und ist eingehalten.

## 5. Test-/Gate-Evidenz (selbst ausgeführt, WSL Ubuntu 24.04, 2026-11-15; nach T7-Fixes erneut)

- `cargo +1.97.1 test --offline --locked -p gedefense-common -p gedefense-core`
  (aus `rust/`): **Exit 0**; common 31 Lib-Tests + 2 Bin-Tests, core **83 passed /
  0 failed**, 0 doc-tests. Der **Real-BTF-Host-Test**
  `titan_btf_live_vmlinux_resolves_all_offsets` lief auf WSL 6.18 wirklich (kein
  SKIP) und belegte live `i_ctime_sec=104`, `i_ctime_nsec=120`, NSEC-Width 4,
  `inode_size=608` (übrige Golden-Werte unverändert).
- Nightly-eBPF-Build `cargo +nightly-2026-07-16 build --locked -p gedefense-ebpf
  --release --target bpfel-unknown-none -Z build-std=core`: **Exit 0**;
  `dist/gedefense-ebpf` **109.384 Byte**, **keine `__multi3`-Symbole**; `readelf
  -S/-s`: Sektionen `lsm/socket_create`, `lsm/bprm_check_security`,
  `lsm/mmap_file`; Symbole `TITAN_EXEC_STATE/OFFSETS/MODE/POLICY/EVENTS`,
  `gedefense_titan_exec_bprm`, `gedefense_titan_exec_mmap` vorhanden.
- `cd control && go vet ./...`: **Exit 0**; `go test -count=1 -run 'Titan|Exec|XDR'
  ./...`: **Exit 0** (`ok … 7.561s`; `-v`: **219 RUN, 219 PASS, 0 FAIL, 0 SKIP**).
  Voller Lauf nach den Fixes (selbst ausgeführt, `-v`, T7-Stand): **Exit 0**, 1420
  `=== RUN`, **1418 PASS, 0 FAIL, 2 SKIP** (`ok … 265.976s`; Nicht-`-v`-Lauf
  ebenfalls Exit 0); 981 deklarierte `func Test`-Funktionen. Fixbelege:
  `TestParseCoreTitanExecEventsAcceptsRawKernelComm`,
  `TestTitanExecHostileCommDoesNotSuppressBatch`,
  `titan_btf_split_ctime_layout_publishes_the_nsec_width`,
  `titan_btf_live_vmlinux_resolves_all_offsets`.
- `bash scripts/security-audit.sh`: **Exit 0**, `SECURITY AUDIT PASS`,
  **26 PASS-Prüfungen** inkl. P1-Anker, T7-Fix-Anker (Split-ctime/NSEC-Width, roher
  `comm`, Inert-Policy-Grenze) und ELF-Gate; der bestehende Attach-Anker wurde auf
  `program.load("socket_create", btf)?` aktualisiert und die Slot-/Aritätsprüfung auf
  stabile Anker (`bprm_nargs`/`mmap_nargs` + `*match_ebpf_slots` über beide
  Core-Dateien) robust repariert — die harte 1/4-Bedingung bleibt geprüft.
- `node --check control/web/*.js`: **Exit 0** (19 Dateien);
  `bash packaging/tests/install-smoke.sh`: **Exit 0**, **48 passed, 0 failed**
  (T6-Stand, in dieser Runde nicht erneut ausgeführt).

## 6. Restrisiken/Phasengrenzen

- **Aktivierungsblocker Server:** keine Wirkung ohne Boot-Cmdline `lsm=...,bpf` +
  Reboot (Operator, Rettungs-Kernel); Cmdline-Änderung/Reboot sind nicht Teil der
  Implementierung.
- **Kein Live-Verifier-/Attach-Test auf Produktion:** belegt sind Nightly-Build
  (Verifier-Gate), readelf, lokale Unit-Tests und die reale Live-BTF-Auflösung
  (`titan_btf_live_vmlinux_resolves_all_offsets`); echtes `bpf()`-Load/Attach auf
  einem aktivierten Produktions-Kernel bleibt Integrationsschritt.
- Event-`f_flags` ist Phase 1 immer 0 (kein Offset im ABI).
- Dev-Roots werden nicht kernel-enforced; STRICT erfordert vollständige Allowlist
  (sonst Exec-/SSH-Lockout); Map-Verlust = dokumentiertes Fail-open-Fenster bis
  Resync (≤ 10 s).
- Phasengrenzen: kein `file_mprotect`/W^X, kein fs-verity-Enforcement, kein
  Fanotify-Exec-Fallback (nur Option), Events ohne Pfad, Overlayfs-Copy-up; Phase 1
  ohne UI-Panels (nur Settings + read-only API), keine Enforcement-Behauptung ohne
  aktive LSM-Liste. **T7-Restrisiken bereinigt:** ctime-Layout- und comm-Parser-Risiko
  sind mit Fixes + Tests entfallen; P1-T7 hat keinen offenen FAIL.

## 7. Nächster Schritt

Punkt 2 (ephemere Parser-Zellen) gemäß Blueprint-Reihenfolge; P1-T7-Review ist
abgeschlossen (PARTIAL, Fixes umgesetzt). Die Operator-Aktivierung (`lsm=...,bpf` +
Reboot) erfolgt separat auf einem Test-/Wartungsfenster. Kein GitHub-Push in dieser
Runde.
