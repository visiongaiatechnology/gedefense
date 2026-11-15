# POINT 5 — Emergency Lockdown: Phase-1-Implementierungs- und Verifikationsbericht

**Stand:** 2026-11-15 · **Release:** GeDefense V6 (`6.0.0`) · **Status:** Phase 1 implementiert und gate-verifiziert
**Vertrag:** `docs/POINT5-LOCKDOWN.md` (§3–§9 ABI/Phasen, §12 DoD, §13 Abweichungen)
**Deployment:** **nichts deployt**; Default **disabled** (`lockdown.enabled=false`, Settings-Schema v16); kein Git-Push/Commit/Tag/Release.

## 1. Scope (Phase 1)

Umgesetzt: Anti-Physical-Extraction/Emergency-Lockdown-Detektion und -Latch auf
Linux – eBPF-Netz-Drop (XDP/TC/cgroup-Egress), USB/Thunderbolt-Hotplug-Policy
(sysfs + Netlink-UEVENT), reversible Hardening-Sysctl-Beobachtung/-Opt-Write,
Key-Broker-Freeze (`SIGSTOP`/`SIGCONT`), Zell-/Parser-Zell-Phasen über bestehende
Go-Engines, Evidence-first-Latch, Operator-API und Runbook-fähiger Status.

Bewusst **nicht** Phase 1: LUKS/DM-Suspend (`/dev/mapper` fehlt durch
`PrivateDevices`), `loginctl lock-sessions` (kein D-Bus), Kernel-Lockdown-Umschaltung
(nur Boot-Parameter), RAM-Zeroize der Broker (nur Freeze, kein „locked"-Claim),
UI-Panels (nur Settings + API/Status).

## 2. Architektur

```text
Trigger (Morpheus CRITICAL | Canary UNAUTHORIZED | Boot-Trust-Drift | Operator | Duress)
   ▼
Go-Control (unprivilegiert): LockdownEngine
   ├─ Latch-Dokument AEAD/atomar (/var/lib/vgt/gedefense/lockdown-engine.state)
   ├─ P0 Intent-Evidence + State (fail-closed: korrupt ⇒ latched)
   ├─ P1 LOCKDOWN_TRIGGER via VGT3 → Core (NET/USB/TB/HARDENING/BROKERS)
   ├─ P2 Zellen (CellGuard/TransactionEngine) + Parser-Zellen (BurnForIncident)
   └─ P3 Audit + Latch; Clear nur Operator (Confirmation + expected_epoch)
   ▼
Rust-Core (root): LockdownCore, USB/TB-Policy, Uevent-Thread, Hardening,
   Broker-pidfd-Freeze, State-File/Re-Arm; eBPF: LOCKDOWN_STATE/DROPS/WITNESS
```

Privilege Split bleibt erhalten: Go hat CapEff=0, eBPF-Map/Drop und sysfs/pidfd
nur im Core; kein neuer Daemon, keine Shell/`Command`-Primitive, kein D-Bus.

## 3. Datei-Inventar (P5)

| Bereich | Dateien (Zeilen) |
|---|---|
| Rust-Common (ABI-1) | `rust/gedefense-common/src/lockdown.rs` (499; Word/Event/Konstanten/Decoder), Re-Export in `lib.rs` |
| eBPF (ABI-2) | `rust/gedefense-ebpf/src/main.rs` (additiv: `LOCKDOWN_STATE`, `LOCKDOWN_DROPS`, `LOCKDOWN_WITNESS_PASSES`, Fastpath in XDP/TC/Egress) |
| Rust-Core (ABI-3) | `lockdown.rs` (496), `lockdown_usb.rs` (500), `lockdown_uevent.rs` (457), `lockdown_hardening.rs` (324), `lockdown_brokers.rs` (387), `main.rs` (State-File/Re-Arm, Map-Handles, `LOCKDOWN_*`-Dispatch, Tests) |
| Go-Control | `lockdown.go` (375), `lockdown_engine.go` (385), `lockdown_phases.go` (381), `lockdown_settings.go` (459), `lockdown_status.go` (218), `lockdown_triggers.go` (404), `lockdown_api.go` (254), `lockdown_maintenance.go` (206); Tests `lockdown_test.go` (464), `lockdown_engine_test.go` (462), `lockdown_api_test.go` (322) |
| Go additive Edits | `runtime_settings.go` (v16/Migration), `fabric_settings.go`, `fabric_schema.go` (Modul `lockdown`), `server.go` (4 Routen + Evidence-Gate-Ausnahme + Snapshot), `xdr.go` (Incident-Hook/Attach), `main.go` (Engine-Konstruktion/Start), `state.go` (Snapshot), `coreipc.go` (VGT3-Client/Parser), `security_fuzz_test.go` (2 Fuzz-Targets), `Makefile` |
| Packaging | `packaging/systemd/gedefense-core.service` (USB/TB-sysfs inkl. `/sys/devices` für die Symlink-Ziele, 3 Sysctl- und State-Dir-Grants; keine Cap/AF/Syscall-Änderung), `scripts/security-audit.sh` (P5-Anker + ELF-Symbole), `scripts/validate-systemd.sh`, `packaging/tests/install-smoke.sh` |
| Doku | `docs/POINT5-LOCKDOWN.md` (§13), `ARCHITECTURE.md` (§3.37 + Drift-Korrektur Emergency Stop), dieser Report |

Alle neuen Go-/Rust-Dateien ≤500 Zeilen (VGT-Regel). Durch P5-T4 wurden **keine**
Go-/Rust-Code- oder Testdateien verändert.

## 4. Test-Evidenz (nur selbst ausgeführt, WSL Ubuntu 24.04, uid 1000)

- `cargo +1.97.1 test --offline --locked -p gedefense-common -p gedefense-core -p gedefense-cell-helper`
  → **Exit 0**: 191 passed, 0 failed, 1 ignored (helper 40 + 1 root-gated ignored,
  common 38 lib + 2 Bin-Tests = 40, core 111, 0 doc-tests). Die root-gated uevent-Netlink-
  Test ist als `#[ignore]` markiert (non-root SKIP, kein stilles OK).
- eBPF-Nightly-Build (`nightly-2026-07-16`, `bpfel-unknown-none`, `-Z build-std=core`)
  → **Exit 0**; `dist/gedefense-ebpf` neu gebaut (112.176 B); `readelf -s -W` enthält
  `LOCKDOWN_STATE`, `LOCKDOWN_DROPS`, `LOCKDOWN_WITNESS_PASSES`; Sektionen `xdp`,
  `classifier`, `cgroup_skb/egress` vorhanden. (Build-Warnung `linker stderr:
  unable to open LLVM shared lib …` ist eine Host-/Toolchain-Warnung des
  bpf-linker, der Build ist Exit 0; sie ändert das Objekt nicht.)
- `cd control && go vet ./...` → **Exit 0**; `go test -count=1 -timeout 1800s ./...`
  → **Exit 0** (`ok … 181.426s`, keine FAIL-Zeile); separater `-v`-Beleglauf → **Exit 0**,
  **1519 PASS / 0 FAIL / 2 SKIP** bei 1521 RUN (`ok … 154.020s`).
- `node --check control/web/*.js` → **Exit 0**.
- `bash scripts/security-audit.sh` → **Exit 0**, `SECURITY AUDIT PASS`, **29
  PASS-Prüfungen** inkl. Point-5-Block, exaktem sysfs-Grant-Satz und
  eBPF-ELF-Symbolen.
- `bash packaging/tests/install-smoke.sh` → **Exit 0**, **68 passed / 0 failed**
  (STATIC + Staged-Root; 6 NOT_TESTED: cross-account-Traversal, Helper-`--check`
  root-gated, pacman-Install, systemd-Boot, nspawn/VM, AstraeaOS-Login-Gate).
- `bash scripts/validate-systemd.sh` → **Exit 0** (isoliertes Verify-Root; Unit
  inkl. P5-Grants und exaktem sysfs-Set; `/bin/sh`-Staging-Shim bleibt als
  NOT_TESTED dokumentiert).
- **Nicht ausgeführt/NOT_TESTED:** realer systemd-Start der geänderten Unit auf
  einem Zielhost, **realer USB/TB-sysfs-Write unter `ProtectKernelTunables=true`**
  (der `/sys/devices`-Grant für die Symlink-Ziele ist gated, aber nicht auf
  Hardware bewiesen), root-gated Uevent-Netlink-Test (non-root SKIP), Live-XDP/TC-
  Drop-Nachweis auf Produktionsserver, echter USB/TB-Hotplug. Kein Deploy/Netz/git.

## 5. Phasen-Matrix (Phase 1)

| Phase | Status Phase 1 | Beleg / Grenze |
|---|---|---|
| NET (XDP/TC/cgroup-Egress) | implementiert | Map-Wort + Array-Read-back; XDP-Drop, TC_SHOT, Egress-DROP mit loopback-only-Ausnahme; kein Claim ohne Read-back |
| USB | implementiert | `drivers_autoprobe=0` + `authorized` je Gerät; power-only/HID/Hub ausgenommen; not-present ⇒ `unsupported`; Grant `/sys/devices` real NOT_TESTED |
| TB | implementiert | alle `authorized=0` (DMA); not-present ⇒ `unsupported`; Grant `/sys/devices` real NOT_TESTED |
| HARDENING | implementiert | Observe Pflicht; Schreiben nur opt-in (`kexec_load_disabled`, `sysrq`); `modules_disabled` nur explizit |
| BROKERS | implementiert | feste Name-Liste, pidfd-Identität, `frozen-not-locked`, TTL 300 s, keine Kills |
| CELLS | delegiert (Go) | `cells=delegated`; Zell-Freeze via CellGuard/TransactionEngine, Parser-Zellen Burn |
| SESSIONS | `unsupported` | `no-dbus-session-lock` |
| DM/LUKS | `unsupported` | `no-device-mapper` (PrivateDevices) |
| Kernel-Lockdown-Toggle | `unsupported` | `boot-parameter-immutable` |

## 6. Operations-Runbook

**Aktivieren/Armen (Operator):**
1. Settings `lockdown.enabled=true` (Settings-API, Fabric-Modul `lockdown`); optional
   `auto_arm`, Trigger-Schalter, `cooldown_seconds`, `cell_scope`, `drop_loopback` prüfen.
2. `POST /api/v1/lockdown/arm` mit `{mode:"locked", reason:"…≥8 Zeichen"}` (Bearer +
   `X-VGT-Request-ID`). `LOCKDOWN_ARM` schreibt nur das Arming/Policy-Wort, **keinen** Drop.
3. `GET /api/v1/lockdown/status` prüfen: `state=armed`, `epoch`, `phases` leer/`skipped`.

**Triggern:**
- Automatisch: Morpheus-RASP-CRITICAL, Canary-`CANARY_UNAUTHORIZED_PROBE`
  (keine Scanner/System-Zugriffe) oder Boot-Trust-Verschlechterung – Guard:
  Fingerprint-Dedupe 5 min, Cooldown, `require_sources`.
- Manuell: `POST /api/v1/lockdown/trigger`
  `{confirmation:"TRIGGER LOCKDOWN", reason:"…≥8…", source:"manual"}` (Rate-Limit 1/min).
- Danach `status` prüfen: `latched=true`, `phases` je Phase `applied|partial|unsupported`,
  `degraded` bei Teilfehlern; `evidence` nie „applied" ohne Ledger.

**Clear (nur Operator):**
1. `epoch` aus `GET /api/v1/lockdown/status` entnehmen.
2. `POST /api/v1/lockdown/clear`
   `{confirmation:"CLEAR:LOCKDOWN", reason:"…≥8…", expected_epoch:"<8hex>"}`.
3. Falsche Confirmation/Epoch ⇒ 403/409, Latch bleibt. Erst nach erfolgreichem
   `cleared` Kern-Wort aus, Broker/Zellen resumed; Evidence `lockdown.clear.*`.
4. `resume_failed`-Events (z. B. geprunete Zell-Transaction) bedeuten: Workload bleibt
   isoliert – manuell prüfen/nachziehen, kein stilles De-Isolieren.

**Lokale Console/127.0.0.1 während des Drops:** `allow_loopback=true` (Default) hält
Loopback für authentisierte Clear-Requests offen; externer Verkehr ist tot. Ist das
Dashboard nur über eine externe Adresse erreichbar, ist der Clear vom Host selbst
(z. B. lokale Shell → `127.0.0.1:9844`-API) oder über die Gateway-Bindung an
`127.0.0.1:9843` zu fahren.

**Panik-Modus (`drop_loopback=true`):** auch Loopback wird gedroppt; ein API-Clear ist
dann nicht erreichbar. Recovery: lokale TTY/Datei-Token oder Host-Neustart (eBPF-
Maps/Programme enden mit dem Core, kein Pinning) – der Go-Latch bleibt über den
Restart erhalten und wird beim nächsten erreichbaren Operator-Clear mit
`expected_epoch` freigegeben. Diese Grenze ist bewusst dokumentiert.

**Recovery nach Core-Restart (Latch aktiv):** Core startet, liest
`/var/lib/vgt/gedefense/LOCKDOWN.state` und re-armt die persistierten Phasen **vor**
IPC-Ready; Go-Latch bleibt. Status kann kurz `degraded`/`re-arming` zeigen; nach
erfolgreichem Read-back `active`. Korruptes State-File ⇒ `degraded` + latched (kein
stilles Off); Clear bleibt Operator-Sache.

## 7. Restrisiken / Phasengrenzen

- Kein Map-Pinning: Core-Crash beendet den eBPF-Drop (Fenster bis Re-Arm/Neustart),
  Fail-open-Grenze dokumentiert.
- Stale-Attach: alte TC-Filter einer früheren Core-Generation werden nicht detached;
  `LOCKDOWN_STATUS` belegt nur das eigene Wort (kein Full-Stack-Claim).
- Uevent verlustbehaftet (`ENOBUFS` ⇒ Rescan, keine Event-Rekonstruktion); USB-
  Power-only/HID-Heuristik ist bounded, kein Vendor-Sonderfall-Beweis.
- Broker-Freeze ist `frozen-not-locked` (kein Zeroize); `modules_disabled` nie
  automatisch; DM/LUKS/Session/Kernel-Lockdown ehrlich `unsupported`.
- Zell-Reverse hängt an der Transaction-History (Pruning ⇒ lautes `resume_failed`).
- USB/TB-sysfs: die Bus-Pfade `/sys/bus/usb/devices` und
  `/sys/bus/thunderbolt/devices` sind Symlinks; deshalb musste der
  ReadWritePaths-Grant auf `/sys/devices` erweitert werden (sonst EROFS → Policy
  fail-safe, aber real unwirksam). Der Grant ist damit breiter als die exakten
  Geräte; realer Schreibzugriff ist **NOT_TESTED** (kein root/systemd-Zielhost).
- Kein realer systemd-/Hotplug-/XDP-Live-Test in dieser Umgebung; root-gated
  Netlink-Test non-root SKIP. Aktivierung auf Zielhost separat (Wartungsfenster).

## 8. Nächster Schritt

**Blueprint-Punkt 4.** Kein GitHub-Push/Commit/Tag/Release, kein Deploy durch diese
Sitzung; Änderungen bleiben im Arbeitsbaum.
