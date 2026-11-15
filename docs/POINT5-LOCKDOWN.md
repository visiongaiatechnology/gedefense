# POINT 5 — Anti-Physical-Extraction / Emergency Lockdown

**Status:** IMPLEMENTIERT (Phase 1) · Stand 2026-11-15 · GeDefense V6 (`6.0.0`)
**Implementierungsstand:** P5-T1 (Common/eBPF), P5-T2 (Rust-Core), P5-T3 (Go-Control) und P5-T4 (Packaging/Audit/Doku) umgesetzt; Default **disabled** (Settings `lockdown.enabled=false`, Version v16), nichts deployt. Abweichungen und Präzisierungen gegenüber dieser Spec: §13; Test-/Gate-Evidenz und Betriebs-Runbook: `docs/POINT5-PHASE1-REPORT.md`.
**Review-Regel:** Verbindlicher Vertrag zwischen eBPF, Rust-Core, Go-Control und Packaging. ABI-Änderungen zuerst hier.

## 0. Ausgangsbefund (Recon, evidenzbasiert)

- Im Repo existiert **kein** Lockdown/duress/uevent/USB-Code. Der bestehende „Emergency Stop" (`control/release.go`) schreibt nur einen Marker und degradiert XDR — er isoliert **nichts**; Doku-Claims (`POST /api/v1/emergency-stop`, `CMD_BLOCK_ALL`) existieren im Code nicht.
- Trigger sind vorhanden: Morpheus-RASP-CRITICAL (Score 250), Canary-`CANARY_UNAUTHORIZED_PROBE` (CRITICAL/200), Boot-Trust-Local-Baseline-Drift (`VERIFIED→OBSERVE`), Operator-API. Alle münden in `appendIncident`/Event-Bus; Evidence-first-Vertrag vorhanden.
- Core-Fähigkeiten real (Server, gemessen): Caps `KILL,NET_ADMIN,SYS_RESOURCE,SYS_ADMIN,PERFMON,BPF`; `/sys` im Core-Mount-Ns **rw** (USB/TB-sysfs schreibbar), `AF_NETLINK` erlaubt, `/proc/sys` nur einzeln gegrantet; XDP (`ens6`) + TC-ingress + `cgroup_skb/egress` sind **live attached**; `PrivateDevices=true`, `ProtectKernelTunables=true`, `ProtectControlGroups=true`, kein `/dev/mapper/control`.
- **Phase 1 ehrlich möglich:** Netz-Drop im Kernel (XDP/TC/egress), USB/Thunderbolt-Hotplug-Policy (sysfs + Netlink-UEVENT), Hardening-Sysctl-Beobachtung/-Setzen (allowlist), Key-Broker-`SIGSTOP` (reversibel), Zell-Freeze über bestehende Adapter, Latch/Evidence/API. **Nicht Phase 1:** LUKS/DM-Suspend (kein `/dev/mapper`/PrivateDevices), `loginctl lock-sessions` (kein D-Bus), Kernel-Lockdown-Toggle (nur Boot-Parameter), echter RAM-Zeroize der Broker (nur Freeze, ehrlich `frozen-not-locked`).

## 1. Ziel und Leitplanken

Ziel: Bei physischem Tamper/DMA/USB-Hotplug im gesperrten Zustand oder bei High-Confidence-Tamper-Events kappt GeDefense in Sekunden externen Netzverkehr, friert Key-Broker/Prozesse/Zellen ein, verweigert neue USB/Thunderbolt-Geräte, setzt optionale Hardening-Sysctls, versiegelt Evidence und bleibt **gelatcht**, bis ein authentisierter Operator mit korrektem Epoch/Confirmation clears.

Leitplanken:
1. **Privilege Split:** Kernel-/sysfs-/Netlink-/Hardening-Eingriffe nur im Rust-Core über VGT3; Go unprivilegiert (CapEff=0). Kein neuer Daemon, keine Shell/`Command`-Primitive, kein D-Bus.
2. **Keine Attrappe / Fail-Closed:** Jede Phase hat echten Verify/Read-back; nicht unterstützte Phasen melden `unsupported:<reason>`; fehlende Fähigkeiten `unavailable`/`degraded`; **nie** „isoliert/enforced" ohne Kernel-Nachweis. Latch-Persistenz: State umlesbar/korrupt ⇒ latched.
3. **Reversibel & Forensik:** Drop/Freeze/USB-Sperre sind reversibel (Clear mit Epoch/Confirmation + Evidence); nichts wird gelöscht; Zell-Freeze über bestehende TransactionEngine; Evidence vor jeder aktiven Phase (Ausnahme: Kern-Notfall-Drop erlaubt sofort, Evidence-Intent unmittelbar danach mit Epoch-Korrelation).
4. **Recoverability:** `ALLOW_LOOPBACK` (Default **an**) hält die lokale Loopback-Steuerung (127.0.0.1/::1) für authentisierte Clear-Operationen offen; externer Verkehr ist tot. Opt-in `drop_loopback=true` (Panic-Modus) tötet auch Loopback; Clear dann nur lokal (TTY/Datei-Token/Neustart) — dokumentiert.
5. **Kein Umbau bestehender Module:** ResponseEngine/TransactionEngine/EvidenceLedger/CellGuard/Morpheus/Canary bleiben; Ergänzungen additiv.

## 2. Architektur

```
Trigger (Morpheus CRITICAL, Canary unauthorized, Boot-Trust drift, Operator/Duress)
   ▼
Go-Control: LockdownEngine (armed→triggering→active(latched)→clearing)
   ├─ P0 Evidence-Intent (Ledger) + Latch-State (AEAD/atomar)
   ├─ P1 Core LOCKDOWN_TRIGGER (Netz-Drop, USB/TB-Sperre, Hardening, Broker-SIGSTOP)
   ├─ P2 Zellen-Freeze (bestehende CellGuard/TransactionEngine; P2-parser via Burn)
   └─ P3 Latch + Audit-Transaction-Log; Clear = Operator-only, Epoch/Confirmation
   ▼ VGT3
Rust-Core: LOCKDOWN_* Kommandos
   ├─ eBPF LOCKDOWN_STATE (XDP + TC-ingress + cgroup_skb/egress Drop, ALLOW_LOOPBACK)
   ├─ USB/TB: sysfs authorized/drivers_autoprobe + Netlink-UEVENT-Monitor
   ├─ Hardening: allowlist sysctls (kexec_load_disabled, sysrq, modules_disabled opt-in)
   ├─ Broker-Freeze: SIGSTOP/SIGCONT (fixed name list, PID-Identität)
   └─ State-File (atomar) + Re-Arm beim Start, Events/RingBuf/Counter
```
USB-Trigger: Core-UEVENT-Monitor blockt im `locked`-Arm-Modus unbekannte Geräte (authorized=0) und emittiert ein Event; bei `auto_network_drop=true` setzt der Core sofort den Kernel-Drop (Sekundenbruchteile), Go latcht/evidenziert beim Poll. Im `unlocked`-Modus: nur Audit, kein Drop/Sperren (Lade-Kabel-DoS-Schutz).

## 3. ABI-1: gemeinsame Konstanten (`rust/gedefense-common/src/lockdown.rs`)

```
LOCKDOWN_STATE_MAGIC = 0x4C ('L'), LOCKDOWN_STATE_ABI = 1
LOCKDOWN_WORD(epoch u32, mode u8, flags u8, abi, magic) → u64:
  bits0..31 epoch | 32..39 mode(0=off,1=armed) | 40..47 flags
  flags: bit0 DROP_ALL, bit1 ALLOW_LOOPBACK, bit2 WITNESS_ALLOW (Phase 2, immer 0)
          bit3 HARDENING_APPLIED, bit4 USB_LOCKED, bit5 TB_LOCKED
  abi 48..55 = 1, magic 56..63 = 0x4C
LOCKDOWN_EVENT_WIRE_BYTES = 64
LOCKDOWN_REASON_*: MANUAL=1, USB_UNKNOWN=2, TB_UNKNOWN=3, SCREEN_LOCK=4, TAMPER=5,
  XDR_CRITICAL=6, BOOT_TRUST_DRIFT=7, POLICY=8
LOCKDOWN_SOURCE_*: MANUAL=1, UEVENT=2, POLICY=3, TIMER=4
LOCKDOWN_PHASE_*: INTENT=0, NET=1, USB=2, TB=3, HARDENING=4, BROKERS=5, CELLS=6,
  SESSIONS=7, DM=8
LOCKDOWN_OUTCOME_*: APPLIED=1, SKIPPED=2, UNSUPPORTED=3, FAILED=4, PARTIAL=5
```
`LockdownEvent` (64 B, repr(C), native): `seq u64, ts_ms u64, epoch u32, source u8, reason u8, phase u8, outcome u8, cgroup_id u64, detail_u64 u64` + `reserved[16]`; Decoder mit Reject-Matrix (len, Enums, seq>0, ts>0, unbekannte detail-Bits maskieren? detail-semantik je phase dokumentiert; keine Pfade/Secrets). Const-Assert `size_of==64`.

## 4. ABI-2: eBPF (`rust/gedefense-ebpf/src/main.rs`)

- Neue Map `LOCKDOWN_STATE: Array<u64>` (1 Entry). Default-Wort 0 = OFF. Fremde Magic/ABI/Modus ⇒ Altpfad (fail-safe, kein Drop).
- Neue Counter `LOCKDOWN_DROPS`, `LOCKDOWN_WITNESS_PASSES` (PerCpuArray<u64>).
- **Pfade:** `gedefense_xdp` (am Programmkopf, vor `inspect`), `gedefense_tc_ingress` (Kopf), `inspect_egress`/`gedefense_egress` (vor `STYX_GLOBAL`-Lookup). Fastpath: 1 Array-Lookup + 1 Branch; OFF/Wort ungueltig ⇒ byte-identischer Altpfad.
  - XDP: `XDP_DROP` wenn DROP_ALL; `ALLOW_LOOPBACK` irrelevant (XDP nur externer Iface, loopback kommt dort nicht an).
  - TC-ingress: `TC_ACT_SHOT`.
  - cgroup_skb/egress: wenn DROP_ALL und `ALLOW_LOOPBACK` gesetzt: minimalen L3-Header lesen und Loopback (`127.0.0.0/8`, `::1`) passieren lassen; sonst `0` (DROP). Parse-Fehler ⇒ DROP (fail-closed im Lockdown).
- Kein Paket-RingBuf (Flut); Lifecycle-Events erzeugt der Core. Bestehende Programme/Maps/Anker unverändert; `readelf`-Symbole `LOCKDOWN_STATE`/`LOCKDOWN_DROPS` sind Build-Gate.

## 5. ABI-3: Core-Kommandos (VGT3, bestehendes Framing)

| Kommando | Argumente | OK-Payload |
|---|---|---|
| `LOCKDOWN_VERSION` | — | `lockdown-v1` |
| `LOCKDOWN_EPOCH` | — | 8 Hex (u32, neu je Core-Start) |
| `LOCKDOWN_STATUS` | — | `state=<off\|armed\|active\|degraded>;epoch=<8hex>;mode=<locked\|unlocked>;flags=<u8>;phases=<csv-applied>;unsupported=<csv>` |
| `LOCKDOWN_ARM` | `mode` (`locked`\|`unlocked`), `reason` (Token), `flags` (u8; bit0 auto_network_drop, bit1 allow_loopback, bit2 freeze_brokers, bit3 hardening_apply) | `armed:<epoch8>` / `armed-unchanged:<epoch8>` (idempotent) |
| `LOCKDOWN_TRIGGER` | `source` (Token), `reason` (Token), `flags` (u8) | `triggered:<epoch8>;phases=<applied-csv>;unsupported=<csv>` |
| `LOCKDOWN_CLEAR` | `expected_epoch` (8 hex), `reason` (Token) | `cleared` / `already-off`; Epoch-Mismatch = ERR (compare-set) |
| `LOCKDOWN_SET_MODE` | `locked`\|`unlocked` | `applied` (nur Arm-Modus ändern, ohne Trigger) |
| `LOCKDOWN_EVENTS` | — | `empty` oder `<dropped>|<seq:ts:source:reason:phase:outcome>,…` (≤16, Text-Wire, Alles-oder-Nichts beim Go-Parser) |
| `LOCKDOWN_HEALTH` | — | `net_drops:witness_passes:uevent_events:usb_blocks:tb_blocks:broker_frozen` (6 dezimal, Per-CPU-Summen/saturierend) |
| `LOCKDOWN_PHASE` | `phase` (Token), `on\|off` | `applied:<phase>` / `unsupported:<phase>:<reason>` / `failed:<phase>:<reason>` (Einzelphase für Operator-Tests) |

Tokens geschlossen (`src`/`reason`/`phase`), keine Freitext-Pfade/IPs in Payloads; Antworten ≤2048 B; unbekannte Kommandos bleiben ERR.

**Core-Zustand/Persistenz:** State-File `/var/lib/vgt/gedefense/LOCKDOWN.state` (atomar, 0640 root:gedefense, Inhalt `epoch|mode|flags|phases|ts`), Re-Arm beim Start (Drop/USB-Sperre/Hardening wieder anwenden) **vor** IPC-Ready; korrupt/unlesbar ⇒ `degraded` + gelatcht (kein stilles Off). Epoch wird bei jedem Trigger neu erzeugt; Clear prüft Epoch. Keine Map-Pinning: Core-Crash beendet Drop (eBPF-Map/Programme weg) ⇒ bei Neustart Re-Arm sofort; Fenster dokumentiert (Fail-open-Grenze).

## 6. Core-Phasen (Reihenfolge, idempotent, je Verify)

1. `NET`: `LOCKDOWN_STATE`-Wort mit DROP_ALL (+ALLOW_LOOPBACK nach Flag) schreiben; Read-back (Array-read) + Zähler; Fehler ⇒ Phase `failed`, Rest weiter, Gesamt `partial` (kein Claim „Netz tot", wenn Read-back fehlt).
2. `USB`/`TB`: `/sys/bus/usb/drivers_autoprobe=0`, bestehende Geräte nach Policy (`authorized=0` für non-HID/Hub, HID/Hub default-allow wegen Console; Thunderbolt: alle authorized=0, da DMA), Read-back je Gerät; `not-present` ⇒ `unsupported`-Status (kein Fehler, ehrlich). Uevent-Monitor wird bei ARM gestartet (Thread, bounded, Rescan nach ENOBUFS); locked + unbekanntes non-power-only-Gerät ⇒ authorize=0 + Event `source=UEVENT`; optional auto NET-Drop.
3. `HARDENING`: Beobachten (Pflicht, kein Schreiben) von `kexec_load_disabled`, `sysrq`, `modules_disabled`, `unprivileged_bpf_disabled`, kernel-lockdown; Schreiben nur bei Flag: `kexec_load_disabled=1`, `sysrq=0` (idempotent); `modules_disabled=1` **niemals automatisch** (irreversibel/Docker-Risiko), nur expliziter Einzelbefehl `LOCKDOWN_PHASE hardening on` nach separater Operator-Freigabe → dann `unsupported`/`skipped` für Auto. Persistenz nur via bestehendem sysctl-Mechanismus (core-allowlist).
4. `BROKERS`: Fixed-Name-Liste (`ssh-agent`, `gpg-agent`, `gnome-keyring-d`, `keepassxc`, `vault`, `astraea-key-broker`), `/proc`-Scan bounded (≤512 PIDs), Identität per starttime + eigenes PID ausschließen, `SIGSTOP` via pidfd; Status `frozen-not-locked` (kein Zeroize-Claim); Clear sendet `SIGCONT` an dieselben PIDs (bounded, TTL max 300 s). Fehler einzelner PIDs ⇒ `partial`.
5. `CELLS`-Phase läuft im **Go**-Control (Reihenfolge 3), nicht im Core (Core hat keine cgroup-Schreibrechte); Core meldet nur Phase `cells=delegated`.
6. `SESSIONS`/`DM`: Phase 1 `unsupported` (kein D-Bus/`/dev/mapper`), klar im Status; Kernel-Lockdown-Toggle ebenso `unsupported` (Boot-Parameter). Keine Attrappe.

## 7. Go-Control — LockdownEngine

Neue Dateien (≤500 Z./Datei, Muster P1/P3): `control/lockdown_settings.go` (Namespace `lockdown`, `fabricSettingsVersion` 15→16), `lockdown.go` (Engine/Zustandsmaschine), `lockdown_triggers.go` (Incident-/Boot-Trust-/Duress-Trigger), `lockdown_api.go` (Routen), `lockdown_test.go`.
- **Settings:** `Enabled=false`, `AutoArm=false`, `TriggerMorpheusCritical=true`, `TriggerCanaryUnauthorized=true`, `TriggerBootTrustDrift=true`, `RequireSources=1`, `FreezeProcesses=true`, `FreezeBrokers=true`, `NetworkLockdown=true`, `AllowLoopback=true`, `DropLoopback=false`, `FreezeCells=true`, `FreezeParserCells=true`, `CellScope="all|high-risk"`, `HardeningApply=false`, `CooldownSeconds=300`, `MaxTargets=256`, `ExcludeUID0=true`, `DuressTokenPath=""` (optional, nur wenn gesetzt); Defaults inert, Migration v15→v16.
- **Zustand:** `disarmed|armed|triggering|active(latched)|clearing`, persistiert atomar (`/var/lib/vgt/gedefense/lockdown-engine.state`, Muster Release-Sticky/AEAD), unlesbar ⇒ `latched` (fail-closed) + kritische Event. Latch bleibt über Restart; Clear nur Operator (Bearer + Replay + `X-VGT-Request-ID` + `Confirmation="CLEAR:LOCKDOWN"` + `expected_epoch`), Evidence-first `lockdown.clear.intent`.
- **Trigger:** (a) Incident-Hook in `appendIncident`: Morpheus RuleID-Präfix `MORPHEUS.RASP.*` & Severity CRITICAL; Canary nur `KD.LINUX.CANARY_ACCESS` mit `CANARY_UNAUTHORIZED_PROBE`/severity CRITICAL, keine System-/Scannerzugriffe; (b) Boot-Trust 60-s-Reconcile: nur Verschlechterung von `VERIFIED` auf `OBSERVE`/kritische Attestation-Warnung (kein Trigger bei NOT_SUPPORTED); (c) Operator-API mit `Confirmation="TRIGGER LOCKDOWN"`, Reason 8..240; (d) optional Duress-Datei-Token (nur wenn konfiguriert, Poll 1 s, bounded). Dedupe/Cooldown/Fingerprint; `RequireSources` unterstützt Mehrquellen-Bestätigung.
- **Phasen-Orchestrierung:** P0 Evidence-Intent + State; P1 `LOCKDOWN_TRIGGER` (Flags aus Settings) → Phasen-Ergebnisse übernehmen; P2 Zell-Freeze via bestehender `CellGuard.Confine`/Adapter (CellScope), Parser-Zellen via `BurnForIncident` (evidence-first; wenn Cells/Capability fehlt ⇒ `unavailable`, kein Claim); P3 Audit-Transaktions-Log/Event + Latch. Trigger/Clear sind vom Evidence-*Gate* ausgenommen (Deadlock-Schutz), committen aber selbst Evidence vor Phasen; andere Mutationen unverändert.
- **API:** `GET /api/v1/lockdown/status` (read-only, bounded: state/phase status/epoch/settings-summary/cooldowns, keine Secrets), `POST /api/v1/lockdown/arm` (`mode`, `reason`), `POST /api/v1/lockdown/trigger` (Confirmation+Reason+Source optional, Rate-Limit 1/min), `POST /api/v1/lockdown/clear` (Confirmation+Reason+expected_epoch); alle `s.auth`; `GET /api/v1/status` additiv `lockdown`; bestehende Routen unverändert. `/api/v1/release/emergency-stop` bleibt separat (nicht vermischen).
- **Wiring:** Engine-Start in `main.go`/`xdr.go` (Incidents/Boot-Trust), Snapshot in `state.go`, Settings-Propagation; Events/Evidence: `lockdown.trigger.intent/outcome`, `lockdown.phase.*`, `lockdown.clear.*`, `lockdown.false_positive_guard` (nur bei verworfenem Kandidaten gezählt, nicht spammend).

## 8. Packaging / Unit

`packaging/systemd/gedefense-core.service` additiv (deterministisch statt zufällig beschreibbar):
- `ReadWritePaths=/sys/bus/usb /sys/bus/thunderbolt/devices /sys/devices` (USB/TB authorized/autoprobe; **keine** neuen Caps). `/sys/devices` ist zusätzlich nötig, weil `/sys/bus/usb/devices` und `/sys/bus/thunderbolt/devices` sysfs-**Symlinks** in den Gerätebaum sind: der Kernel löst jeden per-device-`authorized`-Write nach `/sys/devices/**` auf, ein Grant nur auf den Bus-Pfad würde also EROFS liefern (fail-safe, aber real unwirksam). Der Grant ist damit bewusst breiter als die exakten Geräte; der Core schreibt weiterhin nur die allowlisteten `authorized`/`drivers_autoprobe`-Knoten, keine Capability-/AddressFamily-/Syscall-Erweiterung. Realer sysfs-Write auf Hardware ist in dieser Umgebung **NOT_TESTED** (kein root-/systemd-Zielhost in der Test-Session),
- `ReadWritePaths=-/proc/sys/kernel/kexec_load_disabled -/proc/sys/kernel/sysrq -/proc/sys/kernel/modules_disabled`,
- `ReadWritePaths=/var/lib/vgt/gedefense` (Verzeichnis für den atomaren `LOCKDOWN.state`/Engine-State; nicht nur die Datei, weil Temp-Datei + Rename im selben Dir liegen).
Keine neuen Capabilities, keine AddressFamily-/Syscall-Erweiterung; `PrivateDevices=true` bleibt (DM Phase 2). `validate-systemd.sh`/`install-smoke.sh`/`security-audit.sh` um Lockdown-Assertions (Default off, eBPF map, exakter sysfs-Grant-Satz inkl. `/sys/devices`, keine Shell) ergänzen; bestehende Anker unverändert.

## 9. Fail-Safe-/Reversibilitäts-Matrix

| Situation | Verhalten | Status |
|---|---|---|
| Default (disabled) | keine Arming, keine Core-Kommandos, keine Events | `lockdown=disabled` |
| Core nicht erreichbar | keine Phasen; Latch (falls aktiv) bleibt; Retry bounded; **kein** „enforced"-Claim | `unavailable`/`degraded` |
| Core-Restart während aktiv | eBPF-Drop endet mit Core; State-Re-Arm beim Start; Fenster dokumentiert | `re-arming`→`active` |
| USB locked + power-only | kein Block/Trigger (Lade-Kabel-DoS-Schutz), Audit-Event | `audit-only` |
| USB locked + HID/Hub | default-allow (Console), Audit | `allowed-console` |
| USB locked + Mass-Storage/Netz/Vendor | `authorized=0` + Event (optional sofort NET-Drop) | `blocked` |
| Thunderbolt neu | immer `authorized=0` (DMA), Event | `blocked` |
| Kein bpf-LSM | Zell-LSM unavailable; Netz-Drop/pidfd/Freeze/Cell-Freeze/Local-Registry bleiben | pro Phase |
| LUKS/DM, Session-Lock, Kernel-Lockdown | `unsupported:<reason>` (kein Fake) | `unsupported` |
| Evidence-Ledger down | Trigger/Clear erlaubt (Gate-exempt), Phasen ohne Intent-Evidence nicht; lautes critical Event | `degraded` |
| Clear falsche Epoch/Confirmation | ERR/403, bleibt latched | `active` |
| Panic-Modus `drop_loopback` | auch Loopback tot; Clear nur lokal (TTY/Datei/Neustart) | `isolated` |

## 10. Testplan

1. **Common:** Word-Encode/Decode + Magic/ABI-Reject + `size_of(LockdownEvent)==64` + Event-Decoder-Matrix; Fuzz optional.
2. **eBPF:** Nightly-Build Exit 0; `readelf` enthält `LOCKDOWN_STATE`, `LOCKDOWN_DROPS`, Programme; bestehende Sections/Maps unverändert; root-gated `#[ignore]`-Test lädt Objekt, schreibt/liest Map-Wort (Verifier-/Map-Existenz), SKIP non-root.
3. **Core:** State-File atomar/Re-Arm/korrupt⇒latched; Word-Write+Read-back; USB/TB-sysfs-Fake (TempDir): Policy (power-only/HID/Hub/Mass-Storage/TB), `authorized`/`autoprobe`-Writes+Verify, idempotent; UEVENT-Parser aus Rohbytes + Fake-Source-Loop; Hardening observe/write-allowlist, `modules_disabled` nie auto; Broker-SIGSTOP/SIGCONT via Fake-/proc oder injizierbare PID-Liste (bounded, kein Kill, self/pid≤4 geschützt); Kommandos: ARM/TRIGGER/CLEAR/STATUS/EVENTS/HEALTH, Idempotenz, Epoch-Mismatch, unbekannte Tokens ⇒ ERR, Antwort≤2048; keine Shell/Command.
4. **Go:** Settings v16 Default-inert/Migration/Caps; Engine-State/Latch-Persistenz inkl. korrupt⇒latched; Trigger-Matrix (Morpheus-CRITICAL ja, Trusted-Debugger/System-Canary nein, Boot-Trust NOT_SUPPORTED nein, Cooldown/Dedupe/RequireSources, MaxTargets); Evidence-first-Assertions; Clear-Auth (falsche Confirmation/Epoch ⇒ 403/409, bleibt latched); Phasen-Teilfehler ⇒ partial + kein Überclaim; API auth/replay/limits/status-bounded; Default-off erzeugt keine Requests/Events; Fake-Core/Fake-Cells.
5. **Adversarial (Reviewer):** Power-only-USB darf keinen Lockdown auslösen; HID-Console bleibt bedienbar; unlocked=audit; Epoch/Confirm-Bypass; Latch-Restart; Core-down; Ledger-down; Map-Verlust/Re-Arm; XDP/TC/egress-Fastpath OFF byte-gleich; Loopback-Erreichbarkeit im Lockdown nur mit Flag; DM/Session ehrlich unsupported; keine Attrappe in Status/UI.
6. **Gates:** `go test ./...`, `go vet`, common/core/ebpf Tests/Build, `security-audit.sh` (+Anker), `validate-systemd.sh`, `install-smoke.sh`, `node --check`; neue Dateien ≤500 Z.

## 11. Datei-Ownership / Phasen

| Task | Owner | Write-Scope | Depends |
|---|---|---|---|
| P5-T1 | Common+eBPF-Agent | `rust/gedefense-common/src/lockdown.rs` (neu) + `lib.rs` Re-Export; `rust/gedefense-ebpf/src/main.rs` (LOCKDOWN_STATE/Drop-Pfade/Counter) | Spec |
| P5-T2 | Core-Agent | `rust/gedefense-core/src/lockdown.rs` (neu) + `main.rs` (Kommandos/Threads/Status), ggf. `lockdown_uevent.rs`/`lockdown_usb.rs` (je ≤500 Z.) | T1 |
| P5-T3 | Go-Agent | `control/lockdown_settings.go`, `lockdown.go`, `lockdown_triggers.go`, `lockdown_api.go`, Tests; additive Edits `runtime_settings.go`, `fabric_settings.go`, `fabric_schema.go`, `server.go`, `xdr.go`, `state.go`, `main.go`, `security_fuzz_test.go`, `Makefile` | Spec (ABI fix) |
| P5-T4 | Packaging/Doku/Gates | `packaging/systemd/gedefense-core.service`, `scripts/security-audit.sh`, `validate-systemd.sh`, `install-smoke.sh`, `ARCHITECTURE.md`, `docs/POINT5-LOCKDOWN.md`, `docs/POINT5-PHASE1-REPORT.md` | T1–T3 |
| P5-T5 | Verifier | read-only adversarial + Gate-Läufe | T4 |

## 12. Definition of Done (Phase 1)

- eBPF-Drop (XDP/TC/egress) real implementiert + Build/readelf; Default OFF byte-gleich.
- Core: LOCKDOWN_* ABI, State-Persistenz/Re-Arm, USB/TB-Policy+uevent, Hardening-Observe/Opt-Write, Broker-SIGSTOP/SIGCONT, Events/Health, Tests; DM/Session/Kernel-Lockdown ehrlich `unsupported`.
- Go: Settings v16, Engine/Trigger/Latch/Clear, Evidence-first+Audit, API, Default inert; kein Attrappe-Status.
- Unit/Assertions/Audit/Doku/Report; adversarialer Review ohne offene FAIL; Restrisiken dokumentiert.

## 13. Umsetzungsabweichungen und Präzisierungen (Phase 1, implementiert)

Diese Sektion hält fest, wo die Implementierung von §3–§9 abweicht oder den Vertrag
präzisiert. Sie ersetzt keine der vorherigen Zusagen; jede Aussage ist durch Code,
Tests oder Gates gedeckt (Evidenz: `docs/POINT5-PHASE1-REPORT.md`).

1. **Event-Struct `reserved[24]` statt `[16]`.** `LockdownEvent` ist exakt 64 Byte
   (`LOCKDOWN_EVENT_WIRE_BYTES`, Compile-/Test-Assert), die Felder vor dem Tail
   belegen 40 Byte (seq 0, ts_ms 8, epoch 16, source/reason/phase/outcome 20..24,
   cgroup_id 24, detail_u64 32), deshalb ist der reservierte Tail 24 Byte
   (Offset 40..64). §3 nennt `[16]`; die Wire-Bytes und alle Offsets bleiben
   unverändert, der Decoder überträgt den Tail unverändert (Roundtrip-Test).
2. **EPOCH-Lebenszyklus.** Der Core erzeugt seinen Start-Epoch zufällig und bei
   **jedem** `LOCKDOWN_TRIGGER` einen neuen, garantiert verschiedenen Epoch
   (`new_epoch`). `LOCKDOWN_CLEAR` ist strikt Compare-Set auf diesen Epoch; ein
   Core-Neustart erzeugt einen neuen Start-Epoch, der Go-Latch folgt im aktiven
   Zustand dem Kernel-Epoch (Status ehrlich), der persistierte Latch bleibt.
3. **STATUS-Phasen und `degraded`.** `phases` enthält nur verifizierte Phasen;
   die Go-dispatchte Zellphase erscheint als `cells=delegated` (kein Fake-Apply im
   Core). `state=degraded` wird gesetzt bei fehlgeschlagener/partieller Phase, bei
   fehlgeschlagenem Word-Read-back, bei fehlgeschlagener Re-Arm-Verifikation und bei
   korruptem State-File (Latch bleibt aktiv). `degraded` behauptet nie „isoliert".
4. **Loopback-Recoverability / Panik-Modus `drop_loopback`.** `ALLOW_LOOPBACK` ist
   Default **an**; der cgroup-Egress-Fastpath lässt nur Pakete passieren, deren
   **beide** L3-Endpunkte nachweislich Loopback sind (`127.0.0.0/8`, `::1`), ein
   Parse-Fehler wird im Lockdown gedroppt (fail-closed). `drop_loopback=true`
   (Settings, Default aus) ist der Panik-Modus: dann ist auch Loopback tot und ein
   Clear ist nur noch lokal (TTY/Datei-Token/Neustart) möglich; der Core-IPC-Socket
   ist ohnehin lokal (AF_UNIX unter `/run/vgt-gedefense`).
5. **USB-Power-only/HID-Console-Heuristik.** `is_power_only` = Device-Class 0,
   höchstens eine Konfiguration, höchstens ein Interface, alle Interface-Klassen 0
   und kein gebundener Treiber ⇒ Lade-Kabel/Port, **kein** Block, **kein** Trigger.
   HID/Hub werden über Device-Class (`0x03`/`0x09`) **oder** Interface-Class erkannt
   und bleiben als lokale Console erlaubt; alles andere wird bei `locked` geblockt.
   Eine „Kinder-vor-Hub“-Reihenfolge ist **nicht implementiert und nicht nötig**:
   Hubs werden policy-seitig nie de-authorisiert (Hub = Console-Allow), daher muss
   kein Kind vor seinem Hub gesperrt werden; Geräte hinter einem Hub werden beim
   Scan einzeln bewertet. Das ist eine bounded Heuristik (§6.2), keine Garantie über
   Vendor-Sonderfälle - im `unlocked`-Modus bleibt sie audit-only.
6. **uevent ist verlustbehaftet.** Der Monitor liest AF_NETLINK-Gruppe 1 mit
   `SO_RCVBUF` 256 KiB (`UEVENT_RCVBUF`); eine einzelne uevent-Nachricht wird auf
   `UEVENT_RECV_MAX` = 2048 Byte begrenzt. `ENOBUFS` löst einen bounded
   **Rescan** der aktuellen Geräte aus. Zwischen Verlust und Rescan können Add/
   Remove-Ereignisse fehlen; der Rescan stellt die Policy für die sichtbaren Geräte
   wieder her, rekonstruiert aber keine Audit-Events. Der Verlust ist damit
   fail-closed für Geräte, aber nicht event-vollständig.
7. **USB-Auto-Drop zeigt kurz `armed` + `DROP_ALL`.** Der Uevent-Thread schreibt bei
   `auto_network_drop` das DROP-Wort unmittelbar (Sekundenbruchteile), während der
   Core-Latch noch `Armed` ist; erst der Go-Poll (10 s) übernimmt und latcht
   `active`. Der Status kann in diesem Fenster ehrlich „armed + DROP_ALL, noch nicht
   active" zeigen; es wird kein vorschneller Isolation-Claim erzeugt.
8. **Core-Crash-Fenster / Re-Arm.** Es gibt kein Map-Pinning: mit dem Core-Prozess
   enden eBPF-Programme und Maps, der Drop fällt also aus (dokumentierte
   Fail-open-Grenze). Der State-File-Re-Arm läuft beim Start **vor** IPC-Ready und
   wendet die persistierten Phasen erneut mit Read-back an; scheitert eine Phase
   oder die Word-Verifikation, bleibt der Zustand `degraded` gelatcht. Ein korruptes
   State-File wird nicht als „off" interpretiert, sondern gelatcht.
9. **Stale-Attach (TC alt + XDP neu).** Der Core hängt seine Programme beim Start
   neu an (XDP-Ladder native→generic→TC, eigenes Map-Wort) und meldet in
   `INGRESS_HEALTH`/Startzeile den tatsächlich aktiven Ingress-Modus. Er enumeriert
   oder detacht **keine** fremden/alten Filter früherer Core-Generationen; ein
   solcher Alt-Filter kann bis zur Qdisc-/Interface-Neuerstellung bestehen bleiben.
   `LOCKDOWN_STATUS` belegt daher nur das **eigene** Wort per Array-Read-back, nicht
   die Abwesenheit anderer Programme - Restrisiko, kein Full-Stack-Claim.
10. **DM/LUKS, Session-Lock, Kernel-Lockdown-Toggle sind `unsupported`.** Phase 1
    hat kein `/dev/mapper` (PrivateDevices), keinen D-Bus und kann den
    Boot-Parameter-Kernel-Lockdown nicht umschalten. Der Core antwortet
    `unsupported:dm:no-device-mapper`, `unsupported:sessions:no-dbus-session-lock`
    bzw. `unsupported:kernel-lockdown:boot-parameter-immutable`; Go zeigt diese
    Phasen sichtbar als nicht unterstützt, nie als applied.
11. **Broker-Freeze ist `frozen-not-locked`.** Nur `SIGSTOP`/`SIGCONT` über pidfd mit
    Identitätsprüfung (PID + Starttime), feste Name-Liste, bounded `/proc`-Scan,
    TTL 300 s beim Resume; es gibt **kein** Zeroize/„locked"-Claim des
    Broker-Speichers. Ein Clear setzt exakt die gemerkten PIDs fort.
12. **`modules_disabled` wird nie automatisch gesetzt.** Der automatische Trigger
    schreibt nur die opt-in Allowlist (`kexec_load_disabled=1`, `sysrq=0`) mit
    Read-back; `modules_disabled` wird nur beobachtet. Nur der explizite
    Operator-Einzelbefehl `LOCKDOWN_PHASE hardening on` darf es setzen; ein Clear
    meldet dafür ehrlich `unsupported:irreversible-until-reboot`.
13. **Zell-Reverse hängt an der Transaction-History.** Die Zell-Freeze-Transaktions-
    IDs werden im Latch-Dokument persistiert, damit ein Clear sie über dieselbe
    TransactionEngine zurückrollen kann. Wurde die History gepruned/verloren, schlägt
    `Reverse` fehl; das erzeugt ein **lautes** kritisches Event
    `lockdown.cells.resume_failed` + Evidence und lässt die Zellen isoliert (kein
    stilles De-Isolieren). Parser-Zellen werden bei Incident **geburned**, nicht
    eingefroren (`BurnForIncident`).
14. **Evidence-Gate-Ausnahme für Trigger/Clear.** `/api/v1/lockdown/trigger` und
    `/api/v1/lockdown/clear` sind vom Evidence-Gate ausgenommen (Deadlock-Schutz),
    committen aber selbst vor den Phasen Intent-Evidence. Fehlt das Ledger ganz,
    meldet der Status `evidence=unavailable`/`degraded` und die Isolation-Phasen
    laufen nicht (kein Claim). Alle anderen Mutationen bleiben unverändert gegated.
15. **Settings-Migration und Inert-Default.** `fabricSettingsVersion` steigt auf
    **16**; ein v15-Dokument wird mit `lockdown.enabled=false`, `auto_arm=false` und
    Migrationshinweis versehen. Ein Upgrade sendet ohne Operator-Aktivierung kein
    `LOCKDOWN_*`-Kommando, pollt keine Duress-Datei und erzeugt keine Events.
16. **Unit-Grants sind exakt und additiv.** Zusätzlich beschreibbar werden die
    USB/TB-sysfs-Knoten samt `/sys/devices` (Symlink-Ziele der Bus-Pfade, sonst
    EROFS, s. §8), die drei opt-in Hardening-Sysctls und das State-Verzeichnis
    `/var/lib/vgt/gedefense` (1770 root:gedefense, atomarer `LOCKDOWN.state` +
    Engine-State); der sysfs-RW-Satz ist per Gate auf genau
    `/sys/bus/usb`, `/sys/bus/thunderbolt/devices`, `/sys/devices` und den
    bestehenden `/sys/fs/bpf`-Mount fixiert. `CapabilityBoundingSet`,
    `AmbientCapabilities`, `RestrictAddressFamilies` und `SystemCallFilter`
    bleiben byte-identisch. **Restrisiko/NOT_TESTED:** der `/sys/devices`-Grant ist
    bewusst breiter als die Bus-Pfade; der reale Schreibzugriff auf Hardware-sysfs
    (root + systemd) ist in dieser Umgebung nicht getestet.
