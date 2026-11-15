# POINT 3 — Phase-1-Report: Per-Cgroup-Egress & Beacon-Detektion

**Stand:** 2026-11-15 · **Release:** GeDefense V6 (`6.0.0`)
**Status:** IMPLEMENTIERT (Phase 1), Default nach Upgrade **off** (keine
Verhaltensänderung). Verbindliche ABI/Spezifikation: `docs/POINT3-EGRESS-BEACON.md`
(§13: Umsetzungsabweichungen/Präzisierungen). Dieser Bericht fasst Scope, Architektur,
Dateien, Verifikation, Review-Ergebnis und Restrisiken zusammen.

## 1. Scope Phase 1

- **Kernel:** opt-in Default-Deny-/Monitor-Egress pro Cgroup über den bestehenden
  `cgroup_skb/egress`-Hook, Per-Cell-Modi/Flags, Allow-/Block-/Resolver-LPMs,
  Pflicht-Veto, DNS/DoT-Pinning, aggregierte Flow-Telemetrie (kein Per-Paket-Dump).
- **Rust-Core:** Map-Handles/Attach, Seed der Pflicht-Veto-Liste, vollständig validierte
  `STYX_*`-Kommandos, Flow-Event-Text-Wire, Health-Zähler, Epoch/Resync-Vertrag.
- **Go-Control (unprivilegiert):** VGT3-Client + strikter Parser + Capability-Gate,
  Beacon-/Exfil-Detektor, XDR-/CellGuard-Anbindung, Settings-Namespace + Policy-Syncer,
  Status-/Beacon-API.
- **Nicht Phase 1:** rx-Zähler/ingress, DNS-Attribution/Direct-IP-Signal (bleibt
  `unknown`, kein Fake), DoH-Attribution, Per-Socket-Tracking, UI-Panels, Cross-Host-Witness.
- **Leitplanke:** Default aus; `monitor` → `enforce` ist Operator-Entscheidung; eBPF-
  Shortcut bei `mode=off` führt den byte-identischen 5.2.0-Legacy-Pfad aus.

## 2. Architektur (Kurzfassung)

**ABI-1 (Wire):** `FlowEvent` ist `repr(C)`, native endian, exakt **104 Byte**
(`STYX_FLOW_EVENT_WIRE_BYTES = 104`) mit `cgroup_id/ts_ns/tx/rx/pid/uid/dst/src/dst_port/
src_port/packets/proto/family/direction/tcp_flags/verdict/reserved/comm`; Decoder
`decode_styx_flow_event` verwirft jeden Producer-unmöglichen Record (Reject, nie Reparatur).

**ABI-2 (Maps):** `CELL_EGRESS_MODE`, `CELL_EGRESS_ALLOW_V4/V6`, `STYX_ALLOW_GLOBAL_V4/V6`,
`STYX_BLOCK_V4/V6`, `STYX_RESOLVER_V4/V6`, `STYX_GLOBAL` (gepacktes
`epoch|flags<<32|mode<<40`), `STYX_RESOLVED` (Positiv-Cache), `FLOW_AGG_V4/V6`
(Fenster-Aggregation), `FLOW_EVENTS` (4-MiB-RingBuf) + sechs PerCPU-Health-Zähler.

**ABI-3 (VGT3):** `STYX_VERSION`, `STYX_EPOCH`, `STYX_GLOBAL`, `STYX_MODE_SET/DEL`,
`STYX_ALLOW_ADD/DEL`, `STYX_BLOCK_ADD/DEL`, `STYX_RESOLVER_ADD/DEL`,
`STYX_FLOW_EVENTS`, `STYX_FLOW_HEALTH`; unbekannt ⇒ `ERR unknown command` ⇒ Go
`ErrStyxUnavailable` (Capability-Fakt, kein XDR-Ausfall).

**Entscheidungspipeline:** (1) `STYX_GLOBAL`-Lookup, off ⇒ Legacy-Pfad; (2) L3-Parse
(fail-closed bei enforce); (3) IPv4-mapped/-compatible-Normalisierung; (4) Cgroup-
Attribution mit begrenztem Ancestor-Walk + Epoch-Cache; (5) Flow-Aggregation/Emit;
(6) Pflicht-Veto; (7) DNS/DoT-Pinning; (8) Allow-Reihenfolge → Legacy-Blocklist →
Loopback → Default. Rückgabe bleibt `0 = DROP, 1 = PASS`.

**Fail-Closed:** Pflicht-Veto-Seed fatal beim Core-Start; Map-/Proto-Fehler ⇒ `ERR` +
Go-Retry/Degraded; Ring-Drops sind Sichtbarkeitsverlust (`degraded`), nie ein „keine
Beacons“-Claim; aktive Response nur nach Evidence und nie in `degraded`/`observe`.

## 3. Datei-Inventar (Zeilen, am 2026-11-15 gemessen)

**Rust-Common**
- `rust/gedefense-common/src/styx_flow.rs` — 496 (ABI-1, Decoder, Tests)
- `rust/gedefense-common/src/bin/flow_event_fuzz.rs` — 250 · `src/lib.rs` — 392
  (Seed-Corpus/Fixpunkt bzw. Modul-/Re-Export-Verdrahtung)

**Rust-Core**
- `rust/gedefense-core/src/styx_flow.rs` — 500 (Validierung, LPM-Keys, Text-Wire)
- `rust/gedefense-core/src/main.rs` — 3.391 (Map-Handles, Seed, Dispatch, Flow-Drain)

**eBPF**
- `rust/gedefense-ebpf/src/main.rs` — 2.133 (einzige Program-Datei; `cgroup_skb/egress`,
  Maps, Pipeline, Flow-Aggregation)

**Go-Control**
- `control/coreipc.go` — 1.792 (u. a. `CoreStyxFlowEvent`, `parseCoreStyxFlowEvents`)
- `control/styx_settings.go` — 239 · `control/styx_policy_plan.go` — 303
- `control/styx_syncer.go` — 403 · `control/styx_syncer_status.go` — 189
- `control/styx_policy.go` — 353 · `control/styx_beacon.go` — 499
- `control/xdr.go` — 1.959 · `control/runtime_settings.go` — 1.146
- `control/fabric_settings.go` — 916 · `control/fabric_schema.go` — 691
- `control/server.go` — 3.626 (u. a. `GET /api/v1/styx/status`, `/api/v1/styx/beacons`)

**Tests (Go, relevant)**
- `control/coreipc_styx_test.go` — 366 · `control/styx_settings_test.go` — 281
- `control/styx_syncer_test.go` — 474 · `control/styx_xdr_test.go` — 245
- `control/styx_api_test.go` — 257 · `control/styx_beacon_test.go` — 482
- `control/styx_beacon_exfil_test.go` — 221 (Phase-1-/T7-Delta-/Kumulativ-Tests)
  · `control/styx_egress_test.go` — 151

**Doku/Gates**
- `docs/POINT3-EGRESS-BEACON.md` — 402 · `ARCHITECTURE.md` §3.34
- `scripts/security-audit.sh` — 917 (neuer Point-3-Ankerblock + ELF-Gate)

## 4. Test-/Gate-Evidenz (selbst ausgeführt, WSL, 2026-11-15)

| Gate | Kommando | Ergebnis |
|---|---|---|
| Rust-Common/-Core | `cargo +1.97.1 test --offline --locked -p gedefense-common -p gedefense-core` | **Exit 0**; common 23+1+1 = **25 passed**, core **69 passed**, 0 failed, 0 doc-tests |
| eBPF (Nightly, Verifier) | `cargo +nightly-2026-07-16 build --offline --locked -p gedefense-ebpf --release --target bpfel-unknown-none -Z build-std=core` | **Exit 0**; `dist/gedefense-ebpf` 68.376 B; readelf: `lsm/socket_create` + `cgroup_skb/egress`, Map-Symbole `CELL_EGRESS_MODE`/`FLOW_EVENTS`/`STYX_GLOBAL`/`STYX_RESOLVED`/`FLOW_AGG_V4` |
| Go-Vet | `cd control && go vet ./...` | **Exit 0** |
| Go-Tests | `go test -count=1 -timeout 1800s ./...` | **Exit 0** (`ok … 235.800s`); Beleglauf `-v`: **935 PASS / 0 FAIL / 2 SKIP** (928 deklarierte Test-Funktionen) |
| Go-Race (StyX-Subset) | `go test -race -count=1 -run 'Styx\|Beacon\|Settings\|XDR' ./...` | **Exit 0** (`ok … 3.866s`); Beleglauf `-v`: **90 PASS / 0 FAIL / 0 SKIP** (89 deklarierte Tests im Subset) |
| Security-Audit | `bash scripts/security-audit.sh` | **Exit 0**, `SECURITY AUDIT PASS`, 22 PASS-Prüfungen (inkl. Point-3-Anker + ELF-Gate) |
| JS-Syntax | `node --check control/web/*.js` | **Exit 0** (19 Dateien) |
| Installer-Smoke | `bash packaging/tests/install-smoke.sh` | **Exit 0**, 48 passed / 0 failed / 5 dokumentierte `NOT_TESTED` |
| Flaky-Fix (separater Fix) | `go test -run '^TestInitFeedSigningProvisioning$' -count=500 .` | **Exit 0**, 0 FAIL (vorher reproduzierbar 11/200 FAIL) |

Hinweise: Der Audit prüft die Go-StyX-Anker über alle `control/styx_*.go` ohne
`_test.go` (nach dem Split nötig, Anker-Texte unverändert). Kein Live-Kernel-Boot,
kein Netzwerkzugriff, kein Git-Push/Commit/Tag/Release.

## 5. P3-T7-Review und Fixes

Read-only-adversarialer Review: **PARTIAL, kein FAIL**. Behoben und testbelegt:

1. **Signal-2-Fenster-Deltas:** Der Kernel emittiert `tx_bytes`/`packets` als
   Fenster-Delta (FLOW_AGG-Reset nach jedem Emit). Go summiert saturierend kumulativ
   (`saturatingAdd` statt `max()`), Schwellen gelten auf der Flow-Gesamtsumme;
   Tests: `TestStyxBeaconSlowExfilCumulativeDeltas`,
   `TestStyxBeaconExfilAsymmetryCumulativeThresholds`,
   `TestStyxBeaconSaturatingVolumeAccounting`.
2. **SensorState-Honesty:** `enabled=true, mode=off` ⇒ Sensor-Zustand `off` (nicht
   `active`), `RecordFlows` ignoriert Flows bei off; Tests
   `TestStyxBeaconModeOffIsNotActive`, `TestStyxBeaconSettingsProjectModeOffHonestly`.
3. **Inerte Policies:** `enabled=true, mode=off` mit PerCell-Modi≠off,
   Allowlist oder Resolvern wird fail-visible abgelehnt („styX mode=off with
   per-cell/allowlist rules has no effect; set mode=monitor or enforce“);
   Test `TestStyxFabricSettingsRejectsInertModeOffPolicy`.
4. **Flaky Feed-Signing:** `TrimSpace` über rohe 32-Byte-Key-Dateien entfernt
   (`feedSigningKeyFileBytes` strippt nur optional einen trailing `\n`/`\r\n`);
   500-Lauf ohne FAIL.
5. **Datei-Split (VGT ≤500 Zeilen):** siehe Inventar; alle genannten Dateien ≤500.
6. **Signal-2-Ehrlichkeit (Refinement nach der T7-Nachprüfung):** Die
   Produktionsprojektion setzt `RxObservationAvailable=false` (Phase 1 hat keine
   Ingress-/rx-Telemetrie) und `DNSObservationAvailable=false`. Ohne
   Canary-Korrelation bleibt die Asymmetrie `unknown` — kein Score, kein Incident,
   keine Ratio-Behauptung; auch zufällig vorhandene rx-Bytes werden nicht verwendet,
   solange die Capability false ist. Mit Canary-Korrelation
   (`KD.LINUX.CANARY_ACCESS` im 900-s-Lookback) und kumulativ `tx >= 1 MiB &&
   samples >= 8` ⇒ Score 200, RuleID `STYX.EXFIL.ASYMMETRY`, Summary „rx telemetry
   unavailable; volume+canary correlation, no ratio claim"; Kombination mit
   Periodizität ⇒ 250/contain. Der rx-bekannte Ratio-Pfad bleibt Phase 2. Tests:
   `TestStyxBeaconPhase1VolumeOnlyStaysUnknown` (unknown), `...CanaryVolumeScore`
   (200 + Ratio-Claim-Verbot), `...CanaryVolumeCombinationContain` (250/contain),
   `TestStyxBeaconProductionSettingsKeepPhase1CapabilitiesOff`. Damit ist die von T7
   gemeldete Alert-Fatigue-/Attrappen-Gefahr mitigiert.

## 6. Restrisiken / Phasengrenzen

- **IPv6-Ext-Header >4 Hops / Nicht-Erst-Fragmente ohne L4:** Ports = 0 ⇒ DNS-Pinning
  (53/853) kann übersprungen werden; IP-Policy/Veto/Blocklist/Telemetrie greifen weiter.
- **Core-Restart-Epoch-Fenster ≤10 s:** Sync-Status kann kurz veraltet sein; der neue
  Core startet immer mit `STYX_GLOBAL=OFF` (fail-safe). **Maps ungepinnt** ⇒
  Core-Neustart leert sie; Control-Restart bei disabled Settings kann Alt-PerCell-
  Einträge nicht enumerieren (nur fail-safe `STYX_GLOBAL(0,0)`).
- **Pflicht-Veto** per authentisiertem `STYX_BLOCK_DEL` löschbar; die Go-Policy-Schicht
  hat keinen Aufrufpfad (Grenze des privilegierten IPC-Vertrauensmodells).
- **Positiv-Cache** kann neue höhere Ancestor-Policy bis Epoch/Eviction verzögern;
  Negativ-Cache wird bewusst nicht geführt.
- **Kein Live-Kernel-/Verifier-Load-Test:** verifiziert sind Nightly-Build (Verifier-
  Gate) und readelf-Prüfung; Attach/Load auf echtem Kernel bleibt Integrationsschritt.
  DoH-443 ist kernelseitig nicht attribuierbar; DNS-Attribution/rx-Bytes bleiben Phase 2.
- **Bekannte Grenzen:** cell-v6-Allow ohne Port/Proto, /0../3-CIDRs und beliebige
  Port-Ranges abgelehnt, Solicited-Node-Multicast kann vom ND-Veto erfasst werden,
  `BLOCKLIST`-Drops bleiben in allen Modi fail-closed; volumenstarke Exfil wird in
  Phase 1 nur mit Canary-Evidenz oder über Periodizität erkannt (nie Ratio-Claim).

## 7. Nächster Schritt

**Punkt 1 — Titan + eBPF-LSM `bprm_check_security`/`mmap_file`** (Exec-/mmap-Gate);
kein weiterer Phase-1-Fix offen, P3-T7-Restrisiken dokumentiert/akzeptiert.
Kein Git-Push/Commit/Tag/Release in dieser Arbeitssitzung.
