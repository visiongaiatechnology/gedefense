# POINT 4 — Out-of-Band Witness: Phase-1-Implementierungs- und Verifikationsbericht

**Stand:** 2026-11-15 · **Release:** GeDefense V6 (`6.0.0`) · **Status:** Phase 1 implementiert und gate-verifiziert
**Vertrag:** `docs/POINT4-WITNESS.md` (§3–§8 Checkpoint/Client/Outbox/Export/Import, §11 DoD, §13 Abweichungen)
**Deployment:** **nichts deployt**; Default **off** (`witness.enabled=false`, `mode=off`, Settings-Schema v17); kein Git-Push/Commit/Tag/Release.

## 1. Scope (Phase 1)

Umgesetzt: signierte, privacy-beschränkte Ledger-Checkpoints (Ledger-Epoch/Sequenz/
Head/Boot-Posture-/Policy-/Sensor-Status), gehärteter HTTPS-Client (Mode A:
Port 443, kein Proxy, keine Redirects, SPKI-/Receipt-Pinning, optional mTLS, Challenge),
AEAD-verschlüsselte bounded Outbox, signierte Witness-Receipts mit Monotonie,
Equivocation-/Rollback-Erkennung, Air-Gapped Export/Import (`vgtw1`, Datei), Settings v17
(Default off) und read-only Status/API.

Bewusst **nicht** Phase 1: externer Witness-Server (Phase 2), QR-Encoding (Phase 2),
frischer TPM-Quote/TPM-Key-Binding (Zielhost ohne TPM/UEFI ⇒ ehrlich `quote_kind="none"`,
`key_binding="software"`), UI-Panels.

## 2. Architektur

```text
EvidenceLedger ──Checkpoint()/Head() atomar──> signierter Checkpoint (epoch,seq,head,fp)
      ▲                                              │
      │                        ┌─────────────────────┴──────────────────────┐
      │        Modus A: HTTPS-Client (Pin, Port 443, kein Proxy)      Modus B: vgtw1 Datei/QR
      │                        │ challenge + checkpoint                     │
      │                Witness (extern, Phase 2) ──signiertes Receipt──┐   │
      │                        │                                      ▼   │
      │                Outbox (AEAD, bounded, fail-closed) ──> Ack-Baseline (AEAD)
      │                        │
      └────── Equivocation/Rollback-Detektor ──> Evidence/Incident ──> optional P5-Lockdown
```

Privilege Split: unprivilegiert im Go-Control; der Ledger-Key verlässt den Prozess nicht und
der Ledger signiert nur über den `WitnessCheckpointSigner()`-Callback. Keine neue Unit,
keine Capability-/AddressFamily-/Syscall-Erweiterung; der Witness-Server ist extern.

## 3. Datei-Inventar (P4)

| Bereich | Dateien (Zeilen) |
|---|---|
| Ledger/Checkpoint (P4-T1) | `control/witness_checkpoint.go` (467), `witness_checkpoint_test.go` (494); additiv `evidence_ledger.go` (Epoch/`Checkpoint()`/`Head()`/Fingerprint/Signer), `evidence_rotation.go` (`epoch+1`) |
| Engine/Client (P4-T2) | `witness.go` (472), `witness_client.go` (454), `witness_outbox.go` (353), `witness_export.go` (497), `witness_engine.go` (480), `witness_settings.go` (284), `witness_api.go` (361) |
| Tests (P4-T1/T2) | `witness_test.go` (419), `witness_client_test.go` (470), `witness_outbox_test.go` (187), `witness_settings_test.go` (265), `witness_api_test.go` (414) |
| Additive Edits | `runtime_settings.go` (Schema v17/Migration v16→v17), `fabric_settings.go`, `fabric_schema.go` (Modul `witness`), `server.go` (6 Routen + Snapshot), `state.go`, `main.go` (Engine/Start, `<stateDir>/witness/`), `lockdown_settings.go`/`lockdown_triggers.go` (additiver Trigger), `security_fuzz_test.go`/`Makefile` (Fuzz-Targets) |
| Gates/Doku (P4-T3) | `scripts/security-audit.sh` (P4-Anker), `scripts/validate-systemd.sh`, `packaging/tests/install-smoke.sh`, `docs/POINT4-WITNESS.md` (§12/§13), `ARCHITECTURE.md` (§3.38), dieser Report |

Alle neuen Go-Dateien sind ≤500 Zeilen (VGT-Regel). Durch P4-T3 wurden **keine**
Go-/Rust-Code- oder Testdateien verändert (nur Skripte/Doku).

## 4. Test-Evidenz (nur selbst ausgeführt, WSL Ubuntu 24.04, uid 1000)

- `rustup run 1.97.1 cargo test --offline --locked --manifest-path rust/Cargo.toml
  -p gedefense-common -p gedefense-core -p gedefense-cell-helper` → **Exit 0**:
  **191 passed / 0 failed / 1 root-gated ignored** (helper 40 + 1 ignored, common
  38 lib + 2 Bin-Tests = 40, core 111, 0 doc-tests).
- eBPF-Nightly-Build (`nightly-2026-07-16`, `bpfel-unknown-none`, `-Z build-std=core`)
  → **Exit 0**; `dist/gedefense-ebpf` 112.176 B
  (`sha256 c4ba4ca9b1229bd22e2fa02e64043e3801f768290b003957a5255de0151897d5`);
  `readelf` enthält `lsm/socket_create`, `lsm/bprm_check_security`, `lsm/mmap_file`,
  `cgroup_skb/egress`, `classifier`, `xdp` und die unveränderten P1/P3/P5-Symbole
  (die bpf-linker-LLVM-Warnung ändert Exit 0 und Objekt nicht).
- `cd control && go vet ./...` → **Exit 0**; `go test -count=1 -timeout 1800s ./...`
  → **Exit 0** (`ok … 171.752s`, keine FAIL-Zeile); `go test -race -count=1
  -run 'Witness|Evidence' ./...` → **Exit 0** (`-v`-Beleglauf: **76 PASS / 0 FAIL /
  0 SKIP**; Witness-Testfunktionen `^TestWitness`: **38 PASS / 0 FAIL**); `node --check
  control/web/*.js` → **Exit 0** (19 Dateien).
- `bash scripts/security-audit.sh` → **Exit 0**, `SECURITY AUDIT PASS`, **30
  PASS-Prüfungen** (neuer Point-4-Block; bestehende P1/P2/P3/P5-Anker unverändert).
- `bash packaging/tests/install-smoke.sh` → **Exit 0**, **71 passed / 0 failed**
  (6 dokumentierte NOT_TESTED); `bash scripts/validate-systemd.sh` → **Exit 0**
  (isoliertes Verify-Root, inkl. POINT-4-Grenzen).

## 5. Checkpoint+Receipt-Matrix (Phase 1)

| Fall | Checkpoint | Receipt/Ack | Ergebnis |
|---|---|---|---|
| Default off | keiner | keiner | 0 Requests/Exports/Events, Status `disabled` |
| Rotation (`epoch+1`) | neuer Checkpoint, höhere Epoch | gültig | **kein** Alarm; Ack-Baseline fortschreiben |
| Fork (gleiche `(epoch,seq)`, anderer Head) | beobachtet | — | Critical-Evidence/Incident `witness.equivocation` (fork) |
| Rollback (niedrigere `(epoch,seq)`) | beobachtet/importiert | — | Equivocation (rollback) + Import-Reject |
| Replay/ältere `witness_seq` | – | `<=` Baseline | Reject `witness.import_rejected`, keine Ack-Persistenz |
| Falscher Pin/Key/Signatur | – | Signatur fail | Reject (permanent), kein Retry-Sturm |
| Outbox voll/korrupt | **keiner** (fail-closed) | – | `degraded`, Event `witness.outbox_full` |
| Netz unreachable | queued | keins | bounded Retry/Backoff, `degraded`, **kein** Lockdown |
| Ledger quarantän | verweigert | – | `unavailable`, kein Claim |

## 6. Operations-Runbook

**Enable (Operator):** `GET /api/v1/settings/witness` (Revision lesen) →
`PUT /api/v1/settings/witness` mit `{"expected_revision":N,"settings":{…}}`
(Bearer + `X-VGT-Request-ID`). Mode `http`: `endpoint` = absolutes `https://…:443`,
mindestens ein Pin (`pinned_server_spki` 64 Hex **oder** `pinned_server_key_file`
0600); Mode `export`: air-gapped, kein Endpoint/Pin. Default bleibt `off`; eine
ungültige Konfiguration wird reject-not-repair abgelehnt.

**Endpoint/Pin/mTLS:** SPKI-Pin = Hex von SHA-256(`cert.RawSubjectPublicKeyInfo`);
Receipt-Pin = Ed25519-Pubkey (32 B raw oder base64, Datei 0600); optional
`client_cert_file`+`client_key_file` (0600) für mTLS, `auth_token_file` (0600) für
Bearer. Kein Env-Proxy, keine Redirects, Response-Limit 64 KiB.

**Checkpoint/Push:** `POST /api/v1/witness/checkpoint` (Operator-Trigger) bzw.
Ticker (`checkpoint_interval_seconds`, Default 300); `POST /api/v1/witness/push`
mit `{"confirmation":"PUSH WITNESS"}` (eigenes Rate-Budget). Status:
`GET /api/v1/witness/status` (`wired/healthy/degraded`, `last_ack`, `outbox`,
`equivocation`, `quote_kind`, `key_binding`).

**Outbox:** bounded via `outbox_max_bytes`/`outbox_max_entries`; `outbox.full=true`
⇒ fail-closed. Reparatur nur durch Operator (Witness erreichbar machen oder Grenzen
bewusst anheben); das Audit-Gate verlangt dabei die unveränderte Evidence-Kette.

**Export/Import (Modus B):** `GET /api/v1/witness/export` → JSON + `vgtw1:<base64url>`
(≤2 KiB) auf Offline-Medium; nach Offline-Verifikation (Schema/Signatur/Pubkey-FP/
`(epoch,seq)`-Monotonie) das signierte Receipt per `POST /api/v1/witness/import`
zurückführen. **Nach Control-Restart zuerst exportieren**, dann importieren
(die `checkpoint_id`-Bindung ist prozesslokal).

**Equivocation-Reaktion:** Status `equivocation=true` + Incident prüfen; Ledger
`Verify()`/Rotation/Backup forensisch sichern; **kein** Löschen. Optionaler
P5-Lockdown nur mit `witness.trigger_lockdown_on_equivocation=true` **und**
`lockdown.trigger_witness_equivocation=true`; Clear über den P5-`expected_epoch`-Pfad.
Unerreichbarkeit ist keine Equivocation.

## 7. Restrisiken

- Kein externer Witness-Server im Repo (Phase 2): die Ferne des Zeugen ist organisatorisch,
  nicht durch GeDefense garantiert; in Phase 1 nur `httptest`-Fakes als Beleg.
- Kein TPM: `quote_kind="none"`/`key_binding="software"`; der Checkpoint belegt nur
  „gleiche Boot-Posture wie zuletzt gesehen" (Boot-Time-Snapshot-Digest), keine frische Quote.
- Import-`checkpoint_id`-Bindung ist prozesslokal (nach Restart Export nötig);
  `require_ack` ist Phase 1 immer wirksam.
- Rotation ist kein Alarm, aber ein **gleichzeitiger** Fork über eine Rotation hinweg wird
  als neuer Zustand akzeptiert (Epoch-Fortschritt ist legitim); Cross-Epoch-Fork-Erkennung
  ist Phase 2. Outbox-/Ack-Korruption ist fail-closed, aber erfordert Operator-Eingriff.
- **Rotation-Crashfenster (eng):** ein Crash zwischen dem Rename der frischen Chain und dem
  durable geschriebenen `epoch+1`-Checkpoint lässt den Ledger **fail-closed quarantänisiert**
  (kein Auto-Complete, Appends/Checkpoints verweigert). Recovery ist ein Operator-Pfad:
  Archiv/Backup prüfen, Rotation bewusst erneut ausführen, Epoch **nicht zurücksetzen**
  (Epoch-Regress würde für einen Zeugen wie Rollback aussehen). P4-T1 hat Code-Kommentar und
  Test dazu präzisiert; das enge Fenster bleibt als Restrisiko dokumentiert.
- Kein Live-Betrieb: keine echte mTLS-Zertifikatskette, kein echter Witness-Endpoint,
  kein systemd-Live-Start in dieser Umgebung.

## 8. NOT_TESTED (ehrliche Grenzen)

- **Echter TPM2-Quote mit Nonce / TPM-Key-Binding** (Zielhost ohne TPM/UEFI; kein TPM-Code
  im Repo) — nicht getestet und nicht behauptet.
- **Echter externer Witness-Server** (HTTPS, Persistenz, Quorum/Rotation) — Phase 2.
- **mTLS mit echtem Zertifikat/CA und echtes SPKI-Pinning gegen einen produktiven Server** —
  Client-Pfad unit-getestet, reale Kette NOT_TESTED.
- **Live-systemd-Betrieb** (Control-Unit + Settings v17 auf Zielhost, realer Netzausfall/
  `degraded`) und echte QR-Größe für `vgtw1` (Phase 2).

## 9. Nächster Schritt

**Finales Gesamt-Review P1–P5 + Deployment-Planung** (Reihenfolge 3→1→2→5→4 abgeschlossen;
Review read-only, danach Operator-Deployment-Entscheidung). Kein GitHub-Push/Commit/Tag/Release,
kein Deploy durch diese Sitzung; Änderungen bleiben im Arbeitsbaum.
