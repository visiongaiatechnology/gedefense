# POINT 4 — Out-of-Band Witness-Attestation („Externer Zeuge")

**Status:** IMPLEMENTIERT (Phase 1) · Stand 2026-11-15 · GeDefense V6 (`6.0.0`)
**Umsetzung:** P4-T1–P4-T3 im Arbeitsbaum; Default nach Upgrade **off** (`witness.enabled=false`, `mode=off`, Settings-Schema **v17**); **nichts deployt**, kein GitHub-Push, kein Commit/Tag/Release. Evidenz/Grenzen/Runbook: `docs/POINT4-PHASE1-REPORT.md`.
**Review-Regel:** Verbindlicher Vertrag zwischen EvidenceLedger, Witness-Client/Outbox, Settings/API und Doku/Tests. ABI-Änderungen zuerst hier.

## 0. Ausgangsbefund (Recon, evidenzbasiert)

- **EvidenceLedger real:** hash-verkettete, Ed25519-signierte Append-Only-Records (`.jsonl`), AEAD-Head-Checkpoint (`.head`: `sequence`,`head_hash`), `Status()`/`Verify()`/`Rotate()`/Budget; Key `evidence.ed25519` + `.pub`; **kein Witness-API, kein Fingerprint-Helfer, kein Outbox**.
- **Kritisch: Rotation setzt die Sequenz auf 0/1 zurück** (`evidence_rotation.go`). Ein Witness, der nur `sequence` monoton prüft, würde eine **legitime Rotation als Rollback/Equivocation** alarmieren. Phase 1 braucht einen persistenten `ledger_epoch`, der bei Rotation inkrementiert (additiv in `.head` + Checkpoint; alte `.head` bleiben lesbar).
- **BootTrust real:** boot-time signierte Attestation + Pinned-Key + Live-PCR-Sysfs + fs-verity + lokale signierte Baseline; **kein frischer TPM-Quote mit Nonce** (kein TPM-Tool/Quote-Code im Repo); Zielserver hat **kein TPM/UEFI** (`hardware_root_of_trust=false`, Claim `local-signed-baseline`). Phase 1 darf **keine** Hardware-Attestierung behaupten: `quote_kind:"none"` + Boot-Posture-Digest, ehrlich „gleiche Boot-Posture wie zuletzt gesehen", kein TPM-Claim.
- **Transport:** gehärtete Feed-HTTP-Client-Muster vorhanden (Proxy aus, https-only, Redirect-/DNS-Rebind-/Limit-Härtung), aber **kein Zert-/SPKI-Pin, kein mTLS, keine Outbox**; Go-stdlib reicht (`crypto/x509`, `crypto/tls`, `crypto/ed25519`, `crypto/subtle`).
- **P5-LockdownEngine existiert** und kann „Witness-Equivocation" als Trigger aufnehmen (Reason-Token additiv, keine Engine-Umbauten).
- Server: 5.2.0-Release (Settings v12), P1–P5 **nicht deployt**; Control unprivilegiert mit bestehendem `AF_INET/INET6` und `ReadWritePaths=/var/lib/vgt/gedefense` ⇒ Witness-Client + Outbox ohne Unit-/Cap-Änderung möglich.

## 1. Ziel und Leitplanken

Ziel: Ein externer, kryptografisch verifizierender Zeuge kann **stille Abschaltung, Log-Fork/Rollback und sensorisches Downgrade** von GeDefense erkennen — ohne dass sensible Inhalte/Pfade das Gerät verlassen. GeDefense erzeugt signierte, präzise **Checkpoints** (Ledger-Head + Boot-Posture-Digest + Policy-/Sensor-Status), sendet sie optional per gehärtetem HTTPS (Modus A) oder exportiert sie air-gapped (Modus B), puffert offline in einer bounded, AEAD-verschlüsselten Outbox, verarbeitet signierte Witness-Receipts (Monotonie inkl. `ledger_epoch`) und eskaliert Equivocation/Rollback lokal (Critical-Evidence, optional P5-Lockdown-Trigger).

Leitplanken:
1. **Privacy:** Checkpoints enthalten nur Hashes/Fingerprints/Enums/Zähler — **keine** Dateipfade, Inhalte, Targets/IPs, Tokens, privaten Keys, Roh-Pubkeys (nur FP), Boot-Baseline-Notizen. Domänentrennung der Signaturen.
2. **Kein neuer privilegierter Pfad:** Alles im unprivilegierten Go-Control; Ledger-Key verlässt den Prozess nicht; keine neue Unit/Caps. Kein TPM-Ioctl/Hardware im Client; ehrliche Fähigkeitsgrenze.
3. **Fail-Closed/Default-off:** `witness.enabled=false` nach Upgrade; keine Requests/Checkpoints/Exports; `enabled=true` ohne Endpoint/Pin/Outbox-Bounds ist Validierungsfehler; Ledger quarantän (`integrityErr`) ⇒ Checkpoint verweigert; Outbox voll/Korrupt ⇒ fail-closed + `degraded` (kein stilles Verwerfen); Netzausfall ≠ Equivocation (kein Lockdown-Trigger bei Unerreichbarkeit).
4. **Witness-Server extern:** Phase 1 liefert **Protokoll + Client + Outbox + Export/Import + Verifier-Contract**, aber **keinen** Server-Dienst im Repo (Phase 2; keine Attrappe). Tests nutzen `httptest`-Fakes.
5. **Reversibel/Forensik:** Kein Löschen von Ledger/Rohdaten; Checkpoints/Receipts sind Evidence (`witness.checkpoint.created`, `witness.acked`, `witness.equivocation`, `witness.outbox_full`, `witness.export/import`); Alarme über bestehende Incident-/Evidence-Pfade; optional P5-Lockdown ohne Engine-Umbau.
6. **Kein Umbau:** Ledger/Rotation/Response/BootTrust/State-Muster bleiben; Ergänzungen additiv (neue Dateien + minimale Edits).

## 2. Architektur (Phase 1)

```
EvidenceLedger (bestehend) ──Checkpoint() atomar──> witness_checkpoint (signiert, epoch/seq/head/fp)
        ▲                                                   │
        │                                    ┌──────────────┴───────────────┐
        │                            Modus A: HTTPS-Client (Pin/mTLS)   Modus B: Export/Import
        │                                    │ challenge/nonce              │ vgtw1 + JSON
        │                              Witness (extern) ──signiertes Receipt──┐
        │                                    │                                  ▼
        │                              ack (monoton) ──> Outbox (AEAD,bounded) ──> Status/Events
        │                                                       │
        └──────────── Equivocation/Rollback-Erkennung ◄─────────┘
                         (ledger_epoch,seq,head) ──> Evidence/Incident ──> optional P5-Lockdown
```
Checkpoint-Erzeugung ist der einzigezeitige Atomaritätskern (`l.mu` einmal; `.head` durable vor In-Memory-Update); Netz-I/O niemals unter Ledger-Lock.

## 3. Checkpoint-Vertrag (`control/witness_checkpoint.go`, Signatur mit Ledger-Key)

```json
{
  "schema": "vgt-gedefense-witness-checkpoint-v1",
  "version": 1,
  "node_id": "<bounded hostname/id>",
  "checkpoint_id": "<16B hex>",
  "created_at": "RFC3339 UTC",
  "ledger_epoch": 0,
  "sequence": 68396,
  "head_hash": "<64 hex>",
  "records": 68396,
  "signing_key_fp": "<sha256(pubkey) 64 hex>",
  "boot_posture": "VERIFIED|OBSERVE|NOT_SUPPORTED",
  "boot_posture_digest": "<64 hex>",
  "quote_kind": "none",
  "policy_revision": 17,
  "policy_digest": "<64 hex>",
  "sensor_state": "online|degraded|offline|disabled",
  "challenge": "<hex or empty>",
  "signature": "<base64url Ed25519>"
}
```
- Digest über `"VGT-GEDEFENSE-WITNESS-CHECKPOINT-V1\0"` + kanonisches JSON **ohne** `signature` (deterministische Feldreihenfolge, strikte JSON); `Ed25519.Sign` über den Digest; `base64.RawURLEncoding` (Muster `evidenceCanonical/evidenceHash`).
- Pflichtfelder/Decode: exakte Schema-Version, Längen-/Hex-/Enum-/Sequenz-Grenzen, `signature` separat; Reject statt Reparatur; keine unbekannten Felder im Signaturbereich (Forward-Kompatibilität nur über neue schema-Version).
- **Ledger-Erweiterung:** `EvidenceLedger` erhält persistenten `ledger_epoch` (in `.head` additiv, bei `Rotate()` inkrementiert; alte `.head` ⇒ epoch 0) + öffentliche Methoden `Checkpoint()`/`Head()` (atomar) + `PublicKeyFingerprint()` (sha256 des Pubkeys) + `Status`-Felder `LedgerEpoch`/`PublicKeyFingerprint` (additiv). `quote_kind` Phase 1 immer `"none"`; `boot_posture_digest` = SHA-256 über kanonisches Subset der BootTrust-Items `{id,state,digest}` **ohne** `source`/`evidence`-Texte/Cmdline/Pfade.
- `policy_digest` = SHA-256 über kanonisches RuntimeSettings-JSON (wie Settings-MAC-Kanonik), `policy_revision` aus Settings; `sensor_state` aus XDR-Sensorstatus (online/degraded/offline/disabled), keine Details.
- `checkpoint_id`/`challenge` via `crypto/rand`; `created_at` UTC.

## 4. Modus A — Witness-HTTP(S)-Client (`control/witness_client.go`)

- Endpoint aus Settings: absolute `https://`-URL, **nur Port 443**, kein Userinfo/Fragment; `Proxy:nil` (kein Env-Proxy), `CheckRedirect` = Fehler (keine Redirects), Timeout/Response-Limit aus Settings (Default 10 s / 64 KiB), TLS≥1.2 (Empfehlung 1.3), keine Retry bei 4xx/5xx außer bounded 5xx/Netzfehler (Backoff).
- **Pinning:** `VerifyConnection` mit `sha256(cert.RawSubjectPublicKeyInfo)` gegen gepinnten SPKI-Hash (Settings/Datei 0600, Mode/Regular-Owner-Check) in constant-time; alternativ gepinnter Witness-Ed25519-Receipt-Key (Datei `0600`, Format wie `feed_signing`); beide Pins optional, aber Mode=http erfordert mindestens einen. **mTLS optional:** `tls.Certificate` aus Cert/Key-Dateien (Key 0600 validiert); Authorization nur optionaler Bearer aus separater Token-Datei (nie in Settings).
- **Protokoll (Client-Contract; Server extern):**
  - `POST <endpoint>/v1/challenge` → `{challenge}` (hex, ≤128 B, TTL vom Server); GeDefense akzeptiert nur nicht-leeren, frischen Challenge (eigene TTL Settings 120 s, einmalig; bounded Cache).
  - `POST <endpoint>/v1/checkpoint` Body = Checkpoint-JSON (oder kompakt base64) → `200 {receipt:{witness_id,witness_seq,checkpoint_id,accepted_at,signature}}`; Receipt-Signatur Ed25519 über kanonisches Receipt (Domäne `VGT-GEDEFENSE-WITNESS-RECEIPT-V1`), verifiziert gegen gepinnten Witness-Key.
  - Fehlerantworten `{error:"..."}` ≤64 KiB, keine Secrets; Client behandelt 401/403 als Pin/Auth-Fehler (`degraded` + Event, kein Retry-Sturm).
- **Receipt-Verarbeitung:** `witness_seq` **streng monoton**; `checkpoint_id` muss zum gesendeten Checkpoint passen; Replay/ältere Seq ⇒ Reject+Evidence; Ack AEAD-persistiert (`witness-ack`), kein Ledger-Key-Leak.
- **Outbox:** `<stateDir>/witness/outbox.enc` (AEAD `StorageCipher`, purpose `witness-outbox`), JSON-Array `{local_seq,checkpoint,signature,attempts,next_attempt_at,state:pending|acked}`; atomar (`atomicWriteFile`+Dir-Sync), bounded `maxBytes`/`maxEntries` (Default 4 MiB/1024); Worker single-flight, exponentielles Backoff, Ack prunt bestätigte Einträge; Restart lädt/authentifiziert, behält pending; voll ⇒ **fail-closed** (Checkpoint-Erzeugung abgelehnt, `degraded`, Event `witness.outbox_full`).
- **Equivocation/Rollback:** lokaler Detektor vergleicht `(ledger_epoch,sequence,head_hash)` mit letztem Ack/letztem beobachteten; `fork` = gleiche `(epoch,seq)`, anderer Head; `rollback` = niedrigere `(epoch,seq)`; ⇒ Critical-Evidence `witness.equivocation`, Status `equivocation=true`, Incident/Alarm; optional P5 `LockdownEngine.Trigger(candidate{Source:policy, Reason:witness-equivocation, Fingerprint})` (nur wenn Setting aktiv; Dedupe/Cooldown greifen). Rotation (epoch+1) ist **kein** Alarm.
- **Fail-safe:** Ledger quarantän/Checkpoint-Fehler ⇒ kein Senden; unreachable ⇒ `degraded` + bounded Outbox, **kein** Lockdown-Trigger; Outbox/State korrupt ⇒ fail-closed + Event; keine stillen Claims (Status `healthy/wired/degraded/unavailable`).

## 5. Modus B — Air-Gapped Export/Import (`control/witness_export.go`)

- `GET /api/v1/witness/export` liefert `{checkpoint, signature}` als JSON + kompakte `vgtw1:<base64url>`-Form (Ziel ≤2 KiB; keine QR-Bibliothek/Dependency; QR-Encoding durch Offline-Werkzeug/UI möglich). Offline verifizierbar: Schema + Signatur gegen bekannten Pubkey-FP + `(epoch,seq)`-Monotonie gegen zuletzt importierte Receipts.
- `POST /api/v1/witness/import` akzeptiert **nur** signierte Witness-Receipts/Import-Bestätigungen (kein Kommando-/Policy-Kanal), prüft Pin, `witness_seq`-Monotonie, `checkpoint_id`-Bindung an lokalen Export; Ablehnung mit präzisem Grund + Evidence; Import alter Epoche ⇒ Rollback-Alarm.
- Export/Import sind Mutationen (Push-Import) bzw. read-only Export (GET, bounded); Replay/`X-VGT-Request-ID`-Verträge gelten.

## 6. Modus C — Hardware-bound Key (Phase 2, ehrlich `unsupported`)

TPM2-sealed/PKCS#11-Signer für den Ledger-Key ist mit stdlib-only nicht umsetzbar und auf dem Zielhost ohne TPM gar nicht verfügbar. Status `key_binding="software"` (dokumentiert), Option `unsupported:tpm-sealed` in Settings/Report. Keine Attrappe.

## 7. Settings/API/Wiring

- **Settings v17:** Namespace `witness` (Pointer, Defaults off): `Enabled=false`, `Mode="off"|"http"|"export"`, `Endpoint=""`, `PinnedServerKeyFile=""`/`PinnedServerSPKI=""`, `ClientCertFile=""`/`ClientKeyFile=""`, `AuthTokenFile=""`, `CheckpointIntervalSeconds=300`, `NonceTTLSeconds=120`, `RequestTimeoutSeconds=10`, `OutboxMaxBytes=4 MiB`, `OutboxMaxEntries=1024`, `RetryAttempts=3`, `RetryBackoffSeconds=30`, `RequireAck=true`, `DegradeAfterFailures=3`, `EquivocationAlarm=true`, `TriggerLockdownOnEquivocation=false`; Validierung reject-not-repair (Endpoint https/Port 443/absolut, Pins vorhanden wenn Mode=http, Bounds, Pfade absolut/0600); Migration v16→v17 mit Notiz.
- **API:** `GET /api/v1/witness/status` (read-only, bounded, keine rohen Pfade/Keys), `POST /api/v1/witness/checkpoint` (Confirmation optional? nur Operator-Trigger, Evidence-first), `POST /api/v1/witness/push` (Mutation; `Confirmation="PUSH WITNESS"`, Replay, Evidence-Gate, Rate-Limit), `POST /api/v1/witness/challenge` (registriert/akzeptiert Operator-Nonce?; bounded), `GET /api/v1/witness/export`, `POST /api/v1/witness/import`; `GET /api/v1/status` additiv `witness`.
- **Status:** `{enabled,mode,wired,healthy,degraded,last_error,checkpoint{epoch,sequence,head_hash,id,created_at},last_ack{witness_seq,checkpoint_id,at},outbox{depth,bytes,full,oldest_at},challenge_pending,equivocation,equivocation_at,quote_kind,key_binding}`; `state.Snapshot` additiv `Witness`; Events/Evidence-Kinds `witness.checkpoint.created`, `witness.push.failed`, `witness.acked`, `witness.equivocation`, `witness.outbox_full`, `witness.export_created`, `witness.import_rejected`.
- **Wiring:** Konstruktion/Start in `main.go`, Engine `Run(ctx)` (Ticker: Checkpoint+Push), `ApplyRuntimeSettings`, `state`-Snapshot; Lockdown-Equivocation-Trigger additiv (`lockdown_settings.go` Reason/Flag, `lockdown_triggers.go` Evaluator, Schema).

## 8. Fail-Safe-/Privacy-Matrix

| Situation | Verhalten | Status |
|---|---|---|
| Default disabled | keine Requests/Checkpoints/Exports | `witness=disabled` |
| `enabled=true` ohne Endpoint/Pin | Validierungsfehler, nichts wird gesendet | `unavailable` |
| Ledger quarantän | Checkpoint verweigert, kein Claim | `unavailable` |
| Netzfehler | bounded Retry/Outbox; **kein** Lockdown | `degraded` |
| Outbox voll/korrupt | fail-closed, keine neuen Checkpoints, Event | `degraded:outbox-full` |
| Receipt falsch/Replay/Seq rückwärts | Reject + Evidence, keine Ack-Persistenz | `degraded` |
| Rotation (epoch+1) | normaler Checkpoint, **kein** Alarm | `healthy` |
| Fork/Rollback | Critical-Evidence+Incident, optional P5-Lockdown | `equivocation` |
| Kein TPM | `quote_kind=none`, `key_binding=software`, ehrlich (kein Hardware-Claim) | `degraded?` nur Anzeige |
| Pfad-/Inhalts-Leak | verboten (Privacy-Vertrag, Tests) | — |

## 9. Testplan

1. **Ledger/Checkpoint:** `ledger_epoch` persistent/inkrementiert bei Rotation; alte `.head` kompatibel; `Checkpoint()` atomar/durable; Signatur deterministisch; Decode-Reject-Matrix (Schema/Version/Längen/Enums/Signatur/fehlende Felder/unklare Zusatzfelder); Fingerprint = sha256(Pubkey); keine privaten Keys in JSON; Fuzz `FuzzWitnessCheckpointDecode`.
2. **Client Mode A:** `httptest.NewTLSServer` mit injizierbarem Transport: gültiger Checkpoint+Receipt, Pin-Mismatch, http-Downgrade, Redirect abgelehnt, Proxy deaktiviert, Response>Limit, Timeout, 4xx kein Retry, 5xx bounded Retry; Challenge abgelaufen/doppelt/leer; falsche Receipt-Sig/Seq rückwärts/Replay; outbox enqueue/ack/prune/Restart/Crash-`.tmp`/Voll-Grenze.
3. **Modus B:** Export deterministisch/bounded, `vgtw1`-Roundtrip, Offline-Verify (ok/falscher FP/alter epoch), Import-Monotonie/Replay/Ablehnung, Größenlimits.
4. **Equivocation:** gleiche (epoch,seq) anderer Head ⇒ fork; niedrigere (epoch,seq) ⇒ rollback; Rotation kein Alarm; Event/Incident/optional P5-Trigger (Fake-LockdownEngine/candidate), Dedupe.
5. **Settings/API:** Default inert/Migration/Caps; Endpoint-/Pin-Validierung; API Auth/Replay/Evidence-Gate/Confirmation/Größen; Status bounded/keine Secrets; Default-off = 0 Requests/Checkpoints/Events.
6. **Gates:** `go test ./...`, `go vet`, `-race`, `security-audit.sh` (+P4-Anker), `validate-systemd.sh`, `install-smoke.sh`, `node --check`; neue Dateien ≤500 Z.

## 10. Datei-Ownership / Phasen

| Task | Owner | Write-Scope | Depends |
|---|---|---|---|
| P4-T1 | Ledger/Checkpoint-Agent | `control/evidence_ledger.go`, `control/evidence_rotation.go`, `control/witness_checkpoint.go` (neu), Tests | Spec |
| P4-T2 | Engine/Client-Agent | `control/witness.go`, `witness_client.go`, `witness_outbox.go`, `witness_export.go`, `witness_settings.go`, `witness_api.go`, Tests; additive Edits `runtime_settings.go`, `fabric_settings.go`, `fabric_schema.go`, `server.go`, `state.go`, `main.go`, `lockdown_settings.go`, `lockdown_triggers.go`, `security_fuzz_test.go`, `Makefile` | T1 |
| P4-T3 | Packaging/Doku/Gates | `scripts/security-audit.sh`, `scripts/validate-systemd.sh`, `install-smoke.sh` (falls nötig), `ARCHITECTURE.md`, `docs/POINT4-WITNESS.md`, `docs/POINT4-PHASE1-REPORT.md` | T1–T2 |
| P4-T4 | Verifier | read-only adversarial | T3 |

## 11. Definition of Done (Phase 1)

- Ledger-Epoch/Checkpoint/Fingerprint implementiert; Rotations-Monotonie korrekt; Checkpoint signiert/verifizierbar; Privacy-Vertrag eingehalten (Tests).
- Modus A (gehärteter HTTPS-Client, Pinning/mTLS, Challenge, Receipts, Outbox, Equivocation) und Modus B (Export/Import) implementiert; Modus C/TPM ehrlich `unsupported`/`quote_kind=none`.
- Settings v17 Default off, API/Status/Events, optional P5-Lockdown-Equivocation-Trigger; Fail-Closed-Matrix durch Tests belegt.
- Gates grün; adversarialer Review ohne offene FAIL; Dokumentation, Phase-1-Report und Systemd-/Audit-Gates aktualisiert.

## 12. Umsetzungsstand (Phase 1)

| Task | Status | Ergebnis |
|---|---|---|
| P4-T1 — Ledger/Checkpoint | implementiert | persistenter `ledger_epoch` additiv im authentifizierten `.head` (alte `.head` ⇒ epoch 0); `Rotate()` schreibt `epoch+1`; atomare Views `Checkpoint()`/`Head()`; `PublicKeyFingerprint()` = SHA-256 des Pubkeys; signierter, streng decodierender Checkpoint |
| P4-T2 — Engine/Client/API | implementiert | gehärteter HTTPS-Client (Mode A), AEAD-bounded Outbox, Receipt-Verify/Monotonie, Equivocation-Detektor, Mode-B Export/Import (`vgtw1`), Settings v17 (Default off), sechs API-Routen, Status/Events, optionaler P5-Lockdown-Trigger |
| P4-T3 — Gates/Doku | dieser Stand | additive P4-Anker in `security-audit.sh`, POINT-4-Assertions in `validate-systemd.sh`/`install-smoke.sh`, Spec/Report/`ARCHITECTURE.md` §3.38 |

- **Neue Go-Dateien (alle ≤500 Zeilen):** `control/witness.go`, `witness_checkpoint.go`, `witness_client.go`, `witness_outbox.go`, `witness_export.go`, `witness_engine.go`, `witness_settings.go`, `witness_api.go` sowie sieben Testdateien (u. a. `witness_checkpoint_test.go`, `witness_client_test.go`, `witness_outbox_test.go`).
- **Additive Edits:** `evidence_ledger.go`/`evidence_rotation.go` (Epoch), `runtime_settings.go` (v17/Migration v16→v17), `fabric_settings.go`, `fabric_schema.go` (Modul `witness`), `server.go` (sechs Routen + Snapshot), `state.go`, `main.go` (Engine-Konstruktion/Start, `<stateDir>/witness/`), `lockdown_settings.go`/`lockdown_triggers.go` (additiver Trigger), `security_fuzz_test.go`/`Makefile` (Fuzz-Targets).
- **Default/Deployment:** `witness.enabled=false`, `mode=off`; ohne Operator-Aktivierung entsteht kein Checkpoint, kein Request, kein Export und kein Event. Auf dem Zielserver ist Phase 1 **nicht installiert/deployt**; Release-Manifest-/Hash-Gates unverändert (keine Binaries veröffentlicht).

## 13. Umsetzungsabweichungen und Präzisierungen (Phase 1)

### 13.1 Rotation = `ledger_epoch+1`, kein Rollback-Alarm
`Rotate()` schreibt `ledger_epoch+1` durable in das authentifizierte `.head`, **bevor** die In-Memory-Epoch und die auf 0/1 zurückgesetzte Sequenz sichtbar werden (`writeEvidenceCheckpoint(headPath, 0, "", nextEpoch, …)`). Eine höhere Epoch ist damit eine legitime Rotation: `compareWitnessHeads` liefert für `head.epoch > previous.epoch` **keinen** Alarm. Erst eine niedrigere `(epoch,sequence)` ist `rollback`, gleiche `(epoch,sequence)` mit anderem Head ist `fork`. `ledger_epoch+1` ist der einzige Fortschrittsbegriff; ein Checkpoint ohne Epoch-Feld (altes `.head`) decodiert als epoch 0 und bleibt gültig.

### 13.2 Ehrliche Fähigkeitsgrenze: `quote_kind="none"`, `key_binding="software"`
Der Zielhost hat **kein TPM/UEFI**; BootTrust liefert einen signierten Boot-Time-Snapshot (Pinned Key + Live-PCR-Sysfs + fs-verity), aber **keine frische Quote mit Nonce**. Deshalb enthält der Checkpoint nur `boot_posture` (`VERIFIED|OBSERVE|NOT_SUPPORTED`) und `boot_posture_digest` (SHA-256 über `{id,state,digest}` der BootTrust-Items, ohne `source`/`evidence`/Cmdline/Pfade) und der Vertrag akzeptiert ausschließlich `quote_kind="none"`. Der Status meldet `key_binding="software"`; es gibt **keinen Hardware-Root-of-Trust-Claim** und keinen TPM-Quote. Ein frischer Quote/TPM-Key-Binding ist Phase 2 (dort auch nur, wenn die Hardware es kann).

### 13.3 Witness-Server extern (Phase 2), kein Fake-Server im Repo
Phase 1 liefert **Protokoll + Client + Outbox + Export/Import + Verifier-Contract**, aber keinen HTTP-Witness-Dienst. Tests sprechen ausschließlich `httptest`-Fakes (`witness_client_test.go`). Die Produktionsdateien enthalten **weder einen Listener noch einen `httptest`-Import**; das Wort `httptest` steht dort nur in einem erklärenden Client-Kommentar. Das `security-audit.sh`-Gate prüft deshalb Import/Listener (nicht Kommentare) und lässt den Kommentar bewusst zu. Ein echter Witness-Server (Persistenz, Quorum/Rotation, Betrieb) ist Phase 2 und bewusst nicht als Attrappe im Repo.

### 13.4 Modus B: Datei/QR — QR-Encoding ist Phase 2
`GET /api/v1/witness/export` liefert das deterministische JSON `{checkpoint, signature}` plus die kompakte Form `vgtw1:<base64url>` (Ziel ≤2 KiB, harter 2-KiB-Bound). Das QR-Encoding selbst ist nicht implementiert (keine QR-Dependency in Phase 1); ein Offline-Werkzeug/UI (Phase 2) rendert `vgtw1` in einen QR-Code. `POST /api/v1/witness/import` akzeptiert nur signierte Witness-Receipts bzw. `{receipt:…}` — nie Kommando-/Policy-Kanäle.

### 13.5 Outbox bounded/fail-closed
Die Outbox ist AEAD-verschlüsselt (`witness-outbox`, AAD pfadgebunden) und bounded über `outbox_max_bytes` (Default 4 MiB; Floor 64 KiB, Ceiling 64 MiB) sowie `outbox_max_entries` (Default 1024; 16..65536). Schreibvorgänge sind atomar (temp+rename, 0600); bestätigte Einträge werden per Ack-prune entfernt, pending bleibt über Restart erhalten (Authentisierung schlägt bei Korruption fehl). Voll/korrupt ⇒ **fail-closed**: keine neuen Checkpoints, `degraded`, Event `witness.outbox_full` (einmal je Cooldown) — nichts wird still verworfen.

### 13.6 Equivocation-Alarm und optionaler P5-Lockdown
Die kritische Evidence/Incident-Kette (`witness.equivocation`) ist immer vorhanden; `equivocation_alarm=true` (Default) schaltet Event/Incident, `equivocation_alarm=false` schreibt nur die Evidence. Der P5-Lockdown-Trigger ist **doppelt** opt-in: `witness.trigger_lockdown_on_equivocation=true` **und** `lockdown.trigger_witness_equivocation=true` (Default beide false). Die P5-Dedupe-/Cooldown-/`require_sources`-Guards und der `expected_epoch`-Clear bleiben unverändert. Unerreichbarkeit des Witness ist **keine** Equivocation und löst keinen Lockdown aus.

### 13.7 Evidence-Gate: keine Ausnahme für Witness-Routen
Alle sechs Witness-Routen laufen durch `s.auth` (Bearer, `X-VGT-Request-ID`-Replay, Evidence-Gate mit `operator.mutation.intent`). `evidenceGateExempt` bleibt auf den dokumentierten vier Auswegen (Emergency Stop, L7-Selftest, Settings-Integrity, Lockdown-Trigger/Clear); **keine** Witness-Route ist exempt. Ein Push/Import/Checkpoint ohne auditierbares Ledger wird abgelehnt; der Export ist ein GET und ohnehin nicht gegated.

### 13.8 `records==sequence` und 2^53-Vertrag
Der Checkpoint setzt `records=sequence` (der Ledger kennt keine separaten „gelöschten" Records) und der Decoder lehnt `records != sequence` ab. Jeder Zähler (`ledger_epoch`, `sequence`, `records`, `policy_revision`, Receipt-`witness_seq`) ist auf `2^53` begrenzt, weil ein JSON-Konsument in einer anderen Sprache sonst rundet; negative Werte sind über `uint64`-JSON-Reject ausgeschlossen.

### 13.9 Import-CID-Bindung ist prozesslokal
`POST /api/v1/witness/import` bindet das Receipt an den `checkpoint_id` des **zuletzt in diesem Prozess** erzeugten Exports (`lastExport`). Nach einem Control-Restart ist `lastExport` leer; der Import wird dann mit „no local export exists; export a checkpoint before importing a receipt" abgelehnt (kein stilles Akzeptieren). Für Air-Gapped-Betrieb gilt: nach Restart zuerst `GET /api/v1/witness/export`, dann importieren.

### 13.10 `RequireAck` ist Phase 1 immer wirksam
`require_ack=true` ist Default und wird als Settings-Wert validiert; Phase 1 implementiert **nur** den Receipt-Pflichtpfad: ein Push ohne gültiges Receipt gilt als Fehlschlag (bounded Retry/Backoff, `degraded` nach `degrade_after_failures`), der Outbox-Eintrag bleibt pending. Ein echter „fire-and-forget"-Modus (`require_ack=false` mit anderer Semantik) ist Phase 2.

### 13.11 NOT_TESTED (ehrliche Grenzen)
- **Echter TPM2-Quote mit Nonce / TPM-Key-Binding:** kein TPM/UEFI auf dem Zielhost und kein TPM-Code im Repo ⇒ nicht getestet und **nicht behauptet** (`quote_kind="none"`, `key_binding="software"`).
- **Echter externer Witness-Server** (HTTPS-Endpoint, Persistenz, Quorum): Phase 2; in Phase 1 nur `httptest`-Fakes.
- **mTLS mit echtem Zertifikat/CA und echtes SPKI-Pinning gegen einen produktiven Server:** Client-Pfad ist unit-getestet, die reale Zertifikatskette ist **NOT_TESTED**.
- **Live-systemd-Betrieb** (Control-Unit + Settings v17 auf dem Zielhost, realer Netzwerkausfall/`degraded`): **NOT_TESTED**; ebenso echte QR-Größe für `vgtw1` (Phase 2).

### 13.12 Rotation-Crashfenster: Ledger fail-closed statt Auto-Completion
Zwischen dem Rename der frischen Chain und dem durable geschriebenen `epoch+1`-Checkpoint liegt ein **enges** Crash-Fenster: Die Live-Chain ist dann bereits leer, das authentifizierte `.head` nennt aber noch Epoch/Sequenz/Head der alten Generation. Ein Crash in genau diesem Fenster wird beim nächsten Start **nicht automatisch repariert**: der Ledger erkennt die Diskrepanz und geht **fail-closed** in Quarantäne (`integrityErr`; Appends und Checkpoints werden verweigert) — es gibt bewusst **kein Auto-Complete**. Recovery ist ein Operator-Pfad: den Ledger-Zustand aus dem zuletzt versiegelten Archiv/Backup prüfen und die Rotation bewusst erneut ausführen; die Epoch darf dabei **nicht zurückgesetzt** werden, weil ein Epoch-Regress für einen Zeugen wie ein Rollback aussieht. P4-T1 hat dazu den Code-Kommentar und den Test präzisiert; das Fenster bleibt als bewusstes, enges Restrisiko dokumentiert (Wirkung fail-closed und laut, kein stiller Datenverlust).
