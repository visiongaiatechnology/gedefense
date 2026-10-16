# Current Task

VGT GeDefense 4.2.2 — Fail-Closed-Härtung nach dem Vorfall vom 08.10.2026 (Schutz fiel auf Observe zurück).

## Completed

- **Startup-Selbstprüfer mit Selbstheilung (deployt `da4fc09e…`) — der Grund für „muss ich nach jedem
  Neustart nachschauen" ist beseitigt.** Nach jedem Neustart stand die Plattform bis zu **300 s** im
  Fail-safe („Automatische Reaktion ausgesetzt"), und wenn ein Modul wirklich hing, blieb sie stehen,
  bis jemand „Schutz aktivieren" klickte. Jetzt prüft sie sich selbst:
  `control/startup_supervisor.go` (Ablauf, Entscheidung, Qualifikation) und
  `control/startup_modules.go` (die Checkliste als **Daten**, nicht als Code).
  **Ablauf:** bis zu 12 Runden à 5 s; jede Runde prüft 10 Module, heilt was heilbar ist (mit den
  **vorhandenen** kanonischen Pfaden — kein zweiter Weg in Kernel-Policy, Ledger oder Allowlist),
  prüft **nach** der Heilung erneut und verlangt **zwei saubere Durchläufe**, bevor es bewaffnet.
  Danach läuft die Prüfung als Watch weiter (Intervall = Re-Arm-Intervall/5, mind. 15 s) und heilt
  auch eine Degradierung, die erst Stunden später auftritt.
  **Module:** `core_ipc`, `kernel_enforcement` (Heilung: `ReconcileVerifiedPolicy`), `management_allowlist`
  (Heilung: `syncCoreAllowlist`), `sensor_coverage`, `signed_policy` (Heilung: `Policy.Load`),
  `evidence_ledger` (Heilung: inkrementelle Prüfung bzw. Rotation bei 90 %), `incident_log`
  (Heilung: `RecoverIncidentLedger`) — alle blockierend; `host_keyring`, `system_integrity`,
  `threat_intel` — berichtend, **nicht** blockierend. Die beiden teuren Prüfungen laufen beim Start,
  die billigen zusätzlich im Watch (`continuous`).
  **Zwei Vertrauensentscheidungen bleiben beim Betreiber und sind getestet:** eine veränderte
  Systemdatei (FIM) wird **nie** automatisch als neue Baseline akzeptiert, die Fall-Historie **nie**
  im Hintergrund umgeschrieben — beide werden benannt, blockieren die Bewaffnung aber nicht.
  **Sofortige Wiederbewaffnung statt Leiter:** `ReleaseController.ReArmVerified` bewaffnet direkt,
  wenn (a) kein Not-Aus aktiv ist, (b) die Gates erfüllt sind, (c) die Kernel-Durchsetzung verifiziert
  ist und (d) der **Host-Fingerabdruck** (Kernel, Release, Node, Interface) dem zuletzt qualifizierten
  Start entspricht. Weicht er ab (neuer Kernel, neue NIC, neues Release), greift weiterhin die
  **sichtbare Canary-Leiter** — genau die Re-Qualifizierung, die `OPERATIONS.md` verlangt. Rate-Limit
  300 s gegen Flattern; die Qualifikation wird geschrieben, sobald die Plattform verifiziert
  `enforce` erreicht (`/var/lib/vgt/gedefense/release-qualification.json`, atomar, 0600).
  **Abnahmetest live (16.10.):** Neustart der Kontrollplane → `enforce` nach **24,2 Sekunden**,
  ohne jeden Klick; im Journal `startup self-check: all 10 blocking modules verified` →
  `release: protection re-armed after the startup self-check: all modules verified and the host is
  unchanged`. Vorher: 300 s plus Betreiber. (Beim allerersten Lauf greift bewusst die Leiter, weil
  noch kein qualifizierter Fingerabdruck existiert — das ist die konservative Richtung.)
  **Tests:** `control/startup_supervisor_test.go` — Entscheidungstabelle (9 Fälle inkl. Not-Aus,
  geänderter Kernel, Rate-Limit), Modulklassifikation (geheilt / kaputt-blockierend / Betreiber),
  Vertrauensentscheidungen (kein Auto-Repair, nicht blockierend), Qualifikations-Roundtrip inkl.
  defekter Datei, Ablauf mit zwei sauberen Durchläufen, und „bewaffnet **nicht** bei kaputtem Modul".
- **Desktop-Indikator (Tray) — Daemon-Seite und Qt6-Client fertig und verifiziert.**
  Dritte, bewusst minimale lokale Schnittstelle neben der token-geschützten HTTP-API und der
  VGT3-authentifizierten Kern-IPC: ein **nur lesender** Unix-Socket unter
  `/run/gedefense/gedefense.sock` (`control/desktop_status.go`, `desktop_status_linux.go`).
  Ein Telegramm, ein Vorgang, harte Grenzen — Protokoll v1:
  `{"v":1,"op":"status"}` → eine JSON-Zeile mit `status` (`secure|warning|alert|stopped`),
  **`status_reason`**, `product_version`, `node_name`, `release_phase`, `enforcement`,
  `kernel_policy`, `ebpf_active`, `sensor`, `threat_count_today`, `blocked_active`,
  `last_anomaly_at`, `last_anomaly_summary`, `active_alert`.
  **Härtung:** Anfrage ≤ 256 B, Antwort ≤ 4 KiB, Lese-Deadline 3 s / Schreib-Deadline 2 s,
  Identität ausschließlich aus `SO_PEERCRED` (wiederverwendet: `l7PeerCredentialsFromConn`),
  max. 2 Verbindungen **pro Identität**, Token-Bucket 60/min (Burst 10), Obergrenze 4096
  verfolgter Identitäten, Steuerzeichen entfernt, alle Zeichenketten längenbegrenzt und
  UTF-8-sicher gekürzt, **keine** Pfade/Hashes/Tokens im Wire-Format. Unbekannter Vorgang,
  falsche Version, Zusatzfelder, Müll und HTTP-Anfragen erhalten eine begrenzte
  `{"v":1,"error":"invalid request"}` **ohne jeden Zustand**.
  **Rechte:** Verzeichnis `2750 gedefense:gedefense-desktop` (setgid), Socket `0660` derselben
  Gruppe — der Fremdbenutzer `nobody` erhält live `Permission denied`.
  **Semantik (bewusste Abweichung von der Skizze):** ein *blockierter* Angriff färbt den Indikator
  **nicht** rot. Blockieren ist das Produkt bei der Arbeit und passiert auf einem exponierten Host
  hundertfach am Tag; Dauerrot ist Alarmmüdigkeit und vom Security-UI-Standard verboten. Rot
  (alert) bleibt dem Unerledigten: verletzte Integrität, kritischer Vorfall im Fenster (10 min).
  Gelb (warning): Automatik ausgesetzt bei erhaltener Durchsetzung, Phase unter `enforce`,
  Forensik-Ledger ungesund, Vorfall hoher Schwere. Grau/rot (stopped): Kern nicht verbunden oder
  Durchsetzung nicht `enforce`.
  **Deploy-Lehren aus der Live-Inbetriebnahme (alle drei behoben und im Repo):**
  1. `ProtectSystem=strict` braucht `/run/gedefense` in `ReadWritePaths` (sonst kein Socket),
  2. das Setgid-Bit darf der Dienst wegen `RestrictSUIDSGID=true` **nicht** setzen — es kommt aus
     `packaging/tmpfiles` (Verzeichnis gehört `gedefense`, Gruppe `gedefense-desktop`),
  3. der Dienst braucht `SupplementaryGroups=gedefense-desktop`, sonst scheitert schon der
     Verzeichniszugriff (`packaging/systemd/gedefense-control.service`).
  Der Code prüft die Verzeichnis-Eigentümerschaft jetzt **vor** dem Binden und nennt die erwartete
  Kombination, statt ein nacktes EPERM zu protokollieren.
  **Tests:** `control/desktop_status_test.go` — Ableitungstabelle (11 Fälle inkl. Fenstergrenzen),
  Tageszählung, Budget-/UTF-8-/Steuerzeichen-Grenzen, Anfrage-Allowlist, Protokoll über echten
  Socket, feindliche Eingaben, Verbindungsgrenze, Ratenlimit, Doppelbindung, Pfadwächter,
  Modus-Parsing. **Live belegt (16.10.):** `desktop status socket ready … mode=0660`, 637-Byte-
  Telegramm, `status=alert` mit „Systemintegrität verletzt" (mein eigener Deploy), 3. Verbindung →
  `busy`, 14 schnelle Anfragen → 13 begrenzt, `nobody` → verweigert.
  **Offen:** Qt6-Tray-Client (`desktop/tray/`, eigener Agent: Build, QTest, Offscreen-Screenshots),
  Installer-Schritt „Gruppe anlegen + Desktop-Benutzer aufnehmen" (sysusers/tmpfiles sind bereits
  ergänzt), READMEs in vier Sprachen, Entscheidung über die Versionsnummer (Feature vs. 4.2.2).
  Der „Schnellscan"-Knopf der Skizze ist bewusst **kein** Socket-Vorgang: der Socket ist nur
  lesend, ein Scan gehört in die authentifizierte Konsole.

- **Ursachenanalyse der Entwaffnung:** ein einzelner ungültiger Kernel-Datensatz (`decode_ingress_event` verletzt bei gemischten Protokoll-Aggregaten seine TCP-Invariante, `take_ingress_events` bricht daraufhin den **ganzen** Batch ab) markierte den Ingress-Sensor als degradiert; das Release-Gate antwortete mit `reconcileLocked("observe")` und **leerte die gesamte Kernel-Blockliste**. Der Host blieb 20 Stunden ungeschützt, weil nichts die Phase zurücknimmt.
- **Fail-Closed-Satz (deployt, `378509be…`):** automatische Degradierung leert die verifizierte Kernel-Policy nie mehr, sondern bestätigt und behält sie (`reconcileVerifiedLocked` prüft jeden Block per idempotentem ADD, weil der Core keinen Read-back hat); Promotionen senken eine verifizierte Enforcement nicht mehr (`retainedEnforcementLocked`); der Start behält die Enforcement aus der signierten Policy (`InitializeStartup`); Wiederbewaffnung nach gehaltener Ruhe mit Anti-Flatter-Soak (`recoverIfGatesPassLocked`, `NominalSince`); Beobachtungsqualität und Enforcement-Fähigkeit sind getrennt (`evaluateKineticSensorHealth` — ein Drain-Fehler ist kein Sensorausfall); Übergänge werden im Journal protokolliert.
- **Vorfalls-Ledger:** `SIZE_BUDGET_EXHAUSTED` ist wiederherstellbar statt terminal. Live belegt: `recoverable: true` → `POST /api/v1/xdr/recovery` (mit `X-VGT-Request-ID`) → `HTTP 200`, Archiv `20261009T175614…`, Manifest-SHA256, danach `health=healthy`, `blockers=[]`.
- **Ausfall behoben und verifiziert (Startdauer 876 s → 7 s):** die Startverifikation des Evidenz-Ledgers lief O(n) über die ganze Datei und überschritt das Start-Timeout der Unit; die Plattform konnte nicht mehr hochkommen (Dashboard *und* Release-Gate weg). Jetzt: authentifizierter Checkpoint + begrenztes Tail-Fenster beim Start, **inkrementelle** Verifikation im Hintergrund (authentifizierter Wasserstand, 25 000 Datensätze pro Lauf), volle Verifikation weiterhin als Operateur-Pfad (`GET /api/v1/evidence/verify`). `AttachEvidenceLedger` verifiziert nicht mehr ein zweites Mal, `fim.go` walkt nicht mehr alle 900 s die ganze Historie.
- **Crash-Sicherheit:** ein durch Sturm/`SIGKILL` unterbrochener Append hinterlässt genau einen unversiegelten Datensatz. Er wird verifiziert und versiegelt (kein Datenverlust) oder verworfen (partieller Schreibvorgang); mehrere Datensätze hinter dem Checkpoint werden abgelehnt. Vorher verhinderte dieser Zustand den Start der Plattform.
- **Sicherheitsloch geschlossen, das die eigenen Tests gefunden haben:** ein *unverschlüsselter* Wasserstand wurde als „legacy plaintext" akzeptiert und übersprang damit die Prüfung der ganzen Historie. Ein Wasserstand gilt jetzt nur noch als gültig, wenn er authentifiziert ist.
- **Verifikation:** `gofmt`/`go vet` sauber, **volle Suite grün (97,4 s)**, 8 neue Verifikations-Vertragstests, **vier Mutationsproben belegt** (Retention zurückgebaut, einzelner Drain-Fehler, Promotion senkt Enforcement, Wasserstand-Authentifizierung entfernt — jede lässt genau die zugehörigen Tests fehlschlagen).

## Current State

- **Schutzstatus: scharf.** `phase=enforce`, `enforcement=enforce`, `kernel=verified-enforce`, `blockers=[]`, alle vier Dienste aktiv, Startdauer 2–7 s. Nach jedem Deploy kehrt die Phase selbstständig zurück (belegt: 18:08:12 und 18:42 nach gehaltener Ruhe).
- **Rust-Kern deployt (`6d1c5ce1…`) — Punkt 3 der Mission erfüllt.** Ein ungültiger Datensatz bricht den Drain nicht mehr ab: `take_ingress_events` überspringt und benennt ihn (`kernel ingress sample rejected: …`) und meldet nur dann einen Fehler, wenn ein ganzer Batch unlesbar ist (Schwelle 16 → „Wire-Format stimmt nicht"). Der Decoder neutralisiert ein TCP-Label, dessen Zähler nicht zu TCP passen (gemischtes Protokoll-Aggregat), statt den Datensatz zu verwerfen. `cargo test -p gedefense-common`: 6/6; beide Crates rustfmt-rein; Live-Vergleich: **47 fatale Abbrüche in 24 h vorher, 0 seit dem Deploy**.
- **Ledger rotieren sich selbst — Punkt 5 der Mission erfüllt.** Evidenz-Ledger live bei 90 % rotiert (266,7 MB versiegelt, Manifest/Digest/Wasserstand, `archive/evidence-20261009T182909…`), Schutz blieb dabei durchgehend `enforce`. Rotation ist crash-sicher (versiegeln → Manifest → Marker → Tausch; unterbrochene Läufe werden beim Start vervollständigt, Marker ohne Manifest fail-closed abgelehnt). Vorfalls-Ledger-Rotation implementiert, getestet und am selben Auslöser im XDR-Lauf.
- **Deploy ist kein Angriff mehr.** Ein Wechsel an einer eigenen Komponente wurde als Selbst-Tamper gewertet, degradierte XDR und pausierte damit jede automatische Reaktion, bis jemand die Kontrollplane neu startete. Jetzt: ein `self_artifact`-Ereignis (high, Score 120, alert-only) und **keine** Degradierung; Fremdobjekte behalten die volle Reaktion. Live belegt: Artefakt bei laufendem Dienst ersetzt → 1 Ereignis, 0 Tamper, XDR binnen 15 s gesund, Durchsetzung durchgehend erhalten.
- **Fail-Open: alle drei Pfade live geschlossen** (automatische Degradierung, Neustart, Promotion) mit Journalbelegen vom 09.10.
- **Evidenz-Verifikation:** begrenzter Start (Checkpoint + Tail), inkrementelle Abdeckung mit authentifiziertem Wasserstand, Crash-Recovery für einen unversiegelten Append.
- **Wiederherstellung des Vorfalls-Ledgers** läuft bei behaltener Durchsetzung (kein Observe nötig).
- **P1: Die Rotation des Vorfalls-Ledgers verweigerte den gesunden Ledger (11./12.10.) — behoben.**
  Die automatische Rotation greift bei **90 %** des Budgets (`xdr.go`: `StoredBytes` gegen
  `evidenceRotationThresholdPercent`). `IncidentLogger.Rotate` delegierte aber unmittelbar an
  `Recover`, und dessen erster Wächter lehnt einen intakten Ledger grundsätzlich ab:
  `incident ledger recovery is not required`. Damit existierte ein **totes Fenster zwischen 90 % und
  100 %**: die Rotation scheiterte genau dann, wenn sie das Protokoll retten sollte, XDR degradierte
  (`cause=incident_log reason=incident log rotation failed: …`), die automatische Reaktion pausierte —
  und erst **oberhalb** des harten Limits, wenn der Ledger als „recoverable" gilt, gelang derselbe
  Aufruf und meldete eine Recovery. Journalbelege: 11.10. 15:32:01 und 16:19:05 Rotationsfehler,
  11.10. 15:32:03 Phase degraded, 12.10. 01:14:27 `incident log size budget exhausted`, 01:14:34
  „recovered" (da erst jetzt recoverable).
  Behoben (`4723e2ff…`): Die Mechanik (versiegeln → Manifest → Quellstabilität → frische Kette →
  Nachweis) liegt jetzt in `archiveIncidentSegments`, die **Vorbedingung** ist getrennt — die Recovery
  verlangt weiterhin einen beschädigten Ledger, die Retention-Rotation versiegelt einen **gesunden**
  bei 90 % und einen beschädigten, sobald er recoverable ist, statt auf das harte Limit zu warten.
  Das Archiv-Manifest trägt `trigger` (`recovery` | `retention`); ein leerer Ledger wird mit
  `errIncidentArchiveEmpty` abgelehnt (kein leerer Archiv als Scheinbeweis). Die Sperre des Loggers
  bleibt über die gesamte Operation gehalten — die Stabilitätsprüfung würde sonst jede Rotation eines
  beschäftigten Ledgers verwerfen.
  **Mutationstest:** `TestIncidentLogRotationWorksOnAHealthyLedgerAtTheBudget` scheiterte auf dem
  alten Code **wörtlich mit der Produktionsmeldung** und ist nach dem Fix grün; der bisherige
  Rotationstest füllte den Ledger bis zum Fehlschlag und deckte das Fenster 90–100 % deshalb nie ab
  (neu: `fillIncidentLogToPercent`).
  **Nebenbefund:** Der Host stand auf `observe`, weil auf einen **Not-Aus** (`EMERGENCY_STOP`) dessen
  Aufhebung folgte — die Plattform startet danach absichtlich in Observe und verlangt eine
  ausdrückliche Freigabe. Wiederbewaffnet über `observe → canary (900 s Soak) → enforce`; eine direkte
  Promotion nach `enforce` wird korrekt abgelehnt (409 mit Begründung im Journal).
- **Wiederkehrende Fail-safes (09.–10.10.) — Ursache gefunden und behoben.** Das Gate fiel im
  Rhythmus von ~39–40 Minuten auf `degraded` (06:00:21, 06:40:16, 07:19:23) und brauchte danach die
  300-s-Ruhe; die Anzeige meldete „XDR is degraded", ohne je einen Grund zu nennen. Ursache war eine
  Kette aus vier Fehlern:
  1. **Der Fall-Speicher auf der Platte enthielt einen doppelten Fingerabdruck.** `decodeCaseStore`
     verwarf daraufhin den **ganzen** Bestand, `NewCaseEngine` setzte `integrity`, und `IngestIncident`
     gab diesen Fehler danach **für jeden** eingehenden Incident zurück — der Fall-Speicher war
     dauerhaft tot (0 Fälle, Revision 0).
  2. **Jeder fehlgeschlagene Incident-Eintrag degradierte die Plattform**, direkt in `State.AddIncident`
     (`s.xdr.Degraded = true`), **am Ursachen-System vorbei**: unsichtbar im Journal, nicht über die
     Ursachen-Hygiene löschbar.
  3. **`SetXDRDegraded(false, …)` löschte fremde Ursachen mit.** Vier Schreiber teilten sich ein Feld;
     der nächste Hygiene-Lauf wischte die Degradierung weg, das Gate hatte aber bereits ein Fail-safe
     verriegelt — deshalb „erholt" sich die Anzeige von selbst und kippt Minuten später erneut.
  4. **Ein einzelner Fehlschlag genügte** — beim Prozess-Sensor (`/proc`-Scan) ebenso wie bei der
     forensischen Verifikation. Kein Wiederholungs-Kriterium.
  Behoben und deployt: `e4dc3edd…` (Verifikation degradiert erst beim **zweiten** Fehlschlag, erster
  wird benannt), `e5beab8b…` (**eine** Wahrheitsquelle: `State.xdrCauses` mit Ursachen-Schlüsseln,
  jede Ursache namentlich im Grund, jeder Übergang im Journal; Fall-Speicher degradiert erst nach zwei
  Fehlschlägen und erholt sich beim ersten Erfolg), `686428dd…` (**Reparatur statt Ablehnung**:
  doppelte Fingerabdrücke werden deterministisch zusammengeführt — neuester Datensatz überlebt,
  Zähler summiert, offene Fälle bleiben offen; doppelte **IDs** bleiben ein harter Fehler).
  Live belegt: `case store repaired: 1 duplicate fingerprint records merged`, danach
  `cases healthy=true revision=21 count=8 repaired=1 error=None`, seither **0** Ingest-Fehler,
  `xdr degraded=false`. Der Reparaturzähler ist über `CaseStatus.repaired` sichtbar.

## Next

1. **Optional — Sichtbarkeit des Rust-Kerns.** Er zählt und protokolliert übersprungene
   Ingress-Datensätze, meldet die Zahl aber nicht in der Health-Antwort. Dafür muss
   `parseCoreIngressHealth` zusätzliche Felder tolerieren (heute genau drei oder vier), damit die
   verlorene Sichtbarkeit auch im Panel erscheint und nicht nur im Dienstprotokoll.
2. **Optional — Produzentenseitige Normalisierung.** Der eBPF-Producer etikettiert ein
   gemischtes Aggregat weiterhin mit dem Protokoll des auslösenden Pakets; die Invariante gilt
   jetzt konstruktiv am Dekoder. Wer sie auch an der Quelle herstellen will, braucht
   `bpf-linker` (hier nicht vorhanden, das eBPF-Objekt ist deshalb nicht neu baubar).
3. **Packaging:** `/var/lib/vgt/gedefense/archive` mit `0700` und Dienst-Eigentümer anlegen (auf
   dem Produktionshost korrigiert), sonst verweigert die Rotation auf einer frischen Installation
   fail-closed.
4. **Dokumentation:** CHANGELOG, konsolidierter Bericht und die READMEs (EN/DE) sind um die
   Fail-Closed-Sitzung, die Rotation und den Rust-Fix ergänzt; RU/ZH laufen.
5. **Sturm der unterdrückten Reaktionen eindämmen.** Solange die automatische Reaktion pausiert ist,
   schreibt **jede** abgewiesene Entscheidung einen Evidenz-Datensatz *und* einen Incident
   (`kinetic.response_suppressed`, Dutzende pro Sekunde; das Evidenz-Ledger stand dadurch bei
   152 MB / 148 606 Datensätzen). Die XDR-Engine hat eine Dedupe (`XDRFabric.DedupeSeconds`,
   5 min), der Kinetic-Runtime nicht. Nächster Schritt: dieselbe Dedupe pro Ziel+Regel anwenden,
   Zähler bleibt vollständig, erster Treffer und periodische Zusammenfassung bleiben im Ledger.
6. **Vorfalls-Log wird alle 30 s vollständig verifiziert und hält dabei seinen Mutex** (~60 s bei
   8,9 MB, wachsend). Der Evidenz-Ledger hat dafür längst die begrenzte Prüfung (Checkpoint + Tail,
   inkrementeller Wasserstand); der Incident-Log sollte dasselbe Verfahren bekommen, sonst wächst
   die Last mit jedem Incident.
7. **Bewusst fail-closed und deshalb klebrig:** `malware.event_queue_overflow` degradiert dauerhaft
   (ein Verlustereignis ist keine Aussetzerscheinung) und wird nur durch Neustart oder Operateur
   gelöst. Das ist eine Entscheidung, kein Versehen — wer sie ändern will, braucht einen
   ausdrücklichen Quittierungspfad.
8. **Beobachtung:** Das natürliche Fenster (~39–40 min nach 07:19:23, also ~07:58) war zum
   Redaktionszeitpunkt noch nicht durchlaufen; der Auslöser ist nachweislich beseitigt
   (Bestand repariert, 0 Ingest-Fehler, XDR gesund, Phase zurück auf `enforce`).

## Deploy-Verfahren (verbindlich)

1. Suite-Gate: kein Deploy bei roter Suite.
2. Mutationsproben für die berührten Sicherheitsverträge.
3. **Startdauer vor dem Deploy messen** und mit dem Start-Timeout der Unit vergleichen.
4. **Dateien nur mit absoluten Pfaden schreiben.** Ein Skript, das relativ las und dann schrieb,
   hat zehn Quelldateien auf ihre Kopfzeile reduziert; die Wiederherstellung kam aus dem
   Build-Verzeichnis des Servers, abgesichert durch einen Volumenabgleich aller Dateien
   (SHA256 je Datei, nicht Stichproben). Vor jedem Schreiben: lesen, absolut adressieren,
   danach den Baum gegen die Referenz vergleichen.
5. Backup mit Zeitstempel, `install` auf Temp-Name, `mv`, Neustart, Zustand verifizieren.
6. Rollback gilt erst als erfolgreich, wenn der Dienst `active` **und** die API erreichbar ist.
7. **Kein `SIGKILL` auf die Kontrollplane, solange ein Append laufen kann** — er hinterlässt den
   unversiegelten Datensatz. `systemctl stop` (SIGTERM) verwenden; die Wiederherstellung ist
   implementiert, aber der Zustand ist vermeidbar.

## Deploy-Verfahren (verbindlich, nach dem Ausfall)

1. Suite-Gate: kein Deploy bei roter Suite.
2. Mutationsproben für die berührten Sicherheitsverträge.
3. **Startdauer vor dem Deploy messen** und mit dem Start-Timeout der Unit vergleichen.
4. Backup mit Zeitstempel, `install` auf Temp-Name, `mv`, Neustart, Zustand verifizieren.
5. Rollback gilt erst als erfolgreich, wenn der Dienst `active` **und** die API erreichbar ist.
6. **Kein `SIGKILL` auf die Kontrollplane, solange ein Append laufen kann** — er hinterlässt den unversiegelten Datensatz. `systemctl stop` (SIGTERM) verwenden; die Wiederherstellung ist implementiert, aber der Zustand ist vermeidbar.
