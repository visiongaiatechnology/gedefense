# Current Task

VGT GeDefense 4.2.2 — Fail-Closed-Härtung nach dem Vorfall vom 08.10.2026 (Schutz fiel auf Observe zurück).

## Completed

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
