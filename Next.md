# Current Task

WP-Kontrollzentrum-Karte in die Linux-Übersicht übernehmen. Abgeschlossen am 17.10.2026.

## Completed

- WP-Design mit identischen 176 Länderpfaden, Farben, Bézier-Bögen, animierten Lichtpunkten, Sonar-Markern, Clustern und Sovereign Host Hub umgesetzt.
- Sechsspaltige Telemetrietabelle: Zeit, Quell-IP/Geo, Zielpfad, Erkennungsmodul, Aktion, ASN/Organisation. Filter für alle Vektoren, geblockte Quellen und Abtastungen; gemeinsame Detailansicht und Hervorhebung.
- Echte Linux-API beibehalten, snake_case-Felder normalisiert, ASN/Organisation mit Ereignissen verbunden, Paketquellen ohne Incident ebenfalls gelistet.
- Lokale Module explizit im Go-Server freigegeben. Begrenzte Quellen/Animationen, Abbruch/Deadline, Pause, Sichtbarkeitssteuerung, Tastatur und reduzierte Bewegung umgesetzt. Keine externen Assets oder neuen Bibliotheken.
- Verifiziert: 37 Browserchecks mit echtem Chrome, Desktop 1600 px / Tablet 1000 px / Mobile 390 px, vier Sprachen, tatsächliche Photon-Bewegung, Cluster, Filter, Fokus/Escape, Pause/Fortsetzen, verborgene Ansicht, leere Daten, unbekannter Host, XSS-Text, Fehler und Wiederabruf. Keine unbehandelten Browserexceptions.
- Linux/WSL: `go vet ./...` und vollständiges `go test -count=1 ./...` grün (250,796 s). Finale Asset-/Modulverträge nochmals grün (0,240 s); `go build` erfolgreich, Prüfbinary nur unter `/tmp/gedefense-control-map-check`.
- Vorhandene Dashboard-Regressionsfixture B2 grün (4/4). JavaScript-Syntax geprüft. 176/176 WP-Länderpfade exakt identisch.
- Betroffene Dateien im vorhandenen GitHub-Upload-Spiegel synchronisiert; betroffene Hash-Einträge in Quell-/Uploadmanifesten aktualisiert.

## Current State

Lokale Implementierung vollständig, Status PLATIN für diesen Änderungsumfang. Kein Produktionsdeploy, keine Dienstneustarts, keine Änderung an Backend-Erkennung oder Kinetic-Karte. Browsernachweise verwenden klar abgegrenzte Testtelemetrie; keine Aussage über die aktuell deployte Oberfläche. Der benannte Quellordner trug bereits `VERSION=4.2.4`; die Versionsnummer wurde nicht verändert. Historische Betriebsübergabe unten unverändert erhalten.

## Next

Kein Implementierungsschritt für diesen Auftrag offen. Ein Deployment ist ein gesonderter Betreiberauftrag.

## Relevant Files

- `control/web/overview-map.js`: Lebenszyklus, Tabelle, Filter, Detailansicht.
- `control/web/overview-map-data.js`: begrenzte Transportnormalisierung und Quellen-/Ereigniszuordnung.
- `control/web/overview-map-renderer.js`: lokale SVG-Geometrie, Cluster, Animation und Zoom/Pan.
- `control/web/overview-map.css`, `control/web/index.html`, `control/web/i18n.js`, `control/web/api.js`.
- `control/server.go`: explizite Asset-Freigabe; `control/overview_map.go`: unveränderter Datenvertrag.
- `qa/overview-map-check.mjs`: reproduzierbare Browserprüfung (startet Fixture-Server selbst).
- `qa/overview-map-results/{report.json,desktop.png,tablet.png,mobile.png}`: Prüfnachweise.
- `ARCHITECTURE.md`: Modulzuständigkeiten am Dokumentende.

## Important Decisions

- Daten aus `/api/v1/overview/threat-map`; keine erfundenen Geo-Positionen oder Zielbögen.
- WP-Look auf Linux-Daten adaptiert. Bestehende lokal vendorte MIT-Weltkarte unverändert genutzt.
- API-Ausfall bleibt sichtbar; letzter erfolgreicher Stand wird als veraltet markiert. Dynamische Telemetrie ausschließlich über DOM/textContent.
- Spiegel nur für betroffene Dateien synchronisiert, fremde Änderungen und historische Betriebsentscheidungen erhalten. Kein Git-Repository im Arbeitswurzelverzeichnis.

---

# Current Task

## ✅ F-01 GESCHLOSSEN (16.10.) — Dienstidentität des Gateways getrennt

**Live verifiziert:** Das internetnahe Gateway läuft als eigenes Konto `gedefense-access`, ohne
Neustartschleife (`NRestarts=0`). Für dieses Konto **unlesbar**: `evidence.ed25519`, `policy.ed25519`,
`xdr-log.key`, `core-ipc.key` (beide Ablagen), `cases.enc`, `storage-master.key`. Dashboard `HTTP 200`,
`phase=enforce`, `kernel=verified-enforce`, `fail_safe=True`, `detail='release gates satisfied'`.
Zuvor konnte das Gateway den Storage-Master-Key lesen (gesamte verschlüsselte Evidenz) und den
Kern-IPC-Schlüssel (signierte Kommandos an den Root-Kern).

**Der Mechanismus, der funktioniert** (nach fünf widerlegten Ansätzen): Eine **root-Vorstufe in der
Unit** legt dem Gateway eine eigene Kopie an —
`ExecStartPre=+/usr/bin/install -o gedefense-access -g gedefense-access -m 0600 /var/lib/vgt/gedefense-access/dashboard.token /var/lib/vgt/gedefense-access/state/backend-token`
— und `--backend-token-file` zeigt darauf. Damit ist die Anforderung erfüllt, die das Gateway selbst
formuliert (`0600`, eigenes Eigentum), ohne dass die Kontrollplane etwas weggeben muss und ohne dass
die Vertrauenswurzel geöffnet wird. Ebenso umgestellt: `User`/`Group=gedefense-access`,
`SupplementaryGroups` entfernt, `ReadWritePaths=/var/lib/vgt/gedefense-access`, Flags für
Passwortdatei, Zertifikat und Session-Schlüssel auf `/etc/vgt/gedefense-access/…` bzw.
`…/gedefense-access/state/…`.

**Fünf widerlegte Ansätze — nicht wiederholen:** Schlüssel in eine gemeinsame Gruppe (Preflight
verbietet gruppenlesbare Vertrauenswurzel) · Verzeichnis `/var/lib/vgt/gedefense` umstellen (dort
liegen alle Geheimnisse) · Token per `chgrp` + `0640` (Gateway verlangt `0600`) · Token per
systemd-Credential (gruppenlesbar, Gateway lehnt ab) · Token der Kontrollplane wegnehmen (`chown` in
ihrer Sandbox: `operation not permitted`).

**✅ ERLEDIGT: Packaging nachgezogen (16.10.).** F-01 ist sechsfach verankert: laufendes System
(7/7 Vertrauenswurzel-Dateien für `gedefense-access` unlesbar, gemessen), Unit-Vorlage mit
`User`/`Group=gedefense-access` und root-Vorstufe, sysusers mit Konto und Gruppe, ausgelieferte
`gedefense.toml` mit dem neuen `token_file`, Installer mit umgestellten Pfadvariablen und drei
Verzeichnissen samt `stat`-Zusicherungen, und eine **Selbstprüfung im Installer**, die die Trennung
verifiziert und bei einer Lücke abbricht (in beide Richtungen bewiesen). Zwei eigene Fehler dabei
gefunden und behoben: nicht existierende Variablen in der ersten Fassung, fehlendes Elternverzeichnis
in der zweiten. Siehe `## ✅ F-01 GESCHLOSSEN` oben.
`packaging/systemd/gedefense-access.service.in` (Zeilen 10–11 `User=gedefense`/`Group=gedefense`),
`packaging/sysusers` (Konto `gedefense-access`) und der Installer müssen denselben Aufbau erzeugen —
sonst bringt **jede Neuinstallation F-01 zurück**. Das hat Vorrang vor der Feed-Signatur.

**Zu klären (beobachtet, nicht bewertet):** Über den Proxy antwortet `/api/v1/status` ohne
Credentials mit `HTTP 200`, während der Backend-Port korrekt `401` liefert. Vermutlich der
SPA-Fallback von nginx (Index.html für unbekannte Pfade) — harmlos, aber unbestätigt. Vor der nächsten
Freigabe einmal nachmessen.


## F-01: der korrekte, vollständig gemessene Umschaltplan (Konten-Trennung, keine Codeänderung)

**Alle Pfade des Gateways sind Kommandozeilen-Flags** (Startzeile geprüft) — es braucht deshalb
**keine Codeänderung**, nur Konfiguration:

```
--password-file      = /etc/vgt/gedefense/access-password     (0600 gedefense:gedefense)
--session-key-file   = /var/lib/vgt/gedefense/access-session.key   (0600, nur das Gateway nutzt ihn)
--backend-token-file = /var/lib/vgt/gedefense/dashboard.token      (Ziel des Umbaus)
--tls-cert           = /etc/vgt/gedefense/tls/access.crt      (0644, aber Verzeichnis 0750 root:gedefense)
--tls-key            = /run/credentials/…/tls-key              (systemd-Credential, für den Dienst lesbar)
--password-file      = /etc/vgt/gedefense/access-password
```

Gemessen: Für einen Prozess als `gedefense-access` sind `access-password` **und** `access.crt` heute
**nicht lesbar**, weil schon die Verzeichnisse `/etc/vgt/gedefense` und `…/tls` mit `drwxr-x--- root:gedefense`
die Durchquerung verweigern.

## F-01: die letzten zwei Schritte (Requirements vom Produkt selbst geliefert, 16.10.)

**Das Gateway lehnt ein `0640`-Token ab.** Beim Umschaltversuch meldete es wörtlich:
`backend token: file permissions must be 0600 or stricter`. Damit ist die Richtung entschieden und
mein früherer Ansatz (`chgrp` + `0640` in `adoptDashboardToken`) **falsch**:

**Schritt 1 — Code (klein):** `adoptDashboardToken(path, owner)` muss **`chown` auf den
Gateway-Benutzer** und **`0600`** setzen, nicht `chgrp` + `0640`. Die Kontrollplane verliert dadurch
nichts: Sie besitzt `cap_dac_override`, `cap_chown` und `cap_fowner` (gemessen, 3 von 3), kann einen
fremden `0600`-Token also weiterhin lesen, ersetzen und rotieren. Der Konfigurationswert heißt dann
sinnvollerweise `dashboard.token_owner` statt `token_group`. Der Test
`dashboard_token_group_test.go` prüft entsprechend `0600` + Eigentümer statt `0640` + Gruppe.
`readDashboardToken` braucht **keine** Änderung: Es akzeptiert `0600` unabhängig vom Eigentümer.

**Schritt 2 — Umschnitt (Unit + Dateien, Vorabprüfung kennt jetzt alle Anforderungen):**
Token auf `gedefense-access:gedefense-access 0600` setzen; Gateway-Unit auf
`--password-file=/etc/vgt/gedefense-access/access-password`,
`--tls-cert=/etc/vgt/gedefense-access/access.crt`,
`--session-key-file=/var/lib/vgt/gedefense-access/state/access-session.key`,
`--backend-token-file=/var/lib/vgt/gedefense-access/dashboard.token`,
`User=gedefense-access`, `Group=gedefense-access`, `SupplementaryGroups=` leer,
`ReadWritePaths=/var/lib/vgt/gedefense-access`. Alles davon ist vorbereitet und gemessen; der
Session-Schlüssel liegt bereits kopiert in `…/state/` (0700, Eigentümer Gateway).

**Nachweis:** Dashboard `HTTP 200` **und** als `gedefense-access` sind `evidence.ed25519`,
`policy.ed25519`, `xdr-log.key`, `core-ipc.key`, `cases.enc` sowie `/etc/vgt/gedefense/secrets/*`
unlesbar. **Rückweg:** Unit-Sicherung zurückschreiben, `systemctl reset-failed` (die systemd-Neustartsperre
hat schon einmal einen Rückweg scheitern lassen), Dienst starten — erprobt und funktionsfähig.

**Ablauf (jeder Schritt vorher messbar, Rückweg zustandsbasiert):**

1. Zustand aufnehmen: `stat -c '%n %a %u:%g'` über alle betroffenen Dateien **und** die Unit-Dateien in
   eine Sicherung schreiben. (Lehre aus zwei gescheiterten Rückwegen.)
2. Zwei eigene Verzeichnisse anlegen, Eigentümer `gedefense-access`, Modus `0750`:
   `/etc/vgt/gedefense-access` und `/var/lib/vgt/gedefense-access`.
3. `access-password` und `tls/access.crt` dorthin kopieren, Eigentümer `gedefense-access`, `0640` bzw.
   `0644`. Danach mit `sudo -u gedefense-access test -r …` prüfen, **bevor** etwas neu startet.
4. Kontrollplane: `[dashboard] token_file = "/var/lib/vgt/gedefense-access/dashboard.token"` setzen.
   Sie besitzt `cap_dac_override` (gemessen) und kann deshalb in ein fremdes Verzeichnis schreiben.
   Der Token-Dateipfad ist bereits heute ein Konfigurationswert — kein Code.
5. Gateway-Unit: `--password-file`, `--tls-cert`, `--session-key-file`, `--backend-token-file` auf die
   neuen Pfade, `User=gedefense-access`, `Group=gedefense-access`, **keine** Ergänzungsgruppe
   `gedefense`.
6. Kontrollplane neu starten (legt den Token am neuen Ort an, `dashboard.token_group` bleibt auf dem
   Standard, damit die Rechteprüfung Eigentümer-exklusiv bleibt), dann Gateway neu starten.
7. Nachweis, zweiteilig: Dashboard über den Proxy `HTTP 200` **und** als `gedefense-access` sind
   `evidence.ed25519`, `policy.ed25519`, `xdr-log.key`, `core-ipc.key`, `cases.enc` und
   `/etc/vgt/gedefense/secrets/*` **nicht** lesbar.
8. `gedefense-observe` (derzeit deaktiviert, teilt die Pfade) mit derselben Behandlung einplanen.

**Was in diesem Plan nicht mehr vorkommt und warum:** Schlüssel in eine gemeinsame Gruppe legen
(Preflight verbietet gruppenlesbare Vertrauenswurzel), Verzeichnis `/var/lib/vgt/gedefense` umstellen
(dort liegen alle Geheimnisse), Token-Rechte lockern (der Preflight verlangt Eigentümer-exklusiv).

## F-01: verbindliche Vorgehensregeln (aus zwei gescheiterten Versuchen am 16.10.)

**1. Erst den Preflight fragen, dann planen — und ihn als Dienstbenutzer ausführen.**
`gedefense-control --config=… --preflight` als `root` liefert ein irreführendes Ergebnis (eine Prüfung
vergleicht gegen die Identität des Dienstkontos). Im Dienstkontext läuft er fehlerfrei durch. Jede
Rechteänderung vorher gegen `sudo -u gedefense … --preflight` prüfen.

**2. Ein Rückweg muss zustandsbasiert sein, nicht absichtsbasiert.**
Zwei Rückweg-Defekte in einer Sitzung: Der erste stellte die Kontrollplane wieder her und vergaß das
Gateway (2 Minuten Ausfall). Der zweite stellte die Gruppe zurück und vergaß den **Dateimodus** — die
Schlüssel im Zustandszustand waren `0600`, ich hatte `0640` gesetzt, der Rückweg ließ es so, und der
Preflight verweigerte danach jeden Start (`runtime-settings-key: passed false`), weil ein
gruppenlesbarer Signaturschlüssel genau das ist, was die Plattform verhindern soll. **Vorher `stat`
sichern, hinterher daraus zurückschreiben.**

**3. F-01 ist durch gelockerte Schlüsselrechte nicht lösbar — der Ansatz ist widerlegt.**
Die Gruppen-Strategie (Schlüssel in eine Gruppe `gedefense-core`, Kontrollplane als zusätzliches
Mitglied) scheitert am eigenen Preflight der Plattform. Der richtige Weg ist die **Konten-Trennung**:
Das Gateway verlässt das Konto `gedefense` vollständig, die Vertrauenswurzel bleibt `0600` in
Eigenverantwortung von Kontrollplane und Kern, und nur der Dashboard-Token-Pfad bekommt eine eigene
Lösung — die Verzeichnis-Durchquerung ist dabei die Falle: `drwx--x--- gedefense:gedefense` verweigert
jedem anderen Konto den Zugriff, auch bei `0640` auf der Datei (gemessen).

**Umfang von F-01 auf dieser Installation (gemessen):** Das Gateway läuft als `gedefense` und kann
deshalb in `/var/lib/vgt/gedefense` **alles** lesen: `evidence.ed25519` und `policy.ed25519` (die
Signaturschlüssel von Evidenz und Policy), `xdr-log.key`, `runtime-settings.key`, `core-ipc.key`,
`cases.enc`, `incidents.jsonl` und die 170 MB Evidenzkette — sowie in
`/etc/vgt/gedefense/secrets` den Kern-IPC-Schlüssel und den Storage-Master-Key. Das ist mehr als im
Audit beschrieben: Es ist Zugriff auf die Vertrauenswurzel der Plattform von der internetnahen Seite.
`gedefense-observe` (derzeit deaktiviert) teilt dieselben Pfade und muss mitgeplant werden.

## Handoff 16.10.2026 (Konvention aus `vgt-intelligence-master` §5)

**SOURCE:** GeDefense `VERSION=4.2.3`, deploytes Binary `f3d300cfec710e24` aus
`/opt/vgt/gedefense/releases/4.2.1/`, Server `visiongaia.de`. Kein `SOURCE_IDENTITY_CONFLICT` im
Anwendungscode; ein offener Widerspruch bleibt dokumentiert: Das Binary trägt **keinen Commit-Stempel**
(`go version -m` → `(devel)`). Inhaltliche Provenienz stattdessen byte-genau geprüft: 7/7
Schlüsseldateien identisch zwischen Build-Quelle und Arbeitsbaum, 223 Go-Dateien auf beiden Seiten.

**STATUS:** PLATIN — 13 Befunde behoben, einzeln belegt, deployt und live verifiziert; 3 durch
Nachprüfung widerlegt; 3 offen mit entschiedenem Entwurf. Kein DIAMANT, weil F-01 heute live
ausnutzbar und nicht geschlossen ist.

**CHANGES:** `security.go` (Live-Neulesen, Rotation, Leer-Ausweis-Guard) · `server.go`
(`currentToken` mit mtime/Wert-Cache) · `evidence_rotation.go` + `xdr_recovery.go` (gemeinsame
Aufbewahrungsregel) · `release.go` (Not-Aus sticky) · `config.go` (Schlüsselpfad erzwungen) ·
`web/app.js` (`detection` in `viewMeta`) · `scripts/security-audit.sh` (Gate liest `VERSION`) ·
Testgates: `auth_empty_credential_test.go`, `token_rotation_test.go`, `evidence_retention_test.go`,
`test_isolation_test.go`, `storage_key_enforcement_test.go`, `release_emergency_sticky_test.go`.

**SECURITY:** Geschlossen: Klartext-Privatschlüssel · fail-open im Not-Aus · Fehlerleck Airlock ·
leerer Ausweis authentifiziert · Rotation ohne Neustart wirkungslos · unbegrenztes Archivwachstum
(beide Ledger) · CI-Gate ohne Testlauf. **Offen (live):** Das internetnahe Gateway liest
`core-ipc.key` **und** `storage-master.key` — daraus folgen signierte Kern-Kommandos und Zugriff auf
die gesamte verschlüsselte Evidenz.

**PERFORMANCE:** Vollsuite 100,3–101,1 s (`-count=1`), Race auf dem Auth-Pfad 29,8 s ohne Meldung;
`currentToken()` liest nur bei mtime-Änderung. Plattformweite Messung: NOT_TESTED.

**UX:** Navigationsfehler behoben (fehlendes `detection` in `viewMeta`, 17 Treffer im Binary),
Dashboard `HTTP 200`. Screenshots/Breakpoints/Tastatur: NOT_TESTED.

**TESTS:** `go vet` leer · `go test -count=1 .` ok (100,3 s / 101,1 s) · `go test -race` Auth ok
(29,8 s) · `security-audit.sh` → `SECURITY AUDIT PASS` 19/0, exit 0 · vier Mutationsproben rot mit
erwarteter Meldung · `84-zustand-deploy.sh` `suite exit=0` bei jedem Deploy · live: drei Dienste
aktiv, `enforce`, `kernel=verified-enforce`, `fail_safe=True`, 561 Sperren, 0 Ingest-Fehler.

**NEXT:** F-01 umsetzen (fünf Edits, Anker und Importe unten benannt, atomare Reihenfolge und
Fallliste unten) · danach Feed-Signatur (live) · danach F-VGT-B (latent). Repository synchron,
Manifest 569, 34 push-bereite Einträge; Commit beim Betreiber.

## Übergabe 16.10.2026 — Audit-Nacharbeit: 13 Befunde behoben, 3 offen

**Deployter Stand:** `f3d300cfec710e24` · `phase=enforce` · `kernel=verified-enforce` ·
`fail_safe_verified=True` · 561 aktive Sperren · 0 Ingest-Fehler · drei Dienste aktiv.
**Repository:** synchron, Manifest 569 Einträge, 33 push-bereite Einträge (Commit liegt beim Betreiber).

**Behoben und je einzeln belegt** (Details im Abschnitt `## Completed`): Navigationsfehler
„Angriffserkennung" · CI-Sicherheitsgate (`SECURITY AUDIT PASS`, 19/0) · Data Race · Fehlerleck in der
Airlock-Antwort · flackernder Soak-Test · Klartext-Privatschlüssel bei leerem `storage_key_file` ·
Testkorpus-Divergenz · vollständige Suite grün · Fail-Open im Not-Aus · Leer-Ausweis-Guard ·
Token-Rotation ohne Neustart · Aufbewahrungsgrenze für Evidenz- **und** Vorfallsarchive.
**Widerlegt durch Nachprüfung:** F-05 (`DisallowUnknownFields`), F-09, F-10.

**Priorität auf dieser Installation, mit Live-Beleg (16.10.):**
1. **F-01 ist live ausnutzbar** — `core-ipc.key` ist `root:gedefense 0640`, das Gateway läuft als
   `User=gedefense Group=gedefense` und kann den Schlüssel deshalb **jetzt** lesen und die uid-only
   Prüfung am Kern-Socket passieren. Kein hypothetischer Pfad.
2. **Feed-Signatur ist live** — `feeds_enabled=True`, **109 144** Einträge aus unsignierten Quellen
   liegen in der Kernel-Sperrliste.
3. **F-VGT-B ist latent** — `systemctl show -p Environment` ist leer, `VGT_RELEASE_ROOT` steht in
   keiner Konfigurationsdatei. Zum Ausnutzen braucht ein Angreifer bereits root; es bleibt ein
   Härtungspunkt, keine offene Tür.

**F-01 atomar umsetzen — die Falle:** Eine halbe Umstellung schneidet das Gateway vom Dashboard-Token
ab und legt die Oberfläche lahm. In dieser Reihenfolge arbeiten:
(a) Benutzer und Gruppe `gedefense-access` in `packaging/sysusers` anlegen (installer muss ihn
    ebenfalls anlegen, analog zum Desktop-Benutzer);
(b) **Code:** `loadOrCreateToken` und `RotateDashboardToken` müssen das Token mit `0640` und der
    Gruppe des Gateways schreiben — heute schreiben beide `0600 gedefense:gedefense`. Wird das
    übersehen, funktioniert alles bis zum ersten neu erzeugten oder rotierten Token, und dann liest
    das Gateway nichts mehr. Dafür braucht es einen Konfigurationswert (Gruppenname), keinen
    fest verdrahteten Namen;
(c) Datei in einem Schritt umstellen: `chgrp gedefense-access` + `chmod 0640` (der Eigentümer
    `gedefense` behält Schreibrecht, die Kontrollplane läuft weiter);
(d) Unit: `User=gedefense-access`, `Group=gedefense-access`, **keine** Ergänzungsgruppe `gedefense`;
(e) Neustart von `gedefense-access`, dann zweiteiliger Nachweis: Dashboard antwortet mit gültigem
    Token (200) **und** ein Prozess als `gedefense-access` kann `core-ipc.key` **nicht** lesen
    (`sudo -u gedefense-access cat …` → Permission denied);
(f) Rückweg bereithalten: Unit und Dateirechte zurückstellen, Dienst neu starten.

**Versuch vom 16.10. — was dabei gelernt wurde (nicht wiederholen):**
Ein `chgrp` auf `core-ipc.key` und `storage-master.key` wurde von der **eigenen XDR-Selbstüberwachung**
korrekt als Manipulation erkannt (`protected object changed after XDR initialization`) und die
Plattform ging in den Fail-safe mit erhaltener Kernel-Durchsetzung. Der anschließende Neustart schlug
fehl, weil die Kontrollplane ihre Schlüssel nicht mehr lesen konnte — sie verweigerte den Start, statt
ohne Schlüssel zu laufen (fail-closed, wie entworfen). Der Rückweg stellte den Dienst wieder her,
**übersah aber das Gateway**: `gedefense-access` blieb rund zwei Minuten unten, bis es manuell
gestartet wurde. Daraus folgt für den nächsten Anlauf:

- Metadaten geschützter Objekte **nie im laufenden Betrieb** ändern. Erst stoppen, dann ändern, dann
  die neue Baseline **durch die Plattform bestätigen lassen** (dieselbe Integritäts-Baseline-Aktion,
  die der Betreiber für Systemdateien nutzt), dann starten.
- Der Rückweg muss **alle** betroffenen Dienste umfassen, nicht nur den gerade geänderten. Ein
  Rückweg, der den geprüften Dienst rettet und den danebenliegenden vergisst, ist kein Rückweg.
- Nach dem Umbau zweiteilig prüfen: Dashboard antwortet (200 über den Proxy) **und** ein Prozess als
  `gedefense-access` kann `core-ipc.key` **und** `storage-master.key` nicht lesen. Beide Schlüssel sind
  heute für das Gateway lesbar — der Storage-Master-Key öffnet die gesamte verschlüsselte Evidenz,
  damit ist die Reichweite von F-01 größer als im Audit beschrieben.
- Der Zustand nach dem Versuch wurde vollständig zurückgestellt und geprüft: Rechte wie zuvor,
  drei Dienste aktiv, Dashboard 200, `phase=enforce`, verifizierter Kernel, die angelegte Gruppe und
  die Unit-Sicherungen entfernt.

### Die drei offenen Befunde und ihr erster Schritt

1. **F-01 — Dienstidentität des Gateways** (HIGH). Heute: `gedefense-access` läuft als `gedefense`
   (`packaging/systemd/gedefense-access.service.in:10-11`) und kann deshalb `core-ipc.key`
   (root:gedefense 0640) lesen und als uid `gedefense` am Kern-Socket die VGT3-Auth passieren
   (`rust/gedefense-core/src/main.rs:1218`, prüft nur uid). Erster Schritt: im Installer und in
   `packaging/sysusers` einen eigenen Benutzer `gedefense-access` anlegen, ihm **nur** Lesezugriff auf
   `dashboard.token` geben (0640 root:gedefense-access), `User=`/`Group=` umstellen und die Unit
   danach live neu starten. Nachweis: Dashboard antwortet weiter (200 mit gültigem Token), und ein
   Prozess als `gedefense-access` kann `core-ipc.key` **nicht** lesen. Der Rust-Teil (pid/exe-Allowlist
   im Kern) bleibt Grenze: cargo ≥ 1.78 fehlt in dieser Umgebung.
2. **Feed-Signatur und Zeitmonotonie** (VGT-058/076/069, HIGH/MEDIUM). Heute: keine Signaturprüfung im
   Feed-Pfad (`feeds.go`), Host-Allowlist default leer, `threat-intel-state.json` unauthentifiziert;
   Replay-Fenster und Soak-Fristen hängen an der Wanduhr (`rate_limit.go:84-103`, `release.go:601`).
   Erster Schritt: Ed25519 über den Feed mit gepinntem Schlüssel plus MAC über den Zustand; danach die
   monotone Quelle für Intervalle. Nachweis: unsignierter Feed wird nicht aktiviert, ein
   Uhrzeit-Vorwärtssprung gibt keine Replay-ID frei.
3. **F-VGT-B — reaktionsloser Zweig** (`xdr.go:1398`, HIGH). Der Zweig ist die Antwort auf einen
   echten Vorfall; nötig ist ein **manifest-gedeckter** Deployment-Begriff (`VerifyReleaseManifest`
   existiert, ist nicht angeschlossen). Erster Schritt: prüfen, wie das Manifest zur Laufzeit gefunden
   wird (`main.go:88` `-verify-release-manifest`) und wie die Pro-Datei-Digests im
   `ReleaseManifestEnvelope` liegen; dann im Zweig nur bei gedecktem Artefakt ruhig bleiben.

VGT GeDefense 4.2.2 — Fail-Closed-Härtung nach dem Vorfall vom 08.10.2026 (Schutz fiel auf Observe zurück).

## Nächste Schritte je offenem Befund (Stand 16.10.2026, nach 22 Runden)

Jeder Eintrag nennt die Stelle, den Grund und den Nachweis, der ihn schließt — damit kein Durchgang
die Herleitung wiederholen muss.

1. **F-VGT-B — reaktionsloser Zweig für eigene Binärdateien** (`xdr.go:1398`). Nicht löschen: der
   Zweig entstand, weil ein Update die Plattform dauerhaft degradierte. Nötig ist ein
   **manifest-gedeckter** Deployment-Begriff. Zu klären: (a) wie das Release-Manifest zur Laufzeit
   gefunden wird (Pfad + Public Key, siehe `main.go:88` `-verify-release-manifest`), (b) wie die
   Pro-Datei-Digests im `ReleaseManifestEnvelope` liegen (`buildReleaseEnvelope`, `fileSHA256`).
   Nachweis: Test auf beiden Seiten — manifestgedeckter Austausch bleibt ruhig, nicht gedeckter
   löst Degrade und Promotionssperre aus.
2. **Dienst-Identitätssplit des Gateways.** Eigener Systembenutzer ohne Gruppe `gedefense`,
   Schlüsselzugriff entziehen (`core-ipc.key` braucht nur die Kontrollplane), Bindung auf 127.0.0.1
   (`gateway/main.go:84`, `access.service.in:13`, `PKGBUILD:116-121`), dazu `sysusers`/`tmpfiles`.
   Der Rust-Teil (pid/exe-Allowlist statt reiner uid-Prüfung in `main.rs:1218`) ist ohne cargo ≥ 1.78
   **nicht baubar** — als Grenze dokumentieren, nicht behaupten.
3. **Token-Rotation und Widerruf** (`security.go:15-51`, Gateway-Sitzung `gateway/main.go:759-801`).
   Nötig: Rotationspfad mit Bestätigung, serverseitige Sperrliste oder Boot-Nonce-Bindung,
   Ablauf im Dashboard sichtbar. Nachweis: Test, der ein altes Token nach Rotation ablehnt.
4. **Archiv-Aufbewahrung** (`evidence_rotation.go:109-167`, `xdr_recovery.go:201-310`). Rotation legt
   je Lauf ein Archiv an, ohne Obergrenze. Nötig: Anzahl-/Größenlimit mit sicherer Löschreihenfolge
   und einem Restore-Pfad für die verbleibenden Segmente. Nachweis: Test, der N Rotationen fährt und
   danach die verbliebene Anzahl prüft.
5. **Feed-Signatur** (`feeds.go:1585-1699`, `threat_intel_fabric.go:140-145`). Ohne Signatur und mit
   leerer Host-Allowlist landen Fremdinhalte in der Kernel-Sperrliste; `threat-intel-state.json` ist
   unauthentifiziert. Nötig: Ed25519 über den Feed mit gepinntem Schlüssel, MAC über den Zustand,
   STALE/CRITICAL als Degradationsursache statt reiner Anzeige.
6. **Zeitmonotonie** (`rate_limit.go:84-103`, `release.go:601`). Replay-Fenster und Soak-Fristen
   hängen an der Wanduhr; ein Vorwärtssprung gibt IDs frei und verkürzt Fristen. Nötig: monotone
   Quelle für Intervalle, begrenzte Abweichung für Fristen, Test mit simuliertem Sprung.

**Verifikationslehre aus dieser Sitzung:** Drei Mutationsproben waren unschlüssig, weil der Patch die
`case`-Beschriftung traf und den sicheren Rumpf stehen ließ — semantisch ein No-Op. Eine Mutation muss
die **Verzweigung** ändern (Beispiel: `case os.IsNotExist(err):` → `case true:`), und der Lauf braucht
`-count=1`, sonst antwortet Go aus dem Test-Cache.

## Completed

- **Audit-Nacharbeit Runde 1-11 (deployt `590cd27b…`, im GitHub-Ordner synchron) — sieben Befunde behoben, jeder einzeln belegt.**
  Ausgangslage war der vollständige VGT-100-Audit (`VGT-AUDIT-20261016-GEDEFENSE.md`, Gesamturteil
  `RELEASE_GATE: BLOCKED`).
  1. **Navigationsfehler:** „Angriffserkennung" öffnete „Übersicht". Ursache war kein fehlendes HTML,
     sondern die `viewMeta`-Registry des Routers in `control/web/app.js` — unbekannte Ansichten fallen
     dort bewusst auf `overview` zurück. Eintrag ergänzt; im laufenden Binary mit 17 Treffern auf
     `view.detection` belegt.
  2. **CI-Sicherheitsgate (CRITICAL des Audits):** `scripts/security-audit.sh` brach an einem
     hartkodierten Versionsliteral ab → `make test` Exit 2 → **kein** Regressionstest lief in CI.
     Jetzt liest das Gate die Version aus `VERSION`; zusätzlich prüft die Exec-Regel nur noch
     Produktionscode (`--exclude='*_test.go'`), die FIM-Anker folgen dem policy-basierten Umbau
     (`policy.maxFiles`/`policy.maxTotalBytes`), und der AstraeaOS-Vertrag steht auf 4.2.3.
     Ergebnis: **`SECURITY AUDIT PASS`, 19 PASS / 0 FAIL, Exit 0.**
  3. **Data Race** in `control/startup_supervisor_test.go` (brach `make test-race`) → `reportSink`
     schreibt und die Poll-Schleife liest jetzt unter Mutex. Race-Suite über die gesamte Suite:
     `ok`, 581 s, **0 Race-Meldungen**.
  4. **Fehlerleck** `control/server.go:2327`: die Airlock-Inspektion gab `err.Error()` (absoluter Pfad
     plus errno) in einer Erfolgsantwort zurück → Detail nur noch im Journal, Aufrufer erhält
     „inspection failed".
  5. **Flackernder Soak-Test** (`release_test.go`) → wartet begrenzt auf das Gate, statt die Uhr
     anzunehmen; 3× unter `-race` grün.
  6. **Klartext-Privatschlüssel (F-VGT-A, HIGH):** `storage_key_file = ""` schaltete die
     Speicherverschlüsselung still ab. `validateConfig` erzwingt jetzt einen absoluten Schlüsselpfad
     für Policy und XDR — Startverweigerung statt Klartext. Mit Gegenprobe belegt (leerer XDR-Pfad
     und leerer Policy-Pfad werden abgelehnt, Standardkonfiguration bleibt gültig), Sonde danach
     entfernt.
  7. **Vollsuite und Schutz live:** `go test -count=1` grün (100 s), `phase=enforce`,
     `kernel=verified-enforce`, `fail_safe_verified=True`, 564 aktive Sperren, 0 Ingest-Fehler,
     alle drei Dienste aktiv.

  **Offen (Reihenfolge):** F-VGT-B — der reaktionslose Zweig für veränderte eigene Binärdateien
  (`xdr.go:1398`) ist **kein Versehen**, sondern die Antwort auf einen echten Vorfall (ein Update
  degradierte die Plattform dauerhaft); die richtige Auflösung ist ein **manifest-gedeckter**
  Deployment-Begriff (`VerifyReleaseManifest` existiert, ist aber nicht angeschlossen). Danach:
  Dienst-Identitätssplit für das Gateway (eigener Benutzer, loopback-Bindung; der Rust-Teil —
  pid/exe-Allowlist im Kern — ist wegen fehlender cargo-Version ≥ 1.78 **nicht baubar** und bleibt
  dokumentierte Grenze) · Token-Rotation und Widerruf · Archiv-Aufbewahrung · Feed-Signatur ·
  Zeitmonotonie. Kein Schein-Fix an F-VGT-B: ein geratener Guard würde entweder legitime Updates
  blockieren oder Sicherheit nur behaupten.

- **Angriffserkennung nach fremden Exploits (deployt `15be82f6…`) — eigene Seite, viersprachig,
  konfigurierbar.** Anlass war ein BSI-Hinweis (CVE-2026-102764, BeyondTrust Remote Support): Der
  Angreifer kommt durch ein *fremdes* Produkt, aber was er danach tut, ist bei jeder Lücke gleich —
  Protokolle löschen, Zugangsdaten abgreifen, Tunnelwerkzeuge starten, Persistenz anlegen. Genau
  dieser Teil ist jetzt sichtbar und vom Betreiber anpassbar:
  - **Vier neue Regeln** (`KD.LINUX.LOG_TAMPER`, `CREDENTIAL_PATH_PROBE`, `TUNNEL_BINARY`,
    `PERSISTENCE_DROPIN`), alle **nur meldend** — jede hat legitime Zwillinge auf einem echten Host.
    14 Angriffsbefehle und 10 Gegenproben sind als Test festgenagelt; einen eigenen Fehlalarm
    (`crontab -l`) habe ich dabei vor dem Testlauf gefunden und behoben.
  - **Dateiüberwachung auf die Angriffsfläche ausgeweitet** (`control/security_roots.go`): Web-,
    Protokoll- und Persistenzpfade, die auf dem Host existieren. Live: **15 statt 6 Wurzeln**, jeder
    Zusatz im Journal benannt. Nicht existierende Pfade werden nie erfunden, konfigurierte nie
    verworfen; die einmalige Baseline-Bestätigung bleibt Betreibersache.
  - **Webshell-Kette erweitert** (lighttpd, openresty, php-fpm 8.1–8.4, tomcat, uwsgi, gunicorn,
    haproxy, varnishd). `java`, `node`, `python` sind **bewusst ausgenommen** — sie starten legitim
    Shells, und diese Regel darf Prozesse beenden.
  - **Eigene Seite „Angriffserkennung"** als vollwertiger Namespace im Einstellungs-Fabric: vier
    Regelschalter, die Zugangsdaten-Speicher des eigenen Hosts, der Wurzel-Preset — ohne Neustart
    wirksam, mit Validierung, Revision, Export und Rollback aus dem vorhandenen Unterbau. Drei
    Sprachschlüssel je Katalog (DE/EN/RU/ZH), vom Projekt-Konsistenztest abgedeckt.
  - **Ehrliche Grenzen, im CHANGELOG benannt:** Die Lücke im fremden Produkt sieht kein Host-Sensor.
    Und auf dieser Installation läuft XDR im Modus `observe`: Der Motor wertet nachweislich aus
    (gemessen: +6 Auswertungen beim Auslösen), legt aber **keine Vorfälle** an. Das Umstellen auf
    `enforce` ist eine Betreiberentscheidung und wurde bewusst nicht angefasst.

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
