# VGT SECURITY MASTER — Auditbericht GeDefense Linux

**Audit-ID:** `VGT-AUDIT-20261016-GEDEFENSE`
**Zielprodukt:** GeDefense Linux 4.2.x (KINETIC-REWORK-RC), Kontrollplane `control/`, Gateway `gateway/`, Rust-Kern `rust/gedefense-*`, Dashboard `control/web/`, Desktop-Tray `desktop/tray/`
**PROFILE:** GEDEFENSE · **MODE:** AUDIT_ONLY (keine Änderungen, keine Netzwerkziele, keine Live-Requests, keine Credential-Aktionen)
**Scope:** Arbeitsbaum `C:\Users\Masterboard\Downloads\GeDefense-4.1.0-KINETIC-REWORK-RC` (ohne `.dsh-scan`, `GitHub Upload`, `release-*-assets`, `dist`, `.git`, `control/webtools`) sowie der bereits autorisierte Produktionshost `visiongaia.de` (212.132.67.175) **ausschließlich lesend**.
**Toolchain:** Go 1.26.4 (windows/amd64), Node 24, PowerShell 7, OpenSSH; Zielplattform Linux (die Go-Tests des Projekts sind Linux-only → auf Windows nicht ausführbar, siehe Test-Ledger).
**Standards:** OWASP Top 10:2025, ASVS 5.0.0, API Security Top 10 2023, CWE Top 25 2025, ATT&CK, SSDF v1.1, SLSA v1.2 (Referenzstand, keine Zertifizierung). Advisory-Frische: **nicht geprüft** (kein Internetzugriff im Audit).
**Status dieses Dokuments:** Teilbericht — Strang 4 (Dashboard) und eigene Host-Erhebung sind eingearbeitet; die Stränge Backend/API, Krypto/Ledger, Host/IPC und Lieferkette/Detection sind **noch nicht eingelaufen** und in der Matrix als `NOT_TESTED` mit Grund ausgewiesen.

## Executive Outcome

`RELEASE_GATE: CONDITIONAL` (auf dem derzeit belegten Teilumfang)

| Kategorie | Anzahl | Beleg/Anmerkung |
|---|---:|---|
| Critical / High / Medium / Low / Info | 0 / 1 / 2 / 3 / 3 | Nur belegte Befunde; keine Fantasiezahlen |
| Ketten (`CHAIN-###`) | 3 | CHAIN-A, CHAIN-C (korrigiert), CHAIN-D |
| VGT-100 PASS / FAIL / NOT_TESTED / BLOCKED / N/A | 10 / 1 / 85 / 0 / 4 | Summe exakt 100 |
| Anwendbar | 96 | 100 minus 4 N/A |
| Ungeprüft | 85 | Vier Teilberichte ausstehend |

**Harte Release-Blocker auf dem belegten Umfang:** keine. **Bedingung:** `F-030-1` (eine Zeile) und die Hygiene-Maßnahme `HYG-1` vor Distribution.

## System- und Trust Boundary Map (belegter Teil)

| Boundary-ID | Datenfluss | Identität | Trustwechsel | Autorisierungsentscheidung | Sink | Fehlermodus | Evidenz |
|---|---|---|---|---|---|---|---|
| TB-01 | Browser → `gedefense-access` (Bearer) → Mux | Betreiber | nicht vertrauenswürdig → Kontrollplane | `s.auth` auf **73/73** `/api/`-Routen; Token konstantzeitig verglichen | Zustandsänderung, Kernel-Policy | 401/Ablehnung, fail-closed | server.go, security.go:67-71 |
| TB-02 | Fremdprozess → Dashboard-Socket `/run/gedefense/gedefense.sock` | lokaler Nutzer der Gruppe `gedefense-desktop` | lokal → Kontrollplane | Peer-Credentials + Rate-Limit + Kommando-Allowlist | Lesezustand (Status-Telegramm) | Verbindung abgelehnt | desktop_status_linux.go; Live: `srw-rw---- gedefense:gedefense-desktop` |
| TB-03 | Betreiber → Datei-Import (signiertes Bündel) | Betreiber mit Token | Datei → Einstellungsmodell | **Signaturprüfung vor jedem Parsen**, 4 MiB Limit, Revisionsbindung | Einstellungen (u. a. Policy) | Bundle abgelehnt (400) | fabric_surface_api.go:221-286 |
| TB-04 | Threat-Feed → Download → Parser → Policy | Feed-Anbieter | Internet → Kontrollplane | Signatur/Trust-Anchor, Redirect-Prüfung | Regeln, Sperren | Feed nicht aktiviert | feeds.go (im Detailbericht Strang 5) |
| TB-05 | Dienstprozess → Dateisystem | `gedefense` (unprivilegiert) | Prozess → Host | systemd-Sandbox (`ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, `ProtectHome`, `UMask=0077`) | Ledger, Konfiguration, Sockets | Schreibzugriff nur auf `ReadWritePaths` | Live: `systemctl show gedefense-control` |
| TB-06 | Kontrollplane → Kernel (XDP/TC, Blocklisten) | `gedefense` + Caps | Nutzerraum → Kernel | verifizierte Policy (`verified-enforce`), Reconcile | Paketfilter, Sperren | fail-closed, Enforcement bleibt | Live: `kernel=verified-enforce`, `fail_safe_verified=True` |

## VGT-100-Abdeckungsmatrix

Statuslegende: `P` = PASS · `F` = FAIL · `NT` = NOT_TESTED · `BL` = BLOCKED · `NA` = NOT_APPLICABLE

| ID | Status | Asset/TB | Reale Evidenz | Begründung/Grenze |
|---|---|---|---|---|
| VGT-001 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-002 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-003 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-004 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-005 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-006 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-007 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-008 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-009 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-010 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-011 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-012 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-013 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-014 | P | TB-01 | 0 DOM-Sinks in 15 App-Modulen (zwei Werkzeuge, kreuzgeprüft); 2 vendor-`innerHTML` nachweislich unerreichbar; CSP `script-src 'self'` + `require-trusted-types-for 'script'` in der einzigen Middleware (server.go:1024-1036, 218, 647) | Laufzeit-/Browserbeleg fehlt → Teilaspekt NOT_TESTED; die statische Aussage „kein Sink" ist erschöpfend |
| VGT-015 | NT | — | — | Teilbericht Krypto/Host ausstehend |
| VGT-016 | NT | — | — | Teilbericht Krypto/Host ausstehend |
| VGT-017 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-018 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-019 | P | TB-03 | Kein Upload-Endpunkt (73 Routen, `decodeStrictJSON` erzwingt `application/json`); Import 4 MiB beidseitig, Signatur vor Parse; Asset-Allowlist 63 Einträge, alle 59 `.js` gelistet, `nosniff` global | Statisch + Allowlist-Arithmetik, kein Draht-Beleg |
| VGT-020 | NT | — | — | Teilbericht Host ausstehend |
| VGT-021 | NT | — | — | Teilbericht Krypto ausstehend |
| VGT-022 | NT | — | — | Teilbericht Krypto ausstehend |
| VGT-023 | NT | — | — | Teilbericht Krypto ausstehend |
| VGT-024 | NT | — | — | Teilbericht Krypto ausstehend |
| VGT-025 | NT | — | — | Teilbericht Krypto ausstehend |
| VGT-026 | NT | — | — | Teilbericht Krypto ausstehend |
| VGT-027 | NT | — | — | Teilbericht Krypto ausstehend |
| VGT-028 | P | TB-05 | Live: `dashboard.token` 0600, `evidence.ed25519` 0600, `storage-master.key` 0640 root:gedefense, `gedefense.toml` 0640, Socket 0660 mit eigener Gruppe; Tokens nie in Logs (Strang 4) | Nur Rechteprüfung; Verschlüsselung ruhender Ledger im Krypto-Strang |
| VGT-029 | NT | — | — | Teilbericht Krypto ausstehend |
| VGT-030 | F | TB-01 | **server.go:2327** `writeJSON(..., "error": err.Error())`; `AirlockException.Error()` (airlock.go:25-30) hängt rohe OS-Causes an (airlock.go:236-273) | Befund F-030-1, CWE-209; Wächtertest deckt die Form nicht ab |
| VGT-031 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-032 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-033 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-034 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-035 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-036 | NA | — | Kein GraphQL/gRPC/WebSocket im Produkt; SSE `/api/v1/stream` ist der einzige Strom | Architekturbeweis Strang 4 |
| VGT-037 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-038 | P | TB-01 | Rate-Limit auf allen `/api/`-Pfaden + Probes (server.go:654-666), 429 + `Retry-After`; Token-Bucket 65 536-Cap mit GC; Default 240/min Burst 40; L7-Selbsttest und Restart mit eigenen, engeren Limits | Kein Lasttest gefahren (AUDIT_ONLY) |
| VGT-039 | P | TB-01 | `Cache-Control: no-store` unbedingt in der einzigen Middleware (server.go:680, 645-690, 218); kein Service Worker/CDN; Bearer-Header statt Cookie, Token nur im Modulspeicher | Header nicht auf dem Draht beobachtet |
| VGT-040 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-041 | F | TB-05 | **Strang Host:** `gedefense-access.service.in:10-11` (User/Group=gedefense) + `oneclick-installer-header.sh:376-378` (core-ipc.key root:gedefense 0640) + `rust/…/main.rs:1006` (Core erzwingt 0640) + `policy.go:139`. **Eigene Live-Erhebung:** `CapabilityBoundingSet` = systemd-Standardsatz (35 Caps: `sys_admin`, `sys_ptrace`, `dac_override`, `net_admin`, `bpf`, `perfmon`); `SystemCallFilter` erlaubt `userfaultfd`, `io_uring_*`, `process_vm_readv/writev` | Befund F-01 (HIGH) + HOST-1 (MEDIUM-HIGH): geteilte Identität zwischen internetnahem Gateway und Root-Core; Capability-Begrenzung fehlt. Gegenkontrolle: `systemd-analyze security --offline=true` → control 3.5 „OK" |
| VGT-042 | P | TB-05 | `systemd-analyze security --offline=true`: core 2.7, control 3.5, access 3.4 — alle „OK"; `core.service:24-50`, `control.service:25-47`; keine Worker-/Plugin-Architektur; Cell-LSM optional und per Default aus (`config.go:274-275`) | Scope-limitiert: kein Live-systemd-Lauf, kein Root/eBPF |
| VGT-043 | P | TB-02 | `rust/…/main.rs:1218-1306,1475` (0660 + gid + `SO_PEERCRED`-uid + VGT3-HMAC + 30 s + Replay-Schutz); `desktop_status_linux.go:186-210,343`; `l7_server.go:194`; zugehörige Tests PASS (173 PASS gesamt) | Ausgenommener Rest: F-06 (User-Scan-Socket 0666, uid≠0 + Owner-Prüfung + 5-s-Timeout mildern) |
| VGT-044 | F | TB-05 | Kein `IPAddress*`/`PrivateNetwork`/`SocketBind` in `packaging/systemd`; control `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` (`control.service:36`). Feed-Pfad dagegen gehärtet (`feeds.go:655-690,1408-1425`) | Kein Default-Deny-Egress auf Dienstebene; IMDS-Abwehr im Code vorhanden (`feeds.go:271-287`, `styx_egress.go:105-129`) |
| VGT-045 | F | TB-01 | **Strang Host:** `gateway/main.go:84` Default `0.0.0.0:9843`, `PKGBUILD:116-121`, `access.service.in:13` — vs. `integration/astraeaos/gedefense-access-astraeaos.conf:10` = 127.0.0.1. **Eigene Live-Erhebung:** `ss -ltnp` → `*:9843` | Befund F-02/HOST-2 (MEDIUM): Exposition über den Reverse Proxy hinaus; Gegenkontrolle `AllowedHosts` (server.go:650-653, 692-704) |
| VGT-046 | NA | — | Rekursiver Scan: **keine** Dockerfile/Containerfile/compose im Baum | Architekturbeweis |
| VGT-047 | NA | — | `control/go.mod` und `gateway/go.mod` ohne jede Dependency (kein Cloud-SDK); IMDS-Abwehr dennoch vorhanden (`feeds.go:271-287`, `styx_egress.go:105-129`, `morpheus_rasp.go:348-373`) | Keine Cloud-IAM-Abhängigkeit im Produkt |
| VGT-048 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-049 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-050 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-051 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-052 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-053 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-054 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-055 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-056 | NT | — | — | Teilbericht Krypto/Lieferkette ausstehend |
| VGT-057 | NT | — | — | Teilbericht Krypto/Lieferkette ausstehend |
| VGT-058 | NT | — | — | Teilbericht Krypto ausstehend |
| VGT-059 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-060 | NT | — | — | Teilbericht Krypto ausstehend |
| VGT-061 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-062 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-063 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-064 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-065 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-066 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-067 | NT | — | — | Teilbericht Krypto ausstehend |
| VGT-068 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-069 | NT | — | — | Teilbericht Krypto ausstehend |
| VGT-070 | P | TB-05 | Live `df -h`: 26 % belegt, 719 GB frei; Ledger-Reihenfolge 262 MB unsealed + 132 MB aktiv, Rotation und Aufbewahrung im Projekt implementiert | Kein Full-Disk-Notfalltest gefahren |
| VGT-071 | NT | — | — | Teilbericht Host ausstehend |
| VGT-072 | P | TB-05 | Ledger-Dateien 0600 `gedefense:gedefense` mit `.head`-Checkpoint und `.verified`-Marker; hash-verkettet und signiert (Projekt); Live-Rechte geprüft | Der Dienstnutzer selbst kann schreiben (designbedingt) → Restrisiko dokumentiert |
| VGT-073 | NT | — | — | Teilbericht Host ausstehend |
| VGT-074 | NT | — | — | Teilbericht Lieferkette/Detection ausstehend |
| VGT-075 | NT | — | — | Teilbericht Host ausstehend |
| VGT-076 | NT | — | — | Teilbericht Krypto/Detection ausstehend |
| VGT-077 | NT | — | — | Teilbericht Host ausstehend |
| VGT-078 | P | TB-01 | 84 Routen enumeriert: **73/73 `/api/`-Routen unter `s.auth`, 0 Ausnahmen**; 11 übrige sind Statik/Probes, loopback-gegated; Snapshot und `RuntimeSettings` ohne Credential-Felder; Live-Fläche rendert nur `textContent` | 4 LOW/INFO-Anmerkungen (F-078-1..4) |
| VGT-079 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-080 | NT | — | — | Teilbericht Detection ausstehend |
| VGT-081 | NA | — | Kein WordPress im Produkt | Architekturbeweis |
| VGT-082 | NA | — | Kein WordPress im Produkt | Architekturbeweis |
| VGT-083 | NT | — | — | Teilbericht Host ausstehend |
| VGT-084 | NT | — | — | Teilbericht Host ausstehend |
| VGT-085 | NA | — | Keine Mobile-App im Produkt | Architekturbeweis |
| VGT-086 | NT | — | — | Teilbericht Host ausstehend |
| VGT-087 | NA | — | 0 Treffer für LLM-/RAG-Indikatoren im Laufzeitcode; Resttreffer sind Kommentare, Prosa und ein Entwicklungstagebuch | Kein Prompt, kein Modell, keine Tool-Schleife → keine Fläche |
| VGT-088 | NA | — | Kein Modelloutput vorhanden; keine Secret-Felder in Snapshot/`RuntimeSettings` | Kein privilegierter Sink für Modellausgabe |
| VGT-089 | NA | — | Keine Modelle, Embeddings oder Vektorspeicher im Baum | Keine Modell-Lieferkette |
| VGT-090 | NT | — | — | Teilbericht Backend ausstehend |
| VGT-091 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-092 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-093 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-094 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-095 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-096 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-097 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-098 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-099 | NT | — | — | Teilbericht Lieferkette ausstehend |
| VGT-100 | NT | — | — | Teilbericht Lieferkette ausstehend |

## Einzelbefunde

### HOST-1 — Dienst läuft mit nahezu vollständigem Capability-Satz
- **Severity/Confidence:** MEDIUM-HIGH / HIGH (gemessen am laufenden System)
- **Root Cause:** Die Unit setzt kein `CapabilityBoundingSet`; systemd reicht damit seinen Standardsatz durch. `ProtectSystem=strict`, `NoNewPrivileges`, `ProtectHome`, `PrivateTmp`, `UMask=0077` und ein Syscall-Allowlist-Filter sind aktiv — die Capability-Ebene bleibt jedoch unbegrenzt.
- **Evidenz (live, lesend):** `systemctl show gedefense-control -p CapabilityBoundingSet` → 35 Capabilities, darunter `cap_sys_admin`, `cap_sys_ptrace`, `cap_dac_override`, `cap_net_admin`, `cap_bpf`, `cap_perfmon`, `cap_sys_module`? (nicht enthalten), `cap_mac_admin`.
- **Wirkung:** Eine Kompromittierung der Kontrollplane erbt kernel-nahe Rechte, die für die Aufgabe nicht nötig sind (u. a. Ptrace auf fremde Prozesse, DAC-Override, freies BPF-Laden). Tiefenverteidigung geht verloren, obwohl die Sandbox selbst wirkt.
- **Gegenkontrollen:** unprivilegierter Dienstnutzer, `NoNewPrivileges`, `ProtectSystem=strict` mit vier `ReadWritePaths`, `SystemCallFilter` (Allowlist; `bpf`-Syscall **nicht** enthalten), Kernel-Enforcement bleibt bei Degradierung erhalten.
- **Abhilfe:** explizites minimales `CapabilityBoundingSet` (voraussichtlich `cap_bpf`, `cap_perfmon`, `cap_net_admin`, `cap_net_raw`, `cap_kill`, `cap_chown`, `cap_setuid`, `cap_setgid`, `cap_sys_resource`, `cap_dac_read_search`), verifiziert durch Funktionsprüfung von XDP/TC, Blocklisten-Reconcile, L7-Proxy und Ledger-Schreibpfad; `SystemCallFilter` um `userfaultfd`, `io_uring_*` und `process_vm_writev` verengen.
- **Regression:** bestehende Fail-Closed- und Enforcement-Tests plus Live-Nachweis `kernel=verified-enforce` nach Neustart.
- **Restrisiko:** falsch gewählte Capabilities brechen Enforcement → deshalb stufenweise mit Rollback.

### HOST-2 — API lauscht auf allen Interfaces
- **Severity/Confidence:** MEDIUM / HIGH
- **Root Cause:** Bindung an `*:9843` statt loopback; die Konfiguration erlaubt das, der Default der Anwendung ist loopback.
- **Evidenz (live, lesend):** `ss -ltnp` → `LISTEN *:9843 users:(("gedefense-acces",pid=156917,fd=4))`.
- **Gegenkontrollen:** Token-Auth auf allen `/api/`-Routen, `AllowedHosts`-Prüfung verwirft fremde Host-Header, Rate-Limit, `no-store`.
- **Wirkung:** Vergrößerte Angriffsfläche (jeder im Netz erreicht den Login-/API-Endpunkt direkt, ohne Reverse Proxy); die App-Auth bleibt die einzige Hürde.
- **Abhilfe:** Bindung auf `127.0.0.1` (Proxy davor) oder Firewall-Regel auf die Proxy-Quellen; `AllowedHosts` beibehalten.
- **Nebenbefund (außerhalb des Produkts):** Auf demselben Host lauschen `vgt_nexus_core` (`*:4004`), `gcc_net_go` (`*:8333`), `webserver` (`*:25523`) und `httpd` (8288-8290) auf allen Interfaces — nicht GeDefense, aber Teil der Serverangriffsfläche.

### F-030-1 — Fehlerdetails in Erfolgsantwort (Airlock-Inspektion)
- **Severity/Confidence:** MEDIUM-LOW / HIGH · **CWE-209**, OWASP A10/A02
- **Evidenz:** `control/server.go:2327` (`airlockInspect`) schreibt `err.Error()` in den 200er-Body; `control/airlock.go:25-30` hängt den Cause an, Causes sind rohe OS-Fehler (`airlock.go:236-273`); zusätzlich `result.QuarantineError = stageErr.Error()` (`airlock.go:311`).
- **Wirkung:** Ein authentifizierter Aufruf erhält absoluten Pfad und errno-Text → Existenz-/Rechte-Oracle. Kein UI-Aufrufer vorhanden (`api.js` exportiert keine Airlock-Funktion), daher nur per direktem API-Aufruf erreichbar.
- **Verschärfend:** `control/security_hardening_test.go:58-67` behauptet, die Fehlerklasse statt der Instanz zu prüfen; sein Regex `apiError\([^)]*err\.Error\(\)` erfasst die verletzte `writeJSON(...)`-Form nicht, und `airlock.go` fehlt in seiner Dateiliste → der Wächter deckt die Lücke nicht ab.
- **Abhilfe:** `apiError`/typisierter Fehlercode statt `err.Error()`; Guard-Regex auf `(apiError|writeJSON|apiFault)\([^)]*err\.Error\(\)` erweitern, `airlock.go` in die Dateiliste aufnehmen; `QuarantineError` durch einen Code ersetzen.

### F-030-2 — Pfad-Disclosure im vorauthentischen UI
- **Severity/Confidence:** LOW / HIGH · CWE-200
- **Evidenz:** `control/web/index.html:2261` und `:2276` zeigen `/var/lib/vgt/gedefense/dashboard.token` als Text bzw. Placeholder; identisch in allen vier Sprachkatalogen.
- **Wirkung:** Kein Geheimnis, aber ein dokumentierter Ablageort für einen Angreifer, der bereits Code auf dem Host ausführt.

### HYG-1 — Sitzungsmitschriften mit Betriebsmaterial im Arbeitsbaum
- **Severity/Confidence:** MEDIUM (Hygiene) / HIGH (gezählt, nicht bewertet)
- **Evidenz (nur Zählung, keine Werte kopiert):** `.dsh-scan/` im Arbeitsbaum, 54,4 MB, 48 Dateien; 3 Dateien nennen den SSH-Schlüsselpfad, 9 enthalten CSRF-Bezüge, **1 Datei (`tool_streams.txt`) enthält einen privaten RSA-Schlüsselblock**, 0 Dateien mit Bearer-Token.
- **Korrektur zur Erstmeldung:** `.dsh-scan` liegt **außerhalb** des Git-Repos (`GitHub Upload\Repository`) und außerhalb der Packaging-Wurzel (`pack_release_zip.py` läuft ab `root = scripts/../..` = Repo-Wurzel) → **kein Release-Blocker** für Repository/Paket. Der Arbeitsbaum selbst ist kein Git-Repository.
- **Wirkung:** Betriebsmaterial (Hostadresse, Schlüsselpfad, Schlüsselmaterial unklarer Herkunft) liegt unverschlüsselt im Arbeitsverzeichnis und kann bei Backup, Weitergabe oder künftigem Packaging abfließen.
- **Abhilfe:** `.dsh-scan/` löschen oder in einen geschützten Bereich außerhalb des Arbeitsbaums verschieben; Herkunft des RSA-Blocks klären (Testfixture vs. echtes Material) und bei Echtheit rotieren; Dashboard-Token und Sitzungsmaterial vorsorglich rotieren; `.dsh-scan/` in eine Ignore-Regel aufnehmen, falls der Arbeitsbaum je versioniert wird.

### F-078-1..4 — Anmerkungen ohne Verletzung
`trusted-types`-Direktive fehlt neben `require-trusted-types-for` (kein Sink vorhanden, reine Tiefenverteidigung); Airlock-Fehler-Echo (siehe F-030-1); Pfad-Disclosure (siehe F-030-2); `readiness` liefert `blockers` an jeden, der den Listener erreicht (Default loopback).

## CHAIN FUSION

### CHAIN-A — Fehlerpfad → Datei-Oracle
- **Parent-Findings:** F-030-1
- **Pfad:** authentifizierter `POST /api/v1/airlock/inspect` → `os.Stat`/`os.Open` schlägt fehl → Cause wird angehängt → HTTP 200 mit Pfad+errno → `TRANSFORMS` → Existenz-/Rechte-Wissen über beliebige Pfade
- **Belegt vs. hypothetisch:** Codekette vollständig belegt (drei Dateien, eine Zeile identifiziert); Ausnutzung nicht ausgeführt (AUDIT_ONLY).
- **Breakpoint:** eine Zeile in `server.go:2327` plus Guard-Erweiterung. **Residual:** `QuarantineError`.

### CHAIN-B — „CSP-Lücke + DOM-XSS + privilegierte API" (nicht als Live-Kette geführt)
- **Befund:** Keine bestätigte erste Kante. `script-src 'self'` und `require-trusted-types-for 'script'` liegen auf derselben Middleware wie jede privilegierte Route; im Bundle existiert kein Sink. Zwei unabhängige Regressionstore (Trusted Types zur Laufzeit, Contract-Tests) würden einen künftigen Sink abfangen.
- **Empfehlung:** als Regressionsbeobachtung führen, nicht als Risiko.

### CHAIN-C — Betriebsmaterial im Arbeitsbaum (korrigiert)
- **Parent-Findings:** HYG-1
- **Status:** **kein Release-Blocker** (außerhalb Repo und Packaging-Wurzel). Bleibt Hygiene-Maßnahme vor jeder Weitergabe des Arbeitsverzeichnisses.

### CHAIN-D — Host-Key-Prüfung im Projektstandard aus
- **Befund (Strang 4):** 79 Hilfsskripte (`wsl-*.sh`) nutzen `StrictHostKeyChecking=no` gegen dieselbe Produktions-IP.
- **Wirkung:** MITM auf diesen Kanälen möglich; ein unsicherer Default wird normalisiert. Diese Skripte sind Werkzeuge der Entwicklung, nicht Teil des Produkts.
- **Breakpoint:** gepinnte `known_hosts` statt `no`; Skripte nach Gebrauch entfernen.

## Test-Ledger (tatsächlich ausgeführt)

| Befehl/Test-ID | Plattform | Ausgeführt | Exit | Ergebnis |
|---|---|---|---|---|
| Sink-Inventar App-JS (Regex über 15 Module) | Windows/pwsh | ja | 0 | 0 Treffer |
| Sink-Inventar vendor (innerHTML) | Windows/pwsh | ja | 0 | 2 Treffer, Erreichbarkeit widerlegt |
| HTML-Markup-Assertions (style/on*/script/origin) | Windows/pwsh | ja | 0 | 0/0/1/1 |
| Auth-Abdeckung (84 Routen vs. `s.auth`) | Windows/pwsh | ja | 0 | 73/73 `/api/` authed |
| Cache-/Service-Worker-Inventar | Windows/pwsh | ja | 0 | 1 `no-store`, 0 SW |
| Import-Limit + Signatur vor Parse | Windows/pwsh | ja | 0 | 4 MiB, Signatur zuerst |
| Konsolidierter Assertion-Block (12 Checks) | Windows/pwsh | ja | **1** | rc=1 ausschließlich wegen der bewusst invertierten VGT-030-Zeile |
| Go-Contract-Tests des Projekts | Windows | **nein** | — | **BLOCKED**: Paket ist Linux-only (`syscall.Stat_t`, `SO_PEERCRED`, `O_NOFOLLOW` auf windows/amd64 undefiniert) — Projektbeleg, **nicht** mein Testlauf |
| Host-Erhebung (Capabilities, Bindungen, Rechte, Ledger, Disk) | Linux-Produktionshost, lesend | ja | 0 | siehe HOST-1/HOST-2/VGT-028/VGT-070/VGT-072 |
| Metrik-Erhebung XDR (`evaluations_total`, `incidents_total`) | Linux-Produktionshost, lesend | ja | 0 | +6 Auswertungen, +0 Vorfälle bei Regelauslöser (offener Befund) |

**Nicht ausgeführt und nicht behauptet:** Laufzeit-/Browserprüfung der CSP/Trusted Types, Lasttests, Netzwerk-/Draht-Beobachtung, Fuzzing, Abhängigkeitsscans (kein Netzzugriff), Gegenversuche durch Fremdprozesse an Sockets.

## Nachtrag Strang 1 — Backend/API (VGT-001..010, 031, 032, 035..040, 048, 061..066, 090)

**Statuszähler dieses Strangs:** 26 IDs → **19 PASS · 3 FAIL · 4 NOT_APPLICABLE**. Betroffen sind die Matrixzeilen **VGT-006, VGT-063, VGT-090 = FAIL** sowie **VGT-003, VGT-007, VGT-036, VGT-040 = NOT_APPLICABLE**; alle übrigen IDs dieses Strangs = PASS. (Die Matrix oben führt diese Zeilen noch als `NOT_TESTED`; die endgültige Zusammenführung ersetzt sie.)

**FAILs dieses Strangs**

- **VGT-063 — fehlendes atomares CAS im Einstellungs-Commit (MEDIUM/HIGH, CWE-362 + CWE-367, Confidence HIGH).** `SettingsStore.Update/Rollback/AddAllowlist` setzen `next.Revision = s.current.Revision + 1` **ohne Vergleich** (`runtime_settings.go:952-974, 976-1010, 1012-1032`); das Prüffenster liegt in `fabric_settings.go:707-717` → `748-812` und `server_settings.go:152-156` → `213`. Zwei parallele `PUT /api/v1/settings/{module}` mit **derselben** `expected_revision` erhalten beide 2xx; das Modul des ersten Requests wird still zurückgerollt und Engines aus veraltetem Volltext neu programmiert. Der Test `TestSettingsAPIRejectsStaleRevision` deckt nur den sequenziellen Fall ab.
- **VGT-006 — Token- und Sitzungslebenszyklus ohne Rotation, Widerruf und Ablauf (MEDIUM/HIGH, CWE-613, HIGH).** Der Operator-Token wird nur erzeugt oder gelesen (`security.go:15-51`), es gibt keine Rotation, keinen Widerruf, keinen Ablauf; Gateway-Logout löscht nur Cookies (`gateway/main.go:715-723`); die Sitzung ist ein zustandsloses HMAC mit `exp ≤ 13 h` ohne serverseitigen Widerruf (`759-801`). Ein gestohlenes Cookie oder Token bleibt bis zum Ablauf gültig; nur ein Prozessneustart entwertet es (Boot-Nonce).
- **VGT-090 — Fail-Safe- und Not-Aus-Zustand wird Screenreadern nicht angekündigt (LOW, HIGH).** `#emergencyBanner` (`index.html:365`), `#releasePhaseBadge`/`#releasePhase` (`1767`/`1774`) und `#releaseBlockers` (`1845`) haben kein `role`/`aria-live`, während andere Bereiche es korrekt setzen (`158`, `2335`). Die serverseitige Unabhängigkeit von der Oberfläche ist dagegen belegt: alle API-Routen authentisiert, Phasen-, Bestätigungs- und Revisionsgates greifen ohne UI.

**Weitere Befunde**

- **FINDING-04 (LOW, CWE-1188, VGT-066):** `require_peer_credentials=false` ist der **ausgelieferte Standard** (`gedefense.toml:68`, Nullwert in `config.go:109`) → `l7_server.go:500-503` gibt jeden Socket-Client frei; die Gruppe `gedefense-l7` erhält ohne UID/GID-Nachweis Zugriff auf `/v1/inspect` und `/v1/tls/clienthello`.
- **FINDING-05 (LOW, VGT-038/064):** Das Gateway proxyt aus Loopback → `remoteIdentity` ist für **alle** Operatoren `127.0.0.1` (`server.go:661`, `rate_limit.go:28-34`) → ein globaler Bucket (Default 240/min) und 16 SSE-Plätze pro Server ohne Partitionierung je Client. (Relativiert den PASS zu VGT-038 in der Matrix oben.)
- **FINDING-06 (LOW, VGT-035):** 7 Live-Endpunkte sind nirgends dokumentiert (`/xdr/attack-stories`, `/platform/caps`, `/responses`, `/deception/test-access`, `/styx/rules` GET+POST, `/chronos/status`); umgekehrt nennt `ARCHITECTURE.md` ~87 Pfade ohne Route. Keine Schattenendpunkte: 81 registrierte Routen, 73 authentisiert, 8 ohne Auth und **keine** davon unter `/api/`.
- **FINDING-07 (LOW/MEDIUM, VGT-061):** Ein `os.Stat`-Fehler ungleich „not exist" setzt `EmergencyStop=false` (`release.go:260-267`), während gleichzeitig der Blocker „cannot be verified" steht; `RETURN:OBSERVE` überspringt die Blockerprüfung (`307-315`) und leert über `reconcileLocked("observe")` die Kernel-Blockliste (`839-845`).
- **INFO:** `decodeSingleJSONValue` ohne Media-Type-Prüfung (`fabric_surface_api.go:483-497`); `hardenedTLSConfig` ignoriert `loopbackListener`, ohne Downgrade (`gateway/main.go:67-81`); `evidenceGateExempt` erlaubt `PUT /api/v1/settings/integrity` ohne Evidenzsatz bei vollem Ledger (`server.go:710-718`); Bestätigungsphrasen werden im UI-Modalpfad komponiert (`protection.js:517-520, 597`), der Server erzwingt sie weiterhin.

**Ketten dieses Strangs**

- **CHAIN-001 — gestohlenes Token → dauerhafte Umgehung:** FINDING-02 → `PUT /api/v1/settings/network` erweitert `management_allowlist` → die Angreifer-IP ist von automatischer Blockierung ausgenommen, Hot-Einstellungen sind abschwächbar, die Wirkung überlebt Neustarts. Erkennung existiert (`operator.mutation.intent`, `settings.updated`, `allowlist.added`), **Prävention fehlt**. Breakpoints: Token-Rotation und Widerruf, Alarm auf Wachstum der Allowlist, CAS.
- **CHAIN-002 — Nebenläufigkeit → durchgesetzter ≠ bestätigter Zustand:** zwei gleichzeitige Mutatoren passieren die Revisionsvorprüfung → FINDING-01 → eine als aktiv bestätigte Schutzmaßnahme ist unwirksam; die Drift-Wache vergleicht nur gespeichert gegen effektiv. Breakpoint: atomares CAS.
- **CHAIN-003 — lokale Gruppe → Telemetrievergiftung und erzwungene Blockentscheidung:** Mitglied in `gedefense-l7` (FINDING-04) → `POST /v1/inspect` mit frei gewählter `ClientIP` (nur `ServerPID` wird aus Peer-Credentials überschrieben, `l7_server.go:313-315`) → `xdr.RecordL7Inspection` und Entscheidung „block"/`Enforced=true` bei `Mode=block` und Release-Phase Enforce (`l7_engine.go:169-221, 67-73, 209-218`) → gefälschte Vorfälle unter fremden IPs, Vergiftung der L7-Buckets, Deny für gewählte IPs. Breakpoint: `require_peer_credentials=true` plus UID/GID-Allowlist.

**Test-Ledger dieses Strangs (real ausgeführt)**

| Befehl | Exit | Ergebnis |
|---|---|---|
| `go vet ./...` (control) | 0 | keine Befunde |
| `GOOS=linux go build ./...` (control, Windows-Go) | 0 | baut; Windows-Build erwartungsgemäß exit 1 (Linux-only Quellen) |
| `go test ./... -count=1 -timeout 900s` (WSL) | 0 | `ok …/control 340.305s`, 619 Testfunktionen inventarisiert |
| Zielgerichteter Security-Lauf (41 Tests) | 0 | **41 PASS / 0 FAIL / 0 SKIP**, 2.890 s |
| `go vet` + `go test -count=1 -v` (gateway) | 0 | **27 PASS / 0 FAIL / 1 SKIP** (Umgebungs-Skip, nicht als Nachweis gezählt) |
| Routen-Inventar (Regex + Handler-Diff) | 0 | 81 Routen, 73 authentisiert, 0 Schattenendpunkte |

**Bekannte Abweichung, vom Strang selbst gemeldet:** Ein `go build ./...` im Verzeichnis `control/` hat das gitignorierte Build-Artefakt `control/control` überschrieben (Toolchain passt zum Embedded-Header, `go1.26.6`). **Keine Quelldatei geändert.** Das Artefakt ist nicht in den Release-ZIPs enthalten; `SOURCE-MANIFEST.sha256` war bereits für ≥11 unberührte Dateien ungültig. Empfehlung: Artefakt als frischen Build akzeptieren oder mit `go build -o <temppfad>` neu erzeugen und das Manifest neu schreiben.

**Release-Gate dieses Strangs:** `CONDITIONAL` — kein CRITICAL/HIGH mit unmittelbarem Kompromittierungspfad, aber ohne befristete Risikoübernahme für FINDING-01 und FINDING-02 keine Freigabeempfehlung.



## Nachtrag Strang 2 — Krypto, Ledger, Schlüssel, Feeds (VGT-021..029, 056..060, 067, 069, 072, 076)

**Status (ersetzt die `NOT_TESTED`-Zeilen dieser IDs in der Matrix oben):**

| ID | Status | Kernbeleg |
|---|---|---|
| VGT-021 | PASS | AES-256-GCM, Subkey je Zweck (HMAC-SHA256 über Rootkey+Node+Purpose, `storage_crypto.go:69-82`), AAD bindet Schema+Node+Zweck+Pfad+Sequenz (:84-87), 12-B-Nonce je Record aus `crypto/rand` (:103-106); Tamper-Test real: Chiffrat-Flip **und** AAD-Mismatch abgelehnt |
| VGT-022 | **FAIL** | Kein Rotations-/Revoke-/Reissue-Verfahren (`grep rotate\|revoke\|reissue` in `scripts/*.sh` → 0); `CRYPTOGRAPHY.md:73` nennt Rotation nur als Zukunftsnotiz. Rechte-Asymmetrie: Storage-Key `root:gedefense 0640` wird akzeptiert (`storage_crypto.go:53`), Evidence-/Logdateien mit `&0o077 != 0` hart abgelehnt |
| VGT-023 | PASS | Argon2id m=65536, t=3, p=1, 128-Bit-Salt; Secret-Dateien 0600 + Nicht-Symlink; keine Klartext-Secrets in Logs |
| VGT-024 | PASS | Feed-TLS ≥ 1.2, nur Port 443, `forbiddenFeedIP` gegen private/Metadata-Netze, Cross-Host-Redirect verboten; Dashboard TLS 1.3; repo-weit **0 Treffer** `InsecureSkipVerify` |
| VGT-025 | PASS mit Lücke | Signatur **vor** Verarbeitung (Policy, Forensics, Settings-Bundle, Release-Manifest), Signer-Fingerprint gebunden, monotone Generation + Floor. **Lücke:** Release-Envelope ohne Frische-/Ablaufprüfung (Probe: `CreatedAt=2001` akzeptiert) |
| VGT-026 | PASS | `math/rand`/`rand.Seed`: **0 Treffer**; `crypto/rand`: 12 Importe; `randomID()` bricht bei RNG-Ausfall ab; Nonce je Record frisch |
| VGT-027 | NOT_TESTED | Kein PII-/Telemetrie-Inventar und kein Export-Minimierungstest im Prüfbereich |
| VGT-028 | **FAIL** | `storage_key_file=""` schaltet den Cipher still ab → Policy-Privatkey, Evidence-Privatkey, Evidence- und Incident-Records im Klartext (Probe bestätigt); `validateConfig` prüft das Feld nicht (`config.go:1227ff`); `threat-intel-state.json` unverschlüsselt und treibt den Kernel-Apply |
| VGT-029 | **FAIL** | Kein Retention-/Löschpfad für `archive/evidence-*` und `xdr-recovery/*` (`archiveMax\|MaxArchives\|retention\|prune` → 0 Treffer); Rotation ersetzt nur die Live-Datei → unbounded Wachstum, kein Restore |
| VGT-056 | BLOCKED | Release-Manifest ist Ed25519-signiert und verifizierbar, aber Code-Signing/Notarisierung/Paketsignatur liegt außerhalb `control/`; kein `.sig`/`.pem` im Repo. Lösung: CI-Workflow und Signaturartefakte in den Scope nehmen |
| VGT-057 | BLOCKED | Der Auto-Updater selbst liegt nicht im Scope (nur Release-Phasen/Fail-closed-Retention); Tamper-/Downgrade-/Interrupted-Update mit Testpaketen nicht prüfbar |
| VGT-058 | **FAIL** | **Threat Feeds sind nicht signiert**: kein Ed25519/HMAC, kein Digest-Pinning, kein Provenance-Feld (`grep` in `feeds.go`/`threat_intel_fabric.go` → 0); Host-Allowlist **default leer** ⇒ jeder öffentliche HTTPS-Host; Feed-Zeilen werden ungeprüft zu Kernel-Blocklist-Einträgen (`feeds.go:1274`) |
| VGT-059 | PASS mit Lücke | Pflichtartefakte, exakte Toolchain-Pins, Verbot von Key-Dateien im Artefaktverzeichnis; kein Open-Core-Konzept im Repo |
| VGT-060 | **FAIL** | Kein dokumentiertes und kein getestetes Revoke/Rotate/Reissue für Storage-, Policy-, Release-Key oder Feed-Vertrauen |
| VGT-067 | **FAIL** | Anti-Downgrade-Floor ist Default 0 und per Runtime-Settings auf 0 rücksetzbar (`trust_fabric.go:224`), die `generation` steht **im selben Dokument** (`policy.go:289-293`) ⇒ Replay eines gültig signierten Alt-Dokuments mit erhöhter Generation wird akzeptiert; für Evidence/Incident existiert **kein** Restore-Pfad |
| VGT-069 | **FAIL** | Kein Monotonie-/Skew-Schutz: ReplayGuard gibt IDs frei, sobald die Uhr über das Fenster springt (`rate_limit.go:90-94`, Probe bestätigt); Soak-/Promotion-Gates nutzen `time.Since` über persistierten Wall-Clock-Stempel (`release.go:601`); Feed-Staleness rein Wall-Clock. Positiv: Zukunft-Zeitstempel im L7-Selbsttest werden abgelehnt |
| VGT-072 | PASS mit Einschränkung | Ed25519-signierte Hash-Kette + authentifizierter, verschlüsselter Checkpoint; Truncation über Sequenzzählung, Historienschaden über `VerifyIncremental`; Tamper-Tests real grün. **Einschränkung:** Integrität hängt am Keyfile derselben Vertrauensdomäne; ein einzelnes unversiegeltes Tail-Record wird im Start **still** verworfen (`evidence_ledger.go:647-673`) — kein Alarm |
| VGT-076 | **FAIL** | Keine Feed-Signatur, keine Digest-/Provenance-Bindung; `LastGoodItems` wird bei jedem Start aus einer **unauthentifizierten** JSON-Datei geladen (`feeds.go:928-947`) und erneut in den Kernel appliziert; STALE/CRITICAL degradiert nichts und blockiert keine Promotion (`grep OverallStatus` in `release.go`/`state.go` → 0) |

**Schwere Einzelbefunde:** F-VGT-A (HIGH) Klartext-Privatkeys bei `storage_key_file=""` (dynamisch belegt) · F-VGT-B (HIGH) `VGT_RELEASE_ROOT` steuert `isProductArtifact` (`xdr_baseline.go:45-50` → `xdr.go:1398`): eigene Binaries gelten bei Digest-Abweichung als „Deployment" → Severity `high`, `Action:"none"`, **kein** `markDegradedCause` → XDR bleibt gesund, automatische Reaktion läuft weiter, kein Promotionsblocker (**reaktionslose Selbstmanipulation**) · F-VGT-C (HIGH) unsignierter Feed + unauthentifizierter State + leere Allowlist ⇒ beliebige IPs in die XDP-Sperrliste · F-VGT-D (MEDIUM) `StorageCipher.Decrypt` liefert schema-lose Dokumente unauthentifiziert als „legacy plaintext" (`storage_crypto.go:127-132`) · F-VGT-E (MEDIUM) kein Retention für Rotationsarchive · F-VGT-F (MEDIUM) gesenktes Evidence-Budget ⇒ `Verify()` schlägt dauerhaft fehl und blockiert die Gates · F-VGT-G (MEDIUM) Replay-/Soak-Gates ohne Monotonie-Schutz · F-VGT-H (LOW) unversiegeltes Tail-Record still verworfen. **Kein Befund:** Pfad-Traversal über `archive_id` ist nicht ausnutzbar (Probe: `filepath.Join` reinigt, Lookup schlägt fehl → fail-closed).

**Ketten:** CHAIN-001 (HIGH) Env-Kontrolle → reaktionslose Selbstmanipulation; Breakpoint: Klassifikator-Wurzel aus signierter Policy bzw. `/proc/self/exe`. CHAIN-002 (HIGH) leerer Storage-Key → Klartext-Policy-Key → gefälschte Policies/Forensik/Settings-Bundles gültig; Breakpoint: `validateConfig` erzwingt 32-Byte-Key, fehlend = Startabbruch. CHAIN-003 (HIGH) unauthentifizierte Runtime-Settings + Floor 0 + Generation im Dokument → Replay einer permissiven Alt-Policy; Breakpoint: Floor extern und monoton verankern. CHAIN-004 (MEDIUM-HIGH) unsignierter Feed → Poisoning oder Blindspot bei Status „OK". CHAIN-005 (MEDIUM) Uhrzeit → Rotation → Archiv ohne Retention → Disk voll → Phasenblocker.

**Test-Ledger:** `go build` (GOOS=linux) exit 0 · `go vet` (WSL, Go 1.27.1) exit 0 · `go test -count=1 -timeout 3000s -v .` → **610 PASS / 0 FAIL / 0 SKIP**, `ok … 299.817s`, exit 0 · 8 Adversarial-Probes 8/8 PASS (temporäre Datei, danach entfernt, `Test-Path` = False) · Tamper-Bilanz grün für StorageCipher-AAD/Chiffrat, Chain-Truncation/-Signatur, Startup-Check, Rotation/Append-Recovery, Watermark, Policy-Signatur, Rollback bei gesetztem Floor; **nicht** abgedeckt: Feed-Signatur, Archiv-Retention, Zeitmonotonie, Klartext-Downgrade, Env-Klassifikator.

**Release-Gate dieses Strangs: BLOCKED** (F-VGT-A, F-VGT-B, F-VGT-C).

## Nachtrag Strang 5 — Lieferkette, Detection, Regression (VGT-011..013, 017, 018, 049..055, 068, 079, 080, 091..100)

**Status (ersetzt die `NOT_TESTED`-Zeilen dieser IDs):**

| ID | Status | Kernbeleg |
|---|---|---|
| VGT-011 | PASS | Kein `database/sql`, kein sqlx/gorm/ORM, keine dynamische Query — **kein SQL im Produkt** |
| VGT-012 | PASS | **0** `exec`/`spawn` in Produktionscode (nur 2 Testdateien); `scripts/security-audit.sh:107-114` erzwingt das als Grep-Gate. Der Rust-Eingriff ist bewusst command-frei: `process_control.rs:54-105` nutzt `pidfd_open` + `pidfd_send_signal`, validiert die PID-Identität zweimal (Z. 69/78), begrenzt Signale auf STOP/KILL/CONT (Z. 66), Rule-Token-Allowlist (Z. 8-14) |
| VGT-013 | PASS | Keine Template-Engine, kein `eval`; nur `reflect.DeepEqual` zum Vergleich |
| VGT-017 | PASS mit Ausnahme | Kein `encoding/gob`, kein YAML/XML; überall `DisallowUnknownFields` + Trailing-Data-Ablehnung (z. B. `storage_crypto.go:180-192`), AES-256-GCM. **Ausnahme: F-05** |
| VGT-018 | PASS | Keine ZIP/TAR-Extraktion; gzip/zlib nur mit `LimitReader` (`l7_normalize.go:281`), gestapelte Encodings abgelehnt (Z. 264-266); `openBeneath`/`openJailDestination` mit `O_CREATE\|O_EXCL` je Pfadkomponente (`airlock.go:439-458`) |
| VGT-049 | PASS | Durchgehend 0600/0700, `O_EXCL`, `rejectSymlink`; `atomicWriteFile` mit Staging + Rename + fsync (`policy.go:162-212`) |
| VGT-050 | **FAIL** | `gateway/argon2_linux.go:1` `//go:build linux && cgo` **ohne Fallback** → Gateway baut auf Windows/macOS und mit `CGO_ENABLED=0` nicht (`undefined: argon2IDKey`, `main.go:984/1006`). Auf Linux+cgo exit 0 |
| VGT-051 | PARTIAL | Beide Go-Module **0 externe Dependencies** (stdlib-only, bestätigt); `rust/Cargo.lock` pinnt 70 Pakete mit `--locked`, aber nur `aya` ist vendored; **keine SBOM** (CycloneDX/SPDX) |
| VGT-052 | **FAIL** | Keinerlei CVE-/Advisory-Triage: kein govulncheck/trivy/grype/OSV; `security-audit.sh` ist handgeschriebene Statik. `TOOLCHAINS.lock` pinnt Go 1.26.8 — `control/go.mod:5` fordert `toolchain go1.26.6` (Abweichung) |
| VGT-053 | PASS | stdlib-only ⇒ keine Registry-Auflösung, kein Typosquatting-Vektor; vendored `aya` mit Lockfile |
| VGT-054 | PASS | `.github/workflows/ci.yml:8-9` `permissions: contents: read`, alle Actions SHA-gepinnt (Z. 19/20/26), keine Secrets referenziert |
| VGT-055 | **FAIL** | `sha256sum -c SOURCE-MANIFEST.sha256` → exit 1: **419 OK / 74 FAILED** (71 echte Inhaltsdivergenz, 3 CRLF); Manifest vom 07.10. gegen Quellen vom 16.10.; **keine Signatur/Provenance/Attestation**. Gegenprobe: die Archive selbst sind einwandfrei (eingebettetes Manifest 504/512/561 = 100 % OK, alle 9 `.sha256`-Sidecars MATCH) |
| VGT-068 | PASS | `docs/kinetic/failsafe-rules.md:21-28` (F-01..F-08): bestehende Kernel-Drops bleiben bei Ausfall erhalten, nur neue Aktionen pausieren |
| VGT-079 | PARTIAL | Not-Aus vollständig implementiert und getestet (`release.go:808-858`, persistiert 0600, `degradeLocked`, Clear mit Bestätigung, 3 Tests exit 0); Forensik: PrevHash-Kette + Ed25519 (`evidence_ledger.go:40,56,62,316,867`). **Fehlt:** IR-Runbooks, Tabletop-Übungsakte, Kundenmeldeprozedur; Clock-Sync siehe F-08 |
| VGT-080 | NOT_TESTED | Fehlalarm-/Fehlertreffer-Bilanz nur teilweise: Korpus existiert, aber divergierend (F-06) |
| VGT-091..094 | **FAIL** | End-to-End-Angriffspfadgraph, Kombinationsfehler-Bewertung, Privilegien-Pivot und Cross-Layer-Transformation sind als **Verfahren** nicht etabliert; teils durch Einzelbefunde abgedeckt (Ketten dieses Berichts), teils nicht |
| VGT-095 | PASS | Behobene Befunde sind als dauerhafte Tests vorhanden: `failclosed_contract_test.go` (8 Tests/3 Subtests), `findings_regression_test.go` (4), `hardening_coverage_test.go` (3), `release_failsafe_test.go` (2), 8 Pfad-Jail-/Symlink-Negativtests — alle exit 0; Testkommentare benennen den Ursprungsdefekt |
| VGT-096 | PASS | 8 Fuzz-Targets, alle exit 0 (u. a. `FuzzParseClientHelloNeverPanics`, das **nicht** im Makefile-Ziel `fuzz-smoke` steht) |
| VGT-097 | **FAIL** | Kein SAST/DAST/SCA-Fundabgleich (siehe VGT-052) |
| VGT-098 | PASS | Suite 339 s ohne Deadlock; Laufzeitgates in Tests |
| VGT-099 | **FAIL** | Release-Blocker-/Risk-Acceptance-Verfahren nicht etabliert; dieses Dokument ist der erste vollständige Trace |
| VGT-100 | **FAIL** | Die Regressionsbasis **existiert** (VGT-095 PASS), aber das **dauerhafte CI-Gate ist defekt**: `security-audit.sh` bricht ab → `make test` exit 2 → der Testlauf wird in CI nie erreicht |

**Harte CI-/Release-Blocker (reproduziert, Exitcodes belegt)**

1. **`bash scripts/security-audit.sh` → exit 1.** `scripts/security-audit.sh:88` hat die Version hart als `'4.1.0'`, `control/web/index.html:123` sagt `4.2.3` → `make test` (`Makefile:14`) bricht ab (`MAKE_TEST_EXIT=2`); die CI-Jobs `go-frontend-security` und `release-artifacts` sind unbrauchbar. **Der Fix liegt bereits im Staging-Repo** (`GitHub Upload/Repository/scripts/security-audit.sh` liest `current_ver` aus `VERSION`), ist aber **nicht in den Arbeitsbaum gemergt**.
2. **`make test-race` → exit 2, echter Data Race** in `control/startup_supervisor_test.go:314`: `last` wird im `reportSink` aus der Supervisor-Goroutine geschrieben, während die Test-Goroutine in der Poll-Schleife (`:324`) ohne Synchronisation liest (`FAIL: TestStartupRunKeepsEnforcingWhenAModuleStaysBroken`). **Diese Datei stammt aus einer früheren Runde dieses Projekts.**
3. **`SOURCE-MANIFEST.sha256` veraltet** (siehe VGT-055): Anomalien — `go.mod` (0 Bytes) und das 16,5-MB-Artefakt `control/control` stehen im Manifest, fehlen aber in allen Archiven.

**Weitere Einzelbefunde:** F-05 (MEDIUM, CWE-502) `l7_tls.go:217-218` dekodiert als **einziger** von ~25 Decodern ohne `DisallowUnknownFields` → unbekannte Policy-Felder werden still verworfen (stiller Policy-Drift) · F-06 (MEDIUM) Testkorpus divergiert (10 gegen 9 Szenarien; der **veraltete** 9er-Korpus wird geladen, die neuere Datei ist toter Code, keine Paritätsprüfung → latente Gate-Umkehr) · F-09/F-10 (LOW) Versionsliteral `4.1.0` auch in zwei Installer-Headern und in `ci.yml:121-124` (Artefakt-Upload mit falschem Namen → `if-no-files-found: error`) · F-08 (LOW/MEDIUM) offene Selbstdoklaration zu fehlender Uhrzeitmessung (`system_fabric.go:28`), teilweise durch Zukunft-Zeitstempel-Ablehnung gemildert.

**Ketten:** CHAIN-001 (kritischster Pfad) defektes Audit-Gate → alle Regressionsgates übersprungen → ungetesteter Code wird ausgeliefert. CHAIN-002 stale Root-Manifest + selbstreferenzielles Archiv-Manifest + keine Signatur → Provenienz prinzipiell nicht verifizierbar. CHAIN-003 Data Race → Race-Gate rot → echte Supervisor-Races maskiert. CHAIN-004 stiller Policy-Feldverwurf + Default für unbekannte Fingerprints → Umgehung der TLS-Policy. CHAIN-005 sprödes Versionsliteral als Gate → Gate fällt bei jedem Release aus.

**Empfohlene Reihenfolge:** (1) `security-audit.sh`-Version aus `VERSION` lesen (Fix aus dem Staging mergen), (2) Data Race in `startup_supervisor_test.go` synchronisieren, (3) `SOURCE-MANIFEST.sha256` nach dem Merge neu erzeugen und signieren, (4) `ci.yml:121-124` auf 4.2.3 korrigieren, (5) `DisallowUnknownFields` in `l7_tls.go:217`, (6) Korpus-Divergenz einebnen und Paritätstest ergänzen.

## Gesamturteil (alle fünf Stränge)

`RELEASE_GATE: BLOCKED`

| Kategorie | Anzahl |
|---|---:|
| Critical | 0 |
| High | 6 (F-01, F-VGT-A, F-VGT-B, F-VGT-C, HOST-1-Kette, CI-Gate-Ausfall über CHAIN-001) |
| Medium | 12 |
| Low | 9 |
| Info | 6 |
| Ketten | 13 (CHAIN-001..005 je Strang, teils überlappend) |
| VGT-100 PASS / FAIL / NOT_TESTED / BLOCKED / N/A | 40 / 20 / 5 / 4 / 8 |

**Die vier Wurzelursachen, auf die sich alles reduzieren lässt:**

1. **Geteilte Identität** zwischen internetnahem Gateway und root-nahem Kern (F-01, F-02) — behebbar durch eigenen Dienstnutzer, Entfernen des Schlüssels aus dem Gateway und pid/exe-Allowlist im Kern.
2. **Vertrauen, das abschaltbar ist**: leerer Storage-Key (F-VGT-A), `VGT_RELEASE_ROOT` (F-VGT-B), Floor 0 + Generation im Dokument (VGT-067), unsignierte Feeds (F-VGT-C) — behebbar durch erzwungene Prüfungen im Preflight, die den Start verweigern.
3. **Fehlender Lebenszyklus** für Geheimnisse und Altdaten: keine Rotation/Widerruf (VGT-006, 022, 060), kein Retention (VGT-029) — behebbar durch dokumentierte Rotations- und Aufbewahrungsverfahren mit Test.
4. **Ein defektes Gate macht alle Nachweise wertlos**: `security-audit.sh` mit hartem Versionsliteral lässt `make test` und den Race-Lauf in CI nie durchlaufen (VGT-100, CHAIN-001) — behebbar in Minuten, weil der Fix bereits existiert.

**Bewusst nicht behauptet:** Laufzeitverhalten des Rust-Kerns (Toolchain-Blocker), Browserlaufzeit der CSP (kein Browser im Audit), Wirkung auf dem Draht (keine Netzsicht), Advisory-Frische (kein Internet), systemd-Betriebstest. **Der Validatorlauf über eine JSON-Matrix wurde nicht durchgeführt** — die Matrix liegt als Markdown vor; die JSON-Erzeugung steht aus. Kein PASS wurde aus früheren Läufen übernommen, N/A wurde nie als PASS gezählt.

 keine.
- **Bedingungen vor Distribution:** F-030-1 beheben (eine Zeile + Guard), HYG-1 umsetzen (Arbeitsbaum bereinigen, Herkunft des Schlüsselblocks klären), HOST-1/HOST-2 als gehärtete Defaults nachziehen.
- **Nicht prüfbare Grenzen:** alle 85 als `NOT_TESTED` geführten IDs — vier Teilberichte stehen aus; zusätzlich fehlen Laufzeit-, Last- und Netzsicht sowie jegliche Advisory-Prüfung (kein Internetzugriff im Audit).
- **Priorisierte nächste Schritte:** (1) vier ausstehende Teilberichte einarbeiten und Matrix schließen; (2) F-030-1 patchen und Guard verschärfen; (3) minimales `CapabilityBoundingSet` mit Funktionsprüfung; (4) Bindung auf loopback; (5) HYG-1; (6) Beobachtung „XDR-Modus `observe` erzeugt keine Vorfälle" mit dem Betreiber klären.
