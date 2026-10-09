<div align="center">

<img width="256" height="256" alt="GeDefense" src="https://github.com/user-attachments/assets/978d2835-c915-473d-9995-d315efaa869c" />



# VGT GeDefense
### Linux Security Fabric

[![License](https://img.shields.io/badge/License-AGPL--3.0--only-blue?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)
[![Version](https://img.shields.io/badge/Version-4.2.2-orange?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-Release_v4.2.2-yellow?style=for-the-badge)](#)
[![Installer](https://img.shields.io/badge/Installer-4.2.2_Universal_Linux-green?style=for-the-badge)](#-schnellstart)
[![Platform](https://img.shields.io/badge/Platform-Linux_x86__64-lightgrey?style=for-the-badge&logo=linux)](#)
[![Data Plane](https://img.shields.io/badge/Data_Plane-Rust_eBPF%2FXDP-red?style=for-the-badge&logo=rust)](#-architektur)
[![Control Plane](https://img.shields.io/badge/Control_Plane-Go-00ADD8?style=for-the-badge&logo=go)](#-architektur)
[![Crypto](https://img.shields.io/badge/Evidence-Ed25519%2FAES--256--GCM-gold?style=for-the-badge)](#-kryptografie)
[![Sovereign](https://img.shields.io/badge/Control_Plane-Local%2FSovereign-brightgreen?style=for-the-badge)](#)
[![Linux](https://img.shields.io/badge/Linux-APT%20%7C%20DNF%20%7C%20pacman%20%7C%20Zypper-cyan?style=for-the-badge&logo=linux)](#-universelle-linux-integration)
[![AstraeaOS](https://img.shields.io/badge/AstraeaOS-Native_Ready-7de3ff?style=for-the-badge)](#-astraeaos-integration)
[![Architecture](https://img.shields.io/badge/Architecture-Specification-9cf?style=for-the-badge&logo=blueprint)](ARCHITECTURE.md)
[![Security Audit](https://img.shields.io/badge/Security-Audit_Beta_5-success?style=for-the-badge&logo=shield)](SECURITY-AUDIT-BETA5.md)
[![VGT](https://img.shields.io/badge/VGT-VisionGaiaTechnology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

**KERNELNAHE NETZWERKVERTEIDIGUNG · HOST-XDR · VERSCHLÜSSELTE EVIDENZ · REVERSIBLE HÄRTUNG · KEINE CLOUD-CONTROL-PLANE**

<br />

🌐 **Languages / Sprachen / Языки / 语言:**  
[English](README.md) · **Deutsch** · [Русский](README.ru.md) · [中文 (简体)](README.zh.md)

</div>

---

## 🚨 KRITISCHER SICHERHEITSHINWEIS & WARNUNG — RELEASE v4.2.2

> [!CAUTION]
> **DRINGENDER SICHERHEITSHINWEIS FÜR ALLE BETREIBER & SYSTEMADMINISTRATOREN (UPGRADE DRINGEND EMPFOHLEN):**
> 
> In GeDefense Version 4.2.0 wurden im Rahmen eines umfassenden Sicherheitsaudits und Verifikationszyklus **mehrere kritische Sicherheitslücken und Integritätsmängel früherer Versionen (4.0.x / 4.1.0)** identifiziert und vollständig behoben. Ein sofortiges Upgrade auf v4.2.2 wird für alle Produktionsinstallationen dringend empfohlen:
> 
> 1. **Kritische Rechteeskalation via Symlink-Traversal (Canary-Deployment):**
>    - *Schwachstelle:* Das bisherige Canary-Deployment folgte symbolischen Links im Decoy- oder Staging-Pfad. Ein von einem Angreifer kontrollierter Symlink in übergeordneten Verzeichnissen konnte Schreiboperationen mit Root-Rechten an beliebige Dateisystemorte umleiten (`cron`, `authorized_keys`, `ld.so.preload`) → Willkürliches Dateischreiben mit Root-Privilege-Escalation.
>    - *Behebung:* Ersetzt durch strikte deskriptorbasierte Pfadauflösung (`openat(2)` mit `O_NOFOLLOW|O_DIRECTORY` auf jeder einzelnen Pfadkomponente). Traversale über Symlinks schlagen deterministisch mit `ELOOP` fehl.
> 
> 2. **Opake Fehlerantworten zur Beseitigung von Informationslecks (Information Disclosure):**
>    - *Schwachstelle:* Fünf API-Handler gaben ungefilterte Laufzeitfehler an Clients weiter (interne Dateisystempfade, Kernelfehler, Upstream-Feed-URLs, DNS/TLS-Interna). Die frühere Wort-Blacklist war fragil und unvollständig.
>    - *Behebung:* Strukturelle Entkopplung — interne Laufzeitfehler werden niemals als API-Fehlerantworten weitergeleitet, sondern durch typisierte, opake Fehlerantworten ersetzt.
> 
> 3. **Fail-Closed CSPRNG & Vorhersagbarkeitsschutz:**
>    - *Schwachstelle:* Versagte die CSPRNG-Entropiequelle, fielen Evidenz-, Vorfalls-, Block- und Transaktions-IDs auf vorhersagbare Zeitstempel zurück.
>    - *Behebung:* Strikte Fail-Closed-Semantik via `log.Fatalf` — kryptografische Bezeichner degradieren niemals zu vorhersagbaren Werten.
> 
> 4. **Absturzsicherer atomarer Writer (`atomicWriteFile`):**
>    - Richtlinien (Policies), Feed-Zustände und Chronos-Checkpoints nutzen ausnahmslos atomare Schreibvorgänge mit Symlink-Zurückweisung, `O_EXCL` und `fsync` sowohl auf die Datei als auch auf das Elternverzeichnis.
> 
> 5. **Härtung der Content Security Policy (CSP) & Trusted Types:**
>    - `unsafe-inline`-Styles wurden vollständig aus der CSP verbannt.
>    - `require-trusted-types-for 'script'` wird vom Browser aktiv als Laufzeitinvariante erzwungen (keine DOM-XSS-Sinks).
> 
> 6. **Beseitigung von Deadlocks & Fail-Open in der Engine:**
>    - Deadlock in `CaseEngine.Status` behoben (rekursiver Mutex-Lock).
>    - Fail-Open-Zustände im Airlock-Inspektor und in der CaseEngine eliminiert.
> 
> 7. **Toolchain-Sicherheitsboden (Go ≥ 1.26.6):**
>    - Behebung von 6 erreichbaren Standardbibliotheks-CVEs älterer Go-Releases auf den Pfaden des Ingress-Reverse-Proxys und der Threat-Intelligence-Feeds.

---

## ⚠️ STABILITÄT & ZUSICHERUNG — RELEASE v4.2.2 · UNIVERSELLE LINUX-PLATTFORM

VGT GeDefense 4.2.2 ist das Flaggschiff des Linux-Sicherheitsgewebes — die gehärtete Verteidigungskette mit Kernel-Geschwindigkeit, kombiniert mit der neuen **Security Fabric Control Plane**, universeller Linux-Integration, gehärteter Release-Pipeline und konkreten Kernel-/NIC-Qualifikations-Gates. Es wurde für souveränen Host- und Netzwerkschutz entwickelt.

**Die Produktionsfreigabe ist bewusst eine Eigenschaft des konkret auditierten Ziel-Hosts — nicht allein des Quellcodes.**

Initiale Bereitstellung: **Ausschließlich Observe-Modus.** Canary und Enforce erst nach Erfüllung aller dokumentierten Gates.

Sicherheitslücke gefunden oder Verbesserungsvorschlag? **Eröffne ein Issue oder kontaktiere uns direkt.**

---

## 🏛️ Sicherheitsarchitektur & Technische Spezifikation

> [!IMPORTANT]
> **Für Sicherheitsforscher, Systemarchitekten & Auditoren:**
> GeDefense führt eine vollständige, formale Spezifikation der technischen Architektur, des Vertrauensgrenzenmodells und des Symboldatenbaums:
> 
> ### ➔ [📘 ARCHITECTURE.md — Vollständige technische Architektur & Spezifikation](ARCHITECTURE.md)
> 
> *Über 2.200 Zeilen zur Spezifikation des 7-stufigen Architekturbaums, der Kernel-eBPF/XDP-Data-Plane, der Go-Control-Plane, des typisierten Rust-Response-Cores, der nativen L7-WAF-Engine, des kryptografischen Evidenz-Ledgers und der reversiblen Härtungs-Engine.*

### Übersicht: 7-stufiges souveränes Verteidigungsgewebe

```text
1. PUBLIC ACCESS GATEWAY       Go · Port 9843 (TLS 1.3, ML-KEM PQ-Hybrid, Argon2id, CSRF-Sync-Tokens)
2. COMMAND CENTER DASHBOARD   ESNext / Vanilla JS / Natives CSS · 0 Abhängigkeiten · CSP-gehärtet
3. CONTROL PLANE               Go · Port 9844 (Nur Loopback · XDR, L7-WAF, FIM, Evidenz-Ledger, Fälle)
4. PRIVILEGED RESPONSE CORE   Rust · /run/vgt-gedefense/core.sock (HMAC VGT3, pidfd_open, sysctl CAS, fanotify)
5. KERNEL DATA PLANE           Rust no_std eBPF/XDP + cgroup-skb + LSM (LPM-Trie 250k Regeln, RingBuf EDR)
6. INTEGRATION FABRIC          Universelles Linux (APT/DNF/pacman/Zypper) · AstraeaOS Native Ring-1 Cells
7. RELEASE ENGINEERING         Toolchains.lock · Reproduzierbare Builds · Kryptografische Spiegel-Manifeste
```

### Kern-Sicherheitsinvarianten
- **Keine Cloud-Control-Plane:** Threat Intelligence, Verhaltens-Baselines, operative Schlüssel und forensische Evidenzen verbleiben zu 100% auf dem lokalen Host.
- **Kernel-Speed Data Plane:** Eingehende Netzwerkangriffe werden auf Treiberebene via Rust eBPF/XDP verworfen, noch vor der Socket-Puffer-Allokation (`sk_buff`).
- **Native L7-Ebene (Nur Go-Standardbibliothek):** Begrenzte HTTP-Normalisierung, Anti-Evasions-Dekodierung und RE2-Regex-Scans ohne Drittanbieter-Abhängigkeiten, ohne CGO und ohne Skript-Runtimes.
- **Web-Evidenz-Isolationsbarriere:** Web-Befunde tragen `AlertOnly: true` (`ResponseScore: 0`). Ein Web-Tier-Befund kann niemals autonom Prozesse auf Host-Ebene beenden (`SIGKILL`/`SIGSTOP`); destruktive Eindämmung erfordert zwingend unabhängige Host-/Kernel-Evidenz.
- **Kryptografischer Evidenz-Ledger:** Manipulationssichere, monotone Sequenz mit Vorgänger-Hashing (`AES-256-GCM` + `Ed25519`).
- **Reversible Sysctl-Härtung:** Atomares Compare-and-Set mit Kernel-Rücklesung und automatischem Rollback bei partiellem Fehlschlag.

---

## 🚀 Neu in GeDefense 4.2.0: Security Fabric Control Plane, Full-Stack Audit-Fixes & UI/UX Supreme

VGT GeDefense 4.2.0 stellt einen maßgeblichen Evolutionssprung für das souveräne Linux-Sicherheitsgewebe dar:

* **Security Fabric Control Plane (12 administrierbare Module):**
  * Vollständig schemagesteuerte Konfiguration für 12 modulare Subsysteme (`kinetic`, `network`, `protection`, `xdr`, `l7`, `threat_intel`, `hardening`, `integrity`, `boot_trust`, `policy_trust`, `forensics`, `system`).
  * Der Server ist die einzige autoritative Quelle; das Dashboard wird vollständig aus Schemas ohne fest codierte Einstellungsnamen gerendert.
  * **Unveränderliche Snapshots auf heißen Pfaden:** Konfigurationsrevisionen werden zu atomaren, unveränderlichen Snapshots kompiliert. Ein Request bindet exakt einen Snapshot, was Race Conditions oder Hybridzustände bei Änderungen während laufender Anfragen ausschließt.
  * **Gehärtete Invarianten sind nicht administrierbar:** Kernel-Map-Grenzen, Core-IPC-Authentifizierung, Pfadvalidierung, Geheimhaltung privater Schlüssel, Management-Selbstaussperrschutz und Feed-Anti-Poisoning bleiben dauerhaft unveränderlich gesperrt.

* **Fabric Control-Plane Operationen & Drift-Erkennung:**
  * `GET /api/v1/settings/search` — Deterministische Suche über alle Konfigurationsschlüssel mit Live-Effektivwerten und Trefferbegründung.
  * `POST /api/v1/settings/export` — Kryptografisch signierte, geheimnisfreie Export-Bundles über alle Namensräume.
  * `POST /api/v1/settings/import/preview` + `.../apply` — Echter zweistufiger Import: kryptografische Signaturprüfung, Diff-Generierung und Ausführung via einmalig gültigen, ablaufenden Tokens, die an den geprüften Inhalt gebunden sind.
  * `GET /api/v1/settings/drift` — Kontinuierliche Drift-Überwachung: Revisionen, die die Synchronisation mit der Engine verfehlen, signalisieren `CONFIG_DRIFT` (niemals fälschlicherweise `SYSTEM_NOMINAL`).

* **Vollständig vendorte Offline-SVG-Weltkarte (jsVectorMap 1.7.0):**
  * 100% lokale Geometrie (`world_merc`) über 43 vendorte Quelldateien. Null CDN, null Kachelserver, null externe Netzwerkaufrufe.
  * **Strikte Durchsetzung von Trusted Types:** Arbeitet 100% konform mit `require-trusted-types-for 'script'`, indem DOM-String-Sinks durch native Button-Elemente umgangen werden.
  * Live-Tracking-Marker, pulsierende neue Quellen, Ereignisraten-Choroplethenkarten und distinkte Farbkategorien für blockierte Bedrohungen.
  * Begrenzte DOM-Render-Budgets (96 Tracking, 48 Blockiert, 24 Puls, 192 Regionen) mit visuellen Schwellenwerten.

* **UI/UX Supreme — Vollständiges Dashboard-Redesign:**
  * Wiederholende Kartenraster in Kinetic Defense, Threat Intel, Application Defense und XDR durch eine einheitliche Befehlsebene und gruppierte Telemetriespuren ersetzt.
  * Semantische `<dl>`-Datenstrukturen mit Haarlinien-Trennern ersetzen schwere Rahmen.
  * Zustandsgesteuerte Akzentfarben: funktionale Hervorhebungen aktivieren sich nur bei Werten ungleich Null.
  * Echte Tastatur-Barrierefreiheit (`<button>`), vollständige WCAG AA-Kontrastkonformität und voller Support für `prefers-reduced-motion`.

---

## 🚀 Neu in GeDefense 4.0.1: Chinesische Lokalisierung, Dedizierter XDR-Kernel-Recovery-Tab & Souveräne Expansion

VGT GeDefense 4.0.1 erweitert die Linux-Verteidigungsplattform um vollständige mehrsprachige Souveränität und selbstheilende Operator-Funktionen:

* **Vollständige Lokalisierung für vereinfachtes Chinesisch (`zh-CN` / `ZH`):**
  * 100% vollständige Übersetzung im gesamten Command Center über alle Tabs, Dialoge, Bedienfelder, Diagramme, Platzhalter und Toast-Benachrichtigungen (743 Schlüssel, identische Parität zu DE, EN und RU).
  * Erweiterung des öffentlichen Access Gateway Startbildschirms (`gateway/main.go`) um lokalisierte Texte, Cookie-gespeicherten Sprachwechsel und dedizierte `ZH`-Auswahl.
  * Automatische Erkennung via HTTP-`Accept-Language` priorisiert chinesische Spracheinstellungen (`zh`, `zh-CN`, `zh-Hans`).
* **Dedizierter XDR-Kernel-Recovery-Tab & Sicherer Zustands-Reset:**
  * Eigener XDR-Kernel-Recovery-Tab und Workflow (`#xdr`-Wiederherstellungsdialog), der es Administratoren ermöglicht, den Kernel-Sensor-Stack direkt über das Dashboard zu inspizieren, wiederherzustellen und neu zu initialisieren — ohne Notfall-SSH-Zugriff oder manuelle Befehlszeileneingriffe.
  * Authentifizierter Endpunkt `/api/v1/xdr/recovery` mit strikter Bestätigungsschranke `ARCHIVE_AND_REINITIALIZE_XDR`.
  * Beschädigte oder degradierte Vorfalls-Ledger-Ketten werden Byte für Byte mit kryptografischen SHA-256-Manifesten nach `/var/lib/vgt/gedefense/xdr-recovery/` archiviert.
  * Erstellt absturzsicher eine frische Vorfallskette unter strikter Bewahrung von Master-Keys, Sensor-IPC-Tokens und Administrator-Zugangsdaten.
  * Re-initialisiert Kernel-eBPF-Sensoren, BPF-LSM-Hooks, Ring-Buffer-Verbindungen und Prozessmonitore.
  * Erfordert Festplattenverifikation und einen unveränderlichen, signierten Evidenz-Ledger-Commit, bevor der permanente `DEGRADED`-Status aufgehoben wird.
* **Kryptografische Evidenz & Ledger-Hash-Integrität:**
  * Trennung der Angriffs-Merkle-Evidenzwurzel (`evidence_root`) von den MAC-Kettenhashes des Vorfalls-Ledgers (`record_hash`), wodurch korrelierte Vorfälle auch über Dienstneustarts hinweg kryptografisch prüfbar bleiben.
  * Gehärtete XDR-Statusweitergabe stellt sicher, dass routinemäßige Hintergrundabfragen niemals einen persistenten degradierten Kernelzustand maskieren.

---

## 🚀 Native L7-Anwendungsverteidigung & Souveräne Härtung (v4.0.0 Architektur)

VGT GeDefense 4.0 erweitert die bisherige L3/L4/Kernel-Architektur um eine **vollständig integrierte, native L7-Anwendungssicherheitsebene (WAF & Reverse-Proxy-Gate)**. Das System analysiert und schützt Webanwendungen und APIs unmittelbar vor der eigentlichen Anwendungslogik — vollständig implementiert mit Primitiven der Go-Standardbibliothek, null Drittanbieter-Abhängigkeiten, null CGO und null externen Skript-Runtimes.

### 🌟 Kernfähigkeiten & L7-Anwendungssicherheit (WAF)
* **Native L7-Ebene (Nur Go-Stdlib):** Voll integrierte WAF, direkt in den `gedefense-control`-Daemon einkompiliert. Null externe Pakete in `go.mod`, kein Lua/WASM/Node.js-Overhead, minimale Latenz und minimaler Speicherverbrauch.
* **Dual-Mode Bereitstellungsarchitektur:**
  * *Advisory / Standalone Socket (`inspect.sock`):* Lokaler Unix-Socket im Modus `0660` für beliebige Webserver (nginx, Apache, Caddy, Envoy) via standardisiertem JSON-Inspektionsprotokoll (`POST /v1/inspect`) mit strikter Envelope-Validierung (`DisallowUnknownFields`).
  * *Natives Inline-Reverse-Proxy-Gate (`edge.sock`):* Arbeitet transparent zwischen TLS-Terminierung und Upstream-Anwendung. Begrenzte Nebenläufigkeit, Fail-Closed-Zulassungsbudgets und strikte Upstream-Isolierung (ausschließlich saubere absolute Unix-Sockets oder explizite Loopback-IP-Literale; keine DNS-Auflösung zur Laufzeit, kein anfragegesteuertes Routing).
* **Begrenzte Normalisierungs- & Anti-Evasions-Engine:**
  * Mehrstufige rekursive Dekodierung (URL-Pfad-/Query-Unescaping, HTML-Entities, Escape-Sequenzen `\uXXXX` und `\xXX`).
  * Unicode Fullwidth Fold (`\uff01`–`\uff5e` auf ASCII abgebildet), verhindert Filterumgehungen durch asiatische Vollbreitenzeichen.
  * Automatische Erkennung und Dekodierung von ungepaddeten und URL-sicheren Base64-Strings in Parametern.
  * Streaming-JSON-Parser mit strikten Rekursionstiefenbegrenzungen (`max_json_depth = 32`) und Token-Budgets.
  * Begrenzte Dekomprimierung: Gzip/Deflate via `io.LimitReader` (Schutz vor Zip-Bomb-/Dekompressions-DoS).
  * Überlappende Blockverarbeitung (256-Byte-Überlappung) für unstrukturierte Textkörper, verhindert Signaturumgehung an Blockgrenzen.
* **Vollständige Angriffserkennungs-Suite (Lineares RE2, Null ReDoS):**
  * *SQL-Injection (SQLi):* UNION SELECT-Syntax, boolesche Tautologien (`' OR 1=1`), Zeitverzögerungen (`pg_sleep`, `benchmark`), gestapelte Query-Befehle.
  * *Cross-Site Scripting (XSS):* Script-Tags, Inline-Event-Handler (`onerror=`, `onload=`), gefährliche Browser-Schemata (`javascript:`, `data:text/html`), `iframe srcdoc`.
  * *Command Injection / RCE:* Shell-Verkettungen (`;`, `&&`, `||`, `|`), Substitutionssyntax (`$(...)`, Backticks), PowerShell- und CMD-Payloads.
  * *Pfadtraversal & LFI:* Traversal-Sequenzen (`../`, `..\`), sensible Linux-Pfade (`/etc/passwd`, `/proc/self/environ`), Stream-Wrapper (`php://`, `phar://`, `data://`).
  * *SSTI, XXE & Deserialisierung:* Template-Syntax (Jinja, Twig, Smarty, Spring), externe XML-Entitäten, PHP-Objektserialisierung, Java-Magic-Bytes (`rO0AB`), JNDI/Log4j-Aufrufe.
  * *HTTP-Protokoll-Smuggling & Anomalien:* Doppelte oder ungültige `Content-Length`, CL.TE / TE.CL-Mehrdeutigkeiten, ungültige Transfer-Encodings, blockierte Methoden (`TRACE`).
* **Evasive SSRF-Erkennung mit flexibler IP-Normalisierung:**
  * Normalisiert und blockiert alternative IPv4-Darstellungen: Hexadezimal (`0x7f.1`), Oktal (`0177.1`), dezimale DWORD-Ganzzahlen (`2130706433`), 2-/3-teilige Kurzschreibweisen.
  * Umfassende Schutzräume gegen Cloud-Metadaten-Endpunkte (AWS/OpenStack IMDSv2 `169.254.169.254`, GCP `metadata.google.internal`, Azure `168.63.129.16`, Alibaba `100.100.100.200`, Oracle `192.0.0.192`).
* **In-Memory Airlock Multipart-Inspektion (`InspectBytes`):**
  * Multipart-Dateiuploads werden direkt im RAM geprüft — **niemals auf persistenten Datenträgern zwischengespeichert**.
  * Begrenzte Dateigrößen und Part-Zahlen; Prüfung von Magic Bytes (ELF, PNG, JPEG, GIF, PDF, ZIP), MIME-Konsistenz, doppelten Endungen (`.php.jpg`), Null-Byte-Injektionen und Malware-Hash-Blacklists.
* **3-stufiges geshardetes Token-Bucket Rate Limiting:**
  * 64 unabhängige Shards via FNV-1a-Hashing eliminieren globale Mutex-Konflikte unter hoher Last.
  * Client-bezogene Volumengrenzen (glätten volumetrische Verkehrsspitzen).
  * Routenbezogene Schutzgrenzen für sensible Endpunkte (schützen `/login`, `/wp-login.php`, `/api/login` vor Brute Force).
  * Globale Routengrenzen (wehren verteilte Botnetze und Credential-Stuffing über rotierende IPs ab).
* **Response Data-Leak Prevention (DLP):**
  * Überwacht Upstream-Antwortkörper auf Datenbankfehler (`SQLSTATE`), Quellcode-Leaks (`<?php`, `<jsp:`), Anwendungs-Stacktraces (Python, Java, Go) und Offenlegung privater Schlüssel (`BEGIN RSA PRIVATE KEY`).
  * Begrenzte Präfixprüfung unter Beibehaltung der exakten Wire-Bytes (`FuzzL7ResponseInspectionPreservesWireBytes`).
* **Web-Evidenz-Isolation im XDR (Anti-False-Positive-Barriere):**
  * L7-Ereignisse werden mit `AlertOnly: true` und `ResponseScore: 0` protokolliert.
  * **Sicherheitsgarantie:** Ein Webangriff kann **niemals autonom** destruktive Host-Reaktionen (SIGKILL/SIGSTOP) gegen lokale Serverprozesse auslösen. Destruktive Reaktionen erfordern stets unabhängige Host-/Kernel-Evidenz.
  * L7-Ereignisse werden als Knoten (`HTTP_REQUEST`, `HTTP_RESPONSE`) in den Trinity XDR 2.0 Kausal-DAG mit Merkle-Root-Beweisen eingespeist.
* **Linux DAC & Betriebssystem-Härtung:**
  * Dedizierte Systemgruppe `gedefense-l7`.
  * Laufzeitverzeichnis `/run/vgt-gedefense-l7` (Modus `0750`, `gedefense:gedefense-l7`) via `systemd-tmpfiles`.
  * Sockets mit Modus `0660` und Kernel-Peer-Credentials (`SO_PEERCRED` via `syscall.GetsockoptUcred`).
  * Gehärtete systemd-Units mit `SupplementaryGroups=gedefense-l7` und restriktiven `ReadWritePaths`.
* **Kontinuierliches Fuzzing & Quality Gates:**
  * 3 neue CI-Fuzz-Ziele (`FuzzL7NormalizerNeverPanics`, `FuzzL7ResponseInspectionPreservesWireBytes`, `FuzzL7InlineUpstreamParserNeverEscapesLocalHost`).
  * Go 1.26.8 Toolchain-Pinning mit automatisiertem AST-Sicherheits-Audit in `scripts/security-audit.sh`.

---

## 🌟 Architekturdurchbrüche von V2 Beta 1 zu V3 Beta 1 (`3.0.0-beta.1`)

VGT GeDefense 3.0.0-beta.1 wandelte die Architektur von einem statischen Host-/Netzwerksensor in ein **vollständig autonomes, reversibles Linux-Sicherheitsgewebe mit Defense-in-Depth**:

* **Dual-Mode-Doktrin (Identische Binärdateien, dynamische Fähigkeitserkennung):** Einheitliche Binaries für AstraeaOS (native Ring-1 GaiaCells, BPF-LSM, Key-Broker) und generische Linux-Distributionen (Ubuntu, Debian, RHEL, Fedora, Arch, Alpine) mit dynamischer Laufzeit-Enklavenerkennung (`platform_caps.go`).
* **Trinity Dynamischer Angriffs-Story-DAG & Vorfallskorrelator:** Kausale Rekonstruktion vollständiger Angriffsgraphen (`CANARY_TRIGGERED`, `PRIVILEGE_ESCALATED`, `EGRESS_ATTEMPTED`) mit deterministischer Merkle-Root-Evidenz statt isolierter Protokollzeilen.
* **Autonome reversible Reaktions-Engine:** Mehrstufige Quarantäne (`CONTAIN_IP`, `FREEZE_EXECUTION`, `CONTAIN_CELL`) mit semantischen TTL-Vorgaben und automatisiertem Rollback bei fehlender Operator-Bestätigung.
* **Nemesis Cyber Deception Grid:** Physische Canary-Fallen auf der Festplatte (`0600`) mit dynamischer Schlüsselableitung via `StorageCipher` und kalibrierter RASP-Erkennung (85% System/Backup vs. 98% unbefugte Entitäten).
* **Styx Zero-Trust Egress & SSRF Shield:** Cgroup-/Cell-basierte Whitelist für ausgehenden Verkehr mit integriertem Filter gegen Cloud-Metadaten-Exfiltration (AWS, GCP, Azure, Alibaba, OCI, IPv6 IMDSv2).
* **Airlock Ingress & Polyglot-Inspektor:** Strikte Magic-Byte-Prüfung, SVG-Bereinigung (neutralisiert eingebettete Skripte, foreignObjects, Embeds, Iframes und DTDs) und Quarantäne-Bereitstellung mit harten Größenlimits und Symlink-Einsperrung.
* **Morpheus Linux RASP & Credential Scrubber:** Schützt überwachte Daemons vor Speicher-Scraping (`/proc/<pid>/mem`, `ptrace`) und maskiert API-Keys und Token in Befehlszeilenargumenten automatisch.
* **Chronos Wiederaufnehmbare FIM:** Ressourceneffizienter Dateiintegritätsscanner mit atomaren Checkpoints, Deskriptor-Leak-Beseitigung und Merkle-Baum-Integritätswurzeln.
* **Reversibler Prozess-Freeze:** Validiert `/proc/<pid>/stat` Start-Ticks gegen PID-Wiederverwendungs-Races; der Rust Core nutzt `libc::SIGCONT` (`XDR_CONT`), um Prozesse nach Ablauf der TTL sicher fortzusetzen.
* **Evasionssichere SSRF-Validierung:** Kanonisiert und fängt dezimale DWORD-, Hexadezimal-, Oktal- und IPv4-in-IPv6-Darstellungen ab und blockiert interne Loopback-Ziele strikt.
* **Zero-Trust Memory Zeroization:** `StorageCipher.Destroy()` überschreibt Hauptschlüssel beim Herunterfahren sicher im RAM.

---

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/29413de7-469a-4207-98bf-496ab69ef20a" />



## 🔍 Was ist VGT GeDefense?

GeDefense ist kein einfacher Firewall-Regelmanager. Es ist ein **lokales, souveränes Linux-Sicherheitsgewebe** — kernelnahe Netzwerkverteidigung, Host-XDR, verschlüsselter Evidenz-Ledger, reversible Systemhärtung und optionale AstraeaOS-native Isolation in einem System, betrieben ohne jede Cloud-Control-Plane.

```
Herkömmliche Linux-Sicherheits-Stacks:
  Unkoordinierte Tools (iptables + auditd + fail2ban)  → kein geteilter Status
  Konfiguration als Vertrauensbasis                     → eigene Regeln erzwingen sofort
  Keine Evidenzkette                                   → Vorfälle nicht beweisbar
  Kein Rollback                                        → Härtungsänderungen irreversibel
  Cloud-SIEM / Control-Plane                           → Daten verlassen den Host

VGT GeDefense:
  Rust eBPF/XDP Data Plane                → kernelnah, bis zu 250.000 Blockeinträge
  Go Control Plane (XDR, Policy, FIM)     → getrennte Vertrauensdomäne, nur Loopback
  Rust Response Core (pidfd, SIGKILL)     → Broker-geprüft vor jedem Kill-Signal
  Getrennte Vertrauensdomänen             → Public Gateway · Control · Core · Data Plane
  Ed25519-signierter Evidenz-Ledger       → monotone Sequenz + Vorgänger-Hash
  AES-256-GCM geschützte FIM-Baselines    → Fail-closed bei Integritätsverletzung
  Reversible Härtung                      → Compare-and-Set, atomare Persistenz, Auto-Rollback
  Verschlüsselter Response Vault (AES-GCM)→ Quarantäne mit SHA-256-Identität
  Keine Cloud-Control-Plane               → sensibler Zustand verlässt niemals den Host
  Universelles Linux                      → APT · DNF/YUM · pacman · Zypper Integration
  AstraeaOS-nativ                         → verifizierter Quellspiegel, identische Kette
```

Ein einzelner Regex-, Feed-, Verhaltens- oder Maskierungs-Treffer **kann niemals eine Prozessbeendigung autorisieren**. Enforce erfordert mindestens zwei unabhängige autorisierte Kategorien, objektive Broker-Evidenz und einen nicht-degradierten Systemzustand.

---

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/1f5cf6ae-ee59-498d-9c5b-e06e8efc9ef2" />



## 🏛️ Architektur

```
┌──────────────────────────────────────────────────────────────┐
│                    PUBLIC ACCESS GATEWAY                      │
│   Go · TLS 1.3 · Argon2id · Host/Origin/CSRF · Session       │
│   unprivilegiert · Port 9843 (konfigurierbar 1024–65535)     │
├──────────────────────────────────────────────────────────────┤
│                      CONTROL PLANE                            │
│   Go · XDR · Policy · Telemetrie · FIM · Evidenz · Fälle     │
│   Benutzer: gedefense · nur Loopback (TCP 9844)              │
├──────────────────────────────────────────────────────────────┤
│                      RESPONSE CORE                            │
│   Rust · VGT3 IPC · pidfd · Quarantäne · Sysctl-Mutationen   │
│   UID 0 · Capability Bounding · HMAC-authentifizierte IPC    │
│   /run/vgt-gedefense/core.sock                               │
├──────────────────────────────────────────────────────────────┤
│                       DATA PLANE                              │
│   eBPF/XDP · IPv4/IPv6 · LPM Allow-/Blocklisten am Interface │
│   Kernel/XDP · bis zu 250.000 Blockeinträge                  │
└──────────────────────────────────────────────────────────────┘
```

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/0712a990-f3ad-4b4a-8d18-8e0a60395fe1" />



### Trennung der Vertrauensdomänen

| Domäne | Rolle | Privilegien |
|---|---|---|
| **Public Gateway** | TLS 1.3, Argon2id, Host/Origin/CSRF, Sitzungs-Auth | Unprivilegiert |
| **Control Plane** | XDR, Policy, Telemetrie, FIM, Evidenz, Fälle, Dashboard | Benutzer `gedefense` |
| **Response Core** | XDP-Maps, pidfd-Reaktion, Quarantäne, typisierte Sysctl-Mutationen | UID 0, Capability Bounding |
| **Data Plane** | IPv4/IPv6-Parsing, LPM Allow-/Blocklisten am Interface | Kernel/XDP |

### Bereitstellungsmodi

**Universelles Linux** — Ein-Klick-Installation auf x86_64 systemd Linux mit APT, DNF/YUM, pacman oder Zypper. Rust Core und eBPF werden für den Zielkernel und die Netzwerkkarte kompiliert und vor der atomaren Aktivierung verifiziert.

**AstraeaOS-nativ** — Identische Kern-Binärdateien, natives Provisioning, AstraeaOS-Härtungsprofil, Boot-Trust-Evidenz und optionale Gaia Cells-Integration. GeDefense ist die **einzige Sicherheitsautorität** in AstraeaOS. Sentinel dient ausschließlich als Migrations- und Auditquelle — kein konkurrierender Laufzeit-Daemon.

---

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/57feccc5-75ab-46a1-a575-3a5ec3402087" />



## 🛡️ Verteidigungsgewebe

### Netzwerkverteidigung (Rust eBPF/XDP)

| Funktion | Detail |
|---|---|
| **Data Plane** | Rust eBPF/XDP — natives XDP mit Generic-XDP-Fallback |
| **Protokollabdeckung** | IPv4 und IPv6 |
| **Matching** | LPM Tries — Longest Prefix Match |
| **Kapazität** | Bis zu 250.000 Blockeinträge |
| **Management-Allowlist** | Wird vor der Blockliste angewendet — Management-Zugriff bleibt stets erhalten |
| **CIDR-Regeln** | Signiert mit TTL |
| **Feed Auto-Apply** | Standardmäßig deaktiviert — öffentliche Feeds erfordern explizite Betreiberautorisierung |
| **Leer-Verifikation** | Autoritative `VERIFY_EMPTY`-Prüfung — keine stillen Restregeln |

### Host-XDR

| Funktion | Detail |
|---|---|
| **Signale** | Prozess, Befehl, Abstammung, Herkunft, Maskierung, Netzwerk, Threat Intel |
| **Profile** | Adaptiv, kardinalitätsbegrenzt pro Prozess |
| **Benutzerdefinierte Regeln** | RE2-Regex — strikt Alert-only, niemals Auto-Enforce |
| **Multi-Signal-Gates** | Evidenzschranken vor jeder Eskalation erforderlich |
| **PID-Identität** | PID + pidfd-Bindung — immun gegen PID-Wiederverwendung |
| **Canary-Reaktion** | Evidenzgeprüftes SIGSTOP |
| **Enforce-Reaktion** | Ausschließlich Broker-geprüftes SIGKILL |

**XDR-Standardgrenzen**

| Parameter | Wert |
|---|---|
| Prozess-Scan-Intervall | 750 ms |
| Netzwerk- / Integritätsprüfung | 3 s / 3 s |
| Alert- / Contain- / Kill-Schwellenwert | 40 / 80 / 120 |
| Worker / Warteschlange | 4 / 2.048 |
| Auswertungen pro Scan | 4.096 |
| Vorfalls-Log-Obergrenze | 64 MiB |

### Evidenz & Integrität

| Funktion | Detail |
|---|---|
| **Evidenz-Ledger** | Verschlüsselt + Ed25519-signiert |
| **Kettenstruktur** | Monotone Sequenz + Vorgänger-Hash |
| **Kürzungs-Schutz** | Separater Head-Checkpoint |
| **FIM-Baselines** | AES-GCM geschützt |
| **Traversierung** | Begrenzt + Streaming SHA-256 |
| **Sicherheitsprüfungen** | Race-, Symlink- und Modus-Verifikation |
| **Integritätsverletzung** | Fail-closed — keine stille Degradierung |

### Fälle & Transaktionen

| Funktion | Detail |
|---|---|
| **Fallkorrelation** | Verschlüsselte Fallkontexte |
| **Wiederauftreten** | Wiederauftretens-Handling mit Ledger-Verpflichtung |
| **Härtungsablauf** | Vorschau → Autorisieren → Anwenden |
| **Auditablauf** | Verifizieren → Auditieren → Zurücksetzen |
| **Start** | Abstimmung — Drift-Quarantäne statt blindem Überschreiben |

---

## 🔒 Betriebssicherheit — Promotions-Gates

```
Observe ──→ Canary ──→ Enforce
   │            │           │
   │       Evidenz-      Signierte CIDR
   │       geprüftes     + Allowlist
   │       SIGSTOP        Sync
   │
 XDP aktiv, keine Blockregel
 verifizierter leerer Kernelzustand
```

| Zustand | Netzwerk | Prozessreaktion | Freigabebedingung |
|---|---|---|---|
| **Observe** | XDP aktiv, keine Blockregel | Aufzeichnung | Verifizierter leerer Kernelzustand |
| **Canary** | Fortgesetzte Beobachtung | Evidenzgeprüftes SIGSTOP | Policy-, Soak- und Health-Gates |
| **Enforce** | Signierte CIDR-Regeln | Broker-geprüftes SIGKILL | Synchronisierte Management-Allowlist |
| **Degraded** | Fail-safe / unbestätigt | Aktive Reaktion ausgesetzt | Sichtbare Wiederherstellung erforderlich |

**Not-Aus-Sequenz:** Reaktion deaktivieren → Blockregeln entfernen → authentifiziertes `VERIFY_EMPTY` → signierte Observe-Policy persistieren → erst dann: verified-empty. Kein Zwischenfehler wird als sicher gemeldet.

---

## 🔐 Kryptografie

| Zweck | Methode | Profil |
|---|---|---|
| **Betreiber-Passwort** | Argon2id | 64 MiB · t=3 · p=1 · 128-Bit-Salt · 256-Bit-Output |
| **Control ↔ Core IPC** | HMAC-SHA-256 | 32-Byte-Schlüssel · Zeitfenster · Nonce · Replay-Cache · SO_PEERCRED |
| **Operativer Speicher** | AES-256-GCM | Zufällige Nonces · zweckgetrennte Unterschlüssel · AAD-Bindung |
| **Policy / Evidenz** | Ed25519 | Lokales Signieren und Verifizieren |
| **Inhaltsidentität** | SHA-256 | Streaming-Hash mit Identitäts-Recheck |
| **Public Gateway** | TLS 1.3 | Lokales oder bereitgestelltes Zertifikat |

AAD-Kontext: Schema · Knoten · Zweck · kanonischer Pfad · Sequenz.
Legacy PBKDF2 wird nur für Migration akzeptiert — wird bei erfolgreicher Anmeldung atomar auf Argon2id aktualisiert.

### Browser- & API-Härtung

| Maßnahme | Status |
|---|---|
| Keine CDN-, Tracker- oder Webfont-Abhängigkeiten | ✓ |
| Keine dynamischen HTML-Sinks oder eval | ✓ |
| Strikte CSP und Framing-Verbot | ✓ |
| Synchronizer CSRF + exakte Origin-Prüfung | ✓ |
| Secure, HttpOnly, SameSite=Strict | ✓ |
| Serverseitige Bearer-Injektion | ✓ |
| Request-ID, TTL und Replay-Schutz | ✓ |
| HTTPS-Feeds mit DNS-/SSRF-Schutz | ✓ |
| Native L7/AppSec-Ebene mit begrenzter Normalisierung | ✓ |
| L7-Implementierung fügt null Go-/Laufzeit-Abhängigkeiten hinzu | ✓ |
| Keine Befehlsausführung zur Laufzeit in Go-Diensten | ✓ |
| Backend ausschließlich auf Loopback | ✓ |

**Sensibler Zustand und Schlüssel verlassen niemals den geschützten Host.**

---

## 🔧 Reversible Härtung

Profile: `Generic Linux Server` und `AstraeaOS Workstation` — feste Key/Value-Allowlist.

Kernelwerte werden per Compare-and-Set geändert, zurückgelesen und atomar in `/etc/sysctl.d/90-vgt-gedefense.conf` persistiert.

Der Rust Core verfügt über **keine generische Shell-, Dateisystem- oder Sysctl-Schnittstelle**. Partielle Profilfehler lösen ein automatisches Zurücksetzen in umgekehrter Reihenfolge aus.

### Verschlüsselter Response Vault

| Funktion | Detail |
|---|---|
| **Verschlüsselung** | AES-256-GCM |
| **Blockgröße** | 1 MiB |
| **Max. Quelldatei** | 256 MiB |
| **Identität** | SHA-256 + vollständige Dateiidentität |
| **Erfassung** | Atomar — wiederherstellungsgeprüft |
| **Symlink-Abwehr** | openat2, O_NOFOLLOW |
| **Vault-Berechtigungen** | root:gedefense 0700 — kein CAP_DAC_OVERRIDE |

---

## 🐧 Universelle Linux-Integration

| Schicht | Beta v4 Integration |
|---|---|
| Paketmanager | APT · DNF/YUM · pacman · Zypper |
| Init | Gehärtete systemd-Units mit Syntax- und Laufzeit-Gates |
| Privilegiengrenze | Polkit-gestützter Readiness-Helper — keine generische Root-Shell |
| Desktop | Lokales Chromium-Anwendungsprofil mit exaktem SPKI-Pinning |
| TLS-Identität | Öffentlicher Host plus `localhost`-, `127.0.0.1`- und `::1`-SANs |
| Release-CI | Go Race/Fuzz/Security · Rust Core · eBPF · Artefakt-Digests |
| Distributionsverträge | Ubuntu/Debian · Fedora/RHEL · Arch · openSUSE |
| Konkretes Host-Gate | bpffs · verifier-sichtbares eBPF · NIC XDP · IPC · TLS |

Distributions-Container validieren portable Paketierungs- und Integrationsverträge. Sie qualifizieren nicht den Host-Kernel. Jeder binäre Release erfordert weiterhin den privilegierten Test auf dem konkreten Kernel, Treiber und Netzwerkgerät.

---

## 🌐 AstraeaOS-Integration

| Funktion | Status |
|---|---|
| Natives Provisioning / systemd | ✅ Implementiert — identische Sicherheitskette wie Standalone |
| GeDefense Quellspiegel | ✅ Implementiert — SHA-256-Manifest verifiziert |
| AstraeaOS Härtungsprofil | ✅ Implementiert — reversibel und persistent |
| Boot-Trust-Evidenz | ✅ Implementiert — rein Evidenz, keine falsche Attestierungsbehauptung |
| Gaia Cells VGTGC1 Adapter | ✅ Implementiert — Laufzeit optional |
| UUID / Generation / cgroup-ID-Bindung | ✅ Implementiert — unveränderliche Aktionsbindung |
| Freeze / Netzwerk-Rollback | ✅ Implementiert — evidenzgebundene Transaktion |
| Gaia Cells Lifecycle Daemon | — Nicht enthalten — AstraeaOS-eigene Laufzeit |
| Isolierter Deception Service | — Zurückgestellt — außerhalb der Beta-Zuständigkeit |

Cell-Aktionen sind an UUID, Lebenszyklus-Generation und Kernel-cgroup-ID gebunden. Peer-UID, HMAC, Zeitfenster und Nonce werden verifiziert.

Ist die Gaia Cells-Laufzeit **nicht vorhanden**, meldet der Adapter `runtime_not_installed`. Die generische Host-Verteidigung bleibt aktiv und ist **nicht degradiert**.

> **Einzige Autorität:** In AstraeaOS ist GeDefense die einzige Sicherheitsautorität. Sentinel dient ausschließlich als Migrations- und Auditquelle.

---

## ⚙️ Laufzeitvertrag

### Systemanforderungen (Standalone)

| Anforderung | Wert |
|---|---|
| **Betriebssystem** | Linux |
| **Architektur** | x86_64 / amd64 |
| **Init** | systemd |
| **Kernel** | BPF/XDP + pidfd |
| **Paketmanager** | apt-get, dnf/yum, pacman oder zypper |
| **Installation** | Root + Internetzugriff für den Build |
| **Gateway-Laufzeit** | libargon2.so.1 |

> Für diese Beta wird keine pauschale Mindest-Kernelversion oder garantierte NIC-Liste deklariert. Der Ziel-Host wird durch Build-, Kernel-Verifier-, XDP-Attachment-, IPC- und Health-Gates qualifiziert.

### Toolchain-Pins

| Komponente | Version |
|---|---|
| **Go** | 1.26.8 |
| **Rust Core** | 1.97.1 |
| **Rust eBPF** | nightly-2026-07-16 |
| **Rust-Komponente** | rust-src |
| **bpf-linker** | 0.10.3 |
| **Cargo-Auflösung** | `Cargo.lock --locked` |

### Schnittstellen

| Schnittstelle | Standard | Exposition |
|---|---|---|
| **HTTPS Gateway** | TCP 9843 | Administrativ / öffentlich — konfigurierbar 1024–65535 |
| **Go Control Backend** | TCP 9844 | Nur Loopback |
| **Rust Core IPC** | `/run/vgt-gedefense/core.sock` | HMAC-VGT3 + SO_PEERCRED |
| **L7-Inspektions-API** | `/run/vgt-gedefense-l7/inspect.sock` | Lokaler Unix-Socket · begrenzt · optional SO_PEERCRED |
| **L7-Inline-Edge** | `/run/vgt-gedefense-l7/edge.sock` | Optionale lokale Unix-Reverse-Proxy-Grenze |
| **Gaia Cells** | `/run/gaia-cells/control.sock` | Optional — VGTGC1 |
| **Threat Feeds** | HTTPS ausgehend | Optional — nur öffentliche IPs |

### Dateisystem-Layout

| Pfad | Zweck |
|---|---|
| `/opt/vgt/gedefense/releases/<version>` | Unveränderlicher Release |
| `/opt/vgt/gedefense/current` | Atomarer aktiver Symlink |
| `/etc/vgt/gedefense/` | Konfiguration, TLS und Geheimnisse |
| `/var/lib/vgt/gedefense/` | Verschlüsselter operativer Zustand |
| `/var/lib/vgt/gedefense/quarantine/objects` | Verschlüsselter Response Vault |
| `/run/vgt-gedefense-l7/` | Ausschließlich flüchtige L7-Unix-Sockets |
| `/sys/fs/bpf` | BPF-Dateisystem |
| `/var/log/vgt-gedefense-install.log` | Installationsdiagnose — Modus 0600 |

---

## 🚀 Schnellstart

```bash
# Installer herunterladen
wget https://github.com/visiongaiatechnology/gedefense/releases/download/v4.2.2/GeDefense-4.2.2-OneClick.run

# SHA-256 verifizieren
sha256sum --check GeDefense-4.2.2-OneClick.run.sha256

# Installieren (Root erforderlich)
chmod 700 GeDefense-4.2.2-OneClick.run
sudo ./GeDefense-4.2.2-OneClick.run
```

> Der Installer und die Prüfsumme werden erst veröffentlicht, nachdem alle GitHub-CI- und konkreten Linux-Host-Qualifikations-Gates bestanden wurden. Führe niemals eine nicht verifizierte RUN-Datei aus.

Der Installer ist erst erfolgreich nach Bestehen von: **Build → Kernel Verifier → XDP Attachment → IPC → Backend → TLS Gates**.

Die Firewall-Regel für den HTTPS-Gateway-Port (TCP 9843) kann während der Installation via UFW, firewalld oder iptables eingerichtet werden.

**Starte im Observe-Modus. Canary und Enforce erst nach dokumentiertem Durchlaufen der Gates.**

---

## ✅ Release-Gates

| Gate | Zustand | Release-Regel |
|---|---:|---|
| Quell- und Upload-Manifeste | ✅ Implementiert | Keine Prüfsummen-Abweichung |
| Scan auf Geheimnisse/Schlüssel | ✅ Implementiert | Null Befunde |
| GitHub Actions & Container Digest Pinning | ✅ Implementiert | Ausschließlich unveränderliche Identitäten |
| Go Unit, Integration und Vet | 🔒 Erforderliche CI | Muss bestehen |
| Go Race Detector & Security Fuzz Smoke | 🔒 Erforderliche CI | Muss bestehen |
| JavaScript- und Shell-Syntax | ✅ Lokal + CI | Muss bestehen |
| Statisches Sicherheits-Regressions-Audit | 🔒 Erforderliche CI | Muss bestehen |
| Native Rust Common/Core-Tests | 🔒 Erforderliche CI | Muss bestehen |
| Rust Core und eBPF Release-Builds | 🔒 Erforderliche CI | Muss bestehen |
| Ubuntu, Fedora, Arch und openSUSE Verträge | 🔒 Erforderliche CI | Alle Matrix-Jobs müssen bestehen |
| Installer-Payload und SHA-256 Verifikation | 🔒 Erforderliche CI | Muss bestehen |
| Konkreter Kernel-Verifier und NIC XDP Attach | ⏳ Host-Qualifikation | Erforderlich pro Release-Host |
| systemd, IPC, Backend, TLS, Polkit und Desktop | ⏳ Host-Qualifikation | Erforderlich pro Release-Host |

**Verbleibendes Release-Gate:** Realer Ziel-Host-Smoketest für konkreten Kernel, Kernel-Verifier, XDP-Modus, Netzwerkschnittstelle und Netzwerktreiber.

---

## 🚧 Bekannte Einschränkungen (4.2.2)

- Keine Swarm- / Mesh-Unterstützung
- Kein QUIC-Offloading
- Keine DDoS-Absorption auf Provider-Ebene
- Keine TLS-Entschlüsselung
- Kein automatisches Erzwingen von Feeds (Feed Auto-Enforce)
- Keine Garantie gegen Root-Kompromittierung
- Keine vollständige Measured-Boot-Attestierung
- Gaia Cells Lifecycle Daemon extern (AstraeaOS-Laufzeit)
- Isolierter Deception Service zurückgestellt
- Wird eine geschützte Release-Komponente ersetzt, wird das mit hoher Schwere gemeldet und entwaffnet die Plattform nicht; die Ledger-Rotation setzt voraus, dass ihr Archivverzeichnis dem Dienst gehört und `0700` trägt, und verweigert den Lauf, statt in ein gemeinsames Verzeichnis zu schreiben
- Der Rust-Kern zählt und protokolliert übersprungene Ingress-Datensätze, meldet die Zahl aber noch nicht in seiner Health-Antwort; die Zahl steht daher im Dienstprotokoll und nicht im Panel

---

## 📋 Changelog

### v4.2.2 — Fail-Closed-Durchsetzung, Ledger-Rotation und ein ehrliches Panel *(Aktuell)*

Eine Härtungsversion. Sie entfernt die Wege, auf denen die Plattform ihren eigenen Schutz verlieren konnte, und bringt jede Oberfläche dazu, zu sagen, was der Kernel tatsächlich tut.

* **Fail-Closed-Durchsetzung (die Entwaffnung):**
  * **Eine automatische Degradierung gibt die verifizierte Kernel-Policy nicht mehr frei.** Ein einzelner Kernel-Datensatz, den der Kern nicht interpretieren konnte — ein gemischtes UDP/TCP-Aggregat, das der Producer mit dem Protokoll des auslösenden Pakets etikettiert, sodass ein TCP-Satz mehr Versuche als SYNs tragen kann — brach den ganzen Drain ab; die Kontrollplane las den fehlgeschlagenen Drain als verlorenen Kernel-Hook, und das Release-Gate beantwortete einen nicht verfügbaren Sensor mit einem Abgleich der Kernel-Policy auf `observe`. Jeder Block wurde aus dem Kernel entfernt, und ein Produktionshost lief zwanzig Stunden ungeschützt, weil nichts ihn zurückholte. Das Gate bestätigt und behält jetzt, was es verifiziert hat (`verified-enforce`), und ein nicht bestätigbarer Zustand wird als `verified-empty` gemeldet, statt als dasselbe zu gelten.
  * **Ein Neustart behält die Enforcement der signierten Policy** statt auf `observe` zu initialisieren.
  * **Eine Promotion senkt eine verifizierte Enforcement nicht.** Das tut nur ein ausdrücklicher Betreiber-Eingriff, und eine Beibehaltung wird als eigene Aktion gemeldet (`automatic_response_paused`), nicht als Änderung der Enforcement.
  * **Ein Drain- oder Parserfehler ist vom Verlust der Durchsetzungsfähigkeit getrennt,** sodass ein Sensor, der keine Daten liefern kann, nicht länger als ein Kernel gelesen wird, der nicht blockieren kann.
  * **Die Plattform bewaffnet sich selbst neu,** sobald die Gates bestehen und die Ruhe hält, und protokolliert den Übergang mit dem Grund, der ihn aufgehalten hatte.
  * **Ein erfolgreicher Verifikationslauf löscht den Grund, den er ersetzt hat.** Gründe waren einseitig: nur eine Rotation oder eine Betreiber-Wiederherstellung entfernte sie, sodass ein transienter Fehler XDR degradiert ließ — und die automatische Antwort pausiert — bis jemand die Kontrollplane neu startete.
  * **Ein Deployment des Betreibers gilt nicht mehr als Eindringen.** Der Austausch einer eigenen Komponente degradierte XDR und pausierte die automatische Antwort; jeder ausgelieferte Fix schaltete damit stillschweigend einen Teil des Schutzes ab. Jetzt ist es ein Ereignis hoher Schwere ohne Reaktion; Fremdobjekte behalten die volle Antwort.
  * **Die Wiederherstellung des Incident-Ledgers verlangt nicht mehr, den Schutz aufzugeben** — unter Beibehaltung war das unerreichbar; das Ledger ließ sich nur reparieren, indem man zuvor den Host entwaffnete, dessen Schutz es erhalten soll.
  * **Der Rust-Kern toleriert ein widersprüchliches Aggregat.** Ein Datensatz, dessen TCP-Label seinen Zählern widerspricht, wird mit neutralisiertem Protokoll und unveränderten Zählern behalten; ein weiterhin undekodierbarer Datensatz wird übersprungen und benannt, statt den Drain abzubrechen; nur ein Batch, in dem viele Sätze undekodierbar sind — die Signatur eines falschen Wire-Formats — wird als Fehler gemeldet.
* **Ledger-Aufbewahrung:**
  * **Beide Forensik-Ledger rotieren, statt sich zu füllen.** Das Erreichen des Budgets stoppte die Aufzeichnung, degradierte XDR und pausierte die automatische Antwort, bis ein Betreiber das Segment von Hand archivierte — zweimal an einem Tag auf einem Produktionshost. Bei neunzig Prozent wird die versiegelte Kette mit einem Manifest archiviert, das Größen, Digests, Sequenz, Head-Hash und Prüfumfang trägt, und eine frische Kette beginnt.
  * **Die Rotation übersteht einen Absturz.** Sie kopiert, bevor sie ersetzt; ein unterbrochener Lauf wird beim nächsten Start aus einer Rotationsmarkierung vervollständigt, und eine Markierung, deren Manifest nicht passt, wird abgelehnt statt geglaubt.
  * **Das Evidenz-Ledger verifiziert sich in Grenzen.** Der Start prüfte das ganze Ledger — rund 260 MB bei etwa 6,7 Sekunden pro Megabyte — und überschritt das Start-Timeout der Unit, sodass weder die Plattform noch das Gateway hochkamen. Der Start prüft jetzt den authentifizierten Checkpoint und ein begrenztes Tail-Fenster; die Historie wird im Hintergrund inkrementell gegen einen authentifizierten Wasserstand abgedeckt; die vollständige Verifikation bleibt dem Betreiber verfügbar. Ein nicht authentifizierter Wasserstand wird abgelehnt, weil eine gefälschte Datei damit die ganze Historie übersprang.
  * **Ein unterbrochener Append wird wiederhergestellt** — verifiziert und versiegelt oder als partieller Schreibvorgang verworfen — statt den Dienststart zu verhindern.
* **Oberflächen-Verifikation:**
  * **Jeder zustandstragende Satz wird gegen die Nutzlast geprüft, aus der er stammt.** Ein Headless-Rendering des Dashboards — elf Nutzlast- und Ansichtskombinationen, achtzig Regeln — vergleicht, was der Betreiber liest, mit dem, was die API gemeldet hat. Es fand drei Aussagen, die dem Zustand widersprachen, den sie beschrieben; alle drei stammten aus den Korrekturen dieser Version.
  * **Der Prüfer belegt, dass er fehlschlagen kann.** Ein Selbsttest mit absichtlich falschen Nutzlasten und ein Regressionsmodus, der die Wächter wieder entfernt: achtzehn der achtzig Regeln werden dann rot, darunter SYSTEM NOMINAL im Badge.

### v4.2.1 — Stabilität, Evidenz und Oberfläche

Eine Fehlerbehebungsversion. Sie bringt kein neues Teilsystem; sie bringt die vorhandenen dazu, die Wahrheit über sich zu sagen und dem Betreiber nicht im Weg zu stehen.

* **Evidence-Ledger:**
  * **Kapazität ist kein Datenverlust mehr.** Das Erreichen des Aufbewahrungsbudgets setzte den Integritätsfehler des Ledgers, quarantänisierte ihn dauerhaft und meldete XDR als degradiert mit „mandatory evidence ledger unavailable". Ein volles Ledger ist kein beschädigtes.
  * **Ein Budget, von jeder Seite gleich gelesen.** Die Konstruktion ist nachsichtig, die Laufzeit streng: Ein Ledger, das unter einem erhöhten Budget berechtigt gewachsen ist, wird nach einem Neustart akzeptiert, statt den Dienststart zu verweigern.
  * **Das Budget, das der Betreiber erhöht, ist das Budget, das der Ledger durchsetzt.** Der Konstruktor setzte seine Policy auf den kompilierten Default von 64 MiB, den der Schreibpfad bevorzugt — ein auf 256 MiB erhöhtes Budget wurde damit bei jedem Start verworfen: Der Ledger stoppte bei 64 MiB und lehnte danach jeden Schreibvorgang ab, während er sich weiter als gesund meldete. Die Plattform hatte stillschweigend aufgehört, Evidenz aufzuzeichnen. Beide Budgets starten nun gleich, und ein später erniedrigtes Budget wirkt weiterhin.
  * **Der Zustand benennt sich selbst.** „Retention budget reached" und „integrity unavailable" sind getrennte Meldungen mit getrennten Zahlen und getrennten Abhilfen.
* **Release-Gate:**
  * **Ein Fail-Safe behält seinen Grund.** Der Grund wurde beim nächsten Refresh von der Liste der aktuellen Blocker überschrieben, sodass eine Plattform, die noch im Observe-Modus stand, schließlich „release gates satisfied" anzeigte.
  * **Ein Fail-Safe ist forensische Evidenz.** Ein Rückfall ist das folgenreichste, was die Plattform von sich aus tut — und er hinterließ keinen Incident.
* **L7 Application Defense:**
  * **Ein bestandener Selbsttest räumt eine veraltete Degradierung ab,** begrenzt auf fünfzehn Minuten, damit ein alter Erfolg keinen Pfad verdeckt, der seither gebrochen ist.
  * **Die erzeugte nginx-Konfiguration konnte nie angewendet werden.** Sie erzeugte einen Server-Block mit `listen ... ssl` und einem Kommentar dort, wo die Zertifikatsdirektiven hingehören — von nginx rundheraus abgelehnt — und nannte einen Host, der bereits einen Server-Block hatte. Sie besteht jetzt aus zwei einfügbaren Teilen, im Testlauf gegen den echten nginx-Parser geprüft.
  * **Der Durchsetzungspfad wird berichtet.** `INGRESS_HEALTH` nennt, welchen Hook der Kernel eingehängt hat — natives XDP, generisches XDP oder TC-Ingress —, statt alle drei als „verified kernel ingress producer" zu bezeichnen, obwohl sie sich unter Last sehr unterschiedlich verhalten.
  * **Der Betreiber sieht, ob HTTP-Verkehr existiert, während L7 nicht in seinem Pfad liegt.** Die Web-Oberflächen-Erkennung meldet, ob auf diesem Host ein Webserver läuft und auf welchen Ports — nur lesend, begrenzt und niemals als Schutz dargestellt, denn Erkennung ist kein Schutz.
  * **Die geführte Webserver-Integration erzeugt Konfigurationstext und sonst nichts.** Sie schreibt nie in die Konfiguration eines Webservers, lädt keinen Dienst neu und behauptet nie, ein erzeugtes Fragment sei in Kraft; der Betreiber wendet es an, und der Selbsttest beobachtet anschließend, ob es gewirkt hat. Jeder eingesetzte Wert wird vorher gegen eine geschlossene Grammatik geprüft, denn die Ausgabe ist eine Konfigurationsdatei für einen privilegierten Dienst.
  * **Geprüfte Requests umfassen beide Zähler, nicht einen.** Das Panel zeigte nur den Request-Zähler, sodass ein Host, dessen Inline-Listener 174 Requests inspiziert hatte, „0 geprüfte Requests" direkt unter seinem eigenen „TRAFFIC AKTIV"-Abzeichen meldete — das Panel widersprach sich selbst und verbarg damit den Beleg, dass sein Urteil richtig war. Die Zahl ist jetzt die Summe, aus der das Urteil berechnet wird.
* **Kinetic Defense:**
  * **Durchsetzung und Wirkung sind sichtbar.** Das Panel nennt den verwendeten Hook, die Gesundheit des Kernelkanals und was die Engine erkannt und getan hat. Im Observe-Modus sagt es das auch: Eine Spalte voller Nullen heißt, dass die Antwortstufe nie betreten wurde — nicht, dass nichts gesehen wurde.
  * **Die Übersicht trägt die Zahlen,** gruppiert nach der Frage, die sie beantworten.
  * **Die Abdeckungs-Zusammenfassung erklärt den Sensor, den sie nennt.** Die Begründungszeile war an einen festen Sensornamen gebunden, sodass eine Zusammenfassung „Mandatory sensors degraded: l7_application" mit dem Satz des gesunden Ingress-Producers erklärt wurde — eine degradierte Überschrift über einer positiven Erklärung, auf einer Seite, die im selben Moment der Application-Defense-Seite widersprach, obwohl beide denselben Snapshot lasen. Die Begründung gehört jetzt dem Sensor, der die Plattform nicht-nominal gemacht hat, mit der Rangfolge des Servers, und der Rückfall ist ein übersetzter Schlüssel statt eines deutschen Literals.
  * **Die Zusammenfassung ist deterministisch.** Sie behauptet, den Status deterministisch zu bestimmen, verknüpfte die Sensornamen aber in Map-Iterationsreihenfolge — derselbe Zustand ergab bei jedem Refresh einen anders geordneten Satz.
* **Härtung und Integrität:**
  * **Ein Manipulationsbefund an GeDefense-eigenen Komponenten bewaffnet nicht mehr die Antwort.** Ein Digest-Konflikt an einer der eigenen Binaries ist von einem genehmigten Update nicht zu unterscheiden, und die Antwort-Engine griff deshalb ein: Über hundert aufgezeichnete Incidents zeigen das Produkt, wie es sein eigenes Zugangsgateway einfriert — eine Dienstblockade, die jeder Angreifer durch das Berühren einer einzigen Datei auslösen kann. Der Befund bleibt in voller Schwere bestehen — dieselbe Regel, dieselbe Bewertung, dieselbe Kategorie — und nur die Antwort wird zurückgehalten; fremde Binaries behalten ihre. Die eigenen Komponenten werden über eine gemeinsame Wurzel erkannt, die `VGT_RELEASE_ROOT` folgt.
  * **Zehn Härtungsschalter waren wirkungslos** auf einem bereits gehärteten Host, weil ein Schalter deaktiviert wurde, sobald seine Kontrolle bereits PROTECTED war; der Preflight prüft eine Auswahl, er wendet sie nicht an.
  * **Die Härtungsstufe kann sich nicht überzeichnen.** Ein Host, auf dem zwei von zweiundzwanzig Kontrollen lesbar waren und beide bestanden, erreichte 100 Punkte und meldete HARDENED. Die Stufe ist jetzt gedeckelt, wenn die Evidenz sie nicht trägt, und die Abdeckung steht neben dem Wert.
  * **Ein geändertes geschütztes Objekt wird als Objekt gemeldet, und zwar einmal.** Die geschützte Menge erreicht dieselbe Release-Binary über `/current/bin/...` und `/releases/<version>/bin/...`, sodass ein Austausch zwei kritische Incidents erzeugte — und eine nicht behobene Änderung wurde in jedem Dedupe-Intervall erneut gemeldet, bis der Dienst neu startete; eine einzige Tatsache begrub das Ledger, in dem sie aufgezeichnet wurde. Die Meldung ist jetzt am aufgelösten Objekt und seinem beobachteten Zustand verankert, und der Grund nennt jedes geänderte Objekt.
  * **Das Integritätspanel benennt das Teilsystem, das tatsächlich degradiert ist,** statt `INTEGRITY_FAILURE` anzuzeigen, während der Incident-Ledger, auf den es zeigt, gesund ist und damit nichts zu tun hat.
* **Threat Intelligence:**
  * **FireHOL Level 1 wird durchgesetzt, nicht korreliert.** Eine protokollierte Schema-Migration hebt den gespeicherten Wert auf bestehenden Knoten an, abgeglichen über die Feed-ID und niemals abgesenkt, weil hier eine Betreibereinstellung in dessen Namen geändert wird.
* **Lebenszyklus der Kontrollplane:**
  * **Ein interner Neustart,** aus der Oberfläche erreichbar, aktiviert die RESTART-Klasse von Werten, die persistiert, aber nie angewendet worden waren. Er verweigert sich, wenn kein Supervisor den Prozess zurückbringen würde, weil ein Beenden dort das Produkt stoppen und gestoppt zurücklassen würde.
* **Zugangsgateway und Oberfläche:**
  * **Das Anmeldeformular macht sich nicht mehr selbst ungültig.** Jeder Seitenaufruf erzeugte ein frisches CSRF-Token und überschrieb das Cookie, sodass das Cookie ein einzelner gemeinsamer Platz war statt eine Eigenschaft des angezeigten Formulars. Die Seite trägt ihre eigenen Sprachlinks, Browser prefetchen und prerendern sie, und diese zweite Anfrage genügte, damit das sichtbare Formular ein Token hielt, zu dem das Cookie nicht mehr passte — deshalb konnte sich ein Betreiber, der nichts falsch gemacht hatte, nicht anmelden, so oft er auch neu lud. Eine zweite Registerkarte, eine Zurück-Navigation und ein fremdes `<img>` auf den Endpunkt taten dasselbe. Das Token, das ein Browser erhält, wird jetzt bis zu seinem Ablauf wiederverwendet; der Schutz ist unverändert: 24 Zufallsbytes in einem host-only gesetzten Cookie mit HttpOnly, Secure und SameSite=Strict, das keine andere Seite lesen oder setzen kann.
  * **Ein abgelaufenes Anmeldeformular endet nicht mehr in einer Sackgasse.** Es war eine nackte `403 request rejected`, die weder Ursache noch Ausweg nannte. Die Ablehnung selbst ist unverändert — ohne passendes Token wird nichts authentifiziert und kein Passwort gelesen —, aber ein veraltetes Formular führt jetzt auf ein frisches mit einer Erklärung in allen vier Sprachen, und die Lebensdauer beträgt eine Stunde.
  * **Der Ablehnungsgrund wird genau einmal gezeigt.** Er reiste in der Query und war damit eine Eigenschaft der Adresse statt des Ereignisses: Ein Neuladen — oder die Rückkehr aus dem Verlauf — wiederholte „Diese Anmeldeseite war abgelaufen" über einem Formular, das gerade frisch ausgestellt und gültig war. Jetzt reist er in einem Einmal-Cookie, das die Seite verbraucht.
  * **Ablehnungen am Gateway sind diagnostizierbar.** Das Log hält den Grund fest, den Fingerabdruck des erwarteten und des eingegangenen Tokens und welche Cookies ankamen — niemals einen Tokenwert.
  * **Die Anmeldeseite wurde neu komponiert** um die Tatsachen, die dieser Host vor jeder Anmeldung bezeugen kann, mit eingebetteter statt in CSS gezeichneter Produktmarke.
  * **Die Authentifizierungsoberfläche des Dashboards** sagt, was der Host bezeugt, und prüft einen Schlüssel gegen die Kontrollplane, bevor sie behauptet, eine Sitzung sei autorisiert.
  * **Protection Center und Navigation:** eine Überschrift, die die Statuspille wiederholte, ein Knopf, der Navigation versprach und nichts tat, ein dauerhaft rot leuchtender Not-Aus neben der Hauptaktion, ein Dollarzeichen als Navigationssymbol und ein doppeltes Schild.
* **Übersetzungen:**
  * **58 Schlüssel existierten nur auf Deutsch,** sodass Betreiber, die Englisch, Russisch oder Chinesisch lesen, rohe Schlüsselbezeichner über das Durchsetzungspanel, den Evidenzhinweis und die Neustart-Oberfläche sahen. Die Abdeckung ist jetzt eine Eigenschaft je Katalog, und `t()`-Aufrufstellen werden ebenso geprüft wie Dokumentattribute.

### v4.2.0 — Security Fabric Control Plane

* **Vollständige Behebung des Sicherheits-Audits & Härtung:**
  * **Kritisch:** Beseitigung der Symlink-Traversal-Schwachstelle im Canary-Deployment (willkürliches Dateischreiben / Root-Privilege-Escalation) via komponentenweiser `openat(2)`-Auflösung mit `O_NOFOLLOW|O_DIRECTORY` und `ELOOP`-Erzwingung.
  * **Hoch:** Ersatz von Information-Disclosure-Lecks durch typisierte, opake Fehlerantworten bei 5 API-Handlern; strukturelle Entkopplung statt unvollständiger Wort-Blacklists.
  * **Hoch:** Fail-Closed CSPRNG (`log.Fatalf`) verhindert vorhersagbare Zeitstempel-IDs für Incidents, Quarantäne und Blöcke.
  * **Hoch:** Remote-Panic im Settings-Import-Preview durch Fail-Closed-Schlüsselerzeugung behoben.
  * **Hoch:** Import-Token sind kryptografisch an den geprüften Inhalt gebunden (verhindert Token-Kollisionen).
  * **Mittel:** Crash-sicherer atomarer Writer (`atomicWriteFile`) für Policy, Feeds und Chronos mit Symlink-Ablehnung und `fsync`.
  * **Mittel:** `unsafe-inline` Styles aus der Content Security Policy verbannt; HSTS ausschließlich über TLS.
* **Security Fabric Control Plane:**
  * 12 administrierbare Module (`kinetic`, `network`, `protection`, `xdr`, `l7`, `threat_intel`, `hardening`, `integrity`, `boot_trust`, `policy_trust`, `forensics`, `system`).
  * Server-authoritatives Schema, unveränderliche Snapshots auf heißen Pfaden, persistierte `restart_required`-Semantik.
  * Nicht-administrierbare Sicherheitsinvarianten: Kernel-Maps, Core-Auth, Private-Key-Geheimhaltung, Management-Self-Lockout, Feed-Anti-Poisoning.
* **Control-Plane Workbench & Telemetrie:**
  * Deterministische Settings-Suche (`GET /api/v1/settings/search`) mit Live-Werten und Trefferbegründung.
  * Kryptografisch signierter, geheimnisfreier Settings-Export (`POST /api/v1/settings/export`).
  * Echter zweistufiger Import (`/import/preview` + `/import/apply`) mit Diff-Analyse und Einmal-Tokens.
  * Kontinuierliche Drift-Erkennung (`GET /api/v1/settings/drift`) signalisiert `CONFIG_DRIFT`.
* **Vendorte Offline-SVG-Weltkarte (jsVectorMap 1.7.0):**
  * 100% lokales Rendern ohne CDN oder Kachelserver; native Buttons gewährleisten vollständige Konformität mit `require-trusted-types-for 'script'`.
  * Lokale GeoIP/ASN-Auflösung, Choropleth-Dichteanzeige, Live-Marker und Traffic-Puls.
* **UI/UX Supreme — Modernes Dashboard-Design:**
  * Kartenraster eliminiert; semantische `<dl>`-Datenbänder mit Haarlinien-Trennern.
  * Reine Zustandsfarben, Barrierefreiheit (WCAG AA), echte Tastatur-Controls (`<button>`) und Unterstützung für `prefers-reduced-motion`.
* **Laufzeit- und Engine-Fixes:**
  * Deadlock in `CaseEngine.Status` behoben.
  * Fail-Open im Airlock-Inspektor und in der CaseEngine beseitigt.
  * Route `GET /assets/{name...}` für mehrstufige Pfade korrigiert.
  * Toolchain-Sicherheitsboden auf Go ≥ 1.26.6 angehoben (behebt 6 Standardbibliothek-CVEs).

### v4.0.1 — Chinesische Lokalisierung, Dedizierter XDR-Kernel-Recovery-Tab & Erweiterung des Startbildschirms

- **Lokalisierung für vereinfachtes Chinesisch (`zh-CN` / `ZH`):** Vollständige Übersetzung des Command Centers über alle Tabs, Dialoge, Operationen, Platzhalter und Laufzeit-Toasts (743 Schlüssel, 100% Parität zu DE, EN, RU). Chinesische Sprachauswahl und lokalisierte Texte auf dem öffentlichen Access Gateway Startbildschirm hinzugefügt.
- **Dedizierter XDR-Kernel-Recovery-Tab:** Eigener Wiederherstellungs-Tab `#xdr` und Endpunkt `/api/v1/xdr/recovery` mit `ARCHIVE_AND_REINITIALIZE_XDR`-Bestätigungsschranke zur Inspektion degradierter Ledger-Zustände, Archivierung beschädigter Ketten mit kryptografischen SHA-256-Manifesten und sicheren Re-Initialisierung von Kernel-eBPF-Sensoren und Maps direkt aus dem Dashboard.
- **Trennung der Ledger-Hash-Domänen:** Eigenständiges `evidence_root`-Feld für Angriffs-Merkle-Bäume und `record_hash` für die HMAC-Vorfallskette, wodurch fälschliche Degradierungen beim Daemon-Neustart verhindert werden.
- **Versionsabgleich:** Alle Binaries, Access Gateway, Web-UI, Integrationsverträge, Rust-Workspace und Paketierungsmanifeste auf `4.0.1` aktualisiert.

### v4.0.0-beta.1 — Native L7-Anwendungssicherheit & Korrelationshärtung

**L7-Anwendungssicherheitsebene (WAF & API Gateway)**

- **Implementierung in der Go-Standardbibliothek:** Integrierte L7-Inspektions-Engine direkt im unprivilegierten Go Control Daemon (`gedefense-control`). 100% CGO-frei, null Drittanbieter-Abhängigkeiten und null Hilfsskript-Engines (kein Lua, WASM oder Node.js).
- **Dual-Mode Bereitstellungsarchitektur:**
  - *Advisory / Standalone Socket:* Unix-Socket im Modus `0660` (`/run/vgt-gedefense-l7/inspect.sock`) mit strukturierter JSON-Evaluierungs-API (`POST /v1/inspect`) und strikter Validierung (`DisallowUnknownFields`) für externe Reverse Proxies (nginx, Caddy, Envoy, Apache).
  - *Natives Inline Reverse-Proxy-Gate:* Transparentes Inline-Filter (`/run/vgt-gedefense-l7/edge.sock`) direkt zwischen TLS-Terminierung und Backend-Anwendungen mit begrenzter Nebenläufigkeit und Fail-Closed-Budgets.
- **Strikte Upstream-Einsperrung (Anti-SSRF):** Inline-Weiterleitungsziele sind strikt auf saubere absolute Unix-Sockets oder explizite Loopback-IP-Literale (`127.0.0.1`, `[::1]`) beschränkt. Anfragegesteuertes Routing und DNS-Auflösung sind architektonisch unmöglich.
- **Begrenzte Normalisierungs- & Anti-Evasions-Engine:**
  - Mehrstufiges rekursives Unescaping (URL-Pfad und Query, HTML-Entities, `\uXXXX` und `\xXX` Escape-Sequenzen).
  - Unicode Fullwidth Fold (`\uff01`–`\uff5e` auf ASCII gefaltet), eliminiert Filter-Bypässe mit breiten asiatischen Zeichen.
  - Automatische Erkennung und Dekodierung von unpadded und URL-sicherem Base64 in Parametern.
  - Streaming-JSON-Parser mit Rekursionsbegrenzung (`max_json_depth = 32`) und Token-Budgets.
  - Begrenzte Gzip- und Deflate-Dekomprimierung via `io.LimitReader` (Schutz vor Zip-Bomben).
  - 16 KB überlappendes Chunking (256 Byte Überlappung) für Fließtext, verhindert Umgehung an Blockgrenzen ohne doppelte Allokation.
- **Vollständige Angriffserkennungs-Suite (Lineare RE2-Ausführung, Null ReDoS):**
  - *SQL Injection (SQLi):* UNION SELECT Syntax, boolesche Tautologien (`' OR 1=1`), Zeitverzögerungen (`pg_sleep`, `benchmark`, `waitfor delay`), gestapelte Queries.
  - *Cross-Site Scripting (XSS):* Ausführbare Script-Tags, Inline-Event-Handler (`onerror=`, `onload=`), gefährliche Schemata (`javascript:`, `data:text/html`), `iframe srcdoc`.
  - *Command Injection / RCE:* Shell-Verkettung (`;`, `&&`, `||`, `|`), Substitution (`$(...)`, Backticks), Windows/PowerShell-Befehlsketten.
  - *Path Traversal & LFI:* Traversal-Sequenzen (`../`, `..\`), sensible Pfade (`/etc/passwd`, `/proc/self/environ`), Stream-Wrapper (`php://`, `phar://`, `data://`).
  - *SSTI, XXE & Deserialisierung:* Server-Side-Template-Ausdrücke (Jinja, Twig, Smarty, Spring), externe XML-Entitäten (`SYSTEM`/`PUBLIC`), PHP-Objektserialisierung, Java-Serialisierungs-Magic (`rO0AB`), JNDI/Log4j.
  - *HTTP Request Smuggling & Framing-Anomalien:* Doppelte oder ungültige `Content-Length`, gleichzeitige `Content-Length` und `Transfer-Encoding` (CL.TE / TE.CL), blockierte `TRACE`-Methode.
- **Evasive SSRF-Abwehr mit flexibler IP-Normalisierung:**
  - Dekodiert und normalisiert alternative IPv4-Darstellungen: hexadezimal, oktal, dezimale DWORD-Ganzzahlen, 2-/3-teilige Punktnotationen.
  - Erzwingt Schutzbereiche gegen Loopback, Link-Local, private Netze und alle gängigen Cloud-Metadaten-Endpunkte (AWS IMDSv2, GCP, Azure, Alibaba, Oracle Cloud).
- **In-Memory Airlock Upload-Inspektion (`InspectBytes`):**
  - Multipart-Uploads werden vor dem Schreiben auf die Festplatte direkt im RAM analysiert.
  - Strikte Begrenzung von Part-Zahl und Dateigröße; Prüfung von Magic Bytes (ELF, PNG, JPEG, GIF, PDF, ZIP), MIME-Cross-Checks, doppelten Endungen (`.php.jpg`), Null-Byte-Injektionen und SHA-256-Blacklists.
- **3-stufiges geshardetes Token-Bucket Rate Limiting:**
  * 64 unabhängige Shards mit FNV-1a Hashing eliminieren Lock-Contention unter hoher Last.
  * Client-spezifisches Volumen-Rate-Limiting.
  * Routenspezifischer Schutz sensibler Endpunkte (`/login`, `/wp-login.php`, `/api/login`) vor Brute-Force.
  * Globales Rate Limiting zum Schutz vor verteilten Botnetzen und Credential-Stuffing.
- **Response Data-Leak Prevention (DLP):**
  * Überwacht Upstream-Antworten auf Datenbankfehler (`SQLSTATE`), Quellcode-Leaks (`<?php`, `<jsp:`), Stacktraces und private Schlüssel (`BEGIN RSA PRIVATE KEY`).
  * Exakte Wire-Byte-Erhaltung: Antworten werden zerstörungsfrei gepuffert und unverändert gestreamt.

**XDR-Korrelation & Host-Integrität**

- **Web-Evidenz-Isolation (Anti-False-Positive-Barriere):** L7-Befunde tragen `AlertOnly: true` und `ResponseScore: 0`. Websignale allein können **niemals** autonome destruktive Prozesseindämmung (SIGKILL / SIGSTOP) auslösen; destruktive Aktionen erfordern stets unabhängige Kernel-Evidenz.
- **Trinity XDR 2.0 DAG-Integration:** L7-Ereignisse werden als Kausalgraphen-Knoten (`HTTP_REQUEST`, `HTTP_RESPONSE`) mit kryptografischer Merkle-Beweiskette erfasst.
- **Host-Netzwerk-Korrelation:** Echtzeit-Korrelation verbindet eingehende feindliche HTTP-Requests mit lokalen Linux-Sockets (`SO_PEERCRED` PID/UID/GID und `NetConnection` Remote-Tracking).
- **Gegatete Durchsetzung:** Inline-Blockierung ist erst aktiv, wenn das Release-Gate `Enforce` mit einem gesunden Core erreicht; andernfalls verbleibt der Verkehr sicher in `Observe`.

**Systemd, Linux DAC & Release-Härtung**

- Dedizierte Systemgruppe `gedefense-l7` und Laufzeitverzeichnis `/run/vgt-gedefense-l7` (Modus `0750`) via `systemd-tmpfiles`.
- Unix-Sockets mit Modus `0660` und authentifizierten Peer-Credentials (`SO_PEERCRED`).
- Gepinnte Go 1.26.8 Release-Toolchain, verifiziert durch AST-Sicherheitsaudit.
- 3 neue Fuzzing-Testsuiten in CI zur Verifikation von Normalisierer-Sicherheit, Response-Byte-Erhaltung und Upstream-Jail.

### v3.0.0-beta.1 — Universelle Linux-Integration

**Integration und Bereitstellung**

- Übernahme der portablen AstraeaOS-Readiness- und Privilegien-Verträge in den generischen Linux-Release.
- Paketmanager-Auflösung für APT, DNF/YUM, pacman und Zypper.
- Generische Polkit-Autorisierungsgrenze und systemd-Readiness-Helper hinzugefügt.
- Desktop-Launcher mit dediziertem Chromium-Profil und exaktem SPKI-Pin ohne Änderung des globalen Trust-Stores.
- SDDM-, ArchISO- und Gaia-Cells-Verhalten bleibt AstraeaOS-Hosts vorbehalten.

**Sicherheit und Korrektheit**

- SANs der Gateway-Zertifikate um `localhost`, `127.0.0.1` und `::1` erweitert.
- Malware-Reputations-Hash-Datenbank in Staging, Release-Payload, geschützte Konfiguration und Rollback integriert.
- Fail-closed Manifeste, Scan nach verbotenen Geheimnis-Markern, Symlink-Ablehnung und strikte Größenlimits.
- LF-Normalisierung und explizite Ausführungsrechte für Linux-Skripte.

**Release Engineering**

- Obligatorische Go Unit/Vet/Race/Fuzz und statische Sicherheits-Gates.
- Gepinnte Rust-Tests, Rust Core Release-Build und no_std eBPF-Build.
- Digest-gepinnte Ubuntu, Fedora, Arch und openSUSE Integrations-Jobs.
- GitHub Actions an unveränderliche 40-Zeichen Commit-IDs gebunden.
- Privilegierter Host-Workflow für bpffs, eBPF-Programme, NIC XDP, IPC/TLS, systemd, Polkit und Desktop.
- Deterministische Artefaktnamen und SHA-256-Prüfungen.

**Unverändertes Sicherheitsfundament**

- Getrennte Go Control Plane, Rust Response Core und Rust eBPF/XDP Data Plane bleiben das Beta 5 Sicherheitsfundament.
- Observe → Canary → Enforce, Evidenz-Ledger, verschlüsselter Response Vault und reversible Härtung bleiben unverändert.

### v1.0.0-beta.5 — Vollständige Beta

Auszeichnung als vollständige Beta — Verteidigungskette funktional komplett und testbar. Installer 3.5.1 mit voller Gate-Sequenz (Build, Kernel-Verifier, XDP-Attach, IPC, Backend, TLS). Byte-identischer Quellspiegel. Volle Validierungsmatrix bestanden.

---

## 🔗 VGT-Ökosystem

| Werkzeug | Typ | Zweck |
|---|---|---|
| 🛡️ **VGT GeDefense** | **Linux Security Fabric** | Kernelnahe Verteidigung, XDR, verschlüsselte Evidenz — du bist hier |
| 🧠 **[VGT AETHEL](https://github.com/visiongaiatechnology/aethel)** | **Souveränes KI-Betriebssystem** | Lokale KI mit Betreiber-Governance |
| 🖥️ **[VGT WP-Desk](https://github.com/visiongaiatechnology/vgtdesk)** | **OS-Ebene / UX** | Gehärteter WordPress-Arbeitsbereich |
| ⚔️ **[VGT Sentinel](https://github.com/visiongaiatechnology/sentinelcom)** | **WAF / IDS** | Zero-Trust WordPress WAF |
| ⚡ **[VGT Auto-Punisher](https://github.com/visiongaiatechnology/vgt-auto-punisher)** | **IDS** | L4+L7 Hybrides IDS |
| 🔐 **[VGT Omega Vault](https://github.com/visiongaiatechnology/vgt-omega-vault)** | **Verschlüsselte Formulare** | AES-256-GCM WordPress Formular-Tresor |
| 🌐 **[GaiaCom](https://github.com/visiongaiatechnology/GaiaCom)** | **Kommunikation** | Post-Quanten föderierte E2EE-Plattform |
| 📊 **[VGT Dattrack](https://github.com/visiongaiatechnology/dattrack)** | **Analytik** | Souveräne lokale Analytik |

---

## 💙 Unterstütze die Mission

[![Donate](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal)](https://paypal.me/dergoldenelotus)

| Methode | Adresse |
|---|---|
| **PayPal** | [paypal.me/dergoldenelotus](https://paypal.me/dergoldenelotus) |
| **Bitcoin** | `bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm` |
| **ETH / USDT (ERC-20)** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |

---

## 📄 Lizenz

**AGPL-3.0-only · © 2026 VisionGaia Technology · Köln, Deutschland**

VGT GeDefense ist freie Software: Sie können sie unter den Bedingungen der GNU Affero General Public License weitergeben und/oder modifizieren, wie sie von der Free Software Foundation veröffentlicht wurde, ausschließlich Version 3. Jedes abgeleitete Werk oder netzwerkbasierte Modifikation muss unter derselben Lizenz veröffentlicht werden.

Enterprise-Bereitstellungen, TIER-0-Audits (VGT SafetySys™) und kommerzielle Ausnahmelizenzen: [visiongaiatechnology.de](https://visiongaiatechnology.de)

### 🗺️ Daten-Attribution & Lokale GeoIP / ASN Datenbank

GeDefense beinhaltet eine vollständig offline betriebene, lokal ausgewertete GeoIP- und Origin-ASN-Datenbank (`/var/lib/vgt/gedefense/geoip.csv`), die null Cloud-Laufzeitabfragen oder externe Telemetrie garantiert:

* **DB-IP Lite:** Dieses Produkt enthält GeoLite2- oder DB-IP Lite-Daten von DB-IP, verfügbar unter [https://db-ip.com/](https://db-ip.com/) unter der Creative Commons Attribution 4.0 International License (CC BY 4.0). Namensnennung / Attribution erforderlich.
* **Origin-ASN-Daten:** Origin-ASN-Zuordnungsdaten bereitgestellt von [sapics/ip-location-db](https://github.com/sapics/ip-location-db) unter der Public Domain Dedication and License (PDDL).

#### Aktualisierung der lokalen GeoIP-Datenbank

Sie können die lokale GeoIP-Datenbank jederzeit mit dem beiliegenden Updater-Skript aktualisieren und per Longest-Prefix-Match atomar einspielen:

```bash
# Lädt die neuesten DB-IP City und Origin-ASN Datensätze herunter, kompiliert eine < 128 MiB / < 1.000.000 Prefixe CSV und ersetzt /var/lib/vgt/gedefense/geoip.csv atomar
sudo python3 scripts/update-geoip-db.py /var/lib/vgt/gedefense/geoip.csv
```

---

<div align="center">

**VISIONGAIATECHNOLOGY – WE ARCHITECT THE FUTURE OF SECURITY.**

[![VGT](https://img.shields.io/badge/VisionGaia-Technology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

*VGT GeDefense 4.2.2 — Universelles Linux Sicherheitsgewebe // Rust eBPF/XDP Data Plane // Go Control Plane // Host XDR // Ed25519 Evidenz-Ledger // AES-256-GCM verschlüsselter Vault // Reversible Härtung // AstraeaOS-nativer Adapter // Getrennte Vertrauensdomänen // Keine Cloud-Control-Plane // AGPL-3.0-only // Linux x86_64*

</div>
