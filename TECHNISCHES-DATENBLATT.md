# Technisches Datenblatt — VGT GeDefense

**Produkt:** VGT GeDefense  
**Hersteller:** VisionGaia Technology  
**Version:** 1.0.0-beta.5 Complete Beta  
**Installer-Revision:** 3.5.1  
**Dokumentstand:** 28. Juli 2026  
**Produktstatus:** Anwendbare und testbare Full-Stack-Beta  
**Lizenz:** AGPL-3.0-only

## 1. Produktdefinition

VGT GeDefense ist eine souveräne, lokal betriebene Linux-Sicherheitsplattform,
die Kernel-nahe Netzwerkabwehr, Host-XDR, Integritätsüberwachung,
reaktionsfähige Isolation, kryptografisch geschützte Beweisketten und ein
lokales Management-Interface in einem System verbindet.

Das Produkt ist für zwei Betriebsmodelle ausgelegt:

1. **Standalone:** eigenständige Installation auf einem kompatiblen
   x86_64-Linux-Server mit systemd und BPF/XDP-Unterstützung.
2. **GaiaOS-native:** dieselben Control-, Broker- und eBPF-Komponenten mit
   GaiaOS-Provisionierung, GaiaOS-Härtungsprofil, Boot-Trust-Evidenz und
   optionaler Gaia-Cells-Laufzeitanbindung.

GeDefense benötigt keinen Cloud-Control-Plane-Dienst. Dashboard,
Entscheidungslogik, Schlüssel, Telemetrie, Richtlinien und Beweisdaten bleiben
auf dem geschützten Host.

## 2. Systemarchitektur

| Vertrauensdomäne | Technologie | Aufgabe | Privilegierung |
|---|---|---|---|
| Public Access Gateway | Go | TLS-1.3-Zugang, Argon2id-Anmeldung, Session-, Host-, Origin- und CSRF-Schutz | unprivilegiert |
| Control Plane / Command Center | Go | XDR, Policy, Telemetrie, Transaktionen, Cases, FIM, Feeds und Dashboard-API | Benutzer `gedefense` |
| Response Core | Rust | XDP-Laden, Map-Verwaltung, pidfd-Reaktion, Quarantäne und typisierte Kernelmutationen | UID 0, capability-begrenzt |
| Data Plane | Rust `no_std`, Aya, eBPF/XDP | IPv4-/IPv6-Paketprüfung und LPM-Allow-/Blocklisten direkt am Interface | Kernel/XDP |
| Gaia Cells Adapter | Go, VGTGC1 | authentifizierte Cell-Erkennung und reversible Freeze-/Netzwerkisolation | optional, Unix-Socket |

Steuerfluss:

```text
Browser → TLS Gateway → Go Control Plane → HMAC-VGT3 IPC
        → privilegierter Rust Core → Aya → eBPF/XDP → Netzwerkinterface
```

Die öffentlichen und internen Vertrauensgrenzen sind getrennt. Der Browser
erhält keinen Backend-Bearer. Das Gateway entfernt Browser-Credentials und
Forwarding-Identitäten und injiziert die interne Authentisierung ausschließlich
serverseitig.

## 3. Kernfunktionen

### 3.1 Netzwerkabwehr

- Rust-eBPF/XDP für IPv4 und IPv6;
- native XDP-Anbindung mit Generic-XDP-Fallback;
- Longest-Prefix-Match über LPM-Tries;
- Management-Allowlist wird vor der Blocklist ausgewertet;
- signierte CIDR-Regeln mit TTL;
- maximal 250.000 Blockeinträge in der Standardkonfiguration;
- autoritative Leerstandsprüfung der Kernel-Blockliste;
- fehlerhafte oder abgeschnittene Pakete werden fail-open behandelt;
- öffentliche Threat Feeds werden lokal korreliert, standardmäßig jedoch nicht
  automatisch in aktive Blockregeln übernommen.

### 3.2 Linux XDR

- Prozess-, Kommando-, Herkunfts-, Lineage-, Masquerading-, Netzwerk-,
  Integritäts- und Threat-Intelligence-Signale;
- adaptive Verhaltensprofile mit begrenzter Kardinalität;
- RE2-basierte benutzerdefinierte Regeln mit linearer Laufzeit;
- benutzerdefinierte Regeln sind Alert-only und dürfen keine aktive Reaktion
  autorisieren;
- Mehrsignalentscheidung mit getrenntem `response_score`;
- PID-Identitätsprüfung über Startzeit und `pidfd`;
- Canary-Containment über `pidfd_send_signal(SIGSTOP)`;
- `SIGKILL` nur im Enforce-Modus nach erneuter objektiver Prüfung im Rust-Core;
- begrenzte Worker, Queues, Historien und Auswertungsbudgets.

Standardwerte:

| Parameter | Wert |
|---|---:|
| Prozessscan | 750 ms |
| Netzwerkkorrelation | 3 s |
| Integritätsscan | 3 s |
| Alert-Schwelle | 40 |
| Containment-Schwelle | 80 |
| Kill-Schwelle | 120 |
| Worker | 4 |
| Queue-Kapazität | 2.048 |
| maximale Auswertungen pro Scan | 4.096 |
| maximales Incident-Log | 64 MiB |

### 3.3 Integrität, Evidenz und Fälle

- verschlüsseltes und signiertes Evidence Ledger mit monotoner Sequenz,
  Vorgängerhash und separatem Head-Checkpoint;
- AES-256-GCM-geschützte FIM-Baselines;
- begrenzte, symlink-resistente Dateibaumprüfung;
- Race-Erkennung durch Identitätsprüfung vor und nach dem Streaming-Hash;
- Integritätsprüfung von Inhalt und Dateimodus;
- verschlüsselte Case Engine zur Korrelation wiederkehrender Incidents;
- Evidence-Ledger-Pflicht für Statusänderungen;
- fail-closed bei manipuliertem, abgeschnittenem oder nicht authentisierbarem
  Sicherheitszustand.

### 3.4 Reversible Security Transactions

Alle sicherheitsrelevanten Mutationen folgen:

```text
Preview → Authorize → Apply → Verify → Audit → Reverse
```

- Live-Vorherzustand und typisierter Plan werden gebunden;
- transaktionsspezifische Bestätigungen;
- verschlüsselte, generationengebundene Transaktionshistorie;
- Start-Reconciliation für unterbrochene Operationen;
- `recovery_required` blockiert weitere Mutationen;
- Compare-and-set statt blindem Überschreiben;
- partielle Profilfehler werden in umgekehrter Reihenfolge zurückgerollt;
- externer Runtime-Drift wird quarantänisiert und nicht automatisch überstimmt.

### 3.5 Systemhärtung

Enthaltene Profile:

- Generic Linux Server;
- GaiaOS Workstation.

Die Profile verwenden eine feste Sysctl-Key-/Wert-Allowlist, prüfen den
Live-Kernel, schreiben atomar nach
`/etc/sysctl.d/90-vgt-gedefense.conf` und sind reversibel. Der Rust-Core stellt
keine generische Sysctl- oder Shell-Schnittstelle bereit.

### 3.6 Verschlüsselte Dateiquarantäne

- AES-256-GCM in begrenzten 1-MiB-Chunks;
- maximale Quelldateigröße: 256 MiB;
- SHA-256-, Größe-, Modus-, UID-, GID-, Device-, Inode- und Zeitbindung;
- atomare Erfassung mit Identitätsprüfung;
- Manipulationsprüfung vor Wiederherstellung;
- identitätserhaltende Wiederherstellung;
- `openat2`-/`O_NOFOLLOW`- und Symlink-Abwehr;
- root-eigener Vault mit Modus `0700`;
- Traversierung ohne `CAP_DAC_OVERRIDE` über den geprüften
  `gedefense:gedefense`-State-Pfad mit Modus `0710`.

## 4. GaiaOS-Integration

GeDefense ist die einzige Security Authority in GaiaOS. Sentinel bleibt nur
Migrations- und Auditquelle; es läuft kein zweiter konkurrierender
Security-Daemon.

| GaiaOS-Funktion | Status |
|---|---|
| native Provisionierung und systemd-Aktivierung | implementiert |
| identische GeDefense-Binaries wie Standalone | implementiert |
| byteverifizierter GeDefense-Quellspiegel | implementiert, 147 Dateien |
| GaiaOS-Härtungsprofil | implementiert |
| Boot-Trust-Evidenz | implementiert, Evidence-only |
| Gaia Cells VGTGC1 Adapter | implementiert, Runtime optional |
| UUID-/Generation-/cgroup-ID-Bindung | implementiert |
| reversible Cell-Freeze-/Netzwerktransaktionen | implementiert |
| Gaia-Cells-Lifecycle-Daemon | GaiaOS-verantwortlich, aktuell nicht enthalten |
| isolierter Deception Service | außerhalb der Beta zurückgestellt |

Fehlt die Gaia-Cells-Runtime, meldet der Adapter
`runtime_not_installed`. Die generische Hostabwehr bleibt dabei aktiv und wird
nicht degradiert.

## 5. Kryptografie und Authentisierung

| Zweck | Verfahren | Schlüssel-/Parameterprofil |
|---|---|---|
| Operator-Passwort | Argon2id | 64 MiB, t=3, p=1, 128-Bit-Salt, 256-Bit-Ausgabe |
| Control ↔ Rust-Core IPC | HMAC-SHA-256 | 32-Byte-Core-IPC-Key, Zeitfenster, Nonce, Replay-Cache |
| operativer Speicher | AES-256-GCM | zufällige Nonces, zweckgetrennte Subkeys |
| Schlüsselableitung | HMAC-SHA-256 | domänen- und zweckgebunden |
| Policy und Evidence Ledger | Ed25519 | lokale Signatur und Verifikation |
| Inhaltsidentität | SHA-256 | Streaming-Hash |
| öffentlicher Zugang | TLS 1.3 | lokales oder bereitgestelltes Zertifikat |
| Browser-Session | HMAC-authentisierte Session | `Secure`, `HttpOnly`, `SameSite=Strict`, `__Host-` |

AES-GCM-AAD bindet Datensätze an Schema, Node, Zweck, kanonischen Pfad und
Sequenz. Unterstützte PBKDF2-Altbestände werden nur zur Migration akzeptiert
und nach erfolgreicher Anmeldung atomar auf Argon2id aktualisiert.

## 6. Sicherheits- und Fail-Safe-Modell

| Betriebszustand | Verhalten |
|---|---|
| Observe | XDP aktiv, keine signierten Blockregeln, XDR protokolliert |
| Canary | Netzwerk bleibt beobachtend; evidenzgeprüftes Prozess-Containment möglich |
| Enforce | signierte CIDR-Regeln und unabhängig geprüfte aktive Reaktion |
| Degraded | aktive Reaktion deaktiviert; Beobachtung und Dashboard bleiben verfügbar |

Enforce bleibt gesperrt, solange die Management-Allowlist leer, nicht
synchronisiert oder der Kernelzustand nicht verifiziert ist.

Emergency Stop:

1. deaktiviert neue aktive Reaktionen;
2. markiert den Kernelzustand zunächst als unbestätigt;
3. entfernt bekannte Blockregeln;
4. fordert authentisiertes `VERIFY_EMPTY` vom Rust-Core;
5. persistiert eine signierte Observe-Policy;
6. meldet erst danach `verified-empty`.

Ein Fehler in dieser Kette wird nicht als sicher ausgegeben.

## 7. Web- und API-Sicherheit

- keine CDN-, Webfont-, Tracker- oder externen Frontend-Abhängigkeiten;
- keine dynamischen HTML-Sinks wie `innerHTML`, `outerHTML`,
  `insertAdjacentHTML`, `document.write` oder `eval`;
- nonce-/same-origin-orientierte Content Security Policy;
- `X-Content-Type-Options: nosniff`;
- Framing-Verbot und Cross-Origin-Isolation;
- Synchronizer-CSRF beim Login;
- exakte HTTPS-Origin-Prüfung für authentisierte Mutationen;
- Host-Allowlist;
- serverseitige Bearer-Injektion;
- Request-ID-, TTL- und Replay-Schutz;
- HTTPS-only Feed-Transport;
- Proxy deaktiviert und SSRF-Sperre für lokale, private, Link-local-,
  Multicast- und nicht öffentliche Ziele;
- keine Shell-/Kommandoausführung in den netzwerkexponierten Go-Diensten.

## 8. Systemanforderungen und Kompatibilität

### Standalone

| Merkmal | Anforderung |
|---|---|
| Betriebssystem | Linux |
| Architektur | x86_64 / amd64 |
| Init-System | aktives systemd |
| Kernel | BPF-/XDP-fähig; Zielkernel-Verifier muss Build akzeptieren |
| Prozessreaktion | Kernel mit `pidfd`-Unterstützung |
| Netzwerk | unterstütztes Interface für Native oder Generic XDP |
| Installation | Root-Rechte |
| Paketmanager | `apt-get`, `dnf` oder `yum` |
| Build-Zugang | Internetzugang während Toolchain-/Dependency-Installation |
| Gateway-Runtime | `libargon2.so.1` |
| Browser | moderner Browser mit TLS 1.3 und ES-Modulen |

Eine feste minimale Kernelversion und garantierte NIC-Liste sind für diese Beta
nicht pauschal deklariert. Kompatibilität wird deshalb auf dem Zielsystem durch
Build, Kernel-Verifier, XDP-Attachment und Health-Gates geprüft.

### GaiaOS

- Arch-Pakete `gedefense` und `gaiaos-gedefense-integration`;
- GaiaOS mindestens Version 0.1 gemäß Integrationsvertrag;
- cgroup v2 für Gaia-Cells-Identitätsbindung;
- Gaia-Cells-Runtime nur für Cell-spezifische Funktionen erforderlich.

## 9. Netzwerk- und IPC-Schnittstellen

| Schnittstelle | Standard | Exposition |
|---|---:|---|
| HTTPS Gateway | TCP 9843, konfigurierbar 1024–65535 | öffentlich bzw. administrativ |
| Go Control Backend | TCP 9844 | ausschließlich Loopback |
| Rust-Core IPC | `/run/vgt-gedefense/core.sock` | Unix-Socket, authentisiert |
| Gaia Cells | `/run/gaia-cells/control.sock` | optionaler Unix-Socket |
| Feed-Abruf | HTTPS outbound | optional, öffentliche Ziele |

Der Installer kann den gewählten HTTPS-Port über UFW, firewalld oder iptables
freigeben. Der Backend-Port wird nicht öffentlich exponiert.

## 10. Relevante Pfade

| Pfad | Inhalt |
|---|---|
| `/opt/vgt/gedefense/releases/<version>` | unveränderliches Release |
| `/opt/vgt/gedefense/current` | atomarer Symlink auf aktives Release |
| `/etc/vgt/gedefense/gedefense.toml` | Hauptkonfiguration |
| `/etc/vgt/gedefense/secrets/` | IPC- und Storage-Schlüssel |
| `/etc/vgt/gedefense/tls/` | Gateway-Zertifikat und privater Schlüssel |
| `/var/lib/vgt/gedefense/` | verschlüsselter operativer Zustand |
| `/var/lib/vgt/gedefense/quarantine/objects` | verschlüsselter Quarantäne-Vault |
| `/run/vgt-gedefense/core.sock` | VGT3-Core-IPC |
| `/sys/fs/bpf` | BPF-Dateisystem |
| `/var/log/vgt-gedefense-install.log` | geschütztes Installationsprotokoll |

## 11. Installation und Aktivierung

Der One-Click-Installer:

1. prüft Plattform und Build-Werkzeuge;
2. installiert gepinnte Rust-Toolchains;
3. kompiliert Rust-Core und eBPF für Zielkernel und Ziel-NIC;
4. führt Rust-Tests aus;
5. prüft Binärversionen, Schlüsselprofile und Service-Sandbox;
6. aktiviert ein neues unveränderliches Release atomar;
7. prüft Core-Socket, authentisiertes IPC, XDP-Modus, Backend und TLS-Gateway;
8. führt bei jedem Aktivierungsfehler einen automatischen Rollback aus.

Toolchain-Pins:

| Komponente | Version |
|---|---|
| Go | 1.23.2 |
| Rust Core | 1.97.1 |
| Rust eBPF | nightly-2026-07-16 + `rust-src` |
| bpf-linker | 0.10.3 |

## 12. Validierter aktueller Stand

Zum Dokumentstand erfolgreich ausgeführt:

- Go Unit- und Integrationstests für Control Plane und Gateway;
- `go vet`;
- Race-Detector für beide Go-Komponenten;
- JavaScript-Syntaxprüfung;
- statischer Security Regression Audit;
- native Rust-Tests für Common und Core;
- Rust-Core-Release-Build;
- eBPF-Release-Build;
- Arch-Paketbuild für GeDefense und GaiaOS-Integration;
- systemd-Unit-Validierung in isolierter Root;
- GaiaOS-Installer-/Hardening-Tests;
- Quarantäne-DAC-Laufzeittest ohne DAC-Bypass-Capabilities;
- Quellspiegel-Verifikation zwischen Standalone und GaiaOS;
- eingebetteter Installer-Payload und SHA-256-Prüfsummen.

Aktueller Installer:

`VGT_GeDefense_Beta_1.0.0-beta.5_OneClick_CompleteBeta.run`

SHA-256:

`ba32a441804f1ef1d25232ababcc781b35b2bfbfd8701ff95ca8f3dc5d9b7e8c`

## 13. Explizite Produktgrenzen

Nicht Bestandteil der Version 1.0.0-beta.5:

- Swarm-/Mesh-Föderation;
- QUIC-Offloading oder verteilte Angriffsabsorption;
- providerseitige Abwehr volumetrischer DDoS-Angriffe oberhalb der
  Host-Uplink-Kapazität;
- TLS-Payload-Entschlüsselung oder Inhalts-DPI;
- automatische Durchsetzung öffentlicher Threat Feeds;
- Garantie gegen einen vollständig kontrollierenden lokalen Root-Angreifer;
- vollständige Hardware-Root-of-Trust-/Measured-Boot-Attestierung;
- Gaia-Cells-Lifecycle-Daemon;
- isolierter Deception Service.

Die verbleibende Freigabegrenze ist ein realer Zielhost-Smoke-Test für den
konkreten Kernel, den Kernel-Verifier, den XDP-Modus und den eingesetzten
Netzwerktreiber. Die Installation gilt erst als erfolgreich, wenn sämtliche
Aktivierungs- und Health-Gates auf diesem Zielhost bestanden sind.

---

**VisionGaia Technology — GeDefense powered by VisionGaiaTechnology**  
Technisches Datenblatt für VGT GeDefense 1.0.0-beta.5 Complete Beta.
