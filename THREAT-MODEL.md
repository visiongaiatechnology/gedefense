# VGT GeDefense 1.0 Production Beta — Threat Model

## Schutzgüter

1. Verfügbarkeit des Linux-Hosts;
2. Integrität der XDP-Regeln;
3. Integrität von Policy, Incident-Historie und Verhaltenprofilen;
4. Vertraulichkeit der lokalen Operator- und IPC-Schlüssel;
5. korrekte Zuordnung von Prozessidentitäten;
6. Nachvollziehbarkeit aktiver Reaktionen;
7. Verfügbarkeit des Sicherheitsstacks unter Ereignisflut.

## Angreifermodelle

### A1 — externer Netzwerkangreifer

Kann Pakete, Verbindungsraten, Protokollheader und Zielmuster kontrollieren, besitzt aber keinen lokalen Zugang.

### A2 — kompromittierter unprivilegierter Prozess

Kann Prozesse starten, Kommandozeilen beeinflussen, Netzwerkverbindungen öffnen und lokale Ressourcen belasten.

### A3 — kompromittierte Go-Control-Plane

Besitzt die Control-Plane-UID und Zugriff auf deren lokale Schlüssel, aber keine generische Root-Shell und keine direkte Kill-Capability.

### A4 — kompromittierter Feed oder Feed-Transportendpunkt

Kann fehlerhafte, übergroße oder gezielt schädliche IP-Präfixe liefern.

### A5 — lokaler Root-Angreifer

Kann Binärdateien, Schlüssel, Kernelzustand und lokale Persistenz gemeinsam verändern. Dieses Modell kann lokal nur erkannt oder erschwert, nicht abschließend besiegt werden.

## Angriffsklassen und Kontrollen

| Angriff | Primäre Kontrollen | Restgrenze |
|---|---|---|
| SYN-/Paketflut | XDP, LPM, kleiner Parser | Uplink-Bandbreite bleibt physische Grenze |
| Management-Lockout | Management-Allowlist vor Blocklist, Enforce-Gate, Out-of-Band-Konsole | falsch konfigurierte CIDRs müssen im Observe-Soak erkannt werden |
| Installations-TOCTOU | root-eigene Verifikationsjail, Signatur + Out-of-Band-Digest | kompromittierter Root bleibt außerhalb |
| DNS-Rebinding gegen Dashboard | Loopback, Host-Allowlist, Origin-Prüfung | Remote-Modus benötigt korrekte TLS-/Hostkonfiguration |
| API-Replay | Bearer + Request-ID + TTL + bounded replay map | gestohlener Token bleibt bis Rotation gültig |
| Core-IPC-Fälschung | Unix-Socket, 0600 Key, SO_PEERCRED, VGT3 HMAC | kompromittierte Control-UID mit Key kann erlaubte Befehle anfragen |
| IPC-Replay | Zeitfenster + Nonce + fail-closed Cache | Uhrsprünge können legitime Requests vorübergehend ablehnen |
| PID-Reuse | Start-Ticks vor/nach pidfd_open + pidfd_signal | Kernel ohne pidfd wird nicht unterstützt |
| Regex-DoS | Go RE2-Semantik, feste Regeln, Command-Limit | sehr viele Prozesse werden über Queuebudgets begrenzt |
| XDR-Selbst-DoS | feste Worker/Queues/Budgets/Histories | Evaluationen können sichtbar verworfen werden |
| Behavior-Cardinality-Angriff | max profiles, max ports, max timestamps | neue Profile werden bei Sättigung nicht gelernt |
| Model Poisoning | Warmup, hohe Z-Schwelle, nur Zusatzsignal | langsame Manipulation kann Statistik verschieben |
| Feed-Kompromittierung | HTTPS, Größen-/Eintragslimit, Public-IP-Filter, kein Auto-Apply | C2-Feedtreffer kann Score erhöhen, ist keine Wahrheit |
| Threat-Lookup-CPU-DoS | Prefix-Buckets statt linearer Feedscan | IPv6 benötigt bis zu 129 Präfixprüfungen |
| Policy-Manipulation | Ed25519, 0600, striktes JSON | signierter Rollback ohne externen Anker möglich |
| Logzeilenänderung/-reorder | HMAC-Kette | Root mit Schlüssel kann neu signieren |
| Tail-Truncation | atomischer Head-Checkpoint | Root kann Log, Head und Key gemeinsam ersetzen |
| Symlink-Angriff auf Schlüssel | Lstat/reject, O_EXCL, atomische Writes | bösartige Mount-/Root-Manipulation bleibt außerhalb |
| Browser-XSS | keine dynamischen HTML-Sinks, CSP, same-origin | Browser-/Extension-Kompromittierung liegt außerhalb |
| Supply-Chain-Angriff | stdlib-only Go, exakte Rust-Pins, geprüfter Vendorbaum, Lockfile-Attest, Offline-Netznamespace, SBOM, signiertes Release-Manifest | Compiler-/Builder-Vertrauen bleibt |

## Mehrsignalreaktion

Ein Kill-Kandidat benötigt:

```text
score >= kill_score
AND mindestens zwei unabhängige killberechtigte Kategorien
AND XDR mode = enforce
AND XDR nicht degradiert
AND Rust-Broker online
AND objektive Broker-Evidenz
```

Ein einzelner Regex-, Threat-Feed-, Verhalten- oder Masquerading-Treffer genügt nicht.

## Degradation statt Selbsttäuschung

GeDefense wechselt in einen sichtbaren degradierten Zustand, wenn:

- Incident-Kette oder Head ungültig ist;
- Verhaltenprofil-MAC ungültig ist;
- ein geschütztes Objekt verändert wurde;
- Incident-Budget erschöpft ist;
- kritische Persistenz fehlschlägt.

Im degradierten Zustand bleibt Beobachtung und Dashboard-Zugriff erhalten, aktive XDR-Reaktion wird jedoch deaktiviert.

## Explizit nicht versprochen

- keine vollständige Abwehr volumetrischer Angriffe oberhalb der physischen Leitung;
- keine passive Inhalts-DPI für verschlüsseltes HTTPS;
- keine Garantie gegen Root;
- keine autonome Malwareklassifikation durch Statistik;
- keine Produktionsfreigabe des unkompilierten Rust/eBPF-Pfads.
