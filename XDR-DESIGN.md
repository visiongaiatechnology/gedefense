# GeDefense Adaptive XDR — Design

## Ziel

Das XDR soll Prozess-, Netzwerk-, Integritäts-, Lineage-, Baseline-, Threat-Intel- und Verhaltenssignale lokal korrelieren. Es darf dabei weder durch eine Einzelheuristik zum Kill-Schalter noch durch Ereignisfluten zum Host-DoS werden.

## Sensoren

### Prozesssensor

Aktueller Beta-Fallback:

- `/proc/<pid>/stat` für PID-Startidentität und PPID;
- `/proc/<pid>/status` für UID/GID;
- `/proc/<pid>/exe` für Herkunft und Deleted-/memfd-Erkennung;
- `/proc/<pid>/cmdline` streng größenbegrenzt;
- `/proc/<pid>/cgroup` für Kontext;
- bestehende Prozesse beim Start nur als Seed, nicht rückwirkend bewertet.

### Netzwerksensor

- `/proc/net/tcp`, `tcp6`, `udp`, `udp6`;
- Socket-Inode → Prozess-FD-Korrelation;
- ausschließlich externe öffentliche Ziele;
- deduplizierte Prozess-/Remote-/Port-Sicht.

### Integritätssensor

- Inotify auf Linux für ereignisgetriebene Änderungen;
- periodischer SHA-256-Fallback;
- Pfad, Größe, Modus und Digest als Ausgangszustand.

## KillerDOM-Linux

KillerDOM ist ein versionierter Satz kleiner, RE2-kompatibler Regeln:

- `KD.LINUX.PIPE_SHELL`;
- `KD.LINUX.ENCODED_EXEC`;
- `KD.LINUX.REVERSE_SHELL`;
- `KD.LINUX.LD_PRELOAD`;
- `KD.LINUX.CREDENTIAL_ACCESS`;
- `KD.LINUX.DESTRUCTIVE`;
- `KD.LINUX.PERSISTENCE`;
- `KD.LINUX.BPF_LOAD`.

Jede Regel besitzt ID, Kategorie, Score, Erklärung und Kill-Eignung. Regeln werden beim Start kompiliert und durch Tests geladen. Die Kommandozeile wird vor der Auswertung begrenzt; gespeicherte Vorschauen werden auf Token-, Passwort-, Authorization- und URL-Credential-Muster redigiert.

## Deterministische Signale

- `XDR.EXE_DELETED`;
- `XDR.MEMFD_EXEC`;
- `XDR.TEMP_EXEC`;
- `XDR.WEB_SHELL_LINEAGE`;
- `XDR.NAME_PATH_MISMATCH`;
- `XDR.THREAT_INTEL_C2`;
- Baseline-Hash-, UID-, Parent- und Netzwerkabweichungen;
- `XDR.SELF_TAMPER`.

## Adaptive Signale

- `XDR.ANOMALY.EXEC_BURST`;
- `XDR.ANOMALY.CONNECTION_FANOUT`;
- `XDR.ANOMALY.REMOTE_DIVERSITY`;
- `XDR.ANOMALY.PORT_DIVERSITY`.

### Lernmodell

- Welford-Online-Statistik für Mittelwert und Varianz;
- Warmup-Mindestzahl;
- konfigurierbare Z-Score-Schwelle in Tausendsteln;
- keine Payload-, Inhalts- oder Benutzerdatenspeicherung;
- Profile nach absolutem Executable-Pfad;
- HMAC-authentifizierte Persistenz;
- maximal 4096 Profile und 256 Ports pro Profil standardmäßig;
- adaptive Signale sind nie `KillEligible`.

## Scoring

```text
ALERT:   score >= alert_score
CONTAIN: score >= contain_score
KILL:    score >= kill_score + mindestens zwei starke Kategorien
```

Standardwerte:

```text
alert = 40
contain = 80
kill = 120
```

Der Gesamtscore ist auf 250 begrenzt. Doppelte Rule-IDs werden nur einmal gezählt.

## Reaktionspipeline

1. Entscheidung im unprivilegierten Go-Prozess;
2. optionales Remote-IP-Quarantine mit kurzer TTL;
3. VGT3-Anfrage an Rust-Core;
4. Peer-, HMAC-, Replay- und PID-Prüfung;
5. bei Kill erneute objektive Evidenzprüfung;
6. pidfd-Signal;
7. Incident-Record und sichtbares Outcome.

Wird ein Kill abgelehnt, versucht GeDefense kontrolliert Containment. Wird auch Containment abgelehnt, bleibt der Prozess unverändert und der Fehler ist im Incident sichtbar.

## Backpressure

Die Pipeline verwendet zwei bounded Channels:

- High Priority: neue Prozessidentitäten;
- Normal Priority: periodische Netzwerkbewertungen.

Bei Sättigung:

- keine zusätzliche Goroutine;
- keine unbegrenzte Speicherallokation;
- Evaluation wird verworfen;
- Drop-Counter steigt;
- Warnungen erscheinen bei 1, 2, 4, 8, ... Drops.

## Baseline

Eine manuell freigegebene Baseline kann pro Executable definieren:

- SHA-256;
- erlaubte UIDs;
- erlaubte Parent-Executables;
- externe Netzwerkerlaubnis;
- erlaubte Remote-Ports;
- erlaubte Remote-CIDRs.

Die Baseline wird nicht automatisch umgeschrieben. Adaptive Profile und freigegebene Baseline sind getrennte Konzepte.

## Incident-Historie

Jeder Incident enthält:

- PID, PPID, Start-Ticks, UID;
- Prozess, Executable, Parent;
- Remote-Ziel;
- redigierte Command-Preview und SHA-256 des vollständigen begrenzten Befehls;
- Rule-IDs und Kategorien;
- Score, Kill-Signalzahl, Entscheidung, Aktion und Outcome;
- HMAC-Record-Hash.

Das Log ist append-only innerhalb des vertrauenswürdigen Loggers, größenbegrenzt und durch Head-Checkpoint verankert.

## Nächste Sensorstufe

Die Beta-Procfs-Erkennung soll durch Kernelereignisse ergänzt werden:

- `sched_process_exec`;
- BPF Ring Buffer;
- cgroup connect hooks;
- ausgewählte BPF-LSM-Hooks;
- Namespace-/Container-Metadaten.

Procfs bleibt als Recovery- und Anreicherungsquelle erhalten.
