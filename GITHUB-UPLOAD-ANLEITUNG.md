# GeDefense auf GitHub veröffentlichen

## Ordnerstruktur

Der erzeugte Ordner `GitHub Upload` enthält zwei getrennte Bereiche:

- `Repository/` — vollständiger Quellstand für das GitHub-Repository;
- `Release Assets/` — binäre und präsentierbare Dateien für das GitHub Release.

Der Inhalt von `Repository/` muss direkt in das Root-Verzeichnis eines neuen
GitHub-Repositorys hochgeladen werden. Nicht den übergeordneten Ordner
`Repository` als zusätzliche Ebene einfügen.

## Empfohlener Ablauf

1. Auf GitHub ein neues leeres Repository anlegen.
2. Den vollständigen Inhalt von `Repository/` in dessen Root hochladen.
3. Prüfen, dass insbesondere `.github/workflows/ci.yml`,
   `rust/Cargo.lock`, `LICENSE`, `README.md` und
   `SOURCE-MANIFEST.sha256` enthalten sind.
4. Den Stand committen und den Tag `v1.0.0-beta.5` erstellen.
5. Für diesen Tag ein GitHub Release anlegen.
6. Die Dateien aus `Release Assets/` als Release Assets anhängen.
7. Die SHA-256-Werte aus den zugehörigen `.sha256`-Dateien gegen die
   hochgeladenen Artefakte prüfen.

## Sicherheitsgrenzen

Nicht in das Repository oder Release hochladen:

- lokale Schlüssel, Token, Passwortdateien oder Zertifikat-Private-Keys;
- Installationslogs;
- `dist/`, `rust/target/`, Go-Caches oder lokale VCS-Daten;
- alte Test- und Zwischen-Releases;
- persönliche IP-Adressen oder Management-CIDRs.

Der staging-Prozess lehnt Symlinks ab, beschränkt Quellpfade auf die
freigegebenen Repository-Bereiche und scannt den fertigen Upload auf
Private-Key-Marker sowie die bekannten privaten Hostwerte.
