# GeDefense Beta v3 auf GitHub veröffentlichen

## Ordnerstruktur

Der erzeugte Ordner `GitHub Upload` enthält zwei getrennte Bereiche:

- `Repository/` — vollständiger Quellstand für das GitHub-Repository;
- `Release Assets/` — zunächst ein Sperrhinweis; echte Binärartefakte werden
  erst nach erfolgreicher Linux-CI und Hostqualifikation eingestellt.

Der Inhalt von `Repository/` muss direkt in das Root-Verzeichnis eines neuen
GitHub-Repositorys hochgeladen werden. Nicht den übergeordneten Ordner
`Repository` als zusätzliche Ebene einfügen.

## Empfohlener Ablauf

1. Auf GitHub ein neues leeres Repository anlegen.
2. Den vollständigen Inhalt von `Repository/` in dessen Root hochladen.
3. Prüfen, dass insbesondere `.github/workflows/ci.yml`,
   `rust/Cargo.lock`, `LICENSE`, `README.md` und
   `SOURCE-MANIFEST.sha256` enthalten sind.
4. Den Source-Stand auf den Branch `main` committen und pushen.
5. Die GitHub-Actions-Workflows vollständig durchlaufen lassen.
6. Die privilegierte Hostqualifikation auf den vorgesehenen Linux-Testsystemen
   ausführen und deren Logs als Release-Evidenz sichern.
7. Erst danach lokal oder auf einem qualifizierten Linux-Builder
   `scripts/package-artifacts.sh` ausführen.
8. Das Staging mit `python3 scripts/stage-github-upload.py --with-release-assets`
   erneut erzeugen.
9. Den Tag `v3.0.0-beta.1` erstellen und die vier Dateien aus
   `Release Assets/` am GitHub Release anhängen.
10. Alle SHA-256-Werte nach dem Upload erneut prüfen.

Für den ersten Source-Upload genügt:

```bash
python3 scripts/stage-github-upload.py
cd "GitHub Upload/Repository"
git init -b main
git add --all
git commit -m "GeDefense Beta v3 source release candidate"
```

## Sicherheitsgrenzen

Nicht in das Repository oder Release hochladen:

- lokale Schlüssel, Token, Passwortdateien oder Zertifikat-Private-Keys;
- Installationslogs;
- `dist/`, `rust/target/`, Go-Caches oder lokale VCS-Daten;
- alte Test- und Zwischen-Releases;
- persönliche IP-Adressen oder Management-CIDRs.

Der Staging-Prozess lehnt Symlinks ab, beschränkt Quellpfade auf die
freigegebenen Repository-Bereiche und scannt den fertigen Upload auf
Private-Key-Marker sowie die bekannten privaten Hostwerte.
