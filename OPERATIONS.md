# Operations Runbook — GeDefense Production Beta

## Betriebsgrundsatz

Ein Beta-Host startet immer in Observe. Keine gespeicherte Policy darf nach Reboot automatisch aktive Reaktion freigeben. Promotion erfolgt ausschließlich nach aktuellen Gesundheits- und Soak-Gates.

## Vor der Installation

- Out-of-Band-Konsole testen;
- reale Management-IP/CIDR bestimmen;
- Release-Public-Key root-eigen unter `/etc/vgt/gedefense/release.ed25519.pub` installieren;
- Manifest-SHA-256 über getrennten Kanal beziehen;
- Kernel-/NIC-Profil in der Supportmatrix bestätigen;
- Host als nichtkritischen Beta-Knoten klassifizieren.

## Installation

```bash
read -r -p "Veröffentlichter Manifest-SHA-256: " VGT_RELEASE_MANIFEST_SHA256
read -r -p "Management-IP oder CIDR: " VGT_MANAGEMENT_ALLOWLIST
export VGT_RELEASE_MANIFEST_SHA256 VGT_MANAGEMENT_ALLOWLIST
export VGT_RELEASE_PUBLIC_KEY="/etc/vgt/gedefense/release.ed25519.pub"
sudo -E ./scripts/install-beta.sh
```

Die Installation ist nur erfolgreich, wenn `/readyz` nach dem atomaren Wechsel grün wird. Andernfalls wird automatisch auf die vorherige Version zurückgeschaltet.

## Health Endpoints

```text
/livez   Prozess und HTTP-Loop leben
/readyz  aktuelle Beta-Phase erfüllt sämtliche Gates
/healthz Alias für Readiness
```

Ein Emergency Stop macht `/readyz` rot, lässt `/livez` aber grün.

## Basisdiagnose

```bash
systemctl status gedefense-bpffs gedefense-core gedefense-control
journalctl -u gedefense-core -u gedefense-control --since=-30min
curl --fail http://127.0.0.1:9843/livez
curl --fail http://127.0.0.1:9843/readyz
mountpoint /sys/fs/bpf
```

## Management-Allowlist

Konfiguration:

```toml
[defense]
allowlist = "198.51.100.42/32,2001:db8:42::/64"
```

Die Adressen oben sind Dokumentationsnetze. Auf einem Beta-Host müssen reale Operator-Quellen eingetragen werden. Nach Konfigurationsänderung Core und Control Plane kontrolliert neu starten. Das Dashboard muss `Allowlist SYNC` melden, bevor Enforce freigegeben werden kann.

## Promotion

### Observe Review

Prüfen:

- keine ungeklärten kritischen Incidents;
- XDR Drop-Rate unter Gate;
- Policy-Signatur verifiziert;
- Forensikkette intakt;
- Core durchgehend authentifiziert;
- Management-Allowlist synchronisiert;
- Recovery-Konsole erreichbar.

### Canary

Nur XDR-Containment wird aktiviert. Netzwerkpolicy bleibt Observe.

### Enforce

Nur nach Canary-Soak und dokumentiertem Rollbackdrill. `ENFORCE` wird verweigert, wenn die Management-Allowlist leer oder nicht im Kernel bestätigt ist.

## Emergency Stop

Über Dashboard/API auslösen. Der Stop-Anker liegt unter:

```text
/var/lib/vgt/gedefense/EMERGENCY_STOP
```

Ein erfolgreicher API-Status setzt voraus, dass der Rust-Core seine autoritative Blockliste geleert, `VERIFY_EMPTY` authentifiziert bestätigt und die Control Plane eine signierte Observe-Policy persistiert hat. Bei `kernel_policy_state=unverified` bleibt der Stop-Anker aktiv; die Wiederholung erfolgt automatisch nach einem authentifizierten Core-Heartbeat. Bis `verified-empty` sichtbar ist, muss der Kernelzustand als potenziell aktiv behandelt und über die Out-of-Band-Konsole geprüft werden.

Vor manueller Entfernung:

1. Logs und signierten Forensikexport sichern;
2. Ursache bestimmen;
3. Kernelregeln und Prozessreaktionen prüfen;
4. gegebenenfalls expliziten Rollback ausführen;
5. erst danach den Anker entfernen und erneut mit Observe beginnen.

## Expliziter Rollback

```bash
sudo ./scripts/rollback-beta.sh
```

Der Scriptlauf prüft das vorherige Release erneut kryptografisch. Bei fehlgeschlagener Liveness wird das ursprüngliche `current`-Ziel wiederhergestellt.

## Forensikexport

Über das Command Center exportieren und offline gegen den Policy-Public-Key prüfen:

```bash
/opt/vgt/gedefense/current/bin/gedefense-control \
  --verify-forensics=/secure/evidence/gedefense-forensics.signed.json \
  --public-key=/var/lib/vgt/gedefense/policy.ed25519.pub
```

## Wartung

- keine Binärdatei unter `current` überschreiben;
- jedes Update als neues unveränderliches Release installieren;
- Policy- und Forensikschlüssel nicht zusammen mit Logs exportieren;
- Vendor-, Lock- und Release-Manifeste pro Version archivieren;
- Feed-Quellen bleiben ohne provisionierten Trust-Anchor `auto_apply=false`; `auto_apply=true` ist nur mit `require_signed_manifest=true`, gepinntem Key und (empfohlen) lokaler Signatur zulässig — siehe Abschnitt „Feed-Signatur lokal provisionieren";
- Enforce nach Kernel-, NIC- oder Distribution-Upgrade erneut über Observe und Canary qualifizieren.

## Feed-Signatur lokal provisionieren

Der Feed-Trust-Anker wird ausschließlich auf dem Host erzeugt. Private Schlüssel
verlassen den Host nicht, werden nie in ein Repository geschrieben und nie über
das Dashboard verwaltet (bootstrap-only Pin).

### 1. Operator-Key erzeugen

Der Dienst läuft als `User=gedefense` (`packaging/systemd/gedefense-control.service`),
`/etc/vgt/gedefense` ist für ihn read-only und `/var/lib/vgt/gedefense` ist
`1770 root:gedefense` und in `ReadWritePaths`. Der Key wird daher bevorzugt
**als Dienstkonto im Datenverzeichnis** erzeugt:

```bash
sudo -u gedefense /opt/vgt/gedefense/current/bin/gedefense-control \
  --init-feed-signing /var/lib/vgt/gedefense/feed-signing
```

Ausgabe (Beispiel):

```text
feed signing key pair created in /var/lib/vgt/gedefense/feed-signing
feeds.trusted_signing_keys = "Qm9...BASE64_PUBLIC_KEY..."
key fingerprint: ed25519:0123456789abcdef
```

Erzeugt werden:

| Datei | Inhalt | Rechte |
|---|---|---|
| `/var/lib/vgt/gedefense/feed-signing/feed-signing.ed25519` | 32-Byte-Ed25519-Seed (roh) | `0600` gedefense |
| `/var/lib/vgt/gedefense/feed-signing/feed-signing.ed25519.pub` | 32-Byte-Public-Key (roh) | `0644` |
| Verzeichnis | — | `0700` gedefense |

**Alternative (Key unter `/etc`):** Wenn der Key bewusst außerhalb des
Datenverzeichnisses liegen soll, als root erzeugen und die Rechte für das
Dienstkonto öffnen (Verzeichnis `0750 root:gedefense`, Private-Key
`0640 root:gedefense`):

```bash
sudo install -d -m 0750 -o root -g gedefense /etc/vgt/gedefense/feed-signing
sudo /opt/vgt/gedefense/current/bin/gedefense-control \
  --init-feed-signing /etc/vgt/gedefense/feed-signing
sudo chmod 0750 /etc/vgt/gedefense/feed-signing
sudo chgrp gedefense /etc/vgt/gedefense/feed-signing/feed-signing.ed25519
sudo chmod 0640 /etc/vgt/gedefense/feed-signing/feed-signing.ed25519
```

Der Loader akzeptiert `0600` (Eigentümer) und `0640` (Gruppe `gedefense`) und
verweigert welt-/gruppenbeschreibbare Keys. Ein erneuter Aufruf mit demselben
Verzeichnis wird verweigert (keine stille Rotation). Rotation ist ein expliziter
Vorgang mit neuem Verzeichnis, neuem Pin und Neustart des Dienstes.

### 2. Konfiguration setzen

In `/etc/vgt/gedefense/gedefense.toml`:

```toml
[feeds]
enabled = true
auto_apply = true
require_signed_manifest = true
manifest_path = "/var/lib/vgt/gedefense/threat-feed-manifest.json"
manifest_max_age_minutes = 1440
local_signing = true
signing_key_file = "/var/lib/vgt/gedefense/feed-signing/feed-signing.ed25519"
snapshot_dir = "/var/lib/vgt/gedefense/feed-snapshots"
trusted_signing_keys = "<BASE64_PUBLIC_KEY_AUS_SCHRITT_1>"
```

`snapshot_dir` und `manifest_path` müssen unter einem Verzeichnis liegen, das
die Unit schreiben darf (`ReadWritePaths=/var/lib/vgt/gedefense`); die Defaults
tun das. `feeds.auto_apply=true` wird bei fehlendem Trust-Anchor oder
deaktiviertem Signatur-Gate bereits bei der Konfigurationsprüfung abgelehnt.

### 3. Prüfen, starten, verifizieren

```bash
sudo /opt/vgt/gedefense/current/bin/gedefense-control -config /etc/vgt/gedefense/gedefense.toml --check-config
sudo systemctl restart gedefense-control
journalctl -u gedefense-control --since=-5min | grep -i 'feed signing'
curl --fail http://127.0.0.1:9843/api/threat-intel
```

Erwartetes Ergebnis:

- `overall_status = "OK"` bzw. `"PARTIAL"` nur bei echten Upstream-Ausfällen,
- alle Feed-Einträge mit `manifest_verified = true` und `manifest_authenticity = "SIGNED"`,
- `kernel_apply_status = "APPLIED"` (der gesunde Wert; das Legacy-„OK" aus 4.1
  wird beim Laden auf `APPLIED` normalisiert),
- `last_kernel_added` > 0 beim ersten Lauf, danach 0 bei unverändertem Content.

Snapshots liegen unter `snapshot_dir/raw/<feed-id>` (`0600`), das signierte
Manifest unter `manifest_path` (`0600`). Feed-Identität im Manifest bleibt die
konfigurierte HTTPS-URL; `file://` ist ausschließlich das interne Leseschema der
Snapshots und wird als konfigurierte Quelle abgelehnt.

### 4. Fehlerbilder

| Symptom | Ursache | Abhilfe |
|---|---|---|
| `local feed signing trust anchor unavailable` | Key-Datei fehlt, ist ein Symlink oder hat falsche Rechte | `--init-feed-signing` erneut in neuem Verzeichnis, Rechte `0600`/`0640` setzen |
| `... is not pinned in feeds.trusted_signing_keys` | Operator-Key und Pin passen nicht zusammen | Public-Key erneut ausgeben lassen (`--feed-public-key`), Pin korrigieren |
| `signed feed manifest is missing/expired` | LAPI-Neustart zwischen den Läufen oder Manifest abgelaufen | Control Plane neu starten; Sync erzeugt ein frisches Manifest |
| `local feed snapshot fetch failed; no signed manifest was produced` | Quelle down und noch kein Snapshot vorhanden | Upstream prüfen; nach erstem erfolgreichen Lauf überbrückt die Pipeline kurze Ausfälle über den letzten Snapshot |
| `kernel apply refused` | Kein verifiziertes/ungültiges Manifest oder `ManifestVerified=false` | `manifest_verified` je Feed prüfen, Key-Pin verifizieren |

## XDR Incident-Ledger Recovery

Ein kryptografischer Fehler der XDR-Incident-Kette ist ein Fail-Closed-Ereignis. GeDefense blockiert Canary/Enforce und lässt die Incident-Kette nicht automatisch reparieren oder abschneiden.

Der unterstützte Recovery-Pfad ist ausschließlich für den Fall vorgesehen, dass das Incident Ledger selbst die einzige XDR-Degradation ist. Er verlangt Observe-Enforcement, Operator-Authentifizierung, Replay-Schutz, einen expliziten Recovery-Dialog und eine Audit-Begründung.

Ablauf:

1. Forensik-Export erstellen.
2. Unter **GeDefense XDR** die Incident-Integrität erneut prüfen.
3. **XDR sicher wiederherstellen** auswählen.
4. GeDefense archiviert Incident Log und Head-Checkpoint unverändert unter dem privaten XDR-Recovery-Bereich, erstellt ein SHA-256-Manifest und verifiziert unmittelbar vor der Umschaltung nochmals, dass sich die Quelle nicht verändert hat.
5. Eine neue leere Incident-Kette wird crash-sicher initialisiert und direkt vom Datenträger verifiziert.
6. Die vorhandenen XDR-/Storage-Schlüssel bleiben unverändert.
7. Erst nach erfolgreichen Evidence-Ledger-Commits wird die Incident-Ledger-Degradation entfernt. Andere XDR-Degradationsursachen bleiben unangetastet.
8. Canary/Enforce werden niemals automatisch aktiviert; Promotion bleibt eine getrennte Operator-Entscheidung.

Unzulässig sind manuelles Editieren, Truncaten oder Löschen des aktiven Incident Logs sowie automatische Key-Rotation als Teil dieser Recovery.
