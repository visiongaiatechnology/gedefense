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
- Feed-Quellen bleiben `auto_apply=false`;
- Enforce nach Kernel-, NIC- oder Distribution-Upgrade erneut über Observe und Canary qualifizieren.
