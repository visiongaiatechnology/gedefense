# Feed-Signatur — lokale Operator-Pipeline

**Status:** implementiert in `control/feed_signing.go`, integriert in
`control/feeds.go`, `control/config.go`, `control/main.go`.
**Gültig für:** GeDefense Linux 5.1.0-beta.1 (Control Plane `gedefense-control`).

## Zweck

Die Upstream-Feeds (Feodo, Spamhaus, CINS, blocklist.de, Emerging Threats,
IPsum, FireHOL, Tor) sind einfache HTTPS-Dokumente ohne Anbietersignatur. Bis
Beta.1 konnte der Betreiber nur zwischen „ungeschützt" (`require_signed_manifest
= false`, `auto_apply = false`) und „gar keine Feeds" (Fail-Closed ohne
Trust-Anchor) wählen. Diese Pipeline schließt die Lücke: Sie erzeugt den
Manifest-Trust-Anker lokal auf dem Host und signiert exakt die Bytes, die der
Manager später prüft und parst.

## Ablauf eines signierten Syncs

1. **Konfigurations-Snapshot** laden (unveränderlich pro Sync).
2. **Bootstrap-Gates** prüfen: `local_signing=true`, `require_signed_manifest=
   true`, mindestens ein gepinnter Key, Operator-Key ladbar und in
   `trusted_signing_keys` enthalten. Jeder Fehlschlag beendet den Sync vor dem
   ersten Download (Fail-Closed).
3. **Rohbytes laden** für jede aktivierte Quelle über den bestehenden Transport
   (HTTPS, Port 443, öffentliche Hosts, Allowlist, Größen-/Zeit-/Retry-Grenzen).
4. **Snapshots schreiben**: `snapshot_dir/raw/<feed-id>`, atomar, `0600`,
   Symlink-verweigernd, auf `snapshot_dir` gejailt.
5. **Manifest bauen**: pro Feed `id`, `url` (konfigurierte HTTPS-URL),
   `raw_sha256` (SHA-256 der Rohbytes), `items_sha256` (kanonischer
   Indikator-Digest über die gemeinsame Parsing-Logik), monotone `version`,
   `action`, `valid_until` (= jetzt + `manifest_max_age_minutes`).
6. **Signieren**: Ed25519 über `threatFeedManifestMessageFor`, Signatur
   base64; Manifest atomar nach `manifest_path` (`0600`).
7. **Verifizierter Fetch**: Die Fetch-Goroutinen lesen den Snapshot statt des
   Netzes und durchlaufen unverändert `verifyFeedArtifact` (Roh-Digest gegen das
   signierte Manifest) und `verifyFeedItemsDigest` (Indikator-Digest).
8. **Kernel-Apply**: Nur Generationen mit verifiziertem, unexpired Manifest
   dürfen in die Kernel-Blockliste. `kernel_apply_status = "APPLIED"`, additive
   und gelöschte Einträge werden gezählt.

Ein Manifest wird niemals für Bytes erzeugt, die nicht vorher validiert wurden
(Größenlimit, Transport-Policy, Parsing-Policy). Schlägt der Download einer
Quelle fehl und existiert ein früherer Snapshot, wird dieser wiederverwendet und
**neu signiert** — die Integritätsaussage bleibt identisch, die Verfügbarkeit
bleibt erhalten. Ohne Snapshot schlägt die gesamte signierte Generation fehl.

## Schlüsselformat

| Datei | Format | Rechte | Zweck |
|---|---|---|---|
| `feed-signing.ed25519` | 32-Byte-Ed25519-Seed (roh); alternativ 64-Byte-Private-Key | `0600` (oder `0640` root:gedefense) | signiert Manifeste auf dem Host |
| `feed-signing.ed25519.pub` | 32-Byte-Public-Key (roh) | `0644` | Betriebs-/Rotationsprüfung |
| `feeds.trusted_signing_keys` | base64(Public-Key), max. 8 Keys | Bootstrap-Config | Pin für die Verifikation |

Die Verifikation ist bootstrap-only (TOML/Packaging), nicht über Dashboard oder
Runtime-Settings veränderbar. Ein kompromittierter Dashboard-Zugang kann damit
keinen neuen Feed-Trust-Anker setzen.

## Anti-Rollback und TTL

- `version` ist global monoton: `max(bekannte Manifest-Version)+1` pro
  signiertem Sync. `checkManifestRollback` lehnt ältere Versionen und
  Versions-Wiederverwendung mit anderem Inhalt ab.
- `valid_until` ist hart: ein abgelaufenes Manifest wird weder geladen noch
  geklont; der Kernel-Apply verweigert ohne gültiges Manifest die gesamte
  Generation und behält die vorherige Durchsetzung (kein Fail-Open).
- Uhren-Skew: Manifeste aus der Zukunft (> 5 min) werden abgelehnt.

## Snapshot-Jail

- Feed-IDs werden als Dateinamen-Token validiert (`[A-Za-z0-9._-]`, max. 64,
  kein führender Punkt) — `../`, absolute Pfade und Separatoren sind unmöglich.
- `EvalSymlinks` prüft das aufgelöste `raw`-Verzeichnis gegen den kanonischen
  `snapshot_dir`-Root; ein Symlink im Pfad führt zur Ablehnung.
- Snapshot-Dateien müssen reguläre, nicht-symlinkte Dateien mit
  `0 < size <= max_download_bytes` sein.
- `file://` existiert nur als internes Diagnoseformat; `validateFeedSourceURL`
  akzeptiert weiterhin ausschließlich HTTPS als konfigurierte Quelle.

## CLI

Der Control-Plane-Dienst läuft als `gedefense`; der Key wird deshalb bevorzugt
als Dienstkonto im schreibbaren Datenverzeichnis erzeugt:

```bash
sudo -u gedefense gedefense-control \
  --init-feed-signing /var/lib/vgt/gedefense/feed-signing
sudo -u gedefense gedefense-control \
  --init-feed-signing /var/lib/vgt/gedefense/feed-signing \
  --feed-public-key /var/lib/vgt/gedefense/feed-signing/published.pub
```

Das Verzeichnis wird `0700` angelegt, vorhandene Schlüssel werden nie
überschrieben (Rotation = neues Verzeichnis + neuer Pin + Restart). Ausgegeben
wird die base64-Form für `feeds.trusted_signing_keys`.

Der Operator-Key wird pro Prozess einmal geladen; nach Provisionierung oder
Rotation muss der Dienst neu gestartet werden. Der Pin selbst ist Bootstrap-only
(TOML) und wird bei einem Dashboard-Reload nicht verändert.

**Alternative `/etc`-Ablage:** als root erzeugen, danach die Rechte für das
Dienstkonto öffnen — Verzeichnis `0750 root:gedefense`, Private-Key
`0640 root:gedefense` (`chgrp gedefense`, `chmod` wie in OPERATIONS.md). Der
Loader akzeptiert `0600` und `0640` und verweigert gruppen-/weltbeschreibbare
Keys sowie Symlinks.

## Betriebs-Checkliste

1. Key erzeugen (Abschnitt „CLI"), Rechte prüfen.
2. `local_signing = true`, `signing_key_file`, `snapshot_dir`,
   `trusted_signing_keys` setzen (`auto_apply = true` nur mit
   `require_signed_manifest = true`).
3. `--check-config` ausführen, Dienst neu starten.
4. `/api/threat-intel`: `manifest_verified=true`,
   `manifest_authenticity="SIGNED"`, `kernel_apply_status="APPLIED"`,
   `last_kernel_added>0`.
5. Rotation: neues Key-Verzeichnis, neuen Pin eintragen, Restart; alte
   Snapshots/Manifeste werden beim ersten Sync neu signiert.

## Threat Model / Grenzen

- **Geschützt:** Manipulation der Feed-Bytes unterwegs oder auf dem Datenträger
  (Roh- und Indikator-Digest), Replay alter Generationen (Anti-Rollback),
  verspätete Zustellung (TTL), fremde Signatur (Pin), Pfad-Traversal über
  Feed-IDs (Jail).
- **Nicht geschützt:** Kompromittierung des Operator-Hosts/der Control Plane
  selbst (der Signaturschlüssel liegt dort per Design für den unbeaufsichtigten
  Betrieb), Kompromittierung des Upstreams **vor** dem ersten Snapshot
  (TOFU-Moment), Verfügbarkeitsangriffe auf die Upstreams (Snapshot-Reuse
  überbrückt nur vorhandene Generationen).
- **Bewusst:** Der Private Key liegt auf dem Host, weil die Pipeline ohne
  manuellen Offline-Schritt laufen muss; die Alternative (Offline-Signing durch
  den Release-Prozess) bleibt über `local_signing=false` und extern erzeugte
  Manifeste weiterhin möglich.

## Tests

`control/feed_signing_test.go` (Linux) deckt ab: Key-Generierung/-Rechte/
Overwrite-Schutz, Ende-zu-Ende-Sync mit In-Memory-Transport, exakte Raw-/Items-
Bindung, Pfad-Jail (Traversal, Symlink-Datei, Symlink-Verzeichnis, Oversize),
Fail-Closed ohne/mit falschem Pin, Kernel-Apply-Verweigerung bei abgelaufenem/
unverifiziertem Manifest, TTL-/Anti-Rollback-Fälle, Snapshot-Reuse bei
Upstream-Ausfall, Config-Validierung und TOML-Overlay.

Verifikationskommandos:

```bash
cd control
gofmt -l .
GOOS=linux go vet ./...
GOOS=linux go test -run 'TestLocalFeedSigning|TestInitFeedSigning|TestFeedSigning|TestFeedLocalSigning' ./...
make test
```
