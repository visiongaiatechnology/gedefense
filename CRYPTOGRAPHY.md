# GeDefense Cryptography and Trust Anchors

## Übersicht

| Zweck | Verfahren | Schlüsselmaterial |
|---|---|---|
| Operator-Passwort | Argon2id, `m=65536 KiB`, `t=3`, `p=1` | zufälliger 128-Bit-Salt, 256-Bit-Ausgabe |
| Control → Rust-Core IPC | HMAC-SHA-256 | 32-Byte Core-IPC-Key |
| Persistente Betriebsdaten | AES-256-GCM + AAD | 32-Byte Storage-Master-Key, domänenspezifische Unterkeys |
| Incident-Innenintegrität | HMAC-SHA-256, verkettet und domänengetrennt | XDR-Master-Key |
| Behavior-Innenintegrität | HMAC-SHA-256-Unterkey | aus XDR-Master-Key abgeleitet |
| Policy Snapshots | Ed25519 | lokales Policy-Schlüsselpaar |
| Forensics Exports | Ed25519, eigene Domäne | lokales Policy-Schlüsselpaar |
| Digests/Manifeste | SHA-256 | kein Schlüssel |

## Passwortspeicherung

Neue Installationen verwenden einen kanonischen Datensatz:

```text
v2$argon2id$v=19$m=65536,t=3,p=1$<salt>$<digest>
```

Das Klartextpasswort wird nicht gespeichert. Bestehende gültige PBKDF2-HMAC-SHA-256-Datensätze bleiben für die Migration lesbar und werden nach einer erfolgreichen Anmeldung atomar durch Argon2id ersetzt. Passwortdateien müssen reguläre Nicht-Symlink-Dateien mit Modus `0600` sein.

## AES-256-GCM für Betriebsdaten

Der Installer erzeugt einmalig:

```text
/etc/vgt/gedefense/secrets/storage-master.key
root:gedefense 0640, exakt 32 Zufallsbytes
```

Aus dem Master-Key wird für jeden Speicherzweck ein eigener 256-Bit-Schlüssel mit HMAC-SHA-256 abgeleitet. Der Master-Key wird nicht direkt als GCM-Schlüssel für mehrere Domänen wiederverwendet.

Die Additional Authenticated Data bindet jeden Datensatz an:

```text
Schema + Node-Name + Zweck + kanonischer Dateipfad + Sequenz
```

Ein Kopieren eines gültigen Ciphertexts in eine andere Datei, auf einen anderen Knoten, in eine andere Datendomäne oder auf eine andere Sequenz führt damit zu einem Authentifizierungsfehler. Jeder Schreibvorgang verwendet einen neuen kryptografischen Zufallsnonce.

Verschlüsselt werden insbesondere:

- Runtime-Einstellungen;
- signierte Policy-Snapshots;
- der lokale private Ed25519-Policy-Key;
- adaptive Behavior-Profile;
- Incident-Datensätze und Chain-Checkpoint.

Signaturen und HMAC-Ketten bleiben innerhalb der verschlüsselten Inhalte bestehen. Verschlüsselung schützt Vertraulichkeit und äußere Authentizität; Signaturen/MACs schützen zusätzlich die fachliche Vertrauenskette.

## Core IPC

Request und Response verwenden getrennte Protokolltags (`VGT3`, `VGT3R`). Die MAC-Eingabe enthält alle typisierten Felder in kanonischer Reihenfolge. Zeitfenster, 128-Bit-Nonce, begrenzter Replay-Cache, `SO_PEERCRED` und PID-Startidentität verhindern Wiederverwendung und Prozessverwechslung.

## Domain Separation

Beispiele:

```text
VGT-GEDEFENSE-AES256GCM-KEY-V1\0
VGT-GEDEFENSE-INCIDENT-V2\0
VGT-GEDEFENSE-KDF-V1\0 || behavior-profiles-v2
VGT-GEDEFENSE-FORENSICS-V1\0 || canonical-envelope
VGT-GEDEFENSE-RELEASE-MANIFEST-V1\n || canonical-envelope
```

## Grenzen

Der Storage-Master-Key, TLS-Private-Key, Session-Key, Backend-Token und Core-IPC-Key müssen für unbeaufsichtigte Dienststarts lokal verfügbar sein. Sie werden daher durch Eigentümer-, Gruppen-, Modus-, Nicht-Symlink- und systemd-Sandboxregeln geschützt, nicht durch sich selbst verschlüsselt. Eine vollständige Kompromittierung des Host-Root-Kontexts kann diese Schlüssel und entschlüsselte Laufzeitdaten auslesen. Eine spätere stabile Version kann TPM-Sealing und einen externen monotonen Rollback-Anker ergänzen.

GeDefense entwirft keine eigenen kryptografischen Primitive. Es nutzt AES-GCM, HMAC-SHA-256, Ed25519 und Argon2id mit domänenspezifischen Protokollbindungen.
