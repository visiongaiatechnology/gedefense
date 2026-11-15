# POINT 2 — Ephemere „parser-ephemeral"-Gaia-Cells (Qubes-light)

**Status:** IMPLEMENTIERT (Phase 1) – T5-Review-Fixes eingearbeitet und Gate-verifiziert (2026-11-15) · GeDefense V6 (`6.0.0`)
**Review-Regel:** Verbindlicher Vertrag zwischen Helper (Rust), Go-Control und Packaging/Tests. ABI-Änderungen zuerst hier, dann alle Task-Owner informieren. Umsetzungsstand/Abweichungen: §12; T5-Review-Befunde/Behebungsstand: §12.16–§12.22; Evidenz/Testnachweise: `docs/POINT2-PHASE1-REPORT.md`.

## 0. Ausgangsbefund (Recon, evidenzbasiert)

- Im Repo existiert **keine** Zell-Erzeugung und **keine** echte Prozess-Isolation: Gaia-Cells sind heute nur Beobachter/Operator-Oberfläche für eine externe AstraeaOS-Runtime (`/run/gaia-cells/control.sock`, VGTGC1) oder eine lokale cgroup-Registry (`/sys/fs/cgroup/vgt-cells`), die nur vorhandene Verzeichnisse listet/freezt.
- Go-Control läuft als `gedefense` mit **CapEff=0**, `NoNewPrivileges=yes`, `RestrictNamespaces=yes`, Seccomp-Filter, `ProtectSystem=strict` → kann **keine** Namespaces/Prozesse erzeugen.
- Rust-Core läuft mit `RestrictNamespaces=yes`, `ProtectControlGroups=yes`, ReadOnly-`/sys/fs/cgroup`, Seccomp ohne `mount`; security-audit verbietet Exec-Primitive in control/gateway/core/eBPF → Core darf kein Spawner werden (würde Sandbox aufweichen = Attrappe/Risiko).
- Zielserver: externe Runtime **nicht installiert**, `/sys/fs/cgroup/vgt-cells` existiert (root:root 0755, `cgroup.freeze` root:root 0644), Control kann `cgroup.freeze` **nicht schreiben**; BPF-LSM inaktiv (P1-Befund); P3-Egress (cgroup_skb) ist der einzige heute wirksame Host-Netzhebel, aber **egress-only und Loopback-exempt** — kein Ersatz für eine echte Netzwerk-Isolation.
- Konsequenz: Ohne einen neuen, klar abgegrenzten privilegierten Helper ist Punkt 2 nicht ehrlich umsetzbar. Deshalb: **neuer root-Dienst `gedefense-cell-helper`** (eigenes Binary/Crate, **nicht** Core/Control umbauen), der ausschließlich Parser-Zellen besitzt; Go-Control orchestriert/überwacht über signiertes Protokoll. Keine Attrappe: Fehlt der Helper/die Sandbox-Fähigkeit, wird der Status `unavailable` und `CELL_CREATE` explizit verweigert.

## 1. Ziel und Leitplanken

Ziel: Zero-Click-Parser (PDF/Media/Dokument) laufen in einer **ephemeren**, wegwerfbaren Zelle: eigenes Mount-/PID-/Netz-/IPC-/UTS-Namespace, private tmpfs-Wurzel, nur ein read-only gebundenes Dokument, kein `$HOME`/`~/.ssh`/Keyring/Browser-Cookies, **kein Netzwerk** (leeres netns, `lo` down, AF_UNIX-Sockets nur für explizit gebundene Display/PipeWire-Sockets), Seccomp-/Cap-Drop, TTL + Auto-Burn, forensischer Export nur über einen größenbeschränkten, fd-basierten Broker.

Leitplanken:
1. **Privilege Split:** Helper (root) ist der einzige Spawner; Go bleibt unprivilegiert (CapEff=0); Rust-Core bleibt unverändert (kein Exec, keine Namespace-Syscalls). Neue `security-audit`-Invariante: Exec-Primitive ausschließlich im Helper-Binary, dort nur `execve` auf **gepinnte, hash-verifizierte** Parser-Binaries aus root-owned Profiltabelle.
2. **Keine freien Pfade/Argumente aus dem Netz/API:** API/Settings liefern nur Profil-ID, Input-Token (Staging), TTL und Limits. Binärpfad/argv/env/Display-Flags kommen ausschließlich aus `/etc/vgt/gedefense/parser-profiles.conf` (root-owned, 0640, package-managed, Hash im Helper-Log/Status).
3. **Fail-Closed, Default off:** `parser_cells.enabled=false` nach Upgrade; jede Fähigkeitslücke (kein Helper/Sandbox/Profil) ⇒ `unavailable`/`capability-missing`, Create 503/ERR; nie „isoliert" behaupten, wenn eine Schicht fehlt.
4. **Evidence-first & nichts destruktiv löschen:** Vor Burn/Freeze wird Evidence committet (XDR/EvidenceLedger); Burn zerstört **nur** die ephemeren Zell-Ressourcen (tmpfs/mount-ns/cgroup/Prozesse) und markiert Exporte als untrusted Evidence; Host-Dateien/Quarantäne/Logs bleiben. Export wird nie ausgeführt/gerendert.
5. **Reverse/Forensik:** Burn ist idempotent, Generation/UUID-gebunden; Status/Burn-Ledger bleiben lesbar; Operator kann Zellen manuell burnen (confirm-gated), Auto-Burn nur nach Policy.
6. **Kein Umbau bestehender Module:** GaiaCells-Adapter/VGTGC1, TransactionEngine, EvidenceLedger, CellGuard-Signaturen bleiben; Ergänzungen additiv in neuen Dateien/Modulen.

## 2. Architektur

```
User/UI/Operator ──HTTP──> Go-Control (unprivileged, CapEff=0)
   │                         ├─ ParserCellManager (Settings, Admission, TTL, Evidence, API)
   │                         ├─ Kernel-Policies: P3-StyX-Egress (per Cgroup default-deny),
   │                         │  P1-Titan-Exec (strict, nur wenn bpf-LSM aktiv), Cell-LSM-Flag
   │                         └─ VGTGC2-Client (Unix-Socket, HMAC+Nonce+Peer-UID)
   ▼
go: /run/vgt-gedefense/cell-helper.sock  (0660 root:gedefense)
   ▼
gedefense-cell-helper (root, eigene systemd-Unit)
   ├─ CELL_CREATE: sandbox spawn (namespaces/tmpfs/seccomp/caps/nnp/cgroup)
   ├─ CELL_FREEZE/UNFREEZE, CELL_BURN (cgroup.kill+rmdir), TTL-Timerfd, Orphan-Sweep
   ├─ CELL_EXPORT_READ: sealed memfd via SCM_RIGHTS + size/sha256
   └─ Burn-Ledger (JSONL, fsync) + Health/Status
```
Die externe AstraeaOS-Runtime bleibt unberührt; `parser-ephemeral`-Zellen sind GeDefense-lokale Zellen (Doku-Abgrenzung zu `GEDEFENSE-ASTRAEAOS-INTEGRATION.md`).

## 3. VGTGC2-Protokoll (Helper ↔ Go)

Transport: Unix-Socket `/run/vgt-gedefense/cell-helper.sock`, Mode `0660 root:gedefense`, Listener im Helper; Client im Go-Control als User `gedefense`. **Keine externen JSON-/TOML-Crates** (Workspace hat nur libc/base64/hex/hmac/sha2 offline): kompaktes, zeilenbasiertes Textprotokoll im Stil von VGT3/VGTGC1, Felder mit `0x1f` getrennt, Payload base64url.

- Request-Zeile (≤ 8 KiB): `VGTGC2 <id-hex16> <unix-ts> <command> <base64url-payload> <hex-mac66?>`; MAC = HMAC-SHA256(Key, `"VGTGC2"␟id␟ts␟command␟b64payload`); Key 32 Byte aus `/etc/vgt/gedefense/secrets/cell-helper.key` (0640 root:gedefense); Helper prüft `SO_PEERCRED` (UID == gedefense), Zeitfenster ±30 s, ID-/Nonce-Cache (bounded, Replay), exakte Feldgrenzen; Fehler ⇒ `ERR`-Zeile mit Code (keine internen Pfade an den Client).
- Payload: `k=v`-Paare mit `0x1f` getrennt (Reihenfolge kanonisch für MAC = exakt die Bytes, keine Normalisierung); Werte nur `[A-Za-z0-9._:/+-]` bzw. Hex; keine Leerzeichen/NUL; Längencaps pro Feld. Unbekannte/fehlende Felder ⇒ ERR.
- Antwort-Zeile (≤ 64 KiB): `VGTGC2R <id> <OK|ERR> <base64url-payload> <hex-mac>`; MAC über `"VGTGC2R"␟id␟status␟b64payload`. `CELL_EXPORT_READ`-Antworten dürfen zusätzlich **genau einen** FD via `SCM_RIGHTS` enthalten (sealed memfd `F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK`), Payload `size=..␟sha256=..␟type=..`; Go liest bounded, schließt FD, importiert als untrusted Evidence.
- Kommandos & Payloads (vollständig im Code, bounded):
  - `CELL_CAPABILITIES` → `abi=cell-runtime-v1␟sandbox=true|false␟profiles=<csv-ids>␟max_concurrent=N␟input_bytes=N␟export_bytes=N␟ttl_max=N␟bpf_lsm=active|inactive`
  - `CELL_CREATE profile=<id>␟input_token=<hex32>␟input_sha256=<hex64>␟input_size=N␟ttl_seconds=N␟max_rss_bytes=N␟max_pids=N` → `uuid=<hex32>␟generation=N␟cgroup_id=N␟cgroup_path=..␟pid=N␟expires_at=N␟sandbox=true␟netns=true`
  - `CELL_LIST` → `count=N` + je Zeile `uuid=..␟generation=..␟cgroup_id=..␟profile=..␟state=..␟expires_at=..␟pid=..␟export_size=..`
  - `CELL_FREEZE uuid=..␟generation=..␟cgroup_id=..` / `CELL_UNFREEZE` → `applied|deleted` (idempotent)
  - `CELL_BURN uuid=..␟generation=..␟cgroup_id=..␟evidence_id=..␟reason=..` → `burned=true␟export_size=N␟export_sha256=..` (idempotent; Evidence-ID nur Korrelation, Helper persistiert im Ledger)
  - `CELL_EXPORT_READ uuid=..␟generation=..` → FD + Metadaten; `CELL_HEALTH` → `state=..␟active_cells=N␟burned_total=N␟last_error=..␟started_at=N␟abi=cell-runtime-v1`
- Limits: ≤16 aktive Zellen (konfigurierbar ≤64), Request ≤8 KiB / Antwort ≤64 KiB, Input ≤8 MiB (Settings-Cap), Export ≤2 MiB, TTL 5..3600 s; keine ungeprüften Pfade/Arrays.
- Fehlercodes (geschlossen): `bad-request`, `bad-mac`, `stale`, `replay`, `unknown-command`, `capability-missing`, `profile-unknown`, `profile-invalid`, `input-invalid`, `input-missing`, `sandbox-unavailable`, `cell-limit`, `unknown-cell`, `stale-generation`, `export-missing`, `export-overflow`, `burn-failed`, `internal`.

## 4. Sandbox-Vertrag (Helper-Kind)

Profil (`/etc/vgt/gedefense/parser-profiles.conf`, root-owned; package-managed; **kein TOML-Crate**): einfaches, zeilenbasiertes INI (`#`-Kommentare, `[profile <id>]`-Blöcke, `key=value`, Werte ohne Leerraum/NUL; bounded ≤256 KiB, ≤64 Profile, ≤32 argv-Einträge):
```
# /etc/vgt/gedefense/parser-profiles.conf  (root:root 0640, package-managed)
[profile pdf-viewer]
binary=/usr/bin/pdftoppm
sha256=<64-hex sha256 der Binary>
argv0=/usr/bin/pdftoppm
argv1={input}
argv2=/tmp/cell/out/
env_allow=LANG,LC_ALL,TZ
wayland=false
pipewire=false
max_input_bytes=8388608
max_export_bytes=2097152
ttl_max_seconds=300
```
Helper validiert beim Start: Datei root-owned 0640, kein Symlink; alle Binaries absolute, root-owned, non-symlink Pfade mit passendem SHA-256; `{input}`/Export-Slots nur als Platzhalter; **keine** vom Client beeinflussbaren Pfade/argv/env außer Input-/Export-Slots.
Spawn (Kind nach `clone3`/`fork`):
1. **Namespaces:** `CLONE_NEWNS|NEWPID|NEWIPC|NEWUTS|NEWNET` (User-Namespace optional Phase 2; Host ist root, kein unprivileged-userns nötig). PID-1 im neuen PID-Namespace ist ein Reaper-Prozess (Zombie-frei); `PR_SET_PDEATHSIG=SIGKILL` für das Kind falls Helper stirbt.
2. **Mount-Namespace:** `mount("", "/", MS_REC|MS_PRIVATE)`; tmpfs als neue Wurzel; Verzeichnisse `/tmp` (tmpfs 0700, `nodev,nosuid,noexec`), `/home/parser` (tmpfs 0700, kein Host-Home), `/run` (tmpfs), `/dev` minimal (bind `/dev/null`, `/dev/zero`, `/dev/urandom` `nodev`), `/proc` (nur bei benötigtem PID-Namespace, `hidepid=2`); Input-Datei **read-only** eingebunden (`MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC`, `MS_BIND`), Export-Ziel nur als **vorgeöffneter FD** (kein Schreibpfad im FS); Display: Wayland-Socket nur wenn Profil `wayland=true` (bind ro, `XDG_RUNTIME_DIR` gesetzt), **X11 wird verweigert** (`display-unavailable`, kein Keylogging-Risiko); `pivot_root`/`chroot` in neue Wurzel, `chdir("/")`.
3. **Credentials:** `setgroups([])`, `setgid`/`setuid` auf konfigurierte unprivilegierte UID/GID (Default `nobody` 65534; bei Wayland-Profil die Session-UID aus Allowlist), `prctl(PR_SET_NO_NEW_PRIVS,1)`, Capability-Bounding-Set/Ambient leeren (`capset` 0), rlimits (NOFILE 64, NPROC 64, CORE 0, FSIZE = max_export_bytes, CPU = TTL+5 s, AS = max_rss). `umask(077)`.
4. **Seccomp-BPF** (installiert vor `execve`): deny `ptrace`, `process_vm_readv/writev`, `bpf`, `perf_event_open`, `userfaultfd`, `io_uring_setup/enter/register`, `mount/umount2/pivot_root/chroot/unshare/setns/clone/clone3/fork/vfork`, `keyctl/add_key/request_key`, `kexec_*`, `init_module/finit_module/delete_module`, `open_by_handle_at`, `name_to_handle_at`, `socket` mit Familie ∉ {AF_UNIX}, `socketpair` nur AF_UNIX, `connect/bind` nur AF_UNIX; `execve` nur erlaubt für den gepinnten Parser (Filter auf Pointer ist nicht möglich ⇒ `execve` generell erlauben, aber FS-Wurzel enthält nur Parser+Libs; **kein** `/bin/sh`, kein Host-Pfad erreichbar; zusätzlich `no_new_privs`, keine Setuid-Binaries); Rückgabe `EPERM`/`ENOSYS` (Architektur x86_64; andere Arch ⇒ refuse).
5. **Cgroup v2:** Helper erzeugt `/sys/fs/cgroup/vgt-cells/parser-<uuid>` (root), setzt `memory.max`, `pids.max`, `cpu.max`, schreibt Kind-PID in `cgroup.procs`; Burn = `cgroup.kill` (Kernel ≥5.14) + warten + `rmdir`; Freeze = `cgroup.freeze=1` + Verify; Orphan-Sweep beim Start (`parser-*` cgroups ohne Helper-State ⇒ kill+rmdir+Evidence-Ledger-Eintrag). Rechte: Helper ist root; Control schreibt **nicht** in cgroups (Status nur über Helper).
6. **TTL:** Timerfd im Helper pro Zelle (monotonic), Deadline = `min(ttl, profil.ttl_max)`; Ablauf ⇒ Evidence wird vom Go-Control vorab eingefordert? Reihenfolge: Helper markiert `expiring` und gibt Go-Control ein Zeitfenster? Einfacher: Helper burn bei TTL selbst, schreibt Burn-Ledger-Eintrag mit vorhandenen Export-Metadaten; Go-Control committet Evidence beim nächsten Poll und meldet fehlende Evidence als Incident. Zusätzlich Go-Control-Timer, der vor Ablauf `CELL_BURN` mit Evidence-ID aufruft (best effort). Helper-Timer bleibt autoritativ (auch bei Control-Ausfall).
7. **Export:** Helper öffnet Ziel-Datei in `/var/lib/vgt/gedefense/parser-exports/<uuid>/export.bin` (`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`, 0640 root:gedefense) und reicht den FD als **einzigen** Schreibkanal an das Kind; Größe wird über `fstat` überwacht (Überschreitung ⇒ Kill/Burn, `export-overflow`-Event); beim Burn: `fsync`, `F_SEAL_WRITE|GROW|SHRINK` auf O_PATH-FD? (Sealing nur auf memfd/tmpfs möglich) — alternativ Datei nach Burn unveränderlich machen (`chattr +i` nicht nötig: Helper schließt FD, kopiert nach sealed memfd für `CELL_EXPORT_READ`). Metadaten `{size,sha256,burn_id}` im Ledger. Go liest memfd bounded, scannt über bestehenden Airlock/Malware-Scan (untrusted!), importiert in Quarantäne/Evidence; **nie rendern/ausführen**.
8. **Input:** Go schreibt das zu öffnende Dokument begrenzt (≤8 MiB) unter `/var/lib/vgt/gedefense/parser-inputs/<token>.bin` (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0640 gedefense:gedefense, sha256), übergibt `input_token+sha256+size`; Helper öffnet ausschließlich `<staging>/<token>.bin` (`O_NOFOLLOW`, `fstat` regular, owner/mode-Check, size/hash-Check), bindet read-only in die Zelle, löscht die Staging-Datei **erst nach** Burn (Evidence).
9. **Helper-Prozess-Hygiene:** eigener Seccomp-Filter (nur benötigte Syscalls), `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `RestrictAddressFamilies=AF_UNIX`, `RestrictNamespaces` **gezielt** für die benötigten ns-Typen erlaubt (Unit: `RestrictNamespaces=mnt pid ipc uts net` als Allowlist — die `~`-Schreibweise der Skizze würde die benötigten Typen verbieten, s. §12.8), `CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_KILL CAP_SYS_RESOURCE CAP_CHOWN` (**CAP_CHOWN zwingend**, das Kind setzt tmpfs-/Verzeichnis-Owner), `ReadWritePaths` nur cgroup-vgt-cells, parser-inputs, parser-exports, Ledger und `/run/vgt-gedefense`; `parser-imports` ist **Control-owned** und bewusst nicht im Helper-ReadWritePaths. Kein Netz (`IPAddressDeny=any`), kein Shell-/Command-Primitive außer `execve` auf gepinnte Parser. Der Helper prüft die benötigten Capabilities beim Start/`--check` (fehlendes CAP ⇒ `sandbox-unavailable`, kein Create).

## 5. Host-Kernel-Schichten (Status pro Zelle, keine pauschale Behauptung)

- **L1 Sandbox** (Helper): netns/mountns/pidns/ipcns/uts + tmpfs + seccomp + caps/nnp + cgroup = eigentliche Isolation.
- **L2 Cell-LSM** (bestehend, P1-Aktivierung): `CELL_LSM_DENY_NON_UNIX_SOCKET` für Zell-Cgroup — nur wenn `bpf` in `/sys/kernel/security/lsm`; sonst Status `cell-lsm-unavailable` (kein Claim).
- **L3 StyX-Egress** (P3): `STYX_MODE_SET(cgroup, enforce, flags=0)` + keine Allow-Ziele ⇒ Host-Egress-Default-Deny (Loopback-exempt, deshalb L1-netns nötig). Nur wenn StyX-Settings aktiviert; sonst Status `styx-unavailable`.
- **L4 Titan-Exec** (P1): STRICT-Scope für Zell-Cgroup nur bei aktivem bpf-LSM; sonst `titan-exec-unavailable`.
- Admission-Gate: Eine Zelle wird nur als `isolated`/`ready` markiert, wenn L1 attestiert **und** die per Settings geforderten Host-Layer `applied` sind; fehlende Layer ⇒ Zelle bleibt `degraded`/`refused`, Parser-Start wird nicht behauptet.
- Credentials/Cgroup-ID: `cgroup_id` = kernfs-Inode des Helfer-Cgroups (real); UUID/gen vom Helper; Go verifiziert per LIST.

## 6. Go-Control (ParserCellManager)

Neue Dateien (≤500 Z./Datei): `parser_cells_settings.go` (Settings-Namespace), `parser_cells_client.go` (VGTGC2-Client/Parse/Validation), `parser_cells_manager.go` (State-Machine/Admission/TTL/Burn/Evidence), `parser_cells_api.go` (HTTP), `parser_cells_kernel.go` (StyX/Titan/LSM-Policy-Anbindung), Tests.
- Settings v15 Namespace `parser_cells` (Pointer-Muster): `Enabled=false`, `Profiles []string` (Allowlist aus Helper-Capabilities, Default leer ⇒ alle Helper-Profile), `TTLSeconds=120`, `MaxConcurrent=4`, `MaxInputBytes=8MiB`, `MaxExportBytes=2MiB`, `BurnOnIncident=true`, `IncidentScore=80`, `CooldownSeconds=300`, `RequireHostLayers bool` (Default false: L1 genügt; true: L2/L3/L4 müssen applied sein). Validierung reject-not-repair, Caps, Migration v14→v15.
- `ParserCellManager`: Capability-Negotiation (`CELL_CAPABILITIES`), Admission (Create nur wenn enabled+capability+sandbox=true+Profile erlaubt+Input validiert+Evidence-Gate offen? Create erfordert noch keine Evidence, aber Burn/Incident schon), Lifecycle-State-Machine `requested→spawned→isolated→expiring→burning→burned|failed`, TTL vor Ablauf mit Evidence-Commit (`RecordEvidence` kind `cells.parser.burn.intent`), Incident-Dispatch (`CellGuard` ruft bei Profil `parser-ephemeral` statt Freeze/Revoke den Manager-Burn), Kernel-Policies setzen/entfernen (L2/L3/L4) und Verify; Export-Poll/Import (bounded, untrusted, Airlock/Malware-Scan, Quarantäne/Evidence).
- API (alle `s.auth`, POST mit `X-VGT-Request-ID`+Evidence-Gate, strict JSON, bounded): `GET /api/v1/parser-cells/status`, `GET /api/v1/parser-cells` (bounded Liste), `POST /api/v1/parser-cells/open` (input als base64 bounded oder multipart? **Phase 1: base64, decoded ≤8 MiB**; `POST /api/v1/parser-cells/inputs` mit base64 → Token, dann `POST /open {profile,input_token,sha256,size}`; **die Parser-Input-Route hat ein eigenes, dokumentiertes Body-Limit (12 MiB base64-kodiert)** zusätzlich zum globalen 1-MiB-Mutationslimit, mit Auth/Replay/Evidence-Gate und harter Größenprüfung im Handler), `POST /api/v1/parser-cells/{uuid}/burn` (Confirm `BURN <uuid>`), `POST /api/v1/parser-cells/{uuid}/freeze|unfreeze`, `GET /api/v1/parser-cells/{uuid}/export` (metadaten/optional Download als Evidence? Download nur Operator-Rolle/limit, Content-Disposition, no rendering). Settings-Routen bestehen.
- XDR/Evidence: Create/Burn/Refusal/Overflow/Helper-Fehler ⇒ Events/Evidence; kein stilles OK; Helper-Crash ⇒ `degraded` + Incident, Zellen gelten als beendet (PDEATHSIG), Ledger-Reconcile.
- CellGuard: `parser-ephemeral`-Profil-Erkennung (Zelle aus Manager) ⇒ `Burn` statt `Freeze`; bestehende Cooldown/Score-Logik; kein Umbau der TransactionEngine-Signaturen.
- Fail-safe: enabled=false ⇒ keine Requests, keine Events, Helper wird nicht kontaktiert; Helper fehlt ⇒ `capability-missing`, API 503 mit Code; keine Zell-Erzeugung ohne Attest.

## 7. Packaging / Deployment

- Neuer Workspace-Member `rust/gedefense-cell-helper` (Binary `gedefense-cell-helper`), Installationsziel `libexec/gedefense-cell-helper`; neue Unit `packaging/systemd/gedefense-cell-helper.service` (root, Sandbox s. §4.9, `Restart=on-failure`, `StartLimit`, `ExecStart=… --socket=… --key-file=… --profiles=… --staging-inputs=… --staging-exports=… --ledger=… --cgroup-root=…`, `RuntimeDirectory`/`StateDirectory`; **kein** `--staging-imports`: der Helper liest/schreibt keine Imports, s. §12.17); Key-Provisionierung via `gedefense-provision.service`/tmpfiles (`cell-helper.key` 0640 root:gedefense, 32 Byte, nur wenn fehlt); Verzeichnisse `parser-inputs` 0730 **gedefense:gedefense** (Helper-Staging-Kontrakt: Owner = Control-UID, keine World-Bits; T5-Präzisierung §12.7), `parser-exports` 0750 **root:gedefense** (nur Helper schreibt Originale), `parser-imports` 0750 **gedefense:gedefense** (Control schreibt die aus dem memfd importierte, untrusted Kopie), Ledger 0640 root:gedefense; tmpfiles-Einträge; Installer (oneclick/source/PKGBUILD/AstraeaOS) um Binary/Unit/Profile-Default zu erweitern; Release-Gate/Hashliste; `security-audit.sh` neue Anker (Helper existiert, execve nur im Helper, seccomp/ns-Code-Anker, keine Shell in control/core, Unit-Sandbox-Direktiven) — bestehende Anker unverändert.
- Profile-Datei: Default mit **leerer Profilliste** (kein Parser installiert) ⇒ Helper startet, `CELL_CAPABILITIES.profiles=[]`, Create ⇒ `ERR profile-unknown`; Operator/Paket liefert Profile. Keine erfundenen Parser-Profile.
- Aktivierung: Deploy → Helper-Hash/Unit prüfen → Key/Verzeichnisse → Settings `enabled=true`, `ttl_seconds` klein testen → Monitor/Status → produktiv. Ohne Helper: Status `runtime-unavailable`, keine Attrappe.
- Core/Control-Deployment-Drift: neuer Deployment-Gate-Check (Hashe von core/control/ebpf/helper vs. Release-Manifest; LSM-Liste) im Installer/Updater, damit gemischte Stände (heute: alter Core + neues eBPF) erkannt werden.

## 8. Fail-Safe/Boot-/Recovery-Vertrag

| Situation | Verhalten | Status |
|---|---|---|
| Helper nicht installiert/nicht aktiv | keine Zellen, keine Spawn-Behauptung | `parser_cells=runtime-unavailable`, Create 503 |
| Helper-Capabilities: sandbox=false | Create verweigert | `capability-missing` |
| Kein bpf-LSM | L2/L4 unavailable, L1/L3 wie konfiguriert | Zelle `isolated` nur bei erfüllten Required-Layern |
| StyX disabled | L3 unavailable | wie oben |
| Helper-Crash | PDEATHSIG tötet Zellen, Orphan-Sweep beim Neustart, Ledger | `degraded`+Incident, Zellen weg |
| TTL-Ablauf/Incident | Evidence-Intent zuerst (Go), dann Burn; Helper-Timer autoritativ | `burned`, Evidence/Export erhalten |
| Export-Overflow | Kill/Burn, Event | `failed`+Evidence |
| Evidence-Ledger down | Burn/Freeze laufen weiter (Capability-Removal), **lautes** critical Event; Create verweigert | `degraded` |
| Core/Control-Restart | Helper bleibt autoritativ, Go reconciled per LIST/Ledger | Status neu aufgebaut |
| Upgrade Settings v14→v15 | Defaults merged, Migrationsnotiz | – |

Kein Boot-Lockout: Helper-Unit `Required=false` (kein Boot-Dependency), Default off, Helper-Ausfall beeinträchtigt Kernsystem nicht.

## 9. Testplan (verbindlich)

1. **Rust Helper-Unit:** Profil-Validierung (root-owned, Hash, absolute Pfade, Symlink-Reject), Input-Token-Validierung (`O_NOFOLLOW`, `..`, prefix, size/hash), Export-Grenzen, Seccomp-Programmbau (deterministisch, Arch x86_64), cgroup-/Burn-Ledger-Logik, TTL-Timer (Fake-Clock/Monotonic), Protocol-Auth (MAC/Nonce/Timestamp/Replay/Peer-UID, bounded), Fehlercodes; `cargo +1.97.1 test --offline --locked -p gedefense-cell-helper`.
2. **Root-gated Linux-Integration (WSL, sudo; SKIP wenn Capability fehlt):** Test-Profil mit harmlosem Binary (`/bin/true`/`/bin/sleep`) → Create: cgroup existiert, PID in Namespace, `/proc/<pid>/net` leer/lo down, Host-`/home`/`~/.ssh` im Mount-Ns nicht sichtbar, `/etc/shadow` ENOENT, `AF_INET`-Socket ⇒ EPERM/ENETDOWN, AF_UNIX nicht gebundener Pfad ⇒ ENOENT, `ptrace`/`bpf`/`io_uring` ⇒ EPERM, Export > Limit ⇒ Kill/Event, TTL ⇒ Burn innerhalb Toleranz, cgroup killt alle PIDs, doppeltes Burn idempotent, Helper-SIGKILL ⇒ Kind tot + Sweep, Ledger-Einträge.
3. **Go:** Settings/Migration/Caps/Inert-Reject; Client-Parser (gültig + hostile: oversized, unknown fields, bad hex, paths, replay, wrong MAC, ERR); Manager-State-Machine/Admission/TTL/Incident-Burn (Fake-Helper mit HMAC+SCM_RIGHTS-Fake), Evidence-first-Assertions, Export-Import bounded/untrusted, Kernel-Policy-Anbindung (Fake-Core), API (auth/replay/limits/base64-bounds), Fail-Closed (helper missing ⇒ 503/capability-missing; kein Claim), Default-off-Regression (keine Events/Requests bei disabled).
4. **Gates:** `go test ./...`/`go vet`, Rust workspace tests (common/core/helper), ebpf build unverändert, `security-audit.sh` (neue Helper-Anker, bestehende grün), `node --check`, `install-smoke.sh` ggf. erweitert; neue Dateien ≤500 Z.
5. **Adversarial Reviewer:** Path-Traversal/Symlink-TOCTOU Input/Export, Namespace-Escape-Versuche (die im Sandbox-Test), Seccomp-Lücken, MAC/Replay, TTL-Race, Burn-Race, Incident-Dispatch, Default-off, keine Attrappe bei fehlendem Helper/bpf-LSM, Deployment-Gate.

## 10. Datei-Ownership / Phasen

| Task | Owner | Write-Scope | Depends |
|---|---|---|---|
| P2-T1 | Helper-Protocol/Lifecycle-Agent | `rust/gedefense-cell-helper/{Cargo.toml,src/main.rs,src/protocol.rs,src/lifecycle.rs,src/config.rs,src/types.rs,src/export.rs}`, `rust/Cargo.toml` (Member) | Spec |
| P2-T2 | Helper-Sandbox-Agent | `rust/gedefense-cell-helper/src/sandbox.rs`, `src/seccomp.rs` (+Tests in eigenen Modulen) | P2-T1 types |
| P2-T3 | Go-Control-Agent | `control/parser_cells_settings.go`, `parser_cells_client.go`, `parser_cells_manager.go`, `parser_cells_api.go`, `parser_cells_kernel.go`, Tests; additive Edits `runtime_settings.go`, `fabric_settings.go`, `fabric_schema.go`, `server.go`, `xdr.go`, `cell_guard.go`, `main.go`, `config.go` | Spec |
| P2-T4 | Packaging/Docs/Gates-Agent | `packaging/systemd/gedefense-cell-helper.service`, `packaging/tmpfiles/*`, Installer/Build/PKGBUILD/Release-Hashlisten, `scripts/security-audit.sh`, `ARCHITECTURE.md`, `docs/POINT2-PARSER-CELLS.md`, `docs/POINT2-PHASE1-REPORT.md` | T1–T3 |
| P2-T5 | Integration/Adversarial-Verifier | read-only + Root-gated Testskripte (z. B. `scripts/tests/parser_cell_sandbox_test.sh`), Reviewer | T1–T4 |

## 11. Definition of Done (Phase 1)

- Helper real implementiert (ns/tmpfs/seccomp/caps/nnp/cgroup/TTL/Burn/Export), root-gated Integrationstests (soweit Umgebung es zulässt) grün oder als NOT_TESTED mit exakter Begründung dokumentiert.
- Go-Control: Settings v15, Client, Manager, API, Kernel-Policy-/CellGuard-Integration, Fail-Closed; Default off; Upgrade ohne Verhaltensänderung.
- Packaging vollständig (Unit/Verzeichnisse/Key/Profile-Default/Installer/Release-Gate/Audit-Anker); kein Shell-/Exec-Primitive in control/gateway/core/ebpf; nur Helper führt `execve` auf gepinnte Profile aus.
- Adversarialer Review ohne offene FAIL; Restrisiken und Systemd-Anforderungen im Phase-1-Report dokumentiert.

## 12. Umsetzungsabweichungen / Präzisierungen (Phase 1, 2026-11-15)

Die Phase-1-Implementierung hält den Vertrag aus §1–§11 ein, präzisiert aber die
folgenden Punkte dort, wo die Spec-Skizze technisch nicht exakt oder
missverständlich war. Jede Abweichung ist bewusst, getestet und in Unit/Tests
verankert; sie schwächt keine Sicherheitszusage ab.

1. **Protokoll:** VGTGC2 ist wie in §3 ein **Textzeilen-Protokoll** (`0x1f`-Felder,
   base64url-Payload, HMAC-SHA256 über exakt die Wire-Bytes) — **kein JSON**, kein
   serde/toml im Helper (offline-Dependency-Vertrag).
2. **Profile:** Das Profilformat ist das in §4 gezeigte **INI-artige**
   `/etc/vgt/gedefense/parser-profiles.conf` — **kein TOML**. Die Datei ist
   root:root 0640, header-only Default (keine erfundenen Parser); Binaries werden
   über absolute Pfade + SHA-256 gepinnt.
3. **Classic-BPF-Grenze `connect`/`bind`:** Ein Seccomp-BPF-Filter kann den
   `sockaddr`-Pointer von `connect`/`bind` nicht dereferenzieren. Der Helper
   erzwingt deshalb auf zwei Ebenen: `socket`/`socketpair` sind ausschließlich für
   `AF_UNIX` erlaubt (Familie ist Argument 0 und filterbar), damit kann kein
   `AF_INET`-Socket entstehen, den `connect`/`bind` erreichen könnte; zusätzlich
   bleiben `connect`/`bind`-Regeln in der Deny-/Allow-Logik dokumentiert. Eine
   echte Adress-Whitelist ist mit Classic-BPF nicht möglich (Phase-2-Kandidat:
   Landlock/LSM/Cgroup-Connect).
4. **X11:** X11 wird **immer** verweigert (`ErrorCode::display_unavailable` →
   Client-Code `capability-missing`); Wayland/PipeWire-Sockets nur bei
   Profil-Flags `wayland=true`/`pipewire=true` und mit Validierung von
   Owner-UID/Socket-Typ. `DISPLAY`/`XAUTHORITY` stehen auf der Reserved-Env-Liste.
5. **Input-Materialisierung:** Der Helper bindet die Staging-Datei nicht direkt in
   die Zelle, sondern kopiert sie aus einem validierten FD (`O_NOFOLLOW`, fstat,
   owner/mode 0640, nlink=1, size/sha256) über eine 0400-Datei in die private
   tmpfs-Wurzel, chownt sie auf die Zell-UID und remountet sie read-only. Grund:
   `nobody` darf `gedefense:gedefense`-Staging nicht lesen und Host-Pfade sind im
   neuen Mount-Namespace ohnehin nicht erreichbar.
6. **Lib-Bind-Whitelist:** Phase 1 bindet nur den gepinnten Parser-Binary-Pfad
   read-only; dynamische Libraries werden noch nicht als explizite Whitelist
   gebunden (der Parser muss daher statisch/self-contained sein oder die
   Host-Lib-Sichtbarkeit ist Teil des Profil-Reviews). Eine gehashte
   Library-Whitelist ist explizit **Phase 2**.
7. **Staging-/cgroup-Rechte:** `parser-inputs` ist **0730 gedefense:gedefense**
   (T5-Präzisierung: Helper-Staging-Kontrakt ist Owner = Control-UID, keine
   World-Bits; die Gruppe darf benannte 0640-Dateien anlegen, kein Listing). `parser-exports` root:gedefense 0750, Ledger
   `parser-burn-ledger.jsonl` root:gedefense 0640 (Name präzisiert; die Spec-Skizze
   nannte `parser-burns.jsonl`, Go-Control kennt keinen Ledger-Pfad). Der Helper
   läuft als root und ist der **einzige** Schreiber von `/sys/fs/cgroup/vgt-cells`
   (Control schreibt nie in cgroups).
8. **`RestrictNamespaces`:** Die Spec-Schreibweise `~user mnt pid ipc uts net`
   würde unter systemd-Semantik die **benötigten** Namespace-Typen *verbieten*.
   Die Unit nutzt deshalb die Allowlist `RestrictNamespaces=mnt pid ipc uts net`
   (nur diese erlaubt, `user`/`cgroup`/`time` weiterhin verweigert).
9. **`ReadWritePaths`:** Zusätzlich zu cgroup-root/parser-inputs/parser-exports/
   Ledger ist `/run/vgt-gedefense` schreibbar (VGTGC2-Socket + ephemere
   Zell-Wurzelbäume im tmpfs); sonst könnte der Helper seinen eigenen Socket nicht
   binden. `ProtectControlGroups=yes` bleibt bewusst aus (Helper besitzt den
   dedizierten cgroup-Teilbaum), `ProtectSystem=strict` + ReadWritePaths pinnen ihn.
10. **no bpf-LSM ⇒ L2/L4 unavailable:** Ohne `bpf` in `/sys/kernel/security/lsm`
    meldet der Helper `bpf_lsm=inactive`, Go statusiert Cell-LSM/Titan-Exec als
    `unavailable` und eine Zelle wird nur mit den per Settings geforderten
    Host-Layern als `isolated` markiert; L1-Sandbox bleibt davon unabhängig.
    `require_host_layers=true` ohne bpf-LSM ist ein bewusster Operator-Fehler und
    äußert sich als degraded/unavailable — keine Enforcement-Behauptung.
11. **Helper-Unit/Pfade:** Die Unit nutzt den `@RELEASE@`-Platzhalter (Rendering
    durch PKGBUILD/Installer wie `gedefense-access.service.in`) und präzisiert
    Pfade: `--ledger=/var/lib/vgt/gedefense/parser-burn-ledger.jsonl`,
    `--cell-root=/run/vgt-gedefense/cells`, `--max-cells=16`,
    `--peer-uid` bleibt Client-seitig (Go erwartet Server-UID 0). Es gibt keinen
    `Required=`-Boot-Zwang; die Unit ist optional (Default off, §8).
12. **Root-gated Tests:** Privilegierte Integrations-Tests des Helpers
    (Namespaces/mount/seccomp/cgroup/Burn) laufen nur mit root/Capabilities.
    **Final (T5, 2026-11-15):** `sudo -n` ist in der Testumgebung verfügbar —
    non-root-Suite **40 passed/1 ignored**, root-Vollsuite **40 passed/0 failed/
    1 ignored**, root-gated `--ignored` **1 passed** (kein Soft-SKIP, harter Fail
    bei fehlender Umgebung); root-`--check` gegen `/sys/fs/cgroup` **Exit 0**
    (`caps=6/6`), Default-`vgt-cells` in WSL **`cgroup-root-missing`**
    (Umgebungs-NOT_TESTED). Non-root-`--check` fail-closed (`Exit 1`,
    `sandbox-unavailable`). Details: `docs/POINT2-PHASE1-REPORT.md` §4.
13. **Deployment-Drift (Server vs. Repo):** Auf dem Zielserver ist Phase 1 **nicht
    installiert** (kein Helper-Binary, keine Unit, keine Settings-Aktivierung);
    der Repo-Stand ist die Quelle. Der neue Deployment-/Installed-Host-Gate prüft
    deshalb, ob installierte core/control/eBPF/helper-Bytes zum signierten
    Release-Manifest passen, und warnt, wenn `bpf` in der LSM-Liste fehlt, obwohl
    P1/P2-LSM-Features aktiviert sind. Ein fehlendes Manifest ist NOT_TESTED, kein
    stilles PASS.
14. **Release/Manifest:** `gedefense-cell-helper` ist ein reguläres signiertes
    Release-Artefakt (Hash in `release-manifest.signed.json`, SBOM/Provenance,
    Release-Index, Prebuilt-Installer-Header). Der Go-Manifest-Verifier bleibt
    abwärtskompatibel (Pflichtliste unverändert, zusätzliche Artefakte erlaubt).
15. **Settings-Version:** Die Settings-Schema-Version steigt auf **v15**
    (`parser_cells`-Namespace, Migration v14→v15); der bisherige P1-Audit-Anker
    auf v14 wurde auf „≥ v15" erweitert (kein Abschwächen: v14-Dokumente werden
    weiterhin migriert, der titan_exec-Migrationsanker bleibt bestehen).

### 12.16–12.22 T5-Review-Befunde (2026-11-15) und Behebungsstand

16. **Unit-/Capability-Defekt (behoben, Packaging):** Die Helper-Unit fehlte
    `CAP_CHOWN`, obwohl die Sandbox tmpfs-Input-Kopie und Export-Ziel auf die
    Zell-UID chownt (sonst `EPERM`/Create-Fail). Unit + Asserts/Report nutzen jetzt
    `CapabilityBoundingSet/AmbientCapabilities=CAP_SYS_ADMIN CAP_SETUID CAP_SETGID
    CAP_KILL CAP_SYS_RESOURCE CAP_CHOWN`. Der Helper prüft die benötigten
    Capabilities beim Start/`--check` (P2-T1-Fix; fehlendes CAP ⇒
    `sandbox-unavailable`, kein Create).
17. **Export-Import-Design (behoben):** Control schreibt **nicht** nach
    `parser-exports` (0750 root:gedefense, Helper-Originale). Die untrusted
    Import-Kopie liegt in `/var/lib/vgt/gedefense/parser-imports` (0750
    gedefense:gedefense, tmpfiles/Provision/Installer); der Helper schreibt dort
    nie. Bootstrap/Config präzisiert: `[parser_cells] imports_dir` (Default
    `/var/lib/vgt/gedefense/parser-imports`, absolute Pfadvalidierung; das frühere
    `export_dir`-Feld entfällt). Fluss: Helper liefert sealed memfd via
    `SCM_RIGHTS` → Control liest bounded → durable Write (`O_EXCL`/`fsync` +
    Read-back) nach `parser-imports` → Evidence-Commit; „stored"** nur** bei
    Erfolg, sonst `markExportFailed` ohne Claim. Status/Download bounded aus
    `parser-imports` (untrusted, Content-Disposition, no-render). Der API-Import
    ist bounded (max_export_bytes) und wird über den bestehenden
    Airlock/Malware-Pfad geführt.
18. **Adopt-Reassert nach Control-Restart (behoben):** Beim Reconcile/Adopt
    vorhandener Zellen werden L2/L3/L4-Scopes **erneut appliziert** (LSM-Policy,
    StyX-Mode, Titan-Scope; `parser_cells_kernel.Reassert`); gelingt das nicht,
    wird die Zelle/Zellebene `degraded`/`unavailable` statt stillschweigend als
    isoliert geführt.
19. **API-Body-Limit (behoben):** Die Parser-Cell-Input-Route nutzt ein eigenes,
    routen-scoped Body-Limit von **12 MiB base64** (decoded ≤ 8 MiB,
    Settings-Cap); `open`/`burn` behalten ihre kleinen Limits (8 KiB/4 KiB).
    Das globale 1-MiB-Request-Limit der übrigen Routen bleibt unverändert (kein
    globales Aufweichen).
20. **Wayland-Phasengrenze:** Phase 1 unterstützt **kein Wayland**; die Unit/der
    Helper laufen ohne Display-Capability (`CELL_CAPABILITIES`/Status melden
    `wayland=false`, Kind läuft als UID 65534 `nobody`). `[parser_cells]
    wayland_profiles` ist eine package-managed Liste (Default leer, absolute
    Profil-IDs); ein darin genanntes Profil mit Wayland-Anforderung wird
    fail-closed mit `capability-missing` abgelehnt (kein stiller Fallback auf
    X11/Host-Display). Wayland/PipeWire für Session-UIDs ist Phase 2
    (Session-UID-Allowlist + Socket-Validierung).
21. **T5-Root-Evidenz + behobener Helper-Befund:** `sudo -n` ist verfügbar; die
    root-gated Tests wurden real ausgeführt. Dabei fiel im Helper
    `sandbox_available()`/`--check` ein **Root-cgroup-Pfadfehler** auf
    (`/sys/fs/cgroup/cgroup.kill` existiert kernel-seitig nie; `cgroup.kill` ist
    `CFTYPE_NOT_ON_ROOT`) → Capabilities meldeten `sandbox=false`. **Behoben
    (P2-T1):** `probe_cgroup_root()` legt ein Throwaway-Kind unter dem
    CLI-`--cgroup-root` an, prüft dort `cgroup.kill`/`cgroup.freeze`/`cgroup.procs`
    und entfernt es; `CGROUP_PROBE_OK` gated `CELL_CAPABILITIES.sandbox`; Codes
    `cgroup-root-missing`/`cgroup-unavailable` sind Operator-Diagnose (nicht im
    VGTGC2-Wire-Set). Zusätzlich Capability-Selbstcheck (`caps=6/6` aus
    `/proc/self/status`). **Root-Evidenz (selbst reproduziert):** non-root
    Root-Suite 40 passed/0 failed/**1 ignored**; root-Vollsuite (ohne
    `--include-ignored`) 40 passed/0 failed/1 ignored; root-gated **`--ignored`
    → 1 passed** (kein Soft-SKIP; `env_ready`-Vorprüfung + harter Fail); Root-`--check`
    mit `--cgroup-root /sys/fs/cgroup` → **Exit 0** `caps=6/6 cgroup2=ok
    namespaces=ok bpf_lsm=inactive`; Default-`--cgroup-root
    /sys/fs/cgroup/vgt-cells` ist in WSL nicht vorhanden ⇒ **Exit 1
    `cgroup-root-missing`** (umgebungsbedingt NOT_TESTED, kein stilles OK);
    non-root `--check` weiter fail-closed (`sandbox-unavailable`). Weitere
    T5-Fixes (P2-T3: Import-Senke, Adopt-Reassert, 12-MiB-Routenlimit,
    Wayland-Capability) sind umgesetzt und in `docs/POINT2-PHASE1-REPORT.md`
    §4/§5 belegt.
22. **Import-UMask-Lücke (T5-Nachprüfung, behoben):** `parserCellStoreImport`
    öffnete die Import-Kopie zwar mit Mode `0640`, aber die Produktions-Unit läuft
    mit `UMask=0077` → die Datei entstand als **0600**, der Read-back
    (Mode/Size/Owner) scheiterte und der Import war funktional tot („stored" wurde
    nie behauptet, aber die Import-/Download-Kette war unbenutzbar). **Fix P2-T3
    (2026-11-15):** explizites `file.Chmod(0o640)` nach dem
    `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`-Open **vor** `fsync` und Read-back
    (umask-unabhängig), plus Regressionstest
    `TestParserCellsExportImportIsDurableAndDownloadable` unter
    `syscall.Umask(0o077)` (Import + Download bounded, „stored" erst nach
    durable Write + Evidence). Die frühere Formulierung „Export-Import behoben"
    (Punkt 17) war damit zu optimistisch; korrekt ist: behoben **inkl.**
    UMask-Nachfix, belegt durch gezielten Test (Exit 0).
