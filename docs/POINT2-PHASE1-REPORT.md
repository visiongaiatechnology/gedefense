# POINT 2 — Phase-1-Report: Ephemere Parser-Zellen („parser-ephemeral")

**Stand:** 2026-11-15 · **Release:** GeDefense V6 (`6.0.0`) · **Status:** Phase 1 implementiert, Default **off**, **T5-Review-Fixes eingearbeitet und Gate-verifiziert** (voller Gate-Lauf + root-gated Tests; der letzte Import-UMask-Mikro-Fix wurde gezielt per Test verifiziert, s. §4.10; Phase-1-Validierung)
**Verbindliche Spezifikation:** `docs/POINT2-PARSER-CELLS.md` (§12 = Umsetzungsabweichungen/Präzisierungen, §12.16–§12.21 = T5-Befunde/Fixes)
**Nächster Schritt:** Blueprint-Punkt 5. Kein Commit/Push/Tag/Release, kein Deploy, kein Netz.

## 1. Scope & Ergebnis

BluePrint-Punkt 2 („ephemere Parser-Zellen", Qubes-light) ist als **Phase 1**
umgesetzt: ein neuer privilegierter Rust-Helper besitzt ausschließlich ephemere
Parser-Zellen (Namespaces/tmpfs/seccomp/Caps/Cgroup/TTL/Burn/Export-Broker), Go-Control
orchestriert unprivilegiert über das authentisierte VGTGC2-Protokoll. Nach Upgrade
bleibt alles **inert** (`parser_cells.enabled=false`, Settings-Schema v15 mit
Migration v14→v15). Fehlt der Helper oder eine Sandbox-Fähigkeit, wird
`runtime-unavailable`/`capability-missing` gemeldet und `CELL_CREATE` verweigert –
es gibt keine Attrappe und keine Isolations-Behauptung ohne L1-Attestation.

## 2. Architektur (Kurz)

- **Helper** `gedefense-cell-helper` (root, eigene Unit): VGTGC2-Unix-Socket
  (0660 root:gedefense, HMAC-SHA256, SO_PEERCRED beidseitig, ±30 s, Replay-Cache,
  Größen-/Feldgrenzen), Zell-Spawn mit `CLONE_NEWNS|NEWPID|NEWIPC|NEWUTS|NEWNET`,
  privater Mount-Baum/tmpfs, read-only Input, minimales `/dev`, `/proc hidepid=2`,
  `nobody`-Credentials, Cap-Drop, rlimits, `no_new_privs`, Classic-Seccomp (nur
  AF_UNIX-Sockets, X11 verweigert), `execve` nur auf den SHA-256-gepinnten
  Profil-Binarypfad; Cgroup `parser-<uuid>` (memory/pids/cpu.max, freeze/kill),
  TTL-Timer, Orphan-Sweep, append-only Burn-Ledger, Export als sealed memfd via
  `SCM_RIGHTS`.
- **Go-Control:** Settings-Namespace `parser_cells` (v15, Default disabled),
  VGTGC2-Client, ParserCellManager (Admission, State-Machine, TTL mit
  Evidence-first-Burn-Intent, Incident-Burn statt Freeze für `parser-ephemeral`,
  bounded/untrusted Export-Import), API-Routen (auth + `X-VGT-Request-ID` +
  Evidence-Gate + strict JSON + Confirm `BURN <uuid>`; Input-Route mit eigenem
  12-MiB-base64-Body-Limit, decoded ≤ 8 MiB), Kernel-Layer-Anbindung (L2 Cell-LSM,
  L3 StyX-Scope, L4 Titan-Exec-Scope; nur mit aktivem bpf-LSM) inkl.
  **Adopt-Reassert** nach Control-Restart. Bootstrap/Config: `[parser_cells]
  imports_dir` (Default `/var/lib/vgt/gedefense/parser-imports`), `wayland_profiles`
  (Phase 1 Default leer/fail-closed), `export_dir` entfällt — Control schreibt
  untrusted Importe ausschließlich nach `parser-imports`, nie nach `parser-exports`.
- **Kernel-Schichten:** L1 = Helper-Sandbox (eigentliche Isolation), L2/L4 nur mit
  `bpf` in `/sys/kernel/security/lsm`, L3 nur bei aktiviertem StyX; Status pro
  Layer, `require_host_layers` erzwingt L2–L4 für `isolated`. Zielserver: Phase 1
  **nicht installiert**, bpf-LSM inaktiv (P1-Befund) ⇒ L2/L4 `unavailable`.

## 3. Datei-Inventar (neu/geändert, Auszug)

**Rust Helper (neu):** `rust/gedefense-cell-helper/Cargo.toml`, `src/{main,types,protocol,config,export,lifecycle,sandbox,seccomp}.rs`; Workspace-Member in `rust/Cargo.toml`/`Cargo.lock`.

**Go-Control (neu):** `control/parser_cells_{settings,client,client_codec,client_payload,manager,manager_ops,supervision,api,kernel}.go` + zugehörige `*_test.go`.
**Go-Control (additiv geändert):** `runtime_settings.go`, `fabric_settings.go`, `fabric_schema.go`, `server.go`, `xdr.go`, `cell_guard.go`, `main.go`, `config.go` (`imports_dir`, `wayland_profiles`, `export_dir` entfernt), `state.go`, `security_fuzz_test.go`.

**Packaging (neu/erweitert):** `packaging/systemd/gedefense-cell-helper.service`, `packaging/templates/parser-profiles.conf` (header-only Default), `packaging/tmpfiles/vgt-gedefense.conf`, `packaging/systemd/gedefense-provision.service`, `packaging/scripts/gedefense-provision`, `packaging/pacman/gedefense-provision.hook`, `packaging/arch/PKGBUILD`, `Makefile` (`rust-helper`), `scripts/package-artifacts.sh`, `scripts/render-installer-header.py`, `scripts/oneclick-installer-header.sh`, `scripts/oneclick-source-bootstrap-header.sh`, `integration/astraeaos/{gedefense-astraeaos-provision,gedefense-astraeaos-provision.service,contract.json}`, `integration/linux` (unverändert).

**Gates/Skripte:** `scripts/security-audit.sh` (additive P2-Anker), `scripts/validate-systemd.sh`, `scripts/validate-installed-linux-host.sh` (Manifest-Drift + LSM-Warnung), `packaging/tests/install-smoke.sh`.

**Doku:** `docs/POINT2-PARSER-CELLS.md` (§12), `ARCHITECTURE.md` (§3.25 Drift-Korrektur, §3.36) und dieser Report.

## 4. Test-/Gate-Evidenz (nur selbst ausgeführt, WSL Ubuntu 24.04, 2026-11-15)

> Testumgebung: Linux-x86_64-Sandbox mit unprivilegiertem Build-Nutzer sowie root-Helper-Testlauf.
> (root-Tests wurden real ausgeführt, nicht SKIP), `cargo 1.97.1`, `go 1.27.1`,
> `node v24.13.0`, systemd 255. Die T5-Root-/Gate-Zahlen sind unten final
> dokumentiert.

1. **Rust (non-root):** `cd rust && cargo +1.97.1 test --offline --locked -p gedefense-cell-helper -p gedefense-common -p gedefense-core` → **Exit 0**.
   - `gedefense-cell-helper`: **40 passed, 0 failed, 1 ignored** (root-gated Tests laufen separat als root, s. Punkt 9).
   - `gedefense-common`: **31 passed, 0 failed** + 2 Bin-Tests (1+1 passed).
   - `gedefense-core`: **83 passed, 0 failed** (Regression unverändert).
2. **eBPF-Build unverändert:** `cargo +nightly-2026-07-16 build --locked --manifest-path rust/Cargo.toml -p gedefense-ebpf --release --target bpfel-unknown-none -Z build-std=core` → **Exit 0**; sha256 des neu gebauten Objekts = `dist/gedefense-ebpf` = `a558f6561fe4f49015dd97d2be76088671dacdeeaa2b4495934b792af66d4700` (byte-identisch, keine eBPF-Änderung).
3. **Go:** `cd control && go vet ./...` → **Exit 0** (leere Ausgabe); `go test -count=1 -timeout 1800s ./...` → **Exit 0**, `ok github.com/visiongaiatechnology/gedefense/control 151.189s`, keine `FAIL`-Zeile (T5-Fixstand; der nachgelagerte Import-UMask-Mikro-Fix wurde gezielt getestet, s. §4.10). `node --check control/web/*.js` → **Exit 0** (alle JS-Dateien).
4. **Security-Audit:** `bash scripts/security-audit.sh` → **Exit 0**, letzte Zeile `SECURITY AUDIT PASS`, **27 PASS-Prüfungen** (auch nach dem Import-UMask-Mikro-Fix erneut ausgeführt); bestehende P1/P3/Installer-Anker unverändert grün, P2-Anker inkl. T5-Fixes (CAP_CHOWN, Cap-Selbstcheck, cgroup-Probe am dedizierten Root, parser-imports, Adopt-Reassert, 12-MiB-Routenlimit, Wayland-Capability) vorhanden.
5. **Systemd-Unit-Gate:** `bash scripts/validate-systemd.sh` → **Exit 0**; `gedefense-cell-helper.service` wird gerendert und mit `systemd-analyze verify` im isolierten Root geprüft; Helper-Unit-Direktiven (Cap-Set inkl. CAP_CHOWN, ReadWritePaths, Namespace-Allowlist, IPAddressDeny=any, UMask) werden hart asserted. `NOT_TESTED`: `/bin/sh` im Verify-Root ist ein Harness-Shim (Systemd-Analyze-Pfadauflösung), der produktive `ExecStartPre` wird nicht ausgeführt.
6. **Install-Smoke:** `bash packaging/tests/install-smoke.sh` → **Exit 0**, **64 passed, 0 failed** (finaler T5-Lauf; Staging-Wurzeln inkl. parser-imports, Ledger/Profil/Key, PKGBUILD/Hook/Template-Assertions). NOT_TESTED-Zeilen (6): reales `pacman -U`, systemd-Boot der Units/Livez-HTTP, nspawn/VM-Install, AstraeaOS-Login-Gate, cross-account-Traversal als `gedefense` (root-gated), Helper-`--check` root-gated (root-Smoke separat belegt).
7. **Helper-`--check`-Smoke (non-root Fail-safe):** als uid 1000 → **Exit 1**, `check-failed code=sandbox-unavailable`. Erwartetes Fail-closed-Verhalten (kein PASS für die root-gated Validierung; im Smoke-Test als NOT_TESTED ausgewiesen).
8. **Helper-`--check` (root, real ausgeführt):** gestagte Fixtures (`cell-helper.key` 32 B root:0640, header-only Profil root:0640, `parser-inputs` 0730 owner=65534 via `--peer-uid`, `parser-exports` 0750 root):
   - `sudo -n … --cgroup-root=/sys/fs/cgroup` → **Exit 0**, `check-ok abi=cell-runtime-v1 profiles=0 caps=6/6 cgroup_root=/sys/fs/cgroup cgroup2=ok namespaces=ok bpf_lsm=inactive` (Cap-Selbstcheck + cgroup-kill-Probe am Non-Root-cgroup);
   - Default `--cgroup-root=/sys/fs/cgroup/vgt-cells` in WSL nicht vorhanden → **Exit 1** `cgroup-root-missing detail=…` (**umgebungsbedingt NOT_TESTED**, kein stilles OK; Zielhost: tmpfiles); non-root → **Exit 1** `sandbox-unavailable`.
9. **Root-gated Rust-Tests (real, `sudo -n`):** Root-Vollsuite **Exit 0, 40 passed/0 failed/1 ignored**; root-gated `-- --ignored` **Exit 0, 1 passed** (`sandbox::tests::root_gated_namespace_isolation_and_kill`, kein Soft-SKIP) — eigene mnt/net/pid/ipc/uts-Namespaces, kein Host-`/home`/`/etc/shadow`, read-only Input, nur `lo`, Kill tötet Zelle; non-root 40 passed + 1 ignored. Frühere „NOT_TESTED/SKIP"-Aussage korrigiert; offen bleibt nur **Produktions-Deploy** auf echtem Zielhost.
10. **T5-Nachprüfung Import-Durability unter Produktions-`UMask=0077` (gezielt ausgeführt):**
    `cd control && go test -count=1 -v -run 'TestParserCellsExportImportIsDurableAndDownloadable|TestParserCellsStagingFileModeIsHelperCompatible' ./...` → **Exit 0**, beide Tests **PASS** (`ok … 0.069s`); der Import-Test setzt explizit `syscall.Umask(0o077)` und belegt durable Import + bounded Download („stored“ erst nach Read-back/Evidence). Fix-Anker im Code: `parser_cells_manager_ops.go:447` `file.Chmod(0o640)` nach dem `O_EXCL|O_NOFOLLOW`-Open und **vor** `Sync()`/Read-back. `go vet ./...` danach **Exit 0**. Der vorherige volle Go-Suite-Lauf (151.189 s, Exit 0) stammt vom T5-Fixstand unmittelbar davor; der nachgelagerte UMask-Mikro-Fix wurde gezielt (nicht die komplette Suite) verifiziert.

## 5. T5-Review-Befunde & Behebungsstand (2026-11-15)

- **Unit/Capability (behoben):** `CAP_CHOWN` fehlte in der Helper-Unit, obwohl die
  Sandbox Input-Kopie und Export-Ziel auf die Zell-UID chownt. Unit, Asserts
  (install-smoke/validate-systemd/security-audit) und Spec §4.9/§7 tragen jetzt
  `CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_KILL CAP_SYS_RESOURCE CAP_CHOWN`;
  der Helper prüft die 6 Capabilities beim Start/`--check` selbst (`caps=6/6`,
  fehlendes CAP ⇒ `sandbox-unavailable`).
- **Export-Import-Design (behoben, inkl. T5-Nachfix):** Control schreibt nie nach
  `parser-exports`; neue `parser-imports` 0750 gedefense:gedefense (tmpfiles,
  Provision, Installer, AstraeaOS), Helper-Unit ohne Imports-Schreibpfad.
  „stored“/Download erst nach durable Write (O_EXCL/fsync + Read-back) **und**
  Evidence-Commit; Download bounded aus `parser-imports`.
  **T5-Nachprüfung (2026-11-15):** Der Import war unter Produktions-`UMask=0077`
  funktional tot (Datei 0600 statt 0640 → Read-back scheiterte). P2-T3 fixt per
  explizitem `file.Chmod(0o640)` nach dem `O_EXCL|O_NOFOLLOW`-Open und **vor**
  `fsync`/Read-back (umask-unabhängig) + Regressionstest
  `TestParserCellsExportImportIsDurableAndDownloadable` unter
  `syscall.Umask(0o077)`. Die frühere Formulierung „Export-Import behoben" war zu
  optimistisch; jetzt gilt: behoben inkl. UMask-Nachfix, per gezieltem Test
  belegt (Exit 0, s. §4.10).
- **Adopt-Reassert (behoben, Go):** Reconcile/Adopt re-appliziert L2/L3/L4-Scopes
  (`parser_cells_kernel.Reassert`, Test `TestParserCellsKernelReassertsDynamicScopes`);
  sonst `degraded`/`unavailable` statt stiller Isolations-Behauptung.
- **API-Limit (behoben, Go):** eigener Parser-Input-Body **12 MiB base64**
  (decoded ≤ 8 MiB); globales 1-MiB-Limit bleibt unverändert.
- **Staging-Kontrakt präzisiert (behoben):** `parser-inputs` ist **0730
  gedefense:gedefense** (Owner = Control-UID, keine World-Bits) — Helper-Fix
  `validate_staging_dirs(inputs, exports, control_uid)`; `parser-exports` bleibt
  0750 root:gedefense; `--peer-uid` erlaubt den root-Smoke ohne Dienstkonto.
- **Wayland-Phasengrenze:** Phase 1 `wayland=false` (Kind-UID 65534); Profil mit
  `wayland=true` ⇒ fail-closed `capability-missing` (Helper adverstisiert keine
  Wayland-Capability; Client rendert keine stille X11-Fallback-Behauptung).
- **cgroup.kill-Rootpfad-Blocker (behoben, P2-T1):** `sandbox_available()`/
  `--check` prüften `/sys/fs/cgroup/cgroup.kill` (Root-cgroup; kernel-seitig
  `CFTYPE_NOT_ON_ROOT`). Jetzt wird ein Throwaway-Kind unter dem CLI-`--cgroup-root`
  probiert (`probe_cgroup_root`, rmdir rückstandsfrei; Codes
  `cgroup-root-missing`/`cgroup-unavailable`); `CGROUP_PROBE_OK` gated
  `CELL_CAPABILITIES.sandbox`. Root-`--check` real: **Exit 0** `caps=6/6
  cgroup2=ok namespaces=ok` (s. §4.8), Root-Vollsuite **40 passed/0 failed/
  1 ignored**, root-gated `--ignored` **1 passed** (s. §4.9).

## 6. Betriebs-/Aktivierungs-Runbook (Helper-Installation → Key/Profile → Aktivierung)

1. **Installation:** `make full` (baut u. a. `dist/gedefense-cell-helper`) bzw. `PKGBUILD`-Paket/One-Click-Installer; Helper landet in `libexec/gedefense-cell-helper`, Unit in `/usr/lib/systemd/system/gedefense-cell-helper.service` (`@RELEASE@` → `/opt/vgt/gedefense/current`).
2. **Provisionierung:** `gedefense-provision.service` bzw. Installer erzeugt:
   `cell-helper.key` (32 B, 0640 root:gedefense, nur wenn fehlt),
   `parser-inputs` 0730 gedefense:gedefense (Helper-Staging-Kontrakt: Owner =
   Control-UID, keine World-Bits), `parser-exports` 0750 root:gedefense,
   `parser-imports` 0750 gedefense:gedefense (Control-owned untrusted Import-Kopie),
   `parser-burn-ledger.jsonl` 0640 root:gedefense,
   `/etc/vgt/gedefense/parser-profiles.conf` root:root 0640 (header-only, keine erfundenen Parser).
3. **Unit aktivieren/prüfen:** `systemctl enable --now gedefense-cell-helper.service`; `systemctl status`, `journalctl -u gedefense-cell-helper`, Socket `/run/vgt-gedefense/cell-helper.sock` (0660 root:gedefense). Als root: `gedefense-cell-helper --check` (validiert Key/Profile/Staging/Cgroup; Exit 0 = OK, Exit 1 = fail-closed).
4. **Profile pflegen:** Parser-Binary installieren, `sha256sum` messen, `[profile <id>]`-Block (binary/sha256/argv/env_allow/wayland/pipewire/limits) in `parser-profiles.conf`; `systemctl restart gedefense-cell-helper`; `CELL_CAPABILITIES`/Status zeigt `profiles=[…]`.
5. **Aktivierung (Operator):** zuerst TTL/Concurrency klein testen (`parser_cells.enabled=true`, `ttl_seconds` klein, `require_host_layers=false`), Status/API beobachten; danach produktiv. Für L2/L4: Boot-Cmdline `lsm=<aktuelle Liste>,bpf` + Reboot (separat, nur Operator); ohne bpf-LSM bleibt L2/L4 `unavailable` und die Zelle nur L1-isoliert. L3 erfordert aktiviertes StyX.
6. **Monitoring:** `GET /api/v1/parser-cells/status` (helper/sandbox/bpf_lsm/layer_*), Burn-Ledger, Evidence-Events `cells.parser.*`, XDR-Incidents; Exporte immer untrusted/Quarantäne.
7. **Deaktivieren/Rollback:** `parser_cells.enabled=false` (sofort inert), `systemctl stop gedefense-cell-helper` (Kinder sterben per PDEATHSIG, Orphan-Sweep beim Neustart), Paket-/Installer-Rollback über bestehende Release-Rotation; keine Host-Daten werden gelöscht.

## 7. Restrisiken & Phasengrenzen

- **Root-gated Tests:** `sudo -n` wurde genutzt: Root-Vollsuite **40 passed/0 failed/
  1 ignored**, root-gated `--ignored` **1 passed** (kein Soft-SKIP); Root-`--check`
  mit `/sys/fs/cgroup` **Exit 0** (`caps=6/6`), Default `/sys/fs/cgroup/vgt-cells` in WSL
  **Exit 1 `cgroup-root-missing`** (Umgebungs-NOT_TESTED). Kein **Produktions-Deploy**;
  echter Zielhost-Test (Server, bpf-LSM, cgroup v2/tmpfiles) bleibt Operator-Schritt.
- **Wayland = Phase 2:** Phase 1 erzwingt `wayland=false` (Zell-UID 65534); ein
  Profil mit `wayland=true` wird fail-closed (`capability-missing`) abgelehnt, kein
  stiller X11-/Host-Display-Fallback.
- **cgroup.kill-Umgebung:** Helper benötigt cgroup v2 mit `cgroup.kill` auf einem
  **Kind** des dedizierten cgroup-root (Root-cgroup hat es kernel-seitig nicht);
  fehlt es, lautet der Status ehrlich `sandbox-unavailable`/`cgroup-unavailable`.
- **bpf-LSM auf Zielserver inaktiv** (P1-Befund): L2/L4 bleiben `unavailable`; L1-Sandbox ist davon unabhängig, L3 hängt an StyX. Keine Enforcement-Behauptung ohne bpf.
- **Classic-BPF-Grenzen:** `connect`/`bind`-Adressen nicht filterbar (nur AF_UNIX-Familie erzwungen); Parser-Lib-Bind-Whitelist und User-Namespaces = Phase 2; ebenso Landlock/LSM-Connect.
- **Deployment-Drift:** Phase 1 ist auf dem Server **nicht installiert**; Repo ist Quelle. Neuer Installed-Host-Gate prüft Manifest-Konsistenz und warnt bei bpf-freier LSM-Liste trotz aktivierter P1/P2-Features; ohne deploytes Manifest NOT_TESTED (kein stilles PASS).
- **Trust-Grenze Source-Trust-Modus:** prebuilt-Helper ist hashgebunden/signiert; im Source-Trust-Modus wird der Helper aus dem signierten Quell-Payload gebaut (nicht remote attestiert) – dokumentierte Grenze, identisch zu core/eBPF.
- **Export-/Airlock-Abhängigkeit:** Exporte sind untrusted Evidence; Scan/Quarantäne nutzt bestehende Go-Pfade. Fehler dort ⇒ laut degraded/Incident, kein stiller Import.
- **Keine UI-Panels in Phase 1** (nur Settings-Namespace + read-only Status/API); Dashboard folgt in Phase 2.
- **Export/Import-Senke:** Control schreibt Importe ausschließlich nach
  `parser-imports` (nie nach `parser-exports`); „stored“/Download erst nach durable
  Write + Evidence. **T5-Nachfix:** unter Produktions-`UMask=0077` nur durch
  explizites `Chmod(0640)` vor `fsync`/Read-back umask-unabhängig; Regressionstest
  unter umask 0077 grün (Exit 0, §4.10). Fehler ⇒ laut degraded/Incident.
- **Unit nie real unter systemd gestartet / Race-Fenster:** Die Helper-Unit ist
  statisch (`systemd-analyze verify` im isolierten Root) und per `--check`/Root-Tests
  validiert, lief aber **nicht** als echter systemd-Dienst auf einem installierten
  Host; Reconcile/Reassert und TTL-/Incident-Burn haben ein dokumentiertes
  Konvergenz-/Race-Fenster von bis zu ~15 s (bounded, fail-visible, keine stille
  Isolations-Behauptung). Operator-/Zielhost-Test offen.
- **API-Body-Limits:** Parser-Routen haben ein eigenes 12-MiB-base64-Limit
  (decoded ≤ 8 MiB); das globale 1-MiB-Limit der übrigen Routen bleibt unverändert.
- **Umgebungsabhängigkeiten:** cgroup v2 mit `cgroup.kill` (Kind-Cgroup, nicht
  Root-cgroup), systemd ≥ 240 (tmpfiles `C`), root-Helper; fehlende Fähigkeiten ⇒
  explizit `unavailable`, nie Attrappe.

## 8. Nächster atomarer Schritt

Blueprint-Punkt 5 (nach P1/P2/P3). Operator-seitig separat: Root-gated Sandbox-Test
auf Testhost, danach – falls gewünscht – bpf-LSM-Aktivierung per Boot-Cmdline +
Reboot. Kein GitHub-Push in dieser Sitzung.
