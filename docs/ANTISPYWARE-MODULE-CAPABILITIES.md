# GeDefense Linux V6.3.0 — Funktionsumfang des Anti-Spyware- & Anti-Rootkit-Moduls (AP-0 bis AP-9)

**Stand:** V6.3.0 (`Linux/6.2.1-github`) · **Datenquelle:** `gedefense-ebpf`, `gedefense-core` (static-pie musl), `gedefense-control` (`/api/v1/antispyware/status`), `gedefense-access` (Gateway RBAC)

---

## Überblick: Wogegen das Modul schützt

Das V6.3.0 Anti-Spyware-Paket schließt gezielt die Angriffsvektoren moderner Linux-Spyware, kommerzieller Implantate (z. B. Pegasus-/FinFisher-/Graphite-/Ebury-/Symbiote-/OrBit-/Curing-Klassen) und heimlicher eBPF-/Kernel-Rootkits:

- **`LD_PRELOAD`-/glibc-Hooking** gegen Sicherheitsagenten
- **`comm`/`argv[0]`-Spoofing** und heimlicher Binary-Austausch zum Auslesen von Zugangsdaten
- **eBPF-Rootkits** (`bpf_prog_load`, `bpf_probe_write_user`, versteckte eBPF-Programme/Links)
- **Versteckte Prozesse, Sockets, Raw-Taps, LKMs & Ftrace-Hooks** (8-Domänen Cross-View-Abgleich)
- **Asynchrone Syscall-Umgehung via `io_uring`** (z. B. Curing-Klasse)
- **Persistenz-, Linker-, PAM/SSHD-Manipulation & Desktop-Peripherie-Spionage** (Mikrofon, Kamera, Keylogger, Browser-/SSH-Secrets)
- **Stille Datenexfiltration & DNS-Tunnelling** direkt im Kernel-Paketpfad
- **Gezieltes Blenden/Fluten der Telemetrie** (DoS auf Log-Ringe) oder **Vergiftung von Regel-Feeds**

---

## Die 10 Säulen im Detail (AP-0 bis AP-9)

### 1. `AP-0` — Statischer musl Core & SelfGuard
- **Gemeinsame Aktivierung:** Automatisch mit `gedefense-core`, XDR-Engine, `/sys/fs/bpf/gedefense` und dem Fanotify-Canary-Broker.
- **Was es erkennt:** Manipulation oder Löschen der 23 gepinnten kritischen eBPF-Maps (`CRITICAL_MAPS`, alle <= 5 s verifiziert), fehlgeschlagene synthetische Canary-Self-Tests (~30 s Intervall), fehlendes/nicht beschreibbares `bpffs`, veränderte Daemon-Inodes (`SELF_DAEMON_INODES`) sowie Ring-Buffer-Drops.
- **Technischer Schutz & Aktion:**
  - `gedefense-core` ist als **statisches musl-Binary (`static-pie`)** ohne glibc/`NEEDED`-Abhängigkeiten gebaut — Userland-Rootkits über `/etc/ld.so.preload` / `LD_PRELOAD` (Symbiote/OrBit) laufen gegen den Core ins Leere.
  - Treten Manipulationen auf, erzeugt SelfGuard sofort signierte `XDR.SELF_TAMPER` / `SBC-EVID-08` Events und pusht diese vorab an den externen Witness (`S08`/`S15`).
  - *Hinweis zur Systemd-Härtung:* `gedefense-bpffs.service` legt `/sys/fs/bpf/gedefense` explizit an, sodass alle Pins auch unter `systemd 255` (`ProtectKernelTunables=true`) schreib- und prüfbar bleiben.

### 2. `AP-1` — BTF `exec_inode` Trust & `CredentialGuard`
- **Gemeinsame Aktivierung:** Mit `CredentialGuard`, XDR-Enforce, `TRUSTED_EXEC_INODES`, `MALWARE_DENIED_INODES` und dem `PermitV1`-Broker.
- **Was es erkennt:**
  - Lese-/Öffnungsversuche auf System-Secrets (`/etc/shadow`, SSH-Private-Keys, API-Tokens etc.) durch Prozesse, deren echtes Binary (Kernel-BTF-aufgelöst über `task_struct -> mm -> exe_file -> f_inode`: `(dev, ino)` + `ctime`) nicht auf der gepinnten Allowlist steht — immun gegen `prctl(PR_SET_NAME)` / `argv[0]`-Fälschung.
  - Dynamische TTL-Sperren (`MALWARE_DENIED_INODES`) gegen bekannte Schadträger (bösartige `.so`, BPF-Loader, `memfd`-Träger).
- **Technischer Schutz & Aktion:**
  - Das Kernel-LSM verweigert unberechtigten Zugriffen das Lesen der Credentials hart mit **`-EACCES`** und korreliert `SBC-CRED-04`.
  - Vertrauenswürdige Pfade werden via `openat2(RESOLVE_NO_SYMLINKS)` gepinnt. Für gehostete Web-Stacks sind auch unveränderliche, `root:root`-eigene Panel-Server-Pfade (`POOL_SERVICE_PATHS`, z. B. `/www/server/php/...`, `/opt/plesk/php/...`, `openlitespeed`) für Pool-Metadaten berücksichtigt, während Webroots (`/www/wwwroot/...`) strikt gesperrt bleiben.

### 3. `AP-2` — Attach-Time `BPF_GUARD` (eBPF-Rootkit-Wächter)
- **Gemeinsame Aktivierung:** Mit `KernelHooks` (AP-4), `SelfGuard` (AP-0) und `PermitV1`.
- **Was es erkennt:** Jedes `bpf_prog_load`, `bpf_prog_attach`, `raw_tracepoint_open` und `bpf_link_create` über `lsm/bpf_prog`, `tp/syscalls/sys_enter_bpf` sowie (falls im Kernel verfügbar) `kprobe/check_helper_call` **vor** `do_misc_fixups`.
- **Risk-Scoring & Aktion:**
  - Baut pro geladenem eBPF-Programm eine Helper-Risiko-Bitmap — u. a. auf missbrauchsträchtige Kernel-Helper wie `bpf_probe_write_user`, `bpf_override_return` oder `bpf_send_signal`.
  - Meldet observe-first als `XDR.BPF_ANOMALY` und `XDR.BPF_ROOTKIT_HELPER`; legitime System-Loader können per `PermitV1` (`TOLERATED`) abgedeckt werden, eigener Loader ist getrennt abgesichert.

### 4. `AP-3` — 8-Domänen Cross-View-Verifier (Rootkit-Enttarnung)
- **Gemeinsame Aktivierung:** Mit Kernel-Iteratoren (`task`, `tcp`, `udp`, `bpf_prog`, `bpf_map`), `lsm/socket_create`, `socket_setsockopt`, `kprobe/sk_attach_filter`, `NETLINK_SOCK_DIAG` und Paket-DB-Abgleich (`dpkg`/`rpm`).
- **Was es erkennt:** Widersprüche zwischen verschiedenen Kernel- und Userland-Sichten („Lügen-Detektor“ gegen DKOM-/Syscall-Hooking-/Inline-Rootkits):
  1. Versteckte Prozesse (`iter/task` vs. `getdents64` vs. `/proc/<pid>/stat`) → `XDR.HIDDEN_PROCESS`
  2. Versteckte eBPF-Programme/Maps (`GET_NEXT_ID` vs. `GET_FD_BY_ID`) → `XDR.HIDDEN_BPF_PROG`
  3. Versteckte Sockets (`NETLINK_SOCK_DIAG` `inet_diag_req_v2` / `packet_diag_req`) → `XDR.HIDDEN_SOCKET`
  4. Portlose Raw-Packet-Taps / Sniffer → `XDR.PORTLESS_RAW_TAP` (mit Allowlist für `tcpdump`, `dhclient`, `NetworkManager`, `lldpd`, `keepalived`, `suricata`)
  5. Versteckte Kernelmodule → `XDR.LKM_HIDDEN`
  6. Ftrace-Hook-Anomalien → `XDR.FTRACE_HOOK_ANOMALY`
  7. Ausgetauschte/gelöschte BPF-Links & Pin-Mismatches → `XDR.BPF_LINK_TAMPER` / `PIN_MISMATCH`
  8. Abweichungen gemappter Systembibliotheken vs. Paketdatenbank (`library-view`)

### 5. `AP-4` — `KernelHooks`: `io_uring`-Bypass-Schutz & Pre-Stealth LKM-Audit
- **Gemeinsame Aktivierung:** Mit `BPF_GUARD` (AP-2) und Core-Tracepoints.
- **Was es erkennt:**
  - Asynchrone Syscall-Umgehungen über `io_uring` (Curing-/Ring-Implantate) durch BTF-optionale LSM-Hooks (`uring_override_creds`, `uring_sqpoll`, `uring_cmd`) plus `io_uring_create`/`register`/`submit_req`-Tracepoints → `XDR.IO_URING_ANOMALY`.
  - Modul-Ladevorgänge (`module_load`, `init_module`, `finit_module`, `delete_module`) noch **bevor** ein LKM sich verstecken kann → `XDR.LKM_LOAD`.
  - Opt-in-Sysctl-Härtung für `kernel.io_uring_disabled` und `vm.memfd_noexec=2`.

### 6. `AP-5` — `PersistenceGuard`, Speicherinjektion & Peripherieschutz
- **Gemeinsame Aktivierung:** Mit FIM, `Titan` Integrity, `SBC Fusion` und Core-LSM/Tracepoints.
- **Was es erkennt:**
  - Schreib-/Manipulationsversuche auf klassische Linux-Persistenzpfade: `/etc/ld.so.preload`, Dynamic-Linker-Configs & `ld-linux-*.so`, Paket-DB-Abgleich für in `sshd`, `sshd-session`, `sudo`, `su`, `login`, `curl` geladene Libraries (Ebury/Plague/xz-Vektor), `systemd`-Units/Drop-ins/Generatoren, `udev` `RUN+=`, PAM und `authorized_keys`/`sshrc`.
  - Speicherinjektion und Prozess-Ausspähung (`ptrace_access_check`, `process_vm_readv/writev`, `/proc/*/mem`, `mmap`).
  - Desktop-/Endpoint-Spionage: Zugriff auf `/dev/video*` (Kamera), `/dev/snd/*`/PipeWire/Pulse (Mikrofon), `/dev/input/event*` (`XDR.EVDEV_KEYLOG_PROBE`), User-/Browser-Secrets (`~/.ssh`, `~/.gnupg`, `~/.aws`, Browser-DBs, Keyrings) → `XDR.PERIPHERAL_BG_ACCESS`.

### 7. `AP-6` — StyX Phase-2 (PCR), DNS-Tunnelling & `GIEF v1.0 / SBC Fusion`
- **Gemeinsame Aktivierung:** Mit XDP/TC Egress-Policy, `cgroup_skb/ingress`, DNS-Capture-Ring (`UDP/53` `sendto`/`sendmsg`) und `StyxBeaconEngine`.
- **Was es erkennt:**
  - **Stille Exfiltration (PCR):** Der neue `cgroup_skb/ingress`-Observer liefert echte RX-Zähler. Die bidirektionale Producer-Consumer-Ratio `PCR = (tx - rx) / (tx + rx)` über 5-Minuten-Fenster meldet `XDR.STYX_PCR_EXFIL` nur bei echtem `RxObservationAvailable`, `PCR > 0.60` und >= 256 KiB.
  - **DNS-C2 / -Tunnelling:** 5-Signal-Analyse (Shannon-Entropie > 3.5, Zipf-Divergenz >= 3.0, FQDN-Länge > 50, TXT/NULL-Anteil > 10 %, > 100 Subdomains/h). **`XDR.DNS_TUNNEL` feuert erst bei >= 3 gleichzeitigen Signalen** (vermeidet Fehlalarme bei normalen CDNs).
  - **C2-Beacons & Graph-Korrelation:** Jeder Befund erhält ein `gief/v1.0`-Envelope (Fähigkeitsstatus, Evidence-Hashes, Blindspots). Die `SBC Fusion` korreliert Signale über Entitäten in einem zeitgewichteten Graphen (30 Min Halbwertszeit), z. B. `SBC-CRED-04`, `SBC-KERNL-03`, `SBC-PERSIST-06`, `SBC-EVID-08`.

### 8. `AP-7` — `Fanotify On-Access`, `Titan Exec Gate`, `RansomSensor`, `PermitV1` & `Parser Cells`
- **Gemeinsame Aktivierung:** `fanotify-exec` (`FAN_OPEN_EXEC_PERM`) + `fanotify` On-Write + `Titan` BPF-LSM + `RansomSensor` + `gedefense-cell-helper` + verschlüsselter Vault.
- **Präventive Block- & Isolationsfunktionen:**
  - **Fanotify On-Access & On-Write:** Prüft Binaries synchron vor `exec` und überwacht Drop-Zonen (`/tmp`, `/var/tmp`, `/dev/shm`, `/var/www`) asynchron beim Schreiben; überführt Funde atomar über `openat2` in den AES-256-GCM-Quarantäne-Vault.
  - **Titan Exec Gate (`BPF-LSM`):** Erzwingt Binary-/Inode-/ctime-Vertrauen im Kernel und verweigert unsignierten/unbekannten Trägern bzw. verbotenen `PROT_READ|PROT_WRITE|PROT_EXEC` (`WX` / `ANON_NO_JIT`)-Mappings den Start (`TITAN.MMAP_DENIED`).
  - **RansomSensor (`vfs_write` + `vfs_rename`/`unlink`):** Erkennt Entropie-Bursts und Rename-Stürme im Kernel und friert verdächtige Prozesse via `pidfd` ein bzw. eskaliert im Enforce-Modus kontrolliert (mit strikter Pool-Worker-Isolation für `php-fpm`, `nginx`, `httpd`, `mariadbd`, inkl. root-verifizierter Panel-Pfade, sodass nie der ganze Web-Pool gekillt wird).
  - **`PermitV1` Broker & Review Queue:** Signierte Ausnahmen (`AUTHORIZED` / `TOLERATED` / `ANALYST_MODE` mit SHA-256/Inode, Parent-Prüfung, TTL und Ed25519-Ledger-Audit; unsignierte Permits können nie `AUTHORIZED` werden), persistente verschlüsselte Review Queue, `QUARANTINE_PRUNE` sowie Pflicht-Explainability (`stages`, `rules`, `exonerating_evidence_hint`, `blindspots`).
  - **`Parser Cells` (`gedefense-cell-helper`):** Isoliert riskantes Parsen in kurzlebigen, ressourcenbegrenzten Cgroup-/Namespace-Zellen (`burn after use`).

### 9. `AP-8` — Chameleon Identity Mode & Deception Canaries
- **Gemeinsame Aktivierung:** Über signiertes Chameleon-Installationsmanifest (Standard: aus / Opt-in) + Canary Broker.
- **Was es leistet:**
  - **Deception Canaries:** Legt Köder-Dateien/Trap-Keys (`~/.ssh`/Systempfade) ab; jede Berührung außerhalb des eigenen Selbsttests liefert sofort hochpriore Sabotage-/Spyware-Alarme.
  - **Chameleon Mode:** Patcht zur Ladezeit eBPF-Programm- und Map-Namen längengleich im ELF-`.strtab` und randomisiert Sockets, Ports und BPF-Pin-Roots — in `bpftool prog list` tauchen keine `gedefense`/`styx`/`titan`-Signaturen auf, wodurch automatisierte „Security-Agent-Killer“ ins Leere greifen (Admin behält volle Rückverfolgbarkeit über das signierte Step-Up-Reveal-Audit).

### 10. `AP-9` — Selbstverteidigung unter aktivem Angriff (`S09`, `S12`, `R6`, `S08`/`S15`)
- **`S09` TUF-Feed-/Regel-Schutz:** 2-aus-3-Ed25519-Schwellensignatur, Rollentrennung (`root`/`content`/`snapshot`), kurze `expires_at`, Anti-Rollback-Epoche, lokaler Diff- & Regex-Guard (max. 20 % Löschbudget, unantastbare System-Zone) und Last-Known-Good-Rollback.
- **`S12` Anti-DoS Evidence Ring (`SEC_CRIT_EVENTS`):**
  - Unabhängiger **256-KiB-High-Priority-Ring** (4.096 × 64-Byte-Records) für kritische Evidenz (`CRED_GUARD`, `BPF_GUARD`, `KERNEL_HOOKS`, `PERSISTENCE`), damit Massen-Exec/Log-Spam niemals kritische Beweise verdrängen kann.
  - Bulk-Telemetrie läuft vorab durch einen **per-`(class, cgroup, uid)`-Token-Bucket** (`16.384` Kapazität / `16.384 / s` Nachfüllrate, 4.096 LRU-Buckets; Sub-Sekunden-Intervall-Bug in `telemetry_bucket_step` behoben). Reines Bulk-Throttling mit `drops=0` hält Schutzstatus & UI auf `ENFORCE`/`SYSTEM NOMINAL`, während jeder echte Ring-Drop (`drops > 0`) sofort alarmiert.
  - S12-Quoten-Überwachung (Parser-Cell-Concurrency, Review-Queue-Limit, 256-MiB-Quarantäne-Reserve).
- **`R6` Management-API RBAC & Gateway-CSRF-Härtung:**
  - Serverseitige Trennung in **Observer** (Read-Only), **Operator** und **Critical Unlock** (Passwort-/HMAC-Step-Up mit kurzer TTL, Replay-Cache, Bruter-Lockout, signiertem `.gateway-claim` + `Origin`/`Sec-Fetch-Site`-Prüfung).
  - Gepinnter Release-Public-Key für signierte Update-Windows (`override` akzeptiert keine fremden Aufrufer-Keys).
- **`S08`/`S15` Witness-Priorität:** Kritische Self-Tamper-Beweise werden **vor** dem lokalen Log-Append non-blocking an den out-of-band Witness geschickt.

---

## API & Dashboard-Integration

- **UI-Ansicht:** Eigener Menüpunkt **Antispyware** im Seitenmenü (`control/web/js/views_antispyware.js`) mit KPI-Leiste, Co-Activation- & Trigger-Matrix und Detailkarten für alle 10 Ebenen (`AP-0` bis `AP-9`) in 4 Sprachen (`de`, `en`, `ru`, `zh-CN`).
- **Live-API:** `GET /api/v1/antispyware/status` ([server_handlers_antispyware.go](file:///C:/Users/Masterboard/Desktop/Dev_Bunker/GeDefense/Linux/6.2.1-github/control/server_handlers_antispyware.go)) liefert in Echtzeit die aggregierte Ebene (`active_planes / total_planes`), alle Zähler (`self_guard`, `exec_inode`, `bpf_guard`, `cross_view`, `kernel_hooks`, `persistence`, `dns`, `styx_phase2`, `styx`, `sbc_fusion`, `sec_crit`, `credential_guard`, `ransom`, `titan_exec`, `chameleon`, `lpe_guard`).
