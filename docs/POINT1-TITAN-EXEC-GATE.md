# POINT 1 — Titan + eBPF-LSM Exec-/Library-Gate

**Status:** IMPLEMENTIERT (Phase 1) · Implementierung/Verifikation 2026-11-15 · T7-Review PARTIAL, zwei Befunde behoben (ctime-Split-BTF, comm-Härtung) 2026-11-15 · GeDefense V6 (`6.0.0`)
**Review-Regel:** Diese Datei ist der verbindliche Vertrag zwischen eBPF-, Rust-Core- und Go-Control-Anteil. ABI-Änderungen (Wire, Map-Layout, IPC-Kommando) zuerst hier ändern und alle Task-Owner informieren.

## 0. Kritischer Betriebsbefund (vor Implementierung beachten)

Auf Referenzsystemen ohne `bpf` in `/sys/kernel/security/lsm` (z. B. Ubuntu 24.04 mit Standard-Cmdline unter Kernel `7.0.x`) ist **BPF-LSM nicht aktiv**:
`CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, vmlinux-BTF + bpftool vorhanden, **aber** `CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"` und `/sys/kernel/security/lsm` = `lockdown,capability,landlock,yama,apparmor,ima,evm`; kein `bpf`-Token, kein `lsm=` in `/proc/cmdline`.
Folgen (empirisch bestätigt): BPF-LSM-Programme lassen sich laden und `attach()` liefert Erfolg, die `bpf_lsm_*`-Stubs werden aber **nie aufgerufen** ⇒ **stiller No-Op, keine Enforcement-Wirkung**. Der bestehende P3-Socket-Cell-Gate (`gedefense_cell_socket_create`) meldet auf dem Server `attached`, feuert dort aber nie — **dieser falsche Status wird in Phase 1 mitkorrigiert**.

**Aktivierungsvertrag P1:** Echte Exec-Gate-Wirkung setzt Boot-Cmdline `lsm=...` inkl. `bpf` + Reboot voraus (Operator-Entscheidung, eigener Wartungsfenster-Schritt; nicht Teil der Code-Implementierung). Bis dahin muss der Status ehrlich `inactive`/`unavailable` melden, Default bleibt `off`, und es gibt **keine** Enforcement-Behauptung. Die Code-Seite implementiert den Aktivierungs-Check als verbindliche Voraussetzung für Attach + Status.

**Umsetzungsstand (2026-11-15):** Phase 1 ist implementiert und Gate-verifiziert (Details/Evidenz: `docs/POINT1-PHASE1-REPORT.md`). Auf Systemen ohne `bpf`-LSM-Token bleibt der Exec-Gate-Status wegen der fehlenden `bpf`-LSM-Liste ehrlich `inactive`/`path=none`: es wird nicht attached und `TITAN_EXEC_SET_GLOBAL` mit `mode>0` wird mit `ERR enforcement-unavailable` abgelehnt (Go-Sync-State `inactive`, nie `applied`). Der bisherige P3-Socket-LSM-Claim (`bpf-lsm-cell` als Erfolg eines wirkungslosen Attach) ist mitkorrigiert (§7.5; `docs/POINT3-EGRESS-BEACON.md` §13). Präzisierungen/Abweichungen der Umsetzung: §13. **T7-Nachtrag (2026-11-15):** Der adversariale Review ergab PARTIAL ohne offenen FAIL; die zwei Befunde sind behoben — ctime-BTF-Kompatibilität (Split-Layout/NSEC-Width, §13.13) und comm-Härtung (§13.14); die Inert-Policy-Grenze wurde präzisiert (§13.15).

## 1. Ziel und Leitplanken

Ziel: Der Kernel blockiert bereits bei `execve` (`bprm_check_security`) und beim Nachladen ausführbarer Datei-Mappings (`mmap_file`/`PROT_EXEC`) auf Basis einer von **Titan** kompilierten Inode-Policy — Prävention statt nachgelagerter inotify-Quarantäne. Zusätzlich wird die bereits vorhandene P3-LSM-Nutzung status-ehrlich.

Leitplanken (unverhandelbar):
1. **Privilege Split:** Kernel-/BTF-/Map-/Attach-Arbeit nur im Rust-Core (`rust/gedefense-core`), eBPF in `rust/gedefense-ebpf`; Go (`control/`) bleibt unprivilegiert und spricht ausschließlich VGT3 (`control/coreipc.go`).
2. **Fail-safe statt Lockout, aber keine Attrappe:** Aktivierungs-Check (`/sys/kernel/security/lsm` enthält Token `bpf`), Offset-Validierung, Default-Modus **OFF**, leere Map/ungültige Offsets/inaktives LSM ⇒ Hooks erlauben (0) und Status `inactive`/`unavailable`; **niemals** `attached`/`enforce` behaupten, wenn der Hook nicht läuft.
3. **Identität im Kernel, nicht Dateiname:** Policy-Key = `(s_dev, i_ino)`; optional `i_ctime`-Abgleich (im Wert) gegen Inode-Recycling/In-place-Modifikation. Kein String-Vergleich im Kernel; Symlinks werden von Core bei der Policy-Auflösung per fd-basiertem Walk (`O_NOFOLLOW`/`O_PATH`, `fstat`) verworfen.
4. **Kein System-Lockout:** Modus nur per Operator-Settings; STRICT/ CONTAIN nur nach vollständigem Plan; Kernel-Restart/Map-Verlust ⇒ Map leer ⇒ erlauben (Fail-open-Fenster dokumentiert); Boot-Rettungsvertrag über Default-OFF. Die vorhandenen `--require-bpf-lsm`-Semantiken bleiben erhalten.
5. **Forensik/Reversibel:** Kein Löschen; Verstöße erzeugen `TitanExecEvent` → XDR-Evidence/Incident; Reaktionen (CellGuard/Freeze) laufen über bestehende Response-/TransactionEngine-Pfade.
6. **Keine Umbaumodule:** Titan bleibt Beobachter; keine Änderung an `TitanEngine`, `ResponseEngine`, `TransactionEngine`, `EvidenceLedger`-Signaturen; Ergänzungen additiv in neuen Dateien + minimalen Andockpunkten.

## 2. Geltungsbereich Phase 1

| Bestandteil | Phase 1 | Später |
|---|---|---|
| eBPF | `#[lsm(hook="bprm_check_security")]` + `#[lsm(hook="mmap_file")]`, Runtime-Offset-Map (BTF-basiert, kein CO-RE/Objekt-BTF), Modi OFF/OBSERVE/CONTAIN/STRICT, Per-Cgroup-Scopes, JIT-Ausnahme, RingBuf-Events, Counter | `file_mprotect` W^X-Transitionen, fs-verity-Hartbindung, Path-Telemetrie via `bpf_d_path` |
| Rust-Core | Mini-BTF-Parser aus `/sys/kernel/btf/vmlinux`, Offset-Validierung + Map-Seed, Aktivierungs-Check LSM, Attach beider Hooks, Policy-Store, fd-sichere Pfadauflösung, IPC-Kommandos, Event-Drain/Health, Status; P3-Socket-LSM-Statuskorrektur | – |
| Go-Control | Settings `titan_exec` (v14), Plan-/Allowlist-Compiler (Paket-/FIM-/Verity-Quellen), Pfad-Batches + Sync-Reihenfolge, Event-Parser + XDR-Anbindung, Status/API, Fail-Closed | UI-Panels, Dev-Root-Sonderregeln |
| Aktivierung | Status `inactive`, Aktivierungscheck, Betriebsanleitung (`lsm=...,bpf` + Reboot), keine automatische Cmdline-Änderung | optionaler Fanotify-Exec-Fallback (nicht Phase 1) |

**Nicht-Ziele Phase 1:** Fanotify-Exec-Fallback (nur dokumentierte Option), Änderung der Boot-Kommandozeile/Reboot, Live-Verifier-Test auf Produktion, `file_mprotect`, fs-verity-Enforcement (Bitwert/Verhalten nicht belastbar verifiziert), Dev-Root-Kernel-Ausnahmen.

## 3. ABI-1: Wire-Format (`rust/gedefense-common/src/titan_exec.rs`, Go-Spiegel in `control/coreipc.go`)

Native Endian, `repr(C)`, feste Längen, Reject statt Reparatur (Doktrin wie `decode_styx_flow_event`).

### 3.1 Konstanten

```
TITAN_EXEC_EVENT_WIRE_BYTES = 88
TITAN_EXEC_HOOK_BPRM = 1, TITAN_EXEC_HOOK_MMAP = 2
TITAN_EXEC_ACTION_AUDIT = 1, TITAN_EXEC_ACTION_DENY = 2
TITAN_EXEC_REASON_NONE = 0, UNLINKED = 1, TMPFS = 2, MEMFD = 3,
  NOT_ALLOWLISTED = 4, WX = 5, ANON_NO_JIT = 6, READ_FAILURE = 7,
  STATE_NOT_READY = 8, CTIME_MISMATCH = 9, FS_HARD = 10
TITAN_EXEC_MODES: OFF=0, OBSERVE=1, CONTAIN=2, STRICT=3
TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW = 1<<0
TITAN_EXEC_STATE_MAGIC = 0x54 ('T'), TITAN_EXEC_STATE_ABI = 1
TITAN_EXEC_OFFSETS_MAGIC = 0x5449544f ("TITO"), TITAN_EXEC_OFFSETS_ABI = 1
```

### 3.2 `TitanExecEvent` (88 Byte)

| Offset | Größe | Feld | Semantik |
|---:|---:|---|---|
| 0 | 8 | `cgroup_id` u64 | aufgelöste Cell-/Leaf-Cgroup |
| 8 | 8 | `ts_ns` u64 | `bpf_ktime_get_ns` |
| 16 | 4 | `dev` u32 | `s_dev` (dev_t) |
| 20 | 4 | `inode_mode` u32 | `i_mode` |
| 24 | 8 | `ino` u64 | `i_ino` |
| 32 | 4 | `generation` u32 | `i_generation` (nur forensisch; nicht Policy-Key) |
| 36 | 4 | `pid` u32 | |
| 40 | 4 | `tgid` u32 | |
| 44 | 4 | `uid` u32 | `bpf_get_current_uid_gid` |
| 48 | 4 | `gid` u32 | |
| 52 | 4 | `prot` u32 | mmap: `PROT_*`; bprm: 0 |
| 56 | 4 | `f_flags` u32 | Phase 1 immer 0 (eBPF-Offsets-Enum enthält keinen `FILE_F_FLAGS`-Offset); reserviert für Erweiterung |
| 60 | 1 | `hook` u8 | 1=bprm, 2=mmap |
| 61 | 1 | `action` u8 | 1=audit, 2=deny |
| 62 | 1 | `reason` u8 | Enum 0..10 |
| 63 | 1 | `flags` u8 | Bit0: ctime mismatch observed; Bit1: scope snapshot |
| 64 | 16 | `comm` [u8;16] | roher Prozessname (`bpf_get_current_comm`); via `PR_SET_NAME` beliebige Bytes außer NUL (max. 15 + Terminator). Wire: erste NUL beendet den Namen, Rest NUL-Padding; Go akzeptiert jede Hex-Folge ≤16 B und sanitisiert nur die Anzeige (§3.2/§3.3) |
| 80 | 8 | `reserved` [u8;8] | 0 |

Decoder (`decode_titan_exec_event`): `len==88`; `hook∈{1,2}`; `action∈{1,2}`; `reason≤10`; `pid>0`; `ts_ns>0`; `hook==MMAP ⇒ prot!=0`; `action==DENY ⇒ reason∉{NONE,READ_FAILURE}`; comm ohne Nicht-NUL nach erstem NUL; Null-Identität (`dev==0 && ino==0`) ist **nur** erlaubt für (a) `reason==READ_FAILURE && action==AUDIT` oder (b) `hook==MMAP && reason==ANON_NO_JIT && (prot & PROT_EXEC)!=0` (anonyme Exec-Mappings haben keine Datei/Inode); alle anderen Kombinationen mit `dev==0 || ino==0` ⇒ `None`. Ungültig ⇒ `None`.

**comm-Kontrakt:** `comm` ist der rohe Prozessname (`bpf_get_current_comm`); via `PR_SET_NAME` sind beliebige Bytes außer NUL möglich (max. 15 + Terminator). Das Text-Wire transportiert sie hex-kodiert; der Go-Parser muss **jede** Hex-Folge ≤16 Byte akzeptieren und für Anzeige/Summary sanitisieren (nicht druckbare Bytes ersetzen), **nicht** den ganzen Batch verwerfen. Rust- und Go-Seite dürfen hier nicht strenger sein als der Kernel-Vertrag.

### 3.3 Text-Wire (`TITAN_EXEC_EVENTS`)
`empty` **oder** `<dropped>|<record>[,<record>…]` (max. 8 Records; Payload ≤2048 B). Record 16 Felder `:`-getrennt:
`cgroup_dec:ts_dec:dev_dec:inode_mode_dec:ino_dec:gen_dec:pid_dec:tgid_dec:uid_dec:gid_dec:prot_dec:f_flags_dec:hook_dec:action_dec:reason_dec:comm_hex`
- cgroup/ino/ts/pid dezimal; dev/mode/gen/… dezimal; comm ≤32 Hex-Zeichen; keine Leerzeichen/NUL.
- Go-Parser: Alles-oder-Nichts pro Batch, ≤8 Records, `dropped`-Präfix, strenge Bounds; Fehler ⇒ Batch verwerfen + Zähler, nie Teilzustand/panic. `comm` wird als rohe Hex-Folge (≤32 Zeichen, jede Byte-Sequenz ≤16 B) akzeptiert; erzwungen wird nur die NUL-Padding-Form (nach der ersten NUL nur NUL). Die Anzeige sanitisiert `sanitizeTitanExecComm` (nicht druckbar ⇒ `?`); ein hostile `comm` darf **nie** einen ganzen Event-Batch unterdrücken.

## 4. ABI-2: eBPF-Maps (`rust/gedefense-ebpf/src/main.rs`)

| Map | Typ | Key/Value | max_entries |
|---|---|---|---:|
| `TITAN_EXEC_STATE` | Array\<u64\> | 1 Wort: `epoch(bits0-31) \| mode(bits32-39) \| flags(bits40-47) \| abi(bits48-55)=\1 \| magic(bits56-63)=0x54` | 1 |
| `TITAN_EXEC_OFFSETS` | Array\<u32\> | Offset-/ABI-Tabelle (Index-Enum in §4.1) | 48 |
| `TITAN_EXEC_MODE` | HashMap\<u64,u8\> | cgroup→`(mode 0..3) << 2 \| scope-flags(bit0 JIT_ALLOW)` | 4096 |
| `TITAN_EXEC_POLICY` | HashMap\<[u8;16],[u8;16]\> | Key: `dev u32 LE \| ino u64 LE \| pad[4]`; Value: `action u8(=1 ALLOW) @0 \| flags u8(REQUIRE_CTIME=1) @1 \| reserved u16 @2 \| ctime_ns u64 LE @4..12 \| pad[4] @12..16` | 65536 |
| `TITAN_EXEC_EVENTS` | RingBuf | `TitanExecEvent` (88) | 1 MiB |
| `TITAN_EXEC_EVENTS_EMITTED`, `TITAN_EXEC_RING_DROPS`, `TITAN_EXEC_READ_FAILURES`, `TITAN_EXEC_POLICY_DENIES`, `TITAN_EXEC_POLICY_AUDITS`, `TITAN_EXEC_CTIME_REJECTS` | PerCpuArray\<u64\> | Zähler | 1 |

STATE-Flags: Bit0 `offsets_valid`, Bit1 `lsm_active`, Bit2 `ctime_check_enabled`, Bit3 reserved. eBPF akzeptiert das Wort nur bei `magic==0x54 && abi==1`; sonst Fail-safe (allow, Counter).

### 4.1 `TITAN_EXEC_OFFSETS`-Index-Enum (Core füllt, eBPF liest)

```
0 OFFSETS_MAGIC            1 ABI              2 BPRM_FILE_OFF        3 FILE_F_INODE_OFF
4 INODE_I_INO_OFF          5 INODE_I_SB_OFF   6 INODE_I_NLINK_OFF    7 INODE_I_MODE_OFF
8 INODE_I_GEN_OFF          9 SUPER_S_DEV_OFF 10 SUPER_S_MAGIC_OFF   11 INODE_I_CTIME_SEC_OFF
12 INODE_I_CTIME_NSEC_OFF 13 BPRM_NARGS      14 MMAP_NARGS          15 MMAP_FILE_ARG_IDX
16 MMAP_PROT_ARG_IDX      17 MMAP_FLAGS_ARG_IDX 18 TMPFS_MAGIC       19 DEVTMPFS_MAGIC
20 PROC_MAGIC             21 SYSFS_MAGIC     22 OVERLAY_MAGIC        23 BPRM_RETVAL_SLOT
24 MMAP_RETVAL_SLOT       25 INODE_SIZE      26 FILE_SIZE            27 BPRM_SIZE
28 INODE_I_CTIME_NSEC_WIDTH (4 oder 8) 29..47 reserved (0)
```
Core berechnet Arg-Indizes aus Hook-FUNC_PROTO (MMAP: `prot_idx=nargs-2`, `flags_idx=nargs-1`, `file_idx=0`, Retval-Slot=nargs; BPRM: file_idx=0, Retval-Slot=nargs) und validiert Plausibilität (`off < size`, nargs ∈ {1,3..5}). eBPF nutzt ausschließlich `bpf_probe_read_kernel` mit Laufzeit-Offsets (keine direkten variablen Offset-Loads — Verifier!); alle Pointer werden als Skalar behandelt.

**ctime-Layout-Vertrag (wichtig, kernelversionsabhängig):** Moderne Kerne (u. a. 6.18/7.0) haben im `struct inode` **kein** `i_ctime`-timespec64 mehr, sondern Split-Felder `i_ctime_sec` (8 Byte) und `i_ctime_nsec` (4 Byte); ältere Kerne haben `i_ctime` = `struct timespec64` (`tv_sec` 8, `tv_nsec` 8). Der Core löst daher: bevorzugt `i_ctime_sec`/`i_ctime_nsec` (NSEC_WIDTH=4), sonst `i_ctime.tv_sec`/`i_ctime.tv_nsec` (NSEC_WIDTH=8); beide Varianten schreiben `INODE_I_CTIME_SEC_OFF`, `INODE_I_CTIME_NSEC_OFF` und `INODE_I_CTIME_NSEC_WIDTH`. eBPF liest `sec` immer als u64, `nsec` gemäß Width (8 ⇒ u64, 4 ⇒ u32 zero-extended) und vergleicht `sec*1e9 + nsec` mit `ctime_ns` (Overflow-saturierend). Fehlt beides oder ist die Width unplausibel ⇒ `offsets=invalid` ⇒ kein Attach (`unavailable`).** Real-BTF-Gate:** Der Core-Host-Test lädt bei vorhandenem `/sys/kernel/btf/vmlinux` die Live-BTF und verlangt, dass **alle** Offsets inkl. ctime-Variante auflösen; fehlt die Datei, wird der Test als dokumentiertes SKIP geführt (kein stilles Bestehen).

Bekannte Golden-Werte (x86_64, belegt durch synthetische BTF-Fixtures **und** den Real-BTF-Host-Test): `linux_binprm.file=64`, `file.f_inode=32`, `inode.i_ino=64`, `inode.i_sb=40`, `inode.i_nlink=72`, `inode.i_generation=124`, `super_block.s_dev=16`, `super_block.s_magic=96`, `bprm nargs=1`, `mmap nargs=4` (Kerne 6.18/7.0). `i_nlink` liegt in einer anonymen Union (BTF-Parser muss rekursiv auflösen). Der Live-Wert-Lauf auf WSL 6.18 belegt `i_ctime_sec=104`, `i_ctime_nsec=120`, `NSEC_WIDTH=4`, `inode_size=608` (übrige Golden-Werte unverändert).

### 4.2 Modus-/Entscheidungssemantik

- Globaler Modus aus STATE; Per-Cgroup-`TITAN_EXEC_MODE` überschreibt (Ancestor-Walk wie `socket_create`-Hook, Level 0..63, erster Treffer; Scope wird auf der Cell-Root-Cgroup installiert, Kind-Cgroups erben).
- **OFF:** Hooks erlauben sofort (kein Read, kein Event).
- **OBSERVE:** Entscheidung wie CONTAIN/STRICT, aber `action=AUDIT`, Rückgabe 0 (kein Block); Events nur für Treffer/Read-Fehler.
- **CONTAIN:** `bprm`: DENY bei `i_nlink==0` (unlinked/memfd/O_TMPFILE) oder `s_magic ∈ {TMPFS, DEVTMPFS, PROC, SYSFS}` (Ausnahme: inode-Policy ALLOW vorhanden). `mmap` nur wenn `PROT_EXEC`: DENY bei denselben Bedingungen, bei `PROT_WRITE|PROT_EXEC` beider Bits (reason WX), sowie bei anonymem Exec (file==NULL) ohne Scope-Flag JIT_ALLOW (reason ANON_NO_JIT). Loopback/Sonderfälle irrelevant (kein Netz).
- **STRICT:** DENY, wenn kein `TITAN_EXEC_POLICY`-ALLOW für `(dev,ino)`; bei gesetztem REQUIRE_CTIME-Flag zusätzlich DENY bei `i_ctime`-Mismatch (reason CTIME_MISMATCH). Gilt für bprm und für Datei-mmap mit `PROT_EXEC`; anonymer Exec nur mit JIT_ALLOW.
- `previous`-Retval der LSM-Kette respektieren (vgl. `socket_create`: `ctx.arg(nargs)`).
- Read-/Offsets-Fehler: `READ_FAILURES++`; enforce-Modus ⇒ **kein** Block (Fail-safe), Audit-Event mit reason READ_FAILURE (nur OBSERVE/CONTAIN/STRICT aktiv).
- Auf `mmap`-Hook: vor jeglichem Kernel-Read zuerst `prot` aus ctx-Slot lesen; wenn `PROT_EXEC` nicht gesetzt ⇒ sofort 0 (Performance, Libraries werden ständig gemappt).
- Keine Pfad-Strings im Kernel; Events ohne Pfad (Go reichert best-effort via `/proc/<pid>/exe` an, ehrlich `unknown`).

## 5. ABI-3: VGT3-Kommandos (Core + Go-Client)

Format wie bestehend (`VGT3 ts nonce CMD args… mac`; ≤16 Felder, Felder ohne Leerraum/NUL/0x1f; Payload ≤2048 B base64url; ≤4096 B Zeile). Unbekannt ⇒ `ERR unknown command`.

| Kommando | Argumente | OK-Payload |
|---|---|---|
| `TITAN_EXEC_VERSION` | — | `titan-exec-v1` |
| `TITAN_EXEC_EPOCH` | — | 16 Hex (random pro Core-Start) |
| `TITAN_EXEC_STATUS` | — | `status=<state>;mode=<0..3>;flags=<n>;path=<bpf-lsm\|none>;lsm=<active\|inactive>;offsets=<valid\|invalid>;entries=<n>;scopes=<n>;epoch=<hex>` (`state` ∈ `applied\|pending\|failed\|inactive\|unavailable`) |
| `TITAN_EXEC_SET_GLOBAL` | `mode` (0..3), `flags` (u8: Bit0 REQUIRE_CTIME) | `applied`; **ERR `enforcement-unavailable`** wenn mode>0 und (LSM inaktiv oder Offsets invalid) |
| `TITAN_EXEC_ALLOW_ADD` | `path` (absolut, kanonisch, ≤2048 B) | `added:<dev>:<ino>` oder `exists:<dev>:<ino>`; ERR bei Symlink/Nicht-Regular/Nicht-Executable/Read-Fehler |
| `TITAN_EXEC_ALLOW_ADD_BATCH` | `base64url(liste von zeilengetrennten Pfaden)`, ≤2048 B dekodiert | `added:<n>;rejected:<n>;error=<grund>` (Teilakzeptanz erlaubt; `rejected>0` ⇒ Go-Sync gilt als fehlgeschlagen) |
| `TITAN_EXEC_ALLOW_DEL` | `dev` (dec), `ino` (dec) | `deleted` (idempotent bei KeyNotFound) |
| `TITAN_EXEC_CLEAR` | — | `cleared` |
| `TITAN_EXEC_SCOPE_SET` | `cgroup_id` (dec≠0), `mode` (0..3), `flags` (u8) | `applied` |
| `TITAN_EXEC_SCOPE_DEL` | `cgroup_id` | `deleted` (idempotent) |
| `TITAN_EXEC_EVENTS` | — | §3.3 oder `empty` |
| `TITAN_EXEC_HEALTH` | — | `emitted:ring_drops:read_failures:denies:audits:ctime_rejects` (Per-CPU-Summen, 6 Felder) |

Core-Validierung vor Map-/Store-Write (keine Teiländerung bei Fehler): Modus/Flags-Wertebereiche, Pfad absolut + Länge + keine NUL, cgroup≠0, dev/ino≠0, Batch-Größe/Caps. DELETE idempotent (`KeyNotFound ⇒ deleted`). Antwort-Payload ≤2048 B (Truncation ⇒ ERR statt stiller Kürzung; Events ≤8).

**Resync-Vertrag:** Go lernt `epoch`; Core-Restart ⇒ neue Epoch + leere Maps ⇒ Go voller Resync. Reihenfolge (fail-safe): `SET_GLOBAL(0,0)` → Allowlist (Adds/Batches) → Scopes → `SET_GLOBAL(mode,flags)`; bei Deaktivierung: `SET_GLOBAL(0,0)` zuerst, dann Clear/Deletes. Adds vor Deletes. Fehler ⇒ Status `failed`/`pending`, **niemals** `applied`; Events `titan_exec.policy_sync_failed`.

## 6. Rust-Core (`rust/gedefense-core`)

- Neue Module (≤500 Zeilen/Datei): `src/btf_offsets.rs` (Mini-BTF-Parser + Hook-Proto-/Feld-Offset-Auflösung + Validierung), `src/titan_exec.rs` (Policy-Store, fd-sichere Pfadauflösung + Batch, Event-Queue/Encoding, Status, LSM-Aktivierungsprobe).
- `btf_offsets`: liest `/sys/kernel/btf/vmlinux` (bounded, max. 64 MiB), parst BTF-Header (magic `0xeb9f`, version 1, hdr_len 24), Typen (STRUCT/UNION/INT/FUNC/FUNC_PROTO), anonyme Unions rekursiv, `FUNC_PROTO`-Params für `bpf_lsm_bprm_check_security` und `bpf_lsm_mmap_file`; jeder Fehler/fehlendes Feld ⇒ `Err` ⇒ Gate `inactive` (keine Heuristik). Keine neue Crate; keine `unsafe`-Pointer-Leserei über BTF hinaus. **ctime:** bevorzugt Split-Layout `i_ctime_sec` (8 B)/`i_ctime_nsec` (Width 4|8 aus dem realen BTF-Feldtyp), sonst Legacy-`i_ctime.tv_sec/tv_nsec`; die Width wird als `INODE_I_CTIME_NSEC_WIDTH` (OFFSETS[28]) veröffentlicht; unplausible Width/Reihenfolge ⇒ `Err` (kein Attach).
- Aktivierungsprobe: `/sys/kernel/security/lsm` lesen und Token `bpf` in der CSV-Liste verlangen; Ergebnis in Status + STATE-Flag `lsm_active`. **P3-Fix:** `attach_cell_socket_lsm` darf `cell_lsm_attached` nur bei aktiver LSM-Liste setzen; bei inaktiv Status `optional-unavailable`/Warning loggen (kein Attach-Claim). `--require-bpf-lsm` bleibt: wenn gesetzt und inaktiv ⇒ Startup-Fehler (bestehende Semantik schärfen, Dokumentation).
- Beim Start: BTF-Offsets auflösen/validieren → `TITAN_EXEC_OFFSETS` + STATE(flags offsets_valid) schreiben; wenn LSM aktiv: beide Programme mit `Btf::from_sys_fs()` laden (`Lsm::load(hook, &btf)`) und attachen (Attach-Modus wie bestehend; mehrere Programme auf verschiedenen Hooks sind unkritisch); STATE mode=OFF. Fehlt LSM: nicht attachen, Status `inactive`, Hooks existieren nicht (keine Wirkung, keine Attrappe).
- Policy-Store (nur Core, im RAM): `HashMap<(u32,u64), PolicyEntry>` + Scopes `HashMap<u64,u8>`, bounded (Policy ≤65536, Scopes ≤4096), zusätzlich Map-Writes für eBPF wenn aktiv. `ALLOW_ADD`: Pfad mit fd-basiertem Walk (`O_PATH|O_NOFOLLOW`, `fstat`) auflösen; Symlink/Non-Regular/Nicht-Executable/Fehler ⇒ ERR; `dev/ino/ctime` übernehmen; optional `FS_IOC_MEASURE_VERITY`-Unterstützung **nicht** Phase 1 (dokumentiert). `ALLOW_ADD_BATCH`: base64 dekodieren (Format: UTF-8, zeilengetrennt, ≤256 Pfade/Batch, ≤2048 B), jeden Pfad einzeln wie ADD; Antwortzähler. Alle Einträge mit ctime_ns (nanos seit Epoch; fstat `ctime()+ctime_nsec*1e9`), REQUIRE_CTIME-Flag nur wenn Settings es aktivieren (CTA); eBPF vergleicht.
- Event-Drain: `TITAN_EXEC_EVENTS`-Ring lesen (≤8), 88-Byte-Check, `decode_titan_exec_event`, ungültige überspringen + zählen (kein Drain-Abbruch), Text-Wire §3.3, `dropped` = Ring-Drop-Delta; Health = Per-CPU-Summen (6 Felder).
- IPC: neue Dispatch-Arme + Limits; bestehende Kommandos/Semantik unverändert; `PING`-Mode-String um Exec-Status ergänzen (z.B. `+titan-exec:<inactive|audit|contain|strict>`), ohne bestehende Tests zu brechen (Tests ggf. additiv erweitern).
- Tests: BTF-Parser mit synthetischen Fixtures (magic/version/anonyme Union/Bitfields/FUNC_PROTO/Truncation), Offset-Golden-Tabelle 6.18/7.0 als Kommentar + Validierungslogik, Pfadauflösung (Symlink/Hardlink/TOCTOU-Ersatz/Non-Regular), Batch-Decode, Event-Encoding, DELETE-Idempotenz, Status-/Health-Format, `unknown command` bleibt Fehler; bestehende Tests grün.

## 7. Go-Control

### 7.1 Settings (v14) — `control/titan_exec_settings.go`
`RuntimeSettings.TitanExec *TitanExecFabricSettings` (Pointer-Muster wie StyX), Defaults: `Enabled=false, Mode="off", MaxEntries=8192, MaxScopes=256, RequireCtime=false`, Listen leer ⇒ Upgrade ändert Kernelverhalten nicht. Felder: `Enabled bool`, `Mode string` (`off|observe|contain|strict`), `ExecRoots []string` (Verzeichnisse, deren reguläre ausführbare Dateien allowlisted werden), `AllowPaths []string` (einzelne Dateien/Verzeichnisse), `DevRoots []string` (Phase 1 nur dokumentiert, **keine** Kernel-Freigabe), `JitCgroups []uint64`, `StrictCgroups []uint64`, `MaxEntries int`, `MaxScopes int`, `RequireCtime bool`.
Validierung (reject-not-repair): Mode-Enum; `mode=off` + nicht-leere Regeln **bei `Enabled=true`** ⇒ Fehler (Inert-Policy-Verbot; disabled-Entwürfe mit Regeln bleiben zulässig); Pfade absolut/kanonisch/NUL-frei/caps; cgroup≠0, unique, ≤MaxScopes; `strict` erfordert `ExecRoots/AllowPaths` nicht leer; `MaxEntries` 1..65536. `fabricSettingsVersion` 13→14 + Migrationsnotiz; Fabric-Modul `titan_exec`, Schema HOT/critical.

### 7.2 Plan-Compiler — `control/titan_exec_plan.go`
Rein, ohne Seiteneffekte. Quellen: (1) `ExecRoots`: bounded Walk (max. MaxEntries, Depth ≤32, keine Symlinks, nur regular+executable, Dedupe via dev/ino); (2) `AllowPaths`: einzelne Dateien/Verzeichnisse (Verzeichnisse → bounded Walk); (3) Paket-/FIM-Evidenz: pro Pfad `titanPackageVerifier.Owner` + `FIM.TitanBaselineRecord` (nur `regular && !symlink && SHA256==baseline`) als **Pflicht** für `ExecRoots`-Einträge? Phase 1: Root-Walk liefert Kandidaten, aber Eintrag nur wenn Datei regular+executable und (Paket-Ownership ODER explizit in AllowPaths) — dokumentierte Vertrauensquelle; Dev-Roots fließen nicht ein.
Plan: `{Enabled, Mode uint8, Flags, Entries[]{Path, Dev, Ino, CtimeNS, Action, Flags}, Scopes[]{CgroupID, Mode, Flags}, Fingerprint}`; Caps; deterministisch sortiert; `fingerprint` SHA-256. Kern-Identität ermittelt der **Core** beim ADD/Batch (fd-sicher); Go liefert Pfade, nicht dev/ino. `Compile(ctx)` mit bounded Zeitaufwand; Fehler ⇒ Plan-Fehler (kein Teil-Sync).
Hinweis: Dateien in `ExecRoots` mit Symlink/Verzeichnis-Anteil werden übersprungen (kein stiller Follow); Rejected-Count im Plan sichtbar.

### 7.3 Syncer — `control/titan_exec_syncer.go` (+ `_status.go`)
Eigenständig laufender Syncer (`Run(ctx)`, 10 s Retry, Versions-/Epoch-Check, Steady-State-Fingerprint-Skip), Muster `styxPolicySyncer`. Reihenfolge fail-safe (§5). Status `TitanExecSyncStatus`: `state ∈ applied|pending|failed|inactive|unavailable|capability-missing`, `capability`, `epoch`, `enabled/mode`, `path=bpf-lsm|none`, `lsm`, `offsets`, `entries/scopes`, `applied_entries`, `last_error` (bounded), Retry. `ErrTitanExecUnavailable`-Sentinel bei unknown command. Capability-Missing ist Fakt, kein XDR-Degraded. `ApplyRuntimeSettings`-Hook ruft `Configure` (asynchron).

### 7.4 Events/Integration — `control/titan_exec_events.go` + `control/xdr.go`
- IPC-Client + Parser `parseCoreTitanExecEvents` (Alles-oder-Nichts, ≤8, 16 Felder, Bounds, keine Panics), Fuzz-Target `FuzzCoreTitanExecParser` + Makefile.
- Poll im bestehenden 100 ms-Tick (1 s Rate-Limit, 10 s Backoff); `ErrTitanExecUnavailable` ⇒ `capability-missing`; andere Fehler ⇒ `noteVerificationFailure("titan_exec_sensor", …)` erst bei Wiederholung (2-Treffer-Schwelle), nur wenn enabled.
- Pro Event: Evidence zuerst (`state.RecordEvidence`, Kind `titan.exec.denied|titan.exec.audited`, Target `dev:ino`, Severity high/critical, **ohne Pfad wenn unbekannt**) → Dedupe (`claimFingerprint` pid+start? Event hat keine start_ticks; nutze pid+dev+ino+hook+action+ts-Bucket) → `appendIncident` mit RuleIDs `TITAN.EXEC_DENIED`/`TITAN.MMAP_DENIED`/`TITAN.EXEC_AUDIT`, Categories `execution`, `Decision:"deny-exec"` bei action=DENY (Kernel hats bereits blockt) sonst `Outcome:"audited, not blocked"`, `CellCgroupID` setzen ⇒ bestehender CellGuard/Response greift. Keine neue Response-Route; kein Doppel-Freeze. Pfad-Anreicherung best-effort über `/proc/<pid>/exe` (readlink, bounded) oder `unknown`.
- Status/API: `GET /api/v1/titan/exec/status` (read-only, auth, bounded), optional `GET /api/v1/titan/exec/events?limit=`; `/api/v1/status` additiv `titan_exec`; bestehende Titan-Routen unverändert. `state.go`-Snapshot additiv.

### 7.5 P3-Fix (gleicher Change): Status-Ehrlichkeit
`cell_lsm_attached` im Core nur bei aktiver LSM-Liste; Go-Status zeigt `cell_lsm=inactive` statt `bpf-lsm-cell`, XDR-Sensor-Mode entsprechend; keine bestehenden Tests abschwächen. (Die P3-Spec-§13 wird um diesen Punkt ergänzt.)

## 8. Fail-Safe-/Boot-Vertrag

| Situation | Kernel-Hook | Core/Gate-Status | Go/Response |
|---|---|---|---|
| LSM nicht aktiv (Server heute) | nicht attached (oder attached wirkungslos) | `inactive`, `path=none`, kein Attach-Claim | kein Incident durch Kernel; Status sichtbar; keine Enforcement-Behauptung |
| BTF fehlt/kaputt/Offsets oder ctime-Layout unplausibel | nicht attached | `unavailable`, `offsets=invalid` | wie oben |
| Default-Settings (off) | Hooks erlauben sofort | `state=applied, mode=off` | keine Events/Aktionen |
| Leere Map/Map-Verlust (Core-Restart) | Hooks erlauben (Fail-safe) | `pending`/Mode off bis Resync | dokumentiertes ≤10 s Fenster |
| Mode>0, LSM inaktiv | kein Attach; SET_GLOBAL ⇒ ERR `enforcement-unavailable` | `failed`/`inactive`, kein `applied` | kein Claim |
| Read-Fehler im Hook | allow (fail-safe), Zähler+Event | Health steigt; bei Wiederholung degraded nur für dieses Modul | ehrlicher Zustand |
| Evidence-Ledger down | Kernel blockt ggf. weiter | Incident journalisiert, Response nur mit Evidence (bestehender Vertrag) | keine Response-Behauptung |

Boot-/Recovery: Default off, keine automatischen Map-/Cmdline-Änderungen; Aktivierung nur Operator mit `lsm=…,bpf` + Reboot + Rettungs-Kernel; `--require-bpf-lsm` (Opt-in) macht fehlende Aktivierung zum Startfehler.

## 9. Testplan (verbindlich)

1. **Rust common:** 88-Byte-`size_of`/`offset_of`-Asserts, Decoder-Accept/Reject-Matrix (§3.2), Text-Wire-Encoding, Fuzz-Bin optional.
2. **Rust BTF-Parser:** synthetische BTF-Fixtures; golden Offsets für 6.18/7.0 (Werte §4.1) als Testdaten/Kommentar; anonyme Union/Bitfield/Truncation/Magic-Fehler ⇒ `Err`; FUNC_PROTO-nargs. **ctime:** Split-/Legacy-Fixtures (nsec-Width 4/8 akzeptiert, 2 ⇒ `Err`) und Real-BTF-Host-Test `titan_btf_live_vmlinux_resolves_all_offsets` (Live-BTF WSL 6.18 grün, alle Offsets inkl. Split-ctime; SKIP nur wenn `/sys/kernel/btf/vmlinux` fehlt — kein stilles Bestehen).
3. **Core:** Offset-Validierung, STATE-/OFFSETS-Map-Seed (Fake-Maps schwer testbar → reine Encoder/Validator-Funktionen), Pfad-Resolver (Symlink/Hardlink/Non-Regular/TOCTOU-Ersatz), Batch-Caps/Decode, Event-Encoding/Drain-Grenzen, DELETE idempotent, Status-/Health-Format, P3-LSM-Aktivierungsfix (Funktion `bpf_lsm_active_from_list` mit CSV-Fixtures: bpf vorhanden/fehlend/mehrfach/Whitespace).
4. **eBPF:** Nightly-Build Exit 0 (`bpfel-unknown-none`, `-Z build-std=core`), readelf-Section/Symbole (`lsm/bprm_check_security`, `lsm/mmap_file`, neue Maps), keine Verhaltensänderung bestehender Programme; Verifier-Load nur auf aktiviertem Testkernel (dokumentiert NOT_TESTED in dieser Umgebung).
5. **Go:** Settings-Validate/Defaults/Migration/Inert-Reject/Caps (Inert-Verbot nur bei `enabled=true, mode=off` + Regeln; disabled Entwurf zulässig); Plan-Compiler (Roots, Symlinks, Hardlinks, Dedupe, Caps, deterministischer Fingerprint); Syncer-Reihenfolge (Global-off zuerst), Disable, capability-missing, fake-core (unknown command/ERR/MAC-Fehler); Event-Parser (gültig + ≥8 hostile Fälle + All-or-Nothing + Fuzz, roher/hostiler `comm` akzeptiert: `TestParseCoreTitanExecEventsAcceptsRawKernelComm`, `TestTitanExecHostileCommDoesNotSuppressBatch`); XDR-Integration (Incident genau einmal, Evidence-first, degraded/observe ⇒ keine Response, CellCgroupID gesetzt); API/Auth/Replay; Statusehrlichkeit P3 (`inactive` statt Attach).
6. **Adversarial (Reviewer):** Symlink/Hardlink/TOCTOU, Inode-Recycling (ctime-Mismatch), leere Map/Settings-Default (keine Verhaltensänderung), JIT-Scope missbraucht nicht Exec, Strict ohne Allowlist, Boot-Lockout-Vertrag, P3-Silent-LSM-Fix, ABI-Treue eBPF↔Core↔Go.
7. **Gates:** `go test ./...`, `go vet`, Rust common/core Tests, Nightly-eBPF-Build, `security-audit.sh` (Anker erweitern), `node --check`, `install-smoke.sh`, Datei-≤500-Zeilen-Regel für neue Dateien.

## 10. Datei-Ownership / Phasen

| Task | Owner | Write-Scope | Depends |
|---|---|---|---|
| P1-T1 | Rust-Common-Agent | `rust/gedefense-common/src/titan_exec.rs` (neu), `src/lib.rs` (Re-Export) | — |
| P1-T2 | Go-Settings/Sync-Agent | `control/titan_exec_settings.go`, `titan_exec_plan.go`, `titan_exec_syncer.go`, `titan_exec_syncer_status.go` (neu), `control/coreipc.go` (additiv), `runtime_settings.go`, `fabric_settings.go`, `fabric_schema.go`, `server_settings.go` | Spec |
| P1-T3 | Rust-Core-Agent | `rust/gedefense-core/src/btf_offsets.rs`, `src/titan_exec.rs` (neu), `main.rs` (additiv), P3-LSM-Aktivierungsfix | T1 |
| P1-T4 | eBPF-Agent | `rust/gedefense-ebpf/src/main.rs` | T1 |
| P1-T5 | Go-XDR-Agent | `control/titan_exec_events.go` (neu), `control/xdr.go`, `xdr_types.go`, `state.go`, `server.go`, `security_fuzz_test.go`, `Makefile` | T2, T3 (ABI fest) |
| P1-T6 | Gates/Doku-Agent | `scripts/security-audit.sh`, `docs/POINT1-TITAN-EXEC-GATE.md`, `docs/POINT1-PHASE1-REPORT.md` (neu), `docs/POINT3-EGRESS-BEACON.md` (§13 P3-Fix), `ARCHITECTURE.md` | T1–T5 |
| P1-T7 | Verifier | read-only adversarial | T6 |

## 11. Betriebs-/Aktivierungshinweise (Phase 1)

- **Default nach Update:** `titan_exec.enabled=false, mode=off` ⇒ Kernel-Verhalten unverändert; Hooks (falls LSM aktiv) erlauben sofort.
- **Aktivierung:** (1) Kernel-Cmdline `lsm=<aktuell aktive Liste>,bpf` (Server aktuell: `lockdown,capability,landlock,yama,apparmor,ima,evm`; exakte Reihenfolge vorher per Test-Reboot verifizieren, Rettungs-Kernel bereithalten) + Reboot; (2) `titan_exec.enabled=true, mode=observe` → Audit-Events/Health beobachten; (3) Allowlist planen (STRICT erfordert vollständige Roots); (4) `mode=contain`/`strict` nur zellweise (`StrictCgroups`) nach Evidenz. Ohne Schritt (1) bleibt der Status ehrlich `inactive` und es gibt **keine** Wirkung.
- **STRICT-Risiko:** Vollständige Allowlist nötig (sonst Exec-/SSH-Lockout in der Zelle); Fail-safe: Global-off zuerst, Cell-Scope nur nach explizitem Setzen; Notfall: Settings `enabled=false` (Settings-API bleibt erreichbar) und Core-Restart leert Maps.
- **Grenzen:** kein `file_mprotect`/W^X-Transitionen, kein fs-verity-Enforcement, anonymer JIT nur per Scope-Ausnahme, Events ohne Pfad, Overlayfs-Copy-up, Inode-Recycling nur über ctime-Mitigation, kein Live-Verifier-Test in dieser Umgebung.

## 12. Definition of Done (Phase 1)

- ABI (§3–§5) implementiert; eBPF-Build + Rust-/Go-Tests grün; Gates (§9.7) grün; keine bestehende Assertion abgeschwächt.
- Default-Off-Upgrade verändert Verhalten nicht (Test/Review).
- LSM-Aktivierungsstatus ist ehrlich (P1 neu + P3-Fix), inkl. Tests für aktive/inaktive Liste.
- Adversarialer Review ohne offene FAIL-Befunde; Restrisiken/Aktivierung in Spec und Phase-1-Report dokumentiert.

**Stand 2026-11-15:** DoD-Punkte 1–3 sind belegt (`docs/POINT1-PHASE1-REPORT.md` §5; `bash scripts/security-audit.sh` Exit 0 mit 26 PASS, P1-Anker inkl. ELF-Gate). **P1-T7-Review (read-only, 2026-11-15): PARTIAL, kein offener FAIL** — die zwei Befunde (ctime-BTF-Split, comm-Härtung) sind behoben und testbelegt (§13.13/§13.14), eine Präzisierung ist dokumentiert (§13.15); core 83 Tests, Real-BTF-Host-Test grün. Verbleibende Restrisiken und der Aktivierungsblocker sind in §11/§13 dokumentiert; nächster Schritt ist Punkt 2 (ephemere Parser-Zellen).

## 13. Umsetzungsabweichungen/Präzisierungen (Phase 1, 2026-11-15)

Diese Sektion hält fest, wo die Phase-1-Implementierung die Spec präzisiert oder
abweicht. Sie ist beschreibend, keine nachträgliche Abschwächung: ABI-1/2/3
(Wire-Layout, Map-Namen, VGT3-Kommandos) wurden eingehalten, sofern unten nichts
anderes steht. Maßgeblich ist der Code, nicht die Prosa.

1. **`TITAN_EXEC_MODE`-Value = `(mode<<2) | scope-flags`.** Der Core validiert
   `mode ∈ 0..3` und lehnt Scope-Flags außer Bit0 (`JIT_ALLOW`) ab
   (`rust/gedefense-core/src/main.rs` `encode_titan_exec_scope_value`); das eBPF liest
   Mode als `(value >> 2) & 0x3` und JIT_ALLOW als `value & 1`
   (`rust/gedefense-ebpf/src/main.rs`). Das globale `TITAN_EXEC_STATE`-Wort packt den
   Mode dagegen ungeshiftet in Bits 32..39 (kein `<<2`); beide Kodierungen sind
   bewusst unterschiedlich und durch Tests gepinnt.
2. **`TITAN_EXEC_POLICY`-Value exakt:** `action u8 @0` (nur ALLOW=1),
   `flags u8 @1` (Bit0 REQUIRE_CTIME), reserved `u16 @2`, `ctime_ns u64 LE @4..12`,
   Rest-NUL. Der ctime-Wert entsteht aus `fstat` `ctime()*1e9 + ctime_nsec`. Das
   REQUIRE_CTIME-Flag aus `TITAN_EXEC_SET_GLOBAL` wird in alle Einträge gespiegelt
   (Bestandseinträge werden umgeschrieben) und zusätzlich als STATE-Bit2 geführt.
3. **Event-`f_flags` ist Phase 1 immer 0.** Das Offset-Enum (§4.1) enthält keinen
   `file.f_flags`-Offset; das eBPF schreibt das Feld explizit 0 und der Decoder
   interpretiert es nicht. Es bleibt für eine spätere ABI-Erweiterung reserviert.
4. **Null-Identität nur in den zwei dokumentierten Ausnahmen.** `dev==0|ino==0` ist
   ausschließlich gültig für (a) `READ_FAILURE`+`AUDIT` und (b) `MMAP`+`ANON_NO_JIT`
   mit `PROT_EXEC`; der 88-Byte-Decoder in `rust/gedefense-common/src/titan_exec.rs`
   und der Go-Parser `parseCoreTitanExecEvents` setzen dieselbe Matrix durch
   (Reject statt Reparatur; keine halbe Identität, keine erfundene Null-Identität).
5. **Mini-BTF-Parser ist Little-Endian-only.** `rust/gedefense-core/src/btf_offsets.rs`
   dekodiert BTF-Header/Typen ausschließlich mit `u16/u32/u64::from_le_bytes` (max.
   64 MiB, Version 1, `hdr_len == 24`, rekursive anonyme Unions, Tiefenlimit 16).
   Andere Endianness wird nicht unterstützt; jeder Parserfehler ⇒ `Err` ⇒
   `offsets=invalid` ⇒ kein Attach (keine Heuristik, keine Attrappe).
6. **Attach nur bei exakt unterstützter Hook-Arität.** `titan_exec_offsets_match_ebpf_slots`
   (`rust/gedefense-core/src/main.rs`, ca. Z. 860; die BTF-Plausibilitätsprüfung in
   `btf_offsets.rs` bleibt bei nargs ∈ {1, 3..=5}) fordert
   `bprm_nargs == 1` und `mmap_nargs == 4` (sowie file=0/prot=2/flags=3, Retval-Slots
   1/4). Weicht die BTF-Auflösung ab, bleibt der Gate-Status `unavailable`
   (`offsets=valid`, aber kein Attach, Log „hook arity ... is not supported“) — es
   wird nie ein Programm mit falschen Slots geladen. §4.1 nannte diese Prüfung
   „plausibel“; die Implementierung ist strenger (exakt).
7. **Dev-Roots sind nicht Kernel-enforced.** `titan_exec.dev_roots` wird akzeptiert
   und dokumentiert, fließt aber nicht in Plan/Allowlist ein; eine Kernel-Freigabe
   gibt es dafür nicht (§7.1/§7.2). Explizite Ausnahmen nur über `allow_paths`.
8. **Kein Live-Verifier-/Attach-Test in dieser Umgebung.** Belegt sind der
   Nightly-eBPF-Build (`bpfel-unknown-none`, `-Z build-std=core`, Verifier-Gate),
   die `readelf`-Prüfung von Sektionen (`lsm/bprm_check_security`, `lsm/mmap_file`)
   und Map-/Programm-Symbolen sowie seit dem T7-Fix die **echte Live-BTF-Auflösung**
   (`titan_btf_live_vmlinux_resolves_all_offsets`, WSL 6.18 grün, inkl. ctime-Split).
   Ein echter `bpf()`-Load/Attach und ein Verifier-Ergebnis auf einem aktivierten
   Kernel bleiben Operator-Integrationstest.
9. **Aktivierungsbefund bei Standard-Ubuntu-Kerneln (kritisch).** Auf Ubuntu 24.04
   ohne `lsm=...,bpf`-Bootparameter hat `CONFIG_BPF_LSM=y`, BTF + `bpftool`, aber
   `/sys/kernel/security/lsm` = `lockdown,capability,landlock,yama,apparmor,ima,evm`
   (kein `bpf`), `CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"` und kein
   `lsm=` in `/proc/cmdline`. Ein `attach()` liefert dort Erfolg **ohne Wirkung**
   (Stubs werden nie aufgerufen). Die Implementierung prüft deshalb das
   `bpf`-Token **vor** jedem Attach: ohne Token wird nicht attached, der Status ist
   `inactive`/`path=none`, `TITAN_EXEC_SET_GLOBAL mode>0` liefert
   `ERR enforcement-unavailable`, und Go setzt den Sync-State auf `inactive`
   (nie `applied`). Es gibt ohne Aktivierung **keine** Enforcement-Wirkung.
10. **P3-Socket-LSM-Claim korrigiert (gleicher Change).** `cell_lsm_attached` wird
    nur noch nach erfolgreichem Attach auf einer aktiven LSM-Liste `true`; der
    `PING`-Mode-String hängt `+bpf-lsm-cell` nur dann an
    (`if cell_lsm_attached { mode.push_str("+bpf-lsm-cell"); }`), Cell-LSM-IPC-
    Kommandos werden sonst mit „Gaia Cell BPF LSM is unavailable“ abgelehnt, und der
    Go-Sensor-Modus meldet `cell-lsm-unavailable` statt `bpf-lsm-cell`. Der frühere
    Server-Claim eines wirkungslosen Attach ist damit beseitigt.
11. **Status-/Wire-Präzisierungen:** `TITAN_EXEC_STATUS` ist eine feste
    Key-Reihenfolge (`status;mode;flags;path;lsm;offsets;entries;scopes;epoch`),
    `state ∈ applied|pending|failed|inactive|unavailable` (pending/failed vergibt nur
    die Control Plane), `TITAN_EXEC_EVENTS` ≤ 8 Records/2048 Byte (`empty` bzw.
    `<dropped>|<records>`), `TITAN_EXEC_HEALTH` = 6 Per-CPU-Zähler, Epoch = 16 Hex.
    `PING` trägt `+titan-exec:<inactive|off|observe|contain|strict>`; das
    Spec-Beispiel `audit` heißt implementiert `observe` (und ein enforcement-fähiges
    Gate mit Mode off meldet `off`, nicht `inactive`). Alles ist durch Core-Tests
    (`titan_exec_health_and_status_follow_the_contract`,
    `titan_exec_event_text_wire_matches_section_three_three`) gepinnt.
12. **Aktivierungs-Runbook (Operator, nicht automatisiert):** (1) aktuelle Liste aus
    `/sys/kernel/security/lsm` ablesen; (2) exakt diese Liste plus `bpf` als
    `lsm=<liste>,bpf` in die Boot-Cmdline eintragen (Reihenfolge/Gesamtliste vorher
    auf einem Test-Reboot verifizieren; Rettungs-Kernel/Recovery-Eintrag
    bereithalten); (3) Reboot; (4) `/sys/kernel/security/lsm` muss `bpf` enthalten,
    `TITAN_EXEC_STATUS` muss `path=bpf-lsm`/`lsm=active` liefern; (5) erst dann
    `titan_exec.enabled=true, mode=observe` → Evidenz sammeln → `contain`/`strict`
    zellweise. Ohne Schritt (1)–(4) bleibt der Status `inactive` und es gibt keine
    Wirkung; die Cmdline wird niemals automatisch geändert.
13. **T7-FAIL behoben (2026-11-15): ctime-BTF-Kompatibilität (Split-Layout).** Der
    Review fand, dass moderne Kerne (6.18/7.0) im `struct inode` **kein**
    `i_ctime`-timespec64 mehr haben, sondern `i_ctime_sec` (8 B) + `i_ctime_nsec`
    (4 B). Der Core löst jetzt bevorzugt dieses Split-Layout auf (NSEC_WIDTH aus dem
    realen BTF-Feldtyp, 4 oder 8) und fällt nur bei fehlendem Split auf das
    Legacy-`i_ctime.tv_sec/tv_nsec` (8 B) zurück; die Width wird als
    `INODE_I_CTIME_NSEC_WIDTH` in OFFSETS[28] veröffentlicht. eBPF liest `sec`
    immer als u64, `nsec` gemäß Width als u32 (zero-extended) oder u64, prüft
    `tv_nsec < 1e9`, bildet `sec*1e9 + nsec` **saturierend** (kein `__multi3` auf
    dem BPF-Target) und wertet einen implausiblen Width-/Bereichsfall als
    Read-Failure (fail-safe), nie als Match. Unplausible Layouts ⇒
    `offsets=invalid` ⇒ `unavailable`, kein Attach. Tests: synthetische
    Split-/Legacy-Fixtures inkl. Width 4/8 akzeptiert und Width 2 ⇒ `Err`
    (`titan_btf_split_ctime_layout_publishes_the_nsec_width` u. a.), **Real-BTF-
    Host-Test** `titan_btf_live_vmlinux_resolves_all_offsets`: WSL-Kernel 6.18 grün
    (nicht SKIP; Live-Werte `i_ctime_sec=104`, `i_ctime_nsec=120`, Width 4,
    `inode_size=608`, übrige Golden-Werte unverändert). Die Golden-6.18/7.0-Fixtures
    im Core sind synthetisch; die Live-BTF wird zusätzlich durch den Real-BTF-Test
    abgedeckt (Doku nennt beides: „synthetisch + Real-BTF“). Kein Code-Kommentar
    wurde für diese Doku geändert.
14. **T7-Befund behoben (2026-11-15): comm-Härtung.** Der Kernel-`comm` ist über
    `PR_SET_NAME` prozesskontrolliert (beliebige Bytes außer NUL, max. 15 + Terminator).
    Der Go-Parser akzeptiert deshalb jede Hex-Folge ≤16 B und erzwingt nur die
    NUL-Padding-Form (nach der ersten NUL nur NUL); die Anzeige sanitisiert
    `sanitizeTitanExecComm` (nicht druckbar/nicht-UTF-8 ⇒ `?`, Länge wächst nie) —
    ein hostile `comm` unterdrückt keinen Event-Batch mehr. Tests:
    `TestParseCoreTitanExecEventsAcceptsRawKernelComm` (non-UTF-8, Control-Bytes,
    trailing NUL, UTF-8) und `TestTitanExecHostileCommDoesNotSuppressBatch`.
15. **T7-Präzisierung (c): Inert-Policy-Verbot nur für `enabled=true`.** Die
    Validierung lehnt `mode=off` mit Regeln nur noch ab, wenn das Namespace
    tatsächlich aktiviert ist (`if in.Enabled && mode == 0 && (ExecRoots|AllowPaths|
    DevRoots|JitCgroups|StrictCgroups nicht leer)`); ein **disabled Entwurf**
    (`enabled=false` plus Regeln) ist zulässig, weil er ausdrücklich „nichts wird
    behauptet“ bedeutet. **T7-Review-Ergebnis:** PARTIAL, kein offener FAIL; zwei
    Befunde behoben (13/14), eine Präzisierung (15). Verbleibende Restrisiken:
    kein Live-Verifier-/Attach-Test auf Produktion (nur Build + readelf + reale
    BTF-Auflösung), Aktivierungsblocker Boot-Cmdline/Reboot, Event-`f_flags`=0,
    Dev-Roots nicht Kernel-enforced, STRICT-Lockout-Risiko, Map-Verlust-Fenster.

