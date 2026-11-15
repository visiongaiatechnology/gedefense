# POINT 3 — Per-Cgroup-Egress-Enforcement & C2-Beacon-/Exfiltration-Erkennung

**Status:** IMPLEMENTIERT (Phase 1) · Implementiert 2026-11-15 · Stand 2026-11-15 · GeDefense V6 (`6.0.0`)
**Review-Regel:** Diese Datei ist der verbindliche Vertrag zwischen eBPF-, Rust-Core- und Go-Control-Anteil. Wer eine ABI (Wire-Format, Map-Layout, IPC-Kommando) ändert, ändert zuerst diese Datei und informiert alle Task-Owner.

## 1. Ziel und Leitplanken

Ziel: Styx bekommt **echtes Kernel-Enforcement** pro Cgroup (Default-Deny-Modus opt-in) plus die **Kern-Telemetrie**, die für die Erkennung von C2-Beacons/Exfiltration nötig ist. Der Go-Teil erhält einen neuen Detektor (`control/styx_beacon.go`) und koppelt High-Confidence-Funde an XDR-Response und CellGuard.

Unverhandelbare Leitplanken:

1. **Privilege Split:** Kernel-/Map-/Attach-Arbeit ausschließlich im Rust-Core (`rust/gedefense-core`) und eBPF (`rust/gedefense-ebpf`). Go (`control/`) bleibt unprivilegiert und spricht nur VGT3/IPC.
2. **Fail-closed, aber kein Lockout:** Der Kernel blockt nur, wenn ein Modus ausdrücklich `enforce`/`default-deny` ist. Standard nach Update ist **`off`** (Telemetrie aus, Verhalten unverändert). `monitor` ist Telemetrie ohne Block; `enforce`/`default-deny` ist Operator-Entscheidung pro Cgroup bzw. global. Bei fehlendem Map-Inhalt/Kernel-Hook: keine erzwungene Behauptung, Status `unavailable`/`degraded`, nie stilles „OK".
3. **Kein Per-Paket-Flooding:** Flow-Events werden im Kernel pro Flow **aggregiert** und gebündelt emittiert (Epoch-/Byte-/Paket-Schwellen). Es gibt **keinen** Rohdump pro Paket. Ring-/Map-Drops werden gezählt und als Sichtbarkeitsverlust gemeldet.
4. **Reverse/forensisch:** Enforcement hinterlässt Events im XDR/Evidence-Pfad; es werden keine Dateien gelöscht. Responses sind über bestehende ResponseEngine/CellGuard reversibel (TTL/Reverse).
5. **Kein stilles Enforcement ohne Evidence:** Aktive Go-Response nur nach `RecordEvidence` und nie im `degraded`- oder `observe`-XDR-Modus (bestehender Vertrag, vgl. `xdr.go respond()`).
6. **Keine Attrappen:** Neue Fähigkeiten werden über ein Capability-Kommando ausgehandelt. Ein alter Core ohne die neuen Kommandos darf Go **nicht** crashen, sondern führt den Sensor als `unavailable/capability-missing` und zählt das.

## 2. Geltungsbereich Phase 1

| Bestandteil | Phase 1 | Später (Phase 2+) |
|---|---|---|
| eBPF | `cgroup_skb/egress` Enforcement mit Per-Cgroup-Modi, Allow-/Block-/Resolver-LPMs, Global-Mode, Resolve-Cache, Flow-Aggregation + RingBuf, IPv4-mapped-v6-Bypass-Schutz, IPv6-Ext-Header bounded, ND-Ausnahme | `cgroup_skb/ingress` rx-Zähler, `cgroup_sock_addr`-Connect-Hook für Direct-IP/DNS-Attribution, Per-Socket-Tracking, Tracepoint-Enrichment |
| Rust-Core | Map-Handles/Attach, Policy-Sync-Kommandos (Mode/Allow/Block/Resolver/Global), Kernel-Seed der Pflicht-Blockliste, Epoch, Flow-Event-Drain + Text-Wire, Health-Zähler | BTF/CO-RE Start-Ticks, TLS-ClientHello-Metadaten (ohne Payload), flow-basierte State-Machine im Core |
| Go-Control | IPC-Client + Parser + Capability-Gate + 10s-Backoff, `styx_beacon.go` (3 Signale, Aggregation, Dedupe, TTL, LRU), XDR-DAG/Incident/Response, CellGuard-Anbindung, Settings/API/Status, Tests | UI-Panels, automatische Policy-Empfehlungen aus Feed-ThreatIndex, Cross-Host-Witness (Punkt 4) |

Nicht-Ziele Phase 1: DoH-Resolver-IP-Listen, vollständige DNS-Attribution, X11/Wayland-Isolation, ephemere Parser-Zellen (Punkt 2), Lockdown (Punkt 5), Witness (Punkt 4).

## 3. ABI-1: Gemeinsame Wire-Typen (`rust/gedefense-common/src/lib.rs`, Go-Spiegel in `control/coreipc.go`)

Native Endian, `repr(C)`, feste Längen, Reject statt Reparatur (Doktrin wie `decode_ingress_event`).

### 3.1 Konstanten

```
STYX_FLOW_EVENT_WIRE_BYTES = 104
STYX_PROTO_TCP = 6, STYX_PROTO_UDP = 17 (0 = neutral/unbekannt)
STYX_DIR_EGRESS = 1, STYX_DIR_INGRESS = 2 (0 = unbekannt)
STYX_VERDICT_ALLOW = 0
STYX_VERDICT_AUDIT_DROP = 1      # monitor-Modus: wäre geblockt worden
STYX_VERDICT_DROP = 2            # enforce: geblockt (Policy)
STYX_VERDICT_METADATA_VETO = 3   # Pflicht-Veto (Metadata/LinkLocal/Multicast)
STYX_VERDICT_DNS_PIN = 4         # DNS/DoT-Pinning verletzt
STYX_VERDICT_DEFAULT_DENY = 5    # Default-Deny ohne Allow-Treffer
STYX_MODES: OFF=0, MONITOR=1, ENFORCE=2 (Bits 0..2 in Mode-Flags)
STYX_FLAG_DNS_RESOLVER = 1<<3    # Cgroup darf 53/853 nach außen
STYX_FLAG_ALLOW_METADATA = 1<<4  # nur für explizite Host-Scopes, Default 0
STYX_FLAG_ALLOW_HOST_ALLOWLIST = 1<<5  # Cgroup darf die globale Host-Allowlist nutzen
STYX_FLAG_LOG_FLOWS = 1<<6       # Flow-Telemetrie für diese Cgroup aktiv
```

### 3.2 `FlowEvent` (Wire-Byte-Layout, exakt)

| Offset | Größe | Feld | Semantik |
|---:|---:|---|---|
| 0 | 8 | `cgroup_id` u64 | skb-Cgroup (Socket-Cgroup; Zell-/Leaf-Cgroup nach Ancestor-Auflösung im Kernel gecachet) |
| 8 | 8 | `ts_ns` u64 | `bpf_ktime_get_ns()` beim Emit, monoton |
| 16 | 8 | `tx_bytes` u64 | aggregiert, saturierend |
| 24 | 8 | `rx_bytes` u64 | Phase 1 = 0 (nur egress-Hook), Phase 2 befüllt |
| 32 | 4 | `pid` u32 | Prozess-PID (nur beim ersten Paket des Aggregats gesetzt) |
| 36 | 4 | `uid` u32 | `bpf_get_socket_uid` |
| 40 | 16 | `dst` [u8;16] | Zieladresse; IPv4 in den letzten 4 Byte, davor 0 |
| 56 | 16 | `src` [u8;16] | Quelladresse |
| 72 | 2 | `dst_port` u16 | Host-Order gespeichert (native endian wie Struct) |
| 74 | 2 | `src_port` u16 | Host-Order |
| 76 | 4 | `packets` u32 | aggregierte Pakete |
| 80 | 1 | `proto` u8 | 6/17/0 |
| 81 | 1 | `family` u8 | 4/6 |
| 82 | 1 | `direction` u8 | 1 egress (Phase 1), 2 ingress |
| 83 | 1 | `tcp_flags` u8 | OR der TCP-Flags; 0 wenn kein TCP |
| 84 | 1 | `verdict` u8 | 0..5 (siehe Konstanten) |
| 85 | 3 | `reserved` [u8;3] | 0 |
| 88 | 16 | `comm` [u8;16] | NUL-gepolstert |

Decoder-Vertrag (`decode_styx_flow_event(bytes) -> Option<FlowEvent>`):
- `len == 104`, `family ∈ {4,6}`, `proto ∈ {0,6,17}`, `direction ∈ {1,2}`, `verdict ≤ 5`, `packets > 0`, `ts_ns > 0`;
- `proto != 6 ⇒ tcp_flags == 0`; `family == 4 ⇒ bytes[40..52] == 0` (kanonisch), IPv4-Adresse nicht 0.0.0.0;
- `dst_port/src_port` bei proto 0 müssen 0 sein (neutraler Marker); UDP/TCP dürfen 0 nicht für dst haben? **Ausnahme:** ICMPv6 ND hat keine Ports ⇒ proto 58 mit ports=0 nur intern im Kernel; Wire sendet proto 0/ports 0 für Nicht-TCP/UDP. Regel: `proto == 0 ⇒ dst_port == 0 && src_port == 0`.
- Ungültige Records ⇒ `None`; Core überspringt sie und zählt `FLOW_REJECTED` (kein Drain-Abbruch, kein Degradieren beim ersten Fehlschlag).

### 3.3 Text-Wire (IPC `STYX_FLOW_EVENTS`)

Antwort-Payload: `empty` **oder** `<dropped>|<record>[,<record>…]` (max. 12 Records; `dropped` = saturierender U64-Zähler). Record-Felder `:`-getrennt in fester Reihenfolge:

```
cgroup_hex:ts_dec:tx_dec:rx_dec:pid_dec:uid_dec:dst_hex:dst_port_dec:src_port_dec:packets_dec:family_dec:proto_dec:direction_dec:tcp_flags_dec:verdict_dec:comm_hex
```

- `cgroup_hex` = 16 Hex-Zeichen (kein `0x`), `comm_hex` = ≤32 Hex-Zeichen (max 16 Byte).
- Ports/Bytes/Pakete dezimal, saturierend.
- Go-Parser: Alle-oder-Nichts pro Batch (ein ungültiger Record ⇒ Batch verworfen, Zähler `parse_errors`; nie Teilzustand), strenge Limits: ≤12 Records, ≤2048 Payload-Bytes, keine NUL/Leerzeichen in Feldern.
- `dropped > 0` ⇒ Go-Event `xdr.styx_flow_overflow` + Counter; wiederholter Overflow (≥3 Polls) ⇒ `beacon_sensor=degraded` (Sichtbarkeitsverlust), nie stilles OK.

## 4. ABI-2: eBPF-Maps (`rust/gedefense-ebpf/src/main.rs`)

Aya-0.14-Regel: Keys/Values als Byte-Arrays (`[u8; N]` ist Pod) statt lokaler Structs ohne `unsafe impl Pod`, wo unsicher.

| Map | Typ | Key | Value | max_entries | Flags |
|---|---|---|---:|---:|---|
| `CELL_EGRESS_MODE` | HashMap | cgroup_id u64 (Pod) | u8 = Mode-Flags (Bits s.o.) | 4096 | BPF_F_NO_PREALLOC |
| `CELL_EGRESS_ALLOW_V4` | LpmTrie | `[u8;16]` = [cgroup LE 8][addr 4][dst_port BE 2][proto 1][pad 1] | u8 = 1 | 65536 | BPF_F_NO_PREALLOC |
| `CELL_EGRESS_ALLOW_V6` | LpmTrie | `[u8;24]` = [cgroup LE 8][addr 16] + port/proto wie v4 (in den 24 Byte: 8+16=24, Port/Proto **nicht** enthalten ⇒ v6-Port-Regeln siehe Hinweis) | u8 = 1 | 65536 | BPF_F_NO_PREALLOC |
| `STYX_ALLOW_GLOBAL_V4` | LpmTrie | `[u8;8]` = [addr 4][dst_port BE 2][proto 1][pad 1] | u8 = 1 | 16384 | BPF_F_NO_PREALLOC |
| `STYX_ALLOW_GLOBAL_V6` | LpmTrie | `[u8;20]` = [addr 16][dst_port BE 2][proto 1][pad 1] | u8 = 1 | 16384 | BPF_F_NO_PREALLOC |
| `STYX_BLOCK_V4` | LpmTrie | `[u8;4]` (addr) | u8 = 1 | 4096 | BPF_F_NO_PREALLOC |
| `STYX_BLOCK_V6` | LpmTrie | `[u8;16]` (addr) | u8 = 1 | 4096 | BPF_F_NO_PREALLOC |
| `STYX_RESOLVER_V4` | LpmTrie | `[u8;4]` | u8 = 1 | 256 | BPF_F_NO_PREALLOC |
| `STYX_RESOLVER_V6` | LpmTrie | `[u8;16]` | u8 = 1 | 256 | BPF_F_NO_PREALLOC |
| `STYX_GLOBAL` | Array | — | u64 = epoch(low 32) | flags<<32 | mode<<40 | 1 | — |
| `STYX_RESOLVED` | LruHashMap | skb-cgroup u64 | `[u8;16]` = [cell_cgroup LE 8][epoch LE 4][mode+flags 2][pad 2] | 16384 | — |
| `FLOW_AGG_V4` | LruPerCpuHashMap | `[u8;16]` = [cgroup 8][peer 4][peer_port BE 2][proto 1][pad 1] | `[u8;40]` = [first_ts 8][last_ts 8][tx 8][packets 4][pid 4][tcp_flags 1][verdict 1][reserved 6] | 4096 | — |
| `FLOW_AGG_V6` | LruPerCpuHashMap | `[u8;32]` = [cgroup 8][peer 16][port 2][proto 1][pad 1] | wie v4 | 4096 | — |
| `FLOW_EVENTS` | RingBuf | — | FlowEvent (104) | 4 MiB | — |
| `FLOW_EVENTS_EMITTED`, `FLOW_RING_DROPS`, `FLOW_AGG_INSERT_FAILURES`, `EGRESS_PARSE_ERRORS`, `EGRESS_DROPS_TOTAL`, `EGRESS_POLICY_DROPS` | PerCpuArray | 0 | u64 | 1 | — |

Präfix-Konventionen (LPM-Trie; `prefix_len` zählt Bits ab dem ersten Key-Byte):
- cell-v4: `64` = Cgroup-weit beliebiges Ziel (Allow-All), `64+bits` = Cgroup+IP-CIDR, `96+16` = +Port-BE exakt, `112+8` = +Proto exakt (max 120).
- cell-v6: `64`/`64+bits` (max 192). **Phase-1-Hinweis:** v6-Key enthält keinen Port/Proto-Slot; Port/Proto-genaue v6-Regeln werden als CIDR-Regeln mit Port 0 (alle Ports) angelegt. Das ist dokumentierte Grenze; Phase 2 erweitert den Key auf 32 Byte.
- global-v4: `32` = beliebiger Port/Proto, `48` = +Port exakt, `56` = +Proto exakt (max 56).
- global-v6: `128`/`144`/`152` (max 152).
- Block/Resolver: reine IP-Präfixe (4..32 bzw. 8..128).

**Wichtig:** Der Pflicht-Veto-Block wird vom Core beim Start aus der eingebauten Liste geseedet (169.254.0.0/16, 100.100.100.200/32, 168.63.129.16/32, 192.0.0.192/32, fd00:ec2::254/128, fe80::/10, ff00::/8, 0.0.0.0/8, 224.0.0.0/4). 127/8 und ::1 sind **nicht** im Veto (Loopback muss funktionieren). ND-Ausnahme: IPv6 + ICMPv6 (proto 58) + Typ 135/136 (NS/NA) wird vom fe80-Veto ausgenommen.

## 5. ABI-3: VGT3-Kommandos (Rust-Dispatch + Go-Client)

Format wie bestehend (`VGT3 ts nonce CMD args… mac`; Felder ohne Leerraum; ≤16 Felder; Payload ≤2048 B base64url). Unbekannte Kommandos ⇒ `ERR unknown command` (rückwärtskompatibel).

| Kommando | Argumente | OK-Payload |
|---|---|---|
| `STYX_VERSION` | — | `styx-v1` |
| `STYX_EPOCH` | — | 16 Hex-Zeichen (random pro Core-Start) |
| `STYX_GLOBAL` | `mode` (0..2), `flags` (u8; `LOG_FLOWS`=1<<0 als Bit) | `applied` |
| `STYX_MODE_SET` | `cgroup_id` (dec), `mode` (0..2), `flags` (u8) | `applied` |
| `STYX_MODE_DEL` | `cgroup_id` | `deleted` |
| `STYX_ALLOW_ADD` | `family` (4/6), `scope` (`cell`/`global`), `cgroup_id` (dec, 0 bei global), `cidr` (`ip` oder `ip/len`), `port_lo` (0..65535), `port_hi` (0..65535), `proto_mask` (0=alle,1=TCP,2=UDP,3=TCP+UDP) | `added` |
| `STYX_ALLOW_DEL` | wie ADD | `deleted` |
| `STYX_BLOCK_ADD` / `STYX_BLOCK_DEL` | `family`, `cidr` | `added`/`deleted` |
| `STYX_RESOLVER_ADD` / `STYX_RESOLVER_DEL` | `family`, `cidr` | `added`/`deleted` |
| `STYX_FLOW_EVENTS` | — | Text-Wire (3.3) oder `empty` |
| `STYX_FLOW_HEALTH` | — | `emitted:ring_drops:agg_insert_failures:parse_errors:drops_total:policy_drops` (dezimal) |

Validierungsregeln (Core, hart): Family nur 4/6; CIDR kanonisch (Hostbits 0); prefix-Längen gültig; `port_lo <= port_hi`; proto_mask ≤3; mode ≤2; flags nur bekannte Bits; cgroup_id ≠ 0 bei scope=cell; alle Felder ohne Leerraum/NUL. Fehler ⇒ `ERR` mit klarer Meldung, **keine Teiländerung** (erst validieren, dann Map schreiben). Map-Fehler ⇒ `ERR`; Go behandelt das als Sync-Fehler (Retry mit Backoff, Event, Degraded-Pfad).

Resync-Vertrag: Go merkt sich `epoch`. Core-Neustart ⇒ neue Epoch ⇒ Go pusht nach `STYX_VERSION`/`STYX_EPOCH` alle Policies erneut (Voll-Sync idempotent). Bis dahin keine Enforcement-Behauptung.

## 6. eBPF-Entscheidungspipeline (geordnet)

1. `STYX_GLOBAL` lesen (Array, ein Wert). Ist `mode == OFF` und `LOG_FLOWS == 0`: Verhalten identisch zu 5.2.0 (`return 1`), kein Overhead außer einem Array-Lookup.
2. L3 parsen (`ctx.load`); Parse-Fehler: `EGRESS_PARSE_ERRORS++`; bei enforce Rückgabe `0` (DROP), sonst `1` (PASS). (Heutiger Code: immer PASS.)
3. **Bypass-Normalisierung:** IPv6-Ziel `::ffff:a.b.c.d` (bytes[0..10]==0, [10..11]==0xff) und IPv4-compatible (`bytes[0..12]==0`) werden als IPv4 geprüft (Veto/Allow/Block über V4-Maps). Sonst wäre `::ffff:169.254.169.254` ein Bypass.
4. Attribution: `cg = bpf_skb_cgroup_id(skb)`; Cache `STYX_RESOLVED` (Key cg ⇒ cell+epoch+mode). Miss: Ancestor-Walk über `bpf_skb_ancestor_cgroup_id(skb, level)` für level 0..63; erster Treffer in `CELL_EGRESS_MODE` = Zell-Cgroup; Ergebnis mit Epoch cachen. Kein Treffer ⇒ Zell-cgroup = cg, Modus = global default.
5. Flow-Beobachtung (wenn `LOG_FLOWS` an bzw. mode ≥ MONITOR): `FLOW_AGG_*` saturierend aktualisieren; Emit-Bedingungen: erstes Paket des Aggregats, Epoch-Sekundenwechsel, ≥64 KiB Byte-Delta oder ≥256 Paket-Delta; Emit in `FLOW_EVENTS` (FlowEvent mit aktuellem Verdict). Ring voll ⇒ `FLOW_RING_DROPS++`.
6. Mode `OFF`/`MONITOR` ⇒ kein Block; Verdict `AUDIT_DROP`, wenn eine enforce-Regel greifen würde (nur bei monitor relevant, für Telemetrie); `return 1` (bzw. bei echten Drops in Phase 2 nichts blocken). Verdict `ALLOW` sonst.
7. **Pflicht-Veto** (immer, auch monitor => `METADATA_VETO` Verdict, enforce blockt): `STYX_BLOCK_*`-Treffer (inkl. der geseedeten Metadata/LinkLocal/Multicast-Präfixe), außer Cgroup hat `ALLOW_METADATA` und Ziel ist kein LinkLocal/Multicast. ND-Ausnahme (siehe 4). Loopback ausgenommen.
8. **DNS-Pinning:** Transport-Ports parsen (TCP/UDP; IPv6-Ext-Header bis 4 Hops bounded; Fragmente ohne L4 ⇒ Ports 0). `dst_port ∈ {53, 853}` und Ziel nicht loopback: nur erlaubt, wenn Ziel in `STYX_RESOLVER_*` **und** (Cgroup-Flag `DNS_RESOLVER` oder global-resolver-Flag). Sonst Verdict `DNS_PIN` (enforce: DROP). DoH auf 443 ist nicht kernel-seitig erkennbar — dokumentiert; der Go-Detektor flaggt Direct-IP/DNS-freie Connects.
9. **Allow-Reihenfolge:** a) `CELL_EGRESS_ALLOW_*` (längster Präfix) ⇒ allow; b) `STYX_ALLOW_GLOBAL_*` ⇒ allow (nur wenn Cgroup-Flag `ALLOW_HOST_ALLOWLIST`); c) bestehende `ALLOWLIST_V4/V6` nur mit Flag `ALLOW_HOST_ALLOWLIST`; d) bestehende `BLOCKLIST_*` (Threat-Intel) ⇒ DROP mit bestehendem `EgressDropEvent` (Wire-Format unverändert!).
10. **Default:** Modus enforce ⇒ `len > 0`? kein Treffer ⇒ DROP (`DEFAULT_DENY`); Modus monitor ⇒ PASS. `EGRESS_DROPS_TOTAL`/`EGRESS_POLICY_DROPS` zählen.
11. Rückgabe: `0 = DROP`, `1 = PASS` (bestehende Semantik beibehalten). Bestehende Attach-/`AllowMultiple`-Verträge bleiben unverändert.

## 7. Rust-Core (`rust/gedefense-core`)

- Neue Map-Handles und Attach des bestehenden `cgroup_skb/egress`-Programms bleiben wie heute (Root-Cgroup, `AllowMultiple`); keine Änderung an `CgroupSkbAttachType::Egress`.
- Beim Start: Pflicht-Veto-Blockliste seeden (Konstante im Core), `STYX_GLOBAL` mit `mode=OFF, flags=0` initialisieren, Epoch `random_epoch()` erzeugen.
- Neue Methoden: `styx_version`, `styx_epoch`, `styx_global`, `styx_mode_set/del`, `styx_allow_add/del`, `styx_block_add/del`, `styx_resolver_add/del`, `styx_take_flow_events`, `styx_flow_health`. Validierung vor Map-Write; `Key::new(prefix, data)` für LPMs; bei `MapError::KeyNotFound` beim DELETE `deleted` (idempotent).
- `take_flow_events`: RingBuf bis `MAX_STYX_FLOW_EVENTS_PER_RESPONSE = 8` (Payload-Budget!), pro Record: Größencheck 104, Decode über `decode_styx_flow_event`, ungültig ⇒ `FLOW_REJECTED++` und überspringen (kein Drain-Abbruch!), Text-Wire erzeugen; `dropped` aus Zähler `FLOW_REJECTED`? Nein: `dropped` = `FLOW_RING_DROPS`-Delta seit letztem Poll (Core trackt letzten Stand). Bei >0 `xdr.styx_flow_overflow`-Analogie im Go.
- Health: Summe der Per-CPU-Zähler; Payload-Format fix (6 Felder).
- **Kein** neues Attach-Pinning, keine Shell/Exec-Aufrufe, keine Datei-Lesevorgänge im Enforcement-Pfad. Fehler beim Map-Write ⇒ `ERR`, Go degradiert Sensor (nicht XDR global).
- Tests in `main.rs`/Modul: Parser für alle neuen Wire-Typen, CIDR-/Port-/Proto-Validierung, Idempotenz DELETE, Health-Format, `STYX_*`-Dispatch unbekannte Args ⇒ Err; bestehende 22 Tests bleiben grün.

## 8. Go-Control — IPC + Detektor + Integration

### 8.1 `control/coreipc.go` (additiv)
- Konstanten `maxStyxFlowEventsPerResponse = 8`, `maxStyxFlowPayloadBytes = 2048`.
- Struct `CoreStyxFlowEvent` mit Feldern aus ABI-1 (IPv4 als `net.IP` 4-Byte normalisiert, IPv4-mapped bereits im Kernel normalisiert; Go prüft zusätzlich kanonisch).
- Methoden: `StyxVersion`, `StyxEpoch`, `StyxGlobal(mode, flags)`, `StyxModeSet/Del`, `StyxAllowAdd/Del`, `StyxBlockAdd/Del`, `StyxResolverAdd/Del`, `StyxFlowEvents() ([]CoreStyxFlowEvent, dropped uint64, err error)`, `StyxFlowHealth() (CoreStyxFlowHealth, error)`.
- Parser `parseCoreStyxFlowEvents(response string)`: Alles-oder-Nichts, ≤8 Records, `dropped`-Präfix, Feldanzahl 16, Hex-/Dec-/Bounds-Validierung, IPv4-4-Byte-kanonisch, IPv6 16 Byte, comm ≤16 Byte, `proto=0 ⇒ ports=0`, `proto=6` TCP-Flags erlaubt, sonst 0. Fehler ⇒ error, nie Panic. Fuzz-Target `FuzzCoreStyxFlowParser` in `security_fuzz_test.go` + `Makefile fuzz-smoke` ergänzen.
- Capability-Gate: neue Hilfsfunktion `StyxCapabilities() (string, error)`; `unknown command`-ERR ⇒ `ErrStyxUnavailable` (Sentinel), **nicht** als XDR-Degraded zählen; Backoff 10 s analog `egressRetryAfter` (`xdr.go` 810–817) im Poll-Loop.

### 8.2 `control/styx_beacon.go` (neu; max. 500 Zeilen; Kommentar-Kopf mit STATUS)
Datenmodell (Vorschlag, final im Task):
- `beaconFlowKey{cgroupID uint64; pid int; uid uint32; family uint8; proto uint8; dstIP netip.Addr; dstPort uint16}` (IPs als `netip.Addr`; IPv4/IPv6 getrennt; keine String-Keys).
- `beaconAggregate{firstSeen,lastSeen time.Time; samples int64; intervalWelfordN, intervalMean, intervalM2 float64; txBytes, rxBytes, packets uint64; tcpFlags uint8; lastVerdict uint8; lastDNSSeen bool; dnsCapabilityKnown bool; lastScore int; originVerdicts map[uint8]uint64}`.
- Bounds: `MaxTrackedBeaconFlows = 8192`, `MaxFlowsPerCgroup = 64`, `FlowTTLSeconds = 900`, `MaxIncidentsPerMinute = 6`, `DedupeSeconds = 300`.
- **Signale** (konfigurierbar, Defaults):
  1. `BEACON_PERIODICITY`: `samples >= 12`, mittleres Intervall ∈ [10 s, 3600 s], CV = stddev/mean ≤ 0.30 ⇒ Score 120 (Welford, keine History-Slices).
  2. `BEACON_EXFIL_ASYMMETRY`: `txBytes >= 524288` **und** `txBytes/rxBytes >= 8` (rx=0 ⇒ Verhältnis als ∞, aber dann nur wenn `samples>=8` und `txBytes>=1MiB` um Ein-Paket-Fehlalarme zu vermeiden); bei Korrelation mit sensiblem Pfad/Canary-Zugriff derselben Cgroup/Prozesses im Lookback 900 s (bestehender Canary-/Deception-Eventstrom) ⇒ 250.
  3. `BEACON_DIRECT_IP_NO_DNS`: `DNSSeen == false` (Capability vorhanden!) und Ziel nicht in statischer Allowlist/Resolver und `txBytes >= 65536` ⇒ Score 80. Fehlt DNS-Telemetrie (Phase 1!), Signal bleibt `unknown` und darf **nicht** feuern (kein Fake).
- Kombination: ≥2 Signale ⇒ Gesamt-Score 250, `Decision:"contain"`; sonst max-Score. Dedupe über bestehende `claimFingerprint`-Analogie (eigene Map) + TTL-Prune in `Run`-Tick (5 s).
- Emission: `XDRIncident{Severity:"CRITICAL"|"HIGH", Score/ResponseScore, PID, Process(comm), Remote, Summary ohne Secrets, RuleIDs ["STYX.BEACON.PERIODIC","STYX.EXFIL.ASYMMETRY","STYX.EGRESS.DIRECT_IP"], Categories ["command_and_control","exfiltration"], Decision:"contain", Outcome:"...", CellCgroupID:cgroup, AttackStory: nodes, EvidenceRoot}` via `IncidentSink`/`appendIncident`; `AttackStoryNode{CausalEdge: EdgeEgressAttempted, Sensor:"STYX_BEACON", EventType:"BEACON_PERIODICITY"|"EXFIL_ASYMMETRY"|"DIRECT_IP_NO_DNS", ...}` und `correlator.IngestEvent`-Muster wie `styx_egress.go:312–345`.
- Status: `Snapshot()` (bounded: Anzahl Flows, Top-N nach Score ohne IP-/Comm-PII? Operator darf IPs sehen — bounded Top 10 mit cap, keine Secrets), Counter (events, incidents, dropped, overflows, degraded), `SensorState` (unavailable wenn Capability fehlt; degraded bei Overflow-Serie).

### 8.3 Integration (`control/xdr.go`, `cell_guard.go`, `runtime_settings.go`, `fabric_settings.go`, `server.go`, `server_settings.go`)
- `XDREngine` erhält `styxBeacon *StyxBeaconEngine`; Init neben StyX (`xdr.go` 405–411); Poll im bestehenden 100ms-Tick mit eigenem 1s-Rate-Limit (`flowPollDue`) → `e.client.StyxFlowEvents()` (Batch), `recordBeaconFlows(events)`; Health-Poll alle 10 s; Fehler ⇒ `noteVerificationFailure("styx_flow_sensor", …)` **nur bei wiederholtem Fehler**, nicht Beeinträchtigung des Ingress-Sensors; XDR-GesamtDegraded erst nach eigener Ursache.
- `recordBeaconFlows` füttert Detektor; `emitBeaconIncident` → `appendIncident` + `respond()` (nur wenn nicht degraded/observe) + `state.AddEvent`/`RecordEvidence`; `CellCgroupID` setzen ⇒ bestehender CellGuard-Auto-Confine greift (Score ≥ `Cells.AutoConfineScore`), alternativ direkter `ActionContainCell`-Pfad nur wenn `cells.auto_confine` aktiv — **kein neues stilles Enforcement am Go-CellGuard vorbei**.
- Settings: neuer Namespace `StyxFabricSettings` (Pointer im `RuntimeSettings`, Muster `Detection`): `Enabled bool`, `Mode string` (`off|monitor|enforce`), `LogFlows bool`, `DnsResolvers []string` (CIDRs), `PerCell []StyxCellMode{CgroupID uint64; Mode string; DnsResolver bool; AllowHostAllowlist bool}` (+ optional `Allowlist []StyxAllowRule{CgroupID uint64; CIDR string; PortLo,PortHi uint16; Proto string}`). Validierung: Mode-Enum, CIDR kanonisch, Ports, cgroup≠0, Listen-Caps (PerCell ≤256, Allowlist ≤1024); `fabricSettingsVersion` 12→13 mit Migrationsnotiz; Default: Enabled=false, Mode=off (keine Verhaltensänderung nach Upgrade!).
- Sync: Bei Settings-Apply/Restart/`epoch`-Wechsel `styxPolicySyncer` (neue Datei oder in `styx_beacon.go`): Version/Epoch prüfen → Global setzen → per-cell Modus/Flag → Allowlist → Resolver → Status `applied`; Fehler ⇒ Event `styx.policy_sync_failed`, Status degraded, alte Map-Inhalte werden nicht behauptet. Beim Deaktivieren: Global mode=off + alle Zellen löschen (Reihenfolge: off zuerst ⇒ fail-safe).
- API: `GET /api/v1/styx/beacons` (Top-N, Counter, SensorState), `GET /api/v1/styx/status` (kombiniert Go-Styx-Regeln + Kernel-Status/Health), optional `POST /api/v1/styx/policy` nicht Phase 1 (Settings-Update über bestehenden Settings-PUT). Neue Routen in `routes()`; `GET` = keine Mutation; neue JS-Ausgabe nur wenn UI nötig (Phase 1: Status im bestehenden Settings-/Status-JSON, keine neue JS-Datei ⇒ kein `webAssetAllowlist`-Eingriff).
- Bestehende `POST /api/v1/styx/rules`-API bleibt unverändert (Go-Evaluator-Regeln), klar getrennt dokumentieren.

## 9. Fail-Closed-/Degraded-Matrix

| Situation | Kernel | Go-Status | XDR/Response |
|---|---|---|---|
| Settings Enabled=false / Mode=off | keine Enforcement, kein Flow-Logging | `styx_enforcement=off` | keine Aktion |
| Capability fehlt (alter Core) | — | `sensor=unavailable`, `capability=missing`, Backoff | keine Beacon-Incidents |
| Flow-Ring-Drops > 0 | Enforcement unberührt | `sensor=degraded` nach 3 Polls, Event `xdr.styx_flow_overflow` | Detektion pausiert **behauptet nicht** „keine Beacons"; bestehende Responses bleiben |
| Map-Write/Sync-Fehler | ggf. alter Policy-Stand aktiv | `sync=failed`, Event, Retry-Backoff | keine neue aktive Response |
| XDR degraded/observe | — | — | Beacon-Incident wird aufgezeichnet, aber `respond()` pausiert (bestehender Vertrag) |
| Pflicht-Veto deaktiviert? | unmöglich (Core seedet beim Start; Flag `ALLOW_METADATA` nur Host-Scope) | — | — |

## 10. Testplan (verbindlich)

1. **Rust common** (`cargo +1.97.1 test ... -p gedefense-common`): 104-Byte-`size_of`-Assert, Decoder-Accept/Reject-Matrix (len, family, proto, direction, verdict, packets=0, ts=0, IPv4-nicht-kanonisch, 0.0.0.0, tcp_flags bei UDP, ports bei proto 0, comm-Padding), Fuzz-Corpus-Erweiterung analog `xdp_packet_fuzz`.
2. **eBPF-Build = Verifier-Gate** (`make rust-ebpf`): `cargo +nightly-2026-07-16 build ... --target bpfel-unknown-none -Z build-std=core` muss grün sein; `readelf -S` muss `cgroup_skb/egress` und neue Map-Symbole zeigen; `scripts/security-audit.sh`-ELF-Gate erweitern.
3. **Rust core**: Parser-/Validator-Tests für alle `STYX_*`-Kommandos, DELETE-Idempotenz, Health-Format, Flow-Drain (mit Fake-Maps? wo nicht möglich: reine Funktionen für Text-Encoding + Validierung testen), `unknown command` bleibt Fehler.
4. **Go coreipc**: Parser-Tests (gültig, 8 hostile Fälle, All-or-Nothing, dropped, overflow), Fuzz-Target, Fake-Core-IPC-Test (Unix-Listener mit `coreMAC`-Antwort, analog `security_v5_test.go`) für `STYX_FLOW_EVENTS`-Fehlerpfade; alter Core (unknown command) ⇒ `ErrStyxUnavailable` statt Crash.
5. **Go Detektor**: Welford/CV-Grenzen, Schwellenmatrix, Dedupe, TTL/Prune, LRU-Kardinalität (10k Flows ⇒ `len ≤ 8192`, `-race`), Signal-`unknown` ohne DNS-Capability, Incident-Felder (`CausalEdge == EdgeEgressAttempted`, `CellCgroupID` gesetzt, `Score 250`), Fail-Closed (degraded ⇒ kein Response).
6. **Integration**: Settings-Validate/Schema/Defaults (Mode-Enum, CIDR-Canonical, Caps), Sync-Reihenfolge, Disable-Pfad, `go test ./...` + `go vet`, `node --check`, `security-audit.sh`, i18n-Parität nur falls UI-Keys geändert.
7. **Adversarial (Reviewer, read-only)**: IPv4-mapped-Bypass (`::ffff:169.254.169.254`), IPv6-ext/fragment, Non-canonical CIDR, Port-0-Missbrauch, `proto=0`-Marker, RingFlood (10k Flows), Map-Insert-Fehler, Replay/Request-ID, Fail-open-Regression bei Default-off, PID-Reuse (StartTicks via Go-Prozessinventar / /proc-Join dokumentiert), Kernel-Boot ohne Core (keine Enforcement-Behauptung), Upgrade-Pfad (alte Settings → Default off).

## 11. Datei-Ownership / Phasen

| Task | Owner (Agent) | Dateien (Write-Scope) | Depends |
|---|---|---|---|
| P3-T1 | Rust-Common-Agent | `rust/gedefense-common/src/lib.rs`, `rust/gedefense-common/src/bin/flow_event_fuzz.rs` (neu) | — |
| P3-T2 | Go-IPC/Detector-Agent | `control/coreipc.go`, `control/styx_beacon.go` (neu), `control/coreipc_styx_test.go` (neu), `control/styx_beacon_test.go` (neu), `control/security_fuzz_test.go` (Fuzz-Target), `Makefile` (fuzz-smoke) | Spec ABI |
| P3-T3 | eBPF-Agent | `rust/gedefense-ebpf/src/main.rs` | P3-T1 |
| P3-T4 | Rust-Core-Agent | `rust/gedefense-core/src/main.rs`, `rust/gedefense-core/src/styx_flow.rs` (neu) | P3-T1, P3-T3 (Map-Namen) |
| P3-T5 | Go-Integration-Agent | `control/xdr.go`, `control/xdr_types.go`, `control/runtime_settings.go`, `control/fabric_settings.go`, `control/fabric_schema.go`, `control/server_settings.go`, `control/server.go` (Routen), `control/styx_policy.go` (neu, Sync) | P3-T2 |
| P3-T6 | Gates/Doku-Agent | `scripts/security-audit.sh` (Anker), `ARCHITECTURE.md`, `docs/POINT3-EGRESS-BEACON.md` (diese Datei, Status) | P3-T3/T4/T5 |
| P3-T7 | Reviewer/Verifier | read-only, adversarial gegen alle Tests/§10 | alle |

## 12. Rollout-/Betriebshinweise (Phase 1)

- Default nach Update: `[styx]` nicht gesetzt ⇒ `Enabled=false, Mode=off` ⇒ Kernel-Verhalten **byte-identisch** zu 5.2.0 (nur ein zusätzlicher Array-Lookup im Hook).
- Aktivierung: Settings `styx.enabled=true`, `mode=monitor` (nur Telemetrie) → beobachten (Flow-Events, Health, keine Blocks) → `mode=enforce` + Per-Cell-Regeln erst nach Live-Evidenz; `default-deny` nur mit vollständiger Allowlist (Management, Feeds, DNS-Resolver, OS-Updates), sonst Verbindungsabbrüche.
- Severity/Response: `BEACON_*`-Incidents sind standardmäßig `HIGH` (Score 120–250); aktive Containment nur, wenn XDR-Modus es erlaubt und `cells.auto_confine`/Response-Policy aktiv ist. Kein neues „automatisches Kill" aus Beacon-Signalen.
- Bekannte Grenzen: DoH-über-443 nicht kernel-seitig erkennbar; DNS-Attribution erst Phase 2 (Signal 3 bleibt `unknown`, feuert nicht); rx-Bytes erst Phase 2 (Asymmetrie-Signal nutzt dann echte rx); bestehende Verbindungen werden von egress-Regeln nicht rückwirkend gekappt; Map-Seed-Fenster beim Core-Start (<1 s) dokumentiert.

## 13. Umsetzungsabweichungen/Präzisierungen (Phase 1, 2026-11-15)

Diese Sektion hält fest, wo die Phase-1-Implementierung von der Spec präziser oder
abweichend ist. Sie ist beschreibend, keine nachträgliche Abschwächung: Die ABI-1/2/3
(Wire-Layout, Map-Namen, VGT3-Kommandos) wurde eingehalten, sofern unten nichts anderes
steht. Maßgeblich ist der Code, nicht die Prosa.

1. **Global-Flags: IPC-Bit 0 wird intern zu `1<<6`.** `STYX_GLOBAL` trägt auf dem
   IPC-Wire genau ein Flag-Bit: Bit 0 = `LOG_FLOWS`
   (`control/styx_policy.go`: `styxGlobalFlagLogFlows = 1 << 0`). Der Core lehnt alle
   anderen Bits ab (`rust/gedefense-core/src/styx_flow.rs` `parse_global_flags`) und
   übersetzt Bit 0 auf das interne eBPF-Flag `STYX_FLAG_LOG_FLOWS = 1 << 6`; das gepackte
   Wort ist `epoch (low 32) | flags << 32 | mode << 40`. `STYX_MODE_SET`-Flags nutzen
   dagegen direkt die internen Bits 3/5/6 (§3.1).
2. **Kein Allow-All über CIDR.** Der Go-Validator akzeptiert nur Präfixe /4../32 (IPv4)
   bzw. /8../128 (IPv6) (`control/coreipc.go` `styxCanonicalCIDR`, gespiegelt in
   `control/styx_policy.go` `normalizeStyxTarget`). /0../3 (bzw. v6 < /8) werden
   abgelehnt; „alles erlauben" ist damit nur über Modus `off` oder die dokumentierten
   Ausnahmen (`ALLOW_METADATA` nur für Host-Scopes, `ALLOW_HOST_ALLOWLIST`,
   globale Host-Allowlist/Resolver) erreichbar — nie über eine 0.0.0.0/0-Regel.
3. **cell-v6-Allow-Key ohne Port/Proto.** Der Phase-1-Key `CELL_EGRESS_ALLOW_V6` ist
   24 Byte (`[cgroup LE 8][addr 16]`, LPM-Präfix 64+bits, max. 192) und hat keinen
   Port/Proto-Slot. Der Go-Validator lehnt IPv6-Cell-Regeln mit Port-/Proto-Restriktion
   deshalb explizit ab (`styx_policy.go`: „IPv6 cell rules cannot carry port/protocol
   restrictions in phase 1"), statt sie still auf „alle Ports" zu weiten. Portgenaue
   IPv6-Regeln folgen Phase 2 (Key 32 Byte).
4. **Ports nur exakt oder wildcard.** Zulässig sind nur ein exakter Port (dann Host-CIDR
   /32 bzw. /128) oder der Wildcard-Bereich 0/65535 (Settings akzeptieren 0/0 als
   Wildcard und normalisieren auf 0/65535); jeder andere Bereich wird abgelehnt
   (`control/styx_policy.go` `normalizeStyxAllowRule`, `rust/gedefense-core/src/styx_flow.rs`
   `port_proto`). Proto-Masken 1/2 (TCP/UDP) nur zusammen mit exaktem Port; Maske 3
   (TCP+UDP) wird als „keine Proto-Restriktion" im Key kodiert (nur TCP/UDP besitzen
   Ports, der Port-Slot bleibt wirksam). LPM-Präfixe: cell-v4 64
   (Cgroup-Allow-All) / 64+bits (CIDR) / 96+16 (exakter Port) / 112+8 (Proto, max.
   120); global-v4 32 (beliebig) / 48 (Port) / 56 (Proto); global-v6 128/144/152.
5. **Control-Restart bei deaktivierten Settings.** Der `styxPolicySyncer` hält den
   zuletzt angewendeten Stand nur im Speicher (`applied`). Ein neu gestarteter
   Control-Prozess kann alte PerCell-Einträge nicht enumerieren (ABI-3 hat kein
   „list"-Kommando) und setzt beim Disable-Pfad deshalb nur fail-safe
   `STYX_GLOBAL(0,0)` (`styx_policy.go` `applyPlan` Schritt 1). Diese Alt-Einträge sind
   bei Modus `off` inert (eBPF-Shortcut vor jeder Zell-Auflösung) und werden nicht
   gepinnt — ein Core-Neustart leert die Maps. Restrisiko: Wird später ohne
   Core-Neustart wieder `enabled=true` gesetzt, können unbekannte Alt-Einträge erneut
   wirksam werden; Betriebsregel Phase 1: nach einem Control-Restart vor dem Re-Enable
   den Core neu starten oder den Plan bewusst vollständig neu setzen.
6. **`BLOCKLIST`-Drops bleiben in allen Modi.** Die bestehende Threat-Intel-Blocklist
   (`BLOCKLIST_V4/V6` → DROP + unverändertes `EgressDropEvent`) wird vor Default-Deny
   und Loopback-Ausnahme ausgewertet und bleibt in `off`/`monitor`/`enforce` unverändert
   (fail-closed); sie zählt in `EGRESS_DROPS_TOTAL`, nicht in `EGRESS_POLICY_DROPS`.
   Flow-Events solcher Drops tragen `verdict = DROP (2)`, sind aber keine neue
   Point-3-Policy-Entscheidung. Das Aktivieren der Point-3-Telemetrie schwächt die
   Blocklist nicht.
7. **Loopback/ND.** Loopback (`127.0.0.0/8`, `::1`) ist von Pflicht-Veto und DNS-Pinning
   ausgenommen und wird im Default-Deny nie geblockt; eine Operator-Blocklist, die 127/8
   oder ::1 abdeckt, behält ihre bestehende Wirkung. Die IPv6-ND-Ausnahme gilt nur für
   ICMPv6 NS/NA (Typ 135/136) mit Link-Local-Ziel (fe80::/10). Solicited-Node-Multicast
   (ff02::1:ff… ) fällt nicht darunter und kann vom `ff00::/8`-Veto geblockt werden —
   Restrisiko (kernel-generierte ND läuft nicht durch den Cgroup-Hook; betroffen sind
   nur socket-erzeugte Pakete). Im Betrieb beobachten.
8. **Positiv-Cache vs. neue Ancestor-Policy.** `STYX_RESOLVED` cached die erste
   Zell-Cgroup pro skb-Cgroup mit der Core-Epoch; bei Cache-Treffer wird der Mode-Byte
   neu gelesen (Mode-Änderungen greifen sofort), aber der aufgelöste Zell-Ancestor bleibt
   bestehen. Eine neu installierte Policy auf einem HÖHEREN Ancestor kann daher bis zur
   Epoch/Eviction (LRU 16384) verzögert wirken. Negativ-Ergebnisse werden bewusst nicht
   gecacht, damit neue Regeln auf bisher unbekannten Cgroups sofort greifen.
9. **DNS-Attribution/Direct-IP in Phase 1 `unknown`.** Der eBPF-Hook ist egress-only,
   liefert `rx_bytes = 0` und keine DNS-Information; `DNSObservationAvailable = false`,
   daher bleibt Signal 3 (`BEACON_DIRECT_IP_NO_DNS`) `unknown` und feuert nie (kein Fake).
   Die Asymmetrie nutzt den dokumentierten rx==0-Sonderfall (Samples ≥ 8, tx ≥ 1 MiB) und
   behauptet keine echten rx-Werte. DoH über 443 ist kernelseitig nicht attribuierbar;
   rx-Bytes/DNS-Attribution sind Phase 2.
10. **Flow-Event-Overflow/Health-Semantik.** Ring-Drops (`FLOW_RING_DROPS`) und
    Aggregations-Insert-Fehler (`FLOW_AGG_INSERT_FAILURES`) werden gezählt;
    `STYX_FLOW_EVENTS` liefert auch bei leerem Batch das Drop-Delta (`<dropped>|`). Go
    meldet `xdr.styx_flow_overflow` (gedrosselt auf max. alle 5 min), nach 3
    aufeinanderfolgenden Overflow-Polls wird der Sensor `degraded` (Incidents werden
    unterdrückt und gezählt; kein „keine Beacons"-Claim), nach 3 sauberen Polls erholt er
    sich. `STYX_FLOW_HEALTH` liefert die 6 Zähler; `EGRESS_PARSE_ERRORS` wird bei
    enforce fail-closed (Drop) gezählt, ohne Einzel-Event. Der Core-interne Skip-Zähler
    `styx_flow_rejected` (undecodierbare Records) ist bewusst NICHT Teil des
    Health-Wires und keine Degradierung (§3.2 „kein Drain-Abbruch"). „degraded"/
    „unavailable" ist nie stilles OK.
11. **Batch-Grenze effektiv 8.** §3.3 nennt als Wire-Obergrenze 12 Records; der
    Phase-1-Core deckelt auf `MAX_STYX_FLOW_EVENTS_PER_RESPONSE = 8` (§7,
    Payload-Budget 2048 Byte), der Go-Parser erzwingt unabhängig 8 Records und 2048 Byte.
    Die 12 ist damit eine ungenutzte Obergrenze, keine Zusage.
12. **Attach-Modus (Präzisierung, vorbestehend).** Der `cgroup_skb/egress`-Hook wird am
    Root-Cgroup mit `CgroupSkbAttachType::Egress` + `CgroupAttachMode::AllowOverride`
    attached (`rust/gedefense-core/src/main.rs`); `AllowOverride` ersetzt ein evtl. noch
    hängendes Alt-Programm nach einem Core-Restart (keine Programmansammlung). Die
    Formulierung „bestehende AllowMultiple-Verträge bleiben unverändert" ist damit
    unpräzise: unverändert bleiben Hook-Typ, Root-Cgroup-Ziel und Rückgabe-Semantik
    (0 = DROP, 1 = PASS); der Attach-Modus ist `AllowOverride`. `scripts/security-audit.sh`
    prüft den Attach-Typ und die bestehenden Anker unverändert; der tatsächliche Modus
    ist als zusätzlicher Anker `CgroupAttachMode::AllowOverride` abgesichert.
13. **Signal 2 rechnet mit kumulativen Fenster-Deltas.** Der eBPF-Hook emittiert
    `tx_bytes`/`packets` als **Fenster-Delta** (FLOW_AGG wird nach jedem Emit
    zurückgesetzt; das erste Paket eines Flows emittiert sofort mit der Paketlänge), nicht
    als laufenden Gesamtzähler. Go summiert die Deltas deshalb saturierend kumulativ
    (`saturatingAdd`, kein `max()`), sodass die Schwellen aus §8.2
    (`txBytes >= 524288`, `txBytes/rxBytes >= 8`, rx==0-Sonderfall `samples>=8 &&
    txBytes>=1 MiB`) auf der **Flow-Gesamtsumme** gelten. Mit dem früheren `max()` wäre
    eine langsame Exfiltration unterhalb eines einzelnen Emit-Fensters nie signalisiert
    worden. T7-Befund, behoben; Tests: `TestStyxBeaconSlowExfilCumulativeDeltas`,
    `TestStyxBeaconExfilAsymmetryCumulativeThresholds`,
    `TestStyxBeaconSaturatingVolumeAccounting` (`control/styx_beacon_exfil_test.go`).
14. **SensorState ist bei `enabled=true, mode=off` ehrlich `off`.** Der Kernel-Hook kehrt
    bei `mode==off` vor jedem Flow-Logging zurück (§6.1); deshalb meldet
    `StyxBeaconEngine.SensorState()` in diesem Zustand `off` statt `active`
    (`unavailable` bleibt für disabled/Capability unbekannt), und `RecordFlows` ignoriert
    Flows bei `mode=off`. Der Syncer projiziert den effektiven Modus in
    `styxBeacon.cfg.Mode`. Tests: `TestStyxBeaconModeOffIsNotActive`,
    `TestStyxBeaconSettingsProjectModeOffHonestly`. T7-Befund, behoben.
15. **Inerte Policies werden fail-visible abgelehnt.** `enabled=true` + `mode=off` mit
    PerCell-Modi≠off, nicht-leerer Allowlist oder DNS-Resolvern wird bei der
    Settings-Validierung abgelehnt („styX mode=off with per-cell/allowlist rules has no
    effect; set mode=monitor or enforce", `control/styx_policy_plan.go`
    `buildStyxPolicyPlan`). Reject statt Auto-Eskalation: der Operator erkennt, dass die
    Regeln wirkungslos wären, statt eine still inerte Policy zu speichern. T7-Befund,
    behoben; Test: `TestStyxFabricSettingsRejectsInertModeOffPolicy`.
16. **P3-T7-Reviewergebnis: PARTIAL, kein FAIL.** Drei Befunde wurden behoben
    (Signal-2-Delta, SensorState `off`, inerte Policy — siehe 13–15). Akzeptierte
    Restrisiken: (a) IPv6-Pakete mit mehr als 4 Extension-Header-Hops oder
    Nicht-Erst-Fragmente ohne L4-Header liefern Ports 0, dadurch kann das DNS-Pinning
    (Zielports 53/853) für solche Pakete übersprungen werden (Veto/Allow/Block und
    Flow-Telemetrie greifen weiter; Erst-Fragmente mit L4-Header werden normal geprüft); (b)
    Core-Restart-Epoch-Fenster ≤ 10 s: Go bemerkt einen Core-Neustart erst beim nächsten
    Epoch-/Sync-Poll, bis dahin kann der letzte Sync-Status angezeigt werden — der neue
    Core startet aber immer mit `STYX_GLOBAL=OFF` (fail-safe, keine erzwungene Blockade);
    (c) die beim Start geseedeten Pflicht-Veto-Einträge sind über das authentisierte
    `STYX_BLOCK_DEL` löschbar; die Go-Policy-Schicht hat dafür keinen Aufrufpfad
    (Client-Methode vorhanden, kein Aufrufer), aber ein IPC-Client mit gültigem
    HMAC-Key könnte es — dokumentierte Grenze des privilegierten IPC-Vertrauensmodells;
    (d) Positiv-Cache-Verzögerung (siehe 8); (e) kein Live-Kernel-/Verifier-Load-Test in
    dieser Umgebung — verifiziert sind Nightly-eBPF-Build (Verifier-Gate) und
    Map-Symbol-/Sektionsprüfung per `readelf`, ein Attach-/Load-Test auf einem echten
    Kernel bleibt separater Integrationsschritt.
17. **Datei-Split (VGT-≤500-Zeilen-Regel, T7).** `control/styx_policy.go` wurde
    aufgeteilt in `styx_settings.go` (239 Zeilen; Settings-Namespace/Defaults/Clone),
    `styx_policy_plan.go` (303; pure Validierung und LPM-Plan), `styx_syncer.go` (403;
    Sync-Schleife, Push-Order, Retry/Resync), `styx_syncer_status.go` (189;
    Status-Übergänge/Operator-Events) und `styx_policy.go` (351; XDR-/Beacon-Bridge und
    API-Sicht). Tests: `styx_settings_test.go` (281), `styx_syncer_test.go` (474),
    `styx_xdr_test.go` (245), `styx_api_test.go` (257) sowie
    `styx_beacon_exfil_test.go` (127; T7-Delta-Tests, aus `styx_beacon_test.go`
    ausgelagert). Alle genannten Dateien ≤ 500 Zeilen. Die `scripts/security-audit.sh`-
    Anker prüfen `control/styx_*.go` (ohne `_test.go`) als Gesamtheit, damit der Split
    den Gate nicht umgehen kann.
18. **Flaky `TestInitFeedSigningProvisioning` behoben.** Key-Dateien werden nicht mehr
    über `TrimSpace` über rohe Bytes gelesen: `feedSigningKeyFileBytes` akzeptiert nur
    exakte Größen (32-Byte-Seed / 64-Byte-Private-Key) und strippt optional genau einen
    trailing `\n` bzw. `\r\n`; `loadFeedSigningPublicKey` verwendet die Bytes
    unverändert. Nachweis: `go test -run '^TestInitFeedSigningProvisioning$'
    -count=500 .` → Exit 0, 0 FAIL (vorher reproduzierbar 11/200 FAIL).
19. **Signal-2-Ehrlichkeit/Phase-1-Grenze (Refinement nach T7).** Die
    Produktionsprojektion setzt `RxObservationAvailable=false` **und**
    `DNSObservationAvailable=false` (`control/styx_policy.go`
    `applyStyxBeaconSettings`): Phase 1 hat keine Ingress-/rx-Telemetrie und keine
    DNS-Attribution, eine `tx/rx`-Ratio ist daher nicht beweisbar. Ohne
    Canary-Korrelation bleibt die Asymmetrie **`unknown`** — kein Score, kein Incident,
    keine Ratio-Behauptung; auch zufällig vorhandene rx-Bytes werden nicht für eine
    Ratio verwendet, solange die Capability `RxObservationAvailable=false` meldet
    (`TestStyxBeaconPhase1VolumeOnlyStaysUnknown`). Mit Canary-Korrelation
    (`KD.LINUX.CANARY_ACCESS` im Lookback `FlowTTLSeconds`, d. h. 900 s) und kumulativ
    `txBytes >= 1 MiB && samples >= 8` ⇒ **Score 200**, Severity `HIGH`, Decision
    `alert`, RuleID `STYX.EXFIL.ASYMMETRY`; die Summary nennt ausdrücklich
    „rx telemetry unavailable; volume+canary correlation, no ratio claim"
    (`TestStyxBeaconPhase1CanaryVolumeScore`). Kombiniert mit Periodizität (≥2 Signale)
    ⇒ Score 250, Decision `contain`, Severity `CRITICAL`, weiterhin ohne Ratio-Claim
    (`TestStyxBeaconPhase1CanaryVolumeCombinationContain`). Die Produktionsprojektion
    hält beide Capabilities false (`TestStyxBeaconProductionSettingsKeepPhase1CapabilitiesOff`).
    Der rx-bekannte Ratio-Pfad (`RxObservationAvailable=true`: `tx >= 512 KiB` und
    `tx/rx >= 8` bzw. rx==0-Sonderfall; Canary hebt 200 → 250) bleibt unverändert und
    ist Phase 2/Ingress-Telemetrie. Damit ist die von T7 gemeldete
    Alert-Fatigue-/Attrappen-Gefahr (Fehlalarm bei jedem großen Upload/Backup ohne
    beweisbare Ratio) mitigiert; Restrisiko: Phase 1 erkennt volumenstarke
    Exfiltration nur mit Canary-Evidenz oder über die Periodizität.

20. **P3-Fix: Cell-Socket-LSM-Claim nur bei aktiver LSM-Liste.** Der Zielserver hat
    keine `bpf`-LSM-Liste (Befund §21): der Core meldete bisher `cell_lsm_attached`
    und den `PING`-Token `+bpf-lsm-cell`, obwohl das `Lsm::attach()` dort mangels
    aufgerufener `bpf_lsm_*`-Stubs **wirkungslos** war (silent no-op). Jetzt wird
    `/sys/kernel/security/lsm` vor jedem Attach geprüft: `cell_lsm_attached` wird nur
    bei aktivem `bpf`-Token, vorhandenem BTF und erfolgreichem Attach `true`
    (`rust/gedefense-core/src/main.rs`); der PING-Mode hängt `+bpf-lsm-cell` nur dann
    an (`if cell_lsm_attached { mode.push_str("+bpf-lsm-cell"); }`), der Startlog
    nennt `cell_lsm=optional-unavailable`, und die Cell-LSM-IPC-Kommandos antworten
    ohne Attach mit „Gaia Cell BPF LSM is unavailable" statt Erfolg
    (`require_cell_lsm`). Go projiziert das ehrlich: `xdrSensorMode` meldet
    `cell-lsm-unavailable` statt `bpf-lsm-cell`. `--require-bpf-lsm` macht die
    fehlende Aktivierung weiterhin zum Startfehler. P3-Tests bleiben unverändert
    (`control/xdr_cell_lsm_test.go`); P1-T5 pinnt additiv in
    `control/titan_exec_api_test.go`, dass ein inaktives LSM nie als
    `bpf-lsm-cell`/enforced erscheint.
21. **Befund zum P3-Cell-LSM-Claim auf Systemen ohne `bpf`-LSM.** `uname`
    `7.0.0-38-generic`, `CONFIG_BPF_LSM=y`, BTF + `bpftool` vorhanden, aber
    `/sys/kernel/security/lsm` = `lockdown,capability,landlock,yama,apparmor,ima,evm`
    (kein `bpf`), `CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"`, kein
    `lsm=` in `/proc/cmdline`. Der frühere Attach-Claim war damit wirkungslos; es gab
    keine Enforcement-Wirkung. Ohne Operator-Aktivierung (Boot-Cmdline
    `lsm=<aktuelle Liste>,bpf` + Reboot, exakte Liste vorher testen, Rettungs-Kernel)
    bleibt der Cell-LSM-Status `optional-unavailable`/`cell-lsm-unavailable` und es
    wird **keine** Wirkung behauptet. Details/Evidenz in
    `docs/POINT1-TITAN-EXEC-GATE.md` §13.9/§13.12 und `docs/POINT1-PHASE1-REPORT.md`.

## 14. Definition of Done (Phase 1)

- Alle §10-Tests grün (`go test ./...`, `go vet`, Rust-Tests, eBPF-Build, `security-audit.sh`, `node --check`), keine bestehende Assertion abgeschwächt.
- Default-Off-Upgrade verändert Produktionsverhalten nicht (Test/Review belegt: gleiche Events/Entscheidungen wie 5.2.0 bei Default-Settings).
- Fail-Closed-Matrix (§9) durch Tests belegt; keine `panic`/Nil-Deref-Pfade in neuen Parsern/Sensoren.
- Dokumentation: diese Spec (Status), `ARCHITECTURE.md`-Anker sowie Betriebshinweise und Restrisiken.
- Adversarialer Reviewer-Pass ohne offene FAIL-Befunde; Restrisiken explizit dokumentiert.
