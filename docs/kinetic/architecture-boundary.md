# GeDefense 4.1 Kinetic Defense: Architecture Boundaries & Resource Guarantees

**Status:** Binding Architectural Standard  
**Governing Operating Rules:** Rule 2, Rule 9, Rule 10, Rule 11, Rule 25  
**Version:** 4.1.0  

---

## 1. Architectural Tiers & Separation of Concerns

GeDefense 4.1 enforces a strict boundary between the kernel data plane (Rust eBPF/XDP) and the userspace control plane (Go).

```
+---------------------------------------------------------------------------------------+
|                                    USERSPACE TIER                                     |
|                                                                                       |
|  +---------------------------+  +--------------------------------------------------+  |
|  |     Web UI & REST API     |  |                 Go Control Plane                 |  |
|  | (control/web/kinetic.js)  |  |   - Sliding Window Aggregation (1s, 10s, 60s)    |  |
|  | - 250 Event Ring Buffer   |  |   - Subnet Radix Buckets (/24, /16, /64)         |  |
|  | - Client Backpressure     |  |   - Port Diversity Bitsets                       |  |
|  | - Decoupled Status Cards  |  |   - L7 TLS Parser (JA3, ALPN, GREASE)            |  |
|  +---------------------------+  |   - Evidence Ledger Cryptographic Signing        |  |
|               ^                 |   - Response Controller & Dynamic TTL Sweeper    |  |
|               |                 +--------------------------------------------------+  |
|               |                                           ^                           |
+---------------+-------------------------------------------|---------------------------+
|                                                           | Aya IPC / Ring Buffer     |
+-----------------------------------------------------------v---------------------------+
|                                    KERNEL DATA PLANE                                  |
|                                                                                       |
|  +---------------------------------------------------------------------------------+  |
|  |                           Rust eBPF / XDP (gedefense-ebpf)                      |  |
|  |                                                                                 |  |
|  |  Hot Path (< 100ns execution budget per packet):                                |  |
|  |  1. Parse Ethernet & IP header (IPv4 / IPv6)                                    |  |
|  |  2. Check Management Allowlist LPM Trie -> Pass                                 |  |
|  |  3. Lookup Drop LPM Trie -> XDP_DROP (atomic drop counter++)                    |  |
|  |  4. Sanity check TCP flags (SYN-RST, NULL, FIN-PSH-URG) -> XDP_DROP             |  |
|  |  5. Sample / Aggregate Ingress Counter in Bounded Per-CPU Map                  |  |
|  |  6. Return XDP_PASS                                                             |  |
|  +---------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------+
```

---

## 2. Kernel Data Plane Guarantees (Rule 9 & 10)

1. **Strictly Bounded Maps**:
   - `v4_drop_lpm`: Maximum entries: **65,536** (BPF_MAP_TYPE_LPM_TRIE).
   - `v6_drop_lpm`: Maximum entries: **65,536** (BPF_MAP_TYPE_LPM_TRIE).
   - `allowlist_lpm`: Maximum entries: **4,096** (BPF_MAP_TYPE_LPM_TRIE).
   - `ingress_telemetry_lru`: Maximum entries: **16,384** (BPF_MAP_TYPE_LRU_HASH).
   - Under no circumstances does kernel memory allocation grow unboundedly in response to incoming packet cardinality. When `ingress_telemetry_lru` reaches capacity, kernel LRU eviction drops the least recently accessed entries.
2. **Minimal Hot Path**:
   - No string parsing, no regex, no SHA-256 calculation, and no complex state machines in eBPF/XDP.
   - Hot path packet processing terminates in fewer than 40 instructions for allowed or dropped packets.
3. **Equal IPv4 and IPv6 Treatment (Rule 11)**:
   - Both address families have dedicated LPM trie drop and allowlist tables.
   - Telemetry aggregation supports 128-bit IPv6 address keys natively.

---

## 3. Userspace Control Plane Guarantees (Rule 3 & 22)

1. **Sliding Windows & Cardinality Bounds**:
   - The Go Kinetic Detection Engine tracks up to **65,536** active IP buckets simultaneously in a concurrency-safe, partitioned shard structure.
   - Stale IP buckets with no activity for more than 60 seconds are automatically reclaimed during the periodic 5-second sweep cycle.
2. **Backpressure & UI Streaming (Rule 22)**:
   - The real-time SSE stream (`/api/v1/kinetic/events`) uses a bounded ring buffer of **250** recent events per connected client.
   - If a client connection is slow or fails to consume events, events are dropped with an increment to `kinetic_stream_dropped_events` rather than buffering indefinitely in server RAM.
3. **No Deadlocks & Clean Graceful Degradation**:
   - Mutexes protecting telemetry and incident logs use sub-millisecond lock spans.
   - All external system calls and IPC requests to the Rust Core broker are protected by context timeouts (maximum 2.0 seconds).
