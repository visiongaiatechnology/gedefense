# GeDefense 4.1 Kinetic Defense: Fail-Safe State Machine & Fault Response Matrix

**Status:** Binding Security Standard  
**Governing Operating Rules:** Rule 7, Rule 8, Rule 24  
**Version:** 4.1.0  

---

## 1. Principles of Fail-Safe Operation

1. **Safety Over Silence (Rule 7)**: A broken sensor, broken persistence, or corrupted kernel map must never be silently ignored or glossed over as `SYSTEM NOMINAL`.
2. **Preventing Operator Lockout (Rule 7 & 16)**: Under no failure condition may the management allowlist be revoked or bypass protections dropped.
3. **Deterministic State Transitions (Rule 8)**: Every system failure triggers a strictly defined state transition in the `ReleaseController` and `KineticEngine`.

---

## 2. Failure Path Response Matrix

| Failure Mode | Trigger Condition | Data Path Action | Containment / Ban Action | System Health State | Release Controller State | Telemetry / Alert |
|:---|:---|:---|:---|:---|:---|:---|
| **F-01: eBPF Ring Buffer Offline** | Loss of IPC read stream from kernel perf/ring buffer for > 5 seconds | Existing kernel LPM drop rules remain active (no traffic flood) | New kinetic strikes halted (transition to observe) | `IngressNetwork: DEGRADED` | Demoted from `enforce` to `degraded` | Alert `ERR_EBPF_RINGBUFFER_OFFLINE`, counter `kinetic_sensor_failures`++ |
| **F-02: Kernel Map Sync Failure** | Rust Core IPC returns error on LPM map update / delete | Existing kernel drops retained; retry queued up to 3 times | New bans queued in memory but flagged as `PENDING_KERNEL_SYNC` | `KernelDataPlane: DEGRADED` | Blocks canary/enforce promotion | Alert `ERR_KERNEL_MAP_SYNC_FAILED`, blocker `kernel policy reconciliation is pending` |
| **F-03: Evidence Ledger Unwritable** | Disk full, read-only filesystem, or signature failure in `EvidenceLedger` | Existing kernel drops retained | **FREEZE**: All new automated bans blocked until evidence ledger is restored | `EvidenceLedger: OFFLINE` | Demoted to `observe` / emergency stop trigger | Blocker `mandatory evidence ledger is unavailable`, alert `CRIT_EVIDENCE_DISK_ERROR` |
| **F-04: Signed Policy Persistence Error** | Cannot commit snapshot to disk or signature verification fails | In-memory policy retains last verified snapshot | Automatic policy generation paused | `PolicyTrust: DEGRADED` | Demoted to `observe` | Blocker `signed policy is not verified` |
| **F-05: Threat Feed Divergence** | Feed download succeeds but kernel application fails or consecutive failures >= 3 | Existing feed vectors remain active; no stale or broken vectors applied | Correlate-only mode active | `ThreatIntel: PARTIAL / ERROR` | Blocker if feed sync is required | State reflects `PARTIAL` or `ERROR`, `LastKernelError` logged |
| **F-06: Management Allowlist Eviction or Sync Error** | Allowlist map verification fails or allowlist entries lost | Traffic fails open for allowlist candidates | **FAIL-SAFE LOCKOUT DEFENSE**: Clear all dynamic bans immediately to avoid administrative lockout | `System: DEGRADED` | Immediate demotion to `observe` | Emergency stop signal, alert `CRIT_MANAGEMENT_ALLOWLIST_DESYNC` |
| **F-07: L7 Inspection Crash / Non-Responsive** | L7 proxy healthcheck fails for > 10 seconds | Bypass / fail-open for HTTP/TLS traffic (unless strict quarantine mode configured) | L7 kinetic rules (`TLS.*`) disabled | `ApplicationL7: DEGRADED` | Blocks `enforce` promotion | Blocker `L7 inspection service is unavailable` |
| **F-08: Memory Pressure / Cardinality Saturation** | Active tracking IP entries exceed 60,000 (threshold 65,536) | LRU eviction of oldest inactive entries; active strike IPs protected | Rate limit new entry allocation | `KineticEngine: SATURATED` | Remains in current phase | Alert `WARN_KINETIC_TRACKING_SATURATED`, metric `kinetic_tracking_evictions_total`++ |

---

## 3. Ban Expiration & Rollback Verification (Rule 24)

Every dynamic ban issued by Kinetic Defense has an explicit `ExpiresAt` timestamp.
1. **Periodic Sweeper**: The Response Sweeper runs every 1 second.
2. **Reconciliation**:
   - The IP or subnet is removed from the active userspace containment table.
   - A removal command is dispatched to the Rust Core broker to remove the LPM trie entry.
   - An `Expiry` event is committed to the Evidence Ledger with the original strike ID.
3. **Rollback Failure Handling**:
   - If the kernel map delete fails, the ban is marked `EXPIRY_FAILED_STALE` and the system state is flagged as `DEGRADED`.
   - The Release Controller immediately treats stale rules as a blocker preventing Enforce promotion until reconciled.
