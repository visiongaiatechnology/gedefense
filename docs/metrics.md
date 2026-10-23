# GeDefense 4.1 Telemetry, Metric & Counter Specification

**Status:** Binding Telemetry Standard  
**Governing Operating Rules:** Rule 5, Rule 6, Rule 9, Rule 15, Rule 17, Rule 20  
**Version:** 4.1.0  

---

## 1. Metric Semantics Overview

In GeDefense 4.1, no metric may be displayed without an explicit semantic definition. A value of `0` does not inherently mean "Nominal" or "Healthy". This specification details each metric displayed across the GeDefense dashboard and exposed via `/api/v1/snapshot`, `/api/v1/feeds/status`, `/api/v1/kinetic/events`, and `/metrics`.

---

## 2. Dashboard Cards & Underlying Telemetry Matrix

| Dashboard Card / Label | API Field Path | Metric Scope | Data Source | Reset Behavior | Interpretation of `0` | Nominal Threshold / State |
|:---|:---|:---|:---|:---|:---|:---|
| **Aktive CIDR-Sperren** | `Snapshot.Blocks` (count of entries with `Enforced=true`) | Current active state | Kernel LPM map & Go blocklist store | Dynamic; decrements on TTL expiry or manual unblock | **Neutral**: No currently active network containment blocks | >= 0; any non-zero count reflects active hostile traffic quarantine |
| **XDR Profile** | `Snapshot.XDR.Behavior.Profiles` | Lifetime in memory / current persisted baseline | Go Host XDR Behavior Engine (`behavior.json`) | Persists across restarts; reloads from signed state | **Suspicious / Warning** if system has been up > 1h; baseline learning incomplete | > 10 typical server profiles |
| **Warm Profiles** | `Snapshot.XDR.Behavior.WarmProfiles` | Current state | Evaluated profiles with sufficient observation ticks | Persists across restarts | **Neutral to Warning** if zero after warm-up window | Matches or approaches total profiles |
| **Analyse-Queue** | `Snapshot.XDR.QueueDepth` / `Snapshot.XDR.QueueCapacity` | Instantaneous current queue depth | Go in-memory buffered worker channel (default capacity: 2048) | Dynamic buffer depth | **Ideal / Nominal**: Processing engine is keeping pace with host events | `0 / 2048` is nominal; `> 1800` triggers queue pressure alert |
| **Queue Drops** | `Snapshot.XDR.EvaluationDrops` | Cumulative Lifetime counter | Go XDR Event Ingestion Drop counter | Resets only on daemon restart | **Ideal / Nominal**: 0 dropped events. | `0` is strictly nominal; `> 0` indicates backpressure data loss |
| **Total Evaluations** | `Snapshot.XDR.EvaluationsTotal` | Cumulative Lifetime counter | Go XDR worker evaluation counter | Resets only on daemon restart | **Suspicious** if host is running workload but count remains 0 | Monotonically increasing |
| **Adaptive Anomalien** | `Snapshot.XDR.AnomaliesTotal` | Cumulative Lifetime counter | Behavior Engine anomaly scoring trigger | Resets only on daemon restart | **Nominal**: No behavioral baseline deviation detected | Low numbers nominal; spikes indicate suspicious deviation |
| **Host Incidents** | `Snapshot.Incidents` (count) | Ring buffer (max 250) | XDR Rule & Correlation Engine | Ring buffer FIFO | **Nominal**: No confirmed threat incidents | Low numbers nominal |
| **Threat Feed Vektoren** | `Snapshot.FeedVectors` | Current active state | Feed Manager synchronized threat IOC database | Replaced on successful sync | **Suspicious / Warning**: Feeds not loaded or empty | > 1,000 vectors loaded |
| **Feed Status** | `Snapshot.FeedStatus` | Current active state | Strict Feed Manager state (`OK`, `PARTIAL`, `ERROR`, `NEVER_SYNCED`) | Updates after every scheduled or manual sync | N/A | `OK` is nominal; `PARTIAL` or `ERROR` triggers warning badge |
| **L7 Status (Engine vs Traffic)** | `Snapshot.L7.Healthy` & `Snapshot.L7.RequestsTotal` | Current health & Lifetime requests | L7 Proxy engine healthcheck & request counter | Request count resets on restart | **Important Distinction (Rule 20)**: `Healthy=true` means proxy process is running; if `RequestsTotal=0` in inline mode, inspection traffic is not flowing | `Healthy=true` AND `RequestsTotal > 0` when inline active |
| **Kinetic Ingress Hits** | `Snapshot.Kinetic.HitsTotal` | Cumulative Lifetime counter | eBPF ingress packet sensor & L7 telemetry | Resets on daemon restart | **Suspicious** if exposed to internet but zero hits | Monotonically increasing |
| **Kinetic Velocity Bursts** | `Snapshot.Kinetic.VelocityBurstsTotal` | Cumulative Lifetime counter | Go Kinetic Engine sliding 1-second rate detector | Resets on daemon restart | **Nominal**: No high-velocity packet bursts detected | Spikes indicate SYN or UDP floods |
| **Kinetic Portscans** | `Snapshot.Kinetic.PortscansTotal` | Cumulative Lifetime counter | Go Kinetic Engine port diversity tracker | Resets on daemon restart | **Nominal**: No dark port probes or horizontal sweeps | Spikes indicate scanner activity |
| **Kinetic Subnet Strikes** | `Snapshot.Kinetic.SubnetStrikesTotal` | Cumulative Lifetime counter | Go Kinetic Engine /24, /16, /64 aggregation buckets | Resets on daemon restart | **Nominal**: No coordinated subnet-level attacks | Indicates botnet clustering |
| **Sensor Coverage** | `Snapshot.SensorCoverage.Status` | Deterministic system state | Realtime sensor heartbeat evaluator | Recalculated every second | N/A | Must be `ONLINE` for all required sensors |

---

## 3. Handling Zero Semantics & Operator Clarity (Rule 5 & 20)

1. **Evaluations vs Drops**:
   - `EvaluationDrops = 0` is a positive security metric (no dropped host events).
   - `EvaluationsTotal = 0` after extended uptime is an anomaly indicating disconnected host telemetry.
2. **L7 Health vs Traffic Coverage**:
   - The UI distinguishes between `L7 Engine: ONLINE` (daemon status) and `L7 Traffic: ACTIVE` (incoming request count > 0). If inline mode is enabled but request counter is zero, a badge `KEIN INSPECTION TRAFFIC` is displayed.
3. **Sensor Coverage Guard**:
   - If any mandatory sensor reports `OFFLINE` or `DEGRADED`, the global header cannot show `SYSTEM NOMINAL`. It must display `SENSOR COVERAGE DEGRADED`.
