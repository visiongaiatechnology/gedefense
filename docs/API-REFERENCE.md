# GeDefense Linux 6.3.0 — REST API & RBAC Reference

> **Source of Truth:** [`../control/server.go`](../control/server.go) · [`../gateway/main.go`](../gateway/main.go) · [`V6.3.0-RBAC.md`](V6.3.0-RBAC.md)

---

## 1. Listeners, Authentication & RBAC (`R6`)

- **Gateway (`:9843` HTTPS):** Handles browser/operator TLS 1.3 (ML-KEM hybrid), `__Host-vgt_gedefense_session` cookies, CSRF synchronizer tokens, exact `Host`/`Origin`/`Sec-Fetch-Site` validation, and signed `.gateway-claim` HMAC headers toward loopback backend.
- **Control Backend (`127.0.0.1:9844`):** Loopback-only. Requires `Authorization: Bearer <token>` (`/var/lib/vgt/gedefense/dashboard.token`) plus `X-VGT-Request-ID` (replay-checked UUID) on mutations.
- **Role Tiers (`/api/v1/auth/roles`):**
  1. `Observer` — Read-only posture, incidents, flows, metrics, antispyware telemetry.
  2. `Operator` — Policy toggles, allowlist/blocklist edits, previews, permit lifecycle, quarantines.
  3. `Critical Unlock` — Requires fresh password/HMAC step-up (`POST /api/v1/auth/step-up` or Gateway password re-auth) with bounded brute-force lockout before destructive actions (`release/transition`, `lockdown/*`, `fim/baseline`, `chameleon/reveal`, key rotation).

---

## 2. Core Endpoints by Functional Group

### Health, Status & Auth
- `GET /livez`, `GET /readyz`, `GET /healthz` — Process liveness and gate-verified readiness (no secrets leaked)
- `GET /api/v1/status`, `GET /api/v1/startup`, `GET /api/v1/platform/caps`, `GET /api/v1/stream` (SSE telemetry)
- `GET /api/v1/overview/situation`, `GET /api/v1/overview/connections`, `GET /api/v1/overview/threat-map`
- `GET /api/v1/auth/roles`, `POST /api/v1/auth/step-up`

### Release Lifecycle & Emergency Stop
- `GET /api/v1/release`, `GET /api/v1/release/readiness`
- `POST /api/v1/release/transition` (`PROMOTE:CANARY`, `PROMOTE:ENFORCE`, downgrade)
- `POST /api/v1/release/emergency-stop`, `POST /api/v1/release/emergency-stop/clear`
- `POST /api/v1/system/restart`

### Anti-Spyware & Kernel Defense (`AP-0` – `AP-9`)
- `GET /api/v1/antispyware/status` — Aggregated `active_planes / total_planes`, `self_guard`, `exec_inode`, `bpf_guard`, `cross_view`, `kernel_hooks`, `persistence`, `dns`, `styx_phase2`, `sbc_fusion`, `sec_crit`
- `GET /api/v1/xdr/sec-crit`, `GET /api/v1/xdr/integrity`, `POST /api/v1/xdr/integrity/verify`
- `GET /api/v1/chameleon/status`, `POST /api/v1/chameleon/reveal` (Critical Step-Up)
- `POST /api/v1/deception/test-access`

### Host XDR, PermitV1, Review Queue & Quarantine
- `GET /api/v1/xdr/attack-stories`, `GET /api/v1/xdr/sbc`, `GET /api/v1/xdr/profiles`, `GET /api/v1/xdr/recovery`
- `POST /api/v1/xdr/incidents/{id}/ack`, `POST /api/v1/xdr/incidents/{id}/confine`
- `GET/POST /api/v1/xdr/permits`, `DELETE/GET /api/v1/xdr/permits/{id}` (`PermitV1` signed allowances)
- `GET /api/v1/xdr/review`, `GET /api/v1/xdr/review/{id}`, `POST /api/v1/xdr/review/{id}/ack`
- `GET /api/v1/quarantine`, `POST /api/v1/quarantine/preview`, `POST /api/v1/quarantine/prune`
- `POST /api/v1/xdr/update-window/override`

### Network XDP (Kinetic), StyX Egress & L7 WAF
- `GET /api/v1/kinetic/status`, `GET /api/v1/kinetic/live`, `GET /api/v1/kinetic/events`, `GET /api/v1/kinetic/sources`, `GET /api/v1/kinetic/map`, `POST /api/v1/kinetic/reconcile`
- `GET/POST /api/v1/allowlist`, `POST /api/v1/allowlist/remove`, `POST /api/v1/allowlist/undo`
- `GET/POST /api/v1/blocks`, `DELETE /api/v1/blocks/{id}`, `POST /api/v1/blocks/undo`
- `GET /api/v1/styx/status`, `GET/POST /api/v1/styx/rules`, `GET /api/v1/styx/beacons`
- `GET /api/v1/l7/findings`, `GET/POST /api/v1/l7/integration`, `POST /api/v1/l7/selftest`, `POST /api/v1/airlock/inspect`

### Web Exposure, Worker Guard, TLS Sensor, LPE Guard & Edge Proxy (Modules A–E)
- `GET /api/v1/web-exposure/status`, `POST /api/v1/web-exposure/scan`, `GET /api/v1/web-exposure/advisories`
- `GET /api/v1/worker-guard/status`, `GET /api/v1/worker-guard/events`
- `GET /api/v1/tls-sensor/status`, `GET /api/v1/tls-sensor/flows`, `GET /api/v1/tls-sensor/handshakes`
- `GET /api/v1/lpe-guard/status`, `POST /api/v1/lpe-guard/apply`
- `GET /api/v1/edge-proxy/status`, `POST /api/v1/edge-proxy/restart`

### Titan, FIM, Malware, Hardening, Cells, Lockdown & Witness
- `GET /api/v1/titan/status`, `POST /api/v1/titan/policy`, `POST /api/v1/titan/contain`, `GET /api/v1/titan/events`, `POST /api/v1/titan/events/{id}/review`, `GET /api/v1/titan/quarantine`, `GET /api/v1/titan/exec/status`, `GET /api/v1/titan/exec/events`
- `GET /api/v1/fim`, `POST /api/v1/fim/baseline`, `POST /api/v1/fim/scan`, `GET /api/v1/chronos/status`, `GET /api/v1/package-integrity`, `POST /api/v1/package-integrity/scan`, `POST /api/v1/malware/scan`
- `GET /api/v1/hardening/posture`, `GET /api/v1/boot-trust`, `GET /api/v1/kernel/exposure`, `GET /api/v1/kernel/mitigation`, `POST /api/v1/kernel/mitigation/plan`, `POST /api/v1/kernel/mitigation/apply`, `POST /api/v1/kernel/mitigation/rollback`
- `GET /api/v1/transactions`, `POST /api/v1/transactions/preview`, `POST /api/v1/transactions/{id}/apply`, `POST /api/v1/transactions/{id}/reverse`
- `GET /api/v1/cells`, `GET /api/v1/cells/confinement`, `POST /api/v1/cells/preview`
- `GET /api/v1/parser-cells`, `GET /api/v1/parser-cells/status`, `GET /api/v1/parser-cells/inputs`, `POST /api/v1/parser-cells/open`, `POST /api/v1/parser-cells/{uuid}/freeze`, `POST /api/v1/parser-cells/{uuid}/unfreeze`, `POST /api/v1/parser-cells/{uuid}/export`, `POST /api/v1/parser-cells/{uuid}/burn`
- `GET /api/v1/lockdown/status`, `POST /api/v1/lockdown/arm`, `POST /api/v1/lockdown/trigger`, `POST /api/v1/lockdown/clear`
- `GET /api/v1/witness/status`, `GET /api/v1/witness/export`, `POST /api/v1/witness/checkpoint`, `POST /api/v1/witness/push`, `POST /api/v1/witness/challenge`, `POST /api/v1/witness/import`

### Settings, Feeds, Cases & Forensic Export
- `GET/PUT /api/v1/settings`, `GET /api/v1/settings/schema`, `GET /api/v1/settings/search`, `GET /api/v1/settings/drift`, `GET /api/v1/settings/integrity`, `GET /api/v1/settings/history`, `POST /api/v1/settings/{module}/preview`, `PUT /api/v1/settings/{module}`, `POST /api/v1/settings/rollback`, `GET /api/v1/settings/export`, `POST /api/v1/settings/import/preview`, `POST /api/v1/settings/import/apply`
- `GET /api/v1/feeds/status`, `POST /api/v1/feeds/sync`, `POST /api/v1/feeds/apply`
- `GET /api/v1/cases`, `POST /api/v1/cases/{id}/status`
- `GET /api/v1/evidence`, `POST /api/v1/evidence/verify`, `GET /api/v1/forensics/export`
