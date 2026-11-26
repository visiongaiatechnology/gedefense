# GeDefense Linux 6.3.0 — Configuration & Operational Lifecycle

> **Reference:** [`../OPERATIONS.md`](../OPERATIONS.md) · [`../PRODUCTION-BETA-GATE.md`](../PRODUCTION-BETA-GATE.md) · [`API-REFERENCE.md`](API-REFERENCE.md)

---

## 1. Promotion Gates (`Observe → Canary → Enforce`)

New installations always boot cleanly into **`observe`** mode with zero active kernel blocking until core IPC (`VGT3`), signed policies, and management allowlists synchronize:

```text
Observe ───────────▶ Canary ───────────▶ Enforce
  │                    │                   │
  │ XDP active,        │ Evidence-checked  │ Signed XDP/CIDR enforcement +
  │ zero block rules,  │ SIGSTOP only      │ broker-verified SIGKILL +
  │ recording telemetry│ (network observe) │ safe V6 defaults (StyX/Titan/Cells)
```

| State | Network Plane | Host / Process Reaction | Mandatory Gate |
|---|---|---|---|
| **Observe** | XDP attached, empty blocklist (`VERIFY_EMPTY`) | Record telemetry only | Authenticated `core_connected=true` + signed Observe policy |
| **Canary** | Observe + telemetry soak | Evidence-checked `SIGSTOP` (`AlertOnly` on web tier) | Policy verified + healthy XDR + soak period |
| **Enforce** | Signed LPM block rules | Broker-verified `pidfd` `SIGKILL` / Quarantine Vault | Non-empty `ManagementAllowlist` synchronized in XDP (`Allowlist SYNC`) |
| **Degraded** | Fail-safe / unconfirmed | Active blocking suspended | Visible incident / operator recovery required |

> [!IMPORTANT]
> Never lock yourself out: configure your operator management IP/CIDR in `/etc/vgt/gedefense/gedefense.toml` under `[defense] allowlist` or via Runtime Settings before promoting to `enforce`. Enforce transitions fail closed if `allowlist` is empty.

---

## 2. Promoting Phases & Sealing Release FIM

All state-changing calls to `/api/v1/*` require a Bearer token (plus Gateway CSRF/Step-Up when proxied via HTTPS `:9843`) and a unique `X-VGT-Request-ID` UUID:

```bash
# Promote Observe -> Canary -> Enforce (on local loopback :9844 or via Gateway RBAC step-up)
curl -X POST http://127.0.0.1:9844/api/v1/release/transition \
  -H "Authorization: Bearer $TOKEN" -H "X-VGT-Request-ID: $(uuidgen)" \
  -H "Content-Type: application/json" -d '{"target_phase":"canary","confirm":"PROMOTE:CANARY"}'

curl -X POST http://127.0.0.1:9844/api/v1/release/transition \
  -H "Authorization: Bearer $TOKEN" -H "X-VGT-Request-ID: $(uuidgen)" \
  -H "Content-Type: application/json" -d '{"target_phase":"enforce","confirm":"PROMOTE:ENFORCE"}'

# Seal immutable release binaries & config into the AES-GCM FIM baseline
curl -X POST http://127.0.0.1:9844/api/v1/fim/baseline \
  -H "Authorization: Bearer $TOKEN" -H "X-VGT-Request-ID: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{"scope":"release","reason":"Initial verified 6.3.0 enforce seal","confirm":"REBASELINE RELEASE"}'
```

---

## 3. Emergency Stop & Recovery

Triggered via Web UI or `POST /api/v1/release/emergency-stop`:
1. Immediately writes `/var/lib/vgt/gedefense/EMERGENCY_STOP` and halts response triggers.
2. Commands `gedefense-core` to empty all XDP block maps and return authenticated `VERIFY_EMPTY`.
3. Persists a signed `observe` policy (`verified-empty` reported only when all three steps succeed; `/readyz` flips red while `/livez` stays green).
4. After root-cause review, clear the anchor via `POST /api/v1/release/emergency-stop/clear` and review posture before re-promoting.

---

## 4. Runtime Settings Namespaces & Hardened Benchmark Profile (`EDR/Hardened Max`)

Runtime policies persist versioned settings with dry-run preview (`POST /api/v1/settings/{module}/preview` → `PUT /api/v1/settings/{module}`), schema validation, and instant rollback (`/api/v1/settings/rollback`):

| Namespace | Purpose | Conservative Default on `enforce` | Max-Hardness Benchmark Profile |
|---|---|---|---|
| `kinetic` | eBPF/XDP LPM + flood/portscan defense | Active per allowlist | `enforcement_mode="block"`, `ip_threshold=20`, `velocity_limit=10`, `portscan_threshold=3`, `auto_contain_*=true` |
| `l7` | Native Go L7 WAF & normalization | `alert` / optional inline | `mode="block"`, `inline_enabled=true`, `alert_score=30`, `block_score=70`, rate-limits `20/m` & `180/m` |
| `xdr` | Host behavioral & Anti-Spyware correlation | Active correlation | `alert=30`, `contain=60`, `kill=90`, all 6 rule modules + `advanced.malware_correlation=true` |
| `titan` / `titan_exec` | FIM Contraband + BPF-LSM Exec Gate | `titan_exec="contain"` | `titan.mode="STRICT"` + `titan_exec.mode="untrusted"` (`require_ctime=true`) |
| `styx` | Cgroup Egress + Phase-2 PCR + DNS Tunnel | `mode="monitor"` | Global `monitor` + `per_cell mode="enforce"` on web worker cgroups (`php-fpm`/`nginx`) |
| `worker_guard` / `tls_sensor` / `lpe_guard` | Modules B–D (crashes, ALPN, kernel LPE) | Opt-in on web hosts | All 3 active (`strict_exec`, `strict_mmap`, deny `AF_PACKET`/`VSOCK`/`SCTP`, `enforce_aslr=true`) |
| `parser_cells` / `lockdown` | Ephemeral burn cells & Emergency Lockdown | `parser_cells=enabled`, `lockdown` opt-in | `parser_cells.burn_on_incident=true`; `lockdown` `auto_arm=true`, `freeze_processes/brokers=true` |
| `chameleon` | Load-time kernel symbol obfuscation (`AP-8`) | Off (`default-off`) | Signed install manifest via `scripts/apply-chameleon-profile.sh` |
| `hardening` | Transactional sysctl (`astraeaos-cis-l1`) | Operator-applied | Preview → Apply via `/api/v1/transactions/*` + opt-in `gedefense-cis-baseline --apply` |
