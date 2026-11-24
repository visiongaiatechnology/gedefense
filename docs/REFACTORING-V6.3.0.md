# GeDefense Linux V6.3.0 — Structural Refactoring Log

Living log for the post-release structural refactoring waves defined in
`C:\Users\Masterboard\Desktop\Dev_Bunker\GeDefense\GeDefense_Linux_Refactoring_Plan.md`.
Rules: structure-only (no logic/API/ABI/error-string/security changes), the
security-audit anchors and the full gate matrix must stay green, and each wave
( or documented sub-wave) ends with a local commit — no push unless explicitly
requested.

Baseline: V6.3.0 release commit `fb21f9d` (`VERSION = 6.3.0`, all gates green,
`dist/` artifacts rebuilt, quality pass done).

## Wave 1 — Go backends (`control/` & `gateway/`)

### Wave 1a (2026-11-24) — the largest Go files

| Original | Before | After | New same-package files |
|---|---:|---:|---|
| `control/server.go` | 3,860 | **565** | 13 `server_handlers_*.go` (largest 483): overview, xdr, defense, defense_feeds, integrity, transactions, titan_styx, settings, web, support, middleware, lifecycle, kinetic |
| `control/feeds.go` | 3,127 | **458** | `feeds_types` 386, `feeds_parser` 398, `feeds_manifest` 388, `feeds_store` 667, `feeds_manager` 608, `feeds_apply` 312 |
| `control/feed_signing.go` | 1,171 | — (deleted) | `feed_signing_verify` 522, `feed_tuf_manifest` 663 |
| `control/coreipc.go` | 2,716 | **677** | `coreipc_network` 635, `coreipc_exec_titan` 455, `coreipc_malware_quarantine` 546, `coreipc_hardening_lockdown` 451 |
| `control/config.go` | 2,006 | **239** | `config_types` 300, `config_defaults` 27, `config_parser` 526, `config_parser_sections` 489, `config_validate` 457 |
| `control/xdr.go` | 2,797 | **698** | `xdr_correlator` 712, `xdr_lineage` 715, `xdr_incidents` 711 |
| `gateway/main.go` | 1,598 | **408** | `routes_proxy` 693, `auth_kdf` 359, `tls` 77, `ratelimit` 110 |

All files `package main`; no new packages, symbols, dependencies, routes or
behaviour changes. Remaining files in the XDR family are 698–715 lines (a
follow-up fine-grain split to ≤500 is listed below); every other new production
file is ≤ 700 (`server.go` 565, others 483 max).

**Audit/test contract updates (integration owner, documented):** the audit
pinned the pre-split single files, so it was updated to check the same anchors
over the production-file families instead of moving anchors:
- `control/xdr.go` (10 sites) → concatenation of `control/xdr*.go` (tests excluded);
- `gateway/main.go` (4 sites) → concatenation of `gateway/*.go` (tests excluded);
- `control/server.go` (12 sites) → concatenation of `control/server*.go` (tests excluded);
- the source-scanning guard `TestNoHandlerForwardsARuntimeErrorAsOperatorText`
  now scans `server*.go` patterns through a new `moduleFamilySource` helper, so
  the moved handlers stay covered (same check, broader file set).
Anchors are still checked literally; nothing was removed or weakened. The audit
also gained no new permissions/paths and keeps the same forbid checks (e.g. no
`Decision: "kill"` in any `xdr*.go`).

**Documented deviations:**
- `control/feed_signing.go` contained the F-03 operator signing pipeline; it was
  distributed as `feed_signing_verify.go` + `feed_tuf_manifest.go` and the
  original file deleted (audit does not read it; tests compile unchanged).
- `feeds.go` needed a 1:1 extracted helper `(*FeedManager).tufSyncGateStateLocked`
  because an audit regex requires the TUF-gate precedence sentence physically in
  `feeds.go`; the extracted block is byte-identical, the call site ordering and
  lock discipline are unchanged (focused `TestFeed|TestTUF|…` green).
- XDR family: 4 files cannot all be ≤700 without deleting code (total 2,836
  lines); the 712/711/715 split is the tightest 4-way partition. Follow-up
  fine-grain split (5-way, ≤~570 each) is deferred to the wave-1 fine-grain step.

#### Wave 1a gate evidence (serial, settled tree)
| Gate | Result |
|---|---|
| `go vet ./...` control (linux/CGO=0) + gateway (CGO=1) | exit 0 / exit 0 |
| `gofmt -l` on all 46 touched files | empty |
| `make test` | **exit 0** — control `ok 187.7 s`, gateway `ok 24.2 s`, node check + `SECURITY AUDIT PASS` |
| `make test-race` | **exit 0** — control `ok 274.9 s`, gateway `ok 136.3 s` |
| `make fuzz-smoke` | **24/24 PASS** |
| Validators | `validate-linux-integration` (`GeDefense 6.3.0 … PASS`), `validate-github-release`, `validate-systemd`, `security-audit.sh` PASS |
| Focused anchors | `TestIdentifiersAreCorrelationOnly` PASS, `TestNoHandlerForwardsARuntimeErrorAsOperatorText` PASS |
| Behaviour proof | per-file byte-identical chunk verification (143 server chunks exactly once; xdr/gateway AST-based relocation with gofmt-normalised multiset equality; 1:1 feeds helper) |

Wave 1a commit: `refactor(wave1a): split Go control/gateway mega-files
(structure-only)`.

### Wave 1b (pending) — remaining >1,000-line Go files
`runtime_settings.go` 1,442 · `state.go` 1,377 · `evidence_ledger.go` 1,363 ·
`kinetic_engine.go` 1,305 · `release.go` 1,281 · `titan.go` 1,235 ·
`fabric_settings.go` 1,157 · `boot_trust.go` 1,061 · `main.go` 1,097 ·
`kernel_advisories.go` 1,023 → same-package thematic files (audit anchors kept
in the family where the audit contract permits; otherwise family aggregation as
in wave 1a), then the wave gate + local commit.

### Wave 1 fine-grain (optional, per plan)
Files in the 500–999 range (`fabric_schema`, `l7_server`, `cms`,
`l7_fabric_settings`, `mitigation_guard`, `l7_tls`, `airlock`, `transactions`,
`fim`, `xdr_recovery`, `deception`, `overview_map`, `cases`, `response_engine`,
…) and the XDR family 5-way split to reach the ≤ 500 guideline in the Go
backend.

## Wave 2 — Web UI (`control/web/`) — pending
## Wave 3 — Rust privileged core (`rust/gedefense-core/src/`) — pending
## Wave 4 — Rust eBPF (`rust/gedefense-ebpf/src/`) — pending
## Wave 5 — Shell scripts & large test files — pending
