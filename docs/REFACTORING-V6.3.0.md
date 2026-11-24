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

### Wave 1b (2026-11-24) — remaining >1,000-line Go files

| Original | Before | After | New same-package files |
|---|---:|---:|---|
| `control/runtime_settings.go` | 1,491 | **271** | `runtime_settings_types` 330, `runtime_settings_store` 476, `runtime_settings_apply` 443 |
| `control/state.go` | 1,480 | **498** | `state_persist` 427, `state_metrics` 576 |
| `control/evidence_ledger.go` | 1,418 | **476** | `evidence_ledger_crypto` 495, `evidence_ledger_query` 478 |
| `control/kinetic_engine.go` | 1,394 | **495** | `kinetic_probes` 495, `kinetic_eval` 418 |
| `control/release.go` | 1,336 | **537** | `release_gate` 518, `release_soak` 321 |
| `control/titan.go` | 1,318 | **635** | `titan_sync` 483, `titan_policy_compile` 241 |
| `control/boot_trust.go` | 1,117 | **213** | `boot_trust_tpm` 500, `boot_trust_eval` 443 |
| `control/fabric_settings.go` | 1,191 | **284** | `fabric_settings_validate` 480, `fabric_settings_projection` 452 |
| `control/main.go` | 1,119 | **392** | `main_wire` 563, `main_runtime` 286 |
| `control/kernel_advisories.go` | 1,077 | — (deleted) | `kernel_advisories_db` 464, `kernel_advisories_eval` 631 |

All files `package main`, no new packages/dependencies/symbols, no logic, flag,
startup-order, error-string, evidence-signing, TPM/release-gate or advisory
changes. All files ≤ 700 (hard ceiling); six files are above the 500-line
guideline with documented reasons: `state_metrics` 576 (minimal coherent 3-way
partition of the state aggregate), `main_wire` 563 (clean construction/attach
split of the control-plane wiring), `kernel_advisories_eval` 631 (the plan
prescribes a two-file split: DB + evaluation), `release.go` 537 /
`release_gate` 518 / `titan.go` 635 (type parents kept together deliberately).
`kernel_advisories.go` was deleted after its content was distributed; the wave
commit stages the deletion together with the replacements.

**Audit contract:** integration owner pre-aggregated the audit reads to the
production families `runtime_settings*.go`, `state*.go`, `evidence_ledger*.go`,
`release*.go`, `fabric_settings*.go`, `main*.go` (tests excluded); the audit was
green before and after the split, no anchors were removed. `titan*`/`kinetic*`/
`boot_trust*`/`kernel_advisories*` have no audit read sites, their behaviour was
proven by the focused and full test suites.

#### Wave 1b gate evidence (serial, settled tree)
| Gate | Result |
|---|---|
| `go vet ./...` control (linux/CGO=0) + gateway (CGO=1) | exit 0 / exit 0 |
| `gofmt -l` on all touched files | empty |
| `make test` | **exit 0** — control `ok 248.3 s`, gateway cached green, node check + `SECURITY AUDIT PASS` |
| `make test-race` | **exit 0** — control `ok 291.9 s`, gateway cached green |
| `make fuzz-smoke` | **24/24 PASS** |
| Validators | `validate-linux-integration` (`GeDefense 6.3.0 … PASS`), `validate-github-release`, `validate-systemd`, `security-audit.sh` PASS |
| Structure proof | per-file AST/line-slice relocation checks: all original declarations present exactly once, parents contain only deletions/relocated glue (e.g. release 0 insertions/799 deletions, titan 0/683, boot_trust 0/904; runtime+state 2,790/2,790 original non-blank lines preserved; evidence 48/48 + kinetic 36/36 declarations; fabric/main/advisories relocated once, bootstrap/serve blocks byte-identical) |

Wave 1b commit: `refactor(wave1b): split remaining Go mega-files
(structure-only)`.

### Wave 1 fine-grain (optional, per plan) — pending
Files in the 500–999 range (`fabric_schema`, `l7_server`, `cms`,
`l7_fabric_settings`, `mitigation_guard`, `l7_tls`, `airlock`, `transactions`,
`fim`, `xdr_recovery`, `deception`, `overview_map`, `cases`, `response_engine`,
…), the XDR family 5-way split, and the six >500 files from wave 1b above, to
reach the ≤ 500 guideline across the Go backend.

## Wave 2 — Web UI (`control/web/`)

### Wave 2 (2026-11-24) — i18n, app module graph and stylesheet modularization

| Original | Before | After | New files |
|---|---:|---:|---|
| `control/web/i18n.js` | 9,053 | **86** | `i18n/{de,en,ru,zh-CN}.js` (2,251 lines each, catalogue data + stable import point) |
| `control/web/app.js` | 3,160 | **425** | `js/state.js` 564 · `js/navigation.js` 519 · `js/views_overview.js` 663 · `js/views_xdr_spyware.js` 300 · `js/views_logs_audit.js` 276 · `js/views_titan_styx.js` 752 |
| `control/web/app.css` | 1,371 | — (deleted) | `css/{tokens 103, layout 543, modals 459, components 3,134, tables 77}` |
| `control/web/v4.css` | 2,950 | — (deleted) | (same five css files) |
| `control/web/index.html` | 3,873 | 3,873 (−2/+5 lines) | five stylesheet links replace the two legacy ones |

Structure-only: the four catalogues are the original JSON data byte-identically
(`export const catalog = Object.freeze(...)` per language; `i18n.js` keeps the
public translator API and re-exports the frozen `catalogs`, so every
`import { t } from './i18n.js'` is unchanged). `app.js` remains the single ES
module entry: 138 original declarations preserved exactly once, 27 external
imports in the pre-split order, 51 DOM listener registrations in identical
order, `initialize()` call order byte-identical; six `bind*` helpers are the
only added glue. CSS: 1,163 top-level blocks reparse-verified byte-identical
(4,321 → 4,316 lines: only boundary newlines changed); `index.html` links
`tokens → layout → modals → components → tables` and drops the legacy
`app.css`/`v4.css` links.

**Cascade analysis (CSS):** exhaustive permutation testing over the five files
and a full declaration model (media, `!important`, property families) compared
the effective winner per selector/property over 40 widths (every breakpoint
±1, 2000→300 px) × reduced-motion on/off: **0 winner changes**. The only
positional change is that the former `v4.css` rules now also precede the
vendored jsvectormap stylesheet; that stylesheet only defines `--jvm-*` custom
properties and flat `.jvm-*` rules, and the moved selectors either do not exist
there or are more specific/tie with identical values — proven by element-level
simulation (0 changes). Residual risk (honest): static analysis cannot simulate
every descendant/pseudo-state/runtime-composed class-list interaction without a
browser; no rule text changed.

**Audit/tests/allowlist (integration owner):**
- Audit i18n gate now reads the four `web/i18n/<language>.js` catalogues,
  enforces the same parity/placeholder/coverage rules and checks the thin
  translator contract; translation-coverage scanning is recursive over
  `web/**/*.js` (i18n data and vendor excluded) so the split app modules remain
  covered. The audit `app` anchors (`scanMalware`, `renderMalwareProtection`,
  `renderMalwareResult`) are checked over `web/app.js` + `web/js/*.js`; the
  `i18n.js` asset anchor remains (thin module still served).
- `webAssetAllowlist`: added the 4 i18n, 6 js and 5 css assets; removed the
  deleted `app.css`/`v4.css`. The exhaustive embedded↔allowlist contract tests
  are green.
- Test updates are path-only / scan-scope only, with assertions identical:
  `evidence_gate_test` (catalogue count across four files),
  `fabric_settings_ui_test`, `hardening_coverage_test`,
  `kinetic_layout_test`, `protection_ui_test`, `threat_intel_ui_contract_test`
  (stylesheet path → `css/components.css`), `web_i18n_contract_test`
  (catalogues read per language; t()-call scan recursive). `web_i18n_contract_test`
  still pins `authorizeSession()` to `app.js`, and that function stayed there.
- `Makefile` node syntax gate is recursive now:
  `find control/web -name '*.js' -type f -exec node --check {} +`.

**Documented deviations:** `js/state.js` 564, `js/views_overview.js` 663,
`js/views_titan_styx.js` 752 and `css/components.css` 3,134 exceed the 500-line
guideline — the JS files are single cohesive domains under the plan's fixed
six-file allowlist, and the CSS split is the plan's five-theme scheme; a future
fine-grain pass can subdivide `components.js`/`components.css` theme sections
with new allowlist entries.

#### Wave 2 gate evidence (serial, settled tree)
| Gate | Result |
|---|---|
| `node --check` recursive over `control/web/**/*.js` | exit 0 |
| `go vet ./...` control + gateway | exit 0 / exit 0 |
| `make test` | **exit 0** — control `ok 190.2 s`, gateway cached green, recursive node check + `SECURITY AUDIT PASS` |
| `make test-race` | **exit 0** — control `ok 230.0 s` |
| `make fuzz-smoke` | **24/24 PASS** |
| Validators | `validate-linux-integration` (`GeDefense 6.3.0 … PASS`), `validate-github-release`, `validate-systemd`, `security-audit.sh` PASS |
| Focused web contract tests | embedded↔allowlist exhaustive, asset resolution, fabric/hardening/kinetic/protection/threat-intel UI contracts, i18n parity+coverage, auth-before-claim — PASS |

Wave 2 commit: `refactor(wave2): modularize web UI (i18n, app modules, css)
(structure-only)`.

## Wave 3 — Rust privileged core (`rust/gedefense-core/src/`) — pending
## Wave 4 — Rust eBPF (`rust/gedefense-ebpf/src/`) — pending
## Wave 5 — Shell scripts & large test files — pending
