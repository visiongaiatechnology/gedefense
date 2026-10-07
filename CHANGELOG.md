# Changelog

## 4.2.0 — Security Fabric Control Plane

> **Release state:** all batches B16–B24 implemented. Every gate that can run without
> a kernel core is green: `gofmt`, `go build`, `go vet`, `go test`, `go test -race`,
> `go test -shuffle=on -count=10`, `govulncheck` (no vulnerabilities found) and a
> headless-browser check of the dashboard under the production CSP, including
> Trusted Types enforcement.
>
> **Not covered:** the control plane has not been run as a live service, because that
> needs a kernel core and the XDP/TC datapath. Kernel verification, real drop
> evidence, the Gateway and Rust release gates, and a soak run remain target-host
> tasks. `staticcheck` and `golangci-lint` are not installed on the build host.
>
> **Deploy recommendation:** Observe mode first. Static analysis alone once let a
> completely blank operator console through — see the four dashboard defects listed
> in the security section below.

- **Security fixes for 4.1.0** — every finding from the full-stack audit is remediated
  and locked by a test. The most severe was in 4.1.0's canary deployment: a symbolic
  link placed at the decoy path or its staging path redirected the write to any
  location the service identity could reach (cron directories, `authorized_keys`,
  `ld.so.preload`), which is arbitrary file write leading to privilege escalation on
  a root service. Two further classes were found while verifying the fix and are also
  closed: the original `O_CREATE|O_EXCL` remedy protected only the final path
  component, and three write paths followed links. All paths a request can influence
  now resolve one component at a time with `openat(2)` and `O_NOFOLLOW`.
  Five handlers that returned raw runtime error text (filesystem paths, kernel
  faults, upstream feed URLs, DNS/TLS detail) now return opaque fault responses
  behind a structural disclosure rule instead of a keyword blacklist. Predictable
  fallback identifiers, a remote panic path in the import preview store, colliding
  import tokens, a CSP that granted `unsafe-inline` for styles, and HSTS over
  cleartext are all fixed.
- **Four dashboard defects fixed that static analysis could not see** — the operator
  console was **completely blank**: four double commas in `i18n.js` broke the entire
  ES module graph, and `node --check` had passed because Node validates `.js` as
  CommonJS. The vendored map could **never** load: module resolution is URL-based,
  so a directory import resolved the module's relative imports against a file URL and
  requested a path that does not exist; a directory now redirects to its
  trailing-slash form. Sources without coordinates were plotted at 0,0 because
  `Number(null)` is `0`, drawing fabricated markers in the Gulf of Guinea. And the
  live-source layer would have stayed permanently empty because the map library only
  creates its marker group when the constructor receives a marker list.
- **Toolchain security floor** — `go.mod` declares `toolchain go1.26.6`.
  `govulncheck` reports six reachable standard-library vulnerabilities below it,
  including two on the most exposed paths in the product (the L7 ingress reverse
  proxy and the threat-intelligence feed fetcher). A test refuses to pass a build on
  an older toolchain, so the floor cannot silently decay. **Build with Go ≥ 1.26.6.**
- **Security Fabric Control Plane** — twelve administrable modules (kinetic, network,
  protection, xdr, l7, threat_intel, hardening, integrity, boot_trust, policy_trust,
  forensics, system). The server is the single source of truth and the dashboard
  renders from its schema, so it contains no setting name, bound or apply class.
  Immutable snapshots on hot paths; restart-class values are persisted but never
  activated silently. Safety invariants are deliberately **not** administrable:
  bounded kernel maps, core authentication, path validation, private-key secrecy,
  management self-lockout, feed anti-poisoning, the canary HMAC key and the built-in
  quarantine denylist.
- **Fabric control-plane surface** — deterministic settings search with live effective
  values, a signed secret-free export bundle, a genuinely two-stage import (a
  single-use token that expires and refuses if the stored revision moved), and a
  drift watch that reports `CONFIG_DRIFT` rather than `SYSTEM_NOMINAL`.
- **Vendored SVG world map (jsVectorMap 1.7.0, MIT)** for the Kinetic live view —
  local only, no CDN and no tile server, GeoIP/ASN resolution entirely on the host.
  Live sources render as markers, countries are coloured by event rate, blocked
  sources are drawn from their own bucket, and every layer is bounded before it
  reaches the DOM. **Trusted Types are not weakened:** the library's two `innerHTML`
  sites sit behind a factory argument that is skipped when both zoom buttons are
  supplied, verified in a real browser rather than argued.
- **Backward-compatible settings migration** — the new namespaces keep the canonical
  HMAC input byte-identical so an installation that predates them still authenticates,
  is upgraded in place and keeps its operator tuning.
- **UI/UX recomposure** — the operational views no longer stack full-width bands above
  equal-weight statistic cards. The card grid is gone from the entire dashboard,
  colour is state-driven rather than decorative, interactive rows are real `<button>`
  elements (zero `role="button"` remain), and WCAG AA contrast plus
  `prefers-reduced-motion` are respected throughout.

- **Dashboard module graph repaired (production blocker)**:
  - `fabric-settings.js` was imported by `app.js` but missing from the embedded asset allowlist, so `/assets/app.js` failed to resolve and the entire operator console stayed blank — the same failure class as the 4.1.0 `kinetic.js`/`threat-intel.js` incident.
  - The allowlist is now a named value locked to the real module graph by three new contract tests, including one that walks the actual ES `import` graph from `app.js` and requires every resolved module to be served.
- **Fabric Settings metadata registry (plan section 6)**:
  - New server-side registry is the single authoritative source for every administrable setting: bounds, default, value type, operator-facing group, apply class, risk class and description.
  - `GET /api/v1/settings/schema` publishes it; risk/apply classification, the restart-class detectors and the dashboard all derive from the same data instead of independent heuristics.
- **Application Defense (L7) administration (B20, plan section 16)**:
  - Full request-budget, score, rate-limit, sensitive-path, peer-authentication, inline-edge and TLS/SNI/JA3 namespace, including an administrable unknown-fingerprint behaviour.
  - Administrable built-in rule registry (enablement, score, confidence, block eligibility) over a closed allowlist; patterns stay read-only and an alert-only rule can never authorise a block.
  - Configuration is compiled into an immutable snapshot published atomically. One inspection resolves exactly one snapshot, so a revision landing mid-request can no longer produce a half-old configuration.
  - Restart-class values are persisted but never activated silently; the module reports `restart_required` and the change is refused outside Observe/Degraded.
- **Schema-driven Settings workbench**:
  - The dashboard no longer contains any setting name, bound or apply class. The surface renders from the server schema, so client and backend cannot drift.
  - Orientation rail with search, field editor that shows apply class, risk, bounds and the effective value from the running component, docked preview sidecar with per-key diff, revision history with restore, and a dirty-state guard.
  - Internal module sub-navigation with anchors into each module's real sections instead of empty placeholder tabs.
  - No `innerHTML`, no external CDN, reduced-motion aware, keyboard reachable.
- **Backward-compatible settings migration (v2 → v3)**:
  - The new namespace keeps the canonical HMAC input byte-identical for existing encrypted settings documents, so an installation that predates the namespace still authenticates, is upgraded in place and keeps its operator tuning.

- **Threat Intelligence administration (B21, plan section 18)**:
  - Structured feed source model replacing the hard-coded global source list: id, name, enablement, URL, format, action, priority, trust weight and per-feed bounds. The static `feeds.sources` key now seeds the first revision instead of being silently ignored.
  - Administrable transport safety (host allowlist, redirect budget, cross-host policy, content type policy), resource bounds (per-feed download and entry ceilings, global budget, timeout, concurrency), validation policy (address families, valid-entry ratio, malformed ceiling, generation policy), bounded retry with exponential backoff, and kernel publication guard rails including a maximum diff per sync.
  - New `POST /api/v1/feeds/apply` plus a "Publish kernel generation" action, pairing with automatic publication being optional.
  - **Determinism fix:** the published generation was composed by iterating a map under a size cap, so which entries survived the budget was non-deterministic between syncs. Composition now follows priority order with trust weight breaking ties, and always yields the same generation for the same input.
  - **Truthfulness fix:** feed health is now time-aware. A feed whose last known-good generation has aged past the configured thresholds reports STALE or CRITICAL instead of OK.
  - One truth for feed enablement: the namespace and the legacy `feeds_enabled`/`auto_feed_sync` fields are derived from each other in the same transaction and re-validated on every save.

- **Host Security administration (B22, plan section 20)**:
  - New `hardening` namespace covering posture, sysctl profiles, Morpheus RASP, the deception grid and Airlock. Every one of those five areas previously had **zero** configuration fields: the RASP protected-name set and Airlock size bound were compiled in, the sysctl profile map was frozen at construction, and the posture thresholds were hard-coded at 90/75/50.
  - Administrable posture evaluation with a periodic loop, per-required-domain verdicts, and threshold classification. A required domain with no measurable control is reported UNAVAILABLE, so removing a domain from the list can never turn an unmeasurable posture green.
  - Sysctl profiles are now derived from the closed, centrally allowed control vocabulary: an operator selects controls and can never author a kernel key or value. Ad-hoc control submissions can be refused by policy.
  - RASP gained an administrable protected-name set, per-tool debugger exemptions, and a report-only posture that still emits the incident while suppressing containment.
  - The deception grid is no longer add-only: canaries can be listed, re-enrolled on a type, owner or mode change, and retired. A canary path outside every allowed root is rejected before deployment.
  - Airlock inspection and staging bounds are live, and `executable_upload_policy` is a real enforcement lever (reject vs. report at a score that cannot cross a block threshold), with optional automatic quarantine that preserves a refused upload as evidence.
  - One distribution choke point projects the namespace onto all three engines from a single revision.

- **Integrity administration (B22 part 2, plan section 21)**:
  - New `integrity` namespace covering file integrity monitoring, Chronos checkpointing, package verification and the evidence ledger. None of those four areas had a single configuration field before.
  - **Chronos walked the filesystem unbounded** — no file or byte budget over an operator-supplied root, with every visited path retained in memory. The walk is now bounded and a consumed budget reports a partial digest set instead of a completed scan.
  - **The Chronos checkpoint was plaintext JSON** containing a path → SHA-256 map of the protected tree, while every other store is sealed. It is now encrypted with the same storage cipher and an unsealed checkpoint is rejected.
  - Periodic evidence verification and scheduled package verification, both on administrable intervals, so tampering is detected while the service runs rather than at the next operator mutation.
  - The FIM scan cadence is re-read from the published revision every cycle instead of being captured at start.
  - **Dashboard truthfulness fix:** the Integrity view tested for a `HEALTHY` FIM state the engine never emits, so a verified baseline was rendered as an action-required failure and the header could never turn green.

- **Boot Trust and Policy Trust administration (B22 part 3, plan sections 22 and 23)**:
  - New `boot_trust` namespace: evidence cache lifetime, the required TPM PCR selection, the required kernel boot arguments, three enforcement switches, and the evidence and kernel-image read bounds. All of it was frozen at compile time before.
  - New `policy_trust` namespace: live signature requirement, policy state read bound, periodic verification interval, and **rollback protection** — a generation floor that refuses a replayed older policy document instead of letting a restored state file silently downgrade enforcement.
  - Requirements that cannot be proven are now violations rather than observations: a mandatory-but-disabled Secure Boot anchor, an unobservable kernel lockdown and an absent attestation are all reported as policy violations instead of neutral platform properties.
  - The required PCR selection is compared in order by the attestation contract, so it is sorted and deduplicated on write and is live in both directions.
  - New periodic trust watch: the signed policy document is re-verified on an administrable interval and boot evidence is re-collected, so tampering or a changed boot anchor is detected while the service runs.
  - **UI fix:** the Settings workbench mounted an empty tab on the five views that have no administrable namespace, and the Boot and Policy pages needed a module-to-page alias before their Settings tabs could mount at all.

- **Operational view recomposure (UI/UX Supreme)**:
  - Kinetic Defense, Threat Intelligence, Application Defense and XDR no longer stack three full-width bands above a row of equal-weight statistic cards. Each view now opens with a single command plane that answers the question the view exists for, followed by a grouped telemetry rail.
  - The card grid is gone from those views: counters live in semantic `<dl>` groups (*window / detection / response*, *traffic / verdict*, *visibility / pipeline*, *vectors / sources*) inside one bounded surface with hairline dividers. Per-card radius, border, shadow and decorative corner accent removed.
  - Eight verbose label/value/footnote triples collapse into a short label plus one group-level qualifier, so the actual data-source truth statement is stated once instead of eight times.
  - Colour is now state-driven rather than decorative: counters no longer carry a static accent, and the two functional tones appear only when the value is non-zero.
  - Threat Intelligence's block/correlate/annotate mix is drawn as one stacked share track with the same three numbers readable as text beside it; a zero total renders an empty track and the degraded state clears it.
  - Accessibility: rail text roles moved off the low-contrast secondary token to meet WCAG AA on a gradient surface, values use tabular numerals, and the rail groups are plain `<div>`s so they do not register as unnamed region landmarks.
  - The Overview landing page followed: its six equal cards — four navigation shortcuts and two status values sharing one container — became a four-group node board. The card-grid pattern is now absent from the entire dashboard.
  - Interactive rows are real `<button>` elements, so keyboard activation works natively: four hand-written Enter/Space handlers and four `role="button"` substitutions were deleted, leaving zero `role="button"` attributes in the dashboard.
  - New contract tests lock the composition (no card autopilot on any view), the rail styles, and the resolution of every literal element reference in every served module.

- **Fabric control-plane surface (B23 part 1, plan sections 36–39)**:
  - New `GET /api/v1/settings/search` — deterministic search across every administrable key, returning each hit with its live effective value and the reason it matched. A hit opens the owning module's Settings tab and focuses the field.
  - New `POST /api/v1/settings/export` — a sanitized bundle of all ten namespaces, signed with the policy trust anchor. The bundle is built from administrable values only and a test scans the raw output for key material rather than trusting that.
  - New `POST /api/v1/settings/import/preview` and `.../import/apply` — a genuinely two-stage import. The preview verifies the signature, validates dependencies and shows the diff; the apply installs exactly the revision that was reviewed, keyed by a single-use token that expires and that refuses if the stored revision moved. There is no import-to-apply shortcut.
  - An imported bundle passes the *same* release-phase guards as a dashboard edit, so it cannot install in Enforce what the editor is forbidden from changing there.
  - New `GET /api/v1/settings/drift` plus a periodic drift watch: a stored revision that has not reached the engine reports `CONFIG_DRIFT`, never `SYSTEM_NOMINAL`, with restart-class findings flagged as such.
  - The global settings page is now the **Fabric Settings** control-plane surface with search, drift, revision history, export and the two-stage import.

- **Security audit — fixes (full stack)**:
  - **Critical:** canary deployment followed symbolic links. A link placed at a decoy path or its staging path redirected the write to any location the service identity could reach (cron directories, `authorized_keys`, `ld.so.preload`) — arbitrary file write leading to privilege escalation. The write now uses `O_CREATE|O_EXCL` with `Lstat` checks on the target, the parent and the staging path, closing both the attack and the check-to-open race.
  - **High:** five handlers returned raw runtime error text to clients, disclosing filesystem paths, kernel faults, upstream feed URLs and DNS/TLS detail. A dedicated opaque fault response replaces them.
  - **High:** the disclosure guard was a keyword blacklist that missed real leaks and rewrote legitimate operator wording. Replaced by a structural rule that makes forwarding a runtime error as a published message impossible.
  - **High:** evidence identifiers fell back to a timestamp when the system random source failed, making block, incident, quarantine, transaction and case IDs predictable. It is now fail-closed.
  - **High:** a failed secret generation left the import preview store nil, giving two endpoints a remote panic path. Both now fail closed.
  - **High:** import tokens were derived from a change descriptor, so two reviews sharing a revision and change count could collide and apply the wrong configuration. Tokens now bind the reviewed content.
  - **Medium:** three further write paths followed links (Chronos checkpoint staging, feed state, quarantine vault with `O_TRUNC`); all now use the crash-safe atomic writer or `O_EXCL`, and the vault allocates a suffixed name instead of truncating existing evidence.
  - **Medium:** the CSP no longer grants `unsafe-inline` for styles, and `require-trusted-types-for 'script'` turns the absence of DOM-XSS sinks into a browser-enforced runtime invariant rather than a source-scan property.
  - **Medium:** HSTS is emitted only on TLS connections.
  - New `security_hardening_test.go` locks every fix as an invariant, including the 19-character evidence identifier contract and the absence of Trusted Types sinks.

- **Forensics administration (B23 part 2, plan section 24)**:
  - New `forensics` namespace covering cases, the signed evidence export and the quarantine boundary. Every value in it either bounds work or restricts what the forensics path may do; none of it can widen access.
  - **The quarantine denylist can only be tightened.** The compiled-in set covering `/`, `/proc`, `/sys`, `/dev`, `/run` and the service directories is appended at evaluation time and never stored in a revision, so no configuration can remove an entry. An administered allowlist that overlaps a forbidden root is rejected, because it could never be reached or would silently disable the denial it sits inside. The malware-scan paths deliberately keep the immutable rules only and never inherit an operator relaxation.
  - **Export redaction runs before signing**, so a verifier sees the redacted document as canonical and redaction cannot be undone with the public key. Private, loopback, link-local and CGNAT addresses become a stable token derived from the address; public indicators are kept and address-shaped substrings are left alone.
  - `signing_required` defaults to true and refuses an export that cannot be signed; waiving it produces a record that announces itself in a response header and in the body.
  - **Case correlation is now bounded in time.** A recurrence outside the administrable window opens a new case instead of extending one indefinitely, and case creation is gated by an administrable score threshold so a noisy detector cannot flood the register.
  - Auto-close of idle cases is opt-in (default off) and never touches a case an operator moved out of `open`.
  - System namespace remains open within B23.

- **System administration (B23 part 3, plan sections 26–27)**:
  - New `system` namespace covering the control plane's own bounds and exposure: API rate limit and burst, stream client ceiling, metrics exposition, event cache budget, API payload ceiling and the core command deadline.
  - **The payload ceiling is applied in the middleware**, so no handler can be reached with a larger body and a future handler inherits it unchanged. It caps a handler's own limit rather than replacing it, so one revision cannot widen every endpoint at once.
  - **A tightened rate limit clamps existing buckets.** Without that step a caller who had already accumulated the old allowance could keep spending it for the rest of the minute, so the new limit would not take effect until the next minute.
  - **A tightened event budget trims the ring immediately**, and the core command deadline became an atomic read on the IPC path so a revision retunes it without a restart.
  - The module view publishes the compiled-in hard cap beside every administered value, so an operator can see that a setting is not the last line of defence.
  - Bootstrap material (listen address, TLS paths, core and cell sockets) is deliberately not administrable: a "setting" that silently needs a restart is a control that only appears to work. Log level and clock drift are absent because no such subsystem exists.
  - B23 is complete; 12 Fabric modules registered.

- **Security correction — symlink resolution and identifier boundary**:
  - The audit's claim that `O_CREATE|O_EXCL` removed the write race was **overstated**: it protects the final path component only. Parent directories are re-resolved by the kernel at open time, so a substituted parent directory redirected the write while the exclusive create still succeeded — an arbitrary-write primitive for a root service.
  - Paths a request can influence now resolve **one component at a time** with `openat(2)` relative to an already-open descriptor, carrying `O_NOFOLLOW|O_DIRECTORY` on every step. A substituted symlink fails with `ELOOP` instead of being followed. Removal and replacement use the same walk (`unlinkat`, `renameat`).
  - Chosen over `openat2` with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`: that needs kernel 5.6+ and either a new dependency or a hardcoded syscall number, while the walk needs only long-standing syscalls and gives the same per-component guarantee.
  - Applied to the canary deployment path (administrable), the quarantine vault (upload filename) and both append logs, which now pass `O_NOFOLLOW`.
  - **A real bug the correction exposed:** the quarantine vault wrote through the symlink-resolved root but cleaned up through the unresolved one, so a refused oversized upload could be deleted from a different directory than it was written to.
  - `atomicWriteFile` now states the exact scope of its guarantee in the code, including the part it does not cover and the primitive that does.
  - **The identifier boundary is now enforced:** `randomID` documents its 64-bit budget and forbids use as a capability; the transaction confirmation is documented as an intent guard rather than an authority check; and a route-table test requires every identifier-carrying route to be authenticated, with `GET /assets/{name}` pinned as the single allowlist-constrained exception.

- **Vendored SVG world map for the Kinetic live view (jsVectorMap 1.7.0, MIT)**:
  - jsVectorMap is vendored into `control/web/vendor/jsvectormap/` — 43 source files, the `world_merc` geometry, the upstream licence and the Sass sources. Nothing is fetched at runtime: no CDN, no tile server, no external origin. GeoIP/ASN resolution stays entirely local.
  - **Trusted Types are not weakened.** The library has exactly two `innerHTML` sites, both behind the `html = true` argument of its element factory, and the only caller is the zoom-button factory — which uses an element you supply instead of creating one when `zoomInButton`/`zoomOutButton` are given. Supplying both therefore selects the branch that never touches the sink, so `require-trusted-types-for 'script'` stays in force with no exception, and real zoom controls remain — as native `<button>` elements with keyboard support.
  - Live sources render as markers, the newest few pulse, countries are coloured by event rate with a ramp that keeps "no traffic" distinguishable from "a little traffic", and blocked sources are drawn from their own bucket in their own colour so they cannot be crowded out by ordinary tracked traffic.
  - Every layer is bounded before it reaches the DOM (96 tracked, 48 blocked, 24 pulsing, 192 countries) and the enforced bound is displayed, so the map never silently shows less than the feed reported.
  - Vendored code is unmodified except for three documented one-token deviations (the SCSS import, a global assignment, and the map data wrapper). Extensionless imports are resolved by a server-side shim over exactly three candidates, each checked against the exhaustive asset allowlist — so auditable third-party code stays byte-identical to upstream rather than being rewritten by hand.
  - The stylesheet is a mechanical compilation of the vendored SCSS; no declaration was added, removed or reordered.
  - New contract tests make the allowlist exhaustive in both directions, pin the Trusted Types conditions, reject traversal and unknown names at the resolver, and assert that no vendored file performs a network operation.

- **B24 validation pass — two gate failures found and one release blocker raised**:
  - **`govulncheck` reports 6 reachable standard-library vulnerabilities** in Go 1.26.4, fixed in 1.26.5/1.26.6. The reachable traces include the L7 ingress reverse proxy (`l7_edge.go` → `httputil.ReverseProxy`) and the threat-intelligence feed fetcher (`feeds.go` → `http.Client.Do`). There are no third-party dependencies, so this is purely a toolchain issue.
  - `go.mod` now declares `toolchain go1.26.6`, and `toolchain_security_test.go` refuses to pass a build on an older toolchain and fails if the declaration drifts below the floor. The comparison logic was executed natively (14/14 cases, including `go1.26.10 > go1.26.6` where a lexical compare fails).
  - **26 of 166 Go files were not gofmt-clean** — double blank lines, unaligned const blocks and unaligned struct literals introduced by scripted edits. All now conformant.
  - The 82 `_ = operation()` sites were audited individually rather than asserted safe: every dropped close error is on a failure path, and every success path checks its close before marking the handle closed.
  - **Release status: GOLD, blocked.** DIAMANT requires every applicable gate to have been executed and the artefact verified on the target platform; without a Linux runtime and a browser, three conditions fail and one gate carries an unremediated Critical finding.

## 4.1.0 — Kinetic Defense & Ingress Shield Architecture

> **Release state:** Source-level Release Candidate after the OpenAI B00-B14 recovery/rework. Production/kernel certification remains gated by `scripts/validate-kinetic-release-candidate.sh --target-host <interface>` and the target-host/soak requirements documented in `docs/kinetic/release-candidate-status.md`.

- **Kinetic Defense Ingress Sensor & Realtime Telemetry**:
  - Integrated high-speed eBPF/XDP ingress telemetry with bounded per-IP packet counters, TCP SYN detection, rate/velocity windows, and portscan tracking.
  - Subnet aggregation across IPv4 /24, IPv4 /16 campaign correlation, and IPv6 /64 subnets with dedicated Live Kinetic Defense Command Center view.
  - Automated containment pipeline with TTL profiles (15m, 1h, 6h, 24h, 7d), repeat-offender escalation, signed policy persistence, and atomic kernel rollback.
  - Uncompromised management allowlist precedence preventing self-lockout under all conditions.
- **Dedicated Threat Intelligence View & Strict Sync Semantics**:
  - Separated Threat Intelligence into a dedicated Command Center page with per-feed health cards, mode tracking, and generation metadata.
  - Corrected `lastSuccessfulSyncAt` semantics: partial or failed syncs no longer masquerade as full success; introduced `LastFullySuccessfulSyncAt` and explicit `PARTIAL` status.
- **XDR Behavior Profile & UI Consistency Fixes**:
  - Fixed XDR profile counter binding in `control/web/xdr.js` using `xdr.behavior.profiles` and `xdr.behavior.warm_profiles`.
  - Renamed `Aktive Regeln` to `Aktive CIDR-Sperren` and added separate counting for active detection rules.
  - Clarified `Adaptive Anomalien` and XDR analysis queue metrics (`queue_depth`, `queue_capacity`, `evaluation_drops`).
  - Decoupled SSE stream status from Control Plane availability, with graceful fallback polling and exponential backoff.
- **L7 Inspection Health & Traffic Coverage**:
  - Differentiated between L7 engine health and active inline inspection traffic, preventing false `HEALTHY` assumptions on unrouted setups.
  - Native Go TLS handshake decoder for JA3 signatures, SNI anomalies, host mismatch, and handshake flood detection.
- **Control Plane Asset Router Whitelist & Deterministic MIME Types**:
  - Registered `kinetic.js` and `threat-intel.js` in `control/server.go` allowed asset whitelist, resolving browser 404s that prevented ES module dashboard initialization.
  - Implemented deterministic MIME type resolution (`text/javascript; charset=utf-8`, `text/css; charset=utf-8`, `image/png`) preventing stripped OS environments from falling back to generic binary streams.
  - Added automated test suite `TestAllWebAssetsAreAllowlistedAndAccessible` ensuring all embedded Command Center assets are permanently covered.

## 4.0.1 — Chinese Localization, Dedicated XDR Kernel Recovery Tab & Startscreen Expansion

- **Simplified Chinese (`zh-CN` / `ZH`) Localization**:
  - Added complete Simplified Chinese translation catalog across all Command Center tabs, dialogs, operations, placeholders, and runtime toasts (743 keys, 100% parity across DE, EN, RU, and zh-CN).
  - Integrated Chinese (`ZH` / `zh-CN`) on the public Access Gateway Startscreen (`gateway/main.go`) with localized copy (`主权安全控制平面`, `操作员访问`, etc.) and cookie/query language switching.
  - Added automatic `Accept-Language` detection for `zh`, `zh-CN`, and `zh-Hans`.
- **Dedicated XDR Kernel Recovery Tab & Safe State Reset**:
  - Added a dedicated XDR Kernel Recovery interface tab and workflow (`#xdr` recovery view) allowing operators to inspect, recover, and re-initialize the kernel sensor stack directly from the UI if issues arise after installation.
  - Implemented authenticated `/api/v1/xdr/recovery` endpoint with strict `ARCHIVE_AND_REINITIALIZE_XDR` confirmation gating.
  - Byte-for-byte archiving of corrupted or degraded incident ledger chains into `/var/lib/vgt/gedefense/xdr-recovery/` with cryptographic SHA-256 manifests.
  - Crash-safe initialization of fresh incident chains while strictly preserving storage master keys, sensor IPC tokens, and operator credentials.
  - Re-initializes kernel eBPF sensors, BPF-LSM hooks, ring buffer attachments, and process monitors.
  - Requires disk verification and an immutable signed Evidence Ledger commit before transitioning out of sticky `DEGRADED` status.
- **Correlation & Ledger Hash Integrity**:
  - Separated attack-story Merkle evidence root (`evidence_root`) from incident ledger MAC chain hashes (`record_hash`), preventing valid correlated incidents from becoming unverifiable across reboots.
  - Hardened XDR status propagation to prevent routine telemetry polling from masking degraded kernel states.
- **Sovereign Threat Intelligence Subsystem (100% Opt-In, 12h Sync & Kernel-Speed Blocking)**:
  - **100% Sovereign Opt-In**: The threat intelligence subsystem is disabled by default (`FeedsEnabled = false`), ensuring zero external DNS or HTTP requests occur until explicitly enabled by an administrator in the settings.
  - **12-Hour Automatic Sync (`vis_threat_intel_cron_sync`)**: Synchronizes feeds every 12 hours (`12 * time.Hour`), guarded by an atomic transient lock with a 15-minute TTL (`vis_threat_intel_sync_lock`) to prevent race conditions and concurrent downloads between background cron and operator API triggers.
  - **9 Integrated Threat Intelligence Feeds with 3-Tier Action Semantics**:
    - `BLOCK` (Feodo Tracker C2, Spamhaus DROP IPv4 & IPv6): strictly these vectors enter kernel XDP / cgroup LPM tries and cause `DROP_THREAT_INTEL`.
    - `CORRELATE_ONLY` (CINS Army, blocklist.de, Emerging Threats, IPsum Level 1+, FireHOL Level 1): utilized for XDR incident scoring and process correlation with zero kernel drops.
    - `ANNOTATE_ONLY` (Tor Bulk Exit Nodes): strictly forensic flow and telemetry annotation without hostile scoring or packet drops.
  - **Mathematical Hardening against SQLi & Poisoning**: Enforces strict length boundaries (`3 <= len <= 49`), pre-parsing regex whitelisting (`^[0-9a-fA-F.:\/]+$`) eliminating injection characters (`'`, `"`, `;`, `--`, spaces, and control codes), allocation-free `netip` validation, and strict anti-poisoning exclusions for loopback, RFC 1918, multicast, link-local, cloud metadata IMDS (AWS, GCP, Azure, Alibaba, IPv6 IMDSv2), and default routes (`0.0.0.0/0`, `::/0`).
  - **Enforcement Invariants & Kernel Synchronization**:
    - *Last-Known-Good Generation*: failed, empty, truncated or malformed downloads never overwrite active generations.
    - *Management Allowlist Precedence*: allowlists take precedence during enforcement (evaluated first in Styx and eBPF LPM maps); whole threat CIDRs are never discarded at parse time.
    - *Additions-Before-Deletions & Rollback*: kernel diffs apply additions before deletions; addition errors trigger immediate rollback of added items and abort generation publication.
    - *Shared Monotonic Generation & Cryptographic Fingerprint*: kernel and userspace expose shared generation ID and canonical SHA-256 fingerprint.
    - *Live Sync Lock Ownership*: the 15-minute lock TTL is strictly crash recovery; active owners retain ownership indefinitely until synchronization concludes.
    - *Persisted Scheduling*: scheduling computes initial delays from persisted `/var/lib/vgt/gedefense/threat-intel-state.json`, preventing daemon restarts from postponing synchronization.
  - **Dual Inbound & Outbound Kernel-Speed Blocking**: Drops inbound malicious traffic at the NIC driver layer via XDP LPM Trie (`BLOCKLIST_V4` / `BLOCKLIST_V6`), drops outbound C2 connections in the kernel via `gedefense_egress` (`cgroup_skb(egress)`), and intercepts socket connections in user-space via the Styx Egress Engine (`DROP_THREAT_INTEL`). Uses zero-latency diff-sync to update eBPF maps atomically without packet drop spikes.
- **Version 4.0.1 Release Alignment**:
  - Updated all core binaries, access gateway, web UI assets, Rust workspace crates, packaging manifests, and integration contracts to version `4.0.1`.

## 4.0.0-beta.1 — Native L7 Application Security & Correlation Hardening

- Added complete Simplified Chinese (`zh-CN`) Command Center localization and browser-language detection for `zh-CN`/`zh-Hans`, while preserving German, English and Russian.
- Audited all Command Center tabs, dialogs, operations, placeholders and runtime toasts for translation coverage; moved remaining user-facing hardcoded strings behind the shared i18n catalog and added catalog/placeholder parity validation.
- Corrected the operator-key privacy text to match implementation: the key remains in volatile tab memory and is discarded on reload; it is not persisted in browser storage.
- Added a native, standard-library-only L7 application-security plane with bounded HTTP normalization, deterministic candidate extraction and fail-closed resource budgets.
- Added optional Unix-socket inline enforcement with static local upstreams only; no scripting runtime, plugin engine, dynamic upstream resolution or new third-party dependency is required.
- Added request detection for SQL injection, XSS, command injection, path traversal/file inclusion, SSTI, XXE, unsafe deserialization/JNDI patterns, scanner probes, protocol ambiguity, SSRF and upload abuse.
- Added bounded gzip/deflate inspection, encoded-input canonicalization and evasive IPv4/URL representation handling without changing forwarded request bytes.
- Added response leak inspection that preserves the exact response wire body while emitting bounded, hashed evidence only.
- Connected L7 findings to XDR attack-story correlation while keeping web-only evidence alert-only for destructive host-response scoring.
- Added shared global admission, candidate, memory, parser and cardinality budgets across inspection and inline paths.
- Hardened local trust boundaries with pre-provisioned runtime directories, restrictive Unix-socket DAC, Linux peer credentials, forwarding-header reconstruction and removal of authentication secrets from inspection state.
- Added route/host canonicalization for policy and rate decisions while retaining original request paths for forensic evidence.
- Extended release gates with L7 unit, race, fuzz, static-security, packaging and dependency invariants.
- Added an explicit fail-closed XDR incident-ledger recovery workflow: corrupt chains are archived byte-for-byte with SHA-256 manifests, source stability is rechecked before replacement, authentication/storage keys are preserved, a fresh empty chain is created crash-safely, and XDR leaves `DEGRADED` only after disk verification plus mandatory Evidence Ledger commits.
- Hardened XDR status propagation so routine sensor refreshes cannot accidentally erase a sticky degraded state; only an explicit verified recovery path may clear it.
- Fixed a semantic hash-domain collision in XDR incidents: attack-story Merkle evidence now uses the dedicated `evidence_root` field while `record_hash` is reserved exclusively for the authenticated incident-ledger chain. Pre-populated caller hashes are explicitly cleared before ledger MAC calculation, preventing otherwise valid correlated incidents from becoming unverifiable on restart.

## 3.0.0-beta.1 — Beta v3 Universal Linux & AstraeaOS Deep Integration (VGT Doktrin DIAMANT)

- Integrated TRINITY XDR 2.0 Directed Acyclic Graph (DAG) for causal attack stories with Merkle-root cryptographic proof chaining.
- Integrated Reversible Response Engine with semantic TTL presets (300s, 900s, 3600s), 4x repeat offender escalation, and automatic background rollback.
- Integrated Nemesis & Ghost Trap Linux Deception Grid with canary file placement, path jailing, and zero-false-positive process freeze.
- Added Dynamic Capability Detection (Dual-Mode) for transparent runtime detection of AstraeaOS native enclaves vs. generic Linux distributions.

## 3.0.0-beta.1 — Beta v3 universal Linux integration

- Promoted portable AstraeaOS readiness, desktop and privilege-boundary
  contracts into the generic Linux release payload.
- Added APT, DNF/YUM, pacman and Zypper installer coverage.
- Added a local SPKI-pinned Chromium application profile without changing the
  global trust store.
- Preserved AstraeaOS-only SDDM, ArchISO and Gaia Cells behavior as conditional
  adapters instead of imposing those assumptions on other distributions.
- Added mandatory Go race/fuzz/security, pinned Rust/eBPF release-build and
  cryptographic artifact gates to the Beta v3 CI.
- Added containerized Ubuntu, Fedora, Arch and openSUSE integration contracts.
- Added a privileged installed-host gate for systemd, authenticated readiness,
  bpffs, verifier-visible eBPF programs, concrete NIC XDP attachment, polkit and
  desktop metadata.
- Added loopback and localhost SAN identities to generated gateway certificates
  so the local pinned desktop application and the configured remote identity
  share one explicitly scoped leaf certificate.

## 1.0.0-beta.5 Complete Beta

- Added root-cgroup IPv4/IPv6 egress enforcement and bounded, authenticated
  XDR drop telemetry for signed CIDR policy targets.
- Added a real `sched_process_exec` eBPF sensor, bounded Ring Buffer,
  authenticated event retrieval and procfs identity enrichment/fallback.
- Added bounded local Pacman `.MTREE` SHA-256 package integrity scanning with
  asynchronous API, hardening-posture integration and dedicated UI findings.
- Installer 3.5.1 korrigiert die DAC-Kette des verschlüsselten
  Quarantäne-Vaults bei Upgrades: `/var/lib/vgt/gedefense` ist nun `0710`
  (`gedefense:gedefense`). Der privilegierte Core kann dadurch mit seiner
  expliziten `gedefense`-Gruppe zum root-eigenen `0700`-Vault traversieren,
  ohne `CAP_DAC_OVERRIDE` oder Verzeichnis-Listing zu erhalten.
- Installer und Security-Audit prüfen die Vault-Eigentümer und Modi vor der
  Service-Aktivierung fail-closed.

- Added chunked AES-256-GCM quarantine with atomic capture, verification and
  restore through the typed Rust broker.
- Added encrypted durable cases with deterministic recurrence correlation and
  Evidence Ledger-gated status transitions.
- Added authenticated Gaia Cells v1 discovery and reversible isolation
  transactions bound to UUID, generation and kernel cgroup ID.
- Added atomically persisted server/AstraeaOS hardening profiles with runtime and
  boot-state rollback.
- Replaced the AstraeaOS Sentinel runtime package path with native GeDefense
  packages, provisioning, systemd activation and a pinned local TLS launcher.
- Added privacy-safe installer prompts and actionable activation diagnostics.

## 1.0.0-beta.5 hardening continuation

- added the encrypted durable Transaction Engine with exact preview binding, confirmation-gated apply/reverse, crash recovery, reboot reconciliation and runtime-drift quarantine;
- added typed Rust broker commands for allowlisted sysctl reads and compare-and-set writes with post-state verification;
- added reversible generic Linux server and AstraeaOS workstation hardening profiles without a shell or generic privileged file-write primitive;
- added the hardened Prometheus FIM successor with bounded traversal, race-aware regular-file hashing, SHA-256 content and mode verification, encrypted authenticated baselines and tamper quarantine;
- added authenticated FIM status, scan and baseline APIs whose operator mutations pass through the mandatory Evidence Ledger gate;
- added a complete manifest-verified GeDefense source mirror under `AstraeaOS/gedefense` plus local Arch package builds without developer-path dependencies;
- added Evidence Ledger v2 with per-record Ed25519 signatures, AES-256-GCM record encryption, sequence-bound AAD, durable head checkpoints, truncation detection, bounded replay and fail-closed mutation gates;
- added mandatory pre-action evidence intents for authenticated operator mutations and automated XDR response;
- added a versioned AstraeaOS integration contract, strict AstraeaOS runtime profile and byte-level cross-repository synchronization verifier;
- established the AstraeaOS/Sentinel fusion architecture with GeDefense as the single security authority for generic Linux and AstraeaOS;
- added an authenticated evidence-only Boot Trust API covering AstraeaOS identity, Secure Boot state, kernel lockdown, redacted boot-parameter evidence, TPM presence, cgroup v2, Gaia Cells runtime presence and bounded kernel-image hashing;
- added strict bounds, non-symlink evidence reads, kernel command-line secret redaction, cache isolation and Linux regression tests for host-trust collection;
- fixed authenticated runtime-settings upgrades by omitting absent post-upgrade rule fields from the legacy MAC input;
- removed public-host and management-CIDR values from installer prompts and the final console summary;
- added automatic `systemctl` and `journalctl` capture before activation rollback;
- made Emergency Stop a verified fail-safe transaction with authenticated empty-kernel confirmation, signed Observe persistence and automatic recovery reconciliation;
- added configurable XDR signal modules and bounded dashboard-managed RE2 rules with strict separation between alert score and active-response score;
- added native Go fuzz targets plus a shared Rust eBPF packet-prefix parser and host-side fuzz harness;
- committed the Rust dependency lockfile and enforced locked builds across CI, Makefile, installer and source packaging;
- split settings handlers, TLS file operations and privileged process control into isolated modules;
- bounded privileged-core IPC responses and removed ignored rollback errors.

## 1.0.0-beta.5

### Product and interface

- unified the public login and embedded Command Center under the product identity **GeDefense powered by VisionGaiaTechnology**;
- added consistent version labels to login, navigation, hero, footer and operational dialogs;
- added complete browser-language switching for German, English and Russian, including dynamic status text, forms, dialogs, tables, notifications, dates and number formatting;
- added an optional VGT support panel for PayPal, Bitcoin, ETH and USDT (ERC-20), without external scripts, trackers or payment SDKs;
- retained the existing dashboard visual system while making branding, navigation and responsive layouts deterministic across login and authenticated views.

### Data-at-rest protection

- added a 32-byte installation-specific storage master key under `/etc/vgt/gedefense/secrets/storage-master.key`;
- added AES-256-GCM envelopes with random nonces, per-purpose HMAC-SHA-256 subkeys and AAD binding to schema, node identity, storage purpose, canonical path and record sequence;
- encrypted runtime settings, policy snapshots, the local Ed25519 policy private key, behavior profiles, incident records and incident-chain checkpoints;
- added authenticated migration from supported legacy plaintext records to encrypted storage;
- retained policy signatures and incident MAC chains inside the encrypted envelopes for defense in depth.

### Authentication

- new password records use Argon2id with 64 MiB memory, three iterations, one lane, a random 128-bit salt and a 256-bit output;
- existing PBKDF2-HMAC-SHA-256 password records remain accepted and migrate to Argon2id after successful authentication;
- added strict private-file validation for password records and runtime verification of `libargon2.so.1`.

### Security hardening

- added fail-closed same-origin enforcement for authenticated mutating requests and logout;
- retained synchronizer-token login CSRF protection and explicit cross-site request rejection;
- hardened Host validation, session validation, security headers and reverse-proxy trust-boundary resets;
- removed browser forwarding identity from internal backend requests, including explicit suppression of automatic `X-Forwarded-For` injection;
- added HTTPS-only threat-feed validation and dial-time SSRF protection against loopback, private, link-local, multicast and unspecified networks;
- added a static security regression audit that rejects unsafe DOM HTML sinks, inline handlers, runtime command execution primitives and missing cryptographic/security anchors;
- added security tests for CSRF failure, origin mismatch, auth/session forgery, Host bypass, backend bearer protection, asset traversal and strict header presence.

### Full-stack base retained from Beta 4

- Rust response core, authenticated VGT3 IPC and Rust `no_std` eBPF/XDP data plane;
- target-kernel compilation and verifier-gated activation;
- fixed-header IPv4/IPv6 parser accepted for source-CIDR filtering without attacker-controlled pointer arithmetic;
- Observe → Canary → Enforce safety gates, management allowlist, Emergency Stop, automatic degradation, XDR and signed policy generations;
- Swarm/Mesh remains deliberately deferred.
