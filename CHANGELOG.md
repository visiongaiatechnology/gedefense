# Changelog

## 4.2.2 - Fail-Closed Enforcement, Ledger Rotation and an Honest Panel

A hardening release. It removes the paths on which the platform could lose its own
protection, and it makes every surface state what the kernel is actually doing.

### Fail-closed enforcement

A production host ran unprotected for twenty hours after a single kernel sample it could not
interpret. The sample was not hostile: the ingress producer keeps one counter set per source and
labels the aggregate with the protocol of the packet that flushed it, so a source that sent UDP
and TCP inside the same window produced a TCP record whose attempt counter exceeded its SYN
counter. The decoder treated that as impossible, the drain aborted the whole batch instead of
skipping the record, the control plane read the failed drain as a lost kernel hook and declared
the mandatory ingress sensor degraded - and the release gate answered an unavailable sensor by
reconciling the kernel policy to `observe`, which removed every block from the kernel. Nothing
brought it back: the platform had no path from a degraded phase to an armed one, so only the next
deployment cleared the state.

The response to a loss of confidence is now a loss of authority, not a loss of protection:

- **An automatic degradation never releases the verified kernel policy.** The gate confirms and
  retains the enforcement it verified instead of reconciling to `observe`. Confirmation means
  every block is re-applied, because the core's insert is idempotent and it offers no read-back;
  the resulting state is reported as `verified-enforce` and an unconfirmed one as
  `verified-empty`, and the two are never conflated.
- **A restart keeps the enforcement the signed policy carries.** The startup path no longer
  initialises to `observe`; it retains the verified enforcement recorded in the policy it just
  authenticated.
- **A promotion never lowers verified enforcement.** Only an explicit operator action
  (`RETURN:OBSERVE`, emergency stop) reduces it, and a retention is reported as its own action
  (`automatic_response_paused`) rather than as an enforcement change.
- **A drain or parser failure is separated from the loss of enforcement capability.** Health
  probes govern the sensor verdict and name "the enforcement path is unavailable"; drain failures
  degrade only the observation and name themselves. A sensor that cannot deliver samples is not a
  kernel that cannot block.
- **The platform re-arms itself.** Once the gates pass and the calm holds for the soak, the phase
  returns to `enforce` on its own, and the transition is logged together with the cause that had
  held it.
- **A verification that succeeds clears the cause it replaced.** Causes were one-way: a failure
  recorded one and only a rotation or an operator recovery removed it, so a transient fault kept
  XDR degraded - and the automatic response paused - until somebody restarted the control plane.
- **A deployment by the operator is not an intrusion.** Replacing one of GeDefense's own
  components was reported as self-tampering, degraded XDR and paused the automatic response, so
  shipping a fix quietly switched part of the protection off. It is now a high-severity record
  with no response attached; third-party objects keep the full reaction.
- **Recovering the incident ledger no longer requires giving up the protection.** The recovery
  demanded `observe` enforcement, which under retention is unreachable - the ledger could only be
  repaired by first disarming the host whose protection it exists to preserve.
- **The Rust decoder and drain tolerate an inconsistent aggregate.** A record whose TCP label
  contradicts its counters is kept with a neutralised protocol and its counters untouched; a
  record that still cannot be decoded is skipped and named instead of aborting the drain; only a
  batch in which many samples are undecodable - the signature of a wrong wire format - is
  reported as a fault.

### Ledger retention

- **Both forensic ledgers rotate instead of filling up.** Reaching the budget stopped the
  recording, degraded XDR and paused the automatic response until an operator archived the
  segment by hand, which happened twice on the production host in one day. At ninety percent the
  sealed chain is archived with a manifest carrying sizes, digests, sequence, head hash and
  scope, and a fresh chain continues. The rotation copies before it replaces: a crash before the
  swap leaves a working ledger, a crash during it is completed at the next start from a rotation
  marker, and a marker whose manifest does not match is refused rather than trusted. The archive
  directory must belong to the service and be `0700`; a directory that is group- or
  world-accessible is refused instead of written to.
- **The evidence ledger verifies itself within bounds.** Startup verified the entire ledger -
  around 260 MB at roughly 6.7 seconds per megabyte - and exceeded the unit's start timeout, so
  the platform could not come up and neither could the gateway. Startup now checks the
  authenticated checkpoint and a bounded tail; the history is covered incrementally in the
  background against an authenticated watermark; the complete verification stays available to the
  operator. An unauthenticated watermark is refused, because accepting one let a forged file skip
  the entire history.
- **An interrupted append is recovered.** A process killed mid-write left one record ahead of its
  checkpoint and the service refused to start. The unsealed tail is now verified and sealed, or
  dropped when it is a partial write; several records behind the checkpoint are still refused.

Verification for this change set: `gofmt`, `go vet` and the full `go test ./...` suite green
(99 s), six mutation proofs - releasing the retention to `observe`, degrading the sensor on a
single drain failure, letting a promotion lower verified enforcement, trusting an unauthenticated
watermark, removing the cause-clearing, treating a product artifact as an intrusion - each of
which fails the corresponding contract test when reverted. Live verification on the production
host: measured startup of 2-7 s, a rotation of the evidence ledger at 266.7 MB while the
enforcement stayed armed, the disarmament path refusing to release the policy, and the automatic
re-arm after the soak.

### Interface truthfulness

A fail-safe has two meanings since the change above - the kernel kept the enforcement it verified,
or it did not - and the interface only knew one of them. An operator looking at a host that was
still blocking read, on a single screen, `DEGRADED` in the header, `SYSTEM NORMAL` in the sidebar,
"all current release gates are satisfied" in the preflight, `Observe` as the reached step and
`Enforce` as **locked**.

- **The sidebar reads the release phase.** It knew the XDR state, the policy and the sensor
  coverage, but not the phase, so a platform with its automatic response paused announced SYSTEM
  NOMINAL in green. A fail-safe with a retained enforcement now reports itself as restricted, and
  the two modes are labelled with what they are.
- **The backend's detail sentence follows the phase, not the reason.** It was keyed on the stored
  fail-safe reason, and a transient cause that a later verification cleared left that field empty -
  so exactly the state in question reported "release gates satisfied" beneath its own DEGRADED
  badge. The sentence now names what the kernel is doing.
- **A degraded platform no longer says that every gate is satisfied.** The preflight list and the
  release blocker list only collected the promotion blockers of the current phase; the degraded
  phase has none of its own, so an empty list was rendered as "all gates satisfied" in two places.
  Both now state the fail-safe, its cause and whether the enforcement is retained.
- **The ladder shows what is enforcing, not only what may start.** `Enforce` read LOCKED while the
  kernel was enforcing it and `Observe` read as a passed milestone while the platform was above it
  with the response paused. The retained step is now marked as retained, the paused step as paused,
  and the promotion button says what it actually changes - with a retained enforcement, only the
  XDR response moves, never the kernel policy.
- **The version the interface claims is the version that runs.** The hero line and the footer said
  4.1, the document title 4.2, and only the version readout came from the API; all four language
  catalogues now name 4.2.1, and the values that belong to one source are on their way there.

### Interface verification

The state corrections above were themselves checked by rendering the dashboard headlessly and
comparing every state-bearing sentence against the payload it came from: eleven payload/view
combinations, eighty rules, plus a self-test proving the checker can fail. Three statements were
still wrong, all of them introduced by the corrections:

- **The release readiness field repeated "release gates satisfied" while the phase was degraded.**
  It mapped that backend sentence to a catalogue key without consulting the phase, so a host still
  reporting the old sentence - an older backend, or a rollout in progress - showed it beneath an
  EINGESCHRÄNKT badge, directly beside the gate list that explained the retained enforcement. The
  phase now decides, not the string.
- **The fail-safe line claimed a retained enforcement during a healthy enforce phase.** It keyed
  on the kernel state alone, and `verified-enforce` is also the normal state of a platform that is
  enforcing as intended, so `fail_safe_verified` was never consulted. Only a fail-safe can report
  a retention.
- **The Enforce step read BEREIT during an active emergency stop**, because that branch did not
  consult the emergency flag the same function already honoured for the button beside it.

The check also exposed a vocabulary defect: the panel said "pausiert" in the release card and
"ausgesetzt" in the preflight for the same condition. One state, one word.

Verification: eleven fixtures, eighty rules, zero failures, and a regression mode that removes the
guards again - eighteen of the eighty rules then go red, including SYSTEM NOMINAL in the badge and
the "all gates satisfied" sentence. The tooling stays out of the repository: its fixtures carry
real operational data (management allowlist, observed source addresses, process command lines).

## 4.2.1 - Stability, Evidence and Interface Fixes

A fix release. It carries no new subsystem; it makes the ones already present tell the
truth about themselves and stay out of the operator's way.

### Evidence ledger

- **Capacity is no longer treated as corruption.** Reaching the retention budget set the
  ledger's integrity error, which quarantined it permanently and reported XDR as degraded
  with "mandatory evidence ledger unavailable". A full ledger is not a damaged one.
- **One budget, read the same way from every side.** `Append` consulted the administrable
  policy, `Verify` consulted the constructor value, and `NewEvidenceLedger` verified
  against the constructor value before the policy was known. An operator who raised the
  budget, let the ledger grow and restarted the service had it rejected at boot as
  "exceeds its size budget" - a service that would not start, locked out by the very
  setting it had been told to raise. Construction is now permissive, runtime strict.
- **The condition names itself.** "retention budget reached" and "integrity unavailable"
  are separate messages with separate remedies, and the dashboard states which one applies
  with the figures and the route to the fix.
- **The budget the operator raises is the budget the ledger enforces.** `main.go` constructed
  the ledger with the administrable budget it had read, and the constructor seeded its policy
  with the compiled-in default of 64 MiB - which the append path prefers. An operator who
  raised the budget to 256 MiB was therefore ignored at every start: the ledger stopped at
  64 MiB, and once the file reached it every append failed while the status still reported the
  ledger healthy. The platform silently stopped recording evidence and said nothing beyond a
  single line in the service log. The two budgets now start out equal, floored by the same
  rule construction already used to decide whether an existing ledger is acceptable, and a
  budget lowered afterwards still takes effect.

### Release gate

- **A fail-safe keeps its reason.** The cause was overwritten on the next refresh by the
  live blocker list, and once the blockers cleared it read "release gates satisfied" while
  the platform was still sitting in Observe. The cause and the moment it was observed are
  now preserved and shown.
- **A fail-safe is forensic evidence.** It is the most consequential thing the platform
  does on its own and it left no incident behind: the Forensics view counted zero after a
  fall-back because only the XDR process pipeline ever created one.

### L7 Application Defense

- **A passing self-test clears a stale degradation.** The inline health flag is inferred
  from events and never re-derived, so one transient error reported a working path as
  degraded indefinitely - while the self-test proved the opposite on the same screen. The
  verdict is now recorded and accepted as the stronger evidence, bounded to fifteen
  minutes so a stale pass cannot mask a path that has since broken.
- **The generated nginx configuration could never be applied.** It emitted a server block
  with `listen ... ssl` and a comment where the certificate directives belong, which nginx
  rejects outright - and it named a host that already had a server block, creating a
  conflicting server name. It is now two insertable pieces, validated against the real
  nginx parser in the test suite.
- **The enforcement path is reported.** `INGRESS_HEALTH` carries which hook the kernel
  attached - native XDP, generic XDP or TC ingress - and the dashboard shows it. All three
  previously read as "verified kernel ingress producer", though they perform very
  differently under load.
- **The operator can see whether HTTP traffic exists while L7 is not in its path.**
  Web-surface discovery reports whether a web server runs on this host and on which ports.
  It is read-only, bounded, and never presented as protection, because detection is not
  protection.
- **Guided web-server integration generates configuration text and nothing else.** It never
  writes to a web server's configuration, never reloads a service and never claims that a
  generated snippet is in effect: the operator applies it, and the self-test then observes
  whether it worked. Every interpolated value is validated against a closed grammar before
  it reaches the template, because the output is a configuration file for a privileged
  daemon and a socket path containing a newline could otherwise append arbitrary
  directives to a server block.
- **Inspected requests are both counters, not one of them.** The panel displayed the request
  counter alone, so a host whose inline listener had inspected 174 requests reported
  "0 geprüfte Requests" directly beneath its own "TRAFFIC ACTIVE" badge - the panel
  contradicting itself, and hiding the evidence that the coverage verdict was right. The
  figure is now the sum the verdict itself is computed from.
- **A degraded inline listener says what it reported.** "Inline L7 listener is degraded" is a
  verdict, not an explanation. The service also records the error it saw, that text lives only
  for the lifetime of the process, and the transition is not logged - so an operator who went
  looking after the fact found a degradation, no cause and no trace. The sentence now carries
  the report when there is one and remains the verdict alone when there is not. No verdict and
  no gate is affected by the addition.

### Kinetic Defense

- **Enforcement and effect are visible.** A panel states the hook in use, the kernel
  channel's health and what the engine detected and did. In Observe mode it says so:
  a column of zeros means the response stage was never entered, not that nothing was seen.
- **The overview carries the numbers**, grouped by the question each answers.
- **The coverage summary explains the sensor it names.** The sentence beneath it was bound to
  one sensor name, so a summary reading "Mandatory sensors degraded: l7_application" was
  explained by the healthy ingress producer's sentence - a degraded headline over a positive
  explanation, on a page that contradicted the Application Defense page in the same session
  while both read the same snapshot. The reason now belongs to the sensor that made the
  platform non-nominal, using the server's precedence (offline and disabled outrank degraded),
  and the fallback is a translated key instead of a German literal.
- **The summary is deterministic.** It states that it determines the status deterministically,
  but it joined the sensor names in map iteration order, so the same state produced a
  differently ordered sentence on every refresh.
- **The page that shows the verdict derives it, instead of serving a stored copy.** The
  Kinetic page reads `/api/v1/kinetic/live`, and that endpoint answered from the stored
  telemetry while `/api/v1/status` re-derived the coverage from the published fields. The L7
  verdict is a function of fields that two components write, so the stored copy recorded
  whichever of them wrote last: one process answered "All mandatory sensors operational" on
  one endpoint and "Mandatory sensors degraded: l7_application" on the other, in the same
  second, and the operator saw the second one. The derivation now lives in one place and both
  endpoints take it from there.

### Hardening

- **A tamper finding on GeDefense's own components no longer arms the response.** A digest
  mismatch on one of the product's own binaries cannot be told apart from an approved
  update, and the response engine contained on it: over a hundred recorded incidents show
  the product freezing its own access gateway. That is a denial of service any attacker can
  trigger by touching a single file, and it costs the operator the console that would have
  explained it. The finding survives at full severity - same rule, same score, same
  category - and only the response is withheld. Third-party binaries keep their full
  response, and the product's own components are recognised through one shared root that
  follows `VGT_RELEASE_ROOT`.
- **The controls work.** Every switch was disabled when its control was already PROTECTED,
  which made ten switches inert on a hardened host for no security reason - the preflight
  verifies a selection, it does not apply one. They now use the switch primitive the rest
  of the product uses.
- **The posture cannot overstate itself.** A host where two of twenty-two controls were
  readable and both passed scored 100 and reported HARDENED. The level is now capped when
  the evidence cannot support it, and the coverage is stated beside the score.
- **A protected object is reported as the object, once, when it changes.** The protected set
  reaches the same release binary through `/current/bin/...` and `/releases/<version>/bin/...`,
  so replacing it once produced two critical incidents; and because the announcement went
  through the time-based anomaly dedupe, an unremediated change was announced again every
  dedupe interval - five minutes by default - until the service restarted. One fact buried the
  ledger it was recorded in. The announcement is now keyed by the resolved object and its
  observed state: one change is one incident, a further modification is still a new one, and
  the degraded reason names every object that changed rather than only the last one checked.
- **The integrity panel names the subsystem that is actually degraded.** It showed the
  incident ledger's reason code, and the literal `INTEGRITY_FAILURE` when the ledger had none
  because it was healthy, while XDR was in fact degraded by an object that no longer matched
  its baseline. The operator was sent to examine a ledger with nothing wrong with it. The
  report's own reason is what is shown unless the ledger is the unhealthy part.

### Threat Intelligence

- **FireHOL Level 1 is enforced, not correlated.** The compiled-in default was corrected
  in 4.2.0, but a default only reaches a fresh installation. A schema migration raises the
  stored value on existing nodes, matched by feed ID, never lowered - and recorded, because
  an operator's setting is being changed on their behalf.

### Control plane lifecycle

- **An internal restart**, reachable from the interface, for the RESTART-class values that
  were persisted but never activated. It refuses when no supervisor would bring the process
  back, because exiting there would stop the product and leave it stopped.

### Interface

- **The gateway login page was recomposed.** It carried a marketing headline, a decorative
  grid, a glow, three architecture cards and a five-item technology claim, none of which
  answers a question an operator has at a trust boundary. The facts this host can attest
  before any credential exists are now the composition, and the product mark is embedded
  rather than drawn in CSS.
- **The sign-in form no longer invalidates itself.** Every request for the login page minted
  a fresh CSRF token and overwrote the cookie, so the cookie was a single shared slot rather
  than a property of the form on screen. The page carries its own language links, browsers
  prefetch and prerender them, and that second request was enough to leave the visible form
  holding a token the cookie no longer matched. Submitting it was refused as stale, and
  reloading re-armed the same race - which is why an operator who did nothing wrong could
  not sign in however often they reloaded. A second tab, a back/forward restore and a
  third-party `<img>` pointing at the endpoint did the same. The token a browser is given is
  now reused until it expires. The protection is unchanged: 24 random bytes bound to an
  HttpOnly, Secure, SameSite=Strict, host-only cookie that no other site can read or set.
- **An expired sign-in form no longer ends in a dead end.** The login CSRF cookie lived for
  ten minutes, which is shorter than the time an operator may reasonably take between opening
  the page and submitting it. Past that point the gateway answered with a bare
  `403 request rejected`: it named neither the cause nor a way out. The rejection itself is
  unchanged - without a matching token nothing is authenticated and no password is read - but
  a stale form is now returned to a fresh one carrying a message that says so, in all four
  languages, and the lifetime is an hour. The gateway log now records the rejection with its
  reason, the fingerprint of the token it expected and of the one it received, and which
  cookies arrived, so the next report of this kind is diagnosed from evidence rather than
  from a guess.
- **The refusal reason is shown once.** It travelled in the query string, which made it a
  property of the address instead of the event: reloading, or returning to the page from
  history, repeated "this sign-in page had expired" over a form that was freshly issued and
  valid, and the only way to silence it was to edit the URL by hand. It now rides a one-shot
  cookie that the page consumes.
- **The dashboard authentication surface** states what the host attests, and verifies a key
  against the control plane before claiming a session was authorised.
- **Protection Center**: the headline repeated the status pill verbatim, a button promised
  navigation and did nothing, and a permanently solid-red emergency stop sat beside the
  primary action.
- **Navigation icons** were one dollar sign and a duplicated shield; every entry is now
  distinct and names its destination.

### Translations

- **58 keys existed only in German.** Every language variant had been written into the
  German catalogue, so operators reading English, Russian or Chinese saw raw key
  identifiers across the enforcement panel, the evidence notice and the restart surface.
- The contract test that should have caught it counted occurrences across the file rather
  than per catalogue, so a key written four times into one catalogue passed. Coverage is
  now a per-catalogue property, and `t()` call sites are checked as well as document
  attributes.

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
