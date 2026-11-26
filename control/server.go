// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed web
var webAssets embed.FS

type APIServer struct {
	cfg        Config
	state      *State
	core       *CoreClient
	feeds      *FeedManager
	policy     *PolicyStore
	xdr        *XDREngine
	release    *ReleaseController
	settings   *SettingsStore
	tokenStamp atomic.Int64
	tokenLive  atomic.Pointer[string]
	token      string
	// tokenMu serializes the first, certified token-file read and every rotation check,
	// so a rotation that happens before the first authenticated request is effective
	// instead of being cached away (F-21 / CHAIN-014).
	tokenMu     sync.Mutex
	http        *http.Server
	feedSyncing atomic.Bool
	limiter     *RateLimiter
	// Pre-auth, authenticated and health budgets are distinct (F-08 / CHAIN-006).
	preAuthLimiter *RateLimiter
	healthLimiter  *RateLimiter
	limiterOnce    sync.Once
	replay         *ReplayGuard
	// denialSeen bounds authentication-denial evidence writes (F-19).
	denialMu   sync.Mutex
	denialSeen map[string]time.Time
	// undoEntries carries the short-lived, server-side undo for protection-removing
	// block/allowlist deletions (F-22).
	undoMu           sync.Mutex
	undoEntries      map[string]undoEntry
	sseClients       atomic.Int32
	bootTrust        *BootTrustCollector
	hardening        *HardeningCollector
	packages         *PackageIntegrityScanner
	kinetic          *KineticEngine
	kineticResponse  *KineticResponseEngine
	kineticRules     *KineticRuleRegistry
	kineticRuntimeMu sync.Mutex
	kineticCancel    context.CancelFunc
	// kineticContextSeen bounds the M5.2 XDR correlation of applied kinetic
	// blocks (one incident/story per rule+target per window). It is independent of
	// the XDR dedupe settings, so a zero-value runtime settings document cannot
	// turn the correlation into an incident flood.
	kineticContextMu   sync.Mutex
	kineticContextSeen map[string]time.Time
	geo                *GeoResolver
	l7                 *L7Engine
	// restartHook is invoked immediately before an internal restart exits the process.
	// It exists so a test can observe the restart without ending the test process.
	restartHook func()
	// The socket topology and the administrable path live on the service, not on the
	// engine, so the self-test and the integration generator need the service. Without
	// it both endpoints would have to reconstruct configuration they do not own.
	l7Service *L7Service
	cms       *CMSEngine
	fim       *FIMEngine
	// kernelExposure is the shared kernel-advisory measurement (see kernel_advisories.go). It is
	// optional: a server built without it simply has no advisory surface, which is what the unit
	// tests that construct a bare server expect.
	kernelExposure *kernelExposureCache
	// mitigationGuard owns the automatic entry-point mitigation and its probation watch. Optional for
	// the same reason as the exposure cache.
	mitigationGuard *MitigationGuard
	// cellGuard owns the automatic Gaia Cell isolation. Optional for the same reason.
	cellGuard *CellGuard
	// lockdown is the Emergency Lockdown engine (POINT 5 / P5-T3). Optional: a
	// server built without it reports an honest unavailable status instead of a
	// fake idle lockdown.
	lockdown *LockdownEngine
	// lockdownLimiter is the dedicated 1/min budget of the emergency trigger. It is
	// separate from the global budget so the most destructive endpoint cannot be
	// reached by exhausting the general operator budget.
	lockdownLimiter *RateLimiter
	// witness is the Out-of-Band Witness engine (POINT 4 / P4-T2). Optional: a
	// server built without it reports an honest disabled/unwired status instead
	// of creating checkpoints it cannot send.
	witness *WitnessEngine
	// witnessLimiter is the dedicated push budget. A checkpoint push leaves the
	// host, so one operator click is fine but a loop of them is not.
	witnessLimiter *RateLimiter
	// V6.3.0 AP-9 (R6): management-API role enforcement and the bounded guards
	// behind it. They are created lazily so a server built as a struct literal
	// (several tests and tooling do) keeps working unchanged.
	rbacOnce           sync.Once
	rbacMu             sync.Mutex
	rbacReported       map[string]time.Time
	tokenAuthLockout   *attemptLockout
	stepUpAuthLockout  *attemptLockout
	directStepUpNonces *nonceReplayCache
	gatewayClaimNonces *nonceReplayCache
	// rbacNow is the injectable clock of the role subsystem; production uses
	// time.Now, whose readings carry the monotonic clock.
	rbacNow func() time.Time
	// Rate limits for the destructive entry-point and isolation actions: one operator click is fine,
	// a loop of them is not. Confirmation phrases prove intent, the budget proves restraint.
	mitigationLimiter *RateLimiter
	confineLimiter    *RateLimiter
	// v61 bundles the GeDefense 6.1.0 module engines (web posture, worker guard,
	// TLS sensor, LPE guard). Optional: a server built without it reports an honest
	// unavailable runtime for every 6.1.0 module instead of a fake idle one.
	v61 *V61Engines

	packageMu     sync.Mutex
	packageCancel context.CancelFunc

	trustMu     sync.Mutex
	trustCancel context.CancelFunc
	driftCancel context.CancelFunc
	caseCancel  context.CancelFunc
	imports     *importPreviewStore

	hardeningMu     sync.Mutex
	hardeningCancel context.CancelFunc
	// hardeningMemo suppresses repeated posture events for a domain that keeps
	// reporting the same state, so the event stream stays readable.
	hardeningMemo  map[string]string
	hardeningLevel string
}

func NewAPIServer(cfg Config, state *State, core *CoreClient, feeds *FeedManager, policy *PolicyStore, xdr *XDREngine, release *ReleaseController, settings *SettingsStore, token string) *APIServer {
	s := &APIServer{
		cfg: cfg, state: state, core: core, feeds: feeds, policy: policy, xdr: xdr, release: release, settings: settings, token: token,
		limiter: NewRateLimiter(cfg.Dashboard.RateLimitPerMinute, cfg.Dashboard.RateLimitBurst), replay: NewReplayGuard(10 * time.Minute),
		bootTrust: NewBootTrustCollector(5 * time.Minute),
		hardening: NewHardeningCollector(),
		packages:  NewPackageIntegrityScanner(),
	}
	// The persisted Integrity/FIM policy is the authority for the hot budgets (and
	// for the already-bound root set). Project it once at construction; otherwise a
	// restart silently reverts FIM to its compiled-in 512 MiB budget while the API
	// continues to display the operator's persisted revision.
	if settings != nil && state != nil {
		var chronos *ChronosScanner
		if xdr != nil {
			chronos = xdr.Chronos()
		}
		if err := applyIntegrityPolicies(
			effectiveIntegritySettings(settings.Get()),
			state.FIM(), chronos, s.packages, state.EvidenceLedger(),
		); err != nil {
			log.Printf("integrity settings could not be applied at start: %v", err)
		}
	}
	imports, importErr := newImportPreviewStore()
	if importErr != nil {
		// Without a preview store there is no way to review an import, so the
		// import endpoints must be able to say so instead of dereferencing nil.
		log.Printf("fabric import preview store unavailable: %v", importErr)
	}
	s.imports = imports
	rules := NewKineticRuleRegistry()
	s.kineticRules = rules
	effectiveKinetic := cfg.Kinetic
	effectiveAllowlist := append([]string(nil), cfg.Defense.Allowlist...)
	var persisted RuntimeSettings
	if settings != nil {
		persisted = settings.Get()
		effectiveKinetic = kineticConfigFromRuntime(cfg.Kinetic, persisted.Kinetic)
		effectiveAllowlist = append([]string(nil), persisted.ManagementAllowlist...)
		// The boot evidence requirements are projected here, where the collector is
		// constructed, so the first collection already evaluates the persisted
		// policy instead of the compiled-in default.
		if err := s.bootTrust.ApplyPolicy(effectiveBootTrustSettings(persisted)); err != nil {
			s.bootTrust = NewBootTrustCollector(5 * time.Minute)
		}
		// The rate limiter belongs to this server, so its bound is applied here
		// rather than from main, where no limiter exists yet.
		if err := applySystemPolicies(effectiveSystemSettings(persisted), s.limiter, nil, nil); err != nil {
			log.Printf("system rate limit could not be applied at start, using the compiled-in default: %v", err)
		}
	}
	s.kinetic = NewKineticEngine(effectiveKinetic, state, rules, effectiveAllowlist)
	if feeds != nil {
		s.kinetic.SetThreatIntel(feeds.BlockIndex(), feeds.CorrelateIndex(), feeds.AnnotateIndex())
	}
	s.kineticResponse = NewKineticResponseEngine(cfg, state, core)
	if settings != nil {
		s.kineticResponse.UpdateConfig(persisted.Kinetic, persisted.Network)
		s.kineticResponse.UpdateAllowlist(persisted.ManagementAllowlist)
	}
	// F-24 / CHAIN-009: verify the shipped SHA-256 sidecar at load and enforce
	// the optional signed-update gate configured via kinetic.geoip_signing_keys.
	s.geo = NewGeoResolverWithTrust(cfg.Kinetic.GeoIPCSV, cfg.Kinetic.GeoIPSigningKeys)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	// The static dashboard shell and its assets carry no operator data, tokens or posture;
	// they are the same bytes that ship in the package. They stay servable on the loopback
	// origin because the authenticated console is reached through the gateway, while every
	// data-bearing surface (/api, /metrics, /bootz, /panelz) requires the backend credential
	// (G-WEB-05 / F-23).
	mux.HandleFunc("GET /assets/{name...}", s.asset)
	mux.HandleFunc("GET /api/v1/status", s.auth(s.status))
	// POINT 5 / P5-T3: the Emergency Lockdown surface. Status is read-only and
	// bounded; the two emergency routes are exempted from the evidence gate below
	// because the gate must never be able to seal the way out of its own condition.
	mux.HandleFunc("GET /api/v1/lockdown/status", s.auth(s.lockdownStatus))
	mux.HandleFunc("POST /api/v1/lockdown/arm", s.auth(s.lockdownArm))
	mux.HandleFunc("POST /api/v1/lockdown/trigger", s.auth(s.lockdownTrigger))
	mux.HandleFunc("POST /api/v1/lockdown/clear", s.auth(s.lockdownClear))
	// POINT 4 / P4-T2: the Out-of-Band Witness surface. Status and export are
	// read-only and bounded; every POST goes through the same authentication,
	// replay and evidence gate as any other operator mutation, and push adds its
	// own confirmation phrase plus a dedicated rate budget.
	mux.HandleFunc("GET /api/v1/witness/status", s.auth(s.witnessStatus))
	mux.HandleFunc("GET /api/v1/witness/export", s.auth(s.witnessExport))
	mux.HandleFunc("POST /api/v1/witness/checkpoint", s.auth(s.witnessCheckpoint))
	mux.HandleFunc("POST /api/v1/witness/push", s.auth(s.witnessPush))
	mux.HandleFunc("POST /api/v1/witness/challenge", s.auth(s.witnessChallenge))
	mux.HandleFunc("POST /api/v1/witness/import", s.auth(s.witnessImport))
	// V6.3.0 AP-9 (R6): role discovery and the direct-loopback critical step-up
	// flow. Both are authenticated like every other operator surface; the mint is
	// additionally refused for gateway-proxied browser requests, which have to
	// re-authenticate their password at the gateway instead (docs/V6.3.0-RBAC.md).
	mux.HandleFunc("GET /api/v1/auth/roles", s.auth(s.requireRole(RoleObserver, s.authRoles)))
	mux.HandleFunc("POST /api/v1/auth/step-up", s.auth(s.requireRole(RoleOperator, s.authStepUp)))
	// GeDefense 6.1.0 module A-D surfaces (docs/V6.1.0-BLUEPRINT.md §3.1). GET is
	// read-only and bounded; POST goes through the same authentication, replay and
	// evidence gate as every other operator mutation.
	mux.HandleFunc("GET /api/v1/web-exposure/status", s.auth(s.webExposureStatus))
	mux.HandleFunc("POST /api/v1/web-exposure/scan", s.auth(s.webExposureScan))
	mux.HandleFunc("GET /api/v1/web-exposure/advisories", s.auth(s.webExposureAdvisories))
	mux.HandleFunc("GET /api/v1/worker-guard/status", s.auth(s.workerGuardStatus))
	mux.HandleFunc("GET /api/v1/worker-guard/events", s.auth(s.workerGuardEvents))
	mux.HandleFunc("GET /api/v1/tls-sensor/status", s.auth(s.tlsSensorStatus))
	mux.HandleFunc("GET /api/v1/tls-sensor/handshakes", s.auth(s.tlsSensorHandshakes))
	mux.HandleFunc("GET /api/v1/tls-sensor/flows", s.auth(s.tlsSensorFlows))
	mux.HandleFunc("GET /api/v1/lpe-guard/status", s.auth(s.lpeGuardStatus))
	mux.HandleFunc("POST /api/v1/lpe-guard/apply", s.auth(s.lpeGuardApply))
	// Module E (memory-safe edge terminator) routes are served by the engine in
	// control/edge_proxy.go; the settings namespace is registered here like the
	// other 6.1.0 modules.
	mux.HandleFunc("GET /api/v1/edge-proxy/status", s.auth(s.edgeProxyStatus))
	mux.HandleFunc("POST /api/v1/edge-proxy/restart", s.auth(s.edgeProxyRestart))
	mux.HandleFunc("GET /api/v1/startup", s.auth(s.startupStatus))
	mux.HandleFunc("GET /api/v1/boot-trust", s.auth(s.bootTrustStatus))
	mux.HandleFunc("GET /api/v1/hardening/posture", s.auth(s.hardeningPosture))
	mux.HandleFunc("GET /api/v1/kernel/exposure", s.auth(s.kernelExposureStatus))
	mux.HandleFunc("GET /api/v1/kernel/mitigation", s.auth(s.kernelMitigationStatus))
	mux.HandleFunc("GET /api/v1/kernel/mitigation/plan", s.auth(s.kernelMitigationPlan))
	mux.HandleFunc("POST /api/v1/kernel/mitigation/apply", s.auth(s.kernelMitigationApply))
	mux.HandleFunc("POST /api/v1/kernel/mitigation/rollback", s.auth(s.kernelMitigationRollback))
	mux.HandleFunc("GET /api/v1/cells/confinement", s.auth(s.cellsConfinementStatus))
	mux.HandleFunc("POST /api/v1/xdr/incidents/{id}/confine", s.auth(s.confineIncident))
	mux.HandleFunc("GET /api/v1/evidence", s.auth(s.evidenceStatus))
	mux.HandleFunc("GET /api/v1/evidence/verify", s.auth(s.evidenceVerify))
	mux.HandleFunc("GET /api/v1/fim", s.auth(s.fimStatus))
	mux.HandleFunc("POST /api/v1/fim/scan", s.auth(s.fimScan))
	mux.HandleFunc("POST /api/v1/fim/baseline", s.auth(s.fimBaseline))
	mux.HandleFunc("GET /api/v1/package-integrity", s.auth(s.packageIntegrityStatus))
	mux.HandleFunc("POST /api/v1/package-integrity/scan", s.auth(s.packageIntegrityScan))
	mux.HandleFunc("GET /api/v1/titan/status", s.auth(s.titanStatus))
	mux.HandleFunc("GET /api/v1/titan/events", s.auth(s.titanEvents))
	mux.HandleFunc("POST /api/v1/titan/policy", s.auth(s.titanSetPolicy))
	mux.HandleFunc("POST /api/v1/titan/events/{id}/review", s.auth(s.titanReview))
	mux.HandleFunc("GET /api/v1/titan/quarantine", s.auth(s.titanQuarantine))
	mux.HandleFunc("POST /api/v1/titan/contain", s.auth(s.titanContain))
	// POINT 1 / P1-T5: read-only status and bounded recent-decision history for
	// the kernel Titan exec gate. Both are additive: the existing /titan/* routes
	// above keep their exact semantics (Go-side TitanEngine).
	mux.HandleFunc("GET /api/v1/titan/exec/status", s.auth(s.titanExecStatus))
	mux.HandleFunc("GET /api/v1/titan/exec/events", s.auth(s.titanExecEvents))
	mux.HandleFunc("POST /api/v1/malware/scan", s.auth(s.malwareScan))
	mux.HandleFunc("GET /api/v1/transactions", s.auth(s.transactionStatus))
	mux.HandleFunc("POST /api/v1/transactions/preview", s.auth(s.transactionPreview))
	mux.HandleFunc("POST /api/v1/transactions/{id}/apply", s.auth(s.transactionApply))
	mux.HandleFunc("POST /api/v1/transactions/{id}/reverse", s.auth(s.transactionReverse))
	mux.HandleFunc("GET /api/v1/quarantine", s.auth(s.quarantineStatus))
	mux.HandleFunc("POST /api/v1/quarantine/preview", s.auth(s.quarantinePreview))
	// V6.3.0 AP-7: evidence-first prune of a verified false-positive vault
	// object (full identity + object-id confirmation required).
	mux.HandleFunc("POST /api/v1/quarantine/prune", s.auth(s.quarantinePrune))
	mux.HandleFunc("GET /api/v1/cases", s.auth(s.caseStatus))
	mux.HandleFunc("POST /api/v1/cases/{id}/status", s.auth(s.caseSetStatus))
	mux.HandleFunc("GET /api/v1/cells", s.auth(s.cellsStatus))
	mux.HandleFunc("POST /api/v1/cells/preview", s.auth(s.cellsPreview))
	// POINT 2 / P2-T3: ephemeral parser cells. All routes are auth-gated like every
	// other operator surface; POST additionally takes the replay guard and evidence
	// gate from s.auth. GET status/list answer locally even when the helper is absent.
	mux.HandleFunc("GET /api/v1/parser-cells/status", s.auth(s.parserCellsStatus))
	mux.HandleFunc("GET /api/v1/parser-cells", s.auth(s.parserCellsList))
	mux.HandleFunc("POST /api/v1/parser-cells/inputs", s.auth(s.parserCellsInput))
	mux.HandleFunc("POST /api/v1/parser-cells/open", s.auth(s.parserCellsOpen))
	mux.HandleFunc("POST /api/v1/parser-cells/{uuid}/burn", s.auth(s.parserCellsBurn))
	mux.HandleFunc("POST /api/v1/parser-cells/{uuid}/freeze", s.auth(s.parserCellsFreeze))
	mux.HandleFunc("POST /api/v1/parser-cells/{uuid}/unfreeze", s.auth(s.parserCellsUnfreeze))
	mux.HandleFunc("GET /api/v1/parser-cells/{uuid}/export", s.auth(s.parserCellsExport))
	mux.HandleFunc("GET /api/v1/stream", s.auth(s.stream))
	mux.HandleFunc("GET /api/v1/policy", s.auth(s.policyStatus))
	mux.HandleFunc("GET /api/v1/xdr/profiles", s.auth(s.behaviorProfiles))
	mux.HandleFunc("GET /api/v1/xdr/integrity", s.auth(s.xdrIntegrityStatus))
	mux.HandleFunc("POST /api/v1/xdr/integrity/verify", s.auth(s.xdrIntegrityVerify))
	mux.HandleFunc("POST /api/v1/xdr/recovery", s.auth(s.xdrRecovery))
	mux.HandleFunc("GET /api/v1/forensics/export", s.auth(s.forensicsExport))
	mux.HandleFunc("GET /api/v1/release", s.auth(s.releaseStatus))
	mux.HandleFunc("GET /api/v1/release/readiness", s.auth(s.releaseReadiness))
	mux.HandleFunc("GET /api/v1/cms", s.auth(s.cmsStatus))
	mux.HandleFunc("PUT /api/v1/cms", s.auth(s.cmsUpdate))
	mux.HandleFunc("POST /api/v1/cms/bridge/rotate", s.auth(s.cmsRotateBridgeKey))
	mux.HandleFunc("POST /api/v1/cms/bridge/revoke", s.auth(s.cmsRevokeLeases))
	mux.HandleFunc("GET /api/v1/l7/findings", s.auth(s.l7Findings))
	// The self-test is a POST because it consumes engine admission and moves the
	// inspection counters it reports on.
	mux.HandleFunc("POST /api/v1/l7/selftest", s.auth(s.l7SelfTest))
	// Restarting is an operator mutation, so it goes through the same authentication,
	// replay guard and evidence gate as every other one.
	mux.HandleFunc("POST /api/v1/system/restart", s.auth(s.systemRestart))
	mux.HandleFunc("GET /api/v1/l7/integration", s.auth(s.l7Integration))
	mux.HandleFunc("POST /api/v1/l7/integration", s.auth(s.l7Integration))
	mux.HandleFunc("POST /api/v1/release/transition", s.auth(s.releaseTransition))
	mux.HandleFunc("POST /api/v1/release/emergency-stop", s.auth(s.releaseEmergencyStop))
	mux.HandleFunc("POST /api/v1/release/emergency-stop/clear", s.auth(s.releaseEmergencyStopClear))
	mux.HandleFunc("GET /api/v1/settings", s.auth(s.settingsStatus))
	mux.HandleFunc("PUT /api/v1/settings", s.auth(s.updateSettings))
	mux.HandleFunc("GET /api/v1/settings/schema", s.auth(s.fabricSettingsSchema))
	mux.HandleFunc("GET /api/v1/settings/history", s.auth(s.fabricSettingsHistory))
	mux.HandleFunc("POST /api/v1/settings/rollback", s.auth(s.fabricSettingsRollback))
	mux.HandleFunc("GET /api/v1/settings/search", s.auth(s.fabricSettingsSearch))
	mux.HandleFunc("GET /api/v1/settings/drift", s.auth(s.fabricSettingsDrift))
	mux.HandleFunc("POST /api/v1/settings/export", s.auth(s.fabricSettingsExport))
	mux.HandleFunc("POST /api/v1/settings/import/preview", s.auth(s.fabricSettingsImportPreview))
	mux.HandleFunc("POST /api/v1/settings/import/apply", s.auth(s.fabricSettingsImportApply))
	mux.HandleFunc("GET /api/v1/settings/{module}", s.auth(s.fabricSettingsModule))
	mux.HandleFunc("POST /api/v1/settings/{module}/preview", s.auth(s.fabricSettingsPreview))
	mux.HandleFunc("PUT /api/v1/settings/{module}", s.auth(s.fabricSettingsUpdate))
	mux.HandleFunc("POST /api/v1/allowlist", s.auth(s.addAllowlist))
	mux.HandleFunc("POST /api/v1/allowlist/remove", s.auth(s.removeAllowlist))
	mux.HandleFunc("POST /api/v1/allowlist/undo", s.auth(s.undoAllowlist))
	mux.HandleFunc("POST /api/v1/blocks", s.auth(s.addBlock))
	mux.HandleFunc("POST /api/v1/blocks/undo", s.auth(s.undoBlock))
	mux.HandleFunc("DELETE /api/v1/blocks/{id}", s.auth(s.deleteBlock))
	mux.HandleFunc("POST /api/v1/feeds/sync", s.auth(s.syncFeeds))
	mux.HandleFunc("POST /api/v1/feeds/apply", s.auth(s.applyFeeds))
	mux.HandleFunc("GET /api/v1/feeds/status", s.auth(s.getFeedStatus))
	mux.HandleFunc("GET /api/v1/kinetic/status", s.auth(s.getKineticStatus))
	mux.HandleFunc("GET /api/v1/kinetic/live", s.auth(s.getKineticLive))
	mux.HandleFunc("GET /api/v1/kinetic/events", s.auth(s.getKineticEvents))
	mux.HandleFunc("GET /api/v1/kinetic/sources", s.auth(s.getKineticSources))
	mux.HandleFunc("GET /api/v1/kinetic/map", s.auth(s.getKineticMap))
	// The overview map reads every detection path at once, not just the packet path: see overview_map.go.
	mux.HandleFunc("GET /api/v1/overview/threat-map", s.auth(s.overviewThreatMap))
	mux.HandleFunc("GET /api/v1/overview/situation", s.auth(s.overviewSituation))
	mux.HandleFunc("GET /api/v1/overview/connections", s.auth(s.overviewConnections))
	mux.HandleFunc("POST /api/v1/kinetic/reconcile", s.auth(s.reconcileKinetic))
	mux.HandleFunc("POST /api/v1/xdr/incidents/{id}/ack", s.auth(s.ackIncident))
	// V6.3.0 AP-7: persistent review queue (bounded, TTL, deduplicated).
	mux.HandleFunc("GET /api/v1/xdr/review", s.auth(s.xdrReviewQueue))
	mux.HandleFunc("POST /api/v1/xdr/review/{id}/ack", s.auth(s.xdrReviewAck))
	mux.HandleFunc("DELETE /api/v1/xdr/review/{id}", s.auth(s.xdrReviewDelete))
	// V6.3.0 AP-6/7/8/9: SBC fusion, S12 sec-crit, PermitV1 CRUD, Chameleon status/reveal, signed update override & antispyware plane telemetry.
	mux.HandleFunc("GET /api/v1/antispyware/status", s.auth(s.antispywareStatus))
	mux.HandleFunc("GET /api/v1/xdr/sbc", s.auth(s.xdrSBCFusion))
	mux.HandleFunc("GET /api/v1/xdr/sec-crit", s.auth(s.xdrSecCrit))
	mux.HandleFunc("GET /api/v1/xdr/permits", s.auth(s.xdrPermitsList))
	mux.HandleFunc("POST /api/v1/xdr/permits", s.auth(s.xdrPermitsUpsert))
	mux.HandleFunc("DELETE /api/v1/xdr/permits/{id}", s.auth(s.xdrPermitsDelete))
	mux.HandleFunc("POST /api/v1/xdr/update-window/override", s.auth(s.xdrUpdateWindowOverride))
	mux.HandleFunc("GET /api/v1/chameleon/status", s.auth(s.chameleonStatus))
	mux.HandleFunc("POST /api/v1/chameleon/reveal", s.auth(s.chameleonReveal))
	mux.HandleFunc("GET /api/v1/xdr/attack-stories", s.auth(s.attackStories))
	mux.HandleFunc("GET /api/v1/platform/caps", s.auth(s.platformCapabilities))
	mux.HandleFunc("GET /api/v1/responses", s.auth(s.activeResponses))
	mux.HandleFunc("POST /api/v1/deception/test-access", s.auth(s.deceptionTestAccess))
	mux.HandleFunc("GET /api/v1/styx/rules", s.auth(s.styxRules))
	mux.HandleFunc("POST /api/v1/styx/rules", s.auth(s.addStyxRule))
	// POINT 3 / P3-T5: read-only status for the kernel-side StyX enforcement and the
	// aggregated flow telemetry. Auth required, no mutation, bounded payloads; the
	// existing /styx/rules endpoints above keep their exact semantics (Go evaluator).
	mux.HandleFunc("GET /api/v1/styx/status", s.auth(s.styxKernelStatus))
	mux.HandleFunc("GET /api/v1/styx/beacons", s.auth(s.styxBeacons))
	mux.HandleFunc("POST /api/v1/airlock/inspect", s.auth(s.airlockInspect))
	mux.HandleFunc("GET /api/v1/chronos/status", s.auth(s.chronosStatus))
	mux.HandleFunc("POST /api/v1/gateway/auth-denials", s.auth(s.gatewayAuthDenials))
	mux.HandleFunc("GET /metrics", s.auth(s.metrics))
	mux.HandleFunc("GET /livez", s.liveness)
	mux.HandleFunc("GET /readyz", s.readiness)
	mux.HandleFunc("GET /healthz", s.readiness)
	mux.HandleFunc("GET /bootz", s.auth(s.bootHealth))
	mux.HandleFunc("GET /panelz", s.auth(s.panelStatus))
	s.http = &http.Server{
		Addr: cfg.Dashboard.Listen, Handler: s.secure(mux), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 0, IdleTimeout: 2 * time.Minute,
		MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
	s.ensureLimiters()
	s.denialSeen = make(map[string]time.Time)
	s.undoEntries = make(map[string]undoEntry)
	return s
}

// AttachL7 binds the running Application Defense engine to the control plane so
// the Fabric module can report apply state, the effective values and the rule
// catalogue from the component that actually enforces them. It is called after
// construction because the L7 engine is created later than the HTTP server.
func (s *APIServer) AttachL7(engine *L7Engine) { s.l7 = engine }

// AttachL7Service gives the API the socket topology and policy owner, which the
// self-test and the integration generator both need.
func (s *APIServer) AttachL7Service(service *L7Service) { s.l7Service = service }

// AttachCMS binds the optional CMS detector and WordPress bridge to the API.
func (s *APIServer) AttachCMS(cms *CMSEngine) { s.cms = cms }

// AttachFIM binds the running file integrity engine so the Integrity module can
// project its policy and report effective state.
func (s *APIServer) AttachFIM(engine *FIMEngine) { s.fim = engine }

// AttachKernelExposure binds the shared kernel-advisory measurement. The self-check, the release
// gate and this server all read the same cache, so an operator never sees two exposure numbers.
func (s *APIServer) AttachKernelExposure(exposure *kernelExposureCache) {
	if exposure == nil {
		return
	}
	s.kernelExposure = exposure
	if s.hardening != nil {
		s.hardening.AttachKernelExposure(exposure)
	}
}

// AttachCellGuard binds the automatic Gaia Cell isolation.
func (s *APIServer) AttachCellGuard(guard *CellGuard) {
	if guard == nil {
		return
	}
	s.cellGuard = guard
	if s.confineLimiter == nil {
		s.confineLimiter = NewRateLimiter(20, 5)
	}
}

// AttachMitigationGuard binds the automatic entry-point mitigation and its probation watch.
func (s *APIServer) AttachMitigationGuard(guard *MitigationGuard) {
	if guard == nil {
		return
	}
	s.mitigationGuard = guard
	if s.mitigationLimiter == nil {
		s.mitigationLimiter = NewRateLimiter(20, 5)
	}
}

// AttachFeeds binds the running Threat Intelligence manager so the Fabric module
// can report the active revision and the per-feed generation state.
func (s *APIServer) AttachFeeds(feeds *FeedManager) {
	if feeds == nil {
		return
	}
	s.feeds = feeds
}

func validateTLSMaterial(certPath, keyPath string) error {
	if certPath == "" && keyPath == "" {
		return nil
	}
	for label, path := range map[string]string{"TLS certificate": certPath, "TLS private key": keyPath} {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must be a regular non-symlink file", label)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s must not be group/world writable", label)
		}
	}
	keyInfo, err := os.Lstat(keyPath)
	if err != nil {
		return err
	}
	if keyInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("TLS private key must not be group/world accessible")
	}
	return nil
}

func (s *APIServer) Run() error { return s.RunWithReady(nil) }

func (s *APIServer) RunWithReady(ready chan<- struct{}) error {
	if err := validateTLSMaterial(s.cfg.Dashboard.TLSCertFile, s.cfg.Dashboard.TLSKeyFile); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return err
	}
	s.startKineticRuntime()
	s.startHardeningPosture()
	s.startPackageIntegrity()
	s.startTrustWatch()
	s.startDriftWatch()
	s.startCaseSweep()
	if ready != nil {
		close(ready)
	}
	if s.cfg.Dashboard.TLSCertFile != "" {
		return s.http.ServeTLS(listener, s.cfg.Dashboard.TLSCertFile, s.cfg.Dashboard.TLSKeyFile)
	}
	return s.http.Serve(listener)
}

func (s *APIServer) Shutdown(ctx context.Context) error {
	s.setKineticRuntimeEnabled(false)
	s.stopHardeningPosture()
	s.stopPackageIntegrity()
	s.stopTrustWatch()
	s.stopDriftWatch()
	s.stopCaseSweep()
	return s.http.Shutdown(ctx)
}

// resolveWebAsset maps a request path to an allowlisted embedded file.
//
// Vendored libraries live in subdirectories and import each other with
// extensionless specifiers (`./map`, `../util`), which is what Node and every
// bundler accept and what a browser does not: it requests the specifier verbatim.
// Rewriting 43 upstream files to add extensions would replace auditable third-party
// code with our own edit of it, so the resolution happens here instead, over exactly
// three candidates. Every candidate is looked up in the exhaustive allowlist, so the
// shim cannot reach a file the allowlist does not already expose, and the returned
// name is the one that gets read - the request string is never used as a path.
//
// A directory index is different from the other two candidates and returns a
// redirect instead of a file. Module resolution is URL-based, not filesystem-based:
// if `.../js/core` answered with the bytes of `core/index.js`, the browser would
// resolve that module's own relative imports against `.../js/core` as though it were
// a file, request `.../js/setupContainerEvents`, and the entire vendored tree would
// fail to load. Redirecting to the trailing-slash form makes the directory the base
// URL, which is the only form a relative import resolves correctly from.
//
// The second return value is non-empty when the caller must redirect to it.
func resolveWebAsset(name string) (string, string) {
	if !webAssetNameAllowed(name) {
		return "", ""
	}
	if webAssetAllowlist[name] {
		return name, ""
	}
	if webAssetAllowlist[name+".js"] {
		return name + ".js", ""
	}
	trimmed := strings.TrimSuffix(name, "/")
	if webAssetAllowlist[trimmed+"/index.js"] {
		if !strings.HasSuffix(name, "/") {
			return "", trimmed + "/"
		}
		return trimmed + "/index.js", ""
	}
	return "", ""
}
