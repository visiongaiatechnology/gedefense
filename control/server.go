package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed web/*
var webAssets embed.FS

type APIServer struct {
	cfg              Config
	state            *State
	core             *CoreClient
	feeds            *FeedManager
	policy           *PolicyStore
	xdr              *XDREngine
	release          *ReleaseController
	settings         *SettingsStore
	token            string
	http             *http.Server
	feedSyncing      atomic.Bool
	limiter          *RateLimiter
	replay           *ReplayGuard
	sseClients       atomic.Int32
	bootTrust        *BootTrustCollector
	hardening        *HardeningCollector
	packages         *PackageIntegrityScanner
	kinetic          *KineticEngine
	kineticResponse  *KineticResponseEngine
	kineticRules     *KineticRuleRegistry
	kineticRuntimeMu sync.Mutex
	kineticCancel    context.CancelFunc
	geo              *GeoResolver
	l7               *L7Engine
	// restartHook is invoked immediately before an internal restart exits the process.
	// It exists so a test can observe the restart without ending the test process.
	restartHook func()
	// The socket topology and the administrable path live on the service, not on the
	// engine, so the self-test and the integration generator need the service. Without
	// it both endpoints would have to reconstruct configuration they do not own.
	l7Service *L7Service
	fim       *FIMEngine

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
	s.geo = NewGeoResolver(cfg.Kinetic.GeoIPCSV)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	// The multi-segment wildcard is required: `{name}` matches a single segment, so
	// the vendored library under vendor/jsvectormap/js/** was unreachable through the
	// router even though resolveWebAsset accepted it. `{name...}` keeps the
	// single-segment case working and lets the allowlist remain the only authority.
	mux.HandleFunc("GET /assets/{name...}", s.asset)
	mux.HandleFunc("GET /api/v1/status", s.auth(s.status))
	mux.HandleFunc("GET /api/v1/boot-trust", s.auth(s.bootTrustStatus))
	mux.HandleFunc("GET /api/v1/hardening/posture", s.auth(s.hardeningPosture))
	mux.HandleFunc("GET /api/v1/evidence", s.auth(s.evidenceStatus))
	mux.HandleFunc("GET /api/v1/evidence/verify", s.auth(s.evidenceVerify))
	mux.HandleFunc("GET /api/v1/fim", s.auth(s.fimStatus))
	mux.HandleFunc("POST /api/v1/fim/scan", s.auth(s.fimScan))
	mux.HandleFunc("POST /api/v1/fim/baseline", s.auth(s.fimBaseline))
	mux.HandleFunc("GET /api/v1/package-integrity", s.auth(s.packageIntegrityStatus))
	mux.HandleFunc("POST /api/v1/package-integrity/scan", s.auth(s.packageIntegrityScan))
	mux.HandleFunc("POST /api/v1/malware/scan", s.auth(s.malwareScan))
	mux.HandleFunc("GET /api/v1/transactions", s.auth(s.transactionStatus))
	mux.HandleFunc("POST /api/v1/transactions/preview", s.auth(s.transactionPreview))
	mux.HandleFunc("POST /api/v1/transactions/{id}/apply", s.auth(s.transactionApply))
	mux.HandleFunc("POST /api/v1/transactions/{id}/reverse", s.auth(s.transactionReverse))
	mux.HandleFunc("GET /api/v1/quarantine", s.auth(s.quarantineStatus))
	mux.HandleFunc("POST /api/v1/quarantine/preview", s.auth(s.quarantinePreview))
	mux.HandleFunc("GET /api/v1/cases", s.auth(s.caseStatus))
	mux.HandleFunc("POST /api/v1/cases/{id}/status", s.auth(s.caseSetStatus))
	mux.HandleFunc("GET /api/v1/cells", s.auth(s.cellsStatus))
	mux.HandleFunc("POST /api/v1/cells/preview", s.auth(s.cellsPreview))
	mux.HandleFunc("GET /api/v1/stream", s.auth(s.stream))
	mux.HandleFunc("GET /api/v1/policy", s.auth(s.policyStatus))
	mux.HandleFunc("GET /api/v1/xdr/profiles", s.auth(s.behaviorProfiles))
	mux.HandleFunc("GET /api/v1/xdr/integrity", s.auth(s.xdrIntegrityStatus))
	mux.HandleFunc("POST /api/v1/xdr/integrity/verify", s.auth(s.xdrIntegrityVerify))
	mux.HandleFunc("POST /api/v1/xdr/recovery", s.auth(s.xdrRecovery))
	mux.HandleFunc("GET /api/v1/forensics/export", s.auth(s.forensicsExport))
	mux.HandleFunc("GET /api/v1/release", s.auth(s.releaseStatus))
	mux.HandleFunc("GET /api/v1/release/readiness", s.auth(s.releaseReadiness))
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
	mux.HandleFunc("POST /api/v1/blocks", s.auth(s.addBlock))
	mux.HandleFunc("DELETE /api/v1/blocks/{id}", s.auth(s.deleteBlock))
	mux.HandleFunc("POST /api/v1/feeds/sync", s.auth(s.syncFeeds))
	mux.HandleFunc("POST /api/v1/feeds/apply", s.auth(s.applyFeeds))
	mux.HandleFunc("GET /api/v1/feeds/status", s.auth(s.getFeedStatus))
	mux.HandleFunc("GET /api/v1/kinetic/status", s.auth(s.getKineticStatus))
	mux.HandleFunc("GET /api/v1/kinetic/live", s.auth(s.getKineticLive))
	mux.HandleFunc("GET /api/v1/kinetic/events", s.auth(s.getKineticEvents))
	mux.HandleFunc("GET /api/v1/kinetic/sources", s.auth(s.getKineticSources))
	mux.HandleFunc("GET /api/v1/kinetic/map", s.auth(s.getKineticMap))
	mux.HandleFunc("POST /api/v1/kinetic/reconcile", s.auth(s.reconcileKinetic))
	mux.HandleFunc("POST /api/v1/xdr/incidents/{id}/ack", s.auth(s.ackIncident))
	mux.HandleFunc("GET /api/v1/xdr/attack-stories", s.auth(s.attackStories))
	mux.HandleFunc("GET /api/v1/platform/caps", s.auth(s.platformCapabilities))
	mux.HandleFunc("GET /api/v1/responses", s.auth(s.activeResponses))
	mux.HandleFunc("POST /api/v1/deception/test-access", s.auth(s.deceptionTestAccess))
	mux.HandleFunc("GET /api/v1/styx/rules", s.auth(s.styxRules))
	mux.HandleFunc("POST /api/v1/styx/rules", s.auth(s.addStyxRule))
	mux.HandleFunc("POST /api/v1/airlock/inspect", s.auth(s.airlockInspect))
	mux.HandleFunc("GET /api/v1/chronos/status", s.auth(s.chronosStatus))
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /livez", s.liveness)
	mux.HandleFunc("GET /readyz", s.readiness)
	mux.HandleFunc("GET /healthz", s.readiness)
	mux.HandleFunc("GET /bootz", s.bootHealth)
	mux.HandleFunc("GET /panelz", s.panelStatus)
	s.http = &http.Server{
		Addr: cfg.Dashboard.Listen, Handler: s.secure(mux), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 0, IdleTimeout: 2 * time.Minute,
		MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
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

// caseEngine returns the case engine when it is attached.
func (s *APIServer) caseEngine() *CaseEngine {
	if s.state == nil {
		return nil
	}
	return s.state.Cases()
}

// quarantineApplier returns the quarantine transaction applier when the
// transaction engine is attached. It is reached through the engine rather than
// stored separately, so there is one instance and no second policy target.
func (s *APIServer) quarantineApplier() *QuarantineTransactionApplier {
	if s.state == nil {
		return nil
	}
	engine := s.state.Transactions()
	if engine == nil {
		return nil
	}
	return engine.QuarantineApplier()
}

// AttachFIM binds the running file integrity engine so the Integrity module can
// project its policy and report effective state.
func (s *APIServer) AttachFIM(engine *FIMEngine) { s.fim = engine }

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

// startHardeningPosture runs the administrable periodic posture evaluation. It
// is the only place that raises a posture event, so the operator sees a change
// once instead of on every dashboard poll.
func (s *APIServer) startHardeningPosture() {
	if s.hardening == nil {
		return
	}
	s.hardeningMu.Lock()
	if s.hardeningCancel != nil {
		s.hardeningMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.hardeningCancel = cancel
	if s.hardeningMemo == nil {
		s.hardeningMemo = make(map[string]string)
	}
	s.hardeningMu.Unlock()

	go func() {
		for {
			interval := time.Duration(hardeningDefaultPostureIntervalSeconds) * time.Second
			autoScan := true
			if s.settings != nil {
				posture := effectiveHardeningSettings(s.settings.Get()).Posture
				autoScan = posture.AutoScan
				if posture.ScanIntervalSeconds > 0 {
					interval = time.Duration(posture.ScanIntervalSeconds) * time.Second
				}
			}
			if autoScan {
				s.evaluateHardeningPosture()
			} else {
				// A disabled automatic scan still re-reads the policy regularly so
				// re-enabling it does not require a restart.
				interval = 30 * time.Second
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func (s *APIServer) stopHardeningPosture() {
	s.hardeningMu.Lock()
	cancel := s.hardeningCancel
	s.hardeningCancel = nil
	s.hardeningMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// startTrustWatch re-verifies the signed policy document and the boot evidence
// requirements periodically. Without it a tampered state file, a replayed older
// revision or a boot anchor that changed after startup would only be noticed at
// the next operator action.
func (s *APIServer) startTrustWatch() {
	if s.policy == nil && s.bootTrust == nil {
		return
	}
	s.trustMu.Lock()
	if s.trustCancel != nil {
		s.trustMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.trustCancel = cancel
	s.trustMu.Unlock()

	go func() {
		lastVerified := true
		lastLevel := ""
		for {
			interval := time.Duration(defaultPolicyTrustFabricSettings().VerifyIntervalSeconds) * time.Second
			if s.settings != nil {
				configured := effectivePolicyTrustSettings(s.settings.Get()).VerifyIntervalSeconds
				if configured >= policyTrustVerifyFloor {
					interval = time.Duration(configured) * time.Second
				}
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if s.state == nil {
				continue
			}
			if s.policy != nil {
				if _, err := s.policy.Load(); err != nil {
					if lastVerified {
						s.state.AddEvent(Event{Severity: "critical", Kind: "policy.verification_failed", Source: "policy",
							Message: "Signed policy document failed periodic verification; the last known-good policy remains active"})
					}
					lastVerified = false
				} else {
					lastVerified = true
					s.state.SetPolicyStatus(s.policy.Status())
				}
			}
			if s.bootTrust != nil {
				report := s.bootTrust.Collect()
				if report.Summary != lastLevel {
					if lastLevel != "" {
						s.state.AddEvent(Event{Severity: "warning", Kind: "boot_trust.changed", Source: "boot",
							Message: "Boot trust evidence changed: " + report.Summary})
					}
					lastLevel = report.Summary
				}
			}
		}
	}()
}

func (s *APIServer) stopTrustWatch() {
	s.trustMu.Lock()
	cancel := s.trustCancel
	s.trustCancel = nil
	s.trustMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// startCaseSweep closes open cases that have been idle longer than the
// administrable age. A zero setting disables it, which is the default: closing a
// case is an operator judgement, and the sweep never touches a case an operator
// moved to a non-open status.
func (s *APIServer) startCaseSweep() {
	if s.caseEngine() == nil {
		return
	}
	s.trustMu.Lock()
	if s.caseCancel != nil {
		s.trustMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.caseCancel = cancel
	s.trustMu.Unlock()

	go func() {
		for {
			interval := 30 * time.Minute
			enabled := false
			if s.settings != nil {
				enabled = effectiveForensicsSettings(s.settings.Get()).Cases.AutoCloseAfterHours > 0
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if !enabled {
				continue
			}
			engine := s.caseEngine()
			if engine == nil {
				continue
			}
			policy := engine.policySnapshot()
			status := engine.Status(policy.listMaxLimit)
			now := time.Now().UTC()
			for _, record := range status.Cases {
				if !autoCloseCandidate(record, now, policy) {
					continue
				}
				if _, err := engine.SetStatus(record.ID, "resolved", "automatically closed after the configured inactivity window"); err != nil {
					continue
				}
				if s.state != nil {
					s.state.AddEvent(Event{Severity: "info", Kind: "case.auto_closed", Source: "forensics",
						Message: fmt.Sprintf("Case %s was closed automatically after %d hours without activity", record.ID, policy.autoCloseHours)})
				}
			}
		}
	}()
}

func (s *APIServer) stopCaseSweep() {
	s.trustMu.Lock()
	cancel := s.caseCancel
	s.caseCancel = nil
	s.trustMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// startPackageIntegrity runs the administrable package verification schedule. It
// re-reads enablement and cadence on every cycle, so an operator change needs no
// restart.
func (s *APIServer) startPackageIntegrity() {
	if s.packages == nil {
		return
	}
	s.packageMu.Lock()
	if s.packageCancel != nil {
		s.packageMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.packageCancel = cancel
	s.packageMu.Unlock()

	go func() {
		for {
			interval := time.Hour
			run := false
			if s.settings != nil {
				policy := effectiveIntegritySettings(s.settings.Get()).Packages
				if policy.IntervalHours >= 1 {
					interval = time.Duration(policy.IntervalHours) * time.Hour
				}
				run = policy.Enabled && policy.AutoScan
			}
			if run && !s.packages.Status().Running {
				s.packages.Start(s.recordPackageIntegrityOutcome)
			}
			if !run {
				interval = time.Minute
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func (s *APIServer) stopPackageIntegrity() {
	s.packageMu.Lock()
	cancel := s.packageCancel
	s.packageCancel = nil
	s.packageMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// recordPackageIntegrityOutcome publishes the scheduled scan result as an event.
func (s *APIServer) recordPackageIntegrityOutcome(status PackageIntegrityStatus) {
	if s.state == nil {
		return
	}
	if status.Modified > 0 || status.Missing > 0 || status.Errors > 0 {
		s.state.AddEvent(Event{Severity: "warning", Kind: "package_integrity.deviation", Source: "integrity",
			Message: fmt.Sprintf("Scheduled package verification found %d modified and %d missing file(s) across %d package(s)", status.Modified, status.Missing, status.Packages)})
		return
	}
	s.state.AddEvent(Event{Severity: "info", Kind: "package_integrity.verified", Source: "integrity",
		Message: fmt.Sprintf("Scheduled package verification confirmed %d package(s) and %d file(s)", status.Packages, status.Files)})
}

// evaluateHardeningPosture collects the live posture and reports a level change
// or a required-domain regression exactly once per transition.
func (s *APIServer) evaluateHardeningPosture() {
	if s.hardening == nil || s.state == nil {
		return
	}
	settings := HardeningPostureSettings{}
	if s.settings != nil {
		settings = effectiveHardeningSettings(s.settings.Get()).Posture
	}
	report := s.hardening.Collect(s.state.Snapshot(), s.bootTrust.Collect())
	report.Checks = append(report.Checks, packageIntegrityPostureCheck(s.packages.Status()))
	posture := summarizeHardening(report.CollectedAt, report.Checks, settings.thresholds())
	findings := assessHardeningPosture(posture, settings)

	s.hardeningMu.Lock()
	defer s.hardeningMu.Unlock()
	if posture.Level != s.hardeningLevel {
		severity := "info"
		switch posture.Level {
		case "CRITICAL":
			severity = "critical"
		case "BASIC":
			severity = "warning"
		}
		s.state.AddEvent(Event{Severity: severity, Kind: "hardening.posture_changed", Source: "hardening",
			Message: fmt.Sprintf("Host hardening posture is now %s at %d%% compliance", posture.Level, posture.Score)})
		s.hardeningLevel = posture.Level
	}
	for _, finding := range findings {
		previous, seen := s.hardeningMemo[finding.Domain]
		if seen && previous == finding.State {
			continue
		}
		s.hardeningMemo[finding.Domain] = finding.State
		if finding.State == "PROTECTED" {
			continue
		}
		severity := "warning"
		if finding.State == "CRITICAL" || finding.State == "UNAVAILABLE" {
			severity = "critical"
		}
		s.state.AddEvent(Event{Severity: severity, Kind: "hardening.required_domain", Source: "hardening",
			Message: fmt.Sprintf("Required posture domain %s is %s at %d%% (threshold %d): %s", finding.Title, finding.State, finding.Score, finding.Threshold, finding.Reason)})
	}
}

func (s *APIServer) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if !s.hostAllowed(r.Host) {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") ||
			r.URL.Path == "/metrics" ||
			r.URL.Path == "/healthz" ||
			r.URL.Path == "/livez" ||
			r.URL.Path == "/readyz" ||
			r.URL.Path == "/bootz" ||
			r.URL.Path == "/panelz" {
			if !s.limiter.Allow(remoteIdentity(r.RemoteAddr), time.Now()) {
				w.Header().Set("Retry-After", "2")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Origin-Agent-Cluster", "?1")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		// Every mutating body passes this ceiling before any handler sees it. A
		// handler that accepts less still accepts less; the administrable value can
		// only tighten, so one revision cannot widen every endpoint at once.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.apiPayloadLimit())
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS != nil {
			// HSTS is only meaningful on a TLS origin. Emitting it from a plain-HTTP
			// control port is noise that hides whether TLS is actually in effect.
			if r.TLS != nil {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *APIServer) hostAllowed(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	for _, allowed := range s.cfg.Dashboard.AllowedHosts {
		if strings.EqualFold(strings.Trim(allowed, "[]"), host) {
			return true
		}
	}
	return false
}

// evidenceGateExempt lists the endpoints that stay reachable while the evidence ledger
// is unavailable. Every entry is a route out of that condition, not an ordinary
// mutation; the audit guarantee is unchanged for everything else. See the call site for
// why each one is here.
func evidenceGateExempt(path string) bool {
	switch path {
	case "/api/v1/release/emergency-stop", // stopping the platform cannot need its audit trail
		"/api/v1/l7/selftest",        // a diagnostic must survive the condition it diagnoses
		"/api/v1/settings/integrity": // the remedy for a full ledger is itself a mutation
		return true
	}
	return false
}

func (s *APIServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			expected := "http://" + r.Host
			if r.TLS != nil {
				expected = "https://" + r.Host
			}
			if o != expected {
				http.Error(w, "origin rejected", http.StatusForbidden)
				return
			}
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !tokenEqual(got, s.token) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "authorization required", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.replay.Claim(r.Header.Get("X-VGT-Request-ID"), time.Now()) {
				http.Error(w, "request identifier missing or replayed", http.StatusConflict)
				return
			}
			if s.state != nil && s.state.EvidenceLedger() != nil {
				// A closed evidence gate must not seal the exits from its own condition.
				//
				// The gate exists so an operator mutation is never accepted without an
				// audit record, and that stays true for everything else. Three endpoints
				// have to remain reachable while the ledger is unavailable, because each
				// is a way out of the condition rather than an ordinary action:
				//
				//   emergency stop  - stopping the platform cannot depend on its audit
				//                     trail being writable.
				//   L7 self-test    - a diagnostic that cannot run while the platform is
				//                     degraded is not a diagnostic. Without this the
				//                     operator sees "mandatory evidence ledger unavailable"
				//                     reported as a traffic-path failure, which diagnoses
				//                     the wrong subsystem entirely.
				//   integrity apply - a full ledger is remedied by raising its budget or
				//                     rotating it, and both are mutations. Gating the
				//                     remedy behind the condition deadlocked the operator
				//                     with no route out through the interface at all.
				exempt := evidenceGateExempt(r.URL.Path)
				if message, err := s.state.EvidenceGateCondition(); err != nil && !exempt {
					apiError(w, http.StatusServiceUnavailable, message, err)
					return
				}
				if err := s.state.RecordEvidence(EvidenceRecord{
					Severity: "high", Kind: "operator.mutation.intent", Source: "access-gateway",
					Message: "Authenticated operator mutation accepted for processing",
					Target:  r.Method + " " + r.URL.Path, RequestID: r.Header.Get("X-VGT-Request-ID"),
				}); err != nil && !exempt {
					apiError(w, http.StatusServiceUnavailable, "mandatory evidence commit failed", err)
					return
				}
			}
		}
		next(w, r)
	}
}

func (s *APIServer) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.serveEmbedded(w, r, "web/index.html", "text/html; charset=utf-8")
}

// webAssetAllowlist is the complete set of dashboard assets the embedded HTTP
// handler is permitted to serve. Every ES module that app.js imports must be
// listed here: a missing entry breaks the whole module graph with a 404 rather
// than a single missing view, which is why serving is contract-tested against
// the real import graph.
// webAssetAllowlist is the exhaustive set of embedded files the network may reach.
//
// It is exact, not a prefix rule: a request is resolved against this map and
// nothing else. Files that ship for provenance but must never be served - the
// upstream licence, the readme, the upstream manifest and the Sass sources - are
// embedded because the embed directive covers the whole directory, and are kept out
// of the network by being absent here.
var webAssetAllowlist = map[string]bool{
	"api.js":             true,
	"app.css":            true,
	"app.js":             true,
	"charts.js":          true,
	"fabric-settings.js": true,
	"fabric-surface.js":  true,
	"gedefense-logo.png": true,
	"geo-map.js":         true,
	"i18n.js":            true,
	"kinetic.js":         true,
	"l7-integration.js":  true, "l7.js": true,
	"operations.js":   true,
	"protection.js":   true,
	"render.js":       true,
	"threat-intel.js": true,
	"v4.css":          true,
	"vendor/jsvectormap/js/components/base.js":                  true,
	"vendor/jsvectormap/js/components/concerns/interactable.js": true,
	"vendor/jsvectormap/js/components/line.js":                  true,
	"vendor/jsvectormap/js/components/marker.js":                true,
	"vendor/jsvectormap/js/components/region.js":                true,
	"vendor/jsvectormap/js/components/tooltip.js":               true,
	"vendor/jsvectormap/js/core/applyTransform.js":              true,
	"vendor/jsvectormap/js/core/coordsToPoint.js":               true,
	"vendor/jsvectormap/js/core/createLines.js":                 true,
	"vendor/jsvectormap/js/core/createMarkers.js":               true,
	"vendor/jsvectormap/js/core/createRegions.js":               true,
	"vendor/jsvectormap/js/core/createSeries.js":                true,
	"vendor/jsvectormap/js/core/getInsetForPoint.js":            true,
	"vendor/jsvectormap/js/core/getMarkerPosition.js":           true,
	"vendor/jsvectormap/js/core/index.js":                       true,
	"vendor/jsvectormap/js/core/repositionLabels.js":            true,
	"vendor/jsvectormap/js/core/repositionLines.js":             true,
	"vendor/jsvectormap/js/core/repositionMarkers.js":           true,
	"vendor/jsvectormap/js/core/resize.js":                      true,
	"vendor/jsvectormap/js/core/setFocus.js":                    true,
	"vendor/jsvectormap/js/core/setScale.js":                    true,
	"vendor/jsvectormap/js/core/setupContainerEvents.js":        true,
	"vendor/jsvectormap/js/core/setupContainerTouchEvents.js":   true,
	"vendor/jsvectormap/js/core/setupElementEvents.js":          true,
	"vendor/jsvectormap/js/core/setupZoomButtons.js":            true,
	"vendor/jsvectormap/js/core/updateSize.js":                  true,
	"vendor/jsvectormap/js/dataVisualization.js":                true,
	"vendor/jsvectormap/js/defaults/events.js":                  true,
	"vendor/jsvectormap/js/defaults/options.js":                 true,
	"vendor/jsvectormap/js/eventHandler.js":                     true,
	"vendor/jsvectormap/js/index.js":                            true,
	"vendor/jsvectormap/js/legend.js":                           true,
	"vendor/jsvectormap/js/map.js":                              true,
	"vendor/jsvectormap/js/projection.js":                       true,
	"vendor/jsvectormap/js/scales/ordinalScale.js":              true,
	"vendor/jsvectormap/js/series.js":                           true,
	"vendor/jsvectormap/js/svg/baseElement.js":                  true,
	"vendor/jsvectormap/js/svg/canvasElement.js":                true,
	"vendor/jsvectormap/js/svg/imageElement.js":                 true,
	"vendor/jsvectormap/js/svg/shapeElement.js":                 true,
	"vendor/jsvectormap/js/svg/textElement.js":                  true,
	"vendor/jsvectormap/js/util/deepMerge.js":                   true,
	"vendor/jsvectormap/js/util/index.js":                       true,
	"vendor/jsvectormap/jsvectormap.css":                        true,
	"vendor/jsvectormap/maps/world-merc.js":                     true,
	"xdr.js":                                                    true,
}

// webAssetNameAllowed validates a request path before any resolution happens. It
// accepts exactly one optional trailing slash and nothing else: no absolute path, no
// backslash, no NUL, no empty, dot or dot-dot segment, and no uncleaned form.
func webAssetNameAllowed(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	if strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") {
		return false
	}
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" || path.Clean(trimmed) != trimmed {
		return false
	}
	for _, segment := range strings.Split(trimmed, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
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

func (s *APIServer) asset(w http.ResponseWriter, r *http.Request) {
	name, redirect := resolveWebAsset(r.PathValue("name"))
	if redirect != "" {
		// The trailing slash is preserved in the Location so the browser re-resolves
		// relative imports against the directory rather than against a file URL.
		http.Redirect(w, r, "/assets/"+redirect, http.StatusMovedPermanently)
		return
	}
	if name == "" {
		http.NotFound(w, r)
		return
	}
	extension := path.Ext(name)
	contentType := mime.TypeByExtension(extension)
	switch extension {
	case ".js":
		contentType = "text/javascript; charset=utf-8"
	case ".css":
		contentType = "text/css; charset=utf-8"
	case ".png":
		contentType = "image/png"
	default:
		if contentType == "" {
			contentType = "application/octet-stream"
		}
	}
	s.serveEmbedded(w, r, "web/"+name, contentType)
}

func (s *APIServer) serveEmbedded(w http.ResponseWriter, r *http.Request, name, contentType string) {
	b, err := webAssets.ReadFile(name)
	if err != nil {
		http.Error(w, "asset unavailable", http.StatusInternalServerError)
		return
	}
	digest := sha256.Sum256(b)
	etag := `"` + hex.EncodeToString(digest[:16]) + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("ETag", etag)
	_, _ = w.Write(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// opaqueFaultMessage maps a status code to a stable, non-descriptive client text.
// The operator correlates it through the returned error identifier, which is the
// only value that ties the response to the internal log line.
func opaqueFaultMessage(status int) string {
	switch {
	case status == http.StatusBadRequest:
		return "request rejected"
	case status == http.StatusUnauthorized:
		return "authorization required"
	case status == http.StatusForbidden:
		return "request rejected"
	case status == http.StatusNotFound:
		return "resource not found"
	case status == http.StatusConflict:
		return "request conflicts with the current state"
	case status == http.StatusTooManyRequests:
		return "rate limit exceeded"
	case status >= 500:
		return "internal fault"
	default:
		return "request rejected"
	}
}

// apiFault reports an internal fault opaquely. The client receives a stable text
// and an identifier; the detail goes to the log only.
func apiFault(w http.ResponseWriter, status int, internal error) {
	id := randomID()
	if internal != nil {
		log.Printf("api fault id=%s status=%d: %v", id, status, internal)
	}
	writeJSON(w, status, map[string]string{"error": opaqueFaultMessage(status), "error_id": id})
}

// contentSecurityPolicy is the single source of truth for the dashboard policy.
//
// The application ships no inline script and no inline style, so neither
// 'unsafe-inline' nor 'unsafe-eval' is needed and neither is granted. Trusted
// Types makes the absence of DOM-XSS sinks a runtime invariant instead of a
// property that only a source scan checks: any future assignment to a script
// sink raises instead of executing.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"font-src 'none'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'; " +
	"manifest-src 'self'; " +
	"worker-src 'none'; " +
	"require-trusted-types-for 'script'"

// apiError publishes only explicitly approved operator messages. Unknown text
// and messages identical to an internal cause are opaque, even without a cause.
func apiError(w http.ResponseWriter, status int, publicMessage string, internal error) {
	// Only registered operator messages may cross the disclosure boundary.
	if _, approved := operatorMessages[publicMessage]; !approved {
		if internal == nil {
			internal = errors.New(publicMessage)
		}
		apiFault(w, status, internal)
		return
	}
	if internal != nil {
		if publicMessage == "" || publicMessage == internal.Error() {
			apiFault(w, status, internal)
			return
		}
	}
	if publicMessage == "" {
		apiFault(w, status, nil)
		return
	}
	id := randomID()
	if internal != nil {
		log.Printf("api fault id=%s status=%d: %v", id, status, internal)
	}
	writeJSON(w, status, map[string]string{"error": publicMessage, "error_id": id})
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, max int64, dst any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, max)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func (s *APIServer) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.state.Snapshot())
}

func (s *APIServer) bootTrustStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.bootTrust.Collect())
}

// hardeningPosture evaluates the live posture with the administrable thresholds
// and reports the required-domain verdicts beside it, so the dashboard never has
// to re-derive a classification the backend already made.
func (s *APIServer) hardeningPosture(w http.ResponseWriter, _ *http.Request) {
	settings := HardeningPostureSettings{}
	if s.settings != nil {
		settings = effectiveHardeningSettings(s.settings.Get()).Posture
	}
	posture := s.hardening.Collect(s.state.Snapshot(), s.bootTrust.Collect())
	posture.Checks = append(posture.Checks, packageIntegrityPostureCheck(s.packages.Status()))
	summarized := summarizeHardening(posture.CollectedAt, posture.Checks, settings.thresholds())
	writeJSON(w, http.StatusOK, struct {
		HardeningPosture
		RequiredDomains []HardeningDomainFinding `json:"required_domains"`
	}{HardeningPosture: summarized, RequiredDomains: assessHardeningPosture(summarized, settings)})
}

func (s *APIServer) evidenceStatus(w http.ResponseWriter, r *http.Request) {
	ledger := s.state.EvidenceLedger()
	// The page bounds are administrable so an operator can widen the evidence
	// view without a code change, while the ceiling keeps the response bounded.
	pageDefault, pageCeiling := 100, 500
	if s.settings != nil {
		policy := effectiveIntegritySettings(s.settings.Get()).Evidence
		if policy.APIRecentDefault > 0 {
			pageDefault = policy.APIRecentDefault
		}
		if policy.APIRecentMax >= pageDefault {
			pageCeiling = policy.APIRecentMax
		}
	}
	limit := pageDefault
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > pageCeiling {
			apiError(w, http.StatusBadRequest, "invalid evidence limit", err)
			return
		}
		limit = value
	}
	if ledger == nil {
		apiError(w, http.StatusServiceUnavailable, "evidence ledger unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": ledger.Status(), "records": ledger.Recent(limit)})
}

func (s *APIServer) evidenceVerify(w http.ResponseWriter, _ *http.Request) {
	ledger := s.state.EvidenceLedger()
	if ledger == nil {
		apiError(w, http.StatusServiceUnavailable, "evidence ledger unavailable", nil)
		return
	}
	if err := ledger.Verify(); err != nil {
		apiError(w, http.StatusServiceUnavailable, "evidence verification failed", err)
		return
	}
	writeJSON(w, http.StatusOK, ledger.Status())
}

func (s *APIServer) liveness(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Dashboard.AllowRemote && !isLoopbackRemote(r.RemoteAddr) {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version})
}

func (s *APIServer) readiness(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Dashboard.AllowRemote && !isLoopbackRemote(r.RemoteAddr) {
		http.NotFound(w, r)
		return
	}
	ready, blockers := s.release.Ready()
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	snap := s.state.Snapshot()
	writeJSON(w, status, map[string]any{"ok": ready, "release": snap.Release, "blockers": blockers, "core": snap.CoreConnected, "xdr": snap.XDR, "policy": snap.Policy})
}

func localHealthRequest(r *http.Request) bool {
	return isLoopbackRemote(r.RemoteAddr)
}

func (s *APIServer) bootHealth(w http.ResponseWriter, r *http.Request) {
	if !localHealthRequest(r) {
		http.NotFound(w, r)
		return
	}
	snap := s.state.Snapshot()
	status := http.StatusOK
	if !snap.CoreConnected {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{
		"ok":             snap.CoreConnected,
		"core_connected": snap.CoreConnected,
		"core_mode":      snap.CoreMode,
	})
}

func (s *APIServer) panelStatus(w http.ResponseWriter, r *http.Request) {
	if !localHealthRequest(r) {
		http.NotFound(w, r)
		return
	}
	snap := s.state.Snapshot()
	openFindings := snap.Cases.Open
	if !snap.Cases.Healthy {
		uniqueFindings := make(map[string]struct{})
		for _, incident := range snap.Incidents {
			if !incident.Acknowledged {
				uniqueFindings[caseFingerprint(incident)] = struct{}{}
			}
		}
		openFindings = len(uniqueFindings)
	}
	safe := snap.CoreConnected && !snap.XDR.Degraded && openFindings == 0
	state := "alert"
	if safe {
		state = "safe"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             safe,
		"state":          state,
		"open_findings":  openFindings,
		"core_connected": snap.CoreConnected,
		"xdr_degraded":   snap.XDR.Degraded,
		"xdr_sensor":     snap.XDR.Sensor,
	})
}

func isLoopbackRemote(remote string) bool {
	host := remoteIdentity(remote)
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *APIServer) stream(w http.ResponseWriter, r *http.Request) {
	if s.sseClients.Add(1) > s.sseClientLimit() {
		s.sseClients.Add(-1)
		http.Error(w, "stream capacity reached", http.StatusServiceUnavailable)
		return
	}
	defer s.sseClients.Add(-1)
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	s.state.RecordStreamConnect()
	defer s.state.RecordStreamDisconnect()
	ch, cancel := s.state.Subscribe()
	defer cancel()
	if _, err := fmt.Fprint(w, "event: snapshot\ndata: "); err != nil {
		s.state.RecordStreamWriteError()
		return
	}
	if err := json.NewEncoder(w).Encode(s.state.Snapshot()); err != nil {
		s.state.RecordStreamWriteError()
		return
	}
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		s.state.RecordStreamWriteError()
		return
	}
	fl.Flush()
	heartbeat := time.NewTicker(5 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			if _, err := fmt.Fprint(w, "event: event\ndata: "); err != nil {
				s.state.RecordStreamWriteError()
				return
			}
			if err := json.NewEncoder(w).Encode(e); err != nil {
				s.state.RecordStreamWriteError()
				return
			}
			if _, err := fmt.Fprint(w, "\n"); err != nil {
				s.state.RecordStreamWriteError()
				return
			}
			fl.Flush()
		case <-heartbeat.C:
			s.state.RecordStreamHeartbeat()
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				s.state.RecordStreamWriteError()
				return
			}
			fl.Flush()
		}
	}
}

func (s *APIServer) addBlock(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target     string `json:"target"`
		Reason     string `json:"reason"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := decodeStrictJSON(w, r, 16<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request", err)
		return
	}
	network := NetworkRuntimeSettings{DefaultTTLSeconds: s.cfg.Defense.DefaultTTLSeconds, MaxTTLSeconds: s.cfg.Defense.MaxTTLSeconds, MaxBlockEntries: s.cfg.Defense.MaxBlockEntries}
	if s.settings != nil {
		network = s.settings.Get().Network
	}
	if in.TTLSeconds == 0 {
		in.TTLSeconds = network.DefaultTTLSeconds
	}
	if in.TTLSeconds < 60 || in.TTLSeconds > network.MaxTTLSeconds {
		apiError(w, http.StatusBadRequest, "TTL outside policy", nil)
		return
	}
	normalizedTarget, err := normalizeTarget(in.Target)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid target", err)
		return
	}
	in.Target = normalizedTarget
	if s.kineticResponse != nil && s.kineticResponse.IsAllowlistProtected(in.Target) {
		apiError(w, http.StatusConflict, "target overlaps immutable management allowlist", ErrAllowlistProtected)
		return
	}
	enforced := false
	enforcement, _ := s.state.Modes()
	if enforcement == "enforce" {
		if err := s.core.Add(in.Target); err != nil {
			s.state.SetCore(false, "offline")
			apiError(w, http.StatusServiceUnavailable, "kernel core unavailable", err)
			return
		}
		enforced = true
	}
	b, err := s.state.AddBlock(in.Target, in.Reason, "manual", time.Duration(in.TTLSeconds)*time.Second, enforced, network.MaxBlockEntries)
	if err != nil {
		if enforced {
			if rollbackErr := s.core.Delete(in.Target); rollbackErr != nil {
				failSafeErr := s.release.FailSafe("manual block rollback failed")
				apiError(w, http.StatusServiceUnavailable, "kernel transaction reconciliation failed", errors.Join(err, rollbackErr, failSafeErr))
				return
			}
		}
		apiFault(w, http.StatusBadRequest, err)
		return
	}
	if err := persistPolicy(s.policy, s.cfg, s.state); err != nil {
		s.state.RemoveBlockByID(b.ID)
		if enforced {
			if rollbackErr := s.core.Delete(b.Target); rollbackErr != nil {
				failSafeErr := s.release.FailSafe("manual block policy rollback failed")
				apiError(w, http.StatusServiceUnavailable, "kernel transaction reconciliation failed", errors.Join(err, rollbackErr, failSafeErr))
				return
			}
		}
		apiError(w, http.StatusInternalServerError, "signed policy persistence failed", err)
		return
	}
	s.state.AddEvent(Event{Severity: "high", Kind: "block.added", Source: "operator", Message: "Signed block rule activated", Target: b.Target})
	writeJSON(w, http.StatusCreated, b)
}

func (s *APIServer) deleteBlock(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		apiError(w, http.StatusBadRequest, "missing rule id", nil)
		return
	}
	b, ok := s.state.RemoveBlockByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if b.Enforced {
		if err := s.core.Delete(b.Target); err != nil {
			s.state.RestoreBlock(b)
			apiError(w, http.StatusServiceUnavailable, "kernel core rejected rule removal", err)
			return
		}
	}
	if err := persistPolicy(s.policy, s.cfg, s.state); err != nil {
		s.state.RestoreBlock(b)
		if b.Enforced {
			if rollbackErr := s.core.Add(b.Target); rollbackErr != nil {
				s.state.AddEvent(Event{Severity: "critical", Kind: "policy.rollback_failed", Source: "policy", Message: "Kernel rollback failed after signed policy persistence error", Target: b.Target})
				failSafeErr := s.release.FailSafe("block deletion policy rollback failed")
				apiError(w, http.StatusServiceUnavailable, "kernel transaction reconciliation failed", errors.Join(err, rollbackErr, failSafeErr))
				return
			}
		}
		apiError(w, http.StatusInternalServerError, "signed policy persistence failed", err)
		return
	}
	s.state.AddEvent(Event{Severity: "info", Kind: "block.removed", Source: "operator", Message: "Signed block rule removed", Target: b.Target})
	w.WriteHeader(http.StatusNoContent)
}

func (s *APIServer) syncFeeds(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil || !s.settings.Get().FeedsEnabled {
		apiError(w, http.StatusConflict, "threat intelligence is disabled (100% Opt-In)", nil)
		return
	}
	if s.feeds == nil {
		apiError(w, http.StatusServiceUnavailable, "threat intelligence manager unavailable", nil)
		return
	}
	allowlist := s.settings.Get().ManagementAllowlist
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	s.state.AddEvent(Event{Severity: "info", Kind: "feeds.sync_started", Source: "intelligence", Message: "Threat intelligence synchronization started: fetching and validating configured sources"})
	items, errs, err := s.feeds.SyncWithLock(ctx, "operator")
	if err != nil {
		var lockErr *ThreatIntelLockException
		severity := "error"
		if errors.As(err, &lockErr) {
			severity = "warning"
			s.state.AddEvent(Event{Severity: severity, Kind: "feeds.sync_failed", Source: "intelligence", Message: err.Error()})
			apiFault(w, http.StatusConflict, err)
			return
		}
		s.state.AddEvent(Event{Severity: severity, Kind: "feeds.sync_failed", Source: "intelligence", Message: "Threat intelligence source synchronization failed"})
		apiError(w, http.StatusInternalServerError, "feed synchronization failed", err)
		return
	}

	downloadSeverity := "info"
	downloadKind := "feeds.sources_validated"
	downloadMessage := fmt.Sprintf("Threat intelligence sources validated: %d active block vectors composed", len(items))
	if len(errs) > 0 {
		downloadSeverity = "warning"
		downloadKind = "feeds.sources_partial"
		downloadMessage = fmt.Sprintf("Threat intelligence source fetch completed partially: %d source errors; last-known-good data preserved", len(errs))
	}
	s.state.AddEvent(Event{Severity: downloadSeverity, Kind: downloadKind, Source: "intelligence", Message: downloadMessage})

	// Automatic kernel publication is administrable. With it disabled the
	// validated generation stays in userspace until the operator applies it
	// explicitly, so a sync alone can never change kernel policy.
	policy := effectiveThreatIntelSettings(s.settings.Get())
	added, deleted := 0, 0
	if policy.Kernel.AutoApply {
		s.state.AddEvent(Event{Severity: "info", Kind: "feeds.kernel_applying", Source: "intelligence", Message: "Applying validated BLOCK feed generation to kernel policy"})
		var applyErr error
		added, deleted, applyErr = s.feeds.ApplyToKernel(s.core, allowlist)
		if applyErr != nil {
			s.state.AddEvent(Event{Severity: "error", Kind: "feeds.kernel_apply_failed", Source: "intelligence", Message: "Threat intelligence kernel synchronization failed"})
			apiError(w, http.StatusInternalServerError, "kernel synchronization failed", applyErr)
			return
		}
	} else {
		s.state.AddEvent(Event{Severity: "info", Kind: "feeds.kernel_pending", Source: "intelligence", Message: "Validated generation held in userspace: automatic kernel publication is disabled, apply explicitly to enforce it"})
	}

	blockCount := s.feeds.BlockIndex().Count()
	correlateCount := s.feeds.CorrelateIndex().Count()
	annotateCount := s.feeds.AnnotateIndex().Count()
	gen := s.feeds.Generation()
	fingerprint := s.feeds.Fingerprint()
	status := s.feeds.OverallStatus()
	lastAttempt := s.feeds.LastAttemptAt()
	lastSuccess := s.feeds.LastSuccessfulSyncAt()
	lastFullSuccess := s.feeds.LastFullySuccessfulSyncAt()

	s.state.SetFeedState(blockCount, correlateCount, annotateCount, gen, fingerprint, status, lastAttempt, lastSuccess, lastFullSuccess)
	severity := "info"
	message := fmt.Sprintf("Threat intelligence synchronized [gen=%d fp=%.12s]: %d vectors (block=%d, correlate=%d, annotate=%d, kernel: +%d/-%d)",
		gen, fingerprint, len(items), blockCount, correlateCount, annotateCount, added, deleted)
	if len(errs) > 0 {
		severity = "warning"
		message += fmt.Sprintf("; %d source errors", len(errs))
	}
	s.state.AddEvent(Event{Severity: severity, Kind: "feeds.synced", Source: "intelligence", Message: message})
	telemetry := s.feeds.Telemetry()
	writeJSON(w, http.StatusOK, map[string]any{
		"vectors":                         len(items),
		"generation":                      gen,
		"fingerprint":                     fingerprint,
		"overall_status":                  telemetry.OverallStatus,
		"last_attempt_at":                 telemetry.LastAttemptAt,
		"last_successful_sync_at":         telemetry.LastSuccessfulSyncAt,
		"last_partial_successful_sync_at": telemetry.LastPartialSuccessfulSyncAt,
		"last_fully_successful_sync_at":   telemetry.LastFullySuccessfulSyncAt,
		"block_vectors":                   blockCount,
		"correlate_vectors":               correlateCount,
		"annotate_vectors":                annotateCount,
		"source_errors":                   len(errs),
		"kernel_added":                    added,
		"kernel_deleted":                  deleted,
		"kernel_apply_status":             telemetry.KernelApplyStatus,
		"kernel_generation":               telemetry.KernelGeneration,
		"feeds":                           telemetry.Feeds,
		"auto_apply":                      policy.Kernel.AutoApply,
		"lock":                            threatIntelLockKey,
		"note":                            "Threat intelligence active at kernel speed (XDP + cgroup_skb egress).",
	})
}

// applyFeeds publishes the currently validated userspace generation to the
// kernel. It is the explicit counterpart to automatic publication and is the
// only way to enforce a generation while "apply to kernel automatically" is
// switched off.
func (s *APIServer) applyFeeds(w http.ResponseWriter, r *http.Request) {
	if s.feeds == nil {
		apiError(w, http.StatusServiceUnavailable, "threat intelligence manager unavailable", nil)
		return
	}
	var allowlist []string
	if s.settings != nil {
		allowlist = s.settings.Get().ManagementAllowlist
	}
	added, deleted, err := s.feeds.ApplyToKernel(s.core, allowlist)
	if err != nil {
		s.state.AddEvent(Event{Severity: "error", Kind: "feeds.kernel_apply_failed", Source: "intelligence", Message: "Explicit threat intelligence kernel publication failed"})
		apiError(w, http.StatusInternalServerError, "kernel synchronization failed", err)
		return
	}
	telemetry := s.feeds.Telemetry()
	s.state.SetFeedState(
		s.feeds.BlockIndex().Count(), s.feeds.CorrelateIndex().Count(), s.feeds.AnnotateIndex().Count(),
		telemetry.Generation, telemetry.Fingerprint, telemetry.OverallStatus,
		telemetry.LastAttemptAt, telemetry.LastSuccessfulSyncAt, telemetry.LastFullySuccessfulSyncAt,
	)
	s.state.AddEvent(Event{Severity: "info", Kind: "feeds.kernel_applied", Source: "intelligence",
		Message: fmt.Sprintf("Operator published threat intelligence generation %d to the kernel: +%d/-%d", telemetry.Generation, added, deleted)})
	writeJSON(w, http.StatusOK, map[string]any{
		"kernel_added":        added,
		"kernel_deleted":      deleted,
		"kernel_apply_status": telemetry.KernelApplyStatus,
		"kernel_generation":   telemetry.KernelGeneration,
		"generation":          telemetry.Generation,
		"fingerprint":         telemetry.Fingerprint,
	})
}

func (s *APIServer) getFeedStatus(w http.ResponseWriter, r *http.Request) {
	if s.feeds == nil {
		writeJSON(w, http.StatusOK, ThreatIntelTelemetry{OverallStatus: "DISABLED", KernelApplyStatus: "NOT_APPLIED"})
		return
	}
	writeJSON(w, http.StatusOK, s.feeds.Telemetry())
}

func (s *APIServer) ackIncident(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		apiError(w, http.StatusBadRequest, "missing incident id", nil)
		return
	}
	if !s.state.AcknowledgeIncident(id) {
		http.NotFound(w, r)
		return
	}
	s.state.AddEvent(Event{Severity: "info", Kind: "xdr.acknowledged", Source: "operator", Message: "XDR incident acknowledged", Target: id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *APIServer) policyStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": s.policy.Status(), "blocks": s.state.BlocksSnapshot()})
}

func (s *APIServer) behaviorProfiles(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 1 && value <= 500 {
			limit = value
		}
	}
	if s.xdr == nil || s.xdr.behavior == nil {
		writeJSON(w, http.StatusOK, map[string]any{"profiles": []any{}, "summary": BehaviorSummary{IntegrityOK: true}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": s.xdr.behavior.Snapshot(limit), "summary": s.xdr.behavior.Summary()})
}

func (s *APIServer) fimStatus(w http.ResponseWriter, _ *http.Request) {
	engine := s.state.FIM()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "file integrity monitoring unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, engine.Status())
}

func (s *APIServer) fimScan(w http.ResponseWriter, _ *http.Request) {
	engine := s.state.FIM()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "file integrity monitoring unavailable", nil)
		return
	}
	summary, err := engine.Scan()
	if err != nil {
		apiError(w, http.StatusConflict, "file integrity scan rejected", err)
		return
	}
	severity := "info"
	kind := "fim.verified"
	if summary.Tampered > 0 || summary.Missing > 0 || summary.New > 0 || summary.Errors > 0 {
		severity = "critical"
		kind = "fim.deviation"
	}
	s.state.AddEvent(Event{
		Severity: severity, Kind: kind, Source: "operator",
		Message: fmt.Sprintf(
			"Manual FIM scan: verified=%d tampered=%d missing=%d new=%d errors=%d",
			summary.Verified, summary.Tampered, summary.Missing, summary.New, summary.Errors,
		),
	})
	writeJSON(w, http.StatusOK, summary)
}

func (s *APIServer) fimBaseline(w http.ResponseWriter, _ *http.Request) {
	engine := s.state.FIM()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "file integrity monitoring unavailable", nil)
		return
	}
	status, err := engine.CreateBaseline()
	if err != nil {
		apiError(w, http.StatusConflict, "file integrity baseline rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "fim.baseline_created", Source: "operator",
		Message: fmt.Sprintf(
			"Encrypted FIM baseline generation %d committed for %d protected files",
			status.Generation, status.BaselineCount,
		),
	})
	writeJSON(w, http.StatusOK, status)
}

func (s *APIServer) packageIntegrityStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.packages.Status())
}

func (s *APIServer) packageIntegrityScan(w http.ResponseWriter, _ *http.Request) {
	err := s.packages.Start(func(status PackageIntegrityStatus) {
		severity := "info"
		kind := "package_integrity.verified"
		message := fmt.Sprintf("Pacman package integrity verified: packages=%d files=%d verified=%d", status.Packages, status.Files, status.Verified)
		if status.Modified > 0 || status.Missing > 0 || status.Errors > 0 {
			severity = "critical"
			kind = "package_integrity.deviation"
			message = fmt.Sprintf(
				"Pacman package integrity deviation: modified=%d missing=%d errors=%d",
				status.Modified, status.Missing, status.Errors,
			)
		}
		s.state.AddEvent(Event{Severity: severity, Kind: kind, Source: "package-integrity", Message: message})
	})
	if err != nil {
		apiError(w, http.StatusConflict, "package integrity scan rejected", err)
		return
	}
	writeJSON(w, http.StatusAccepted, s.packages.Status())
}

func (s *APIServer) malwareScan(w http.ResponseWriter, r *http.Request) {
	if s.core == nil {
		apiError(w, http.StatusServiceUnavailable, "malware scanner unavailable", nil)
		return
	}
	var request struct {
		Path string `json:"path"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid malware scan request", err)
		return
	}
	result, err := s.core.MalwareScan(request.Path)
	if err != nil {
		apiError(w, http.StatusConflict, "malware scan rejected", err)
		return
	}
	severity := "info"
	kind := "malware.clean"
	if result.State == "suspicious" {
		severity = "high"
		kind = "malware.suspicious"
	} else if result.State == "malicious" {
		severity = "critical"
		kind = "malware.detected"
	}
	s.state.AddEvent(Event{
		Severity: severity, Kind: kind, Source: "malware-scanner",
		Message: fmt.Sprintf("Content scan %s: type=%s reason=%s size=%d sha256=%s", result.State, result.Classification, result.Reason, result.Size, result.SHA256),
		Target:  request.Path,
	})
	if result.State != "clean" && s.xdr != nil {
		s.xdr.recordManualMalwareFinding(request.Path, result)
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *APIServer) transactionStatus(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			apiError(w, http.StatusBadRequest, "transaction limit is invalid", nil)
			return
		}
		limit = parsed
	}
	writeJSON(w, http.StatusOK, engine.Status(limit))
}

func (s *APIServer) quarantineStatus(w http.ResponseWriter, _ *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "quarantine unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, engine.QuarantineStatus())
}

func (s *APIServer) quarantinePreview(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "quarantine unavailable", nil)
		return
	}
	var request struct {
		Path   string `json:"path"`
		Reason string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid quarantine preview request", err)
		return
	}
	payload, err := json.Marshal(quarantineRequest{Path: request.Path})
	if err != nil {
		apiError(w, http.StatusInternalServerError, "quarantine preview unavailable", err)
		return
	}
	transaction, err := engine.Preview(
		quarantineTransactionType,
		"Quarantine file",
		request.Reason,
		payload,
	)
	if err != nil {
		apiError(w, http.StatusConflict, "quarantine preview rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "quarantine.previewed", Source: "operator",
		Message: "File quarantine preview committed with immutable identity",
		Target:  transaction.ID,
	})
	writeJSON(w, http.StatusCreated, transaction)
}

func (s *APIServer) caseStatus(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Cases()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "case engine unavailable", nil)
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > caseListMaxLimit {
			apiError(w, http.StatusBadRequest, "case limit is invalid", nil)
			return
		}
		limit = parsed
	}
	writeJSON(w, http.StatusOK, engine.Status(limit))
}

func (s *APIServer) caseSetStatus(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Cases()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "case engine unavailable", nil)
		return
	}
	id := r.PathValue("id")
	if !validCaseID(id) {
		apiError(w, http.StatusBadRequest, "case identifier is invalid", nil)
		return
	}
	var request struct {
		Status     string `json:"status"`
		Resolution string `json:"resolution"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid case status request", err)
		return
	}
	record, err := engine.SetStatus(id, request.Status, request.Resolution)
	if err != nil {
		apiError(w, http.StatusConflict, "case status mutation rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "case.status_changed", Source: "operator",
		Message: "Security case status changed with durable evidence",
		Target:  record.ID + " " + record.Status,
	})
	writeJSON(w, http.StatusOK, record)
}

func (s *APIServer) cellsStatus(w http.ResponseWriter, _ *http.Request) {
	adapter := s.state.Cells()
	if adapter == nil {
		apiError(w, http.StatusServiceUnavailable, "Gaia Cells adapter unavailable", nil)
		return
	}
	writeJSON(w, http.StatusOK, adapter.Status(true))
}

func (s *APIServer) cellsPreview(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	var request struct {
		UUID       string `json:"uuid"`
		Generation uint64 `json:"generation"`
		CgroupID   uint64 `json:"cgroup_id"`
		Action     string `json:"action"`
		Reason     string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid Gaia Cell preview request", err)
		return
	}
	payload, err := json.Marshal(cellIsolationRequest{
		UUID: request.UUID, Generation: request.Generation,
		CgroupID: request.CgroupID, Action: request.Action,
	})
	if err != nil {
		apiError(w, http.StatusInternalServerError, "Gaia Cell preview unavailable", err)
		return
	}
	transaction, err := engine.Preview(
		cellTransactionType,
		"Gaia Cell "+request.Action,
		request.Reason,
		payload,
	)
	if err != nil {
		apiError(w, http.StatusConflict, "Gaia Cell preview rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "cell.isolation_previewed", Source: "operator",
		Message: "Gaia Cell isolation preview bound to immutable cgroup identity",
		Target:  transaction.ID + " " + request.UUID,
	})
	writeJSON(w, http.StatusCreated, transaction)
}

func (s *APIServer) transactionPreview(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	var request struct {
		Type    string          `json:"type"`
		Summary string          `json:"summary"`
		Reason  string          `json:"reason"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := decodeStrictJSON(w, r, 32<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid transaction preview request", err)
		return
	}
	transaction, err := engine.Preview(
		request.Type, request.Summary, request.Reason, request.Payload,
	)
	if err != nil {
		apiError(w, http.StatusConflict, "transaction preview rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "info", Kind: "transaction.previewed", Source: "operator",
		Message: "Reversible security transaction preview committed",
		Target:  transaction.ID + " " + transaction.Type,
	})
	writeJSON(w, http.StatusCreated, transaction)
}

func (s *APIServer) transactionApply(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	id := r.PathValue("id")
	if !validTransactionID(id) {
		apiError(w, http.StatusBadRequest, "transaction identifier is invalid", nil)
		return
	}
	var request struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeStrictJSON(w, r, 4<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid transaction apply request", err)
		return
	}
	transaction, err := engine.Apply(id, request.Confirmation)
	if err != nil {
		apiError(w, http.StatusConflict, "transaction apply rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "high", Kind: "transaction.applied", Source: "operator",
		Message: "Security transaction applied and verified",
		Target:  transaction.ID + " " + transaction.Type,
	})
	writeJSON(w, http.StatusOK, transaction)
}

func (s *APIServer) transactionReverse(w http.ResponseWriter, r *http.Request) {
	engine := s.state.Transactions()
	if engine == nil {
		apiError(w, http.StatusServiceUnavailable, "transaction engine unavailable", nil)
		return
	}
	id := r.PathValue("id")
	if !validTransactionID(id) {
		apiError(w, http.StatusBadRequest, "transaction identifier is invalid", nil)
		return
	}
	var request struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeStrictJSON(w, r, 4<<10, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid transaction reverse request", err)
		return
	}
	transaction, err := engine.Reverse(id, request.Confirmation)
	if err != nil {
		apiError(w, http.StatusConflict, "transaction reverse rejected", err)
		return
	}
	s.state.AddEvent(Event{
		Severity: "critical", Kind: "transaction.reversed", Source: "operator",
		Message: "Security transaction reversed and verified",
		Target:  transaction.ID + " " + transaction.Type,
	})
	writeJSON(w, http.StatusOK, transaction)
}

// forensicsExport produces the signed forensic record.
//
// The administrable policy shapes the snapshot before it is signed, so the
// signature covers exactly the bytes the operator receives. Redaction therefore
// cannot be undone by a verifier, and an export that was redacted is
// distinguishable from one that was not because the redaction changed the signed
// content rather than a display layer.
func (s *APIServer) forensicsExport(w http.ResponseWriter, _ *http.Request) {
	settings := effectiveForensicsSettings(s.settings.Get()).Export
	snapshot, err := shapeForensicsSnapshot(s.state.Snapshot(), settings, s.policy.TrustedPublicKey() != nil)
	if err != nil {
		apiError(w, http.StatusConflict, "forensics export rejected by policy", err)
		return
	}
	if !settings.SigningRequired {
		// The operator explicitly accepted an unauthenticated record. The response
		// says so in a header and in the body, so a consumer cannot mistake it for a
		// verified one.
		w.Header().Set("X-Gedefense-Signature", "none")
		w.Header().Set("Content-Disposition", `attachment; filename="gedefense-forensics.unsigned.json"`)
		writeJSON(w, http.StatusOK, map[string]any{"signed": false, "snapshot": snapshot})
		return
	}
	document, err := s.policy.SignForensics(snapshot)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "forensics export could not be signed", err)
		return
	}
	w.Header().Set("X-Gedefense-Signature", "ed25519")
	w.Header().Set("Content-Disposition", `attachment; filename="gedefense-forensics.signed.json"`)
	writeJSON(w, http.StatusOK, document)
}

func (s *APIServer) releaseStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.release.Status())
}

func (s *APIServer) releaseReadiness(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	readiness, err := s.release.Readiness(target)
	if err != nil {
		apiFault(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, readiness)
}

func (s *APIServer) l7Findings(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}
	snap := s.state.Snapshot()
	type L7FindingItem struct {
		ID         string            `json:"id"`
		Time       time.Time         `json:"time"`
		Severity   string            `json:"severity"`
		Score      int               `json:"score"`
		Confidence int               `json:"confidence"`
		RequestID  string            `json:"request_id"`
		Method     string            `json:"method"`
		Host       string            `json:"host"`
		Path       string            `json:"path"`
		RemoteIP   string            `json:"remote_ip"`
		RuleIDs    []string          `json:"rule_ids"`
		Categories []string          `json:"categories"`
		Summary    string            `json:"summary"`
		Decision   string            `json:"decision"`
		Action     string            `json:"action"`
		Outcome    string            `json:"outcome"`
		BodySHA256 string            `json:"body_sha256,omitempty"`
		Story      []AttackStoryNode `json:"attack_story,omitempty"`
	}
	items := make([]L7FindingItem, 0, limit)
	for i := len(snap.Incidents) - 1; i >= 0 && len(items) < limit; i-- {
		inc := snap.Incidents[i]
		if inc.RequestID != "" || inc.HTTPHost != "" || strings.HasPrefix(inc.Decision, "deny-http") {
			conf := 95
			if len(inc.AttackStory) > 0 && inc.AttackStory[0].Confidence > 0 {
				conf = inc.AttackStory[0].Confidence
			}
			items = append(items, L7FindingItem{
				ID:         inc.ID,
				Time:       inc.Time,
				Severity:   inc.Severity,
				Score:      inc.Score,
				Confidence: conf,
				RequestID:  inc.RequestID,
				Method:     inc.HTTPMethod,
				Host:       inc.HTTPHost,
				Path:       inc.HTTPPath,
				RemoteIP:   inc.Remote,
				RuleIDs:    inc.RuleIDs,
				Categories: inc.Categories,
				Summary:    inc.Summary,
				Decision:   inc.Decision,
				Action:     inc.Action,
				Outcome:    inc.Outcome,
				BodySHA256: inc.BodySHA256,
				Story:      inc.AttackStory,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": items,
		"total":    len(items),
		"status":   snap.L7,
	})
}

func (s *APIServer) releaseTransition(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target       string `json:"target"`
		Confirmation string `json:"confirmation"`
		Reason       string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid release transition request", err)
		return
	}
	status, err := s.release.Transition(in.Target, in.Confirmation, in.Reason)
	if err != nil {
		apiError(w, http.StatusConflict, "release gate rejected transition", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *APIServer) releaseEmergencyStop(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reason string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid emergency stop request", err)
		return
	}
	status, err := s.release.EmergencyStop(in.Reason)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "emergency stop failed", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *APIServer) releaseEmergencyStopClear(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Confirmation string `json:"confirmation"`
		Reason       string `json:"reason"`
	}
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid emergency-stop clear request", err)
		return
	}
	status, err := s.release.ClearEmergencyStop(in.Confirmation, in.Reason)
	if err != nil {
		apiError(w, http.StatusConflict, "emergency stop could not be cleared", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *APIServer) metrics(w http.ResponseWriter, r *http.Request) {
	if !s.metricsAllowed() {
		http.NotFound(w, r)
		return
	}
	if s.cfg.Dashboard.AllowRemote && !isLoopbackRemote(r.RemoteAddr) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	snap := s.state.Snapshot()
	core := 0
	if snap.CoreConnected {
		core = 1
	}
	xdrDegraded := 0
	if snap.XDR.Degraded {
		xdrDegraded = 1
	}
	policyVerified := 0
	if snap.Policy.Verified {
		policyVerified = 1
	}
	fmt.Fprintf(w, "# HELP gedefense_up Control plane health.\n# TYPE gedefense_up gauge\ngedefense_up 1\n")
	fmt.Fprintf(w, "# TYPE gedefense_core_connected gauge\ngedefense_core_connected %d\n", core)
	fmt.Fprintf(w, "# TYPE gedefense_policy_verified gauge\ngedefense_policy_verified %d\n", policyVerified)
	fmt.Fprintf(w, "# TYPE gedefense_policy_generation gauge\ngedefense_policy_generation %d\n", snap.Policy.Generation)
	fmt.Fprintf(w, "# TYPE gedefense_blocks_active gauge\ngedefense_blocks_active %d\n", len(snap.Blocks))
	fmt.Fprintf(w, "# TYPE gedefense_feed_vectors gauge\ngedefense_feed_vectors %d\n", snap.FeedVectors)
	fmt.Fprintf(w, "# TYPE gedefense_cpu_percent gauge\ngedefense_cpu_percent %.2f\n", snap.Telemetry.CPUPercent)
	fmt.Fprintf(w, "# TYPE gedefense_memory_percent gauge\ngedefense_memory_percent %.2f\n", snap.Telemetry.MemoryPercent)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_incidents_total counter\ngedefense_xdr_incidents_total %d\n", snap.XDR.IncidentsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_actions_total counter\ngedefense_xdr_actions_total %d\n", snap.XDR.ActionsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_degraded gauge\ngedefense_xdr_degraded %d\n", xdrDegraded)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_processes gauge\ngedefense_xdr_processes %d\n", snap.XDR.Processes)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_external_connections gauge\ngedefense_xdr_external_connections %d\n", snap.XDR.OpenConnections)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_evaluations_total counter\ngedefense_xdr_evaluations_total %d\n", snap.XDR.EvaluationsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_evaluation_drops_total counter\ngedefense_xdr_evaluation_drops_total %d\n", snap.XDR.EvaluationDrops)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_anomalies_total counter\ngedefense_xdr_anomalies_total %d\n", snap.XDR.AnomaliesTotal)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_queue_depth gauge\ngedefense_xdr_queue_depth %d\n", snap.XDR.QueueDepth)
	fmt.Fprintf(w, "# TYPE gedefense_xdr_behavior_profiles gauge\ngedefense_xdr_behavior_profiles %d\n", snap.XDR.Behavior.Profiles)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_hits_total counter\ngedefense_kinetic_hits_total %d\n", snap.Kinetic.HitsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_velocity_bursts_total counter\ngedefense_kinetic_velocity_bursts_total %d\n", snap.Kinetic.VelocityBurstsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_portscans_total counter\ngedefense_kinetic_portscans_total %d\n", snap.Kinetic.PortscansTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_subnet_strikes_total counter\ngedefense_kinetic_subnet_strikes_total %d\n", snap.Kinetic.SubnetStrikesTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_active_tracking_ips gauge\ngedefense_kinetic_active_tracking_ips %d\n", snap.Kinetic.ActiveTrackingIPs)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_tracking_drops_total counter\ngedefense_kinetic_tracking_drops_total %d\n", snap.Kinetic.TrackingDropsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_tracking_evictions_total counter\ngedefense_kinetic_tracking_evictions_total %d\n", snap.Kinetic.TrackingEvictionsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_aggregate_evictions_total counter\ngedefense_kinetic_aggregate_evictions_total %d\n", snap.Kinetic.AggregateEvictionsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_kernel_ring_drops_total counter\ngedefense_kinetic_kernel_ring_drops_total %d\n", snap.Kinetic.KernelRingDrops)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_kernel_track_insert_failures_total counter\ngedefense_kinetic_kernel_track_insert_failures_total %d\n", snap.Kinetic.KernelTrackInsertFailures)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_bans_enforced_total counter\ngedefense_kinetic_bans_enforced_total %d\n", snap.Kinetic.BansEnforcedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_bans_expired_total counter\ngedefense_kinetic_bans_expired_total %d\n", snap.Kinetic.BansExpiredTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_response_applied_total counter\ngedefense_kinetic_response_applied_total %d\n", snap.Kinetic.ResponseAppliedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_response_suppressed_total counter\ngedefense_kinetic_response_suppressed_total %d\n", snap.Kinetic.ResponseSuppressedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_kinetic_response_failed_total counter\ngedefense_kinetic_response_failed_total %d\n", snap.Kinetic.ResponseFailedTotal)
	l7Healthy := 0
	if snap.L7.Healthy {
		l7Healthy = 1
	}
	fmt.Fprintf(w, "# TYPE gedefense_l7_healthy gauge\ngedefense_l7_healthy %d\n", l7Healthy)
	fmt.Fprintf(w, "# TYPE gedefense_l7_requests_total counter\ngedefense_l7_requests_total %d\n", snap.L7.RequestsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_findings_total counter\ngedefense_l7_findings_total %d\n", snap.L7.FindingsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_blocked_total counter\ngedefense_l7_blocked_total %d\n", snap.L7.BlockedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_rate_limited_total counter\ngedefense_l7_rate_limited_total %d\n", snap.L7.RateLimitedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_rejected_total counter\ngedefense_l7_rejected_total %d\n", snap.L7.RejectedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_active_requests gauge\ngedefense_l7_active_requests %d\n", snap.L7.ActiveConnections)
	inlineHealthy := 0
	if snap.L7.InlineHealthy {
		inlineHealthy = 1
	}
	fmt.Fprintf(w, "# TYPE gedefense_l7_inline_healthy gauge\ngedefense_l7_inline_healthy %d\n", inlineHealthy)
	fmt.Fprintf(w, "# TYPE gedefense_l7_inline_requests_total counter\ngedefense_l7_inline_requests_total %d\n", snap.L7.InlineRequestsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_inline_blocked_total counter\ngedefense_l7_inline_blocked_total %d\n", snap.L7.InlineBlockedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_inline_upstream_errors_total counter\ngedefense_l7_inline_upstream_errors_total %d\n", snap.L7.InlineUpstreamErrorsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_responses_inspected_total counter\ngedefense_l7_responses_inspected_total %d\n", snap.L7.ResponsesInspectedTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_response_findings_total counter\ngedefense_l7_response_findings_total %d\n", snap.L7.ResponseFindingsTotal)
	fmt.Fprintf(w, "# TYPE gedefense_l7_response_inspection_errors_total counter\ngedefense_l7_response_inspection_errors_total %d\n", snap.L7.ResponseInspectionErrorsTotal)
	releaseReady := 0
	if snap.Release.Ready {
		releaseReady = 1
	}
	fmt.Fprintf(w, "# TYPE gedefense_release_ready gauge\ngedefense_release_ready %d\n", releaseReady)
	fmt.Fprintf(w, "# TYPE gedefense_release_core_misses gauge\ngedefense_release_core_misses %d\n", snap.Release.CoreMisses)
}

func (s *APIServer) platformCapabilities(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil {
		writeJSON(w, http.StatusOK, DetectPlatformCapabilities("/"))
		return
	}
	writeJSON(w, http.StatusOK, s.xdr.PlatformCaps())
}

func (s *APIServer) activeResponses(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Responses() == nil {
		writeJSON(w, http.StatusOK, []ResponseRecord{})
		return
	}
	writeJSON(w, http.StatusOK, s.xdr.Responses().ActiveResponses())
}

func (s *APIServer) deceptionTestAccess(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Deception() == nil {
		apiError(w, http.StatusServiceUnavailable, "deception engine offline", nil)
		return
	}
	var req struct {
		CanaryPath string `json:"canary_path"`
		PID        int    `json:"pid"`
		Comm       string `json:"comm"`
		RemoteIP   string `json:"remote_ip"`
	}
	if err := decodeStrictJSON(w, r, 64*1024, &req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}
	evt := DeceptionAccessEvent{
		CanaryPath:   req.CanaryPath,
		AccessorPID:  req.PID,
		AccessorUID:  1000,
		AccessorComm: req.Comm,
		RemoteIP:     req.RemoteIP,
		Timestamp:    time.Now().UTC(),
	}
	inc, resp, err := s.xdr.Deception().HandleCanaryAccess(r.Context(), evt)
	if err != nil {
		apiFault(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"incident": inc,
		"response": resp,
	})
}

func (s *APIServer) attackStories(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Correlator() == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	stories := s.xdr.Correlator().GetAllStories()
	type storySummary struct {
		ChainID      string            `json:"chain_id"`
		RootNodes    []string          `json:"root_nodes"`
		EvidenceRoot string            `json:"evidence_root"`
		NodeCount    int               `json:"node_count"`
		Nodes        []AttackStoryNode `json:"nodes"`
	}
	out := make([]storySummary, 0, len(stories))
	for _, g := range stories {
		out = append(out, storySummary{
			ChainID:      g.ChainID,
			RootNodes:    g.RootNodes,
			EvidenceRoot: g.EvidenceRoot(),
			NodeCount:    len(g.Nodes),
			Nodes:        g.CloneNodes(),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *APIServer) styxRules(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Styx() == nil {
		writeJSON(w, http.StatusOK, map[string]any{"rules": []EgressRule{}, "drops": 0, "metadata_hits": 0})
		return
	}
	drops, hits := s.xdr.Styx().Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"rules":         s.xdr.Styx().Rules(),
		"drops":         drops,
		"metadata_hits": hits,
	})
}

func (s *APIServer) addStyxRule(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Styx() == nil {
		apiError(w, http.StatusServiceUnavailable, "styx engine offline", nil)
		return
	}
	var rule EgressRule
	if err := decodeStrictJSON(w, r, 64*1024, &rule); err != nil {
		apiError(w, http.StatusBadRequest, "invalid rule payload", err)
		return
	}
	if err := s.xdr.Styx().AddRule(rule); err != nil {
		apiFault(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "rule": rule})
}

func (s *APIServer) airlockInspect(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Airlock() == nil {
		apiError(w, http.StatusServiceUnavailable, "airlock inspector offline", nil)
		return
	}
	var req struct {
		FilePath string `json:"file_path"`
	}
	if err := decodeStrictJSON(w, r, 64*1024, &req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid inspect request", err)
		return
	}
	res, err := s.xdr.Airlock().InspectFile(req.FilePath)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"clean": false, "error": err.Error(), "result": res})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clean": true, "result": res})
}

func (s *APIServer) chronosStatus(w http.ResponseWriter, r *http.Request) {
	if s.xdr == nil || s.xdr.Chronos() == nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "offline"})
		return
	}
	cp, err := s.xdr.Chronos().LoadCheckpoint()
	if err != nil || cp == nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "idle", "checkpoint": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": cp.Phase, "checkpoint": cp})
}

type kineticLiveBounds struct {
	SourceLimit                int    `json:"source_limit"`
	EventLimit                 int    `json:"event_limit"`
	EventCapacity              int    `json:"event_capacity"`
	EventDropsTotal            uint64 `json:"event_drops_total"`
	EventHistoryComplete       bool   `json:"event_history_complete"`
	SourceRetentionSeconds     int64  `json:"source_retention_seconds"`
	SourceHistoryComplete      bool   `json:"source_history_complete"`
	AggregationHistoryComplete bool   `json:"aggregation_history_complete"`
	AggregateEvictionsTotal    uint64 `json:"aggregate_evictions_total"`
	SourceBucketResolution     string `json:"source_bucket_resolution"`
	TopPortsBasis              string `json:"top_ports_basis"`
	TopRulesBasis              string `json:"top_rules_basis"`
	Bounded                    bool   `json:"bounded"`
}

type kineticLiveResponse struct {
	GeneratedAt   time.Time                 `json:"generated_at"`
	Window        string                    `json:"window"`
	WindowSeconds int64                     `json:"window_seconds"`
	StateFilter   string                    `json:"state_filter"`
	ActiveBlocks  int                       `json:"active_blocks"`
	Status        KineticTelemetry          `json:"status"`
	Traffic       KineticTrafficWindow      `json:"traffic"`
	Sources       []KineticSourceSnapshot   `json:"sources"`
	Events        []KineticEvent            `json:"events"`
	Decisions     []KineticEvent            `json:"decisions"`
	Subnets       []KineticSubnetAggregate  `json:"subnets"`
	TopRules      []KineticTopRule          `json:"top_rules"`
	TopPorts      []KineticTopPort          `json:"top_ports"`
	Countries     []kineticCountryAggregate `json:"countries"`
	Geo           GeoStatus                 `json:"geo"`
	Bounds        kineticLiveBounds         `json:"bounds"`
}

func kineticRequestLimit(r *http.Request, fallback int) (int, error) {
	limit := fallback
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 250 {
			return 0, errors.New("limit must be between 1 and 250")
		}
		limit = parsed
	}
	return limit, nil
}

func filterKineticSourcesByState(sources []KineticSourceSnapshot, stateFilter string) ([]KineticSourceSnapshot, bool) {
	stateFilter = strings.ToLower(strings.TrimSpace(stateFilter))
	if stateFilter == "" {
		stateFilter = "all"
	}
	if stateFilter != "all" && stateFilter != "suspicious" && stateFilter != "blocked" {
		return nil, false
	}
	if stateFilter == "all" {
		return sources, true
	}
	out := make([]KineticSourceSnapshot, 0, len(sources))
	for _, src := range sources {
		state := strings.ToUpper(src.State)
		switch stateFilter {
		case "blocked":
			if src.Blocked || state == "BLOCKED" {
				out = append(out, src)
			}
		case "suspicious":
			if src.Blocked || src.Score >= 40 || state == "SUSPICIOUS" || state == "SCAN" || state == "BURST" || state == "THREAT" || state == "BLOCKED" {
				out = append(out, src)
			}
		}
	}
	return out, true
}

func kineticSourceBucketResolution(spec KineticWindowSpec) string {
	if spec.Duration <= time.Minute {
		return "60s-calendar"
	}
	if spec.Duration <= time.Hour {
		return "5m"
	}
	return "1h"
}

func activeKineticBlockCount(state *State, now time.Time) int {
	if state == nil {
		return 0
	}
	count := 0
	for _, entry := range state.BlocksSnapshot() {
		if !entry.Enforced {
			continue
		}
		if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now) {
			continue
		}
		count++
	}
	return count
}

func (s *APIServer) getKineticLive(w http.ResponseWriter, r *http.Request) {
	spec, ok := parseKineticWindow(r.URL.Query().Get("window"))
	if !ok {
		apiError(w, http.StatusBadRequest, "invalid kinetic window", errors.New("supported windows: live, 1m, 5m, 15m, 1h, 24h"))
		return
	}
	limit, err := kineticRequestLimit(r, 100)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid source limit", err)
		return
	}
	stateFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))
	if stateFilter == "" {
		stateFilter = "all"
	}
	now := time.Now().UTC()
	if s.kinetic == nil {
		if _, valid := filterKineticSourcesByState(nil, stateFilter); !valid {
			apiError(w, http.StatusBadRequest, "invalid kinetic state filter", errors.New("supported filters: all, suspicious, blocked"))
			return
		}
		writeJSON(w, http.StatusOK, kineticLiveResponse{
			GeneratedAt: now, Window: spec.Name, WindowSeconds: int64(spec.Duration / time.Second), StateFilter: stateFilter, ActiveBlocks: activeKineticBlockCount(s.state, now),
			Status: DefaultKineticTelemetry(), Traffic: KineticTrafficWindow{Name: spec.Name, Seconds: int64(spec.Duration / time.Second), GeneratedAt: now},
			Sources: []KineticSourceSnapshot{}, Events: []KineticEvent{}, Decisions: []KineticEvent{}, Subnets: []KineticSubnetAggregate{},
			TopRules: []KineticTopRule{}, TopPorts: []KineticTopPort{}, Countries: []kineticCountryAggregate{}, Geo: s.geo.Status(),
			Bounds: kineticLiveBounds{SourceLimit: limit, EventLimit: limit, SourceRetentionSeconds: int64(kineticSourceRetention / time.Second),
				SourceBucketResolution: kineticSourceBucketResolution(spec), TopPortsBasis: "security_events", TopRulesBasis: "security_events", Bounded: true},
		})
		return
	}

	status := s.kinetic.SnapshotTelemetry()
	traffic := s.kinetic.TrafficWindow(spec, now)
	sources := s.kinetic.SourceSnapshotForWindow(limit, spec, now)
	s.enrichKineticSources(sources)
	filtered, valid := filterKineticSourcesByState(sources, stateFilter)
	if !valid {
		apiError(w, http.StatusBadRequest, "invalid kinetic state filter", errors.New("supported filters: all, suspicious, blocked"))
		return
	}
	events, drops, eventsComplete := s.kinetic.RecentEventsForWindow(spec, now, limit)
	countries := aggregateKineticCountries(filtered)
	sourceComplete := spec.Duration <= kineticSourceRetention && traffic.HistoryComplete && status.TrackingEvictionsTotal == 0
	writeJSON(w, http.StatusOK, kineticLiveResponse{
		GeneratedAt: now, Window: spec.Name, WindowSeconds: int64(spec.Duration / time.Second), StateFilter: stateFilter, ActiveBlocks: activeKineticBlockCount(s.state, now),
		Status: status, Traffic: traffic, Sources: filtered, Events: events, Decisions: kineticDecisions(events, minInt(limit, 50)),
		Subnets: aggregateKineticSubnets(filtered, 20), TopRules: aggregateKineticRules(events, 12), TopPorts: aggregateKineticPorts(events, 12),
		Countries: countries, Geo: s.geo.Status(),
		Bounds: kineticLiveBounds{
			SourceLimit: limit, EventLimit: limit, EventCapacity: s.kinetic.eventQueue.Capacity(), EventDropsTotal: drops,
			EventHistoryComplete: eventsComplete, SourceRetentionSeconds: int64(kineticSourceRetention / time.Second),
			SourceHistoryComplete: sourceComplete, AggregationHistoryComplete: status.AggregateEvictionsTotal == 0, AggregateEvictionsTotal: status.AggregateEvictionsTotal, SourceBucketResolution: kineticSourceBucketResolution(spec),
			TopPortsBasis: "security_events", TopRulesBasis: "security_events", Bounded: true,
		},
	})
}

func (s *APIServer) getKineticStatus(w http.ResponseWriter, r *http.Request) {
	if s.kinetic == nil {
		writeJSON(w, http.StatusOK, DefaultKineticTelemetry())
		return
	}
	writeJSON(w, http.StatusOK, s.kinetic.SnapshotTelemetry())
}

func (s *APIServer) getKineticEvents(w http.ResponseWriter, r *http.Request) {
	if s.kinetic == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []KineticEvent{}, "drops": uint64(0)})
		return
	}
	if rawWindow := strings.TrimSpace(r.URL.Query().Get("window")); rawWindow != "" {
		spec, ok := parseKineticWindow(rawWindow)
		if !ok {
			apiError(w, http.StatusBadRequest, "invalid kinetic window", errors.New("supported windows: live, 1m, 5m, 15m, 1h, 24h"))
			return
		}
		limit, err := kineticRequestLimit(r, 100)
		if err != nil {
			apiError(w, http.StatusBadRequest, "invalid event limit", err)
			return
		}
		events, drops, complete := s.kinetic.RecentEventsForWindow(spec, time.Now().UTC(), limit)
		writeJSON(w, http.StatusOK, map[string]any{"events": events, "drops": drops, "window": spec.Name, "history_complete": complete})
		return
	}
	events, drops := s.kinetic.RecentEvents()
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"drops":  drops,
	})
}

func (s *APIServer) getKineticSources(w http.ResponseWriter, r *http.Request) {
	if s.kinetic == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sources": []KineticSourceSnapshot{}})
		return
	}
	limit, err := kineticRequestLimit(r, 100)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid source limit", err)
		return
	}
	var sources []KineticSourceSnapshot
	windowName := ""
	if rawWindow := strings.TrimSpace(r.URL.Query().Get("window")); rawWindow != "" {
		spec, ok := parseKineticWindow(rawWindow)
		if !ok {
			apiError(w, http.StatusBadRequest, "invalid kinetic window", errors.New("supported windows: live, 1m, 5m, 15m, 1h, 24h"))
			return
		}
		windowName = spec.Name
		sources = s.kinetic.SourceSnapshotForWindow(limit, spec, time.Now().UTC())
	} else {
		sources = s.kinetic.SourceSnapshot(limit)
	}
	s.enrichKineticSources(sources)
	if stateFilter := strings.TrimSpace(r.URL.Query().Get("state")); stateFilter != "" {
		filtered, ok := filterKineticSourcesByState(sources, stateFilter)
		if !ok {
			apiError(w, http.StatusBadRequest, "invalid kinetic state filter", errors.New("supported filters: all, suspicious, blocked"))
			return
		}
		sources = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": sources, "geo": s.geo.Status(), "window": windowName})
}

type kineticCountryAggregate struct {
	Code    string  `json:"code"`
	Name    string  `json:"name"`
	Events  int     `json:"events"`
	Blocked int     `json:"blocked"`
	Hits    int     `json:"hits"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

func aggregateKineticCountries(sources []KineticSourceSnapshot) []kineticCountryAggregate {
	byCountry := make(map[string]*kineticCountryAggregate)
	for _, source := range sources {
		if source.CountryCode == "" || source.Latitude == nil || source.Longitude == nil {
			continue
		}
		agg := byCountry[source.CountryCode]
		if agg == nil {
			agg = &kineticCountryAggregate{Code: source.CountryCode, Name: source.Country}
			byCountry[source.CountryCode] = agg
		}
		agg.Events++
		n := float64(agg.Events)
		agg.Lat += (*source.Latitude - agg.Lat) / n
		agg.Lon += (*source.Longitude - agg.Lon) / n
		hits := source.WindowHits
		if hits <= 0 {
			hits = source.Hits
		}
		agg.Hits += hits
		if source.Blocked {
			agg.Blocked++
		}
	}
	countries := make([]kineticCountryAggregate, 0, len(byCountry))
	for _, agg := range byCountry {
		countries = append(countries, *agg)
	}
	sort.Slice(countries, func(i, j int) bool {
		if countries[i].Hits != countries[j].Hits {
			return countries[i].Hits > countries[j].Hits
		}
		return countries[i].Code < countries[j].Code
	})
	return countries
}

func (s *APIServer) getKineticMap(w http.ResponseWriter, r *http.Request) {
	if s.kinetic == nil {
		writeJSON(w, http.StatusOK, map[string]any{"countries": []kineticCountryAggregate{}, "sources": []KineticSourceSnapshot{}, "geo": s.geo.Status(), "origin": s.resolveKineticOrigin()})
		return
	}
	var sources []KineticSourceSnapshot
	windowName := ""
	if rawWindow := strings.TrimSpace(r.URL.Query().Get("window")); rawWindow != "" {
		spec, ok := parseKineticWindow(rawWindow)
		if !ok {
			apiError(w, http.StatusBadRequest, "invalid kinetic window", errors.New("supported windows: live, 1m, 5m, 15m, 1h, 24h"))
			return
		}
		windowName = spec.Name
		sources = s.kinetic.SourceSnapshotForWindow(250, spec, time.Now().UTC())
	} else {
		sources = s.kinetic.SourceSnapshot(250)
	}
	s.enrichKineticSources(sources)
	countries := aggregateKineticCountries(sources)
	// The host's own position travels with the map so the client can draw the origin
	// marker and the arcs. It is resolved from this host's addresses, never guessed,
	// and carries a reason when it could not be resolved.
	origin := s.resolveKineticOrigin()
	writeJSON(w, http.StatusOK, map[string]any{
		"countries": countries, "sources": sources, "geo": s.geo.Status(),
		"window": windowName, "origin": origin, "origin_note": describeOrigin(origin),
	})
}

func (s *APIServer) enrichKineticSources(sources []KineticSourceSnapshot) {
	if s.geo == nil {
		return
	}
	for i := range sources {
		geo, ok := s.geo.Lookup(net.ParseIP(sources[i].SourceIP))
		if !ok {
			continue
		}
		sources[i].CountryCode = geo.CountryCode
		sources[i].Country = geo.Country
		sources[i].ASN = geo.ASN
		sources[i].ASName = geo.ASName
		lat, lon := geo.Latitude, geo.Longitude
		sources[i].Latitude, sources[i].Longitude = &lat, &lon
	}
}

func (s *APIServer) reconcileKinetic(w http.ResponseWriter, r *http.Request) {
	// Policy TTL expiry has exactly one owner: the central transactional worker in
	// main.go. This endpoint only forces detector ageing, otherwise an operator
	// click could race the expiry worker and lose signed-policy evidence.
	now := time.Now().UTC()
	if s.kinetic != nil {
		s.kinetic.Sweep(now)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"reconciled": 0,
		"entries":    []BlockEntry{},
		"note":       "detector state swept; policy TTL expiry is owned by the central transactional worker",
	})
}
