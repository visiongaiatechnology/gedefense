// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"
)

// The construction and attachment phase of the control plane. main() keeps the
// CLI/bootstrap contract (flags, early exits, Chameleon seam); this file builds
// the long-lived service graph and records it in controlPlane for the runtime
// and shutdown phases (refactoring wave 1b, structure-only).
type controlPlane struct {
	cfg             Config
	iface           string
	token           string
	core            *CoreClient
	policy          *PolicyStore
	settings        *SettingsStore
	state           *State
	cells           *GaiaCellsAdapter
	evidenceDir     string
	cmsEngine       *CMSEngine
	evidence        *EvidenceLedger
	fim             *FIMEngine
	transactions    *TransactionEngine
	titanEngine     *TitanEngine
	cellGuard       *CellGuard
	cancelCells     context.CancelFunc
	cancelXDR       context.CancelFunc
	release         *ReleaseController
	kernelExposure  *kernelExposureCache
	mitigationGuard *MitigationGuard
	feeds           *FeedManager
	xdr             *XDREngine
	l7Engine        *L7Engine
	l7Service       *L7Service
	l7EdgeService   *L7EdgeService
	stopTelemetry   chan struct{}
	stopWorkers     chan struct{}
	srv             *APIServer
}

func wireControlPlane(cp *controlPlane, cfg Config, configPath string, chameleon *ChameleonProfile) {
	token, err := loadOrCreateToken(cfg.Dashboard.TokenFile)
	if err != nil {
		log.Fatalf("dashboard token: %v", err)
	}
	if err := adoptDashboardToken(cfg.Dashboard.TokenFile, cfg.Dashboard.TokenOwner); err != nil {
		log.Fatalf("dashboard token owner: %v", err)
	}
	core, err := NewCoreClient(cfg.Core.Socket, cfg.Core.AuthKeyFile, time.Duration(cfg.Core.RequestTimeoutMillis)*time.Millisecond)
	if err != nil {
		log.Fatalf("core client: %v", err)
	}
	policy, err := NewPolicyStore(cfg.Policy, cfg.Node.Name)
	if err != nil {
		log.Fatalf("policy store: %v", err)
	}
	policyEnvelope, policyErr := policy.Load()
	if policyErr != nil || !policy.Status().Verified {
		// Never enforce an unverified policy state. The static intent drops to observe for
		// visibility only; the release controller below keeps the kernel enforcement it can
		// confirm and quarantines the document itself without writing to it. Nothing here and
		// nothing in the quarantine path re-signs the unverified policy (FIND-013).
		cfg.Defense.Enforcement = "observe"
		cfg.XDR.Mode = "observe"
	}
	settings, err := NewSettingsStore(cfg.Runtime.SettingsFile, cfg.Runtime.KeyFile, cfg)
	if err != nil {
		log.Fatalf("runtime settings: %v", err)
	}
	// The persisted Fabric revision is the authority for every administrable
	// runtime parameter. The static configuration file only seeds the first
	// revision, exactly as documented in the control-plane plan (section 5).
	cfg.L7 = effectiveL7Settings(settings.Get(), cfg.L7).toConfig()
	cfg.Defense.DPIEnabled = cfg.L7.Enabled
	// The same rule applies to Threat Intelligence: the persisted Fabric
	// namespace is the authority for feed definitions and bounds.
	cfg.Feeds = effectiveThreatIntelSettings(settings.Get()).effectiveFeedConfig(cfg.Feeds)

	state := NewState(version, cfg)
	cells := NewGaiaCellsAdapter(cfg.Cells)
	if err := state.AttachCells(cells); err != nil {
		log.Fatalf("Gaia Cells adapter attachment: %v", err)
	}
	evidenceDir := filepath.Dir(cfg.Policy.StateFile)
	cmsEngine := NewCMSEngine(filepath.Join(evidenceDir, "cms-settings.json"), filepath.Join(evidenceDir, "wp-bridge.key"))
	evidenceBudget := int64(effectiveIntegritySettings(settings.Get()).Evidence.MaxBytes)
	if evidenceBudget <= 0 {
		evidenceBudget = 64 << 20
	}
	evidence, err := NewEvidenceLedger(
		filepath.Join(evidenceDir, "evidence.jsonl"),
		filepath.Join(evidenceDir, "evidence.ed25519"),
		cfg.Policy.StorageKeyFile,
		cfg.Node.Name,
		evidenceBudget,
	)
	if err != nil {
		log.Fatalf("evidence ledger: %v", err)
	}
	if err := state.AttachEvidenceLedger(evidence); err != nil {
		log.Fatalf("evidence ledger verification: %v", err)
	}
	// V6.3.0 AP-8: one evidence record for an opt-in Chameleon installation.
	// Only the non-secret mapping commitment is recorded (install id, salt
	// fingerprint hash, commitment hash); the full public=neutral mapping lives
	// in the privileged core's root-only admin audit file and can be re-derived
	// by the administrator from the signed install manifest.
	if mapping, ok := chameleon.AuditMapping(); ok {
		if recordErr := state.RecordEvidence(EvidenceRecord{
			Severity: "medium", Kind: "chameleon.profile.active", Source: "chameleon",
			Message: "Opt-in Chameleon Identity Mode is active: kernel program/map identifiers, core/scan sockets and daemon state paths are installation-specific; the real mapping is recoverable by the administrator from the signed install manifest",
			Target:  fmt.Sprintf("install_id=%s;salt_fingerprint=%s;mapping_sha256=%s", mapping.InstallID, mapping.SaltFingerprint, mapping.MappingHash),
		}); recordErr != nil {
			log.Printf("chameleon profile evidence: %v", recordErr)
		}
	}
	// A schema upgrade may raise an operator setting on the operator's behalf. That is
	// recorded here, once the ledger is attached and before anything enforces the new
	// value, so the change is attributable rather than merely persisted. A failure to
	// record is reported but does not stop the boot: refusing to start because the audit
	// trail is unavailable would take the platform down over the very condition the
	// operator needs it running to inspect.
	for _, migration := range settings.Get().Migrations {
		if err := state.RecordEvidence(EvidenceRecord{
			Severity: "high", Kind: "settings.migration.applied", Source: "control-plane",
			Message: "Runtime settings schema upgrade changed an operator value",
			Target:  migration,
		}); err != nil {
			log.Printf("settings migration evidence: %v", err)
		}
	}
	fimStorage, err := NewStorageCipher(cfg.Policy.StorageKeyFile, cfg.Node.Name)
	if err != nil {
		log.Fatalf("FIM storage: %v", err)
	}
	protectedPaths, addedSecurityRoots := securityProtectionRoots(cfg.XDR.ProtectedPaths, cfg.XDR.ProtectedSecurityRoots, securityProtectionRootLimit)
	if len(addedSecurityRoots) > 0 {
		log.Printf("FIM protects %d roots; %d added for attack visibility: %v", len(protectedPaths), len(addedSecurityRoots), addedSecurityRoots)
	}
	fim, err := NewFIMEngine(
		protectedPaths,
		filepath.Join(evidenceDir, "fim-baseline.enc"),
		fimStorage,
	)
	if err != nil {
		log.Fatalf("FIM initialization: %v", err)
	}
	if err := state.AttachFIM(fim); err != nil {
		log.Fatalf("FIM state attachment: %v", err)
	}
	cases, err := NewCaseEngine(
		filepath.Join(evidenceDir, "cases.enc"),
		fimStorage,
		state.RecordEvidence,
	)
	if err != nil {
		log.Fatalf("case engine initialization: %v", err)
	}
	if err := state.AttachCases(cases); err != nil {
		log.Fatalf("case engine state attachment: %v", err)
	}
	// The quarantine applier is constructed once and passed on, so the Fabric module
	// publishes its path policy to the same instance that enforces it.
	quarantine := NewQuarantineTransactionApplier(core)
	transactions, err := NewTransactionEngine(
		filepath.Join(evidenceDir, "transactions.enc"),
		fimStorage,
		state.RecordEvidence,
		NewSysctlTransactionApplier(core),
		quarantine,
		NewCellTransactionApplier(cells),
	)
	if err != nil {
		log.Fatalf("transaction engine initialization: %v", err)
	}
	if err := state.AttachTransactions(transactions); err != nil {
		log.Fatalf("transaction state attachment: %v", err)
	}
	// Titan observes the explicitly protected XDR paths by default. The FIM
	// engine may widen its own attack-visibility roots to directories the
	// unprivileged control user cannot read; inheriting those would make the
	// Titan sensor fail closed with a permission error instead of watching the
	// files the operator actually protected.
	titanRoots := append([]string(nil), cfg.Titan.Roots...)
	if len(titanRoots) == 0 {
		if len(cfg.XDR.ProtectedPaths) > 0 {
			titanRoots = append(titanRoots, cfg.XDR.ProtectedPaths...)
		} else {
			titanRoots = append(titanRoots, protectedPaths...)
		}
	}
	if len(titanRoots) > titanMaxRoots {
		// The FIM protection set can be wider than Titan's bounded watcher; the
		// overflow is dropped explicitly instead of failing the whole control
		// plane at startup. The effective root list is visible in Titan status.
		log.Printf("Titan observes the first %d of %d configured roots", titanMaxRoots, len(titanRoots))
		titanRoots = titanRoots[:titanMaxRoots]
	}
	cfg.Titan.Roots = titanRoots
	titanEngine, titanErr := NewTitanEngine(cfg.Titan, TitanDeps{
		Version: version, DataRoot: evidenceDir,
		FIM: fim, Packages: newTitanPackageVerifier(), Context: newTitanStateContext(state),
		Containment: newTitanTransactionContainment(transactions),
		Evidence:    state.RecordEvidence, Events: state.AddEvent,
	})
	if titanErr != nil {
		log.Fatalf("Titan initialization: %v", titanErr)
	}
	if err := state.AttachTitan(titanEngine); err != nil {
		log.Fatalf("Titan state attachment: %v", err)
	}
	// Automatic cell isolation runs off the same transaction engine and the same cells adapter the
	// dashboard uses, so an isolation it performs is exactly as auditable and reversible as a manual one.
	cellCtx, cancelCells := context.WithCancel(context.Background())
	cellGuard := NewCellGuard(state, cfg.Cells)
	go cellGuard.Run(cellCtx)
	transactionReconcileErr := transactions.ReconcileApplied()
	if fim.Status().Health == "QUARANTINED" {
		state.AddEvent(Event{
			Severity: "critical", Kind: "fim.baseline_quarantined", Source: "integrity",
			Message: "Encrypted FIM baseline failed authentication and was quarantined",
		})
	}
	if transactionStatus := transactions.Status(1); transactionReconcileErr != nil || !transactionStatus.Healthy {
		state.AddEvent(Event{
			Severity: "critical", Kind: "transaction.recovery_required", Source: "transaction-engine",
			Message: "Security transactions are fail-closed pending integrity recovery",
		})
	}
	if caseStatus := cases.Status(1); !caseStatus.Healthy {
		state.AddEvent(Event{
			Severity: "critical", Kind: "case.history_quarantined", Source: "case-engine",
			Message: "Encrypted case history failed authentication; automated response is degraded",
		})
	}
	state.SetSettings(settings.Get())
	state.SetPolicyStatus(policy.Status())
	if policyErr != nil || !policy.Status().Verified {
		// The release controller below quarantines the document without ever re-signing it.
		// This event is the first operator instruction: it names the degradation and the only
		// explicit recovery path, so a tampered state file is never silently "repaired".
		state.AddEvent(Event{
			Severity: "critical", Kind: "policy.signature_failure", Source: "policy",
			Message: "Signed policy could not be verified; the document on disk is preserved unmodified and quarantined in memory (no automatic re-signing), kernel enforcement is retained and automatic decisions stay paused. " +
				"Operator recovery is explicit: verify host integrity, inspect the preserved document and its forensic copy, restore a trusted signed policy backup, then re-establish the policy with the explicit RETURN:OBSERVE operator transition",
		})
		log.Printf("policy: verification failed; the document is preserved unmodified and quarantined without re-signing. Operator recovery required: verify host integrity, restore a trusted signed policy backup, then use the explicit RETURN:OBSERVE transition")
	}
	if policyErr == nil && policy.LastLoadRecovered() {
		state.AddEvent(Event{Severity: "high", Kind: "policy.recovered_last_known_good", Source: "policy", Message: "Current policy state was unverifiable; the signed last-known-good intent was recovered and re-persisted"})
		log.Printf("policy: current state was unverifiable; recovered the signed last-known-good intent")
	}

	coreOnline := false
	if mode, pingErr := core.Ping(); pingErr == nil {
		coreOnline = true
		state.SetCore(true, mode)
		if allowErr := syncCoreAllowlist(core, settings.Get().ManagementAllowlist); allowErr != nil {
			state.SetAllowlistReady(false)
			state.AddEvent(Event{Severity: "warning", Kind: "allowlist.unsynchronized", Source: "kernel", Message: allowErr.Error()})
		} else {
			state.SetAllowlistReady(true)
			state.AddEvent(Event{Severity: "info", Kind: "allowlist.synchronized", Source: "kernel", Message: fmt.Sprintf("Synchronized %d management CIDR entries", len(settings.Get().ManagementAllowlist))})
		}
		state.AddEvent(Event{Severity: "info", Kind: "core.online", Source: "kernel", Message: "Authenticated Rust XDP core connected: " + mode})
	} else {
		state.SetCore(false, "offline")
		state.SetAllowlistReady(false)
		state.AddEvent(Event{Severity: "warning", Kind: "core.offline", Source: "kernel", Message: "Rust XDP core is offline; dashboard remains in safe control-only mode"})
	}

	if policyErr == nil && len(policyEnvelope.Blocks) > 0 {
		// The blocks are imported here and applied by the release controller, which is the
		// single authority on what the kernel holds. Applying them here as well - gated on
		// the static configuration file instead of the signed policy - meant two places
		// decided the kernel state, and the second one emptied it again moments later.
		blocks := make([]BlockEntry, 0, len(policyEnvelope.Blocks))
		for _, block := range policyEnvelope.Blocks {
			block.Enforced = false
			blocks = append(blocks, block)
		}
		count := state.ImportBlocks(blocks, time.Now().UTC(), cfg.Defense.MaxBlockEntries)
		state.AddEvent(Event{Severity: "info", Kind: "policy.restored", Source: "policy", Message: fmt.Sprintf("Restored %d verified policy blocks (core online at startup: %t)", count, coreOnline)})
	}

	release := NewReleaseController(cfg, state, core, policy, settings)
	// Kernel advisories are measured once here and shared by the self-check, the release gate and the
	// dashboard. The measurement is cheap but it reads the host, so it is cached and re-taken on a
	// short interval rather than per request or per gate evaluation.
	kernelExposure := newKernelExposureCache(
		func() time.Time { return time.Now().UTC() },
		func() kernelExposureSource { return osExposureSource{root: string(filepath.Separator)} },
	)
	release.AttachKernelExposure(kernelExposure)
	// The network sensors cannot see a local kernel trust failure, so the exposure is announced on the
	// event stream once at startup: an operator who never opens the advisories panel still learns that
	// this host's kernel is affected and which door is open.
	if cfg.Advisories.Enabled {
		if exposure := kernelExposure.Current(); exposure.Verdict != kernelVerdictUnaffected {
			state.AddEvent(Event{
				Severity: "high", Kind: "kernel.advisory_exposure", Source: "advisories",
				Message: fmt.Sprintf("Kernel exposure %d of 100 (%s): %s", exposure.Score, exposure.Grade, exposure.Recommendation),
			})
		}
	}
	// The mitigation guard owns the only automatic kernel change the platform may make. It is created
	// here so the same exposure measurement, the same privileged core and the same event stream drive
	// it; the watch probes are the host's own services, not GeDefense's opinion of itself.
	mitigationGuard := NewMitigationGuard(core, kernelExposure, cfg.Advisories, state, DefaultMitigationProbes(
		func(ctx context.Context) error {
			_, err := core.Ping()
			return err
		}))
	// The persisted mitigation record is authenticated with an HMAC subkey derived from the
	// runtime settings key and validated against the compiled catalogue before it may cause
	// a privileged write (F-19 / G-STATE-05). A missing key makes a restore fail closed.
	if mitigationKey, keyErr := deriveMitigationStateKey(cfg.Runtime.KeyFile); keyErr != nil {
		log.Printf("kernel mitigation: state authentication key unavailable, restore will be refused: %v", keyErr)
	} else {
		mitigationGuard.AttachStateMACKey(mitigationKey)
	}
	// The start is a race with the privileged core. If the record is missing or the core was not ready,
	// the guard retries for a bounded time instead of leaving a real protection unasserted.
	go func() {
		for attempt := 0; attempt < 30; attempt++ {
			select {
			case <-time.After(10 * time.Second):
			}
			mitigationGuard.HealIfUnasserted()
			if err := mitigationGuard.AdoptAuxiliaryTargets("startup: managed auxiliary CVE control"); err != nil {
				log.Printf("kernel mitigation: auxiliary control adoption not complete: %v", err)
			}
		}
	}()
	// A mitigation recorded by the previous run is re-established before anything else claims the host.
	if err := mitigationGuard.Restore(); err != nil {
		log.Printf("kernel mitigation: restore after restart not possible: %v", err)
	}
	if err := mitigationGuard.AdoptAuxiliaryTargets("startup: managed auxiliary CVE control"); err != nil {
		log.Printf("kernel mitigation: auxiliary control adoption not possible yet: %v", err)
	}
	if cfg.Advisories.AutoMitigate {
		go func() {
			// The core IPC and the first exposure measurement need a moment after start; retry instead
			// of giving up on the first attempt, and never retry after a refusal that is about policy.
			for attempt := 0; attempt < 6; attempt++ {
				select {
				case <-time.After(20 * time.Second):
				}
				if _, err := mitigationGuard.ApplyAutomatic("startup: automatic mitigation for a reachable advisory entry point"); err != nil {
					log.Printf("kernel mitigation: attempt %d not applied: %v", attempt+1, err)
					continue
				}
				return
			}
		}()
	}
	// The verified signed policy decides what the kernel holds at startup. A platform that
	// verified enforcement before the restart keeps it; only an absent or non-enforcing
	// intent starts from a verified-empty kernel.
	startupEnforcement := ""
	if policyErr == nil {
		startupEnforcement = policyEnvelope.Enforcement
	}
	if err := release.InitializeStartup(startupEnforcement, policyErr == nil && policy.Status().Verified); err != nil {
		state.AddEvent(Event{
			Severity: "critical", Kind: "release.startup_unverified", Source: "release-gate",
			Message: "Startup remained fail-safe degraded: " + err.Error(),
		})
	}
	if policyErr == nil && policyEnvelope.Enforcement == "enforce" {
		state.AddEvent(Event{Severity: "info", Kind: "release.startup_retained", Source: "release-gate", Message: "Signed policy states enforcement; the kernel state was retained and verified instead of being emptied"})
		if policy.Status().Verified {
			if updatedSettings, activated, armErr := settings.ApplySafeV6DefaultsOnEnforce(); armErr != nil {
				log.Printf("v6 startup auto-arm settings update failed: %v", armErr)
			} else if activated {
				state.SetSettings(updatedSettings)
				state.AddEvent(Event{
					Severity: "info", Kind: "v6.auto_armed", Source: "release-gate",
					Message: "GeDefense V6 safe defaults activated on startup enforce (styx=monitor, titan_exec=contain, parser_cells=enabled; lockdown and witness remain opt-in)",
				})
			}
		}
	} else if policyErr == nil && (policyEnvelope.Enforcement != "" || policyEnvelope.XDRMode != "") {
		state.AddEvent(Event{Severity: "info", Kind: "release.startup_observe", Source: "release-gate", Message: "Signed policy intent was loaded, but beta startup remains observe until runtime promotion gates pass"})
	}

	feeds := NewFeedManager(cfg.Feeds)
	// AP-9/S09: every TUF anti-poisoning rejection becomes a bounded,
	// high-severity state event (stable reason code only; no URLs, keys or
	// signatures). The previous Last-Known-Good generation stays active.
	feeds.SetTUFEventSink(state.AddEvent)
	if err := feeds.applyThreatIntelSettings(effectiveThreatIntelSettings(settings.Get()), settings.Get().Revision); err != nil {
		log.Fatalf("threat intelligence settings: %v", err)
	}
	// The bootstrap feeds.auto_apply flag is authoritative for the local signing
	// pipeline. A persisted runtime document that predates this namespace carries
	// kernel_apply.auto_apply=false, which would silently ignore the operator's
	// explicit opt-in. The bootstrap flag has already been validated to require
	// the signed-manifest gate and a pinned key, so it seeds the running
	// namespace; the dashboard can still change it at runtime afterwards.
	if cfg.Feeds.AutoApply {
		fabric := feeds.LiveSettings()
		if !fabric.Kernel.AutoApply {
			fabric.Kernel.AutoApply = true
			if err := feeds.applyThreatIntelSettings(fabric, settings.Get().Revision); err != nil {
				log.Fatalf("threat intelligence auto-apply bootstrap: %v", err)
			}
		}
	}
	if cfg.Feeds.LocalSigning {
		log.Printf("feed signing: local operator pipeline enabled (key=%s snapshots=%s manifest=%s)",
			cfg.Feeds.SigningKeyFile, cfg.Feeds.SnapshotDir, cfg.Feeds.ManifestPath)
	}
	// Any kernel reconciliation (startup retention, promotion ladder, recovery)
	// rewrites the blocklist from the signed policy. Republish the validated feed
	// generation immediately afterwards; feeds are not part of the signed policy
	// and would otherwise stay absent until the next scheduled sync.
	release.SetKernelReconciledHook(func() {
		current := settings.Get()
		live := feeds.LiveSettings()
		if !current.FeedsEnabled || !live.Kernel.AutoApply || feeds.Generation() == 0 {
			return
		}
		added, deleted, err := feeds.ApplyToKernel(core, current.ManagementAllowlist)
		if err != nil {
			log.Printf("feed kernel republication after reconciliation failed: %v", err)
			state.AddEvent(Event{Severity: "warning", Kind: "feeds.kernel_reapply_failed", Source: "intelligence", Message: "Threat intelligence kernel republication after a release reconciliation failed: " + err.Error()})
			return
		}
		if added > 0 || deleted > 0 {
			state.AddEvent(Event{Severity: "info", Kind: "feeds.kernel_reapplied", Source: "intelligence", Message: fmt.Sprintf("Threat intelligence republished after release reconciliation: +%d/-%d kernel entries", added, deleted)})
		}
	})
	state.SetFeedState(
		feeds.BlockIndex().Count(),
		feeds.CorrelateIndex().Count(),
		feeds.AnnotateIndex().Count(),
		feeds.Generation(),
		feeds.Fingerprint(),
		feeds.OverallStatus(),
		feeds.LastAttemptAt(),
		feeds.LastSuccessfulSyncAt(),
		feeds.LastFullySuccessfulSyncAt(),
	)
	xdr, err := NewXDREngine(cfg, state, core, feeds, policy, settings, configPath)
	if err != nil {
		log.Fatalf("xdr initialization: %v", err)
	}
	xdr.SetReleaseController(release)
	// POINT 2 / P2-T3: the ephemeral parser-cell manager. It is constructed even
	// when the namespace is disabled (it then stays completely inert); the
	// bootstrap section only carries socket/key/staging paths and deadlines. The
	// helper is never started from here - it is its own root unit.
	parserCells := NewParserCellManager(cfg.ParserCells, state, settings, newParserCellKernel(core, settings), xdr.Airlock())
	if err := state.AttachParserCells(parserCells); err != nil {
		log.Fatalf("parser cell manager attachment: %v", err)
	}
	xdr.AttachParserCells(parserCells)
	// Project the persisted Host Security namespace onto the RASP, deception and
	// Airlock engines before anything can observe them, so a restart genuinely
	// activates the stored revision.
	if err := xdr.ApplyRuntimeSettings(settings.Get()); err != nil {
		log.Fatalf("host security settings: %v", err)
	}
	release.SetEnforceSettingsHook(func(updated RuntimeSettings) {
		if err := xdr.ApplyRuntimeSettings(updated); err != nil {
			log.Printf("v6 auto-arm runtime settings apply: %v", err)
		}
	})
	// The API server owns the boot evidence collector, so only the policy trust
	// store is projected here; the boot evidence namespace is applied where that
	// collector is constructed.
	if err := policy.ApplyPolicy(effectivePolicyTrustSettings(settings.Get())); err != nil {
		log.Fatalf("policy trust settings: %v", err)
	}
	// Forensics budgets and the quarantine path policy are projected at start, so
	// the first incident and the first quarantine decision already honour the
	// persisted revision instead of the compiled-in defaults.
	if err := applyForensicsPolicies(effectiveForensicsSettings(settings.Get()), cases, quarantine); err != nil {
		log.Fatalf("forensics settings: %v", err)
	}
	// The rate limiter is owned by the API server, so that part of the System
	// namespace is applied where the server is constructed. The event cache and the
	// core deadline live here and are projected now.
	if err := applySystemPolicies(effectiveSystemSettings(settings.Get()), nil, state, core); err != nil {
		log.Fatalf("system settings: %v", err)
	}

	var l7Engine *L7Engine
	var l7Service *L7Service
	var l7EdgeService *L7EdgeService
	if cfg.L7.Enabled {
		var l7Err error
		l7Engine, l7Err = NewL7Engine(cfg.L7, xdr, release)
		l7Engine.AttachCMS(cmsEngine)
		if l7Err != nil {
			log.Fatalf("l7 engine initialization: %v", l7Err)
		}
		l7Service, l7Err = NewL7Service(cfg.L7, l7Engine, state)
		if l7Err != nil {
			log.Fatalf("l7 service initialization: %v", l7Err)
		}
		if l7Err = l7Service.Start(); l7Err != nil {
			log.Fatalf("l7 service startup: %v", l7Err)
		}
		state.AddEvent(Event{Severity: "info", Kind: "l7.online", Source: "l7", Message: "Bounded L7 inspection service online at " + cfg.L7.Socket})
		go func() {
			for serviceErr := range l7Service.Errors() {
				state.AddEvent(Event{Severity: "critical", Kind: "l7.offline", Source: "l7", Message: "L7 inspection service terminated unexpectedly"})
				log.Printf("l7 service: %v", serviceErr)
				release.Evaluate()
			}
		}()
		if cfg.L7.InlineEnabled {
			l7EdgeService, l7Err = NewL7EdgeService(cfg.L7, l7Engine, state)
			if l7Err != nil {
				log.Fatalf("l7 inline initialization: %v", l7Err)
			}
			if l7Err = l7EdgeService.Start(); l7Err != nil {
				log.Fatalf("l7 inline startup: %v", l7Err)
			}
			state.AddEvent(Event{Severity: "info", Kind: "l7.inline.online", Source: "l7", Message: "Native inline L7 path online at " + cfg.L7.InlineSocket})
			go func() {
				for serviceErr := range l7EdgeService.Errors() {
					state.AddEvent(Event{Severity: "critical", Kind: "l7.inline.offline", Source: "l7", Message: "Inline L7 service terminated unexpectedly"})
					log.Printf("l7 inline service: %v", serviceErr)
					release.Evaluate()
				}
			}()
		}
	}

	cp.cfg = cfg
	cp.token = token
	cp.core = core
	cp.policy = policy
	cp.settings = settings
	cp.state = state
	cp.cells = cells
	cp.evidenceDir = evidenceDir
	cp.cmsEngine = cmsEngine
	cp.evidence = evidence
	cp.fim = fim
	cp.transactions = transactions
	cp.titanEngine = titanEngine
	cp.cellGuard = cellGuard
	cp.cancelCells = cancelCells
	cp.release = release
	cp.kernelExposure = kernelExposure
	cp.mitigationGuard = mitigationGuard
	cp.feeds = feeds
	cp.xdr = xdr
	cp.l7Engine = l7Engine
	cp.l7Service = l7Service
	cp.l7EdgeService = l7EdgeService
}
