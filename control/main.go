// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const version = "5.0.0-beta.2"

func detectInterface(requested string) (string, error) {
	if requested != "" && requested != "auto" {
		if _, err := net.InterfaceByName(requested); err != nil {
			return "", err
		}
		return requested, nil
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var downCandidate string
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		if i.Flags&net.FlagUp != 0 {
			return i.Name, nil
		}
		if downCandidate == "" {
			// Prefer a real NIC even if link is not up yet (common on live boot
			// before NetworkManager finishes). The control plane can still serve
			// the local dashboard; the Rust core resolves the data plane itself.
			downCandidate = i.Name
		}
	}
	if downCandidate != "" {
		return downCandidate, nil
	}
	// Last resort: allow local HTTPS dashboard bring-up without a NIC.
	return "lo", nil
}

type policyPersistence interface {
	Persist(nodeName, enforcement, xdrMode string, blocks []BlockEntry) error
	Status() PolicyStatus
}

func persistPolicy(policy policyPersistence, cfg Config, state *State) error {
	if policy == nil {
		return nil
	}
	enforcement, xdrMode := state.Modes()
	if err := policy.Persist(cfg.Node.Name, enforcement, xdrMode, state.BlocksSnapshot()); err != nil {
		state.SetPolicyStatus(policy.Status())
		return err
	}
	state.SetPolicyStatus(policy.Status())
	return nil
}

func main() {
	configPath := flag.String("config", "./gedefense.toml", "configuration file")
	check := flag.Bool("check-config", false, "validate configuration and exit")
	preflight := flag.Bool("preflight", false, "run service-start preflight and exit")
	activationPreflight := flag.Bool("preflight-activation", false, "run strict beta activation preflight and exit")
	showVersion := flag.Bool("version", false, "print version")
	verifyForensics := flag.String("verify-forensics", "", "verify a signed forensics export")
	trustedPublicKey := flag.String("public-key", "", "trusted Ed25519 public key for offline verification")
	scanFile := flag.String("scan-file", "", "scan one absolute file through the privileged malware core")
	userScanFile := flag.String("user-scan-file", "", "scan one browser-quarantine file through the peer-bound malware socket")
	probeURL := flag.String("probe-ready", "", "wait for a loopback /readyz endpoint")
	probeLiveURL := flag.String("probe-live", "", "wait for a loopback /livez endpoint")
	probeTimeout := flag.Duration("probe-timeout", 30*time.Second, "maximum readiness probe duration")
	signReleaseDir := flag.String("sign-release-dir", "", "sign all production artifacts in a directory")
	releaseManifestOutput := flag.String("release-manifest-output", "", "output path for the signed release manifest")
	verifyReleaseManifest := flag.String("verify-release-manifest", "", "verify a signed release manifest")
	releaseArtifactDir := flag.String("release-artifact-dir", "", "artifact directory used during release manifest verification")
	releasePrivateKey := flag.String("release-private-key", "", "offline Ed25519 release private key")
	releasePublicKey := flag.String("release-public-key", "", "trusted Ed25519 release public key")
	initFeedSigning := flag.String("init-feed-signing", "", "generate the local feed-signing Ed25519 key pair in this directory and print the pinned public key")
	feedPublicKeyOut := flag.String("feed-public-key", "", "optional output path for the generated feed-signing public key")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *signReleaseDir != "" {
		if *releaseManifestOutput == "" || *releasePrivateKey == "" || *releasePublicKey == "" {
			log.Fatal("release signing requires --release-manifest-output, --release-private-key, and --release-public-key")
		}
		if err := SignReleaseDirectory(*signReleaseDir, *releasePrivateKey, *releasePublicKey, *releaseManifestOutput); err != nil {
			log.Fatalf("release signing: %v", err)
		}
		fmt.Println("release manifest signed")
		return
	}
	if *verifyReleaseManifest != "" {
		if *releasePublicKey == "" {
			log.Fatal("--release-public-key is required for release verification")
		}
		document, err := VerifyReleaseManifest(*verifyReleaseManifest, *releasePublicKey, *releaseArtifactDir)
		if err != nil {
			log.Fatalf("release verification: %v", err)
		}
		fmt.Printf("release manifest valid; signer=%s version=%s artifacts=%d\n", document.Signer, document.Envelope.Version, len(document.Envelope.Artifacts))
		return
	}
	if *feedPublicKeyOut != "" && *initFeedSigning == "" {
		log.Fatal("--feed-public-key requires --init-feed-signing")
	}
	if *initFeedSigning != "" {
		publicKey, err := InitFeedSigning(*initFeedSigning, *feedPublicKeyOut)
		if err != nil {
			log.Fatalf("feed signing init: %v", err)
		}
		fmt.Printf("feed signing key pair created in %s\n", *initFeedSigning)
		fmt.Printf("feeds.trusted_signing_keys = \"%s\"\n", feedSigningPublicKeyBase64(publicKey))
		fmt.Printf("key fingerprint: %s\n", feedSigningFingerprint(publicKey))
		return
	}
	if *probeURL != "" {
		if *probeTimeout < time.Second || *probeTimeout > 5*time.Minute {
			log.Fatal("--probe-timeout must be between 1s and 5m")
		}
		if err := probeReady(*probeURL, *probeTimeout); err != nil {
			log.Fatal(err)
		}
		fmt.Println("readiness probe passed")
		return
	}
	if *probeLiveURL != "" {
		if *probeTimeout < time.Second || *probeTimeout > 5*time.Minute {
			log.Fatal("--probe-timeout must be between 1s and 5m")
		}
		if err := probeLive(*probeLiveURL, *probeTimeout); err != nil {
			log.Fatal(err)
		}
		fmt.Println("liveness probe passed")
		return
	}
	if *verifyForensics != "" {
		if *trustedPublicKey == "" {
			log.Fatal("--public-key is required with --verify-forensics")
		}
		document, verifyErr := VerifyForensicsFile(*verifyForensics, *trustedPublicKey)
		if verifyErr != nil {
			log.Fatalf("forensics verification: %v", verifyErr)
		}
		fmt.Printf("forensics signature valid; signer=%s node=%s exported_at=%s incidents=%d\n", document.Signer, document.Envelope.NodeName, document.Envelope.ExportedAt.Format(time.RFC3339), len(document.Envelope.Incidents))
		return
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}
	if *userScanFile != "" {
		result, scanErr := UserMalwareScan("/run/gedefense-scan/scan.sock", *userScanFile, 30*time.Second)
		if scanErr != nil {
			log.Fatalf("user malware scan: %v", scanErr)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(true)
		if encodeErr := encoder.Encode(result); encodeErr != nil {
			log.Fatalf("malware result encoding: %v", encodeErr)
		}
		if result.State != "clean" {
			os.Exit(2)
		}
		return
	}
	if *scanFile != "" {
		if os.Geteuid() != 0 {
			log.Fatal("--scan-file requires administrative execution")
		}
		core, coreErr := NewCoreClient(cfg.Core.Socket, cfg.Core.AuthKeyFile, time.Duration(cfg.Core.RequestTimeoutMillis)*time.Millisecond)
		if coreErr != nil {
			log.Fatalf("core client: %v", coreErr)
		}
		result, scanErr := core.MalwareScan(*scanFile)
		if scanErr != nil {
			log.Fatalf("malware scan: %v", scanErr)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(true)
		if encodeErr := encoder.Encode(result); encodeErr != nil {
			log.Fatalf("malware result encoding: %v", encodeErr)
		}
		if result.State != "clean" {
			os.Exit(2)
		}
		return
	}
	iface, err := detectInterface(cfg.Node.Interface)
	if err != nil {
		log.Fatalf("interface: %v", err)
	}
	cfg.Node.Interface = iface
	if *check {
		fmt.Printf("configuration valid; interface=%s listen=%s enforcement=%s xdr=%s\n", iface, cfg.Dashboard.Listen, cfg.Defense.Enforcement, cfg.XDR.Mode)
		return
	}
	if *preflight || *activationPreflight {
		report := runPreflight(cfg, *configPath, *activationPreflight)
		if err := writePreflightJSON(report); err != nil {
			log.Fatalf("preflight output: %v", err)
		}
		if !report.Passed {
			os.Exit(1)
		}
		return
	}

	// A second control-plane process must not open the revision-bound stores on the same
	// state directory in parallel (G-STATE-08). The lock is held for the process lifetime.
	instanceLock, err := acquireInstanceLock(cfg.Policy.StateFile)
	if err != nil {
		log.Fatalf("control-plane instance lock: %v", err)
	}
	defer func() {
		if releaseErr := instanceLock.Release(); releaseErr != nil {
			log.Printf("control-plane instance lock release: %v", releaseErr)
		}
	}()
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
	if policyErr != nil {
		// Keep visibility but never enforce an unverified policy state.
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
	cmsEngine := NewCMSEngine(filepath.Join(evidenceDir, "cms-settings.json"), filepath.Join(filepath.Dir(cfg.Core.AuthKeyFile), "wp-bridge.key"))
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
	defer cancelCells()
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
	if policyErr != nil {
		state.AddEvent(Event{Severity: "critical", Kind: "policy.signature_failure", Source: "policy", Message: "Signed policy verification failed; kernel enforcement is retained in degraded mode instead of being released"})
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
		}
	}()
	// A mitigation recorded by the previous run is re-established before anything else claims the host.
	if err := mitigationGuard.Restore(); err != nil {
		log.Printf("kernel mitigation: restore after restart not possible: %v", err)
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
	} else if policyErr == nil && (policyEnvelope.Enforcement != "" || policyEnvelope.XDRMode != "") {
		state.AddEvent(Event{Severity: "info", Kind: "release.startup_observe", Source: "release-gate", Message: "Signed policy intent was loaded, but beta startup remains observe until runtime promotion gates pass"})
	}

	feeds := NewFeedManager(cfg.Feeds)
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
	xdr, err := NewXDREngine(cfg, state, core, feeds, policy, settings, *configPath)
	if err != nil {
		log.Fatalf("xdr initialization: %v", err)
	}
	xdr.SetReleaseController(release)
	// Project the persisted Host Security namespace onto the RASP, deception and
	// Airlock engines before anything can observe them, so a restart genuinely
	// activates the stored revision.
	if err := xdr.ApplyRuntimeSettings(settings.Get()); err != nil {
		log.Fatalf("host security settings: %v", err)
	}
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

	xdrCtx, cancelXDR := context.WithCancel(context.Background())
	defer cancelXDR()
	go xdr.Run(xdrCtx)
	go titanEngine.Run(xdrCtx)
	go runFIM(xdrCtx, state, fim, settings)
	go runEvidenceVerification(xdrCtx, state, settings)
	go cmsEngine.Run(xdrCtx)
	go runTransactionVerification(xdrCtx, state, transactions, 60*time.Second)

	state.AddEvent(Event{Severity: "info", Kind: "node.started", Source: "system", Message: "GeDefense Beta control plane started in gated observe phase on " + iface})
	stopTelemetry := make(chan struct{})
	go runTelemetry(state, iface, stopTelemetry)
	stopWorkers := make(chan struct{})
	go func() {
		ping := time.NewTicker(5 * time.Second)
		expire := time.NewTicker(2 * time.Second)
		defer ping.Stop()
		defer expire.Stop()
		for {
			select {
			case <-stopWorkers:
				return
			case <-ping.C:
				_ = cells.Status(true)
				mode, pingErr := core.Ping()
				online := pingErr == nil
				if !online {
					mode = "offline"
					state.SetAllowlistReady(false)
				} else if !state.Snapshot().AllowlistReady {
					if allowErr := syncCoreAllowlist(core, settings.Get().ManagementAllowlist); allowErr != nil {
						state.SetAllowlistReady(false)
						state.AddEvent(Event{Severity: "warning", Kind: "allowlist.resync_failed", Source: "kernel", Message: allowErr.Error()})
					} else {
						state.SetAllowlistReady(true)
						state.AddEvent(Event{Severity: "info", Kind: "allowlist.resynchronized", Source: "kernel", Message: "Management allowlist restored after core reconnect"})
					}
				}
				state.SetCore(online, mode)
				release.ObserveCore(online)
				release.Evaluate()
			case now := <-expire.C:
				_, _ = reconcileExpiredNetworkBlocks(now.UTC(), state, core, policy, cfg, release)
			}
		}
	}()

	go func() {
		// A restart reconciles the kernel against the signed policy and therefore
		// drops feed-generated entries. Republish the validated generation once
		// before the refresh timer can wait up to a full interval.
		go func() {
			select {
			case <-time.After(8 * time.Second):
			case <-stopWorkers:
				return
			}
			current := settings.Get()
			if !current.FeedsEnabled || feeds.Generation() == 0 {
				return
			}
			if !feeds.LiveSettings().Kernel.AutoApply {
				return
			}
			added, deleted, err := feeds.ApplyToKernel(core, current.ManagementAllowlist)
			if err != nil {
				log.Printf("threat intelligence kernel republication after restart failed: %v", err)
				return
			}
			if added > 0 || deleted > 0 {
				state.AddEvent(Event{Severity: "info", Kind: "feeds.kernel_reapplied", Source: "intelligence", Message: fmt.Sprintf("Threat intelligence republished after control-plane restart: +%d/-%d kernel entries", added, deleted)})
			}
		}()
		// vis_threat_intel_cron_sync: 12-hour synchronization loop with atomic transient lock (vis_threat_intel_sync_lock).
		// Invariant 7: Scheduling is based on persisted lastSuccessfulSyncAt, so daemon restarts cannot indefinitely postpone synchronization.
		// 100% Opt-In: Zero DNS/HTTP egress occurs unless explicitly activated in settings.
		wasEnabled := false
		firstRun := true
		for {
			// The refresh interval and the shortest per-feed override are read
			// from the published Fabric revision, so an operator change takes
			// effect on the next scheduling decision without a restart.
			live := feeds.LiveSettings()
			interval := time.Duration(live.RefreshMinutes) * time.Minute
			for _, feed := range live.Feeds {
				if !feed.Enabled || feed.RefreshMinutes <= 0 {
					continue
				}
				if override := time.Duration(feed.RefreshMinutes) * time.Minute; override < interval {
					interval = override
				}
			}
			if interval < time.Minute {
				interval = 12 * time.Hour
			}
			if firstRun {
				firstRun = false
				lastSync := feeds.LastSuccessfulSyncAt()
				if !lastSync.IsZero() {
					elapsed := time.Since(lastSync)
					if elapsed >= interval {
						interval = 5 * time.Second
					} else {
						interval = interval - elapsed
					}
				} else {
					interval = 10 * time.Second
				}
			}

			timer := time.NewTimer(interval)
			select {
			case <-stopWorkers:
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
			current := settings.Get()
			if !current.FeedsEnabled {
				if wasEnabled {
					if core != nil {
						cleared, _ := feeds.ClearFromKernel(core)
						if cleared > 0 {
							state.AddEvent(Event{Severity: "info", Kind: "feeds.cleared", Source: "intelligence", Message: fmt.Sprintf("Threat intelligence deactivated: removed %d rules from kernel", cleared)})
						}
					}
					state.SetFeedVectors(0, time.Now().UTC())
					wasEnabled = false
				}
				continue
			}
			wasEnabled = true
			if !current.AutoFeedSync {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			items, syncErrs, err := feeds.SyncWithLock(ctx, threatIntelCronKey)
			cancel()
			if err != nil {
				log.Printf("threat intelligence sync skipped: %v", err)
				continue
			}

			added, deleted := 0, 0
			if live.Kernel.AutoApply {
				added, deleted, _ = feeds.ApplyToKernel(core, current.ManagementAllowlist)
			}
			if feeds.KernelDivergent() && live.Kernel.DivergenceDegrades {
				state.AddEvent(Event{Severity: "critical", Kind: "feeds.kernel_divergent", Source: "intelligence",
					Message: "Threat intelligence kernel state diverged from the validated userspace generation; the release gate is forced into a safe phase"})
				if err := release.FailSafe("threat intelligence kernel divergence"); err != nil {
					log.Printf("threat intelligence divergence fail-safe: %v", err)
				}
			}

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
			severity := "info"
			message := fmt.Sprintf("vis_threat_intel_cron_sync completed (gen %d / fp %.8s...): %d block vectors (+%d/-%d kernel)",
				feeds.Generation(), feeds.Fingerprint(), len(items), added, deleted)
			if len(syncErrs) > 0 {
				severity = "warning"
				message += fmt.Sprintf("; %d source errors", len(syncErrs))
			}
			state.AddEvent(Event{Severity: severity, Kind: "feeds.auto_synced", Source: "intelligence", Message: message})
		}
	}()

	srv := NewAPIServer(cfg, state, core, feeds, policy, xdr, release, settings, token)
	srv.AttachKernelExposure(kernelExposure)
	srv.AttachMitigationGuard(mitigationGuard)
	srv.AttachCellGuard(cellGuard)
	if l7Engine != nil {
		srv.AttachL7(l7Engine)
	}
	if l7Service != nil {
		// The self-test and the integration generator need the socket topology, which
		// lives on the service rather than on the engine.
		srv.AttachL7Service(l7Service)
	}
	srv.AttachCMS(cmsEngine)
	srv.AttachFeeds(feeds)
	srv.AttachFIM(fim)
	if l7Service != nil && l7Engine != nil {
		l7Service.SetTLSFindingSink(func(clientIP string, summary TLSClientHelloSummary, findings []L7Finding, now time.Time) {
			generated := srv.kinetic.IngestTLSFindings(clientIP, summary, findings, now)
			srv.handleKineticDecisions(generated)
		})
	}
	errCh := make(chan error, 1)
	readyCh := make(chan struct{})
	go func() {
		log.Printf("GeDefense %s dashboard: %s (interface=%s gated_phase=observe)", version, cfg.Dashboard.Listen, iface)
		errCh <- srv.RunWithReady(readyCh)
	}()
	select {
	case <-readyCh:
		_ = sdNotify("READY=1\nSTATUS=GeDefense beta observe gate online")
	case e := <-errCh:
		log.Fatalf("server startup: %v", e)
	}
	watchdogCtx, cancelWatchdog := context.WithCancel(context.Background())
	defer cancelWatchdog()
	// The desktop indicator socket is not a protection component: if it cannot be served, the
	// platform keeps protecting and the journal names the reason. It is started after the API is
	// ready so the first telegram already describes a fully populated state.
	desktopCtx, cancelDesktop := context.WithCancel(context.Background())
	defer cancelDesktop()
	desktopStatus := NewDesktopStatusServer(cfg.Desktop, state)
	go func() {
		if desktopErr := desktopStatus.Start(desktopCtx); desktopErr != nil {
			log.Printf("desktop status socket unavailable: %v", desktopErr)
		}
	}()
	// The startup self-check. It verifies the modules that carry the protection, repairs the ones
	// with a canonical repair, and re-arms without the operator when the host is the one that was
	// qualified - so a restart no longer means five minutes of a paused automatic response and a
	// manual check.
	if cfg.Startup.Enabled {
		startupDeps := StartupDeps{
			Release: release, State: state, Core: core, Policy: policy, Settings: settings,
			XDR: xdr, Titan: titanEngine, Exposure: kernelExposure, Advisories: cfg.Advisories, Interface: iface,
		}
		// Assigned only when the service exists: a nil *L7Service stored in the interface field
		// would look present and only fail at the first probe.
		if l7Service != nil {
			startupDeps.L7 = l7Service
		}
		supervisor := &StartupSupervisor{
			modules:  newStartupModules(startupDeps),
			identity: newStartupIdentity(state, iface),
			reArm: func(reason string) (ReleaseStatus, error) {
				return release.ReArmVerified(reason)
			},
			status:       release.Status,
			now:          func() time.Time { return time.Now().UTC() },
			rounds:       cfg.Startup.Rounds,
			roundGap:     time.Duration(cfg.Startup.RoundGapSeconds) * time.Second,
			armInterval:  time.Duration(cfg.Startup.ArmIntervalSec) * time.Second,
			healAttempts: cfg.Startup.HealAttempts,
			qualifyPath:  cfg.Startup.QualificationFile,
		}
		go supervisor.Run(desktopCtx)
	}
	go startSystemdWatchdog(watchdogCtx, func() string {
		status := release.Status()
		return fmt.Sprintf("phase=%s ready=%t core_misses=%d", status.Phase, status.Ready, status.CoreMisses)
	})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Printf("received %s", s)
	case e := <-errCh:
		if !errors.Is(e, http.ErrServerClosed) {
			log.Fatalf("server: %v", e)
		}
	}
	_ = sdNotify("STOPPING=1\nSTATUS=GeDefense shutting down")
	cancelWatchdog()
	cancelXDR()
	close(stopWorkers)
	close(stopTelemetry)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if l7EdgeService != nil {
		if err := l7EdgeService.Shutdown(ctx); err != nil {
			log.Printf("l7 inline shutdown: %v", err)
		}
	}
	if l7Service != nil {
		if err := l7Service.Shutdown(ctx); err != nil {
			log.Printf("l7 shutdown: %v", err)
		}
	}
	_ = srv.Shutdown(ctx)
}
