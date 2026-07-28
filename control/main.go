package main

import (
	"context"
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

const version = "1.0.0-beta.5"

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
	for _, i := range ifs {
		if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
			return i.Name, nil
		}
	}
	return "", errors.New("no active non-loopback interface found")
}

func persistPolicy(policy *PolicyStore, cfg Config, state *State) error {
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
	probeURL := flag.String("probe-ready", "", "wait for a loopback /readyz endpoint")
	probeLiveURL := flag.String("probe-live", "", "wait for a loopback /livez endpoint")
	probeTimeout := flag.Duration("probe-timeout", 30*time.Second, "maximum readiness probe duration")
	signReleaseDir := flag.String("sign-release-dir", "", "sign all production artifacts in a directory")
	releaseManifestOutput := flag.String("release-manifest-output", "", "output path for the signed release manifest")
	verifyReleaseManifest := flag.String("verify-release-manifest", "", "verify a signed release manifest")
	releaseArtifactDir := flag.String("release-artifact-dir", "", "artifact directory used during release manifest verification")
	releasePrivateKey := flag.String("release-private-key", "", "offline Ed25519 release private key")
	releasePublicKey := flag.String("release-public-key", "", "trusted Ed25519 release public key")
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

	token, err := loadOrCreateToken(cfg.Dashboard.TokenFile)
	if err != nil {
		log.Fatalf("dashboard token: %v", err)
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

	state := NewState(version, cfg)
	cells := NewGaiaCellsAdapter(cfg.Cells)
	if err := state.AttachCells(cells); err != nil {
		log.Fatalf("Gaia Cells adapter attachment: %v", err)
	}
	evidenceDir := filepath.Dir(cfg.Policy.StateFile)
	evidence, err := NewEvidenceLedger(
		filepath.Join(evidenceDir, "evidence.jsonl"),
		filepath.Join(evidenceDir, "evidence.ed25519"),
		cfg.Policy.StorageKeyFile,
		cfg.Node.Name,
		64<<20,
	)
	if err != nil {
		log.Fatalf("evidence ledger: %v", err)
	}
	if err := state.AttachEvidenceLedger(evidence); err != nil {
		log.Fatalf("evidence ledger verification: %v", err)
	}
	fimStorage, err := NewStorageCipher(cfg.Policy.StorageKeyFile, cfg.Node.Name)
	if err != nil {
		log.Fatalf("FIM storage: %v", err)
	}
	fim, err := NewFIMEngine(
		cfg.XDR.ProtectedPaths,
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
	transactions, err := NewTransactionEngine(
		filepath.Join(evidenceDir, "transactions.enc"),
		fimStorage,
		state.RecordEvidence,
		NewSysctlTransactionApplier(core),
		NewQuarantineTransactionApplier(core),
		NewCellTransactionApplier(cells),
	)
	if err != nil {
		log.Fatalf("transaction engine initialization: %v", err)
	}
	if err := state.AttachTransactions(transactions); err != nil {
		log.Fatalf("transaction state attachment: %v", err)
	}
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
		state.AddEvent(Event{Severity: "critical", Kind: "policy.signature_failure", Source: "policy", Message: "Signed policy verification failed; active enforcement forced to observe mode"})
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
		blocks := make([]BlockEntry, 0, len(policyEnvelope.Blocks))
		for _, block := range policyEnvelope.Blocks {
			block.Enforced = false
			if cfg.Defense.Enforcement == "enforce" && coreOnline {
				if err := core.Add(block.Target); err == nil {
					block.Enforced = true
				} else {
					state.AddEvent(Event{Severity: "warning", Kind: "policy.restore_failed", Source: "policy", Message: "Kernel rejected restored signed block", Target: block.Target})
				}
			}
			blocks = append(blocks, block)
		}
		count := state.ImportBlocks(blocks, time.Now().UTC(), cfg.Defense.MaxBlockEntries)
		state.AddEvent(Event{Severity: "info", Kind: "policy.restored", Source: "policy", Message: fmt.Sprintf("Restored %d verified policy blocks", count)})
	}

	release := NewReleaseController(cfg, state, core, policy, settings)
	if err := release.InitializeObserve(); err != nil {
		state.AddEvent(Event{
			Severity: "critical", Kind: "release.startup_unverified", Source: "release-gate",
			Message: "Startup remained fail-safe degraded: " + err.Error(),
		})
	}
	if policyErr == nil && (policyEnvelope.Enforcement != "" || policyEnvelope.XDRMode != "") {
		state.AddEvent(Event{Severity: "info", Kind: "release.startup_observe", Source: "release-gate", Message: "Signed policy intent was loaded, but beta startup remains observe until runtime promotion gates pass"})
	}

	feeds := NewFeedManager(cfg.Feeds)
	xdr, err := NewXDREngine(cfg, state, core, feeds, policy, settings, *configPath)
	if err != nil {
		log.Fatalf("xdr initialization: %v", err)
	}
	xdr.SetReleaseController(release)
	xdrCtx, cancelXDR := context.WithCancel(context.Background())
	defer cancelXDR()
	go xdr.Run(xdrCtx)
	go runFIM(
		xdrCtx,
		state,
		fim,
		time.Duration(cfg.XDR.IntegrityIntervalSeconds)*time.Second,
	)
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
				expired := state.Expired(now)
				removed := 0
				for _, b := range expired {
					if b.Enforced {
						if err := core.Delete(b.Target); err != nil {
							state.RestoreBlock(b)
							state.AddEvent(Event{Severity: "warning", Kind: "block.expiry_deferred", Source: "policy", Message: "Kernel core rejected expired rule removal; signed policy retained the rule", Target: b.Target})
							continue
						}
					}
					removed++
					state.AddEvent(Event{Severity: "info", Kind: "block.expired", Source: "policy", Message: "Temporary block expired", Target: b.Target})
				}
				if removed > 0 {
					if err := persistPolicy(policy, cfg, state); err != nil {
						for _, b := range expired {
							if _, exists := state.BlockByID(b.ID); exists {
								continue
							}
							state.RestoreBlock(b)
							if b.Enforced {
								if rollbackErr := core.Add(b.Target); rollbackErr != nil {
									failSafeErr := release.FailSafe("expired block policy rollback failed")
									state.AddEvent(Event{
										Severity: "critical", Kind: "policy.rollback_failed", Source: "policy",
										Message: errors.Join(rollbackErr, failSafeErr).Error(), Target: b.Target,
									})
								}
							}
						}
						state.AddEvent(Event{Severity: "critical", Kind: "policy.persist_failed", Source: "policy", Message: "Failed to persist signed policy after expiry; rules restored"})
					}
				}
			}
		}
	}()

	go func() {
		// Runtime-controlled, staged threat intelligence synchronization. Public
		// feeds are never inserted into XDP automatically; they only enrich XDR.
		for {
			interval := time.Duration(cfg.Feeds.RefreshMinutes) * time.Minute
			if interval < time.Minute {
				interval = time.Minute
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
			if !current.FeedsEnabled || !current.AutoFeedSync {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			items, syncErrs := feeds.Sync(ctx)
			cancel()
			state.SetFeedVectors(len(items), time.Now().UTC())
			severity := "info"
			message := fmt.Sprintf("Automatic threat-feed staging completed: %d unique prefixes", len(items))
			if len(syncErrs) > 0 {
				severity = "warning"
				message += fmt.Sprintf("; %d source errors", len(syncErrs))
			}
			state.AddEvent(Event{Severity: severity, Kind: "feeds.auto_synced", Source: "intelligence", Message: message})
		}
	}()

	srv := NewAPIServer(cfg, state, core, feeds, policy, xdr, release, settings, token)
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
	_ = srv.Shutdown(ctx)
}
