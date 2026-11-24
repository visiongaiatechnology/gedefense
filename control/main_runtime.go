// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"
)

// The start phase of the control plane: background loops and the attach
// sequences that turn the constructed service graph into a serving node.
// The context cancels and stop channels are handed back through controlPlane
// so main() owns signal handling and ordered shutdown (refactoring wave 1b,
// structure-only).
func (cp *controlPlane) startRuntime() {
	cfg, state, core := cp.cfg, cp.state, cp.core
	policy, settings, release := cp.policy, cp.settings, cp.release
	kernelExposure, mitigationGuard := cp.kernelExposure, cp.mitigationGuard
	feeds, xdr, titanEngine := cp.feeds, cp.xdr, cp.titanEngine
	cellGuard, transactions, cells := cp.cellGuard, cp.transactions, cp.cells
	evidence, fim, cmsEngine := cp.evidence, cp.fim, cp.cmsEngine
	evidenceDir, iface, token := cp.evidenceDir, cp.iface, cp.token
	l7Engine, l7Service := cp.l7Engine, cp.l7Service

	xdrCtx, cancelXDR := context.WithCancel(context.Background())
	cp.cancelXDR = cancelXDR
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
	// POINT 5 / P5-T3: the Emergency Lockdown engine. It is constructed even while
	// the namespace is disabled (it then stays completely inert: no core command, no
	// ticker traffic, no event) and it owns the authenticated latch document. The
	// state is sealed with the same storage master key as the other state stores.
	lockdownStorage, lockdownStorageErr := NewStorageCipher(cfg.Runtime.StorageKeyFile, cfg.Node.Name)
	if lockdownStorageErr != nil {
		log.Fatalf("lockdown state encryption: %v", lockdownStorageErr)
	}
	lockdownEngine, lockdownErr := NewLockdownEngine(LockdownEngineConfig{
		Storage: lockdownStorage, Settings: settings, State: state, Core: core, CellGuard: cellGuard,
	})
	if lockdownErr != nil {
		log.Fatalf("lockdown engine: %v", lockdownErr)
	}
	// The boot-trust reconcile uses the same bounded collector as /api/v1/boot-trust,
	// so the operator never sees two verdicts for the same boot.
	lockdownEngine.AttachBootTrust(srv.bootTrustVerdict)
	srv.AttachLockdown(lockdownEngine)
	xdr.AttachLockdown(lockdownEngine)
	go lockdownEngine.Run(xdrCtx)
	// POINT 4 / P4-T2: the Out-of-Band Witness engine. It is constructed even while
	// the namespace is disabled (it then stays completely inert: no ticker, no
	// request, no checkpoint and no event) and it owns the authenticated outbox and
	// acknowledgement documents below <stateDir>/witness/. The ledger key stays in
	// the ledger; the engine only receives the signing callback it already hands
	// out through WitnessCheckpointSigner.
	witnessStorage, witnessStorageErr := NewStorageCipher(cfg.Runtime.StorageKeyFile, cfg.Node.Name)
	if witnessStorageErr != nil {
		log.Fatalf("witness state encryption: %v", witnessStorageErr)
	}
	witnessEngine, witnessErr := NewWitnessEngine(WitnessEngineConfig{
		NodeID: cfg.Node.Name, Ledger: evidence, Settings: settings, State: state,
		Storage:     witnessStorage,
		OutboxPath:  filepath.Join(evidenceDir, "witness", "outbox.enc"),
		AckPath:     filepath.Join(evidenceDir, "witness", "ack.enc"),
		BootTrust:   func() BootTrustReport { return srv.bootTrust.Collect() },
		SensorState: state.XDRSensorState,
		Lockdown:    lockdownEngine,
	})
	if witnessErr != nil {
		log.Fatalf("witness engine: %v", witnessErr)
	}
	srv.AttachWitness(witnessEngine)
	go witnessEngine.Run(xdrCtx)
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
	// GeDefense 6.1.0: attach the module A-D engines (web posture, worker guard,
	// TLS sensor, LPE guard). Each engine polls the persisted namespace on its own
	// tick, so a disabled module performs no kernel or host action at all.
	attachV61Engines(srv, settings, state, core, xdr, xdrCtx)
	// FIND-006: converge the optional edge listener once before serving, so an
	// operator-enabled edge starts at boot instead of waiting for the first
	// dashboard status poll. The edge is optional: a failure is logged and the
	// control plane keeps serving, never blocked by it.
	if edgeStatus, edgeSyncErr := srv.syncEdgeProxy(); edgeSyncErr != "" {
		log.Printf("edge proxy startup sync failed (state=%s): %s", edgeStatus.State, edgeSyncErr)
	}

	cp.srv = srv
	cp.stopTelemetry = stopTelemetry
	cp.stopWorkers = stopWorkers
}
