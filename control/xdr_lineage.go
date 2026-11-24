// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func (e *XDREngine) protectedPaths() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	paths := make([]string, 0, len(e.protected))
	for path := range e.protected {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func (e *XDREngine) Run(ctx context.Context) {
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	for i := 0; i < e.cfg.XDR.WorkerCount; i++ {
		e.workers.Add(1)
		go e.worker(workerCtx)
	}
	defer e.workers.Wait()

	// Kernel-observed deception canaries: fanotify events become incidents and
	// reversible responses without any manual API call.
	StartCanarySensor(ctx, e.core, e.deception, e.state)

	// The StyX policy syncer owns its own retry/epoch loop. Driving it from a
	// sensor tick would let a slow core delay event processing; it also has to work
	// when the XDR engine itself is disabled, because egress enforcement is a
	// kernel policy and not an XDR detection feature.
	if e.styxPolicy != nil {
		go e.styxPolicy.Run(ctx)
	}
	// POINT 1 / P1-T5: the Titan exec-gate syncer owns the same independent
	// retry/epoch loop; it also has to work when the XDR engine is disabled,
	// because the kernel exec policy is not an XDR detection feature.
	if e.titanExec != nil {
		go e.titanExec.Run(ctx)
	}
	// POINT 2 / P2-T3: the parser-cell manager owns the same independent supervisor
	// loop (helper health, TTL deadlines, ledger reconcile). It is inert while the
	// namespace is disabled, so this goroutine costs one ticker and no request.
	if e.parserCells != nil {
		go e.parserCells.Run(ctx)
	}

	runtime := e.runtimeSettings()
	scanTick := time.NewTicker(time.Duration(runtime.ScanIntervalMillis) * time.Millisecond)
	execTick := time.NewTicker(100 * time.Millisecond)
	netTick := time.NewTicker(time.Duration(runtime.NetworkIntervalSeconds) * time.Second)
	integrityTick := time.NewTicker(time.Duration(e.cfg.XDR.IntegrityIntervalSeconds) * time.Second)
	chronosInterval := time.Duration(e.cfg.XDR.IntegrityIntervalSeconds) * time.Second
	if chronosInterval < 30*time.Second {
		chronosInterval = 30 * time.Second
	}
	chronosTick := time.NewTicker(chronosInterval)
	logVerifyTick := time.NewTicker(30 * time.Second)
	cleanupTick := time.NewTicker(time.Minute)
	behaviorSaveTick := time.NewTicker(5 * time.Minute)
	statusTick := time.NewTicker(time.Second)
	rollbackTick := time.NewTicker(15 * time.Second)
	defer scanTick.Stop()
	defer execTick.Stop()
	defer netTick.Stop()
	defer integrityTick.Stop()
	defer chronosTick.Stop()
	defer logVerifyTick.Stop()
	defer cleanupTick.Stop()
	defer behaviorSaveTick.Stop()
	defer statusTick.Stop()
	defer rollbackTick.Stop()

	integrityEvents, stopIntegrityWatch, watchErr := watchIntegrityChanges(ctx, e.protectedPaths())
	defer stopIntegrityWatch()
	if watchErr != nil {
		e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.integrity_watch_fallback", Source: "integrity", Message: "Native integrity event watch unavailable; bounded periodic verification remains active"})
	}

	_, runtimeXDRMode := e.state.Modes()
	runtime = e.runtimeSettings()
	cellLSMPolicyOnline := true
	if e.cfg.Cells.Enabled {
		if err := e.syncCellLSMPolicies(); err != nil {
			cellLSMPolicyOnline = false
			e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.cell_lsm_policy_unavailable", Source: "bpf-lsm", Message: "Gaia Cell BPF-LSM policy synchronization is unavailable; existing restrictive entries remain installed"})
		}
	}
	cellLSMEventOnline := true
	sensor := xdrSensorMode(true, true, true, e.cfg.Cells.Enabled, cellLSMPolicyOnline)
	if !runtime.XDREnabled {
		sensor = "disabled-by-operator"
	}
	e.state.SetXDRStatus(XDRStatus{Enabled: runtime.XDREnabled, Mode: runtimeXDRMode, Sensor: sensor, ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
	if degraded, reason := e.degradedState(); degraded {
		e.state.MarkXDRDegraded(reason)
		e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.integrity_failure", Source: "integrity", Message: reason})
	}
	e.state.AddEvent(Event{Severity: "info", Kind: "xdr.online", Source: "xdr", Message: fmt.Sprintf("GeDefense XDR online: mode=%s workers=%d bounded_queue=%d", runtimeXDRMode, e.cfg.XDR.WorkerCount, cap(e.highJobs)+cap(e.normalJobs))})

	var processes map[string]ProcessSample
	execSensorOnline := true
	egressSensorOnline := true
	malwareSensorOnline := true
	var execRetryAfter time.Time
	var egressRetryAfter time.Time
	var malwareRetryAfter time.Time
	var cellLSMEventRetryAfter time.Time
	var cellLSMPolicyRetryAfter time.Time
	// POINT 3 / P3-T5: independent rate limits for the kernel flow channel. The
	// 100 ms tick stays the clock, but the flow drain/health polls run on their own
	// 1 s / 10 s cadence so they can never delay exec, egress or malware ingestion.
	var styxFlowRetryAfter time.Time
	var styxHealthRetryAfter time.Time
	// POINT 1 / P1-T5: the kernel exec-gate drain/health own their rate limits too;
	// the 100 ms tick is only the clock, so neither can delay exec, egress or
	// malware ingestion.
	var titanExecDrainRetryAfter time.Time
	var titanExecHealthRetryAfter time.Time
	// M2.2: independent cadence for the kernel ransomware sensor (1 s events,
	// 10 s status) so a freeze record is never delayed behind other ingestion.
	var ransomDrainRetryAfter time.Time
	var ransomStatusRetryAfter time.Time
	// M2.4: independent cadence for the kernel credential guard (1 s decisions,
	// 10 s status).
	var credGuardDrainRetryAfter time.Time
	var credGuardStatusRetryAfter time.Time
	// V6.3.0: independent cadence per new kernel family so a slow status query
	// can never delay another sensor's drain.
	var selfGuardRetryAfter time.Time
	var execInodeRetryAfter time.Time
	var bpfGuardRetryAfter time.Time
	var crossViewRetryAfter time.Time
	var kernelHooksRetryAfter time.Time
	var persistenceRetryAfter time.Time
	// V6.3.0 AP-6/AP-7 cadences (phase-2 analytics, DNS, permit maintenance).
	var styxPhase2RetryAfter time.Time
	var dnsTunnelRetryAfter time.Time
	var permitRetryAfter time.Time
	// V6.3.0 AP-9 (S12): high-priority ring cadence and SBC corroboration drain.
	var secCritRetryAfter time.Time
	var sbcCorroborationRetryAfter time.Time
	var execArgvRetryAfter time.Time
	var kernelProbeRetryAfter time.Time
	for {
		select {
		case <-ctx.Done():
			if e.behavior != nil {
				_ = e.behavior.Persist()
			}
			cancelWorkers()
			return
		case <-scanTick.C:
			runtime = e.runtimeSettings()
			scanTick.Reset(time.Duration(runtime.ScanIntervalMillis) * time.Millisecond)
			if !runtime.XDREnabled {
				e.state.SetXDRStatus(XDRStatus{Enabled: false, Mode: "disabled", Sensor: "disabled-by-operator", ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
				continue
			}
			p, err := scanLinuxProcesses(runtime.XDRFabric.MaxCommandBytes)
			if err != nil {
				// A failed /proc listing is a hiccup, not a sensor outage: it happens when the
				// descriptor table is momentarily full, and the scan a second later succeeds. It
				// degrades only once it repeats, and the next successful scan clears it again -
				// otherwise a single transient failure would pause the platform for good.
				if count, repeated := e.claimRepeatedFailure("process_sensor"); repeated {
					e.markDegradedCause("process_sensor", "process sensor unavailable: "+err.Error())
				} else {
					log.Printf("process sensor scan failed (%d/%d, not degrading yet): %v", count, forensicFailureThreshold, err)
				}
				continue
			}
			e.noteVerificationSuccess("process_sensor")
			processes = p
			e.evaluateNewProcesses(p)
			now := time.Now().UTC()
			degraded, reason := e.degradedState()
			e.state.UpdateXDRScan(len(p), -1, now, degraded, reason, len(e.protected))
		case now := <-execTick.C:
			runtime = e.runtimeSettings()
			if e.cfg.Cells.Enabled && !now.Before(cellLSMEventRetryAfter) {
				events, err := e.core.CellLSMEvents()
				if err != nil {
					if cellLSMEventOnline {
						cellLSMEventOnline = false
						e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.cell_lsm_event_unavailable", Source: "bpf-lsm", Message: "Gaia Cell BPF-LSM enforcement events are unavailable"})
						if runtime.XDREnabled {
							e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, true, false), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
						}
					}
					cellLSMEventRetryAfter = now.Add(10 * time.Second)
				} else {
					if !cellLSMEventOnline {
						cellLSMEventOnline = true
						e.state.AddEvent(Event{Severity: "info", Kind: "xdr.cell_lsm_event_recovered", Source: "bpf-lsm", Message: "Gaia Cell BPF-LSM enforcement event correlation recovered"})
					}
					for _, event := range events {
						e.recordCellLSMDeny(event)
					}
				}
			}
			// POINT 1 / P1-T5: drain the kernel exec-gate decisions on their own
			// bounded cadence. The records are kernel enforcement telemetry, not an
			// XDR detection feature, so the drain deliberately runs before the XDR
			// enablement gate: an operator pausing detection must not make the
			// kernel ring overflow and lose enforcement evidence.
			if e.core != nil && !now.Before(titanExecDrainRetryAfter) {
				payload, drainErr := e.core.TitanExecEvents()
				titanExecDrainRetryAfter = now.Add(e.consumeTitanExecDrain(payload, drainErr, now))
			}
			if e.core != nil && !now.Before(titanExecHealthRetryAfter) && e.titanExecCapabilityKnown() {
				health, healthErr := e.core.TitanExecHealth()
				e.consumeTitanExecHealth(health, healthErr, now)
				titanExecHealthRetryAfter = now.Add(titanExecHealthInterval)
			}
			if !runtime.XDREnabled {
				continue
			}
			if !now.Before(execRetryAfter) {
				events, err := e.core.ExecEvents()
				if err != nil {
					if execSensorOnline {
						execSensorOnline = false
						e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.exec_sensor_fallback", Source: "kernel", Message: "Kernel exec event stream unavailable; bounded procfs detection remains active"})
						e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, e.cfg.Cells.Enabled, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
					}
					execRetryAfter = now.Add(10 * time.Second)
				} else {
					if !execSensorOnline {
						execSensorOnline = true
						e.state.AddEvent(Event{Severity: "info", Kind: "xdr.exec_sensor_recovered", Source: "kernel", Message: "Kernel exec event stream recovered"})
						e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, e.cfg.Cells.Enabled, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
					}
					for _, event := range events {
						process, readErr := readExecProcess(event, runtime.XDRFabric.MaxCommandBytes)
						if readErr != nil || process.PID == e.selfPID || e.allowedProcess(process.Exe) {
							continue
						}
						key := fmt.Sprintf("%d:%d", process.PID, process.StartTicks)
						e.mu.Lock()
						_, alreadySeen := e.seen[key]
						e.seen[key] = struct{}{}
						e.mu.Unlock()
						if alreadySeen {
							continue
						}
						e.submit(evaluationJob{process: process, source: "exec"}, true)
					}
				}
			}
			if !now.Before(malwareRetryAfter) {
				batch, err := e.core.MalwareEvents()
				if err != nil {
					if malwareSensorOnline {
						malwareSensorOnline = false
						e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.malware_sensor_unavailable", Source: "kernel", Message: "Fanotify execution decisions remain fail-closed, but their XDR event channel is unavailable"})
						e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, e.cfg.Cells.Enabled, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
					}
					malwareRetryAfter = now.Add(10 * time.Second)
				} else {
					if !malwareSensorOnline {
						malwareSensorOnline = true
						e.state.AddEvent(Event{Severity: "info", Kind: "xdr.malware_sensor_recovered", Source: "kernel", Message: "Fanotify execution block events are again correlated by XDR"})
						e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, e.cfg.Cells.Enabled, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
					}
					if batch.Dropped > 0 {
						e.recordMalwareOverflow(batch.Dropped)
					}
					if runtime.XDRFabric.MalwareCorrelation {
						for _, event := range batch.Events {
							e.recordMalwareEvent(event)
						}
					}
				}
			}
			// POINT 3 / P3-T5: drain the kernel's aggregated flow telemetry on its own
			// bounded cadence. A failure here degrades only this sensor's own cause and
			// never delays the ingress/egress channels above.
			if runtime.XDREnabled && e.core != nil && !now.Before(styxFlowRetryAfter) {
				if !e.styxFlowPollEnabled() {
					// The operator namespace is disabled: nothing to drain, no claim.
					styxFlowRetryAfter = now.Add(10 * time.Second)
				} else {
					events, dropped, flowErr := e.core.StyxFlowEvents()
					switch {
					case errors.Is(flowErr, ErrStyxUnavailable):
						// A pre-StyX core is a capability fact, never an XDR degradation.
						e.setStyxBeaconCapability(false)
						styxFlowRetryAfter = now.Add(10 * time.Second)
					case flowErr != nil:
						e.recordStyxFlowHealthFailure(flowErr)
						e.noteVerificationFailure("styx_flow_sensor", "kernel styx flow telemetry unavailable: "+flowErr.Error())
						styxFlowRetryAfter = now.Add(10 * time.Second)
					default:
						e.noteVerificationSuccess("styx_flow_sensor")
						e.setStyxBeaconCapability(true)
						e.recordStyxFlowBatch(events, dropped, now)
						styxFlowRetryAfter = now.Add(time.Second)
					}
				}
			}
			if runtime.XDREnabled && e.core != nil && !now.Before(styxHealthRetryAfter) && e.styxFlowCapabilityKnown() {
				health, healthErr := e.core.StyxFlowHealth()
				if healthErr != nil {
					if errors.Is(healthErr, ErrStyxUnavailable) {
						e.setStyxBeaconCapability(false)
					} else {
						e.recordStyxFlowHealthFailure(healthErr)
						e.noteVerificationFailure("styx_flow_sensor", "kernel styx flow health unavailable: "+healthErr.Error())
					}
					styxHealthRetryAfter = now.Add(5 * time.Second)
				} else {
					e.recordStyxFlowHealth(health, now)
					styxHealthRetryAfter = now.Add(time.Second)
				}
			}
			// M2.2: kernel ransomware sensor. Status first (capability + arm
			// state), then the freeze-record drain on the 100 ms execTick so a
			// fast encryptor cannot finish the burst during a longer idle gap.
			// Every record is either escalated with evidence or the freeze is
			// released again - the Go side never leaves a group frozen silently.
			if runtime.XDREnabled && e.ransomCore != nil && !now.Before(ransomStatusRetryAfter) {
				status, statusErr := e.ransomCore.RansomStatus()
				e.consumeRansomStatus(status, statusErr, now)
				if statusErr == nil && !status.Armed && !e.ransomArmedRequested {
					e.ransomArmedRequested = true
					if err := e.ransomCore.RansomSet(true); err != nil {
						e.ransomArmedRequested = false
						e.ransomMu.Lock()
						e.ransomStatusErr = boundedStyxText(err)
						e.ransomMu.Unlock()
					}
				}
				ransomStatusRetryAfter = now.Add(10 * time.Second)
				e.state.SetXDRRansomSensor(e.RansomSensorReport())
			}
			if runtime.XDREnabled && e.ransomCore != nil && e.ransomCapabilityKnown && !now.Before(ransomDrainRetryAfter) {
				events, dropped, ransomErr := e.ransomCore.RansomEvents()
				ransomDrainRetryAfter = now.Add(e.consumeRansomEvents(events, dropped, ransomErr, now, e.ransomEscalationAllowed()))
			}
			// M2.4: kernel credential guard. Status first (capability + arm), then
			// the DENY/AUDIT drain. Active is only claimed when the core reports the
			// hook attached and at least one protected object watched.
			if runtime.XDREnabled && e.credCore != nil && !now.Before(credGuardStatusRetryAfter) {
				status, statusErr := e.credCore.CredGuardStatus()
				e.consumeCredGuardStatus(status, statusErr, now)
				if statusErr == nil && !status.Armed && !e.credArmedRequested {
					e.credArmedRequested = true
					if err := e.credCore.CredGuardSet(true); err != nil {
						e.credArmedRequested = false
						e.credMu.Lock()
						e.credStatusErr = boundedStyxText(err)
						e.credMu.Unlock()
					}
				}
				credGuardStatusRetryAfter = now.Add(10 * time.Second)
				e.state.SetXDRCredentialGuard(e.CredentialGuardReport())
			}
			if runtime.XDREnabled && e.credCore != nil && e.credCapabilityKnown && !now.Before(credGuardDrainRetryAfter) {
				events, dropped, credErr := e.credCore.CredGuardEvents()
				credGuardDrainRetryAfter = now.Add(e.consumeCredGuardEvents(events, dropped, credErr, now))
			}
			// V6.3.0 AP-0/AP-1/AP-2: sensor self-protection, executable-inode trust
			// and the attach-time eBPF guard. Each family owns its retry state.
			selfGuardRetryAfter = e.pollSelfGuard(runtime, now, selfGuardRetryAfter)
			execInodeRetryAfter = e.pollExecInode(runtime, now, execInodeRetryAfter)
			bpfGuardRetryAfter = e.pollBpfGuard(runtime, now, bpfGuardRetryAfter)
			// V6.3.0 AP-3/AP-4/AP-5: cross-view, io_uring/LKM and persistence/
			// peripheral families. Each owns its cadence and failure isolation.
			crossViewRetryAfter = e.pollCrossView(runtime, now, crossViewRetryAfter)
			kernelHooksRetryAfter = e.pollKernelHooks(runtime, now, kernelHooksRetryAfter)
			persistenceRetryAfter = e.pollPersistence(runtime, now, persistenceRetryAfter)
			// V6.3.0 AP-6/AP-7: phase-2 PCR/IdleHint analytics, DNS tunnelling
			// and PermitV1 maintenance. All are bounded and failure-isolated.
			styxPhase2RetryAfter = e.pollStyxPhase2(runtime, now, styxPhase2RetryAfter)
			dnsTunnelRetryAfter = e.pollDnsTunnel(runtime, now, dnsTunnelRetryAfter)
			permitRetryAfter = e.pollPermits(runtime, now, permitRetryAfter)
			// V6.3.0 AP-9 (S12): drain the high-priority security ring; its
			// cadence is independent of the bulk telemetry drains above.
			secCritRetryAfter = e.pollSecCrit(runtime, now, secCritRetryAfter)
			// V6.3.0 AP-6: drain bounded SBC corroboration events evidence-first.
			if e.sbc != nil && !now.Before(sbcCorroborationRetryAfter) {
				if _, err := e.recordSBCCorroborations(now); err != nil {
					e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.sbc_corroboration_failed",
						Source: "xdr", Message: boundedStyxText(err)})
				}
				sbcCorroborationRetryAfter = now.Add(5 * time.Second)
			}
			if runtime.XDREnabled && e.probeCore != nil && !now.Before(execArgvRetryAfter) {
				var nextDelay time.Duration
				for batch := 0; batch < 12; batch++ {
					argvEvents, argvErr := e.probeCore.ExecArgvEvents()
					nextDelay = e.consumeExecArgvEvents(argvEvents, argvErr, runtime.XDRFabric.MaxCommandBytes)
					if argvErr != nil || len(argvEvents) < maxExecArgvEventsPerResponse {
						break
					}
				}
				execArgvRetryAfter = now.Add(nextDelay)
			}
			if runtime.XDREnabled && e.probeCore != nil && !now.Before(kernelProbeRetryAfter) {
				var nextDelay time.Duration
				for batch := 0; batch < 6; batch++ {
					probeEvents, probeErr := e.probeCore.KernelProbeEvents()
					nextDelay = e.consumeKernelProbeEvents(probeEvents, probeErr, now)
					if probeErr != nil || len(probeEvents) < maxKernelProbeEventsPerReply {
						break
					}
				}
				kernelProbeRetryAfter = now.Add(nextDelay)
			}
			if now.Before(egressRetryAfter) {
				continue
			}
			egressEvents, err := e.core.EgressEvents()
			if err != nil {
				if egressSensorOnline {
					egressSensorOnline = false
					e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.egress_sensor_fallback", Source: "kernel", Message: "Kernel cgroup egress event stream unavailable; block policy remains owned by the Rust core"})
					e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, e.cfg.Cells.Enabled, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
				}
				egressRetryAfter = now.Add(10 * time.Second)
				continue
			}
			if !egressSensorOnline {
				egressSensorOnline = true
				e.state.AddEvent(Event{Severity: "info", Kind: "xdr.egress_sensor_recovered", Source: "kernel", Message: "Kernel cgroup egress event stream recovered"})
				e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, e.cfg.Cells.Enabled, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
			}
			for _, event := range egressEvents {
				target := event.Destination.String()
				fingerprint := fmt.Sprintf("kernel-egress:%d:%d:%s:%s", event.UID, event.Protocol, target, event.Comm)
				if !e.claimFingerprint(fingerprint) {
					continue
				}
				processName := event.Comm
				if processName == "" {
					processName = "unknown"
				}

				// REAL SENSOR -> STYX ENGINE -> DECISION -> RESPONSE ENGINE ENFORCEMENT
				if e.styx != nil {
					protoStr := "TCP"
					if event.Protocol == 17 {
						protoStr = "UDP"
					}
					allowed, reason, styxErr := e.styx.EvaluateEgress(ctx, "HOST", "DEFAULT", target, 0, protoStr, event.PID, processName)
					if !allowed || styxErr != nil {
						if e.responses != nil {
							_, _ = e.responses.ApplyResponse(
								ctx, now,
								fmt.Sprintf("egress-%d", now.UnixNano()),
								ActionContainIP, "IP", target,
								95, reason, "",
							)
						}
					}
				}

				e.state.AddEvent(Event{
					Severity: "high",
					Kind:     "xdr.egress_blocked",
					Source:   "kernel",
					Message:  fmt.Sprintf("Kernel blocked outbound protocol=%d process=%s pid=%d uid=%d", event.Protocol, processName, event.PID, event.UID),
					Target:   target,
				})
			}
		case <-netTick.C:
			runtime = e.runtimeSettings()
			netTick.Reset(time.Duration(runtime.NetworkIntervalSeconds) * time.Second)
			if !runtime.XDREnabled || !runtime.NetworkSensorEnabled || processes == nil {
				continue
			}
			connections, total := correlateLinuxConnections(processes)
			queued := 0
			for key, p := range processes {
				if queued >= runtime.XDRFabric.MaxEvaluationsPerScan {
					e.noteDrop("network scan evaluation budget exhausted")
					break
				}
				p.Connections = connections[key]
				if e.submit(evaluationJob{process: p, conns: p.Connections, source: "network"}, false) {
					queued++
				}
			}
			now := time.Now().UTC()
			degraded, reason := e.degradedState()
			e.state.UpdateXDRScan(len(processes), total, now, degraded, reason, len(e.protected))
		case _, ok := <-integrityEvents:
			if ok {
				e.checkProtected()
			}
		case <-integrityTick.C:
			e.checkProtected()
		case <-chronosTick.C:
			if e.chronos != nil && e.chronos.Enabled() && runtime.XDREnabled && e.chronosRunning.CompareAndSwap(false, true) {
				go func() {
					defer e.chronosRunning.Store(false)
					cp, err := e.chronos.Scan(ctx, true)
					if err != nil && !errors.Is(err, context.Canceled) {
						severity := "warning"
						if cp != nil && cp.Phase == "BOUNDED" {
							// A bounded walk is a policy outcome, not a fault: the digest
							// set is partial and says so instead of reporting success.
							severity = "info"
						}
						e.state.AddEvent(Event{
							Severity: severity, Kind: "chronos.scan_failed", Source: "fim",
							Message: fmt.Sprintf("Chronos FIM scan did not complete: %v", err),
						})
					} else if cp != nil && cp.Phase == "COMPLETED" {
						e.state.AddEvent(Event{
							Severity: "info", Kind: "chronos.merkle_verified", Source: "fim",
							Message: fmt.Sprintf("Chronos Merkle tree integrity verified: root=%s files=%d bytes=%d", cp.MerkleRoot, cp.FilesScanned, cp.BytesScanned),
						})
					}
				}()
			}
		case <-logVerifyTick.C:
			e.verifyForensicArtefacts(ctx)
		case <-behaviorSaveTick.C:
			if e.behavior != nil {
				if err := e.behavior.Persist(); err != nil {
					e.markDegradedCause("behavior", "behavior profile persistence failed: "+err.Error())
				}
			}
		case now := <-rollbackTick.C:
			if e.responses != nil {
				_, _ = e.responses.RollbackExpired(ctx, now)
			}
		case now := <-cleanupTick.C:
			e.cleanupDedupe(now)
		case now := <-statusTick.C:
			runtime = e.runtimeSettings()
			if e.cfg.Cells.Enabled && !now.Before(cellLSMPolicyRetryAfter) {
				if err := e.syncCellLSMPolicies(); err != nil {
					if cellLSMPolicyOnline {
						cellLSMPolicyOnline = false
						e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.cell_lsm_policy_unavailable", Source: "bpf-lsm", Message: "Gaia Cell BPF-LSM policy synchronization is unavailable; existing restrictive entries remain installed"})
					}
					cellLSMPolicyRetryAfter = now.Add(10 * time.Second)
				} else if !cellLSMPolicyOnline {
					cellLSMPolicyOnline = true
					e.state.AddEvent(Event{Severity: "info", Kind: "xdr.cell_lsm_policy_recovered", Source: "bpf-lsm", Message: "Gaia Cell BPF-LSM policy synchronization recovered"})
				}
				if runtime.XDREnabled {
					e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, true, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
				}
			}
			e.state.UpdateXDRRuntime(len(e.highJobs)+len(e.normalJobs), cap(e.highJobs)+cap(e.normalJobs), e.drops.Load(), e.evaluated.Load(), e.anomalies.Load(), e.behavior.Summary())
			e.state.SetXDREnabled(runtime.XDREnabled, runtime.NetworkSensorEnabled)
		}
	}
}

func (e *XDREngine) worker(ctx context.Context) {
	defer e.workers.Done()
	for {
		var job evaluationJob
		var ok bool
		select {
		case <-ctx.Done():
			return
		case job, ok = <-e.highJobs:
			if !ok {
				return
			}
		default:
			select {
			case <-ctx.Done():
				return
			case job, ok = <-e.highJobs:
				if !ok {
					return
				}
			case job, ok = <-e.normalJobs:
				if !ok {
					return
				}
			}
		}
		e.evaluate(job.process, job.conns, job.source)
	}
}

func (e *XDREngine) submit(job evaluationJob, high bool) bool {
	ch := e.normalJobs
	if high {
		ch = e.highJobs
	}
	select {
	case ch <- job:
		return true
	default:
		e.noteDrop("XDR evaluation queue full")
		return false
	}
}

func (e *XDREngine) noteDrop(reason string) {
	n := e.drops.Add(1)
	if n == 1 || n&(n-1) == 0 {
		e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.backpressure", Source: "pipeline", Message: fmt.Sprintf("%s; dropped evaluations=%d", reason, n)})
	}
}

func (e *XDREngine) evaluateNewProcesses(processes map[string]ProcessSample) {
	runtime := e.runtimeSettings()
	budget := runtime.XDRFabric.MaxEvaluationsPerScan
	e.mu.Lock()
	current := make(map[string]struct{}, len(processes))
	if !e.seeded {
		for key := range processes {
			e.seen[key] = struct{}{}
		}
		e.seeded = true
		e.mu.Unlock()
		return
	}
	var jobs []evaluationJob
	for key, p := range processes {
		current[key] = struct{}{}
		if _, known := e.seen[key]; known {
			continue
		}
		e.seen[key] = struct{}{}
		if p.PID == e.selfPID || allowedProcessRuntime(p.Exe, runtime.XDRFabric.AllowProcesses) {
			continue
		}
		if len(jobs) < budget {
			jobs = append(jobs, evaluationJob{process: p, source: "exec"})
		}
	}
	for key := range e.seen {
		if _, ok := current[key]; !ok {
			delete(e.seen, key)
		}
	}
	e.mu.Unlock()
	for _, job := range jobs {
		e.submit(job, true)
	}
	if len(jobs) >= budget {
		e.noteDrop("process scan evaluation budget exhausted")
	}
}

func allowedProcessRuntime(exe string, allowedProcesses []string) bool {
	exe = filepath.Clean(strings.TrimSuffix(exe, " (deleted)"))
	for _, allowed := range allowedProcesses {
		if filepath.Clean(allowed) == exe {
			return true
		}
	}
	return false
}

func (e *XDREngine) allowedProcess(exe string) bool {
	return allowedProcessRuntime(exe, e.runtimeSettings().XDRFabric.AllowProcesses)
}

func hasTrustedExecutableIdentity(p ProcessSample) bool {
	executable := filepath.Clean(strings.TrimSuffix(p.Exe, " (deleted)"))
	return executable != "." && executable != string(filepath.Separator) &&
		filepath.IsAbs(executable)
}

// titanExecCapabilityKnown reports whether the core proved the TITAN_EXEC_* ABI.
func (e *XDREngine) titanExecCapabilityKnown() bool {
	if e == nil {
		return false
	}
	e.titanExecMu.Lock()
	defer e.titanExecMu.Unlock()
	return e.titanExecCapability == titanExecCapabilityAvailable
}

// sanitizeTitanExecComm renders a raw kernel task name for operator surfaces.
// PR_SET_NAME lets a process choose arbitrary bytes, so the parser accepts them
// unconditionally (§3.2 comm contract); this renderer replaces every invalid or
// non-printable rune with '?' so the value can never forge a line or a field
// separator, while valid printable UTF-8 stays unchanged. It always terminates
// and never grows the value beyond its raw byte length.
func sanitizeTitanExecComm(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(raw))
	for len(raw) > 0 {
		character, size := utf8.DecodeRune(raw)
		switch {
		case character == utf8.RuneError && size == 1:
			builder.WriteByte('?')
		case strconv.IsPrint(character):
			builder.WriteRune(character)
		default:
			builder.WriteByte('?')
		}
		raw = raw[size:]
	}
	return builder.String()
}
