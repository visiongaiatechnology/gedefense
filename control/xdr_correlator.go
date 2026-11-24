// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (e *XDREngine) Responses() *ResponseEngine {
	return e.responses
}

func (e *XDREngine) Deception() *DeceptionEngine {
	return e.deception
}

func (e *XDREngine) Styx() *StyxEngine {
	return e.styx
}

func (e *XDREngine) Morpheus() *MorpheusRASP {
	return e.morpheus
}

func (e *XDREngine) Airlock() *AirlockInspector {
	return e.airlock
}

func (e *XDREngine) Chronos() *ChronosScanner {
	return e.chronos
}

func (e *XDREngine) PlatformCaps() PlatformCapabilities {
	return e.platformCaps
}

func (e *XDREngine) Correlator() *IncidentCorrelator {
	return e.correlator
}

func (e *XDREngine) runtimeSettings() RuntimeSettings {
	if e.settings != nil {
		return e.settings.Get()
	}
	return defaultRuntimeSettings(e.cfg)
}

func desiredCellLSMPolicies(status GaiaCellsStatus) (map[uint64]uint8, error) {
	desired := make(map[uint64]uint8)
	if !status.Enabled {
		return desired, nil
	}
	if !status.Healthy || status.Availability != "online" {
		return nil, errors.New("authenticated Gaia Cells inventory is unavailable")
	}
	for _, cell := range status.Cells {
		if err := validateGaiaCell(cell); err != nil {
			return nil, err
		}
		if (cell.State == "running" || cell.State == "frozen") && cell.NetworkState == "none" {
			desired[cell.CgroupID] = cellLSMDenyNonUnixSocket
		}
	}
	return desired, nil
}

func (e *XDREngine) syncCellLSMPolicies() error {
	if !e.cfg.Cells.Enabled {
		return nil
	}
	if e.core == nil {
		return errors.New("GeDefense core is unavailable for Cell LSM synchronization")
	}
	epoch, err := e.core.CellPolicyEpoch()
	if err != nil {
		return err
	}
	adapter := e.state.Cells()
	if adapter == nil {
		return errors.New("Gaia Cells adapter is unavailable")
	}
	desired, err := desiredCellLSMPolicies(adapter.Status(false))
	if err != nil {
		return err
	}
	if epoch != e.cellPolicyEpoch {
		e.cellPolicyEpoch = epoch
		e.cellPolicies = make(map[uint64]uint8)
	}
	additions := make([]uint64, 0, len(desired))
	for cgroupID, flags := range desired {
		if current, exists := e.cellPolicies[cgroupID]; !exists || current != flags {
			additions = append(additions, cgroupID)
		}
	}
	sort.Slice(additions, func(left, right int) bool { return additions[left] < additions[right] })
	for _, cgroupID := range additions {
		flags := desired[cgroupID]
		if err := e.core.CellPolicySet(cgroupID, flags); err != nil {
			return fmt.Errorf("apply Cell LSM policy for cgroup %d: %w", cgroupID, err)
		}
		e.cellPolicies[cgroupID] = flags
	}
	removals := make([]uint64, 0)
	for cgroupID := range e.cellPolicies {
		if _, exists := desired[cgroupID]; !exists {
			removals = append(removals, cgroupID)
		}
	}
	sort.Slice(removals, func(left, right int) bool { return removals[left] < removals[right] })
	for _, cgroupID := range removals {
		if err := e.core.CellPolicyDelete(cgroupID); err != nil {
			return fmt.Errorf("delete stale Cell LSM policy for cgroup %d: %w", cgroupID, err)
		}
		delete(e.cellPolicies, cgroupID)
	}
	return nil
}

func (e *XDREngine) recordCellLSMDeny(event CoreCellLSMDenyEvent) {
	fingerprint := fmt.Sprintf("cell-lsm:%d:%d:%d", event.CgroupID, event.PID, event.Family)
	if !e.claimFingerprint(fingerprint) {
		return
	}
	summary := fmt.Sprintf(
		"BPF LSM denied socket creation in offline Gaia Cell: cgroup=%d family=%d pid=%d uid=%d",
		event.CgroupID, event.Family, event.PID, event.UID,
	)
	target := fmt.Sprintf("cgroup:%d", event.CgroupID)
	if err := e.state.RecordEvidence(EvidenceRecord{
		Severity: "high", Kind: "cell.lsm_socket_denied", Source: "bpf-lsm",
		Message: summary, Target: target,
	}); err != nil {
		// The ledger owns this condition: State.RecordEvidence names it precisely and clears it
		// again when the ledger recovers. Marking it here as well produced a second, vaguer cause
		// that nothing could clear.
		log.Printf("cell lsm evidence commit failed: %v", err)
	}
	e.state.AddEvent(Event{
		Severity: "high", Kind: "cell.lsm_socket_denied", Source: "bpf-lsm",
		Message: summary, Target: target,
	})
	e.appendIncident(XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: "high", Score: 220, ResponseScore: 220,
		PID: event.PID, UID: event.UID, CellCgroupID: event.CgroupID, SocketFamily: event.Family,
		RuleIDs: []string{"CELL.LSM_SOCKET_DENY"}, Categories: []string{"cell-isolation", "lsm", "network"},
		Summary: summary, Decision: "deny-socket", Action: "deny", Outcome: "blocked by BPF LSM before socket creation",
	})
}

func (e *XDREngine) evaluate(p ProcessSample, conns []NetConnection, source string) {
	if p.PID <= 4 || p.PID == e.selfPID {
		return
	}
	if !hasTrustedExecutableIdentity(p) {
		return
	}
	runtime := e.runtimeSettings()
	if err := e.rules.Configure(runtime); err != nil {
		// Invalid rules mean no detection, so this degrades at once - but the next successful
		// configuration must clear it again, or a corrected setting would need a restart.
		e.markDegradedCause("rule_config", "runtime rule configuration invalid: "+err.Error())
		return
	}
	e.clearDegradedCause("rule_config")
	if !runtime.XDREnabled {
		return
	}
	e.evaluated.Add(1)

	// Morpheus RASP: Active Memory-Scraping / Ptrace Inspection in Data Path.
	//
	// A detection is signalled whether or not containment is armed. An alert-only RASP used to
	// return the event without an error, and this caller only dispatched on the error, so an
	// operator who chose alert-only got no XDR alarm at all. The RASP emits its own incident
	// through the sink in both cases; the event decides whether an active response follows.
	if e.morpheus != nil {
		if raspEvt, _ := e.morpheus.InspectProcess(p); raspEvt != nil {
			now := time.Now().UTC()
			containment := e.morpheus.ContainmentEnabled()
			kind := "morpheus.memory_scraping_detected"
			message := fmt.Sprintf("Morpheus RASP detected memory scraping by PID %d (%s)", p.PID, p.Comm)
			if containment {
				kind = "morpheus.memory_scraping_blocked"
				message = fmt.Sprintf("Morpheus RASP blocked memory scraping by PID %d (%s)", p.PID, p.Comm)
			}
			e.state.AddEvent(Event{
				Severity: "critical", Kind: kind, Source: "rasp",
				Message: message, Target: fmt.Sprintf("pid:%d", p.PID),
			})
			if containment && e.responses != nil {
				freezeTarget := fmt.Sprintf("%d:%d", p.PID, p.StartTicks)
				evDigest := raspEvt.EventID
				if raspEvt.AttackNode != nil {
					evDigest = raspEvt.AttackNode.ComputeNodeDigest()
				}
				_, _ = e.responses.ApplyResponse(
					context.Background(), now,
					raspEvt.EventID, ActionFreezeExecution, "PID", freezeTarget,
					100, "MORPHEUS_RASP_MEMORY_SCRAPING", evDigest,
				)
			}
		}
	}

	// Styx Egress Engine: Live Socket Connection Evaluation in Data Path
	if e.styx != nil && len(conns) > 0 {
		for _, c := range conns {
			if ip := net.ParseIP(c.RemoteIP); ip != nil {
				now := time.Now().UTC()
				if allowed, reason, styxErr := e.styx.EvaluateEgress(context.Background(), "CGROUP", p.Cgroup, c.RemoteIP, c.RemotePort, c.Protocol, p.PID, p.Comm); !allowed || styxErr != nil {
					if e.responses != nil {
						_, _ = e.responses.ApplyResponse(
							context.Background(), now,
							fmt.Sprintf("egress-conn-%d", now.UnixNano()),
							ActionContainIP, "IP", c.RemoteIP,
							95, reason, "",
						)
					}
				}
			}
		}
	}

	var extra []RuleMatch
	if runtime.BehaviorEnabled && e.behavior != nil {
		now := time.Now().UTC()
		if source == "exec" {
			extra = e.behavior.ObserveExec(p, now)
		} else if source == "network" {
			extra = e.behavior.ObserveNetwork(p, conns, now)
		}
		if len(extra) > 0 {
			e.anomalies.Add(uint64(len(extra)))
		}
	}
	if e.l7Recent != nil {
		extra = append(extra, e.l7Recent.Match(conns, time.Now().UTC())...)
	}
	var index *ThreatIndex
	if runtime.FeedsEnabled && e.feeds != nil {
		index = e.feeds.CorrelateIndex()
	}
	decision := e.rules.EvaluateProcess(p, conns, index, e.baseline, extra...)
	// A digest mismatch on one of our own components is a trust-boundary event, not a process
	// that should be frozen or killed. The right answer is the fail-closed degradation that
	// XDR.SELF_TAMPER records - and a verified signed update window is the only thing that may
	// turn the same bytes into a deployment. This interception is why the baseline no longer
	// downgrades own artifacts to AlertOnly: nothing here may ever dispatch an "action: none"
	// incident for them.
	if containsString(decision.RuleIDs, "BASELINE.HASH_MISMATCH") && isProductArtifact(p.Exe) {
		expected, actual, mismatch := e.baseline.ProductArtifactMismatch(p.Exe)
		if mismatch {
			identity := resolvedIdentity(p.Exe)
			observed := actual
			if observed == "" {
				observed = "unreadable"
			}
			if e.updateWindowCovers(identity, actual, false) {
				if updated, ok := newProtectedObject(resolvedIdentity(p.Exe), actual); ok {
					e.applyAuthorizedUpdate(p.Exe, identity, actual, observed, false, updated)
				}
			} else {
				e.selfTamper(p.Exe, observed, fmt.Sprintf(
					"GeDefense component digest differs from the approved baseline (approved=%s observed=%s); an update requires a verified signed package-update window",
					expected, observed))
			}
			return
		}
	}
	if decision.Score < runtime.AlertScore || len(decision.RuleIDs) == 0 {
		return
	}
	// V6.3.0 AP-7: consult the PermitV1 broker before any active response is
	// planned. A matching permit can only suppress or downgrade — it never
	// authorizes a response, never raises the decision and never bypasses the
	// kill gate, which has already been applied by combineMatches above.
	permitDecision := e.evaluatePermitBroker(p, decision)
	if permitDecision != nil && permitDecision.TrustLevel == permitTrustAuthorized {
		e.recordAuthorizedPermitOutcome(p, decision, permitDecision)
		return
	}
	decision.Decision = "alert"
	if decision.ResponseScore >= runtime.KillScore && decision.KillSignals >= 2 {
		decision.Decision = "kill"
	} else if decision.ResponseScore >= runtime.ContainScore {
		decision.Decision = "contain"
	}
	if permitDecision != nil {
		// V6.3.0 AP-7: a TOLERATED / ANALYST_MODE permit keeps the evidence and
		// the scores but suppresses the active response. The helper is
		// suppression-only and can never elevate the decision.
		decision = applyPermitDecision(decision, permitDecision)
	}
	finger := fmt.Sprintf("%d:%d:%s:%s", p.PID, p.StartTicks, strings.Join(decision.RuleIDs, ","), decision.Remote)
	if !e.claimFingerprint(finger) {
		return
	}
	severity := "warning"
	if decision.ResponseScore >= runtime.ContainScore {
		severity = "high"
	}
	if decision.Decision == "kill" {
		severity = "critical"
	}
	now := time.Now().UTC()
	incidentID := randomID()
	storyNode := AttackStoryNode{
		NodeID:     fmt.Sprintf("node-%d-%d", p.PID, now.UnixNano()),
		Timestamp:  now,
		Sensor:     source,
		Category:   strings.Join(decision.Categories, ","),
		EventType:  "PROCESS_EXEC",
		EntityID:   fmt.Sprintf("PID:%d", p.PID),
		Actor:      fmt.Sprintf("UID:%d", p.UID),
		Severity:   severity,
		Confidence: decision.ResponseScore,
		CausalEdge: EdgeForkedFrom,
		EventUUID:  incidentID,
		Metadata: map[string]string{
			"comm":   p.Comm,
			"exe":    p.Exe,
			"remote": decision.Remote,
		},
	}
	var storyNodes []AttackStoryNode
	recordHash := storyNode.ComputeNodeDigest()
	execChainID := storyNode.NodeID
	if e.correlator != nil {
		actorStr := fmt.Sprintf("UID:%d", p.UID)
		categoryStr := "EXEC"
		if len(decision.Categories) > 0 {
			categoryStr = decision.Categories[0]
		}
		graph, _, err := e.correlator.IngestEvent(now, actorStr, p.Comm, categoryStr, storyNode)
		if err == nil && graph != nil {
			storyNodes = graph.CloneNodes()
			recordHash = graph.EvidenceRoot()
			execChainID = graph.ChainID
		}
	}
	if len(storyNodes) == 0 {
		storyNodes = []AttackStoryNode{storyNode}
	}

	incident := XDRIncident{
		ID: incidentID, Time: now, Severity: severity, Score: decision.Score, ResponseScore: decision.ResponseScore, KillSignals: decision.KillSignals,
		PID: p.PID, PPID: p.PPID, StartTicks: p.StartTicks, UID: p.UID, Process: p.Comm, Executable: p.Exe,
		Parent: p.ParentExe, Remote: decision.Remote, CommandPreview: e.rules.RedactCommand(p.Cmdline, runtime.XDRFabric.CommandPreviewBytes),
		CommandSHA256: p.CmdSHA256, RuleIDs: decision.RuleIDs, Categories: decision.Categories, Summary: decision.Summary,
		Decision: decision.Decision, Action: "none", Outcome: "observed",
		ExecutionChainID: execChainID, AttackStory: storyNodes, EvidenceRoot: recordHash,
	}
	if permitDecision != nil {
		// V6.3.0 AP-7: attach the bounded permit metadata to the downgraded
		// finding (absent for findings no permit explained).
		incident.Permit = permitDecision
	}
	incident.Action, incident.Outcome = e.respond(incident)
	e.appendIncident(incident)
	e.state.AddEvent(Event{Severity: severity, Kind: "xdr." + incident.Decision, Source: source, Message: incident.Summary + " [" + strings.Join(incident.RuleIDs, ",") + "]", Target: fmt.Sprintf("pid:%d", p.PID)})
}

func (e *XDREngine) respond(i XDRIncident) (string, string) {
	if degraded, _ := e.degradedState(); degraded {
		return "none", "XDR degraded; active response disabled"
	}
	_, xdrMode := e.state.Modes()
	if xdrMode == "observe" || i.Decision == "alert" {
		return "none", "observe mode"
	}
	if e.core == nil {
		return "none", "response broker unavailable"
	}
	if e.state.EvidenceLedger() != nil {
		if err := e.state.RecordEvidence(EvidenceRecord{
			Severity: i.Severity, Kind: "xdr.response.intent", Source: "xdr",
			Message: "Automated response authorized by independently scored evidence",
			Target:  fmt.Sprintf("pid:%d:start:%d:decision:%s", i.PID, i.StartTicks, i.Decision),
		}); err != nil {
			return "none", "mandatory evidence commit failed; active response disabled"
		}
	}

	quarantined := false
	if i.Remote != "" && (containsString(i.RuleIDs, "XDR.THREAT_INTEL_C2") || containsString(i.RuleIDs, "KD.LINUX.REVERSE_SHELL")) {
		if err := e.quarantineRemote(i.Remote, i); err == nil {
			quarantined = true
		} else {
			e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.quarantine_failed", Source: "response", Message: err.Error(), Target: i.Remote})
		}
	}
	rule := responseRule(i.RuleIDs)
	if xdrMode == "contain" || i.Decision == "contain" {
		// F-HOTFIX-3: every process freeze must be owned by the reversible
		// response engine so it carries a TTL and a rollback record. The
		// privileged core can SIGSTOP a process, but only the response engine
		// schedules the matching SIGCONT and keeps it across a restart. An
		// untracked fallback would leave the process frozen forever.
		if e.responses == nil || i.PID <= 0 {
			return actionName(quarantined, "none"), "failed: reversible response engine unavailable; untracked freeze refused"
		}
		respRec, err := e.responses.ApplyResponse(
			context.Background(),
			time.Now().UTC(),
			i.ID,
			ActionFreezeExecution,
			"PID",
			strconv.Itoa(i.PID),
			i.Score,
			rule,
			i.EvidenceRoot,
		)
		if err != nil {
			return actionName(quarantined, "none"), "failed: " + err.Error()
		}
		return actionName(quarantined, "stop"), fmt.Sprintf("process frozen through reversible response engine (TTL=%s)", respRec.ExpiresAt.Sub(respRec.StartedAt))
	}
	if i.Decision == "kill" && xdrMode == "enforce" {
		// M2.3: an evidence-backed ransom kill must terminate the whole process
		// tree (child workers otherwise keep encrypting). Every other kill keeps the
		// historical single-pidfd path.
		if strings.HasPrefix(rule, "XDR.RANSOM_") && e.core != nil {
			killed, killErr := e.core.KillTree(i.PID, i.StartTicks, rule)
			if killErr != nil {
				if stopErr := e.core.Stop(i.PID, i.StartTicks, rule); stopErr != nil {
					return actionName(quarantined, "kill-tree"), "tree kill rejected and containment failed: " + killErr.Error() + "; " + stopErr.Error()
				}
				return actionName(quarantined, "stop"), "tree kill rejected; process frozen for operator review: " + killErr.Error()
			}
			return actionName(quarantined, "kill-tree"), fmt.Sprintf("process tree terminated through authenticated tree-kill broker (%d process(es))", killed)
		}
		if err := e.core.Kill(i.PID, i.StartTicks, rule); err != nil {
			if stopErr := e.core.Stop(i.PID, i.StartTicks, rule); stopErr != nil {
				return actionName(quarantined, "kill"), "broker rejected kill and containment failed: " + err.Error() + "; " + stopErr.Error()
			}
			return actionName(quarantined, "stop"), "broker rejected kill; process frozen for operator review: " + err.Error()
		}
		return actionName(quarantined, "kill"), "process terminated through authenticated pidfd broker"
	}
	return actionName(quarantined, "none"), "policy did not authorize active response"
}

func actionName(quarantined bool, action string) string {
	if quarantined {
		return "network-quarantine+" + action
	}
	return action
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func (e *XDREngine) quarantineRemote(remote string, incident XDRIncident) error {
	ip := net.ParseIP(remote)
	if ip == nil || !isPublicIP(ip.String()) {
		return fmt.Errorf("remote quarantine rejected invalid public IP")
	}
	target := ip.String()
	if ip.To4() != nil {
		target += "/32"
	} else {
		target += "/128"
	}
	enforced := false
	enforcement, _ := e.state.Modes()
	if enforcement == "enforce" {
		if err := e.core.Add(target); err != nil {
			return fmt.Errorf("kernel quarantine failed: %w", err)
		}
		enforced = true
	}
	maxBlocks := e.cfg.Defense.MaxBlockEntries
	if runtime := e.runtimeSettings(); runtime.Network.MaxBlockEntries > 0 {
		maxBlocks = runtime.Network.MaxBlockEntries
	}
	containTTL := 15 * time.Minute
	if runtime := e.runtimeSettings(); runtime.XDRFabric.ContainmentTTLSeconds > 0 {
		containTTL = time.Duration(runtime.XDRFabric.ContainmentTTLSeconds) * time.Second
	}
	block, err := e.state.AddBlock(target, "XDR containment: "+strings.Join(incident.RuleIDs, ","), "xdr", containTTL, enforced, maxBlocks)
	if err != nil {
		if enforced {
			if rollbackErr := e.core.Delete(target); rollbackErr != nil {
				var failSafeErr error
				if e.release != nil {
					failSafeErr = e.release.FailSafe("XDR quarantine rollback failed")
				}
				return errors.Join(err, fmt.Errorf("kernel rollback failed: %w", rollbackErr), failSafeErr)
			}
		}
		return err
	}
	if e.policy != nil {
		// Persist through the central funnel, never directly: it refuses to re-sign a policy
		// document the platform could not verify (errPolicyUnverified) and publishes the refusal
		// event. Writing e.policy.Persist here bypassed exactly that guard (FIND-013 funnel gap).
		if err := persistPolicy(e.policy, e.cfg, e.state); err != nil {
			e.state.RemoveBlockByID(block.ID)
			if enforced {
				if rollbackErr := e.core.Delete(target); rollbackErr != nil {
					var failSafeErr error
					if e.release != nil {
						failSafeErr = e.release.FailSafe("XDR quarantine policy rollback failed")
					}
					return errors.Join(err, fmt.Errorf("kernel rollback failed: %w", rollbackErr), failSafeErr)
				}
			}
			return fmt.Errorf("signed policy persistence failed: %w", err)
		}
	}
	e.state.AddEvent(Event{Severity: "high", Kind: "xdr.network_quarantine", Source: "response", Message: "Remote endpoint quarantined for 15 minutes", Target: target})
	return nil
}

func responseRule(ids []string) string {
	for _, preferred := range []string{"XDR.MEMFD_EXEC", "XDR.EXE_DELETED", "XDR.TEMP_EXEC", "KD.LINUX.DESTRUCTIVE"} {
		for _, id := range ids {
			if id == preferred {
				return id
			}
		}
	}
	if len(ids) == 0 {
		return "XDR.UNKNOWN"
	}
	return ids[0]
}

func (e *XDREngine) claimFingerprint(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	if until, ok := e.dedupe[key]; ok && now.Before(until) {
		return false
	}
	e.dedupe[key] = now.Add(time.Duration(e.runtimeSettings().XDRFabric.DedupeSeconds) * time.Second)
	return true
}

func (e *XDREngine) cleanupDedupe(now time.Time) {
	e.mu.Lock()
	for k, until := range e.dedupe {
		if !until.After(now) {
			delete(e.dedupe, k)
		}
	}
	e.mu.Unlock()
}

// ApplyRuntimeSettings applies the hot-reloadable XDR settings. Queue capacity,
// worker count and integrity watch roots are persisted but require a controlled
// service restart because the underlying channels/watchers are created at boot.
// The Host Security namespace is projected onto the RASP, deception and Airlock
// engines from the same revision, so one apply never leaves them inconsistent.
func (e *XDREngine) ApplyRuntimeSettings(settings RuntimeSettings) error {
	if e == nil {
		return nil
	}
	if err := e.rules.Configure(settings); err != nil {
		return err
	}
	if e.behavior != nil {
		e.behavior.Configure(settings.XDRFabric)
	}
	hardening := effectiveHardeningSettings(settings)
	if err := applyHardeningPolicy(hardening, e.morpheus, e.airlock, e.deception); err != nil {
		return err
	}
	// POINT 3 / P3-T5: project the StyX namespace onto the detector immediately and
	// hand the desired kernel policy to the syncer. The syncer is asynchronous on
	// purpose: an old core or a temporary IPC failure must never roll back an
	// operator's settings revision. It reports applied/pending/failed/capability-
	// missing in its own status instead of pretending consent.
	e.applyStyxBeaconSettings(settings)
	if e.styxPolicy != nil {
		e.styxPolicy.Configure(settings)
	}
	// POINT 1 / P1-T5: hand the desired exec-gate revision to its syncer. It is
	// asynchronous on purpose: a pre-TitanExec core or a transient IPC failure must
	// never roll back the operator's settings, and the syncer reports
	// applied/pending/inactive/capability-missing in its own status.
	if e.titanExec != nil {
		e.titanExec.Configure(settings)
	}
	// POINT 2 / P2-T3: project the parser-cell namespace onto the manager. It never
	// contacts the helper here; the supervisor applies the revision asynchronously.
	if e.parserCells != nil {
		e.parserCells.Configure(settings)
	}
	return nil
}

// ------------------------------------------------- Titan exec-gate projection
//
// POINT 1 / P1-T5: read-only accessors for the kernel exec gate. None of them
// derives an enforcement claim: the sync status reports what the core applied,
// the sensor state reports whether decisions are actually being drained, and the
// kernel facts (path/lsm/offsets) are carried through verbatim.

// TitanExecPolicyStatus returns the structured sync status of the exec-gate
// policy syncer. It is the method fabric_settings.go's titanExecStatusSource
// detects, so the settings module recognizes the wired runtime automatically.
// Without a wired syncer the honest unavailable state is returned.
func (e *XDREngine) TitanExecPolicyStatus() TitanExecSyncStatus {
	if e == nil || e.titanExec == nil {
		return titanExecUnavailableStatus()
	}
	return e.titanExec.Snapshot()
}

// setTitanExecCapability records the negotiated ABI fact. Only transitions are
// operator-visible, and a missing capability is a fact, never an XDR degradation
// (§7.3): an old core must not be reported as a detection outage.
func (e *XDREngine) setTitanExecCapability(available bool) {
	if e == nil {
		return
	}
	next := titanExecCapabilityMissing
	if available {
		next = titanExecCapabilityAvailable
	}
	e.titanExecMu.Lock()
	previous := e.titanExecCapability
	e.titanExecCapability = next
	e.titanExecMu.Unlock()
	if previous == next || e.state == nil {
		return
	}
	switch {
	case available && previous == titanExecCapabilityMissing:
		e.state.AddEvent(Event{Severity: "info", Kind: "titan_exec.capability_available", Source: "titan-exec",
			Message: "The privileged core advertises the TITAN_EXEC_* command family again; kernel exec-gate decisions are drained"})
	case !available && previous == titanExecCapabilityAvailable:
		e.state.AddEvent(Event{Severity: "info", Kind: "titan_exec.capability_missing", Source: "titan-exec",
			Message: "The privileged core no longer advertises the TITAN_EXEC_* command family; no kernel exec-gate decisions are available. This is a capability fact, not an XDR degradation"})
	}
}

// titanExecHealthSnapshot returns the last kernel health sample and the recorded
// per-channel errors (health command, event drain) for the status view.
func (e *XDREngine) titanExecHealthSnapshot() (CoreTitanExecHealth, *time.Time, string, string) {
	if e == nil {
		return CoreTitanExecHealth{}, nil, "", ""
	}
	e.titanExecMu.Lock()
	defer e.titanExecMu.Unlock()
	var at *time.Time
	if !e.titanExecHealthAt.IsZero() {
		sampled := e.titanExecHealthAt
		at = &sampled
	}
	return e.titanExecHealth, at, e.titanExecHealthErr, e.titanExecDrainErr
}

// titanExecSensorState derives the honest ingestion state. It never says
// "active" for a namespace whose kernel hook is not attached: unavailable
// capability and inactive/unattached sync states win over a configured mode.
func (e *XDREngine) titanExecSensorState() string {
	if e == nil || e.titanExec == nil {
		return "unavailable"
	}
	if !e.titanExecCapabilityKnown() {
		return "unavailable"
	}
	sync := e.TitanExecPolicyStatus()
	switch sync.State {
	case TitanExecSyncStateCapabilityMissing, TitanExecSyncStateUnavailable:
		return "unavailable"
	case TitanExecSyncStateInactive:
		return "inactive"
	case TitanExecSyncStateFailed:
		return "degraded"
	}
	if !sync.Enabled || sync.Mode == TitanExecModeOff {
		return "inactive"
	}
	if e.titanExecSensorCauseSet() {
		return "degraded"
	}
	if sync.State == TitanExecSyncStatePending {
		return "pending"
	}
	return "active"
}

func titanExecCountersView(stats titanExecEventCounters) TitanExecEventCountersView {
	return TitanExecEventCountersView{
		EventsTotal: stats.EventsTotal, Denies: stats.Denies, Audits: stats.Audits,
		Dropped: stats.Dropped, ParseErrors: stats.ParseErrors, Incidents: stats.Incidents,
	}
}

func titanExecActionName(action uint8) string {
	if action == titanExecActionDeny {
		return "denied"
	}
	return "audited"
}
