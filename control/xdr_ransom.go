// STATUS: DIAMANT VGT SUPREME
package main

// M2.2: kernel ransomware sensor integration.
//
// The Rust core freezes a process group with SIGSTOP as soon as its own VFS
// sensor sees an entropy burst or a rename/unlink storm. The Go control plane
// must never ignore that freeze and must never leave it behind: for every record
// it either escalates with an evidence-backed tree kill (enforce mode only) or
// releases the freeze again with GROUP_CONT. A failed release is reported as a
// critical operator condition instead of silently disappearing.
//
// Ransom sensing is an observation of the kernel, so the record itself is
// objective evidence; there is no heuristic auto-kill without that record.

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ransomStartTicksHook resolves the frozen TGID identity for the tree kill. It
// is a variable so the escalation contract can be tested without depending on
// the test runner's live PID namespace; production always uses
// ransomProcStartTicks (`/proc/<pid>/stat`, field 22).
var ransomStartTicksHook = ransomProcStartTicks

// ransomCore is the subset of the privileged client the ransomware integration
// needs. It is an interface so the escalation/release contract is testable with
// synthetic kernel answers and no privileged core.
type ransomCore interface {
	KillTree(pid int, startTicks uint64, rule string) (int, error)
	StopGroup(pgid int, rule string) error
	ResumeGroup(pgid int, rule string) error
	RansomSet(enabled bool) error
	RansomEvents() ([]CoreRansomEvent, uint64, error)
	RansomStatus() (CoreRansomStatus, error)
}

// RansomSensorStatus is the honest operator projection of the kernel sensor. It
// distinguishes "no capability" from "disarmed by the core", "armed but the LSM
// hook is not attached" and an active sensor.
type RansomSensorStatus struct {
	State         string     `json:"state"` // active | disarmed | degraded | unavailable
	Capability    string     `json:"capability"`
	Armed         bool       `json:"armed"`
	Attached      bool       `json:"attached"`
	Emitted       uint64     `json:"emitted"`
	Drops         uint64     `json:"drops"`
	StopsOK       uint64     `json:"stops_ok"`
	StopsFailed   uint64     `json:"stops_failed"`
	StopsSkipped  uint64     `json:"stops_skipped"`
	TrackFailures uint64     `json:"track_failures"`
	Reason        string     `json:"reason,omitempty"`
	SampledAt     *time.Time `json:"sampled_at,omitempty"`
}

func ransomRuleForReason(reason string) (string, int) {
	switch reason {
	case RansomReasonEntropyBurst:
		return "XDR.RANSOM_ENTROPY_BURST", 145
	case RansomReasonRenameStorm:
		return "XDR.RANSOM_RENAME_STORM", 135
	default:
		return "", 0
	}
}

// ransomEscalationAllowed reports whether an automatic tree kill is allowed.
// The freeze by itself is always applied by the kernel; only an enforce-mode XDR
// deployment may escalate from freeze to kill.
func (e *XDREngine) ransomEscalationAllowed() bool {
	if e == nil || !e.runtimeSettings().XDREnabled {
		return false
	}
	mode, _ := e.state.Modes()
	return strings.EqualFold(strings.TrimSpace(mode), "enforce")
}

// consumeRansomStatus classifies one RANSOM_STATUS answer. A pre-M2.2 core is a
// capability fact; any other failure is reported as a degraded sensor.
func (e *XDREngine) consumeRansomStatus(status CoreRansomStatus, statusErr error, now time.Time) {
	if e == nil {
		return
	}
	e.ransomMu.Lock()
	wasKnown := e.ransomCapabilityKnown
	if statusErr == nil {
		e.ransomStatus = status
		e.ransomStatusAt = now
		e.ransomStatusErr = ""
		e.ransomCapabilityKnown = true
	} else if errors.Is(statusErr, ErrRansomUnavailable) {
		e.ransomCapabilityKnown = false
		e.ransomStatus = CoreRansomStatus{}
		e.ransomStatusAt = time.Time{}
		e.ransomStatusErr = ""
	} else {
		e.ransomStatusErr = boundedStyxText(statusErr)
	}
	known := e.ransomCapabilityKnown
	e.ransomMu.Unlock()
	if e.state != nil {
		switch {
		case !known && wasKnown:
			e.state.AddEvent(Event{Severity: "info", Kind: "xdr.ransom_capability_missing", Source: "kernel",
				Message: "The privileged core no longer advertises the RANSOM_* command family; kernel ransomware freeze protection is unavailable (capability fact, not an XDR degradation)"})
		case known && !wasKnown:
			e.state.AddEvent(Event{Severity: "info", Kind: "xdr.ransom_capability_available", Source: "kernel",
				Message: "Kernel ransomware sensor is available; freeze records are drained and released or escalated with evidence"})
		}
	}
}

// consumeRansomEvents handles one drained batch and returns the next drain delay.
func (e *XDREngine) consumeRansomEvents(events []CoreRansomEvent, dropped uint64, drainErr error, now time.Time, escalationAllowed bool) time.Duration {
	if e == nil {
		return 10 * time.Second
	}
	if drainErr != nil {
		if errors.Is(drainErr, ErrRansomUnavailable) {
			e.consumeRansomStatus(CoreRansomStatus{}, ErrRansomUnavailable, now)
			return 10 * time.Second
		}
		e.ransomMu.Lock()
		e.ransomStatusErr = boundedStyxText(drainErr)
		e.ransomMu.Unlock()
		return 10 * time.Second
	}
	if len(events) > 0 {
		e.handleRansomEvents(events, now, escalationAllowed)
	}
	if dropped > 0 && e.state != nil {
		e.ransomMu.Lock()
		last := e.ransomLastOverflow
		if last.IsZero() || now.Sub(last) >= 5*time.Minute {
			e.ransomLastOverflow = now
			e.ransomMu.Unlock()
			e.state.AddEvent(Event{Severity: "high", Kind: "xdr.ransom_overflow", Source: "kernel",
				Message: fmt.Sprintf("Kernel ransomware sensor dropped %d freeze record(s); visibility is reduced but every reported freeze is still handled", dropped)})
		} else {
			e.ransomMu.Unlock()
		}
	}
	// Drain on the 100 ms execTick, not once per second: the kernel freezes the
	// process group only when this function calls the core, so a one-second
	// idle pause was enough for a fast encryptor to finish hundreds of files
	// before the SIGSTOP was issued. 100 ms is the control-plane tick budget;
	// the core-side arm state is already set at load when a kprobe attached.
	return 100 * time.Millisecond
}

func (e *XDREngine) handleRansomEvents(events []CoreRansomEvent, now time.Time, escalationAllowed bool) {
	for _, event := range events {
		ruleID, score := ransomRuleForReason(event.Reason)
		if ruleID == "" {
			continue
		}
		if !e.claimRansomRecord(event, now) {
			continue
		}
		summary := fmt.Sprintf("Kernel ransomware sensor froze process group %d (%s): %s, %d event(s) in the detection window",
			event.PGID, event.Comm, event.Reason, event.Count)
		evidenceErr := e.state.RecordEvidence(EvidenceRecord{
			Severity: "critical", Kind: "xdr.ransom_freeze", Source: "kernel",
			Message: "Kernel ransomware freeze evidence recorded before any response: " + summary,
			Target:  fmt.Sprintf("pgid:%d", event.PGID), Time: now,
		})
		action := "none"
		outcome := ""
		if evidenceErr != nil {
			outcome = "freeze retained by the kernel; mandatory evidence commit failed, so no automatic response was issued: " + evidenceErr.Error()
		} else if escalationAllowed && e.ransomCore != nil {
			startTicks, ticksErr := ransomStartTicksHook(event.TGID)
			if ticksErr != nil {
				outcome = "freeze retained; the control plane could not resolve the frozen TGID start-time identity, so no tree kill was attempted: " + ticksErr.Error()
			} else {
				killed, killErr := e.ransomCore.KillTree(event.TGID, startTicks, ruleID)
				switch {
				case killErr != nil && strings.Contains(strings.ToLower(killErr.Error()), "protected"):
					if resumeErr := e.ransomCore.ResumeGroup(event.PGID, ruleID); resumeErr != nil {
						outcome = fmt.Sprintf("freeze retained; protected target rejected tree kill (%v) and resume failed: %v", killErr, resumeErr)
					} else {
						action = "resume"
						outcome = fmt.Sprintf("freeze released: protected target rejected tree kill (%v)", killErr)
					}
				case killErr != nil:
					outcome = "freeze retained; evidence-backed tree kill was rejected: " + killErr.Error()
				case killed == 0:
					outcome = "freeze retained; tree kill matched no process (identity already gone), operator review"
				default:
					action = "kill-tree"
					outcome = fmt.Sprintf("process tree terminated through the authenticated tree-kill broker (%d process(es))", killed)
				}
			}
		} else if e.ransomCore != nil {
			if resumeErr := e.ransomCore.ResumeGroup(event.PGID, ruleID); resumeErr != nil {
				outcome = "freeze retained; non-escalation resume failed, process group stays frozen for operator review: " + resumeErr.Error()
			} else {
				action = "resume"
				outcome = "freeze released again: no enforce-mode escalation policy is active"
			}
		} else {
			outcome = "freeze retained; privileged core client unavailable, operator review required"
		}
		decision := "freeze"
		if action == "kill-tree" {
			decision = "kill-tree"
		} else if action == "resume" {
			decision = "resume"
		}
		incident := XDRIncident{
			ID: randomID(), Time: now, Severity: "critical", Score: score,
			PID: event.TGID, UID: event.UID, Process: event.Comm,
			RuleIDs: []string{ruleID}, Categories: []string{"impact", "ransomware"},
			Summary: summary, Decision: decision, Action: action, Outcome: outcome,
		}
		e.appendIncident(incident)
		severity := "critical"
		e.state.AddEvent(Event{Time: now, Severity: severity, Kind: "xdr." + ruleID, Source: "kernel",
			Message: summary + "; " + outcome, Target: fmt.Sprintf("pgid:%d", event.PGID)})
		if action == "none" && ransomOutcomeNeedsOperator(outcome) {
			e.state.AddEvent(Event{Time: now, Severity: "critical", Kind: "xdr.ransom_freeze_orphaned", Source: "kernel",
				Message: "A kernel-frozen process group has no automated release: " + outcome, Target: fmt.Sprintf("pgid:%d", event.PGID)})
		}
	}
}

func ransomOutcomeNeedsOperator(outcome string) bool {
	return strings.Contains(outcome, "resume failed") || strings.Contains(outcome, "unavailable") || strings.Contains(outcome, "rejected")
}

// claimRansomRecord deduplicates one kernel record (bounded window). Records
// themselves are unique by timestamp+tgid+reason; a duplicated drain of the same
// record must not create a second incident.
func (e *XDREngine) claimRansomRecord(event CoreRansomEvent, now time.Time) bool {
	key := fmt.Sprintf("%d|%d|%s|%d", event.TGID, event.PGID, event.Reason, event.TsNS)
	e.ransomMu.Lock()
	defer e.ransomMu.Unlock()
	if e.ransomSeen == nil {
		e.ransomSeen = make(map[string]time.Time)
	}
	if until, exists := e.ransomSeen[key]; exists && now.Before(until) {
		return false
	}
	e.ransomSeen[key] = now.Add(5 * time.Minute)
	if len(e.ransomSeen) > 4096 {
		for seenKey, until := range e.ransomSeen {
			if !until.After(now) {
				delete(e.ransomSeen, seenKey)
			}
		}
	}
	return true
}

// RansomSensorReport returns the honest operator view of the kernel sensor.
func (e *XDREngine) RansomSensorReport() RansomSensorStatus {
	report := RansomSensorStatus{State: "unavailable", Capability: "unknown"}
	if e == nil {
		return report
	}
	e.ransomMu.Lock()
	status := e.ransomStatus
	sampled := e.ransomStatusAt
	statusErr := e.ransomStatusErr
	known := e.ransomCapabilityKnown
	e.ransomMu.Unlock()
	report.Armed = status.Armed
	report.Attached = status.Attached
	report.Emitted = status.Emitted
	report.Drops = status.Drops
	report.StopsOK = status.StopsOK
	report.StopsFailed = status.StopsFailed
	report.StopsSkipped = status.StopsSkipped
	report.TrackFailures = status.TrackFailures
	if !sampled.IsZero() {
		at := sampled
		report.SampledAt = &at
	}
	switch {
	case !known:
		if statusErr != "" {
			report.State = "degraded"
			report.Capability = "missing"
			report.Reason = "ransom status query failed: " + statusErr
		} else {
			report.State = "unavailable"
			report.Capability = "missing"
			report.Reason = "the privileged core does not advertise the RANSOM_* command family"
		}
	case statusErr != "":
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "ransom event drain failed: " + statusErr
	case !status.Armed:
		report.State = "disarmed"
		report.Capability = "available"
		report.Reason = "kernel ransomware sensor is armed off (RANSOM_SET 0)"
	case !status.Attached:
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "sensor is armed but the kernel LSM hook is not attached; freeze protection is inactive"
	default:
		report.State = "active"
		report.Capability = "available"
	}
	if status.StopsFailed > 0 && report.Reason == "" {
		report.Reason = fmt.Sprintf("%d kernel freeze stop(s) failed; unfrozen processes are reported individually", status.StopsFailed)
	}
	return report
}
