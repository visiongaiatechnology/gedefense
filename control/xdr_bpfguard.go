// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"time"
)

// V6.3.0 AP-2: XDR integration of the attach-time eBPF guard.
//
// Maps the helper-risk bitmap to `XDR.BPF_ANOMALY` (any observed attach of an
// untolerated loader, score 45, observe-only) and `XDR.BPF_ROOTKIT_HELPER`
// (>= 2 high-risk helper bits within one hour for the same loader process, or a
// load from /tmp, /var/tmp, /dev/shm or a shell lineage; score 120, alert-only).
// Dev-/observability-tool loaders (bpftrace, perf, cilium, falco, tetragon,
// cargo, go, gcc, ...) are TOLERATED by the control plane — never silently by
// the kernel — and only produce an info event.
//
// Both rules are evidence-first (RecordEvidence before the incident; an evidence
// failure is recorded in the incident outcome), emit an attack-story node and
// set `Action:"none"`. The guard never derives an active response: no kill path,
// no containment and no change to `combineMatches` are introduced here.

// bpfGuardCore is the subset of the privileged client the AP-2 contract needs.
type bpfGuardCore interface {
	BpfGuardSet(enabled bool) error
	BpfGuardStatus() (CoreBpfGuardStatus, error)
	BpfGuardEvents() ([]CoreBpfGuardEvent, uint64, error)
	BpfGuardEpoch() (string, error)
}

// pollBpfGuard runs one status + drain cycle and returns the next due time. The
// XDR loop ticks every 100 ms; this returns the drain cadence (1 s) and performs
// the status query only when its 5 s cadence is due, so neither can delay the
// other ingestion path.
func (e *XDREngine) pollBpfGuard(runtime RuntimeSettings, now time.Time, retryAfter time.Time) time.Time {
	if e == nil || e.bpfGuardCore == nil || !runtime.XDREnabled || now.Before(retryAfter) {
		return retryAfter
	}
	if e.bpfGuardStatusDue(now) {
		status, statusErr := e.bpfGuardCore.BpfGuardStatus()
		e.consumeBpfGuardStatus(status, statusErr, now)
		if statusErr == nil {
			// Arm the observe-only guard once. The core arms itself at load; this
			// covers a core that was explicitly disarmed and then upgraded, and
			// keeps a later operator disarm authoritative (the request latches).
			if !status.Enabled && !e.bpfGuardArmedRequested {
				e.bpfGuardArmedRequested = true
				if err := e.bpfGuardCore.BpfGuardSet(true); err != nil {
					e.bpfGuardArmedRequested = false
					e.setBpfGuardStatusError(err)
				}
			}
			e.bpfGuardFetchEpoch()
		}
	}
	events, dropped, drainErr := e.bpfGuardCore.BpfGuardEvents()
	if drainErr != nil {
		if errors.Is(drainErr, ErrBpfGuardUnavailable) {
			e.consumeBpfGuardStatus(CoreBpfGuardStatus{}, ErrBpfGuardUnavailable, now)
		} else {
			// Never pretend healthy: the report shows degraded with this reason
			// until the drain succeeds again.
			e.setBpfGuardDrainError(drainErr)
		}
		return now.Add(bpfGuardDrainInterval)
	}
	e.clearBpfGuardDrainError()
	e.consumeBpfGuardEvents(events, dropped, now)
	return now.Add(bpfGuardDrainInterval)
}

func (e *XDREngine) bpfGuardStatusDue(now time.Time) bool {
	e.bpfGuardMu.Lock()
	defer e.bpfGuardMu.Unlock()
	return e.bpfGuardStatusAt.IsZero() || now.Sub(e.bpfGuardStatusAt) >= bpfGuardStatusInterval
}

func (e *XDREngine) setBpfGuardStatusError(err error) {
	if e == nil || err == nil {
		return
	}
	e.bpfGuardMu.Lock()
	e.bpfGuardStatusErr = "status query failed: " + boundedStyxText(err)
	e.bpfGuardMu.Unlock()
}

func (e *XDREngine) setBpfGuardDrainError(err error) {
	if e == nil || err == nil {
		return
	}
	e.bpfGuardMu.Lock()
	e.bpfGuardStatusErr = "event drain failed: " + boundedStyxText(err)
	e.bpfGuardMu.Unlock()
}

// clearBpfGuardDrainError forgets only a drain-origin error; a persistent
// status-query failure is cleared by the next successful status query.
func (e *XDREngine) clearBpfGuardDrainError() {
	if e == nil {
		return
	}
	e.bpfGuardMu.Lock()
	if strings.HasPrefix(e.bpfGuardStatusErr, "event drain failed:") {
		e.bpfGuardStatusErr = ""
	}
	e.bpfGuardMu.Unlock()
}

// bpfGuardFetchEpoch caches the per-boot epoch once (best effort; a failure is
// recorded as a degraded status reason but never blocks the drain).
func (e *XDREngine) bpfGuardFetchEpoch() {
	e.bpfGuardMu.Lock()
	known := e.bpfGuardEpoch != ""
	e.bpfGuardMu.Unlock()
	if known {
		return
	}
	epoch, err := e.bpfGuardCore.BpfGuardEpoch()
	if err != nil {
		e.setBpfGuardStatusError(err)
		return
	}
	e.bpfGuardMu.Lock()
	e.bpfGuardEpoch = epoch
	e.bpfGuardMu.Unlock()
}

func (e *XDREngine) consumeBpfGuardStatus(status CoreBpfGuardStatus, statusErr error, now time.Time) {
	if e == nil {
		return
	}
	e.bpfGuardMu.Lock()
	wasKnown := e.bpfGuardCapabilityKnown
	if statusErr == nil {
		e.bpfGuardStatus = status
		e.bpfGuardStatusAt = now
		e.bpfGuardStatusErr = ""
		e.bpfGuardCapabilityKnown = true
	} else if errors.Is(statusErr, ErrBpfGuardUnavailable) {
		e.bpfGuardCapabilityKnown = false
		e.bpfGuardStatus = CoreBpfGuardStatus{}
		e.bpfGuardStatusAt = time.Time{}
		e.bpfGuardStatusErr = ""
		e.bpfGuardEpoch = ""
	} else {
		e.bpfGuardStatusErr = "status query failed: " + boundedStyxText(statusErr)
	}
	known := e.bpfGuardCapabilityKnown
	e.bpfGuardMu.Unlock()
	if e.state == nil {
		return
	}
	switch {
	case !known && wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.bpf_guard_capability_missing", Source: "kernel",
			Message: "The privileged core no longer advertises the BPF_GUARD_* command family; attach-time eBPF visibility is unavailable (capability fact, not an XDR degradation)"})
	case known && !wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.bpf_guard_capability_available", Source: "kernel",
			Message: "Attach-time eBPF guard is available; BPF load/attach records and helper-risk bitmaps are ingested (observe-only)"})
	}
}

// consumeBpfGuardEvents turns one bounded kernel batch into evidence/incidents.
func (e *XDREngine) consumeBpfGuardEvents(events []CoreBpfGuardEvent, dropped uint64, now time.Time) {
	if e == nil {
		return
	}
	for _, event := range events {
		if !e.claimBpfGuardRecord(event, now) {
			continue
		}
		if tolerated, reason := e.bpfGuardEventTolerated(event); tolerated {
			if e.state != nil && reason != "own core daemon" && reason != "own control process" {
				e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.bpf_guard_tolerated", Source: "kernel",
					Message: fmt.Sprintf("Tolerated BPF loader activity observed: pid=%d tgid=%d uid=%d comm=%s action=%s command=%s (%s)",
						event.PID, event.TGID, event.UID, event.Comm, bpfGuardActionName(event.Action), bpfGuardCommandName(event.Command), reason),
					Target: fmt.Sprintf("pid:%d", event.PID)})
			}
			continue
		}
		e.recordBpfGuardFinding(event, now)
	}
	if dropped > 0 && e.state != nil {
		e.bpfGuardMu.Lock()
		last := e.bpfGuardLastOverflow
		if last.IsZero() || now.Sub(last) >= bpfGuardOverflowMinGap {
			e.bpfGuardLastOverflow = now
			e.bpfGuardMu.Unlock()
			e.state.AddEvent(Event{Severity: "high", Kind: "xdr.bpf_guard_overflow", Source: "kernel",
				Message: fmt.Sprintf("Attach-time eBPF guard dropped %d record(s); BPF load/attach visibility is reduced", dropped)})
		} else {
			e.bpfGuardMu.Unlock()
		}
	}
}

func (e *XDREngine) resolveProcessPath(pid int) string {
	if pid <= 0 {
		return "unknown"
	}
	if e != nil && e.execPathOverride != nil {
		return e.execPathOverride(pid)
	}
	return titanExecProcessPath(uint32(pid))
}

// bpfGuardEventTolerated is the single TOLERATED policy enforcement point for
// untrusted kernel records. A loader is never tolerated solely on mutable task
// `comm` (`prctl(PR_SET_NAME)` spoofing); its verified executable path must be
// known and not in a writable drop path:
//  1. own control process (`selfPID`) or SO_PEERCRED-verified core daemon (`CorePID`),
//  2. installation-managed executable path (/usr/bin, /usr/sbin, /usr/local/bin,
//     /opt, /usr/lib/systemd, /usr/libexec), or
//  3. PermitV1-style trusted parent's non-shell, non-temp verified child binary.
func (e *XDREngine) bpfGuardEventTolerated(event CoreBpfGuardEvent) (bool, string) {
	if e != nil && e.selfPID > 0 && event.PID == e.selfPID {
		return true, "own control process"
	}
	if e != nil && e.core != nil && event.PID > 0 && event.PID == e.core.CorePID() {
		return true, "own core daemon"
	}
	comm := strings.ToLower(strings.TrimSpace(event.Comm))
	path := e.resolveProcessPath(event.PID)
	if path == "" || path == "unknown" {
		if resolved := resolveToleratedPathByInode(comm, event.ExeDev, event.ExeIno); resolved != "" {
			path = resolved
		}
	}
	if path == "" || path == "unknown" || bpfGuardPathUnderAny(path, bpfGuardTempPathPrefixes) {
		return false, ""
	}
	if _, ok := bpfGuardToleratedComms[comm]; ok && bpfGuardPathUnderAny(path, bpfGuardToleratedPathPrefixes) {
		return true, "tolerated loader comm"
	}
	if bpfGuardPathUnderAny(path, bpfGuardToleratedPathPrefixes) {
		return true, "installation-managed executable path"
	}
	parentPID, parentComm := bpfGuardParentInfo(event.PID)
	if parentPID > 0 && parentComm != "" {
		parentPath := e.resolveProcessPath(parentPID)
		if parentPath != "" && parentPath != "unknown" && !bpfGuardPathUnderAny(parentPath, bpfGuardTempPathPrefixes) {
			if _, ok := bpfGuardTrustedParentComms[parentComm]; ok {
				if _, shell := bpfGuardShellComms[comm]; !shell {
					return true, "trusted parent"
				}
			}
		}
	}
	return false, ""
}

// recordBpfGuardFinding creates evidence first, then exactly one alert-only
// incident for the record: XDR.BPF_ROOTKIT_HELPER when the rootkit threshold is
// met (>= 2 high-risk helper bits within one hour, or a load from a temporary
// path / shell lineage), otherwise XDR.BPF_ANOMALY. No response is derived.
func (e *XDREngine) recordBpfGuardFinding(event CoreBpfGuardEvent, now time.Time) {
	helperBits := 0
	aggregateMask := uint32(0)
	if event.Action == BpfGuardActionHelperRisk {
		aggregateMask = e.bpfGuardRememberRisk(event, now)
		helperBits = bits.OnesCount32(aggregateMask)
	}
	path := titanExecProcessPath(uint32(event.PID))
	_, parentComm := bpfGuardParentInfo(event.PID)
	tempPath := bpfGuardPathUnderAny(path, bpfGuardTempPathPrefixes)
	shellLineage := bpfGuardCommIn(parentComm, bpfGuardShellComms)

	rootkit := false
	trigger := ""
	switch {
	case event.Action == BpfGuardActionHelperRisk && helperBits >= 2:
		rootkit = true
		trigger = fmt.Sprintf("%d high-risk helper bits within one hour", helperBits)
	case tempPath:
		rootkit = true
		trigger = "BPF loader executable is in a temporary writable path"
	case shellLineage:
		rootkit = true
		trigger = "BPF loader has a shell lineage"
	}

	identity := "comm-only identity"
	if event.ExeDev != 0 || event.ExeIno != 0 {
		identity = fmt.Sprintf("dev=%d ino=%d", event.ExeDev, event.ExeIno)
	}
	helperText := bpfGuardHelperMaskText(event.HelperMask)
	idsText := bpfGuardHelperIDsText(event.HelperIDs)
	summary := fmt.Sprintf(
		"Attach-time eBPF guard observed BPF loader activity: pid=%d tgid=%d uid=%d comm=%s action=%s command=%s prog_type=%s helper_mask=%s helper_ids=%s path=%s identity=%s",
		event.PID, event.TGID, event.UID, event.Comm, bpfGuardActionName(event.Action),
		bpfGuardCommandName(event.Command), bpfGuardProgTypeName(event.ProgType),
		helperText, idsText, path, identity)

	ruleID := "XDR.BPF_ANOMALY"
	eventKind := "xdr.bpf_anomaly"
	eventType := "BPF_ATTACH_OBSERVED"
	severity := "warning"
	score := 45
	categories := []string{"kernel"}
	if rootkit {
		ruleID = "XDR.BPF_ROOTKIT_HELPER"
		eventKind = "xdr.bpf_rootkit_helper"
		eventType = "BPF_HELPER_RISK"
		severity = "high"
		score = 120
		categories = []string{"kernel", "defense-evasion"}
		summary = fmt.Sprintf("%s; rootkit trigger: %s (aggregate helper mask %s)",
			summary, trigger, bpfGuardHelperMaskText(aggregateMask))
	}

	evidenceErr := e.state.RecordEvidence(EvidenceRecord{
		Severity: severity, Kind: eventKind, Source: "kernel",
		Message: "Attach-time eBPF guard evidence recorded before any response: " + summary,
		Target:  fmt.Sprintf("pid:%d:dev:%d:ino:%d", event.PID, event.ExeDev, event.ExeIno), Time: now,
	})
	outcome := "observed only; the attach-time eBPF guard is observe-only and no active response was derived"
	if evidenceErr != nil {
		outcome = "observed only; mandatory evidence commit failed, incident recorded without response: " + evidenceErr.Error()
	}
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("bpfguard-%d-%d", event.PID, now.UnixNano()),
		Timestamp:  now,
		Sensor:     "kernel-bpf-guard",
		Category:   "kernel",
		EventType:  eventType,
		EntityID:   fmt.Sprintf("pid:%d", event.TGID),
		Actor:      fmt.Sprintf("uid:%d", event.UID),
		Severity:   severity,
		Confidence: 95,
		CausalEdge: EdgeRootCause,
		EventUUID:  randomID(),
		Metadata: map[string]string{
			"action":       bpfGuardActionName(event.Action),
			"command":      bpfGuardCommandName(event.Command),
			"prog_type":    bpfGuardProgTypeName(event.ProgType),
			"helper_mask":  helperText,
			"helper_ids":   idsText,
			"pid":          strconv.Itoa(event.PID),
			"tgid":         strconv.Itoa(event.TGID),
			"uid":          strconv.FormatUint(uint64(event.UID), 10),
			"loader_path":  path,
			"parent_comm":  parentComm,
			"ts_ns":        strconv.FormatUint(event.TsNS, 10),
			"exe_dev":      strconv.FormatUint(uint64(event.ExeDev), 10),
			"exe_ino":      strconv.FormatUint(event.ExeIno, 10),
			"observe_only": "true",
		},
	}
	node.Digest = node.ComputeNodeDigest()
	incident := XDRIncident{
		ID: randomID(), Time: now, Severity: severity, Score: score,
		PID: event.PID, UID: event.UID, Process: event.Comm,
		RuleIDs: []string{ruleID}, Categories: categories,
		Summary: summary, Decision: "alert", Action: "none", Outcome: outcome,
		ExecutionChainID: node.NodeID, AttackStory: []AttackStoryNode{node},
		EvidenceRoot: node.Digest,
	}
	e.appendIncident(incident)
	if e.state != nil {
		e.state.AddEvent(Event{Time: now, Severity: severity, Kind: eventKind, Source: "kernel",
			Message: summary + "; " + outcome, Target: fmt.Sprintf("pid:%d", event.PID)})
	}
}

// claimBpfGuardRecord dedupes by the mandated (ts,pid,action,helper_mask) key.
func (e *XDREngine) claimBpfGuardRecord(event CoreBpfGuardEvent, now time.Time) bool {
	key := fmt.Sprintf("event:%d|%d|%d|%d", event.TsNS, event.PID, event.Action, event.HelperMask)
	e.bpfGuardMu.Lock()
	defer e.bpfGuardMu.Unlock()
	if e.bpfGuardSeen == nil {
		e.bpfGuardSeen = make(map[string]time.Time)
	}
	if until, exists := e.bpfGuardSeen[key]; exists && now.Before(until) {
		return false
	}
	e.bpfGuardSeen[key] = now.Add(bpfGuardDedupeTTL)
	if len(e.bpfGuardSeen) > bpfGuardSeenLimit {
		for seenKey, until := range e.bpfGuardSeen {
			if !until.After(now) {
				delete(e.bpfGuardSeen, seenKey)
			}
		}
	}
	return true
}

// bpfGuardRememberRisk records the observed helper mask for the loader process
// and returns the aggregate of all masks seen within the one-hour window. The
// kernel bitmap is per-tgid; the control-plane aggregation therefore keys on the
// loader process (tgid), not the loading thread (pid).
func (e *XDREngine) bpfGuardRememberRisk(event CoreBpfGuardEvent, now time.Time) uint32 {
	processKey := event.TGID
	if processKey <= 0 {
		processKey = event.PID
	}
	prefix := fmt.Sprintf("risk:%d:", processKey)
	e.bpfGuardMu.Lock()
	defer e.bpfGuardMu.Unlock()
	if e.bpfGuardSeen == nil {
		e.bpfGuardSeen = make(map[string]time.Time)
	}
	e.bpfGuardSeen[prefix+strconv.FormatUint(uint64(event.HelperMask), 10)] = now.Add(bpfGuardRiskWindow)
	aggregate := uint32(0)
	for key, until := range e.bpfGuardSeen {
		if !strings.HasPrefix(key, prefix) || !until.After(now) {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimPrefix(key, prefix), 10, 32)
		if err != nil {
			continue
		}
		aggregate |= uint32(mask)
	}
	if len(e.bpfGuardSeen) > bpfGuardSeenLimit {
		for seenKey, until := range e.bpfGuardSeen {
			if !until.After(now) {
				delete(e.bpfGuardSeen, seenKey)
			}
		}
	}
	return aggregate
}
