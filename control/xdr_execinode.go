// V6.3.0 AP-1: XDR integration of the executable-inode trust gate.
//
// Executive-name spoofing (`prctl(PR_SET_NAME, "sshd")`) no longer buys access
// to credential material: the kernel gate keys on the real executable inode.
// A comm that matches a trusted name while the inode does not is
// XDR.NAME_PATH_MISMATCH evidence (observe-only; the credential read itself is
// already denied by the kernel). A denied inode-gate decision is correlated with
// the matching XDR.CREDENTIAL_READ_BLOCKED incident when one exists (same pid,
// 15 minutes) or recorded as a standalone observe incident. The weaker
// `FALLBACK_COMM` mode (BTF offsets unavailable, comm allowlist decided) is
// reported as an explicit degradation record, never silently equated with the
// inode gate.
//
// Everything here is evidence-first and observe-only: no response action is
// derived, no kill-eligibility is added, and the kernel decision is never
// modified from the control plane.

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// execInodeCore is the subset of the privileged client the AP-1 contract needs.
type execInodeCore interface {
	ExecInodeStatus() (CoreExecInodeStatus, error)
	ExecInodeEvents() ([]CoreExecInodeEvent, uint64, error)
	ExecInodeAllowAdd(path string, flags uint8) error
	ExecInodeAllowDelete(dev uint32, ino uint64) error
	ExecInodeClear() error
}

// ExecInodeGateReport is the bounded operator projection of the executable-inode
// trust gate. It is exposed for future API wiring; no route is changed here.
// Active is only claimed when the core reports the gate enabled with published
// BTF offsets and at least one trusted identity.
type ExecInodeGateReport struct {
	State        string     `json:"state"` // active | degraded | unavailable
	Capability   string     `json:"capability"`
	Active       bool       `json:"active"`
	Enabled      bool       `json:"enabled"`
	OffsetsOK    bool       `json:"offsets_ok"`
	Trusted      uint64     `json:"trusted"`
	Missing      uint64     `json:"missing"`
	Allowed      uint64     `json:"allowed"`
	Denied       uint64     `json:"denied"`
	Events       uint64     `json:"events"`
	Drops        uint64     `json:"drops"`
	Fallbacks    uint64     `json:"fallbacks"`
	MalwareLocks uint64     `json:"malware_locks"`
	ExpiredLocks uint64     `json:"expired_locks"`
	Reason       string     `json:"reason,omitempty"`
	SampledAt    *time.Time `json:"sampled_at,omitempty"`
}

// pollExecInode runs one status + drain cycle and returns the next due time.
// The 100 ms scan tick is only the clock: the status sample runs every 10 s and
// the evidence drain every 1 s. Nothing here arms or changes enforcement.
func (e *XDREngine) pollExecInode(runtime RuntimeSettings, now time.Time, retryAfter time.Time) time.Time {
	if e == nil || e.execInodeCore == nil || !runtime.XDREnabled || now.Before(retryAfter) {
		return retryAfter
	}
	e.execInodeMu.Lock()
	statusAt := e.execInodeStatusAt
	known := e.execInodeCapabilityKnown
	e.execInodeMu.Unlock()
	if statusAt.IsZero() || now.Sub(statusAt) >= 10*time.Second {
		status, statusErr := e.execInodeCore.ExecInodeStatus()
		e.consumeExecInodeStatus(status, statusErr, now)
		e.execInodeMu.Lock()
		known = e.execInodeCapabilityKnown
		e.execInodeMu.Unlock()
	}
	if known {
		events, dropped, drainErr := e.execInodeCore.ExecInodeEvents()
		e.consumeExecInodeEvents(events, dropped, drainErr, now)
	}
	return now.Add(time.Second)
}

// consumeExecInodeStatus stores the honest gate sample and reports capability
// transitions. An absent command family is a fact (info), not a degradation.
func (e *XDREngine) consumeExecInodeStatus(status CoreExecInodeStatus, statusErr error, now time.Time) {
	if e == nil {
		return
	}
	e.execInodeMu.Lock()
	wasKnown := e.execInodeCapabilityKnown
	switch {
	case statusErr == nil:
		e.execInodeStatus = status
		e.execInodeStatusAt = now
		e.execInodeStatusErr = ""
		e.execInodeCapabilityKnown = true
	case errors.Is(statusErr, ErrExecInodeUnavailable):
		e.execInodeCapabilityKnown = false
		e.execInodeStatus = CoreExecInodeStatus{}
		e.execInodeStatusAt = time.Time{}
		e.execInodeStatusErr = ""
	default:
		// A failed sample still records the attempt so the 10 s cadence holds;
		// the previous known status is retained.
		e.execInodeStatusErr = boundedStyxText(statusErr)
		e.execInodeStatusAt = now
	}
	known := e.execInodeCapabilityKnown
	e.execInodeMu.Unlock()
	if e.state == nil {
		return
	}
	switch {
	case !known && wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.exec_inode_capability_missing", Source: "kernel",
			Message: "The privileged core no longer advertises the EXEC_INODE_* command family; executable-inode trust cannot be inspected (capability fact, not an XDR degradation)"})
	case known && !wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.exec_inode_capability_available", Source: "kernel",
			Message: "Kernel executable-inode trust gate is available; name/path mismatch evidence is ingested and audited"})
	}
}

// consumeExecInodeEvents turns one bounded drain into evidence and incidents.
func (e *XDREngine) consumeExecInodeEvents(events []CoreExecInodeEvent, dropped uint64, drainErr error, now time.Time) {
	if e == nil {
		return
	}
	if drainErr != nil {
		if errors.Is(drainErr, ErrExecInodeUnavailable) {
			e.consumeExecInodeStatus(CoreExecInodeStatus{}, ErrExecInodeUnavailable, now)
			return
		}
		e.execInodeMu.Lock()
		e.execInodeStatusErr = boundedStyxText(drainErr)
		e.execInodeMu.Unlock()
		return
	}
	for _, event := range events {
		if !e.claimExecInodeRecord(event, now) {
			continue
		}
		switch event.Action {
		case ExecInodeActionObservedMismatch:
			e.recordExecInodeMismatch(event, now)
		case ExecInodeActionDeniedUntrusted:
			e.recordExecInodeDeny(event, now)
		case ExecInodeActionFallbackComm:
			e.recordExecInodeFallback(event, now)
		}
	}
	if dropped > 0 && e.state != nil {
		e.execInodeMu.Lock()
		last := e.execInodeLastOverflow
		if last.IsZero() || now.Sub(last) >= 5*time.Minute {
			e.execInodeLastOverflow = now
			e.execInodeMu.Unlock()
			e.state.AddEvent(Event{Severity: "high", Kind: "xdr.exec_inode_overflow", Source: "kernel",
				Message: fmt.Sprintf("Executable-inode evidence ring dropped %d record(s); name/path mismatch visibility is reduced", dropped)})
		} else {
			e.execInodeMu.Unlock()
		}
	}
}

// claimExecInodeRecord dedupes one kernel record by
// `(ts_ns, pid, exe_ino, action)` with a bounded 5-minute memory.
func (e *XDREngine) claimExecInodeRecord(event CoreExecInodeEvent, now time.Time) bool {
	key := fmt.Sprintf("%d|%d|%d|%d|%d", event.TsNS, event.PID, event.ExeIno, event.Action, event.TGID)
	e.execInodeMu.Lock()
	defer e.execInodeMu.Unlock()
	if e.execInodeSeen == nil {
		e.execInodeSeen = make(map[string]time.Time)
	}
	if until, exists := e.execInodeSeen[key]; exists && now.Before(until) {
		return false
	}
	e.execInodeSeen[key] = now.Add(5 * time.Minute)
	if len(e.execInodeSeen) > 4096 {
		for seenKey, until := range e.execInodeSeen {
			if !until.After(now) {
				delete(e.execInodeSeen, seenKey)
			}
		}
	}
	return true
}

// recordExecInodeMismatch creates evidence first, then an observe-only
// XDR.NAME_PATH_MISMATCH incident. The kernel already made the access decision;
// this rule is not kill-eligible and never issues an action.
func (e *XDREngine) recordExecInodeMismatch(event CoreExecInodeEvent, now time.Time) {
	parent, chainID, evidenceRoot, storyNodes := e.execInodeCorrelation(event.PID, now)
	summary := fmt.Sprintf(
		"Executable name/path mismatch: task name %q does not match the real executable inode dev=%d ino=%d (pid=%d uid=%d trust_flags=%d)",
		event.Comm, event.ExeDev, event.ExeIno, event.PID, event.UID, event.TrustFlags)
	evidence := EvidenceRecord{
		Severity: "high", Kind: "xdr.name_path_mismatch", Source: "kernel",
		Message: "Executable-name masquerade observed before any response: " + summary,
		Target:  fmt.Sprintf("dev:%d:ino:%d:pid:%d", event.ExeDev, event.ExeIno, event.PID),
		Time:    now,
	}
	evidenceErr := e.state.RecordEvidence(evidence)
	metadata := map[string]string{
		"action":           "alert",
		"decided_by":       "exec_inode_gate",
		"sbc_entity":       fmt.Sprintf("inode:%d:%d", event.ExeDev, event.ExeIno),
		"sbc_actor":        fmt.Sprintf("pid:%d", event.PID),
		"sbc_signal":       "name_path_mismatch",
		"pid":              strconv.Itoa(event.PID),
		"tgid":             strconv.Itoa(event.TGID),
		"uid":              strconv.FormatUint(uint64(event.UID), 10),
		"exe_dev":          strconv.FormatUint(uint64(event.ExeDev), 10),
		"exe_ino":          strconv.FormatUint(event.ExeIno, 10),
		"trust_flags":      strconv.FormatUint(uint64(event.TrustFlags), 10),
		"comm":             event.Comm,
		"kernel_verdict":   "observed",
		"kill_eligibility": "none",
	}
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("execinode-mismatch-%d-%d", event.PID, now.UnixNano()),
		Timestamp:  now,
		Sensor:     "kernel-exec-inode",
		Category:   "masquerading",
		EventType:  "NAME_PATH_MISMATCH",
		EntityID:   fmt.Sprintf("pid:%d", event.PID),
		Actor:      fmt.Sprintf("uid:%d", event.UID),
		Severity:   "high",
		Confidence: 96,
		CausalEdge: EdgeRootCause,
		EventUUID:  randomID(),
		Metadata:   metadata,
	}
	if parent != "" {
		node.CausalParentID = parent
	}
	node.Digest = node.ComputeNodeDigest()
	storyNodes = append(storyNodes, node)
	if evidenceRoot == "" {
		evidenceRoot = node.Digest
	}
	outcome := "observe-only: the kernel executable-inode gate decided the operation; no control-plane response is issued"
	if evidenceErr != nil {
		outcome = "observe-only; mandatory evidence commit failed, incident recorded without response: " + evidenceErr.Error()
	}
	incident := XDRIncident{
		ID: randomID(), Time: now, Severity: "high", Score: 35,
		PID: event.PID, UID: event.UID, Process: event.Comm,
		Executable:       fmt.Sprintf("inode:%d:%d", event.ExeDev, event.ExeIno),
		RuleIDs:          []string{"XDR.NAME_PATH_MISMATCH"},
		Categories:       []string{"masquerading", "identity"},
		Summary:          summary,
		Decision:         "alert",
		Action:           "none",
		Outcome:          outcome,
		ExecutionChainID: chainID,
		AttackStory:      storyNodes,
		EvidenceRoot:     evidenceRoot,
	}
	e.appendIncident(incident)
	if e.state != nil {
		e.state.AddEvent(Event{Time: now, Severity: "high", Kind: "xdr.name_path_mismatch", Source: "kernel",
			Message: summary, Target: fmt.Sprintf("pid:%d", event.PID)})
	}
}

// recordExecInodeDeny either correlates an inode-gate deny with the matching
// credential-read incident (same pid, last 15 minutes) or creates a standalone
// observe-only incident. No response is ever derived.
func (e *XDREngine) recordExecInodeDeny(event CoreExecInodeEvent, now time.Time) {
	summary := fmt.Sprintf(
		"Executable-inode gate denied an operation for an untrusted executable: pid=%d uid=%d comm=%s dev=%d ino=%d trust_flags=%d",
		event.PID, event.UID, event.Comm, event.ExeDev, event.ExeIno, event.TrustFlags)
	if e.matchingCredentialDeny(event.PID, now) {
		if e.state != nil {
			e.state.AddEvent(Event{Time: now, Severity: "high", Kind: "xdr.exec_inode_deny_correlated", Source: "kernel",
				Message: summary + "; correlated with the nearby XDR.CREDENTIAL_READ_BLOCKED credential-deny incident",
				Target:  fmt.Sprintf("pid:%d", event.PID)})
		}
		return
	}
	parent, chainID, evidenceRoot, storyNodes := e.execInodeCorrelation(event.PID, now)
	evidenceErr := e.state.RecordEvidence(EvidenceRecord{
		Severity: "high", Kind: "xdr.credential_read_blocked_inode", Source: "kernel",
		Message: "Executable-inode gate DENY recorded before any response: " + summary,
		Target:  fmt.Sprintf("dev:%d:ino:%d:pid:%d", event.ExeDev, event.ExeIno, event.PID),
		Time:    now,
	})
	metadata := map[string]string{
		"action":               "deny",
		"decided_by":           "exec_inode_gate",
		"sbc_entity":           fmt.Sprintf("inode:%d:%d", event.ExeDev, event.ExeIno),
		"sbc_actor":            fmt.Sprintf("pid:%d", event.PID),
		"sbc_signal":           "credential_read_inode_deny",
		"pid":                  strconv.Itoa(event.PID),
		"tgid":                 strconv.Itoa(event.TGID),
		"uid":                  strconv.FormatUint(uint64(event.UID), 10),
		"exe_dev":              strconv.FormatUint(uint64(event.ExeDev), 10),
		"exe_ino":              strconv.FormatUint(event.ExeIno, 10),
		"trust_flags":          strconv.FormatUint(uint64(event.TrustFlags), 10),
		"comm":                 event.Comm,
		"has_lineage_or_chain": "true",
		"kill_eligibility":     "none",
	}
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("execinode-deny-%d-%d", event.PID, now.UnixNano()),
		Timestamp:  now,
		Sensor:     "kernel-exec-inode",
		Category:   "credential",
		EventType:  "CREDENTIAL_READ_BLOCKED",
		EntityID:   fmt.Sprintf("pid:%d", event.PID),
		Actor:      fmt.Sprintf("uid:%d", event.UID),
		Severity:   "high",
		Confidence: 96,
		CausalEdge: EdgePrivilegeEscalated,
		EventUUID:  randomID(),
		Metadata:   metadata,
	}
	if parent != "" {
		node.CausalParentID = parent
	}
	node.Digest = node.ComputeNodeDigest()
	storyNodes = append(storyNodes, node)
	if evidenceRoot == "" {
		evidenceRoot = node.Digest
	}
	outcome := "operation denied by the executable-inode gate before any byte was returned; no active response required"
	if evidenceErr != nil {
		outcome = "operation denied by the executable-inode gate; mandatory evidence commit failed, incident recorded without response: " + evidenceErr.Error()
	}
	incident := XDRIncident{
		ID: randomID(), Time: now, Severity: "high", Score: 150,
		PID: event.PID, UID: event.UID, Process: event.Comm,
		Executable:       fmt.Sprintf("inode:%d:%d", event.ExeDev, event.ExeIno),
		RuleIDs:          []string{"XDR.CREDENTIAL_READ_BLOCKED"},
		Categories:       []string{"credential", "access"},
		Summary:          summary,
		Decision:         "deny",
		Action:           "none",
		Outcome:          outcome,
		ExecutionChainID: chainID,
		AttackStory:      storyNodes,
		EvidenceRoot:     evidenceRoot,
	}
	e.appendIncident(incident)
	if e.state != nil {
		e.state.AddEvent(Event{Time: now, Severity: "high", Kind: "xdr.credential_read_blocked_inode", Source: "kernel",
			Message: summary + "; " + outcome, Target: fmt.Sprintf("pid:%d", event.PID)})
	}
}

// recordExecInodeFallback reports the weaker comm-fallback mode at most once per
// 15 minutes: an operator must be able to tell the comm allowlist decision apart
// from a real executable-inode decision.
func (e *XDREngine) recordExecInodeFallback(event CoreExecInodeEvent, now time.Time) {
	key := "fallback"
	e.execInodeMu.Lock()
	if until, exists := e.execInodeSeen[key]; exists && now.Before(until) {
		e.execInodeMu.Unlock()
		return
	}
	if e.execInodeSeen == nil {
		e.execInodeSeen = make(map[string]time.Time)
	}
	e.execInodeSeen[key] = now.Add(15 * time.Minute)
	e.execInodeMu.Unlock()
	if e.state == nil {
		return
	}
	e.state.AddEvent(Event{Time: now, Severity: "warning", Kind: "xdr.exec_inode_comm_fallback", Source: "kernel",
		Message: fmt.Sprintf(
			"Executable-inode gate unavailable: the kernel used the comm allowlist fallback for pid=%d comm=%s (weaker, spoofable mode - BTF/offsets missing)",
			event.PID, event.Comm),
		Target: fmt.Sprintf("pid:%d", event.PID)})
}

// matchingCredentialDeny reports whether a recent XDR.CREDENTIAL_READ_BLOCKED
// incident for the same pid exists (the inode deny is then attributed to it).
func (e *XDREngine) matchingCredentialDeny(pid int, now time.Time) bool {
	if e.state == nil {
		return false
	}
	for _, prior := range e.state.Snapshot().Incidents {
		if prior.PID != pid || now.Sub(prior.Time) > 15*time.Minute {
			continue
		}
		for _, ruleID := range prior.RuleIDs {
			if ruleID == "XDR.CREDENTIAL_READ_BLOCKED" {
				return true
			}
		}
	}
	return false
}

// execInodeCorrelation links the new evidence node to a recent incident for the
// same pid (any rule) so the identity evidence joins the process story instead
// of inventing a second chain. Returns the causal parent, the chain id, the
// evidence root and the prior attack story to append to.
func (e *XDREngine) execInodeCorrelation(pid int, now time.Time) (string, string, string, []AttackStoryNode) {
	if e.state == nil {
		return "", "", "", nil
	}
	for _, prior := range e.state.Snapshot().Incidents {
		if prior.PID != pid || now.Sub(prior.Time) > 15*time.Minute {
			continue
		}
		chainID := prior.ExecutionChainID
		if chainID == "" {
			chainID = prior.ID
		}
		story := append([]AttackStoryNode(nil), prior.AttackStory...)
		return prior.ID, chainID, prior.EvidenceRoot, story
	}
	return "", "", "", nil
}

// ExecInodeGateReport returns the honest operator view of the executable-inode
// trust gate. It is intentionally not wired to an HTTP route by AP-1; the future
// API owner can expose it unchanged.
func (e *XDREngine) ExecInodeGateReport() ExecInodeGateReport {
	report := ExecInodeGateReport{State: "unavailable", Capability: "unknown"}
	if e == nil {
		return report
	}
	e.execInodeMu.Lock()
	status := e.execInodeStatus
	sampled := e.execInodeStatusAt
	statusErr := e.execInodeStatusErr
	known := e.execInodeCapabilityKnown
	e.execInodeMu.Unlock()
	report.Enabled = status.Enabled
	report.OffsetsOK = status.OffsetsOK
	report.Trusted = status.Trusted
	report.Missing = status.Missing
	report.Allowed = status.Allowed
	report.Denied = status.Denied
	report.Events = status.Events
	report.Drops = status.Drops
	report.Fallbacks = status.Fallbacks
	report.MalwareLocks = status.MalwareLocks
	report.ExpiredLocks = status.ExpiredLocks
	if !sampled.IsZero() {
		at := sampled
		report.SampledAt = &at
	}
	switch {
	case !known:
		report.Capability = "missing"
		if statusErr != "" {
			report.State = "degraded"
			report.Reason = "executable-inode status query failed: " + statusErr
		} else {
			report.State = "unavailable"
			report.Reason = "the privileged core does not advertise the EXEC_INODE_* command family; the kernel keeps its documented comm fallback"
		}
	case statusErr != "":
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "executable-inode evidence drain failed: " + statusErr
	case !status.Enabled:
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "executable-inode gate is disarmed (no trusted credential reader resolved or BTF offsets unavailable); the kernel guards use the documented comm fallback"
	case !status.OffsetsOK:
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "executable-inode offsets are not published; comm fallback is active in the kernel"
	case status.Trusted == 0:
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "executable-inode gate is enabled but no trusted executable identity was resolved"
	default:
		report.State = "active"
		report.Capability = "available"
		report.Active = true
	}
	if status.Fallbacks > 0 && report.Reason == "" {
		report.Reason = fmt.Sprintf("%d comm-fallback decision(s) reported by the kernel", status.Fallbacks)
	}
	report.Reason = strings.TrimSpace(report.Reason)
	return report
}
