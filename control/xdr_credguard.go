// STATUS: DIAMANT VGT SUPREME
package main

// M2.4: credential-guard XDR integration.
//
// The kernel LSM denies reads of protected credential objects by non-allowlisted
// processes. This file turns those decisions into XDR incidents/evidence and
// exposes the guard state honestly. It never blocks PAM or login by itself: the
// guard is an observation/enforcement point owned by the kernel policy, and the
// Go side only reports, correlates and (when the core advertises the family)
// arms the sensor.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type credGuardCore interface {
	CredGuardSet(enabled bool) error
	CredGuardEvents() ([]CoreCredGuardEvent, uint64, error)
	CredGuardStatus() (CoreCredGuardStatus, error)
}

// CredentialGuardStatus is the bounded operator projection. Active is only
// claimed when the sensor is armed, attached and actually watches files.
type CredentialGuardStatus struct {
	State        string     `json:"state"` // active | degraded | disarmed | unavailable
	Capability   string     `json:"capability"`
	Active       bool       `json:"active"`
	Attached     bool       `json:"attached"`
	Armed        bool       `json:"armed"`
	Files        uint64     `json:"files"`
	Dirs         uint64     `json:"dirs"`
	Emitted      uint64     `json:"emitted"`
	Drops        uint64     `json:"drops"`
	Denied       uint64     `json:"denied"`
	ReadFailures uint64     `json:"read_failures"`
	Reason       string     `json:"reason,omitempty"`
	SampledAt    *time.Time `json:"sampled_at,omitempty"`
}

func (e *XDREngine) consumeCredGuardStatus(status CoreCredGuardStatus, statusErr error, now time.Time) {
	if e == nil {
		return
	}
	e.credMu.Lock()
	wasKnown := e.credCapabilityKnown
	if statusErr == nil {
		e.credStatus = status
		e.credStatusAt = now
		e.credStatusErr = ""
		e.credCapabilityKnown = true
	} else if errors.Is(statusErr, ErrCredGuardUnavailable) {
		e.credCapabilityKnown = false
		e.credStatus = CoreCredGuardStatus{}
		e.credStatusAt = time.Time{}
		e.credStatusErr = ""
	} else {
		e.credStatusErr = boundedStyxText(statusErr)
	}
	known := e.credCapabilityKnown
	e.credMu.Unlock()
	if e.state == nil {
		return
	}
	switch {
	case !known && wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.cred_guard_capability_missing", Source: "kernel",
			Message: "The privileged core no longer advertises the CRED_GUARD_* command family; credential-read protection is unavailable (capability fact, not an XDR degradation)"})
	case known && !wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.cred_guard_capability_available", Source: "kernel",
			Message: "Kernel credential guard is available; DENY decisions are ingested and audited"})
	}
}

func (e *XDREngine) consumeCredGuardEvents(events []CoreCredGuardEvent, dropped uint64, drainErr error, now time.Time) time.Duration {
	if e == nil {
		return 10 * time.Second
	}
	if drainErr != nil {
		if errors.Is(drainErr, ErrCredGuardUnavailable) {
			e.consumeCredGuardStatus(CoreCredGuardStatus{}, ErrCredGuardUnavailable, now)
			return 10 * time.Second
		}
		e.credMu.Lock()
		e.credStatusErr = boundedStyxText(drainErr)
		e.credMu.Unlock()
		return 10 * time.Second
	}
	for _, event := range events {
		if !e.claimCredGuardRecord(event, now) {
			continue
		}
		if event.Action == CredGuardActionAudit {
			if e.state != nil {
				e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.credential_read_audited", Source: "kernel",
					Message: fmt.Sprintf("Credential object read audited by the kernel guard: pid=%d uid=%d comm=%s", event.PID, event.UID, event.Comm),
					Target:  fmt.Sprintf("dev:%d:ino:%d", event.Dev, event.Ino)})
			}
			continue
		}
		e.recordCredentialGuardDeny(event, now)
	}
	if dropped > 0 && e.state != nil {
		e.credMu.Lock()
		last := e.credLastOverflow
		if last.IsZero() || now.Sub(last) >= 5*time.Minute {
			e.credLastOverflow = now
			e.credMu.Unlock()
			e.state.AddEvent(Event{Severity: "high", Kind: "xdr.cred_guard_overflow", Source: "kernel",
				Message: fmt.Sprintf("Kernel credential guard dropped %d decision record(s); credential-read visibility is reduced", dropped)})
		} else {
			e.credMu.Unlock()
		}
	}
	return time.Second
}

// recordCredentialGuardDeny creates evidence first, then the incident with an
// attack-story node. It never issues an active response: the kernel already
// denied the read, and PAM/login must never be changed from this path.
func (e *XDREngine) recordCredentialGuardDeny(event CoreCredGuardEvent, now time.Time) {
	summary := fmt.Sprintf("Kernel LSM denied a credential-object read: pid=%d uid=%d comm=%s",
		event.PID, event.UID, event.Comm)
	evidenceErr := e.state.RecordEvidence(EvidenceRecord{
		Severity: "high", Kind: "xdr.credential_read_blocked", Source: "kernel",
		Message: "Kernel credential-guard DENY recorded before any response: " + summary,
		Target:  fmt.Sprintf("dev:%d:ino:%d:pid:%d", event.Dev, event.Ino, event.PID), Time: now,
	})
	metadata := map[string]string{
		"action":               "deny",
		"uid":                  strconv.FormatUint(uint64(event.UID), 10),
		"pid":                  strconv.Itoa(event.PID),
		"tgid":                 strconv.Itoa(event.TGID),
		"comm":                 event.Comm,
		"dev":                  strconv.FormatUint(uint64(event.Dev), 10),
		"ino":                  strconv.FormatUint(event.Ino, 10),
		"has_lineage_or_chain": "true",
	}
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("credguard-%d-%d", event.PID, now.UnixNano()),
		Timestamp:  now,
		Sensor:     "kernel-cred-guard",
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
	node.Digest = node.ComputeNodeDigest()
	storyNodes := []AttackStoryNode{node}
	evidenceRoot := node.Digest
	chainID := node.NodeID
	// Correlation with the exec/process sensor: if the same pid already appears in
	// a recent incident, link the credential node into that story instead of
	// inventing a second chain.
	if e.state != nil {
		for _, prior := range e.state.Snapshot().Incidents {
			if now.Sub(prior.Time) > 15*time.Minute {
				continue
			}
			if prior.PID != event.PID && prior.Process != event.Comm {
				continue
			}
			node.CausalParentID = prior.ID
			node.Digest = node.ComputeNodeDigest()
			storyNodes = append(append([]AttackStoryNode(nil), prior.AttackStory...), node)
			if prior.EvidenceRoot != "" {
				evidenceRoot = prior.EvidenceRoot
			}
			if prior.ExecutionChainID != "" {
				chainID = prior.ExecutionChainID
			} else {
				chainID = prior.ID
			}
			break
		}
	}
	outcome := "read denied by the kernel LSM before any byte was returned; no active response required"
	action := "none"
	if evidenceErr != nil {
		// The kernel already denied the read; the incident is still recorded with an
		// outcome that states the evidence gap. No response is derived from it.
		outcome = "read denied by the kernel; mandatory evidence commit failed, incident recorded without response: " + evidenceErr.Error()
	}
	incident := XDRIncident{
		ID: randomID(), Time: now, Severity: "high", Score: 150,
		PID: event.PID, UID: event.UID, Process: event.Comm,
		RuleIDs: []string{"XDR.CREDENTIAL_READ_BLOCKED"}, Categories: []string{"credential", "access"},
		Summary: summary, Decision: "deny", Action: action, Outcome: outcome,
		ExecutionChainID: chainID, AttackStory: storyNodes, EvidenceRoot: evidenceRoot,
	}
	e.appendIncident(incident)
	if e.state != nil {
		e.state.AddEvent(Event{Time: now, Severity: "high", Kind: "xdr.credential_read_blocked", Source: "kernel",
			Message: summary + "; " + outcome, Target: fmt.Sprintf("pid:%d", event.PID)})
	}
}

func (e *XDREngine) claimCredGuardRecord(event CoreCredGuardEvent, now time.Time) bool {
	key := fmt.Sprintf("%d|%d|%d|%d|%d", event.PID, event.Ino, event.Action, event.TsNS, event.TGID)
	e.credMu.Lock()
	defer e.credMu.Unlock()
	if e.credSeen == nil {
		e.credSeen = make(map[string]time.Time)
	}
	if until, exists := e.credSeen[key]; exists && now.Before(until) {
		return false
	}
	e.credSeen[key] = now.Add(5 * time.Minute)
	if len(e.credSeen) > 4096 {
		for seenKey, until := range e.credSeen {
			if !until.After(now) {
				delete(e.credSeen, seenKey)
			}
		}
	}
	return true
}

// CredentialGuardReport returns the honest operator view of the guard.
func (e *XDREngine) CredentialGuardReport() CredentialGuardStatus {
	report := CredentialGuardStatus{State: "unavailable", Capability: "unknown"}
	if e == nil {
		return report
	}
	e.credMu.Lock()
	status := e.credStatus
	sampled := e.credStatusAt
	statusErr := e.credStatusErr
	known := e.credCapabilityKnown
	e.credMu.Unlock()
	report.Attached = status.Attached
	report.Armed = status.Armed
	report.Files = status.Files
	report.Dirs = status.Dirs
	report.Emitted = status.Emitted
	report.Drops = status.Drops
	report.Denied = status.Denied
	report.ReadFailures = status.ReadFailures
	if !sampled.IsZero() {
		at := sampled
		report.SampledAt = &at
	}
	switch {
	case !known:
		if statusErr != "" {
			report.State = "degraded"
			report.Capability = "missing"
			report.Reason = "credential guard status query failed: " + statusErr
		} else {
			report.State = "unavailable"
			report.Capability = "missing"
			report.Reason = "the privileged core does not advertise the CRED_GUARD_* command family"
		}
	case statusErr != "":
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "credential guard event drain failed: " + statusErr
	case !status.Armed:
		report.State = "disarmed"
		report.Capability = "available"
		report.Reason = "kernel credential guard is armed off (CRED_GUARD_SET 0)"
	case !status.Attached:
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "credential guard is armed but the kernel LSM hook is not attached"
	case status.Files == 0 && status.Dirs == 0:
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "credential guard is armed and attached but watches no protected object"
	default:
		report.State = "active"
		report.Capability = "available"
		report.Active = status.Active
		if !status.Active {
			report.State = "degraded"
			report.Reason = "kernel reports the guard inactive although its counters are armed"
		}
	}
	if status.ReadFailures > 0 && report.Reason == "" {
		report.Reason = fmt.Sprintf("%d credential-guard read failure(s) reported by the kernel", status.ReadFailures)
	}
	report.Reason = strings.TrimSpace(report.Reason)
	return report
}
