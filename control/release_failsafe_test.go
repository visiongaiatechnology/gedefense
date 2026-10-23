// STATUS: DIAMANT VGT SUPREME
package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFailSafeKeepsItsReasonAndLeavesForensicEvidence covers what the operator saw after
// a real fail-safe: the platform had fallen back to Observe, the hero said a fail-safe
// had happened, and nothing anywhere said what caused it or when. The Forensics view
// counted zero incidents, because only the XDR process pipeline ever created one and a
// fail-safe is not a process incident.
//
// A fall-back disables every active response on the host. It is the most consequential
// thing the platform does on its own, and it was leaving no trace an operator could
// investigate.
func TestFailSafeKeepsItsReasonAndLeavesForensicEvidence(t *testing.T) {
	cfg := defaultConfig()
	cfg.Release.AutoDegrade = true
	state := NewState("test", cfg)

	dir := t.TempDir()
	ledger, err := NewEvidenceLedger(dir+"/evidence.jsonl", dir+"/evidence.ed25519", "", "test-node", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}

	policy, err := NewPolicyStore(PolicyConfig{
		StateFile:      filepath.Join(dir, "policy.json"),
		SigningKeyFile: filepath.Join(dir, "policy.key"),
		PublicKeyFile:  filepath.Join(dir, "policy.pub"),
		RequireSigned:  true,
	}, "test-node")
	if err != nil {
		t.Fatalf("policy store: %v", err)
	}
	controller := NewReleaseController(cfg, state, &releaseCoreStub{}, policy, nil)

	const cause = "Kinetic ingress sensor is unavailable"
	if err := controller.FailSafe(cause); err != nil {
		t.Fatalf("the fail-safe could not complete: %v", err)
	}

	status := state.Snapshot().Release
	if status.Phase != ReleasePhaseDegraded {
		t.Fatalf("the platform did not fall back: phase=%s", status.Phase)
	}
	if !strings.Contains(status.FailSafeReason, cause) {
		t.Fatalf("the cause was not preserved: %q", status.FailSafeReason)
	}
	if status.FailSafeAt == nil {
		t.Fatal("the cause was preserved without the moment it was observed")
	}

	// The reason must survive a refresh. It used to be overwritten by the live detail,
	// and once the blockers cleared the operator was told "release gates satisfied" while
	// the platform was still sitting in Observe.
	controller.Evaluate()
	after := state.Snapshot().Release
	if !strings.Contains(after.FailSafeReason, cause) {
		t.Fatalf("a refresh discarded the cause: %q", after.FailSafeReason)
	}
	if after.FailSafeAt == nil {
		t.Fatal("a refresh discarded the moment of the fall-back")
	}

	// And it is forensic evidence, not only a phase change. The wording states what actually
	// happened: the automatic response paused and the enforcement stayed in place.
	incidents := state.Snapshot().Incidents
	found := false
	for _, incident := range incidents {
		if strings.Contains(incident.Summary, "kernel enforcement retained") {
			found = true
			if incident.Severity != "critical" {
				t.Errorf("the fail-safe incident is not critical: %s", incident.Severity)
			}
			if !strings.Contains(incident.Summary, cause) {
				t.Errorf("the incident does not name the cause: %q", incident.Summary)
			}
			if incident.Action == "" || incident.Outcome == "" {
				t.Errorf("the incident does not state what was done: action=%q outcome=%q", incident.Action, incident.Outcome)
			}
			if strings.Contains(strings.ToLower(incident.Outcome), "empty") {
				t.Errorf("the incident claims an empty kernel that was retained: %q", incident.Outcome)
			}
		}
	}
	if !found {
		t.Fatalf("the fail-safe left no incident; Forensics had %d to show", len(incidents))
	}
}

// TestDegradedStateIsNeverReportedAsSatisfied pins the wording the operator reads.
//
// A platform in Observe after a fail-safe is not a platform with nothing pending, and the
// live detail must not say so. The cause itself is carried separately in FailSafeReason
// because the detail describes the present while the cause describes an event.
func TestDegradedStateIsNeverReportedAsSatisfied(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)
	dir := t.TempDir()
	policy, err := NewPolicyStore(PolicyConfig{
		StateFile:      filepath.Join(dir, "policy.json"),
		SigningKeyFile: filepath.Join(dir, "policy.key"),
		PublicKeyFile:  filepath.Join(dir, "policy.pub"),
		RequireSigned:  true,
	}, "test-node")
	if err != nil {
		t.Fatalf("policy store: %v", err)
	}
	controller := NewReleaseController(cfg, state, &releaseCoreStub{}, policy, nil)

	at := time.Now().UTC().Add(-time.Hour)
	controller.mu.Lock()
	controller.status.Phase = ReleasePhaseDegraded
	controller.status.FailSafeReason = "Kinetic ingress sensor is unavailable"
	controller.status.FailSafeAt = &at
	controller.mu.Unlock()

	controller.Evaluate()
	status := state.Snapshot().Release

	// The cause survives the refresh, whatever the live detail ends up saying.
	if !strings.Contains(status.FailSafeReason, "Kinetic ingress sensor") {
		t.Fatalf("a refresh discarded the cause: %q", status.FailSafeReason)
	}
	if status.FailSafeAt == nil {
		t.Fatal("a refresh discarded the moment of the fall-back")
	}

	// With no current blocker the detail must not claim the gates are satisfied, because
	// the platform is still sitting in Observe for a reason.
	controller.mu.Lock()
	controller.status.Blockers = nil
	controller.mu.Unlock()
	controller.refreshLocked()
	detail := controller.status.Detail
	if len(controller.status.Blockers) > 0 {
		// A blocker is present, so the live detail names it - which is correct, and the
		// cause is still carried separately. What must never happen is the opposite claim.
		if strings.Contains(detail, "release gates satisfied") {
			t.Fatalf("a degraded platform reported its gates as satisfied: %q", detail)
		}
		t.Logf("a current blocker is named instead of the fail-safe cause: %q", detail)
		return
	}
	if strings.Contains(detail, "release gates satisfied") {
		t.Fatalf("a degraded platform reported its gates as satisfied: %q", detail)
	}
	if !strings.Contains(detail, "operator") {
		t.Fatalf("the detail does not say that promotion is an operator action: %q", detail)
	}

	// And a platform that never fell back is unaffected by the branch.
	fresh := NewReleaseController(cfg, NewState("test", cfg), &releaseCoreStub{}, nil, nil)
	fresh.refreshLocked()
	if strings.Contains(fresh.status.Detail, "fail-safe") {
		t.Fatalf("a controller that never fell back mentions a fail-safe: %q", fresh.status.Detail)
	}
}
