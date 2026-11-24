// V6.3.0 AP-1 regression tests for the credential-guard action 3
// (DENY_INODE_UNTRUSTED): the parser accepts it, the XDR incident labels it as
// an executable-inode-gate denial, and the existing actions 1/2 keep their
// behaviour unchanged.

package main

import (
	"strings"
	"testing"
	"time"
)

func newExecInodeCredGuardTestEngine() *XDREngine {
	return &XDREngine{
		state:            NewState("test", defaultConfig()),
		dedupe:           map[string]time.Time{},
		degradeCauses:    map[string]string{},
		forensicFailures: map[string]int{},
	}
}

func execInodeCredGuardEvent(action uint8) CoreCredGuardEvent {
	return CoreCredGuardEvent{
		PID: 4242, TGID: 4242, UID: 1000, Dev: 8, Ino: 123456,
		Action: action, TsNS: 1700000000000000000, Comm: "sshd",
	}
}

func TestCredGuardActionValuesAreAppendOnly(t *testing.T) {
	if CredGuardActionDeny != 1 || CredGuardActionAudit != 2 || CredGuardActionDenyInode != 3 {
		t.Fatalf("credential-guard action ABI changed: %d/%d/%d",
			CredGuardActionDeny, CredGuardActionAudit, CredGuardActionDenyInode)
	}
	events, dropped, err := parseCoreCredGuardEvents(
		"0|4242:4242:1000:8:123456:3:1700000000000000000:73736864")
	if err != nil || dropped != 0 || len(events) != 1 {
		t.Fatalf("action-3 record rejected: events=%d dropped=%d err=%v", len(events), dropped, err)
	}
	if events[0].Action != CredGuardActionDenyInode || events[0].Comm != "sshd" {
		t.Fatalf("action-3 record decoded wrong: %+v", events[0])
	}
}

func TestCredGuardInodeDenyIncidentIsLabelled(t *testing.T) {
	engine := newExecInodeCredGuardTestEngine()
	now := time.Now().UTC()
	engine.consumeCredGuardEvents(
		[]CoreCredGuardEvent{execInodeCredGuardEvent(CredGuardActionDenyInode)}, 0, nil, now)
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 1 {
		t.Fatalf("expected one inode-gate denial incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if !containsString(incident.RuleIDs, "XDR.CREDENTIAL_READ_BLOCKED") ||
		incident.Decision != "deny" || incident.Action != "none" {
		t.Fatalf("inode-gate denial incident shape is wrong: %+v", incident)
	}
	if !strings.Contains(incident.Summary, "executable-inode gate") {
		t.Fatalf("inode-gate denial is not labelled in the summary: %q", incident.Summary)
	}
	if !strings.Contains(incident.Outcome, "executable-inode trust gate") {
		t.Fatalf("inode-gate denial is not labelled in the outcome: %q", incident.Outcome)
	}
	if len(incident.AttackStory) != 1 {
		t.Fatalf("inode-gate denial attack story missing: %+v", incident.AttackStory)
	}
	if got := incident.AttackStory[0].Metadata["decided_by"]; got != "exec_inode_gate" {
		t.Fatalf("inode-gate attack-story metadata is wrong: %q", got)
	}
	if got := incident.AttackStory[0].Metadata["action"]; got != "deny" {
		t.Fatalf("inode-gate attack-story action is wrong: %q", got)
	}
}

func TestCredGuardCommDenyBehaviourIsUnchanged(t *testing.T) {
	engine := newExecInodeCredGuardTestEngine()
	engine.consumeCredGuardEvents(
		[]CoreCredGuardEvent{execInodeCredGuardEvent(CredGuardActionDeny)}, 0, nil, time.Now().UTC())
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 1 {
		t.Fatalf("expected one credential-deny incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if !strings.Contains(incident.Summary, "Kernel LSM denied") {
		t.Fatalf("action-1 summary changed: %q", incident.Summary)
	}
	if got := incident.AttackStory[0].Metadata["decided_by"]; got != "comm_allowlist" {
		t.Fatalf("action-1 decided_by label changed: %q", got)
	}
	if incident.Decision != "deny" || incident.Action != "none" {
		t.Fatalf("action-1 incident shape changed: %+v", incident)
	}
}
