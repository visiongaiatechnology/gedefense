// STATUS: DIAMANT VGT SUPREME
package main

// M2.4 regression tests: bounded CRED_GUARD parsers, the honest status
// projection and the DENY/AUDIT event contract with synthetic core answers.

import (
	"strings"
	"testing"
	"time"
)

func TestParseCoreCredGuardEventsBoundedAndStrict(t *testing.T) {
	valid := "2|4242:4242:1000:8:123456:1:1700000000000000000:6375726c,77:77:0:2049:99:2:1700000000000000001:707764"
	events, dropped, err := parseCoreCredGuardEvents(valid)
	if err != nil {
		t.Fatalf("valid credential batch rejected: %v", err)
	}
	if dropped != 2 || len(events) != 2 {
		t.Fatalf("batch parsed to %d events dropped=%d", len(events), dropped)
	}
	if events[0].PID != 4242 || events[0].Dev != 8 || events[0].Ino != 123456 ||
		events[0].Action != CredGuardActionDeny || events[0].Comm != "curl" {
		t.Fatalf("deny event decoded wrong: %+v", events[0])
	}
	if events[1].Action != CredGuardActionAudit || events[1].UID != 0 {
		t.Fatalf("audit event decoded wrong: %+v", events[1])
	}
	if events, dropped, err := parseCoreCredGuardEvents("5|"); err != nil || dropped != 5 || events != nil {
		t.Fatalf("drop-only batch is wrong: dropped=%d err=%v", dropped, err)
	}
	if events, _, err := parseCoreCredGuardEvents("empty"); err != nil || events != nil {
		t.Fatalf("empty batch is wrong: %v", err)
	}
	invalid := []string{
		"", " 0|", "x|", "0",
		"0|4242:4242:1000:8:123456:1:1700000000000000000",                // missing comm
		"0|4242:4242:1000:8:123456:1:1700000000000000000:6375726c:extra", // extra field
		"0|0:4242:1000:8:123456:1:1700000000000000000:",                  // zero pid
		// Action 3 is valid since V6.3.0 AP-1 (kernel inode-gate denial); the
		// rejecting decoder must still refuse any action outside 1..=3.
		"0|4242:4242:1000:8:123456:4:1700000000000000000:",   // unknown action
		"0|4242:4242:1000:8:123456:0:1700000000000000000:",   // action 0
		"0|4242:4242:1000:8:0:1:1700000000000000000:",        // zero inode
		"0|4242:4242:1000:8:123456:1:0:",                     // zero timestamp
		"0|4242:4242:1000:8:123456:1:1700000000000000000:6",  // odd comm hex
		"0|4242:4242:1000:8:123456:1:1700000000000000000:00", // NUL comm
		"0|" + strings.Repeat("4", maxCredGuardPayloadBytes),
	}
	for _, response := range invalid {
		if events, _, err := parseCoreCredGuardEvents(response); err == nil || events != nil {
			t.Fatalf("hostile credential batch accepted: %.60q", response)
		}
	}
	tooMany := "0|" + strings.TrimSuffix(strings.Repeat("4242:4242:1000:8:123456:1:1700000000000000000:,", maxCredGuardEventsPerResponse+1), ",")
	if _, _, err := parseCoreCredGuardEvents(tooMany); err == nil {
		t.Fatal("a batch above the core ceiling was accepted")
	}
}

func TestParseCoreCredGuardStatusBoundedAndStrict(t *testing.T) {
	status, err := parseCoreCredGuardStatus("1:1:1:12:3:400:0:7:1")
	if err != nil {
		t.Fatalf("valid credential guard status rejected: %v", err)
	}
	if !status.Active || !status.Attached || !status.Armed || status.Files != 12 ||
		status.Dirs != 3 || status.Emitted != 400 || status.Denied != 7 || status.ReadFailures != 1 {
		t.Fatalf("status decoded wrong: %+v", status)
	}
	for _, response := range []string{
		"", "1:1:1", "1:1:1:2:3:4:5:6:7:8", "2:0:0:0:0:0:0:0:0", "1:x:0:0:0:0:0:0:0",
		" 1:1:0:0:0:0:0:0:0", strings.Repeat("1", 300),
	} {
		if _, err := parseCoreCredGuardStatus(response); err == nil {
			t.Fatalf("hostile credential guard status accepted: %.40q", response)
		}
	}
}

type fakeCredGuardCore struct {
	setCalls []bool
	resume   []int
	status   CoreCredGuardStatus
}

func (f *fakeCredGuardCore) CredGuardSet(enabled bool) error {
	f.setCalls = append(f.setCalls, enabled)
	return nil
}
func (f *fakeCredGuardCore) CredGuardEvents() ([]CoreCredGuardEvent, uint64, error) {
	return nil, 0, nil
}
func (f *fakeCredGuardCore) CredGuardStatus() (CoreCredGuardStatus, error) { return f.status, nil }

func newCredGuardTestEngine(fake *fakeCredGuardCore) *XDREngine {
	return &XDREngine{
		state: NewState("test", defaultConfig()), correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
		credCore: fake,
	}
}

func syntheticCredGuardEvent(action uint8) CoreCredGuardEvent {
	return CoreCredGuardEvent{
		PID: 4242, TGID: 4242, UID: 1000, Dev: 8, Ino: 123456,
		Action: action, TsNS: 1700000000000000000, Comm: "curl",
	}
}

func TestCredentialGuardDenyBecomesAlertOnlyIncident(t *testing.T) {
	engine := newCredGuardTestEngine(&fakeCredGuardCore{})
	now := time.Now().UTC()
	engine.consumeCredGuardEvents([]CoreCredGuardEvent{syntheticCredGuardEvent(CredGuardActionDeny)}, 0, nil, now)
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 1 {
		t.Fatalf("expected one credential incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if !containsString(incident.RuleIDs, "XDR.CREDENTIAL_READ_BLOCKED") || incident.Decision != "deny" {
		t.Fatalf("credential deny incident is wrong: %+v", incident)
	}
	if incident.Action != "none" {
		t.Fatalf("credential deny issued an active response: %+v", incident)
	}
	if len(incident.AttackStory) != 1 || incident.AttackStory[0].Metadata["action"] != "deny" {
		t.Fatalf("attack-story node missing: %+v", incident.AttackStory)
	}
	if incident.AttackStory[0].Metadata["comm"] != "curl" || incident.AttackStory[0].Metadata["uid"] != "1000" {
		t.Fatalf("attack-story metadata incomplete: %+v", incident.AttackStory[0].Metadata)
	}
	// Dedupe: the same kernel record must not produce a second incident.
	engine.consumeCredGuardEvents([]CoreCredGuardEvent{syntheticCredGuardEvent(CredGuardActionDeny)}, 0, nil, now)
	if got := len(engine.state.Snapshot().Incidents); got != 1 {
		t.Fatalf("duplicate credential record created %d incidents", got)
	}
}

func TestCredentialGuardAuditDoesNotCreateAnIncident(t *testing.T) {
	engine := newCredGuardTestEngine(&fakeCredGuardCore{})
	engine.consumeCredGuardEvents([]CoreCredGuardEvent{syntheticCredGuardEvent(CredGuardActionAudit)}, 0, nil, time.Now().UTC())
	if incidents := engine.state.Snapshot().Incidents; len(incidents) != 0 {
		t.Fatalf("audit record became an incident: %+v", incidents)
	}
	found := false
	for _, event := range engine.state.Snapshot().Events {
		if event.Kind == "xdr.credential_read_audited" {
			found = true
		}
	}
	if !found {
		t.Fatal("audit record did not reach the event stream")
	}
}

func TestCredentialGuardDenyCorrelatesWithPriorProcessIncident(t *testing.T) {
	engine := newCredGuardTestEngine(&fakeCredGuardCore{})
	now := time.Now().UTC()
	prior := XDRIncident{
		ID: "prior-process-incident", Time: now.Add(-2 * time.Minute), Severity: "high",
		PID: 4242, Process: "curl", RuleIDs: []string{"XDR.MEMFD_EXEC"},
		ExecutionChainID: "chain-4242", EvidenceRoot: "root-4242",
		AttackStory: []AttackStoryNode{{NodeID: "exec-node", Timestamp: now.Add(-2 * time.Minute)}},
	}
	engine.appendIncident(prior)
	engine.consumeCredGuardEvents([]CoreCredGuardEvent{syntheticCredGuardEvent(CredGuardActionDeny)}, 0, nil, now)
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 2 {
		t.Fatalf("expected prior + credential incidents, got %d", len(incidents))
	}
	credential := incidents[0]
	if credential.ExecutionChainID != "chain-4242" || len(credential.AttackStory) != 2 {
		t.Fatalf("credential deny was not linked to the process story: %+v", credential)
	}
	if credential.AttackStory[1].CausalParentID != "prior-process-incident" {
		t.Fatalf("causal parent missing: %+v", credential.AttackStory[1])
	}
}

func TestCredentialGuardReportOnlyActiveWhenArmedAttachedAndWatching(t *testing.T) {
	engine := newCredGuardTestEngine(&fakeCredGuardCore{})
	if got := engine.CredentialGuardReport(); got.State != "unavailable" || got.Capability != "missing" {
		t.Fatalf("missing capability reported as %+v", got)
	}
	now := time.Now().UTC()
	engine.consumeCredGuardStatus(CoreCredGuardStatus{Active: true, Attached: true, Armed: true, Files: 12, Dirs: 3, Emitted: 4}, nil, now)
	report := engine.CredentialGuardReport()
	if report.State != "active" || !report.Active || report.Files != 12 || report.SampledAt == nil {
		t.Fatalf("active guard reported as %+v", report)
	}
	engine.consumeCredGuardStatus(CoreCredGuardStatus{Active: true, Attached: true, Armed: true}, nil, now)
	if got := engine.CredentialGuardReport(); got.State != "degraded" || !strings.Contains(got.Reason, "watches no protected object") {
		t.Fatalf("armed guard without objects reported as %+v", got)
	}
	engine.consumeCredGuardStatus(CoreCredGuardStatus{Active: true, Attached: false, Armed: true, Files: 4}, nil, now)
	if got := engine.CredentialGuardReport(); got.State != "degraded" || !strings.Contains(got.Reason, "not attached") {
		t.Fatalf("unattached guard reported as %+v", got)
	}
	engine.consumeCredGuardStatus(CoreCredGuardStatus{Attached: true, Armed: false, Files: 4}, nil, now)
	if got := engine.CredentialGuardReport(); got.State != "disarmed" {
		t.Fatalf("disarmed guard reported as %+v", got)
	}
	engine.consumeCredGuardStatus(CoreCredGuardStatus{}, ErrCredGuardUnavailable, now)
	if got := engine.CredentialGuardReport(); got.State != "unavailable" {
		t.Fatalf("capability loss reported as %+v", got)
	}
}

func TestCredentialGuardRuleTokenIsClosedEvidence(t *testing.T) {
	if !validXDRRuleToken("XDR.CREDENTIAL_READ_BLOCKED") {
		t.Fatal("credential guard rule token rejected")
	}
	if _, ok := supportedXDRRuleOverrides["XDR.CREDENTIAL_READ_BLOCKED"]; !ok {
		t.Fatal("credential guard rule is missing from the administrable registry")
	}
}
