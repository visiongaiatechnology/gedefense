// V6.3.0 AP-1 regression tests: the executable-inode gate XDR projection,
// observe-only incidents, dedupe/correlation and the comm-fallback reporting.

package main

import (
	"strings"
	"testing"
	"time"
)

type fakeExecInodeCore struct {
	status    CoreExecInodeStatus
	statusErr error
	events    []CoreExecInodeEvent
	dropped   uint64
	eventsErr error
	statusQs  int
	eventsQs  int
}

func (f *fakeExecInodeCore) ExecInodeStatus() (CoreExecInodeStatus, error) {
	f.statusQs++
	return f.status, f.statusErr
}
func (f *fakeExecInodeCore) ExecInodeEvents() ([]CoreExecInodeEvent, uint64, error) {
	f.eventsQs++
	return f.events, f.dropped, f.eventsErr
}
func (f *fakeExecInodeCore) ExecInodeAllowAdd(string, uint8) error     { return nil }
func (f *fakeExecInodeCore) ExecInodeAllowDelete(uint32, uint64) error { return nil }
func (f *fakeExecInodeCore) ExecInodeClear() error                     { return nil }

func newExecInodeTestEngine(fake *fakeExecInodeCore) *XDREngine {
	return &XDREngine{
		state:            NewState("test", defaultConfig()),
		execInodeCore:    fake,
		dedupe:           map[string]time.Time{},
		degradeCauses:    map[string]string{},
		forensicFailures: map[string]int{},
	}
}

func execInodeTestEvent(pid int, ino uint64, action uint8, ts uint64) CoreExecInodeEvent {
	return CoreExecInodeEvent{
		TsNS: ts, PID: pid, TGID: pid, UID: 1000,
		ExeDev: 8, ExeIno: ino, TrustFlags: 0, Action: action, Comm: "sshd",
	}
}

func TestExecInodeGateReportHonestStates(t *testing.T) {
	engine := newExecInodeTestEngine(&fakeExecInodeCore{})
	if got := engine.ExecInodeGateReport(); got.State != "unavailable" || got.Capability != "missing" {
		t.Fatalf("missing capability reported as %+v", got)
	}
	now := time.Now().UTC()
	engine.consumeExecInodeStatus(CoreExecInodeStatus{
		Enabled: true, OffsetsOK: true, Trusted: 12, Allowed: 3, Denied: 1,
		Events: 4, MalwareLocks: 2, ExpiredLocks: 1,
	}, nil, now)
	report := engine.ExecInodeGateReport()
	if report.State != "active" || !report.Active || report.Trusted != 12 || report.SampledAt == nil {
		t.Fatalf("active gate reported as %+v", report)
	}
	engine.consumeExecInodeStatus(CoreExecInodeStatus{Enabled: true, OffsetsOK: true}, nil, now)
	if got := engine.ExecInodeGateReport(); got.State != "degraded" || !strings.Contains(got.Reason, "no trusted executable identity") {
		t.Fatalf("gate without trusted identities reported as %+v", got)
	}
	engine.consumeExecInodeStatus(CoreExecInodeStatus{Enabled: false, OffsetsOK: false, Trusted: 4}, nil, now)
	if got := engine.ExecInodeGateReport(); got.State != "degraded" || !strings.Contains(got.Reason, "comm fallback") {
		t.Fatalf("disarmed gate reported as %+v", got)
	}
	engine.consumeExecInodeStatus(CoreExecInodeStatus{}, ErrExecInodeUnavailable, now)
	if got := engine.ExecInodeGateReport(); got.State != "unavailable" || got.Capability != "missing" {
		t.Fatalf("capability loss reported as %+v", got)
	}
}

func TestExecInodeMismatchCreatesObserveOnlyIncident(t *testing.T) {
	engine := newExecInodeTestEngine(&fakeExecInodeCore{})
	now := time.Now().UTC()
	engine.consumeExecInodeEvents(
		[]CoreExecInodeEvent{execInodeTestEvent(4242, 123456, ExecInodeActionObservedMismatch, 1)},
		0, nil, now)
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 1 {
		t.Fatalf("expected one name/path mismatch incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if !containsString(incident.RuleIDs, "XDR.NAME_PATH_MISMATCH") {
		t.Fatalf("mismatch rule id missing: %+v", incident.RuleIDs)
	}
	if incident.Decision != "alert" || incident.Action != "none" || incident.Severity != "high" {
		t.Fatalf("mismatch incident is not observe-only: %+v", incident)
	}
	if len(incident.AttackStory) != 1 ||
		incident.AttackStory[0].Metadata["sbc_signal"] != "name_path_mismatch" ||
		incident.AttackStory[0].Metadata["kill_eligibility"] != "none" {
		t.Fatalf("mismatch attack story is wrong: %+v", incident.AttackStory)
	}
	// Dedupe by (ts, pid, ino, action): the same kernel record is one incident.
	engine.consumeExecInodeEvents(
		[]CoreExecInodeEvent{execInodeTestEvent(4242, 123456, ExecInodeActionObservedMismatch, 1)},
		0, nil, now)
	if got := len(engine.state.Snapshot().Incidents); got != 1 {
		t.Fatalf("duplicate mismatch record created %d incidents", got)
	}
}

func TestExecInodeDenyCorrelatesOrStandsAlone(t *testing.T) {
	now := time.Now().UTC()
	standalone := newExecInodeTestEngine(&fakeExecInodeCore{})
	standalone.consumeExecInodeEvents(
		[]CoreExecInodeEvent{execInodeTestEvent(4242, 123456, ExecInodeActionDeniedUntrusted, 2)},
		0, nil, now)
	incidents := standalone.state.Snapshot().Incidents
	if len(incidents) != 1 || !containsString(incidents[0].RuleIDs, "XDR.CREDENTIAL_READ_BLOCKED") {
		t.Fatalf("standalone inode deny incident missing: %+v", incidents)
	}
	if incidents[0].Action != "none" || incidents[0].Decision != "deny" {
		t.Fatalf("standalone inode deny issued a response: %+v", incidents[0])
	}

	correlated := newExecInodeTestEngine(&fakeExecInodeCore{})
	correlated.appendIncident(XDRIncident{
		ID: "prior-credential-deny", Time: now.Add(-time.Minute), Severity: "high",
		PID: 4242, Process: "sshd",
		RuleIDs: []string{"XDR.CREDENTIAL_READ_BLOCKED"}, Categories: []string{"credential"},
		ExecutionChainID: "chain-4242", EvidenceRoot: "evidence-root",
	})
	correlated.consumeExecInodeEvents(
		[]CoreExecInodeEvent{execInodeTestEvent(4242, 123456, ExecInodeActionDeniedUntrusted, 2)},
		0, nil, now)
	if got := len(correlated.state.Snapshot().Incidents); got != 1 {
		t.Fatalf("correlated inode deny created a duplicate incident (%d incidents)", got)
	}
	found := false
	for _, event := range correlated.state.Snapshot().Events {
		if event.Kind == "xdr.exec_inode_deny_correlated" {
			found = true
		}
	}
	if !found {
		t.Fatal("correlated inode deny did not emit a correlation event")
	}
}

func TestExecInodeCommFallbackIsReportedOnce(t *testing.T) {
	engine := newExecInodeTestEngine(&fakeExecInodeCore{})
	now := time.Now().UTC()
	engine.consumeExecInodeEvents([]CoreExecInodeEvent{
		execInodeTestEvent(4242, 0, ExecInodeActionFallbackComm, 3),
		execInodeTestEvent(77, 0, ExecInodeActionFallbackComm, 4),
	}, 0, nil, now)
	count := 0
	for _, event := range engine.state.Snapshot().Events {
		if event.Kind == "xdr.exec_inode_comm_fallback" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("comm fallback was reported %d times, expected one bounded warning", count)
	}
	if got := len(engine.state.Snapshot().Incidents); got != 0 {
		t.Fatalf("comm fallback produced %d incidents, expected none", got)
	}
}

func TestExecInodePollSamplesStatusAndDrainsEvents(t *testing.T) {
	fake := &fakeExecInodeCore{
		status: CoreExecInodeStatus{Enabled: true, OffsetsOK: true, Trusted: 3},
		events: []CoreExecInodeEvent{
			execInodeTestEvent(4242, 123456, ExecInodeActionObservedMismatch, 5),
		},
	}
	engine := newExecInodeTestEngine(fake)
	now := time.Now().UTC()
	next := engine.pollExecInode(RuntimeSettings{XDREnabled: true}, now, time.Time{})
	if next != now.Add(time.Second) {
		t.Fatalf("poll cadence is wrong: %v", next)
	}
	if fake.statusQs != 1 || fake.eventsQs != 1 {
		t.Fatalf("poll did not run one status + drain cycle: status=%d events=%d", fake.statusQs, fake.eventsQs)
	}
	if got := engine.ExecInodeGateReport(); got.State != "active" {
		t.Fatalf("poll did not store the active gate sample: %+v", got)
	}
	// A second poll inside the 1 s window is a no-op.
	if next = engine.pollExecInode(RuntimeSettings{XDREnabled: true}, now.Add(100*time.Millisecond), next); next != now.Add(time.Second) {
		t.Fatalf("early poll changed the retry state: %v", next)
	}
	if fake.statusQs != 1 || fake.eventsQs != 1 {
		t.Fatalf("early poll issued core commands: status=%d events=%d", fake.statusQs, fake.eventsQs)
	}
	// XDR disabled is a hard no-op.
	engine.pollExecInode(RuntimeSettings{XDREnabled: false}, now.Add(time.Minute), time.Time{})
	if fake.statusQs != 1 || fake.eventsQs != 1 {
		t.Fatalf("disabled XDR still queried the core: status=%d events=%d", fake.statusQs, fake.eventsQs)
	}
}
