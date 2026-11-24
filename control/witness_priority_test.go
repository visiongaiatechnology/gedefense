// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-9 (S08/S15): the anti-truncate priority-witness regression suite.
// Everything runs in-process: the witness transport is a fake, the evidence ledger
// and the forensic logger are real temporary files, and no socket is opened.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- fixtures

func witnessPriorityEngine(t *testing.T) (*XDREngine, *State, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "incidents.jsonl")
	logger, err := NewIncidentLogger(logPath, filepath.Join(dir, "xdr.key"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	state := NewState("witness-priority-test", cfg)
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	engine := &XDREngine{cfg: cfg, state: state, logger: logger, degradeCauses: map[string]string{}}
	return engine, state, logPath
}

// witnessPriorityEnabledStore returns a settings store whose witness namespace is
// enabled in http mode with a pinned transport anchor. No request is ever sent:
// the priority pusher gets an injected transport in these tests.
func witnessPriorityEnabledStore(t *testing.T) *SettingsStore {
	t.Helper()
	store, _, _ := witnessStoreFixture(t)
	settings := store.Get()
	witness := effectiveWitnessSettings(settings)
	witness.Enabled = true
	witness.Mode = witnessModeHTTP
	witness.Endpoint = "https://witness.example"
	witness.PinnedServerSPKI = strings.Repeat("ab", 32)
	settings.Witness = &witness
	if _, err := store.Update(settings); err != nil {
		t.Fatalf("enabling the test witness namespace: %v", err)
	}
	return store
}

func witnessPriorityEvidenceIncident(id string) XDRIncident {
	return XDRIncident{
		ID: id, Time: time.Now().UTC(), Severity: "critical", Score: 250,
		RuleIDs: []string{"XDR.SELF_TAMPER"}, Categories: []string{"integrity"},
		Summary:  "Sensor self-protection integrity failure (test fixture)",
		Decision: "degrade", Action: "disable-response", Outcome: "observed",
	}
}

type witnessPriorityRecordingSink struct {
	mu    sync.Mutex
	calls []XDRIncident
	// onPush runs synchronously inside the hand-off, which is what lets the
	// ordering test observe the forensic log before it is written.
	onPush func()
}

func (s *witnessPriorityRecordingSink) pushCriticalWitness(incident XDRIncident) {
	s.mu.Lock()
	s.calls = append(s.calls, incident)
	s.mu.Unlock()
	if s.onPush != nil {
		s.onPush()
	}
}

func (s *witnessPriorityRecordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// witnessPriorityFakeTransport is a scripted witnessTransport. It never touches
// the network and records the exact checkpoint the pusher produced.
type witnessPriorityFakeTransport struct {
	mu           sync.Mutex
	challenges   int
	pushes       int
	challengeErr error
	pushErr      error
	gate         chan struct{}
	checkpoint   WitnessCheckpoint
}

func (f *witnessPriorityFakeTransport) Challenge(_ context.Context) (string, error) {
	f.mu.Lock()
	f.challenges++
	gate := f.gate
	err := f.challengeErr
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if err != nil {
		return "", err
	}
	return strings.Repeat("ab", 16), nil
}

func (f *witnessPriorityFakeTransport) Push(_ context.Context, checkpoint WitnessCheckpoint) (WitnessReceipt, error) {
	f.mu.Lock()
	f.pushes++
	f.checkpoint = checkpoint
	err := f.pushErr
	f.mu.Unlock()
	if err != nil {
		return WitnessReceipt{}, err
	}
	return WitnessReceipt{
		WitnessID: "witness-test", WitnessSeq: 1, CheckpointID: checkpoint.CheckpointID,
		AcceptedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (f *witnessPriorityFakeTransport) LastWitnessSeq() uint64 { return 0 }
func (f *witnessPriorityFakeTransport) ChallengePending() bool { return false }

func (f *witnessPriorityFakeTransport) counts() (challenges, pushes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.challenges, f.pushes
}

func (f *witnessPriorityFakeTransport) lastCheckpoint() WitnessCheckpoint {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checkpoint
}

func witnessPriorityCounters(pusher *criticalWitnessPusher) (delivered, failed, dropped uint64) {
	pusher.mu.Lock()
	defer pusher.mu.Unlock()
	return pusher.delivered, pusher.failed, pusher.dropped
}

func waitForWitnessCondition(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s", message)
}

// ------------------------------------------------------------------- tests

// TestWitnessPriorityTriggerSet pins the trigger set: evidence-category and
// self-tamper findings are pushed, ordinary critical findings are not (flood
// protection), and severity alone is never a trigger.
func TestWitnessPriorityTriggerSet(t *testing.T) {
	cases := []struct {
		name     string
		incident XDRIncident
		want     bool
	}{
		{"self-tamper rule", XDRIncident{RuleIDs: []string{"XDR.SELF_TAMPER"}}, true},
		{"self-artifact rule", XDRIncident{RuleIDs: []string{"XDR.SELF_ARTIFACT"}}, true},
		{"integrity category", XDRIncident{Categories: []string{"integrity"}}, true},
		{"evidence category", XDRIncident{Categories: []string{"Evidence"}}, true},
		{"gief evidence family", XDRIncident{GIEF: &GIEFEnvelope{SBCFamily: SBCFamilyEvidence}}, true},
		{"critical network finding", XDRIncident{
			Severity: "critical", RuleIDs: []string{"XDR.ANOMALY.CONNECTION_FANOUT"}, Categories: []string{"network"},
		}, false},
		{"critical behaviour finding", XDRIncident{
			Severity: "critical", Score: 250, RuleIDs: []string{"BASELINE.PARENT_MISMATCH"}, Categories: []string{"behavior"},
		}, false},
		{"ransomware category alone", XDRIncident{
			Severity: "critical", RuleIDs: []string{"XDR.RANSOM_ENTROPY_BURST"}, Categories: []string{"ransomware"},
		}, false},
		{"empty finding", XDRIncident{}, false},
	}
	for _, tc := range cases {
		if got := criticalWitnessTrigger(tc.incident); got != tc.want {
			t.Errorf("%s: trigger=%v want=%v", tc.name, got, tc.want)
		}
	}
}

// TestWitnessPriorityOrderingBeforeForensicAppend proves the seam order: the
// out-of-band hand-off happens before the local forensic record is written, which
// is what makes a later local truncation unable to erase the only copy.
func TestWitnessPriorityOrderingBeforeForensicAppend(t *testing.T) {
	engine, state, logPath := witnessPriorityEngine(t)
	sink := &witnessPriorityRecordingSink{}
	var logAtHandoff string
	sink.onPush = func() {
		raw, err := os.ReadFile(logPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("read incident log during hand-off: %v", err)
		}
		logAtHandoff = string(raw)
	}
	attachCriticalWitnessSinkForTest(engine, sink)
	defer detachCriticalWitnessSinkForTest(engine)

	incident := witnessPriorityEvidenceIncident("self-tamper-ordering-1")
	engine.appendIncident(incident)

	if sink.count() != 1 {
		t.Fatalf("the evidence-category finding was not handed to the witness: %d", sink.count())
	}
	if strings.Contains(logAtHandoff, incident.ID) {
		t.Fatalf("the forensic record was already written before the witness hand-off: %q", logAtHandoff)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(raw), incident.ID) {
		t.Fatalf("the incident never reached the forensic log: %v %q", err, raw)
	}
	if incidents := state.Snapshot().Incidents; len(incidents) != 1 || incidents[0].ID != incident.ID {
		t.Fatalf("the incident state stream does not carry the finding: %+v", incidents)
	}
}

// TestWitnessPriorityNonEvidenceFindingsAreNotPushed proves the flood protection
// half of the trigger: a critical but non-evidence finding never reaches the
// witness path.
func TestWitnessPriorityNonEvidenceFindingsAreNotPushed(t *testing.T) {
	engine, _, _ := witnessPriorityEngine(t)
	sink := &witnessPriorityRecordingSink{}
	attachCriticalWitnessSinkForTest(engine, sink)
	defer detachCriticalWitnessSinkForTest(engine)

	engine.pushCriticalWitness(XDRIncident{
		ID: "network-finding-1", Severity: "critical", Score: 250,
		RuleIDs: []string{"XDR.ANOMALY.CONNECTION_FANOUT"}, Categories: []string{"network"},
	})
	if sink.count() != 0 {
		t.Fatalf("a non-evidence finding was pushed to the witness: %d", sink.count())
	}
	engine.pushCriticalWitness(witnessPriorityEvidenceIncident("self-tamper-2"))
	if sink.count() != 1 {
		t.Fatalf("an evidence finding was not pushed: %d", sink.count())
	}
}

// TestWitnessPriorityDedupeAndSignedCheckpoint proves that one finding produces at
// most one push, and that the push is a witness-valid signed checkpoint of the
// authenticated ledger head.
func TestWitnessPriorityDedupeAndSignedCheckpoint(t *testing.T) {
	engine, state, _ := witnessPriorityEngine(t)
	engine.settings = witnessPriorityEnabledStore(t)
	// The evidence-first rule commits the finding's evidence record before the
	// incident exists; the priority checkpoint must bind that head.
	if err := state.RecordEvidence(EvidenceRecord{
		Severity: "critical", Kind: "xdr.self_tamper", Source: "integrity",
		Message: "Self-protection fact recorded before any response (test fixture)",
	}); err != nil {
		t.Fatal(err)
	}
	transport := &witnessPriorityFakeTransport{}
	pusher := newCriticalWitnessPusher(engine)
	pusher.transportFactory = func(WitnessFabricSettings, func() time.Time) (witnessTransport, error) {
		return transport, nil
	}
	defer pusher.close()

	incident := witnessPriorityEvidenceIncident("dedupe-1")
	pusher.pushCriticalWitness(incident)
	pusher.pushCriticalWitness(incident)
	pusher.pushCriticalWitness(incident)

	waitForWitnessCondition(t, 2*time.Second, func() bool {
		delivered, _, _ := witnessPriorityCounters(pusher)
		return delivered == 1
	}, "the priority checkpoint was not delivered")
	time.Sleep(50 * time.Millisecond)
	if challenges, pushes := transport.counts(); challenges != 1 || pushes != 1 {
		t.Fatalf("a duplicate finding produced extra witness traffic: challenges=%d pushes=%d", challenges, pushes)
	}
	checkpoint := transport.lastCheckpoint()
	if checkpoint.Challenge == "" {
		t.Fatal("the pushed checkpoint carries no challenge")
	}
	ledger := state.EvidenceLedger()
	if err := VerifyWitnessCheckpoint(checkpoint, ledger.publicKey); err != nil {
		t.Fatalf("the priority push is not a witness-valid signed checkpoint: %v", err)
	}
	if checkpoint.NodeID == "" || checkpoint.Records == 0 {
		t.Fatalf("the priority checkpoint names no node or no records: %+v", checkpoint)
	}
}

// TestWitnessPriorityUnavailableIsReportedOnceHonestly proves a host without the
// witness reports that fact once, creates no incident and does not call the gap a
// delivery failure.
func TestWitnessPriorityUnavailableIsReportedOnceHonestly(t *testing.T) {
	engine, state, _ := witnessPriorityEngine(t)
	// The default settings store leaves the witness namespace disabled.
	store, _, _ := witnessStoreFixture(t)
	engine.settings = store
	pusher := newCriticalWitnessPusher(engine)
	defer pusher.close()

	record := criticalWitnessRecordFromIncident(witnessPriorityEvidenceIncident("unavailable-1"), time.Now().UTC())
	pusher.deliver(record)
	pusher.deliver(criticalWitnessRecordFromIncident(witnessPriorityEvidenceIncident("unavailable-2"), time.Now().UTC()))

	delivered, failed, _ := witnessPriorityCounters(pusher)
	if delivered != 0 || failed != 0 {
		t.Fatalf("a disabled witness was reported as a delivery outcome: delivered=%d failed=%d", delivered, failed)
	}
	unavailable := 0
	failedEvents := 0
	for _, event := range state.Snapshot().Events {
		switch event.Kind {
		case "xdr.witness_priority_unavailable":
			unavailable++
		case "xdr.witness_priority_failed":
			failedEvents++
		}
	}
	if unavailable != 1 {
		t.Fatalf("the unavailable witness capability was not reported exactly once: %d", unavailable)
	}
	if failedEvents != 0 {
		t.Fatalf("a disabled witness was reported as a failed push: %d", failedEvents)
	}
	if incidents := state.Snapshot().Incidents; len(incidents) != 0 {
		t.Fatalf("the unavailable capability created an incident: %+v", incidents)
	}
}

// TestWitnessPriorityFailureIsReportedHonestly proves a failed push is never
// swallowed: it is counted, reported as a bounded event, and repeated failures
// inside the cooldown do not flood the event stream.
func TestWitnessPriorityFailureIsReportedHonestly(t *testing.T) {
	engine, state, _ := witnessPriorityEngine(t)
	engine.settings = witnessPriorityEnabledStore(t)
	transport := &witnessPriorityFakeTransport{challengeErr: errors.New("witness unreachable")}
	pusher := newCriticalWitnessPusher(engine)
	pusher.transportFactory = func(WitnessFabricSettings, func() time.Time) (witnessTransport, error) {
		return transport, nil
	}
	defer pusher.close()

	record := criticalWitnessRecordFromIncident(witnessPriorityEvidenceIncident("failed-1"), time.Now().UTC())
	pusher.deliver(record)
	pusher.deliver(criticalWitnessRecordFromIncident(witnessPriorityEvidenceIncident("failed-2"), time.Now().UTC()))

	_, failed, _ := witnessPriorityCounters(pusher)
	if failed != 2 {
		t.Fatalf("failed pushes were not counted honestly: %d", failed)
	}
	failureEvents := 0
	for _, event := range state.Snapshot().Events {
		if event.Kind == "xdr.witness_priority_failed" {
			failureEvents++
		}
	}
	if failureEvents != 1 {
		t.Fatalf("the bounded failure event was not written exactly once per cooldown: %d", failureEvents)
	}
	if incidents := state.Snapshot().Incidents; len(incidents) != 0 {
		t.Fatalf("a failed witness push created an incident: %+v", incidents)
	}
}

// TestWitnessPriorityBoundedQueueUnderFlood proves 1000 rapid evidence findings
// cannot grow memory without bound and cannot panic the ingest path.
func TestWitnessPriorityBoundedQueueUnderFlood(t *testing.T) {
	engine, _, _ := witnessPriorityEngine(t)
	engine.settings = witnessPriorityEnabledStore(t)
	gate := make(chan struct{})
	transport := &witnessPriorityFakeTransport{gate: gate}
	pusher := newCriticalWitnessPusher(engine)
	pusher.transportFactory = func(WitnessFabricSettings, func() time.Time) (witnessTransport, error) {
		return transport, nil
	}

	for index := 0; index < 1000; index++ {
		pusher.pushCriticalWitness(witnessPriorityEvidenceIncident("flood-" + formatUnix(int64(index))))
	}
	if depth := len(pusher.queue); depth > witnessPriorityQueueCapacity {
		t.Fatalf("the priority queue grew past its bound: %d", depth)
	}
	_, _, dropped := witnessPriorityCounters(pusher)
	if dropped == 0 {
		t.Fatal("an overflow beyond the bounded queue was not counted")
	}
	close(gate)
	waitForWitnessCondition(t, 5*time.Second, func() bool { return len(pusher.queue) == 0 }, "the bounded queue did not drain")
	pusher.close()
	if depth := len(pusher.queue); depth != 0 {
		t.Fatalf("records survived the worker shutdown: %d", depth)
	}
}
