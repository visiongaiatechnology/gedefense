package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// POINT 4 / P4-T2: the engine contract (docs/POINT4-WITNESS.md §4, §8).
// The engine is inert by default, creates verifiable checkpoints, never treats a
// rotation as an alarm, and escalates a fork/rollback through evidence, incident
// and - only when asked - the additive P5 trigger.

// fakeWitnessTransport is the no-network push side used by the engine and API
// tests. It produces syntactically valid receipts; the engine's fake path does
// not verify a signature it cannot hold, which is exactly the seam the test
// wants.
type fakeWitnessTransport struct {
	mu           sync.Mutex
	challenges   int
	pushes       int
	sequence     uint64
	challengeErr error
	pushErr      error
	checkpoints  []WitnessCheckpoint
}

func (f *fakeWitnessTransport) Challenge(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.challenges++
	if f.challengeErr != nil {
		return "", f.challengeErr
	}
	return fmt.Sprintf("%032x", f.challenges), nil
}

func (f *fakeWitnessTransport) Push(_ context.Context, checkpoint WitnessCheckpoint) (WitnessReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushes++
	f.checkpoints = append(f.checkpoints, checkpoint)
	if f.pushErr != nil {
		return WitnessReceipt{}, f.pushErr
	}
	f.sequence++
	return WitnessReceipt{
		WitnessID: "witness-1", WitnessSeq: f.sequence, CheckpointID: checkpoint.CheckpointID,
		AcceptedAt: "2026-11-15T12:00:00Z", Signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}, nil
}

func (f *fakeWitnessTransport) LastWitnessSeq() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sequence
}

func (f *fakeWitnessTransport) ChallengePending() bool { return false }

func (f *fakeWitnessTransport) snapshot() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.challenges, f.pushes
}

// fakeWitnessLockdown records the additive P5 trigger calls.
type fakeWitnessLockdown struct {
	mu           sync.Mutex
	fingerprints []string
	err          error
}

func (f *fakeWitnessLockdown) TriggerWitnessEquivocation(fingerprint string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fingerprints = append(f.fingerprints, fingerprint)
	return f.err
}

func (f *fakeWitnessLockdown) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.fingerprints)
}

type witnessEngineFixture struct {
	engine   *WitnessEngine
	state    *State
	ledger   *EvidenceLedger
	store    *SettingsStore
	settings WitnessFabricSettings
}

func newWitnessEngineFixture(t *testing.T, mutate func(*WitnessFabricSettings), transport witnessTransport, lockdown WitnessLockdownTrigger) *witnessEngineFixture {
	t.Helper()
	store, _, _ := witnessStoreFixture(t)
	cfg := defaultConfig()
	state := NewState("test", cfg)
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	witness := defaultWitnessFabricSettings()
	if mutate != nil {
		mutate(&witness)
	}
	current := store.Get()
	current.Witness = &witness
	if _, err := store.Update(current); err != nil {
		t.Fatalf("enable witness settings: %v", err)
	}
	dir := t.TempDir()
	engine, err := NewWitnessEngine(WitnessEngineConfig{
		NodeID: "test-node", Ledger: ledger, Settings: store, State: state,
		Storage: witnessTestStorageCipher(t), OutboxPath: filepath.Join(dir, "witness", "outbox.enc"),
		AckPath:   filepath.Join(dir, "witness", "ack.enc"),
		Transport: transport, Lockdown: lockdown,
		Now: func() time.Time { return time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("witness engine: %v", err)
	}
	return &witnessEngineFixture{engine: engine, state: state, ledger: ledger, store: store, settings: witness}
}

func witnessStateHasEvent(state *State, kind string) bool {
	for _, event := range state.Snapshot().Events {
		if event.Kind == kind {
			return true
		}
	}
	return false
}

func TestWitnessEngineDefaultOffIsInert(t *testing.T) {
	store, _, _ := witnessStoreFixture(t)
	cfg := defaultConfig()
	state := NewState("test", cfg)
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	transport := &fakeWitnessTransport{}
	dir := t.TempDir()
	engine, err := NewWitnessEngine(WitnessEngineConfig{
		NodeID: "test-node", Ledger: ledger, Settings: store, State: state,
		Storage: witnessTestStorageCipher(t), OutboxPath: filepath.Join(dir, "witness", "outbox.enc"),
		AckPath: filepath.Join(dir, "witness", "ack.enc"), Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	status := engine.StatusView()
	if status.Enabled || status.Mode != witnessModeOff || status.Wired {
		t.Fatalf("the default engine claims to be active: %+v", status)
	}
	if _, err := engine.CheckpointNow(context.Background()); err == nil {
		t.Fatal("a disabled engine created a checkpoint")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Run(ctx)
	time.Sleep(120 * time.Millisecond)
	cancel()
	if challenges, pushes := transport.snapshot(); challenges != 0 || pushes != 0 {
		t.Fatalf("a disabled engine sent requests: challenges=%d pushes=%d", challenges, pushes)
	}
	if len(state.Snapshot().Events) != 0 {
		t.Fatalf("a disabled engine wrote events: %+v", state.Snapshot().Events)
	}
	if _, err := os.Stat(filepath.Join(dir, "witness")); !os.IsNotExist(err) {
		t.Fatal("a disabled engine created the witness state directory")
	}
}

func TestWitnessEngineCreatesVerifiableCheckpoint(t *testing.T) {
	fixture := newWitnessEngineFixture(t, func(witness *WitnessFabricSettings) {
		witness.Enabled = true
		witness.Mode = witnessModeExport
	}, nil, nil)
	fixture.ledger.Append(EvidenceRecord{Severity: "info", Kind: "test.one", Source: "test", Message: "first"})
	fixture.ledger.Append(EvidenceRecord{Severity: "info", Kind: "test.two", Source: "test", Message: "second"})
	checkpoint, err := fixture.engine.CheckpointNow(context.Background())
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if err := ValidateWitnessCheckpoint(checkpoint); err != nil {
		t.Fatalf("the checkpoint does not validate: %v", err)
	}
	if err := VerifyWitnessCheckpoint(checkpoint, fixture.ledger.publicKey); err != nil {
		t.Fatalf("the checkpoint signature does not verify: %v", err)
	}
	if checkpoint.Sequence != 2 || checkpoint.Records != 2 || checkpoint.LedgerEpoch != 0 {
		t.Fatalf("the checkpoint does not seal the ledger head: %+v", checkpoint)
	}
	if checkpoint.SensorState != "disabled" || checkpoint.QuoteKind != "none" {
		t.Fatalf("the checkpoint claims a capability it does not have: %+v", checkpoint)
	}
	if checkpoint.PolicyRevision != fixture.store.Get().Revision {
		t.Fatalf("policy revision = %d, want %d", checkpoint.PolicyRevision, fixture.store.Get().Revision)
	}
	if !witnessStateHasEvent(fixture.state, "witness.checkpoint.created") {
		t.Fatal("the creation was not recorded as evidence")
	}
	status := fixture.engine.StatusView()
	if status.Checkpoint == nil || status.Checkpoint.ID != checkpoint.CheckpointID {
		t.Fatalf("status does not project the created checkpoint: %+v", status)
	}
	if status.Wired == false || status.Healthy == false {
		t.Fatalf("an enabled export engine is not healthy: %+v", status)
	}
}

func TestWitnessEngineRotationIsNotAlarm(t *testing.T) {
	fixture := newWitnessEngineFixture(t, func(witness *WitnessFabricSettings) {
		witness.Enabled = true
		witness.Mode = witnessModeExport
	}, nil, nil)
	head := func(hash string) witnessHead {
		return witnessHead{epoch: 0, sequence: 5, headHash: hash}
	}
	fixture.engine.observeHead(head(repeatHex("aa", 32)))
	fixture.engine.observeHead(witnessHead{epoch: 1, sequence: 0, headHash: ""})
	fixture.engine.observeHead(witnessHead{epoch: 1, sequence: 1, headHash: repeatHex("bb", 32)})
	if status := fixture.engine.StatusView(); status.Equivocation {
		t.Fatalf("a legitimate rotation was reported as equivocation: %+v", status)
	}
	if witnessStateHasEvent(fixture.state, "witness.equivocation") {
		t.Fatal("a rotation wrote an equivocation event")
	}
}

func TestWitnessEngineForkAndRollbackAlarm(t *testing.T) {
	for name, sequence := range map[string][]witnessHead{
		"fork": {
			{epoch: 0, sequence: 5, headHash: repeatHex("aa", 32)},
			{epoch: 0, sequence: 5, headHash: repeatHex("bb", 32)},
		},
		"rollback": {
			{epoch: 1, sequence: 5, headHash: repeatHex("aa", 32)},
			{epoch: 1, sequence: 4, headHash: repeatHex("aa", 32)},
		},
	} {
		fixture := newWitnessEngineFixture(t, func(witness *WitnessFabricSettings) {
			witness.Enabled = true
			witness.Mode = witnessModeExport
		}, nil, nil)
		for _, head := range sequence {
			fixture.engine.observeHead(head)
		}
		status := fixture.engine.StatusView()
		if !status.Equivocation || status.EquivocationAt == nil || status.EquivocationKind != name {
			t.Fatalf("%s: equivocation was not reported: %+v", name, status)
		}
		if !witnessStateHasEvent(fixture.state, "witness.equivocation") {
			t.Fatalf("%s: no critical evidence was written", name)
		}
		incidentFound := false
		for _, incident := range fixture.state.Snapshot().Incidents {
			if len(incident.RuleIDs) > 0 && incident.RuleIDs[0] == "WITNESS.EQUIVOCATION" && incident.Severity == "critical" {
				incidentFound = true
			}
		}
		if !incidentFound {
			t.Fatalf("%s: no incident was created", name)
		}
	}
}

func TestWitnessEngineEquivocationLockdownTriggerIsOptional(t *testing.T) {
	fake := &fakeWitnessLockdown{}
	fixture := newWitnessEngineFixture(t, func(witness *WitnessFabricSettings) {
		witness.Enabled = true
		witness.Mode = witnessModeExport
		witness.TriggerLockdownOnEquivocation = true
	}, nil, fake)
	fixture.engine.observeHead(witnessHead{epoch: 0, sequence: 5, headHash: repeatHex("aa", 32)})
	fixture.engine.observeHead(witnessHead{epoch: 0, sequence: 5, headHash: repeatHex("bb", 32)})
	if fake.calls() != 1 {
		t.Fatalf("the configured P5 trigger was called %d times, want 1", fake.calls())
	}
	// A second observation of the same proven condition must not storm the engine;
	// the P5 dedupe/cooldown is authoritative and the local alarm is recorded once.
	fixture.engine.observeHead(witnessHead{epoch: 0, sequence: 5, headHash: repeatHex("cc", 32)})
	if fake.calls() != 1 {
		t.Fatalf("a repeated condition triggered again: %d calls", fake.calls())
	}

	disabled := &fakeWitnessLockdown{}
	offFixture := newWitnessEngineFixture(t, func(witness *WitnessFabricSettings) {
		witness.Enabled = true
		witness.Mode = witnessModeExport
		witness.TriggerLockdownOnEquivocation = false
	}, nil, disabled)
	offFixture.engine.observeHead(witnessHead{epoch: 0, sequence: 5, headHash: repeatHex("aa", 32)})
	offFixture.engine.observeHead(witnessHead{epoch: 0, sequence: 5, headHash: repeatHex("bb", 32)})
	if disabled.calls() != 0 {
		t.Fatalf("the P5 trigger ran although the operator did not enable it: %d calls", disabled.calls())
	}
}

func TestWitnessEnginePushAndAckPath(t *testing.T) {
	transport := &fakeWitnessTransport{}
	fixture := newWitnessEngineFixture(t, func(witness *WitnessFabricSettings) {
		witness.Enabled = true
		witness.Mode = witnessModeHTTP
		witness.Endpoint = "https://witness.example"
		witness.PinnedServerSPKI = repeatHex("ab", 32)
	}, transport, nil)
	fixture.ledger.Append(EvidenceRecord{Severity: "info", Kind: "test.one", Source: "test", Message: "first"})
	receipt, err := fixture.engine.PushNow(context.Background())
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if receipt.WitnessSeq != 1 || transport.pushes != 1 {
		t.Fatalf("push did not reach the transport: receipt=%+v pushes=%d", receipt, transport.pushes)
	}
	status := fixture.engine.StatusView()
	if status.LastAck == nil || status.LastAck.WitnessSeq != 1 {
		t.Fatalf("status does not project the acknowledgement: %+v", status)
	}
	if status.Outbox.Depth != 0 {
		t.Fatalf("the acknowledged entry was not pruned: %+v", status.Outbox)
	}
	if !witnessStateHasEvent(fixture.state, "witness.acked") {
		t.Fatal("the acknowledgement was not recorded as evidence")
	}
	// A failed push stays queued, records the warning and degrades only after the
	// configured threshold; unreachability is never an equivocation.
	transport.pushErr = errors.New("unreachable")
	if _, err := fixture.engine.CheckpointNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.engine.PushNow(context.Background()); err == nil {
		t.Fatal("a failing push was reported as success")
	}
	status = fixture.engine.StatusView()
	if status.Outbox.Depth != 1 {
		t.Fatalf("a failed push lost the checkpoint: %+v", status.Outbox)
	}
	if status.Equivocation {
		t.Fatal("a network failure was reported as equivocation")
	}
	if !witnessStateHasEvent(fixture.state, "witness.push.failed") {
		t.Fatal("a failed push was not recorded")
	}
}

func TestWitnessEngineOutboxFullFailsClosed(t *testing.T) {
	fixture := newWitnessEngineFixture(t, func(witness *WitnessFabricSettings) {
		witness.Enabled = true
		witness.Mode = witnessModeHTTP
		witness.Endpoint = "https://witness.example"
		witness.PinnedServerSPKI = repeatHex("ab", 32)
		witness.OutboxMaxEntries = witnessMinOutboxEntries
	}, &fakeWitnessTransport{}, nil)
	for index := 0; index < witnessMinOutboxEntries; index++ {
		if _, err := fixture.engine.CheckpointNow(context.Background()); err != nil {
			t.Fatalf("checkpoint %d: %v", index, err)
		}
	}
	if _, err := fixture.engine.CheckpointNow(context.Background()); err == nil {
		t.Fatal("a full outbox accepted another checkpoint")
	}
	if !witnessStateHasEvent(fixture.state, "witness.outbox_full") {
		t.Fatal("a full outbox was not recorded")
	}
	status := fixture.engine.StatusView()
	if !status.Outbox.Full || !status.Degraded {
		t.Fatalf("a full outbox is not reported fail-closed: %+v", status)
	}
}

func TestWitnessEngineApplyRuntimeSettingsActivatesAndDeactivates(t *testing.T) {
	fixture := newWitnessEngineFixture(t, nil, nil, nil)
	if fixture.engine.StatusView().Enabled {
		t.Fatal("the fixture is not inert")
	}
	settings := fixture.store.Get()
	witness := effectiveWitnessSettings(settings)
	witness.Enabled = true
	witness.Mode = witnessModeExport
	settings.Witness = &witness
	updated, err := fixture.store.Update(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.engine.ApplyRuntimeSettings(updated); err != nil {
		t.Fatalf("apply enable: %v", err)
	}
	if _, err := fixture.engine.CheckpointNow(context.Background()); err != nil {
		t.Fatalf("an enabled engine refused to create a checkpoint: %v", err)
	}
	witness.Enabled = false
	witness.Mode = witnessModeOff
	disabled := updated
	disabled.Witness = &witness
	disabled.Revision++
	if err := fixture.engine.ApplyRuntimeSettings(disabled); err != nil {
		t.Fatalf("apply disable: %v", err)
	}
	if _, err := fixture.engine.CheckpointNow(context.Background()); err == nil {
		t.Fatal("a deactivated engine still created a checkpoint")
	}
}

func repeatHex(value string, count int) string {
	out := ""
	for i := 0; i < count; i++ {
		out += value
	}
	return out
}
