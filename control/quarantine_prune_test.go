// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-7: evidence-first QUARANTINE_PRUNE test corpus.
//
// Proves the refusal ordering (evidence before the privileged core), the
// confirmation contract, identity-mismatch pass-through, the success path with a
// fake core and the bounded input validation.

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeQuarantinePruneCore struct {
	calls        int
	lastObjectID string
	lastIdentity QuarantineIdentity
	state        string
	err          error
}

func (f *fakeQuarantinePruneCore) QuarantinePrune(objectID string, identity QuarantineIdentity) (string, error) {
	f.calls++
	f.lastObjectID = objectID
	f.lastIdentity = identity
	if f.err != nil {
		return "", f.err
	}
	if f.state == "" {
		return "pruned", nil
	}
	return f.state, nil
}

type fakeQuarantinePruneEvidence struct {
	calls   int
	failAt  int
	records []EvidenceRecord
}

func (f *fakeQuarantinePruneEvidence) RecordEvidence(record EvidenceRecord) error {
	f.calls++
	if f.failAt > 0 && f.calls == f.failAt {
		return errors.New("evidence ledger unavailable")
	}
	f.records = append(f.records, record)
	return nil
}

func quarantinePruneTestFixture(t *testing.T) (*fakeQuarantinePruneCore, *fakeQuarantinePruneEvidence, *quarantinePruner, string, QuarantineIdentity) {
	t.Helper()
	core := &fakeQuarantinePruneCore{}
	evidence := &fakeQuarantinePruneEvidence{}
	events := make([]Event, 0, 2)
	pruner := newQuarantinePruner(core, evidence, func(event Event) {
		events = append(events, event)
	})
	pruner.now = func() time.Time { return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) }
	objectID := "QV-0123456789abcdef"
	identity := quarantineTestIdentity("a")
	return core, evidence, pruner, objectID, identity
}

func TestQuarantinePruneEvidenceFirstRefusal(t *testing.T) {
	core, evidence, pruner, objectID, identity := quarantinePruneTestFixture(t)
	evidence.failAt = 1
	_, err := pruner.Prune(objectID, &identity, objectID)
	if err == nil {
		t.Fatal("prune succeeded although the mandatory evidence commit failed")
	}
	if !errors.Is(err, errQuarantinePruneEvidence) {
		t.Fatalf("evidence failure was not classified: %v", err)
	}
	if !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("evidence refusal does not name the blocking condition: %v", err)
	}
	if core.calls != 0 {
		t.Fatalf("privileged core was contacted before evidence was durable: %d calls", core.calls)
	}
	if len(evidence.records) != 0 {
		t.Fatalf("failed intent evidence was nonetheless recorded: %d", len(evidence.records))
	}
}

func TestQuarantinePruneConfirmMismatchRefused(t *testing.T) {
	core, evidence, pruner, objectID, identity := quarantinePruneTestFixture(t)
	if _, err := pruner.Prune(objectID, &identity, "QV-ffffffffffffffff"); err == nil {
		t.Fatal("prune with a confirm field that does not equal the object id was accepted")
	}
	if core.calls != 0 || evidence.calls != 0 {
		t.Fatalf("a rejected confirmation still contacted core/evidence: core=%d evidence=%d", core.calls, evidence.calls)
	}
	if _, err := pruner.Prune(objectID, nil, objectID); err == nil {
		t.Fatal("prune without an identity was accepted")
	}
	if core.calls != 0 {
		t.Fatal("identity-less prune reached the privileged core")
	}
	var invalidID QuarantineIdentity
	if _, err := pruner.Prune("QV-0123", &invalidID, "QV-0123"); err == nil {
		t.Fatal("invalid object id / identity was accepted")
	}
}

func TestQuarantinePruneIdentityMismatchPassesThroughCoreError(t *testing.T) {
	core, evidence, pruner, objectID, identity := quarantinePruneTestFixture(t)
	core.err = errors.New("quarantine object header binding mismatch")
	_, err := pruner.Prune(objectID, &identity, objectID)
	if err == nil {
		t.Fatal("core identity mismatch did not fail the prune")
	}
	if !errors.Is(err, errQuarantinePruneRejected) {
		t.Fatalf("core refusal was not classified as a prune rejection: %v", err)
	}
	if !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("core identity mismatch detail was lost: %v", err)
	}
	if core.calls != 1 {
		t.Fatalf("expected exactly one core call, got %d", core.calls)
	}
	if len(evidence.records) != 2 ||
		evidence.records[0].Kind != "quarantine.prune.intent" ||
		evidence.records[1].Kind != "quarantine.prune.failed" {
		t.Fatalf("failed prune did not record intent + failure evidence: %+v", evidence.records)
	}
}

func TestQuarantinePruneSuccessPathIsEvidenceBacked(t *testing.T) {
	core, evidence, pruner, objectID, identity := quarantinePruneTestFixture(t)
	core.state = "pruned"
	result, err := pruner.Prune(objectID, &identity, objectID)
	if err != nil {
		t.Fatalf("verified prune failed: %v", err)
	}
	if result.State != "pruned" || result.ObjectID != objectID || result.SHA256 != identity.SHA256 || result.Size != identity.Size {
		t.Fatalf("unexpected prune result: %+v", result)
	}
	if core.lastObjectID != objectID || core.lastIdentity != identity {
		t.Fatalf("core received the wrong prune request: id=%q identity=%+v", core.lastObjectID, core.lastIdentity)
	}
	if len(evidence.records) != 2 {
		t.Fatalf("expected intent + confirmation evidence, got %d", len(evidence.records))
	}
	if evidence.records[0].Kind != "quarantine.prune.intent" || evidence.records[1].Kind != "quarantine.prune.confirmed" {
		t.Fatalf("evidence ordering is not intent -> confirmed: %+v", evidence.records)
	}
	if evidence.records[0].Target != objectID || evidence.records[1].Target != objectID {
		t.Fatalf("evidence records do not bind the object id: %+v", evidence.records)
	}
}

func TestQuarantinePruneConfirmationEvidenceFailureIsReported(t *testing.T) {
	core, evidence, pruner, objectID, identity := quarantinePruneTestFixture(t)
	core.state = "pruned"
	evidence.failAt = 2
	result, err := pruner.Prune(objectID, &identity, objectID)
	if err == nil {
		t.Fatal("a prune whose confirmation evidence failed reported full success")
	}
	if !errors.Is(err, errQuarantinePruneConfirmOnly) {
		t.Fatalf("confirmation-evidence failure was not classified: %v", err)
	}
	if result.ObjectID != objectID {
		t.Fatalf("the caller cannot tell what was already pruned: %+v", result)
	}
}

func TestQuarantinePruneInvalidStatesRejected(t *testing.T) {
	_, _, pruner, objectID, identity := quarantinePruneTestFixture(t)
	pruner.core = &fakeQuarantinePruneCore{state: "restored"}
	if _, err := pruner.Prune(objectID, &identity, objectID); err == nil {
		t.Fatal("an unexpected core prune state was accepted")
	}
	nilPruner := &quarantinePruner{now: func() time.Time { return time.Now() }}
	if _, err := nilPruner.Prune(objectID, &identity, objectID); err == nil {
		t.Fatal("prune without a privileged core was accepted")
	}
}
