// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestCaseEngine(
	t *testing.T,
	evidence func(EvidenceRecord) error,
) (*CaseEngine, string, *StorageCipher) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "storage.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x71}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	storage, err := NewStorageCipher(keyPath, "case-test-node")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cases.enc")
	engine, err := NewCaseEngine(path, storage, evidence)
	if err != nil {
		t.Fatal(err)
	}
	return engine, path, storage
}

// testCaseIncident builds a fixture that clears the case-creation score floor.
//
// The XDR score scale is 0-250, not 0-100: rule scores in this codebase are 50, 55,
// 80, 120, 180 and 250, and the compiled-in MinimumIncidentScore default is 150 -
// the same bar xdr_l7.go uses for a serious L7 response. The previous fixture scored
// 90, which is below that floor, so it described an incident the case engine is
// meant to filter out rather than correlate. 180 matches how this codebase scores a
// high-severity process incident (xdr.go).
func testCaseIncident(id, severity string) XDRIncident {
	return XDRIncident{
		ID: id, Time: time.Unix(1_700_000_000, 0).UTC(),
		Severity: severity, Score: 180, ResponseScore: 175,
		PID: 77, StartTicks: 1234, Executable: "/usr/bin/test-threat",
		RuleIDs: []string{"XDR.TEST.ORIGIN"}, Categories: []string{"origin"},
		Summary:  "Executable origin violated trusted policy",
		Decision: "contain", Action: "stop", Outcome: "stopped",
	}
}

func TestCaseEngineCorrelatesPersistsAndReloadsEncrypted(t *testing.T) {
	engine, path, storage := newTestCaseEngine(
		t, func(EvidenceRecord) error { return nil },
	)
	if err := engine.IngestIncident(testCaseIncident("incident-a", "high")); err != nil {
		t.Fatal(err)
	}
	recurrence := testCaseIncident("incident-b", "critical")
	recurrence.Time = recurrence.Time.Add(time.Minute)
	if err := engine.IngestIncident(recurrence); err != nil {
		t.Fatal(err)
	}
	status := engine.Status(100)
	if !status.Healthy || status.Count != 1 || status.Open != 1 ||
		status.Cases[0].OccurrenceCount != 2 ||
		status.Cases[0].Severity != "critical" ||
		len(status.Cases[0].EvidenceIDs) != 2 {
		t.Fatalf("unexpected correlated case state: %+v", status)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("Executable origin violated")) ||
		bytes.Contains(raw, []byte("/usr/bin/test-threat")) {
		t.Fatal("case operational data leaked into plaintext storage")
	}

	reloaded, err := NewCaseEngine(path, storage, func(EvidenceRecord) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	reloadedStatus := reloaded.Status(100)
	if !reloadedStatus.Healthy || reloadedStatus.Count != 1 ||
		reloadedStatus.Cases[0].OccurrenceCount != 2 {
		t.Fatalf("reloaded case state mismatch: %+v", reloadedStatus)
	}
}

func TestCaseStatusMutationRequiresEvidenceAndDurableCommit(t *testing.T) {
	allowEvidence := true
	engine, _, _ := newTestCaseEngine(t, func(EvidenceRecord) error {
		if !allowEvidence {
			return os.ErrPermission
		}
		return nil
	})
	if err := engine.IngestIncident(testCaseIncident("incident-a", "high")); err != nil {
		t.Fatal(err)
	}
	record := engine.Status(1).Cases[0]
	allowEvidence = false
	if _, err := engine.SetStatus(record.ID, "resolved", "verified false positive"); err == nil {
		t.Fatal("case mutation succeeded without mandatory evidence commit")
	}
	if got := engine.Status(1).Cases[0].Status; got != "open" {
		t.Fatalf("failed mutation changed case state: %s", got)
	}
	allowEvidence = true
	updated, err := engine.SetStatus(record.ID, "resolved", "verified false positive")
	if err != nil || updated.Status != "resolved" {
		t.Fatalf("authorized case mutation failed: record=%+v err=%v", updated, err)
	}
}

func TestCaseStoreTamperFailsClosed(t *testing.T) {
	engine, path, storage := newTestCaseEngine(
		t, func(EvidenceRecord) error { return nil },
	)
	if err := engine.IngestIncident(testCaseIncident("incident-a", "critical")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewCaseEngine(path, storage, func(EvidenceRecord) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if status := reloaded.Status(10); status.Healthy {
		t.Fatalf("tampered case store was accepted: %+v", status)
	}
	if err := reloaded.IngestIncident(testCaseIncident("incident-b", "critical")); err == nil {
		t.Fatal("tampered case store accepted a new incident")
	}
}

// TestCaseEngineScoreFloorAndFailClosedDefaults pins the two behaviours that the
// fixture above depends on, so they are verified rather than assumed.
func TestCaseEngineScoreFloorAndFailClosedDefaults(t *testing.T) {
	// 1. An incident below the compiled-in floor must not open a case.
	engine, _, _ := newTestCaseEngine(t, func(EvidenceRecord) error { return nil })
	low := testCaseIncident("incident-low", "high")
	low.Score = 90
	if err := engine.IngestIncident(low); err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(10); status.Count != 0 {
		t.Fatalf("an incident below the score floor opened a case: %+v", status)
	}

	// 2. An unconfigured engine must record, not discard. The zero value of the
	// policy would silently drop every incident, which is the one outcome a
	// forensics engine must never produce.
	if err := engine.IngestIncident(testCaseIncident("incident-high", "high")); err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(10); status.Count != 1 || status.Open != 1 {
		t.Fatalf("an unconfigured case engine discarded a qualifying incident: %+v", status)
	}

	// 3. A published revision that switches correlation off must still be honoured:
	// the fail-closed default applies only until an administrator decides.
	if err := engine.ApplyPolicy(ForensicsCasesSettings{AutoCreate: false, MinimumIncidentScore: 150, MaxCases: 64, MaxEvidenceRefsPerCase: 16, MaxObservationsPerCase: 16, ListMaxLimit: 50, CorrelationWindowMins: 30}); err != nil {
		t.Fatal(err)
	}
	if err := engine.IngestIncident(testCaseIncident("incident-off", "critical")); err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(10); status.Count != 1 {
		t.Fatalf("a published AutoCreate=false revision was not honoured: %+v", status)
	}
}

// TestCaseStoreRefusesUnauthenticatedLegacyPlaintext pins the FIND-015 follow-up decision for the
// case store: it carries no independent payload authentication (no HMAC, no signature over the
// store or its records), so a plaintext legacy history cannot be authenticated by anything except
// the storage envelope it lacks. The strict Decrypt therefore stays and DecryptForMigration is not
// used: adopting plaintext would let any writer of the state directory replace the case history
// with forged records - the exact silent downgrade FIND-015 closed. Structurally valid plaintext
// must be refused hard, not migrated and not rewritten.
func TestCaseStoreRefusesUnauthenticatedLegacyPlaintext(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "storage.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x33}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	storage, err := NewStorageCipher(keyPath, "case-test-node")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cases.enc")
	fixture := caseRecordFixture(
		"CS-1111111111111111", strings.Repeat("f", 64),
		time.Unix(1_700_000_000, 0).UTC(), 2,
	)
	legacyRaw, err := json.Marshal(caseStore{Schema: caseSchema, Revision: 3, Cases: []SecurityCase{fixture}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacyRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	engine, err := NewCaseEngine(path, storage, func(EvidenceRecord) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(10); status.Healthy {
		t.Fatalf("an unauthenticated plaintext case history was accepted: %+v", status)
	}
	if engine.integrity == nil || !errors.Is(engine.integrity, errStoragePlaintext) {
		t.Fatalf("plaintext case history was not refused by the strict storage reader: %v", engine.integrity)
	}
	if !strings.Contains(engine.integrity.Error(), "unencrypted case history refused") {
		t.Fatalf("the refusal does not name the unauthenticated legacy document: %v", engine.integrity)
	}
	if err := engine.IngestIncident(testCaseIncident("incident-legacy", "critical")); err == nil {
		t.Fatal("a plaintext legacy case store accepted a new incident")
	}
	// No migration may happen behind this refusal: the bytes on disk stay untouched, so retrying
	// cannot turn a tamper attempt into an adopted history.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, legacyRaw) {
		t.Fatal("the refused plaintext case history was rewritten instead of left alone")
	}
}
