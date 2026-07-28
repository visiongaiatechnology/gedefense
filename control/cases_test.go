// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"os"
	"path/filepath"
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

func testCaseIncident(id, severity string) XDRIncident {
	return XDRIncident{
		ID: id, Time: time.Unix(1_700_000_000, 0).UTC(),
		Severity: severity, Score: 90, ResponseScore: 85,
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
