package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIncidentRecoveryArchivesCorruptChainBeforeReinitialization(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "incidents.jsonl")
	keyPath := filepath.Join(dir, "xdr.key")
	logger, err := NewIncidentLoggerWithStorage(logPath, keyPath, "", "test-node")
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 6; n++ {
		if _, err := logger.Append(XDRIncident{
			ID: randomID(), Time: time.Unix(int64(n+1), 0).UTC(), Severity: "warning", Score: 50,
			RuleIDs: []string{"TEST.RULE"}, Categories: []string{"test"}, Summary: "test",
			Decision: "alert", Action: "none", Outcome: "observed",
		}); err != nil {
			t.Fatal(err)
		}
	}
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	corrupt, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(corrupt), "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected six incident records, got %d", len(lines))
	}
	lines[5] = strings.Replace(lines[5], `"score":50`, `"score":51`, 1)
	corrupt = []byte(strings.Join(lines, "\n") + "\n")
	if err := os.WriteFile(logPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	quarantined, err := NewIncidentLoggerWithStorage(logPath, keyPath, "", "test-node")
	if err != nil {
		t.Fatal(err)
	}
	status := quarantined.IntegrityStatus()
	if status.Healthy || !status.Quarantined || !status.Recoverable {
		t.Fatalf("unexpected corrupt-ledger status: %+v", status)
	}
	if status.ReasonCode != "AUTHENTICATION_FAILED" || status.FailureRecord != 6 || status.VerifiedRecords != 5 {
		t.Fatalf("unexpected integrity diagnostics: %+v", status)
	}

	reasonDigest := sha256.Sum256([]byte("operator approved recovery"))
	result, err := quarantined.Recover(context.Background(), hex.EncodeToString(reasonDigest[:]))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Integrity.Healthy || result.ArchiveID == "" || len(result.ManifestSHA256) != sha256.Size*2 {
		t.Fatalf("unexpected recovery result: %+v", result)
	}
	archiveDir := filepath.Join(dir, "xdr-recovery", result.ArchiveID)
	archivedLog, err := os.ReadFile(filepath.Join(archiveDir, "incident-log.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(archivedLog) != string(corrupt) {
		t.Fatal("corrupt incident chain was not archived byte-for-byte")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(archiveDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest incidentRecoveryManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Failure.FailureRecord != 6 || manifest.IncidentLog.SHA256 == "" || manifest.ArchiveID != result.ArchiveID {
		t.Fatalf("unexpected recovery manifest: %+v", manifest)
	}
	fresh, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 0 {
		t.Fatalf("fresh incident chain is not empty: %q", fresh)
	}
	if err := quarantined.Verify(); err != nil {
		t.Fatalf("fresh incident chain failed verification: %v", err)
	}
	keyAfter, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(keyBefore) != string(keyAfter) {
		t.Fatal("incident authentication key changed during recovery")
	}
	if _, err := quarantined.Append(XDRIncident{
		ID: "post-recovery", Time: time.Now().UTC(), Severity: "info", RuleIDs: []string{"TEST"},
		Categories: []string{"test"}, Summary: "post recovery", Decision: "alert", Action: "none", Outcome: "observed",
	}); err != nil {
		t.Fatalf("recovered incident logger rejected a new record: %v", err)
	}
}

func TestXDRRecoveryAPIRequiresExactConfirmationAndRecovers(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "incidents.jsonl")
	keyPath := filepath.Join(dir, "xdr.key")
	logger, err := NewIncidentLogger(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logger.Append(XDRIncident{ID: "one", Severity: "warning", Score: 50, RuleIDs: []string{"TEST"}, Categories: []string{"test"}, Summary: "test", Decision: "alert", Action: "none", Outcome: "observed"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.Replace(string(b), `"score":50`, `"score":51`, 1))
	if err := os.WriteFile(logPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	quarantined, err := NewIncidentLogger(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	cfg := defaultConfig()
	state := NewState("test-node", cfg)
	state.SetModes("observe", "observe")
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	engine := &XDREngine{cfg: cfg, state: state, logger: quarantined, degradeCauses: map[string]string{}, recoveryGate: make(chan struct{}, 1)}
	engine.recoveryGate <- struct{}{}
	engine.markDegradedCause("incident_log", "incident log integrity failure: "+quarantined.Healthy().Error())
	server := NewAPIServer(cfg, state, nil, nil, nil, engine, nil, nil, "0123456789abcdef0123456789abcdef")

	request := func(id, confirmation string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]string{
			"action": "archive_and_reinitialize", "confirmation": confirmation,
			"reason": "forensics exported and operator approved recovery",
		})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/xdr/recovery", bytes.NewReader(body))
		req.Host = "127.0.0.1"
		req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-VGT-Request-ID", id)
		server.http.Handler.ServeHTTP(recorder, req)
		return recorder
	}

	if recorder := request("recovery_1111111111111111", "WRONG"); recorder.Code != http.StatusBadRequest {
		t.Fatalf("wrong recovery confirmation returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := request("recovery_2222222222222222", xdrRecoveryConfirmation); recorder.Code != http.StatusOK {
		t.Fatalf("valid recovery returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if engine.IncidentIntegrityReport().XDRDegraded {
		t.Fatalf("XDR remained degraded after successful API recovery: %+v", engine.IncidentIntegrityReport())
	}
}

func TestIncidentRecoveryRefusesHealthyLedger(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewIncidentLogger(filepath.Join(dir, "incidents.jsonl"), filepath.Join(dir, "xdr.key"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = logger.Recover(context.Background(), strings.Repeat("a", 64))
	if !errors.Is(err, errIncidentRecoveryNotRequired) {
		t.Fatalf("healthy ledger recovery returned %v", err)
	}
}

func TestIncidentRecoveryReasonValidation(t *testing.T) {
	valid := []string{"Operator approved recovery", "Incident chain geprüft"}
	for _, value := range valid {
		if !validRecoveryReason(value) {
			t.Fatalf("valid recovery reason rejected: %q", value)
		}
	}
	invalid := []string{"short", "contains\nnewline", strings.Repeat("x", 241)}
	for _, value := range invalid {
		if validRecoveryReason(value) {
			t.Fatalf("invalid recovery reason accepted: %q", value)
		}
	}
}

func TestXDREngineRecoveryClearsOnlyIncidentLedgerDegradation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "incidents.jsonl")
	keyPath := filepath.Join(dir, "xdr.key")
	logger, err := NewIncidentLoggerWithStorage(logPath, keyPath, "", "test-node")
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		if _, err := logger.Append(XDRIncident{ID: randomID(), Time: time.Now().UTC(), Severity: "warning", Score: 50, RuleIDs: []string{"TEST"}, Categories: []string{"test"}, Summary: "test", Decision: "alert", Action: "none", Outcome: "observed"}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.Replace(string(b), `"score":50`, `"score":51`, 1))
	if err := os.WriteFile(logPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	quarantined, err := NewIncidentLoggerWithStorage(logPath, keyPath, "", "test-node")
	if err != nil {
		t.Fatal(err)
	}

	cfg := defaultConfig()
	state := NewState("test-node", cfg)
	state.SetModes("observe", "observe")
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	engine := &XDREngine{
		cfg: cfg, state: state, logger: quarantined,
		degradeCauses: map[string]string{}, recoveryGate: make(chan struct{}, 1),
	}
	engine.recoveryGate <- struct{}{}
	engine.markDegradedCause("incident_log", "incident log integrity failure: "+quarantined.Healthy().Error())

	result, err := engine.RecoverIncidentLedger(context.Background(), "forensic export created before recovery")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Integrity.Healthy {
		t.Fatalf("recovery result not healthy: %+v", result)
	}
	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("incident-only degradation remained after verified recovery: %s", reason)
	}
	if state.Snapshot().XDR.Degraded {
		t.Fatalf("state remained degraded after verified recovery: %+v", state.Snapshot().XDR)
	}
	kinds := map[string]bool{}
	for _, record := range ledger.Recent(20) {
		kinds[record.Kind] = true
	}
	for _, kind := range []string{"xdr.recovery_started", "xdr.corrupt_chain_archived", "xdr.new_chain_verified", "xdr.recovery_completed"} {
		if !kinds[kind] {
			t.Fatalf("mandatory recovery evidence %q missing: %+v", kind, kinds)
		}
	}
}

func TestXDREngineRecoveryRefusesAdditionalDegradedCause(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "incidents.jsonl")
	keyPath := filepath.Join(dir, "xdr.key")
	logger, err := NewIncidentLogger(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logger.Append(XDRIncident{ID: "one", Severity: "warning", RuleIDs: []string{"TEST"}, Categories: []string{"test"}, Summary: "test", Decision: "alert", Action: "none", Outcome: "observed"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.Replace(string(b), `"summary":"test"`, `"summary":"tampered"`, 1))
	if err := os.WriteFile(logPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	quarantined, err := NewIncidentLogger(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	state := NewState("test-node", cfg)
	state.SetModes("observe", "observe")
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	engine := &XDREngine{cfg: cfg, state: state, logger: quarantined, degradeCauses: map[string]string{}, recoveryGate: make(chan struct{}, 1)}
	engine.recoveryGate <- struct{}{}
	engine.markDegradedCause("incident_log", "incident log integrity failure")
	engine.markDegradedCause("runtime", "process sensor unavailable")

	if _, err := engine.RecoverIncidentLedger(context.Background(), "forensics captured before recovery"); err == nil {
		t.Fatal("recovery was allowed while an independent degraded cause remained")
	}
	if !state.Snapshot().XDR.Degraded {
		t.Fatal("XDR unexpectedly left degraded state")
	}
}

func TestEncryptedIncidentRecoveryCreatesVerifiableFreshHead(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "incidents.jsonl")
	keyPath := filepath.Join(dir, "xdr.key")
	storageKeyPath := testSecret(t, dir, "storage.key")
	logger, err := NewIncidentLoggerWithStorage(logPath, keyPath, storageKeyPath, "node-encrypted")
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		if _, err := logger.Append(XDRIncident{
			ID: randomID(), Time: time.Now().UTC(), Severity: "warning", Score: 50,
			RuleIDs: []string{"TEST"}, Categories: []string{"test"}, Summary: "encrypted",
			Decision: "alert", Action: "none", Outcome: "observed",
		}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
	if len(lines) != 2 || len(lines[1]) < 16 {
		t.Fatalf("unexpected encrypted incident log layout")
	}
	// Change one non-structural byte in the encrypted envelope. The exact failure
	// classification is intentionally irrelevant; recovery must preserve it and
	// create a fresh encrypted head using the existing storage key.
	idx := len(lines[1]) / 2
	if lines[1][idx] == 'a' {
		lines[1][idx] = 'b'
	} else {
		lines[1][idx] = 'a'
	}
	corrupt := append(bytes.Join(lines, []byte("\n")), '\n')
	if err := os.WriteFile(logPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	quarantined, err := NewIncidentLoggerWithStorage(logPath, keyPath, storageKeyPath, "node-encrypted")
	if err != nil {
		t.Fatal(err)
	}
	if quarantined.Healthy() == nil {
		t.Fatal("tampered encrypted incident chain was accepted")
	}
	status := quarantined.IntegrityStatus()
	if !status.Recoverable {
		t.Fatalf("encrypted incident corruption was not classified as recoverable: %+v", status)
	}
	result, err := quarantined.Recover(context.Background(), strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Integrity.Healthy {
		t.Fatalf("encrypted recovery did not return healthy state: %+v", result)
	}
	if err := quarantined.Verify(); err != nil {
		t.Fatalf("fresh encrypted incident chain/head failed verification: %v", err)
	}
	reopened, err := NewIncidentLoggerWithStorage(logPath, keyPath, storageKeyPath, "node-encrypted")
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Healthy(); err != nil {
		t.Fatalf("reopened encrypted incident chain is unhealthy: %v", err)
	}
}
