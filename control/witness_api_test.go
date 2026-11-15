package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// POINT 4 / P4-T2: Mode B export/import (docs/POINT4-WITNESS.md §5) and the
// operator API (§7). The export must be deterministic, bounded and offline
// verifiable; the import must accept only signed receipts bound to a local export
// and must refuse anything that regresses the acknowledged epoch/sequence.

func witnessKeyFile(t *testing.T, publicKey ed25519.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "witness.pub")
	if err := os.WriteFile(path, publicKey, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func signWitnessTestReceipt(t *testing.T, privateKey ed25519.PrivateKey, receipt WitnessReceipt) WitnessReceipt {
	t.Helper()
	payload, err := witnessReceiptCanonicalPayload(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, witnessReceiptDigest(payload)))
	return receipt
}

func witnessReceiptFor(t *testing.T, privateKey ed25519.PrivateKey, checkpointID string, sequence uint64) WitnessReceipt {
	t.Helper()
	return signWitnessTestReceipt(t, privateKey, WitnessReceipt{
		WitnessID: "witness-1", WitnessSeq: sequence, CheckpointID: checkpointID,
		AcceptedAt: "2026-11-15T12:00:00Z",
	})
}

func TestWitnessExportIsDeterministicBoundedAndOfflineVerifiable(t *testing.T) {
	ledger, _ := evidenceFixture(t)
	ledger.Append(EvidenceRecord{Severity: "info", Kind: "test.one", Source: "test", Message: "first"})
	ledger.Append(EvidenceRecord{Severity: "info", Kind: "test.two", Source: "test", Message: "second"})
	checkpoint := witnessFixtureCheckpoint(t, ledger, nil)
	document, err := BuildWitnessExport(checkpoint)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.HasPrefix(document.Compact, witnessExportCompactPrefix) || len(document.Compact) > witnessExportMaxCompactBytes {
		t.Fatalf("compact export is not bounded: %d bytes", len(document.Compact))
	}
	encoded, err := EncodeWitnessExportJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildWitnessExport(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, _ := EncodeWitnessExportJSON(second)
	if string(encoded) != string(secondJSON) || document.Compact != second.Compact {
		t.Fatal("the export is not deterministic")
	}
	// Offline verification: decode the compact form and verify against the known
	// ledger public key. A different key must be refused.
	decoded, err := DecodeWitnessExportCompact(document.Compact)
	if err != nil {
		t.Fatalf("compact decode: %v", err)
	}
	verified, err := VerifyWitnessExport(decoded, ledger.publicKey)
	if err != nil {
		t.Fatalf("offline verify: %v", err)
	}
	if verified.CheckpointID != checkpoint.CheckpointID || verified.LedgerEpoch != checkpoint.LedgerEpoch || verified.Sequence != checkpoint.Sequence {
		t.Fatalf("the offline export does not name the checkpoint: %+v", verified)
	}
	foreignPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyWitnessExport(decoded, foreignPublic); err == nil {
		t.Fatal("an export verified against a foreign public key")
	}
	// (epoch, sequence) monotonicity is part of the offline contract: the same
	// document is current at (0,2), stale at (0,3) and regressive at epoch 1.
	if _, err := VerifyWitnessExportMonotonic(decoded, ledger.publicKey, 0, 2); err != nil {
		t.Fatalf("a current export was refused as stale: %v", err)
	}
	if _, err := VerifyWitnessExportMonotonic(decoded, ledger.publicKey, 0, 3); err == nil {
		t.Fatal("an older sequence inside the same epoch was accepted as current")
	}
	if _, err := VerifyWitnessExportMonotonic(decoded, ledger.publicKey, 1, 0); err == nil {
		t.Fatal("an export from a lower ledger epoch was accepted")
	}
	tampered := decoded
	tampered.Checkpoint.Sequence++
	if _, err := VerifyWitnessExport(tampered, ledger.publicKey); err == nil {
		t.Fatal("a tampered export verified")
	}
	// The witnesses' receipt key is independent of the ledger key; this fixture
	// only needs a syntactically valid signed receipt for the import contract.
}

type witnessImportFixture struct {
	engine     *WitnessEngine
	ledger     *EvidenceLedger
	state      *State
	privateKey ed25519.PrivateKey
}

func newWitnessImportFixture(t *testing.T) *witnessImportFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinPath := witnessKeyFile(t, publicKey)
	fixture := newWitnessEngineFixture(t, func(witness *WitnessFabricSettings) {
		witness.Enabled = true
		witness.Mode = witnessModeExport
		witness.PinnedServerKeyFile = pinPath
	}, nil, nil)
	return &witnessImportFixture{engine: fixture.engine, ledger: fixture.ledger, state: fixture.state, privateKey: privateKey}
}

func (f *witnessImportFixture) export(t *testing.T) witnessExportDocument {
	t.Helper()
	document, err := f.engine.ExportDocument(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return document
}

func importReceiptJSON(t *testing.T, receipt WitnessReceipt) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"receipt": receipt})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestWitnessImportAcceptsSignedReceiptsAndRejectsReplay(t *testing.T) {
	fixture := newWitnessImportFixture(t)
	fixture.ledger.Append(EvidenceRecord{Severity: "info", Kind: "test.one", Source: "test", Message: "first"})
	document := fixture.export(t)
	receipt := witnessReceiptFor(t, fixture.privateKey, document.Checkpoint.CheckpointID, 5)
	accepted, err := fixture.engine.ImportReceipt(context.Background(), importReceiptJSON(t, receipt))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if accepted.WitnessSeq != 5 || accepted.CheckpointID != document.Checkpoint.CheckpointID {
		t.Fatalf("imported receipt = %+v", accepted)
	}
	status := fixture.engine.StatusView()
	if status.LastAck == nil || status.LastAck.WitnessSeq != 5 {
		t.Fatalf("the import did not update the acknowledgement baseline: %+v", status)
	}
	// Replay: the same witness sequence is refused and recorded.
	if _, err := fixture.engine.ImportReceipt(context.Background(), importReceiptJSON(t, receipt)); err == nil {
		t.Fatal("a replayed receipt was accepted")
	}
	if !witnessStateHasEvent(fixture.state, "witness.import_rejected") {
		t.Fatal("the rejected replay was not recorded")
	}
	// The next sequence is accepted.
	if _, err := fixture.engine.ImportReceipt(context.Background(), importReceiptJSON(t, witnessReceiptFor(t, fixture.privateKey, document.Checkpoint.CheckpointID, 6))); err != nil {
		t.Fatalf("higher sequence: %v", err)
	}
}

func TestWitnessImportRejectsWrongKeyForeignCheckpointAndRollback(t *testing.T) {
	fixture := newWitnessImportFixture(t)
	fixture.ledger.Append(EvidenceRecord{Severity: "info", Kind: "test.one", Source: "test", Message: "first"})
	oldDocument := fixture.export(t)

	// Wrong signature key: a validly shaped receipt is not a trusted receipt.
	_, foreignKey, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := fixture.engine.ImportReceipt(context.Background(), importReceiptJSON(t, witnessReceiptFor(t, foreignKey, oldDocument.Checkpoint.CheckpointID, 5))); err == nil {
		t.Fatal("a receipt from a foreign key was accepted")
	}
	// Checkpoint id not bound to the local export.
	if _, err := fixture.engine.ImportReceipt(context.Background(), importReceiptJSON(t, witnessReceiptFor(t, fixture.privateKey, strings.Repeat("cd", 16), 5))); err == nil {
		t.Fatal("a receipt for a foreign checkpoint was accepted")
	}
	// A rotation to epoch 1 is legitimate: export and acknowledge it.
	if _, err := fixture.ledger.Rotate(context.Background(), "test rotation"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	currentDocument := fixture.export(t)
	if _, err := fixture.engine.ImportReceipt(context.Background(), importReceiptJSON(t, witnessReceiptFor(t, fixture.privateKey, currentDocument.Checkpoint.CheckpointID, 5))); err != nil {
		t.Fatalf("rotation receipt: %v", err)
	}
	// Importing a receipt bound to the older epoch now regresses the baseline and
	// must raise the rollback alarm instead of being accepted.
	fixture.engine.mu.Lock()
	old := oldDocument.Checkpoint
	fixture.engine.lastExport = &old
	fixture.engine.mu.Unlock()
	rollbackReceipt := witnessReceiptFor(t, fixture.privateKey, oldDocument.Checkpoint.CheckpointID, 6)
	if _, err := fixture.engine.ImportReceipt(context.Background(), importReceiptJSON(t, rollbackReceipt)); err == nil {
		t.Fatal("a receipt for an older ledger epoch was accepted")
	}
	status := fixture.engine.StatusView()
	if !status.Equivocation || status.EquivocationKind != "rollback" {
		t.Fatalf("the old-epoch import did not raise the rollback alarm: %+v", status)
	}
}

// ---------------------------------------------------------------- API fixture

type witnessAPIFixture struct {
	server    *APIServer
	engine    *WitnessEngine
	state     *State
	store     *SettingsStore
	transport *fakeWitnessTransport
}

func newWitnessAPIFixture(t *testing.T, mutate func(*WitnessFabricSettings), transport *fakeWitnessTransport) *witnessAPIFixture {
	t.Helper()
	fixture := newWitnessEngineFixture(t, mutate, transport, nil)
	cfg := defaultConfig()
	server := NewAPIServer(cfg, fixture.state, nil, nil, nil, nil, nil, fixture.store, fabricTestToken)
	server.AttachWitness(fixture.engine)
	return &witnessAPIFixture{server: server, engine: fixture.engine, state: fixture.state, store: fixture.store, transport: transport}
}

func witnessAPIRequest(t *testing.T, server *APIServer, method, path string, body []byte, requestID string, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1"+path, strings.NewReader(string(body)))
	req.Host = "127.0.0.1"
	if authenticated {
		req.Header.Set("Authorization", "Bearer "+fabricTestToken)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if requestID != "" {
		req.Header.Set("X-VGT-Request-ID", requestID)
	}
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	return rec
}

func witnessEnabledHTTP(witness *WitnessFabricSettings) {
	witness.Enabled = true
	witness.Mode = witnessModeHTTP
	witness.Endpoint = "https://witness.example"
	witness.PinnedServerSPKI = repeatHex("ab", 32)
}

func TestWitnessAPIDefaultOffIsInert(t *testing.T) {
	transport := &fakeWitnessTransport{}
	fixture := newWitnessAPIFixture(t, nil, transport)
	before := len(fixture.state.Snapshot().Events)

	status := witnessAPIRequest(t, fixture.server, http.MethodGet, "/api/v1/witness/status", nil, "", true)
	if status.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
	}
	var view WitnessStatus
	if err := json.Unmarshal(status.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Enabled || view.Mode != witnessModeOff {
		t.Fatalf("the default-off status does not report inert: %+v", view)
	}
	if rec := witnessAPIRequest(t, fixture.server, http.MethodPost, "/api/v1/witness/checkpoint", []byte(`{}`), randomID(), true); rec.Code != http.StatusConflict {
		t.Fatalf("checkpoint on a disabled witness answered %d: %s", rec.Code, rec.Body.String())
	}
	if rec := witnessAPIRequest(t, fixture.server, http.MethodPost, "/api/v1/witness/push", []byte(`{"confirmation":"PUSH WITNESS"}`), randomID(), true); rec.Code != http.StatusConflict {
		t.Fatalf("push on a disabled witness answered %d: %s", rec.Code, rec.Body.String())
	}
	if rec := witnessAPIRequest(t, fixture.server, http.MethodGet, "/api/v1/witness/export", nil, "", true); rec.Code != http.StatusConflict {
		t.Fatalf("export on a disabled witness answered %d", rec.Code)
	}
	if challenges, pushes := transport.snapshot(); challenges != 0 || pushes != 0 {
		t.Fatalf("the disabled API contacted the witness: %d/%d", challenges, pushes)
	}
	if after := len(fixture.state.Snapshot().Events); after != before {
		t.Fatalf("the disabled API wrote events: %d -> %d", before, after)
	}
}

func TestWitnessAPICheckpointPushConfirmationReplayAndLimits(t *testing.T) {
	transport := &fakeWitnessTransport{}
	fixture := newWitnessAPIFixture(t, witnessEnabledHTTP, transport)

	if rec := witnessAPIRequest(t, fixture.server, http.MethodGet, "/api/v1/witness/status", nil, "", false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status answered %d", rec.Code)
	}
	created := witnessAPIRequest(t, fixture.server, http.MethodPost, "/api/v1/witness/checkpoint", []byte(`{}`), "witness-checkpoint-0001", true)
	if created.Code != http.StatusOK {
		t.Fatalf("checkpoint status=%d body=%s", created.Code, created.Body.String())
	}
	// The creation route is replay-protected like every other operator mutation.
	replayed := witnessAPIRequest(t, fixture.server, http.MethodPost, "/api/v1/witness/checkpoint", []byte(`{}`), "witness-checkpoint-0001", true)
	if replayed.Code != http.StatusConflict {
		t.Fatalf("a replayed request id was accepted: %d", replayed.Code)
	}
	// The push phrase proves intent: a wrong one is refused before any request.
	wrong := witnessAPIRequest(t, fixture.server, http.MethodPost, "/api/v1/witness/push", []byte(`{"confirmation":"push witness"}`), "witness-push-wrong-0001", true)
	if wrong.Code != http.StatusForbidden {
		t.Fatalf("a wrong confirmation answered %d", wrong.Code)
	}
	if _, pushes := transport.snapshot(); pushes != 0 {
		t.Fatalf("a wrong confirmation still pushed: %d", pushes)
	}
	pushed := witnessAPIRequest(t, fixture.server, http.MethodPost, "/api/v1/witness/push", []byte(`{"confirmation":"PUSH WITNESS"}`), "witness-push-0001", true)
	if pushed.Code != http.StatusOK {
		t.Fatalf("push status=%d body=%s", pushed.Code, pushed.Body.String())
	}
	if _, pushes := transport.snapshot(); pushes != 1 {
		t.Fatalf("the push did not reach the witness transport: %d", pushes)
	}
	// A replayed push identifier is refused even though the operation would succeed.
	replayedPush := witnessAPIRequest(t, fixture.server, http.MethodPost, "/api/v1/witness/push", []byte(`{"confirmation":"PUSH WITNESS"}`), "witness-push-0001", true)
	if replayedPush.Code != http.StatusConflict {
		t.Fatalf("a replayed push was accepted: %d", replayedPush.Code)
	}
	// Status is bounded and carries no path, endpoint or key.
	status := witnessAPIRequest(t, fixture.server, http.MethodGet, "/api/v1/witness/status", nil, "", true)
	for _, secret := range []string{"/tmp/", "outbox.enc", "ack.enc", "witness.example", "PinnedServer", fabricTestToken} {
		if strings.Contains(status.Body.String(), secret) {
			t.Fatalf("the status leaked %q: %s", secret, status.Body.String())
		}
	}
}

func TestWitnessAPIPushRateLimitAndChallenge(t *testing.T) {
	transport := &fakeWitnessTransport{}
	fixture := newWitnessAPIFixture(t, witnessEnabledHTTP, transport)
	challenge := witnessAPIRequest(t, fixture.server, http.MethodPost, "/api/v1/witness/challenge", []byte(`{}`), "witness-challenge-0001", true)
	if challenge.Code != http.StatusOK || !strings.Contains(challenge.Body.String(), "challenge") {
		t.Fatalf("challenge status=%d body=%s", challenge.Code, challenge.Body.String())
	}
	limited := false
	for attempt := 0; attempt < 6; attempt++ {
		rec := witnessAPIRequest(t, fixture.server, http.MethodPost, "/api/v1/witness/push",
			[]byte(`{"confirmation":"PUSH WITNESS"}`), randomID(), true)
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("the dedicated push budget never engaged")
	}
}

func TestWitnessAPIRespectsTheEvidenceGate(t *testing.T) {
	fixture := newWitnessAPIFixture(t, func(witness *WitnessFabricSettings) {
		witness.Enabled = true
		witness.Mode = witnessModeExport
	}, nil)
	fixture.state.mu.Lock()
	fixture.state.evidenceErr = errors.New("evidence chain verification failed")
	fixture.state.mu.Unlock()
	rec := witnessAPIRequest(t, fixture.server, http.MethodPost, "/api/v1/witness/checkpoint", []byte(`{}`), randomID(), true)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a gated witness mutation answered %d: %s", rec.Code, rec.Body.String())
	}
	if fixture.engine.StatusView().Checkpoint != nil {
		t.Fatal("a gated mutation still created a checkpoint")
	}
	// Read-only surfaces stay reachable while the gate is closed.
	if status := witnessAPIRequest(t, fixture.server, http.MethodGet, "/api/v1/witness/status", nil, "", true); status.Code != http.StatusOK {
		t.Fatalf("status was gated: %d", status.Code)
	}
}

func TestWitnessAPIImportAcceptsAndRejectsReceipts(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinPath := witnessKeyFile(t, publicKey)
	fixture := newWitnessAPIFixture(t, func(witness *WitnessFabricSettings) {
		witness.Enabled = true
		witness.Mode = witnessModeExport
		witness.PinnedServerKeyFile = pinPath
	}, nil)
	fixture.state.EvidenceLedger().Append(EvidenceRecord{Severity: "info", Kind: "test.one", Source: "test", Message: "first"})
	export := witnessAPIRequest(t, fixture.server, http.MethodGet, "/api/v1/witness/export", nil, "", true)
	if export.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", export.Code, export.Body.String())
	}
	var document witnessExportDocument
	if err := json.Unmarshal(export.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"receipt": witnessReceiptFor(t, privateKey, document.Checkpoint.CheckpointID, 3)})
	accepted := witnessAPIRequest(t, fixture.server, http.MethodPost, "/api/v1/witness/import", body, "witness-import-0001", true)
	if accepted.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", accepted.Code, accepted.Body.String())
	}
	bad := witnessAPIRequest(t, fixture.server, http.MethodPost, "/api/v1/witness/import", []byte(`{"receipt":{"witness_id":"x"}}`), randomID(), true)
	if bad.Code == http.StatusOK {
		t.Fatalf("a malformed import was accepted: %s", bad.Body.String())
	}
	if !witnessStateHasEvent(fixture.state, "witness.import_rejected") {
		t.Fatal("the rejected import was not recorded")
	}
}
