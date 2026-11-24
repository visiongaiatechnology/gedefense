// STATUS: DIAMANT VGT SUPREME

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// --------------------------------------------------------------- test helpers

func permitTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate permit keypair: %v", err)
	}
	return publicKey, privateKey
}

// permitTestExecutable creates one executable test file and returns its path,
// SHA-256 and inode identity.
func permitTestExecutable(t *testing.T, dir, name string, content []byte) (string, string, PermitInode) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatalf("write test executable: %v", err)
	}
	digest := sha256.Sum256(content)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat test executable: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("test executable has no inode identity")
	}
	return path, hex.EncodeToString(digest[:]), PermitInode{Device: uint64(stat.Dev), Inode: uint64(stat.Ino)}
}

func permitTestScope(rules ...string) PermitScope {
	return PermitScope{Rules: rules}
}

func permitTestObject(t *testing.T, now time.Time, trustLevel, executable, digest string, inode PermitInode, scope PermitScope, ttl time.Duration) *PermitV1 {
	t.Helper()
	permitID, err := newPermitID()
	if err != nil {
		t.Fatalf("mint permit id: %v", err)
	}
	return &PermitV1{
		Schema: permitSchemaV1, PermitID: permitID, TrustLevel: trustLevel,
		SHA256: digest, Inode: inode, Path: executable, Scope: scope,
		ValidFrom: now.UTC(), ValidUntil: now.UTC().Add(ttl),
	}
}

func newBoundPermitTestBroker(t *testing.T, dir string, verifyKey ed25519.PublicKey, signKey ed25519.PrivateKey) *PermitBroker {
	t.Helper()
	broker := NewPermitBroker()
	binding := permitBrokerBinding{StorageDir: dir}
	if len(verifyKey) > 0 {
		binding.VerifyKey = []byte(verifyKey)
	}
	if len(signKey) > 0 {
		binding.SignKey = []byte(signKey)
	}
	if err := broker.bindPermitStore(binding); err != nil {
		t.Fatalf("bind permit store: %v", err)
	}
	return broker
}

func newAP7TestEngine(t *testing.T, storageDir string) *XDREngine {
	t.Helper()
	cfg := Config{}
	cfg.Node.Name = "ap7-test"
	cfg.XDR.Enabled = true
	cfg.XDR.AlertScore = 0
	cfg.XDR.ContainScore = 80
	cfg.XDR.KillScore = 120
	cfg.XDR.DedupeSeconds = 60
	cfg.XDR.IncidentLog = filepath.Join(storageDir, "incidents.jsonl")
	state := NewState("6.3.0-test", cfg)
	return &XDREngine{
		cfg: cfg, state: state, rules: NewXDRRuleEngine(),
		permits: NewPermitBroker(), reviewQueue: NewReviewQueue(),
		seen: map[string]struct{}{}, dedupe: map[string]time.Time{},
		tamperSeen: map[string]string{}, protected: map[string]protectedObject{},
		cellPolicies: map[uint64]uint8{}, degradeCauses: map[string]string{},
		recoveryGate: make(chan struct{}, 1),
	}
}

// permitEngineSample exposes the command lines that trigger the kill-eligible
// development false positives used by the engine-level permission tests.
func permitEngineSample(t *testing.T, dir, executableName string) (ProcessSample, string, PermitInode, []string) {
	t.Helper()
	executable, digest, inode := permitTestExecutable(t, dir, executableName, []byte("#!/bin/sh\n# "+executableName+"\n"))
	sample := ProcessSample{
		PID: 4242, PPID: 1, StartTicks: 12345, UID: 1000, GID: 1000,
		Comm: executableName, Exe: executable, ParentExe: "/bin/bash",
		Cmdline: "LD_PRELOAD=/tmp/build-hook.so " + executableName + " build",
	}
	return sample, digest, inode, []string{"XDR.TEMP_EXEC", "KD.LINUX.LD_PRELOAD"}
}

func permitEvaluateSample(t *testing.T, broker *PermitBroker, sample ProcessSample, ruleIDs []string) *PermitDecision {
	t.Helper()
	return broker.Evaluate(sample, ruleIDs, []string{"origin", "injection"})
}

func permitIncidentCount(e *XDREngine) int {
	if e == nil || e.state == nil {
		return 0
	}
	return len(e.state.Snapshot().Incidents)
}

func permitEventKinds(e *XDREngine) []string {
	if e == nil || e.state == nil {
		return nil
	}
	snapshot := e.state.Snapshot()
	kinds := make([]string, 0, len(snapshot.Events))
	for _, event := range snapshot.Events {
		kinds = append(kinds, event.Kind)
	}
	return kinds
}

func permitContainsKind(kinds []string, want string) bool {
	for _, kind := range kinds {
		if kind == want {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------ TTL tests

func TestPermitTTLExpiryAndMaintenance(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey := permitTestKeypair(t)
	broker := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	base := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	offset := time.Duration(0)
	broker.clock = func() time.Time { return base.Add(offset) }

	executable, digest, inode := permitTestExecutable(t, dir, "tool-a", []byte("permit-ttl-tool"))
	permit := permitTestObject(t, base, permitTrustTolerated, executable, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), time.Hour)
	if err := broker.UpsertPermit(permit); err != nil {
		t.Fatalf("upsert toleranted permit: %v", err)
	}
	sample := ProcessSample{PID: 33, Comm: "tool-a", Exe: executable}
	if decision := permitEvaluateSample(t, broker, sample, []string{"XDR.TEMP_EXEC"}); decision == nil || decision.TrustLevel != permitTrustTolerated {
		t.Fatalf("active permit did not match: %+v", decision)
	}

	offset = 2 * time.Hour
	if decision := permitEvaluateSample(t, broker, sample, []string{"XDR.TEMP_EXEC"}); decision != nil {
		t.Fatalf("expired permit still matched: %+v", decision)
	}
	expired, changed, err := broker.maintainPermitStore(base.Add(2*time.Hour), nil)
	if err != nil {
		t.Fatalf("permit maintenance: %v", err)
	}
	if expired != 1 || !changed {
		t.Fatalf("expected one expired permit, got expired=%d changed=%t", expired, changed)
	}
	if report := broker.PermitReport(); report.Stored != 0 {
		t.Fatalf("expired permit still stored: %+v", report)
	}
	reloaded := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	if report := reloaded.PermitReport(); report.Stored != 0 {
		t.Fatalf("expiry was not persisted: %+v", report)
	}
}

func TestPermitTTLBoundsAreEnforced(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey := permitTestKeypair(t)
	broker := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	now := time.Now().UTC()
	executable, digest, inode := permitTestExecutable(t, dir, "tool-b", []byte("permit-ttl-bounds"))

	overlongTolerated := permitTestObject(t, now, permitTrustTolerated, executable, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), 48*time.Hour)
	if err := broker.UpsertPermit(overlongTolerated); err == nil {
		t.Fatal("TOLERATED permit above its 24 h TTL bound was accepted")
	}
	overlongAuthorized := permitTestObject(t, now, permitTrustAuthorized, executable, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), 31*24*time.Hour)
	if err := broker.UpsertPermit(overlongAuthorized); err == nil {
		t.Fatal("AUTHORIZED permit above its 30 d TTL bound was accepted")
	}
	inverted := permitTestObject(t, now, permitTrustTolerated, executable, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), time.Hour)
	inverted.ValidUntil = inverted.ValidFrom.Add(-time.Minute)
	if err := broker.UpsertPermit(inverted); err == nil {
		t.Fatal("inverted permit validity window was accepted")
	}
}

// -------------------------------------------------------------- signer policy

func TestPermitInvalidSignatureIsNeverAuthorized(t *testing.T) {
	dir := t.TempDir()
	firstPublic, firstPrivate := permitTestKeypair(t)
	secondPublic, _ := permitTestKeypair(t)
	now := time.Now().UTC()
	executable, digest, inode := permitTestExecutable(t, dir, "tool-c", []byte("permit-invalid-signer"))

	// Sign with key A, then present the object to a broker that trusts key B.
	permit := permitTestObject(t, now, permitTrustAuthorized, executable, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), time.Hour)
	if err := SignPermitObject(permit, firstPrivate); err != nil {
		t.Fatalf("sign permit: %v", err)
	}
	wrongKeyBroker := newBoundPermitTestBroker(t, dir, secondPublic, nil)
	if err := wrongKeyBroker.UpsertPermit(permit); err == nil {
		t.Fatal("permit signed by an unknown signer was accepted")
	}
	if report := wrongKeyBroker.PermitReport(); report.Stored != 0 || report.Authorized != 0 {
		t.Fatalf("invalid signer still stored/authorized: %+v", report)
	}

	// The same object is valid for a broker that trusts key A.
	trustedBroker := newBoundPermitTestBroker(t, dir, firstPublic, firstPrivate)
	if err := trustedBroker.UpsertPermit(permit); err != nil {
		t.Fatalf("signed permit rejected by the trusted key: %v", err)
	}
	if !permitIsHex(permit.Signature, ed25519.SignatureSize) {
		t.Fatal("permit signature is not a real Ed25519 signature")
	}
}

func TestPermitUnsignedIsDemotedToAnalystOnly(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	executable, digest, inode := permitTestExecutable(t, dir, "tool-d", []byte("permit-unsigned"))
	// No signing key bound: the object must be stored as signature=absent and
	// demoted to ANALYST_MODE instead of pretending to be authorised.
	broker := newBoundPermitTestBroker(t, dir, nil, nil)
	permit := permitTestObject(t, now, permitTrustAuthorized, executable, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), time.Hour)
	if err := broker.UpsertPermit(permit); err != nil {
		t.Fatalf("unsigned permit rejected instead of demoted: %v", err)
	}
	report := broker.PermitReport()
	if report.Authorized != 0 || report.AnalystOnly != 1 || report.SignatureStatus != permitSignatureAbsent {
		t.Fatalf("unsigned permit was not demoted honestly: %+v", report)
	}
	sample := ProcessSample{PID: 34, Comm: "tool-d", Exe: executable}
	decision := permitEvaluateSample(t, broker, sample, []string{"XDR.TEMP_EXEC"})
	if decision == nil || decision.TrustLevel != permitTrustAnalyst {
		t.Fatalf("demoted permit did not evaluate as ANALYST_MODE: %+v", decision)
	}
}

// -------------------------------------------------------------- store policies

func TestPermitCorruptStoreFailsClosed(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey := permitTestKeypair(t)
	broker := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	now := time.Now().UTC()
	executable, digest, inode := permitTestExecutable(t, dir, "tool-e", []byte("permit-corrupt"))
	permit := permitTestObject(t, now, permitTrustTolerated, executable, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), time.Hour)
	if err := broker.UpsertPermit(permit); err != nil {
		t.Fatalf("seed permit store: %v", err)
	}
	storePath := filepath.Join(dir, permitStoreFileName)
	if err := os.WriteFile(storePath, []byte("{corrupt permit store"), 0o600); err != nil {
		t.Fatalf("corrupt permit store: %v", err)
	}
	reopened := NewPermitBroker()
	if err := reopened.bindPermitStore(permitBrokerBinding{StorageDir: dir, VerifyKey: []byte(publicKey), SignKey: []byte(privateKey)}); err == nil {
		t.Fatal("corrupt permit store was accepted")
	}
	report := reopened.PermitReport()
	if !report.Corrupt || report.Stored != 0 || !report.Degraded {
		t.Fatalf("corrupt store did not fail closed: %+v", report)
	}
	sample := ProcessSample{PID: 35, Comm: "tool-e", Exe: executable}
	if decision := permitEvaluateSample(t, reopened, sample, []string{"XDR.TEMP_EXEC"}); decision != nil {
		t.Fatalf("corrupt store still produced a permit decision: %+v", decision)
	}
	if err := reopened.UpsertPermit(permitTestObject(t, now, permitTrustTolerated, executable, digest, inode, permitTestScope("XDR.TEMP_EXEC"), time.Hour)); err == nil {
		t.Fatal("corrupt store was overwritten instead of preserved")
	}
	preserved, err := os.ReadFile(storePath)
	if err != nil || !strings.Contains(string(preserved), "corrupt permit store") {
		t.Fatalf("corrupt store evidence was not preserved: %v", err)
	}
}

func TestPermitStoreRejectsLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey := permitTestKeypair(t)
	broker := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	now := time.Now().UTC()
	executable, digest, inode := permitTestExecutable(t, dir, "tool-f", []byte("permit-mode"))
	permit := permitTestObject(t, now, permitTrustTolerated, executable, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), time.Hour)
	if err := broker.UpsertPermit(permit); err != nil {
		t.Fatalf("seed permit store: %v", err)
	}
	storePath := filepath.Join(dir, permitStoreFileName)
	if err := os.Chmod(storePath, 0o644); err != nil {
		t.Fatalf("chmod permit store: %v", err)
	}
	reopened := NewPermitBroker()
	if err := reopened.bindPermitStore(permitBrokerBinding{StorageDir: dir, VerifyKey: []byte(publicKey)}); err == nil {
		t.Fatal("world-readable permit store was accepted")
	}
	if report := reopened.PermitReport(); !report.Corrupt || report.Stored != 0 {
		t.Fatalf("loose-mode store did not fail closed: %+v", report)
	}
}

func TestPermitDuplicateIDsAreDroppedWithCountedReason(t *testing.T) {
	dir := t.TempDir()
	// Binding once creates the local HMAC key; the test then writes a store with
	// two structurally valid permits that share the same permit_id.
	seed := newBoundPermitTestBroker(t, dir, nil, nil)
	_ = seed.PermitReport()
	key, err := os.ReadFile(filepath.Join(dir, permitStoreKeyFileName))
	if err != nil || len(key) != permitStoreKeyBytes {
		t.Fatalf("permit store key: %v len=%d", err, len(key))
	}
	now := time.Now().UTC()
	executable, digest, inode := permitTestExecutable(t, dir, "tool-g", []byte("permit-duplicate"))
	permit := permitTestObject(t, now, permitTrustAnalyst, executable, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), time.Hour)
	// A manually serialized analyst-only permit carries its explicit absent
	// signature state; the loader must never accept a fabricated empty one.
	permit.Signature = permitSignatureAbsent
	encoded, err := json.Marshal(permit)
	if err != nil {
		t.Fatalf("marshal permit: %v", err)
	}
	transport := permitStoreTransport{
		Schema: permitStoreSchema, Sequence: 3,
		Permits: []json.RawMessage{json.RawMessage(encoded), json.RawMessage(encoded)},
	}
	payload, err := json.Marshal(transport)
	if err != nil {
		t.Fatalf("marshal store transport: %v", err)
	}
	document, err := permitStoreSealHMAC(key, 3, payload)
	if err != nil {
		t.Fatalf("seal permit store: %v", err)
	}
	if err := writePrivateFileAtomic(filepath.Join(dir, permitStoreFileName), document); err != nil {
		t.Fatalf("write duplicate store: %v", err)
	}
	reopened := newBoundPermitTestBroker(t, dir, nil, nil)
	report := reopened.PermitReport()
	if report.Stored != 1 || report.Dropped["duplicate"] != 1 {
		t.Fatalf("duplicate permit ID was not dropped and counted: %+v", report)
	}
}

func TestPermitStoreAtomicWriteAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey := permitTestKeypair(t)
	broker := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	now := time.Now().UTC()
	executable, digest, inode := permitTestExecutable(t, dir, "tool-h", []byte("permit-roundtrip"))
	permit := permitTestObject(t, now, permitTrustTolerated, executable, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), time.Hour)
	if err := broker.UpsertPermit(permit); err != nil {
		t.Fatalf("upsert permit: %v", err)
	}
	storePath := filepath.Join(dir, permitStoreFileName)
	info, err := os.Lstat(storePath)
	if err != nil {
		t.Fatalf("stat permit store: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permit store mode is %#o, want 0600", info.Mode().Perm())
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, "."+permitStoreFileName+".tmp-*"))
	if err != nil {
		t.Fatalf("glob temporary permit stores: %v", err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("atomic write left temporary files: %v", leftovers)
	}
	data, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read permit store: %v", err)
	}
	if !json.Valid(data) || !strings.Contains(string(data), permitStoreHMACSchema) {
		t.Fatalf("permit store is not an authenticated envelope: %.80s", data)
	}
	reloaded := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	report := reloaded.PermitReport()
	if report.Stored != 1 || report.Tolerated != 1 || report.SignatureStatus != "attached" {
		t.Fatalf("permit store round-trip failed: %+v", report)
	}
	sample := ProcessSample{PID: 36, Comm: "tool-h", Exe: executable}
	if decision := permitEvaluateSample(t, reloaded, sample, []string{"XDR.TEMP_EXEC"}); decision == nil || decision.PermitID != permit.PermitID {
		t.Fatalf("reloaded permit did not match: %+v", decision)
	}
}
