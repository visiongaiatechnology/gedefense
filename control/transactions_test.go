// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type memoryTransactionApplier struct {
	value       string
	failApply   bool
	failReverse bool
}

func (a *memoryTransactionApplier) Type() string {
	return "test.memory"
}

func (a *memoryTransactionApplier) Preview(
	payload json.RawMessage,
) (json.RawMessage, json.RawMessage, error) {
	var request struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(payload, &request); err != nil || request.Value == "" {
		return nil, nil, errors.New("invalid value")
	}
	plan, _ := json.Marshal(map[string]string{"value": request.Value})
	before, _ := json.Marshal(map[string]string{"value": a.value})
	return plan, before, nil
}

func (a *memoryTransactionApplier) Apply(
	planRaw json.RawMessage,
	_ json.RawMessage,
) (json.RawMessage, error) {
	if a.failApply {
		return nil, errors.New("injected apply failure")
	}
	var plan map[string]string
	if err := json.Unmarshal(planRaw, &plan); err != nil {
		return nil, err
	}
	a.value = plan["value"]
	return json.Marshal(map[string]string{"value": a.value})
}

func (a *memoryTransactionApplier) Verify(
	_ json.RawMessage,
	after json.RawMessage,
) error {
	var state map[string]string
	if err := json.Unmarshal(after, &state); err != nil {
		return err
	}
	if state["value"] != a.value {
		return errors.New("value mismatch")
	}
	return nil
}

func (a *memoryTransactionApplier) Reverse(
	before json.RawMessage,
	_ json.RawMessage,
) error {
	if a.failReverse {
		return errors.New("injected reverse failure")
	}
	var state map[string]string
	if err := json.Unmarshal(before, &state); err != nil {
		return err
	}
	a.value = state["value"]
	return nil
}

func newTestTransactionEngine(
	t *testing.T,
	applier TransactionApplier,
	evidence func(EvidenceRecord) error,
) (*TransactionEngine, string, *StorageCipher) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "storage.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	storage, err := NewStorageCipher(keyPath, "transaction-test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "transactions.enc")
	engine, err := NewTransactionEngine(path, storage, evidence, applier)
	if err != nil {
		t.Fatal(err)
	}
	return engine, path, storage
}

func TestTransactionLifecyclePersistsEncryptedHistory(t *testing.T) {
	applier := &memoryTransactionApplier{value: "before"}
	evidenceCount := 0
	engine, path, storage := newTestTransactionEngine(
		t,
		applier,
		func(EvidenceRecord) error {
			evidenceCount++
			return nil
		},
	)
	preview, err := engine.Preview(
		"test.memory", "Change memory value", "transaction regression",
		json.RawMessage(`{"value":"after"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Status != "previewed" || len(preview.Plan) == 0 {
		t.Fatalf("invalid preview: %+v", preview)
	}
	applied, err := engine.Apply(preview.ID, "APPLY "+preview.ID)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Status != "applied" || applier.value != "after" || evidenceCount != 1 {
		t.Fatalf("invalid applied state: %+v value=%s evidence=%d", applied, applier.value, evidenceCount)
	}
	reversed, err := engine.Reverse(preview.ID, "REVERSE "+preview.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reversed.Status != "reversed" || applier.value != "before" || evidenceCount != 2 {
		t.Fatalf("invalid reversed state: %+v value=%s evidence=%d", reversed, applier.value, evidenceCount)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" || json.Valid(raw) && !containsEncryptedSchema(raw) {
		t.Fatal("transaction history is not an encrypted envelope")
	}
	reloaded, err := NewTransactionEngine(path, storage, func(EvidenceRecord) error { return nil }, applier)
	if err != nil {
		t.Fatal(err)
	}
	status := reloaded.Status(10)
	if !status.Healthy || status.Count != 1 || status.Transactions[0].Status != "reversed" {
		t.Fatalf("invalid reloaded status: %+v", status)
	}
}

func containsEncryptedSchema(raw []byte) bool {
	var envelope encryptedStorageEnvelope
	return json.Unmarshal(raw, &envelope) == nil && envelope.Schema == encryptedStorageSchema
}

func TestTransactionFailsClosedWhenEvidenceUnavailable(t *testing.T) {
	applier := &memoryTransactionApplier{value: "before"}
	engine, _, _ := newTestTransactionEngine(
		t,
		applier,
		func(EvidenceRecord) error { return errors.New("evidence offline") },
	)
	preview, err := engine.Preview(
		"test.memory", "Change memory value", "evidence regression",
		json.RawMessage(`{"value":"after"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Apply(preview.ID, "APPLY "+preview.ID); err == nil {
		t.Fatal("apply unexpectedly succeeded without mandatory evidence")
	}
	if applier.value != "before" || engine.Status(10).Transactions[0].Status != "previewed" {
		t.Fatal("mutation occurred despite evidence failure")
	}
}

func TestTransactionInterruptedApplyRequiresRecovery(t *testing.T) {
	applier := &memoryTransactionApplier{value: "before"}
	engine, path, storage := newTestTransactionEngine(
		t, applier, func(EvidenceRecord) error { return nil },
	)
	preview, err := engine.Preview(
		"test.memory", "Change memory value", "recovery regression",
		json.RawMessage(`{"value":"after"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	engine.records[0].Status = "applying"
	if err := engine.persistLocked(); err != nil {
		engine.mu.Unlock()
		t.Fatal(err)
	}
	engine.mu.Unlock()

	reloaded, err := NewTransactionEngine(
		path, storage, func(EvidenceRecord) error { return nil }, applier,
	)
	if err != nil {
		t.Fatal(err)
	}
	status := reloaded.Status(10)
	if !status.RecoveryRequired || status.Transactions[0].Status != "recovery_required" {
		t.Fatalf("interrupted transaction not quarantined: %+v", status)
	}
	if _, err := reloaded.Preview(
		"test.memory", "Another change", "must remain blocked",
		json.RawMessage(`{"value":"other"}`),
	); err == nil {
		t.Fatal("new preview accepted while recovery is required")
	}
	if _, err := reloaded.Reverse(preview.ID, "REVERSE "+preview.ID); err != nil {
		t.Fatal(err)
	}
}

func TestAppliedTransactionReconcilesAfterRestartAndDetectsRuntimeDrift(t *testing.T) {
	applier := &memoryTransactionApplier{value: "before"}
	engine, path, storage := newTestTransactionEngine(
		t, applier, func(EvidenceRecord) error { return nil },
	)
	preview, err := engine.Preview(
		"test.memory", "Persistent memory value", "startup reconciliation",
		json.RawMessage(`{"value":"after"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Apply(preview.ID, "APPLY "+preview.ID); err != nil {
		t.Fatal(err)
	}
	applier.value = "before"
	reloaded, err := NewTransactionEngine(
		path, storage, func(EvidenceRecord) error { return nil }, applier,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.ReconcileApplied(); err != nil {
		t.Fatal(err)
	}
	if applier.value != "after" || !reloaded.Status(10).Healthy {
		t.Fatalf("startup reconciliation failed: value=%s status=%+v", applier.value, reloaded.Status(10))
	}
	applier.value = "external-drift"
	if err := reloaded.VerifyApplied(); err == nil {
		t.Fatal("runtime drift unexpectedly verified")
	}
	status := reloaded.Status(10)
	if !status.RecoveryRequired || status.Transactions[0].FailureStage != "runtime_drift" {
		t.Fatalf("runtime drift did not fail closed: %+v", status)
	}
}

type memorySysctlCore struct {
	values          map[string]string
	failKey         string
	persistent      string
	failPersistence bool
}

func (c *memorySysctlCore) SysctlGet(key string) (string, error) {
	value, exists := c.values[key]
	if !exists {
		return "", errors.New("missing sysctl")
	}
	return value, nil
}

func (c *memorySysctlCore) SysctlCompareSet(key, expected, desired string) error {
	if key == c.failKey {
		return errors.New("injected sysctl failure")
	}
	if c.values[key] != expected {
		return errors.New("compare-set mismatch")
	}
	c.values[key] = desired
	return nil
}

func (c *memorySysctlCore) HardeningProfileState() (string, error) {
	if !validHardeningState(c.persistent) {
		return "", errors.New("invalid persistent test state")
	}
	return c.persistent, nil
}

func (c *memorySysctlCore) HardeningProfileCompareSet(expected, desired string) error {
	if c.failPersistence {
		return errors.New("injected persistent hardening failure")
	}
	if c.persistent != expected {
		return errors.New("persistent compare-set mismatch")
	}
	c.persistent = desired
	return nil
}

func TestSysctlProfileApplierAppliesVerifiesAndReverses(t *testing.T) {
	core := &memorySysctlCore{values: make(map[string]string), persistent: "absent"}
	applier := NewSysctlTransactionApplier(core)
	profile := applier.profiles["linux-server-balanced"]
	for key := range profile.Values {
		core.values[key] = "0"
	}
	plan, before, err := applier.Preview(json.RawMessage(`{"profile":"linux-server-balanced"}`))
	if err != nil {
		t.Fatal(err)
	}
	after, err := applier.Apply(plan, before)
	if err != nil {
		t.Fatal(err)
	}
	if err := applier.Verify(plan, after); err != nil {
		t.Fatal(err)
	}
	if core.persistent != "linux-server-balanced" {
		t.Fatalf("persistent profile not applied: %s", core.persistent)
	}
	if err := applier.Reverse(before, after); err != nil {
		t.Fatal(err)
	}
	for key, value := range core.values {
		if value != "0" {
			t.Fatalf("sysctl %s was not reversed: %s", key, value)
		}
	}
	if core.persistent != "absent" {
		t.Fatalf("persistent profile not reversed: %s", core.persistent)
	}
}

func TestSysctlProfileRollsBackPartialFailure(t *testing.T) {
	core := &memorySysctlCore{values: make(map[string]string), persistent: "absent"}
	applier := NewSysctlTransactionApplier(core)
	profile := applier.profiles["linux-server-balanced"]
	keys := sortedJSONMapKeys(profile.Values)
	for _, key := range keys {
		core.values[key] = "0"
	}
	nonZero := 0
	for _, key := range keys {
		if profile.Values[key] != "0" {
			nonZero++
			if nonZero == 2 {
				core.failKey = key
				break
			}
		}
	}
	plan, before, err := applier.Preview(json.RawMessage(`{"profile":"linux-server-balanced"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applier.Apply(plan, before); err == nil {
		t.Fatal("injected sysctl failure unexpectedly succeeded")
	}
	for key, value := range core.values {
		if value != "0" {
			t.Fatalf("partial sysctl mutation remained at %s=%s", key, value)
		}
	}
}

func TestSysctlProfileRollsBackRuntimeWhenPersistenceFails(t *testing.T) {
	core := &memorySysctlCore{
		values:          make(map[string]string),
		persistent:      "absent",
		failPersistence: true,
	}
	applier := NewSysctlTransactionApplier(core)
	profile := applier.profiles["linux-server-balanced"]
	for key := range profile.Values {
		core.values[key] = "0"
	}
	plan, before, err := applier.Preview(json.RawMessage(`{"profile":"linux-server-balanced"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applier.Apply(plan, before); err == nil {
		t.Fatal("persistent failure unexpectedly succeeded")
	}
	for key, value := range core.values {
		if value != "0" {
			t.Fatalf("runtime mutation remained after persistence failure at %s=%s", key, value)
		}
	}
	if core.persistent != "absent" {
		t.Fatalf("persistent state changed after injected failure: %s", core.persistent)
	}
}
