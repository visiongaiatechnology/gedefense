// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func policyFunnelFixture(t *testing.T) (Config, *PolicyStore, *State) {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.Policy.StateFile = filepath.Join(dir, "policy.json")
	cfg.Policy.SigningKeyFile = filepath.Join(dir, "policy.key")
	cfg.Policy.PublicKeyFile = filepath.Join(dir, "policy.pub")
	cfg.Policy.StorageKeyFile = ""
	cfg.Policy.RequireSigned = true
	policy, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState("xdr-policy-funnel-test", cfg)
	return cfg, policy, state
}

// TestQuarantineRefusesToResignAnUnverifiedPolicy is the FIND-013 funnel-gap regression test for
// the XDR containment path.
//
// quarantineRemote added the reversible block and then persisted the signed policy document
// directly, bypassing the central persistPolicy funnel and its errPolicyUnverified guard. While
// the startup quarantine happens to keep the platform in observe, the path must nonetheless never
// re-sign a document the platform could not verify.
func TestQuarantineRefusesToResignAnUnverifiedPolicy(t *testing.T) {
	cfg, policy, state := policyFunnelFixture(t)

	// A malformed document leaves the store unverified, exactly like a failed startup load.
	malformed := []byte(`{"envelope":`)
	if err := os.WriteFile(cfg.Policy.StateFile, malformed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(); err == nil {
		t.Fatal("the malformed policy document unexpectedly loaded")
	}
	if policy.Status().Verified {
		t.Fatal("the policy store is still verified after a failed load")
	}

	engine := &XDREngine{
		cfg: cfg, state: state, policy: policy, selfPID: -1,
		protected:     map[string]protectedObject{},
		degradeCauses: map[string]string{},
		tamperSeen:    map[string]string{},
	}
	err := engine.quarantineRemote("203.0.113.9", XDRIncident{RuleIDs: []string{"XDR.THREAT_INTEL_C2"}})
	if err == nil || !errors.Is(err, errPolicyUnverified) {
		t.Fatalf("the containment path did not refuse an unverified policy: %v", err)
	}

	// The unverified document is forensic evidence: not one byte may be rewritten.
	after, readErr := os.ReadFile(cfg.Policy.StateFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, malformed) {
		t.Fatal("the quarantine path re-signed and overwrote the unverified policy document")
	}

	// The reversible block is rolled back when it cannot be persisted, and the refusal is
	// reported once through the central funnel.
	if blocks := state.BlocksSnapshot(); len(blocks) != 0 {
		t.Fatalf("an unpersistable containment block survived: %+v", blocks)
	}
	refusalRecorded := false
	for _, event := range state.Snapshot().Events {
		if event.Kind == "policy.persist_refused" {
			refusalRecorded = true
		}
	}
	if !refusalRecorded {
		t.Fatal("the refused policy persistence left no event for the operator")
	}
}

// TestQuarantinePersistsThroughTheCentralFunnel is the counter-case: with a verified policy the
// containment path still records the block and persists the signed document through the funnel.
func TestQuarantinePersistsThroughTheCentralFunnel(t *testing.T) {
	cfg, policy, state := policyFunnelFixture(t)
	if !policy.Status().Verified {
		t.Fatal("a fresh policy store should be verified")
	}
	engine := &XDREngine{
		cfg: cfg, state: state, policy: policy, selfPID: -1,
		protected:     map[string]protectedObject{},
		degradeCauses: map[string]string{},
		tamperSeen:    map[string]string{},
	}
	if err := engine.quarantineRemote("203.0.113.9", XDRIncident{RuleIDs: []string{"XDR.THREAT_INTEL_C2"}}); err != nil {
		t.Fatalf("the containment path failed with a verified policy: %v", err)
	}
	if blocks := state.BlocksSnapshot(); len(blocks) != 1 {
		t.Fatalf("the containment block was not recorded: %+v", blocks)
	}
	document, err := os.ReadFile(cfg.Policy.StateFile)
	if err != nil {
		t.Fatalf("the signed policy was not persisted: %v", err)
	}
	if len(document) == 0 {
		t.Fatal("the persisted policy document is empty")
	}
	if !policy.Status().Verified {
		t.Fatal("the policy store lost its verified status after a successful persist")
	}
}
