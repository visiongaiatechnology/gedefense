// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTitanPolicyPersistenceAndValidation(t *testing.T) {
	t.Run("policy change persists and survives restart", func(t *testing.T) {
		rig := newTitanTestRig(t, nil)
		status, err := rig.engine.ApplyPolicy(TitanModeStrict, true, true, "operator enables strict containment for the pilot")
		if err != nil {
			t.Fatalf("policy change rejected: %v", err)
		}
		if status.Mode != TitanModeStrict || !status.Armed || !status.AutoContain {
			t.Fatalf("policy status not updated: %+v", status)
		}
		if !rig.evidence.hasKind("titan.policy.updated") {
			t.Fatal("policy change was not evidenced")
		}
		info, err := os.Stat(rig.cfg.PolicyFile)
		if err != nil {
			t.Fatalf("policy file missing: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("policy file mode = %o, want 600", info.Mode().Perm())
		}
		restarted := newTitanTestRigForCfg(t, rig.cfg, rig.stateDir)
		if got := restarted.engine.Status(); got.Mode != TitanModeStrict || !got.Armed || !got.AutoContain {
			t.Fatalf("persisted policy not restored: %+v", got)
		}
	})

	t.Run("invalid policy and reason are rejected without state change", func(t *testing.T) {
		rig := newTitanTestRig(t, nil)
		before := rig.engine.Status()
		if _, err := rig.engine.ApplyPolicy(TitanMode("NOPE"), false, false, "operator supplies an invalid mode value"); err == nil {
			t.Fatal("invalid mode accepted")
		}
		if _, err := rig.engine.ApplyPolicy(TitanModeStrict, true, true, "short"); err == nil {
			t.Fatal("short reason accepted")
		}
		if _, err := rig.engine.ApplyPolicy(TitanModeStrict, true, true, "bad\x00reason here"); err == nil {
			t.Fatal("control character reason accepted")
		}
		after := rig.engine.Status()
		if after.Mode != before.Mode || after.Armed != before.Armed {
			t.Fatalf("rejected policy mutated state: %+v", after)
		}
	})

	t.Run("corrupt policy falls back without destroying the file", func(t *testing.T) {
		base := t.TempDir()
		stateDir := filepath.Join(base, "state")
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		policyPath := filepath.Join(stateDir, "titan-policy.json")
		corrupt := []byte("not-a-policy")
		if err := os.WriteFile(policyPath, corrupt, 0o600); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(base, "roots")
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		cfg := defaultTitanConfig()
		cfg.Roots = []string{root}
		cfg.PolicyFile = policyPath
		cfg.JournalFile = filepath.Join(stateDir, "titan-journal.json")
		engine, err := NewTitanEngine(cfg, TitanDeps{Version: titanTestVersion, DataRoot: stateDir, Now: func() time.Time { return time.Now().UTC() }})
		if err != nil {
			t.Fatalf("corrupt policy stopped the engine: %v", err)
		}
		if engine.loadWarning == "" {
			t.Fatal("corrupt policy was not surfaced")
		}
		if engine.Status().Mode != TitanModeObserve {
			t.Fatalf("corrupt policy did not fall back to configured defaults: %+v", engine.Status())
		}
		preserved, err := os.ReadFile(policyPath)
		if err != nil || string(preserved) != string(corrupt) {
			t.Fatalf("corrupt policy was modified: %v", err)
		}
	})

	t.Run("persistence failure reverts the in-memory policy", func(t *testing.T) {
		rig := newTitanTestRig(t, nil)
		if err := os.MkdirAll(rig.cfg.PolicyFile, 0o700); err != nil {
			t.Fatal(err)
		}
		before := rig.engine.Status()
		if _, err := rig.engine.ApplyPolicy(TitanModeContain, true, false, "operator enables containment while storage is broken"); err == nil {
			t.Fatal("persistence failure was reported as success")
		}
		if got := rig.engine.Status(); got.Mode != before.Mode || got.Armed != before.Armed {
			t.Fatalf("failed persistence left a changed policy: %+v", got)
		}
	})

	t.Run("configuration validation", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*TitanConfig)
			valid  bool
		}{
			{"default", func(*TitanConfig) {}, true},
			{"strict mode", func(c *TitanConfig) { c.Mode = "strict" }, true},
			{"invalid mode", func(c *TitanConfig) { c.Mode = "bogus" }, false},
			{"relative root", func(c *TitanConfig) { c.Roots = []string{"relative/path"} }, false},
			{"filesystem root", func(c *TitanConfig) { c.Roots = []string{"/"} }, false},
			{"nul path", func(c *TitanConfig) { c.Roots = []string{"/tmp/a\x00b"} }, false},
			{"too few events", func(c *TitanConfig) { c.MaxEvents = 1 }, false},
			{"too many bytes", func(c *TitanConfig) { c.MaxFileBytes = 1 << 40 }, false},
			{"journal outside bounds", func(c *TitanConfig) { c.JournalMaxBytes = 1 }, false},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				cfg := defaultTitanConfig()
				cfg.Roots = []string{"/tmp"}
				testCase.mutate(&cfg)
				err := validateTitanConfig(&cfg)
				if testCase.valid && err != nil {
					t.Fatalf("valid config rejected: %v", err)
				}
				if !testCase.valid && err == nil {
					t.Fatal("invalid config accepted")
				}
			})
		}
		full := defaultConfig()
		full.Titan.Roots = []string{"/tmp"}
		if err := assignTitanConfig(&full, "mode", "\"contain\""); err != nil || full.Titan.Mode != "contain" {
			t.Fatalf("assign titan.mode: %v %q", err, full.Titan.Mode)
		}
		if err := assignTitanConfig(&full, "unknown", "true"); err == nil {
			t.Fatal("unknown titan key accepted")
		}
	})
}

func newTitanTestRigForCfg(t *testing.T, cfg TitanConfig, stateDir string) *titanTestRig {
	t.Helper()
	rig := &titanTestRig{
		t: t, cfg: cfg, stateDir: stateDir,
		fim: newFakeTitanFIM(), packages: newFakeTitanPackages(), xdrContext: &fakeTitanContext{},
		containment: newFakeTitanContainment(), evidence: &fakeTitanEvidence{},
		now: time.Date(2026, 10, 22, 20, 0, 0, 0, time.UTC),
	}
	var containment titanContainment = rig.containment
	deps := TitanDeps{
		Version: titanTestVersion, DataRoot: stateDir,
		FIM: rig.fim, Packages: rig.packages, Context: rig.xdrContext, Containment: containment,
		Evidence: rig.evidence.Record,
		Events:   func(Event) {},
		Now:      func() time.Time { return rig.now },
	}
	engine, err := NewTitanEngine(cfg, deps)
	if err != nil {
		t.Fatalf("NewTitanEngine() error: %v", err)
	}
	rig.engine = engine
	return rig
}

func TestTitanReviewFlow(t *testing.T) {
	rig := newTitanTestRig(t, nil)
	event := rig.observe(rig.write("review.bin", "payload"), TitanChangeCreated)
	if got := rig.engine.Status().OpenFindings; got != 1 {
		t.Fatalf("open findings = %d, want 1", got)
	}
	updated, err := rig.engine.Review(event.ID, "REVIEWED", "operator reviewed the dropped file and accepted the finding")
	if err != nil {
		t.Fatalf("review failed: %v", err)
	}
	if updated.Review != "REVIEWED" || updated.ReviewReason == "" {
		t.Fatalf("review state not recorded: %+v", updated)
	}
	if got := rig.engine.Status().OpenFindings; got != 0 {
		t.Fatalf("open findings after review = %d, want 0", got)
	}
	if !rig.evidence.hasKind("titan.review") {
		t.Fatal("review was not evidenced")
	}
	if _, err := rig.engine.Review(event.ID, "SOMETHING", "operator supplies an invalid review decision"); err == nil {
		t.Fatal("invalid review decision accepted")
	}
	if _, err := rig.engine.Review("deadbeefdeadbeef", "REVIEWED", "operator reviews an unknown event identifier"); err == nil {
		t.Fatal("unknown event accepted")
	}
	if _, err := rig.engine.Review(event.ID, "ESCALATED", "short"); err == nil {
		t.Fatal("short review reason accepted")
	}
}
