// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func v6AutoArmFixture(t *testing.T) (Config, *State, *SettingsStore, *ReleaseController) {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.Node.Name = "v6-auto-arm-test"
	cfg.Defense.Allowlist = []string{"192.0.2.10/32"}
	cfg.Runtime.SettingsFile = filepath.Join(dir, "settings.json")
	cfg.Runtime.KeyFile = filepath.Join(dir, "settings.key")
	cfg.Runtime.StorageKeyFile = ""
	cfg.Policy.StorageKeyFile = ""
	cfg.Policy.StateFile = filepath.Join(dir, "policy.json")
	cfg.Policy.SigningKeyFile = filepath.Join(dir, "policy.key")
	cfg.Policy.PublicKeyFile = filepath.Join(dir, "policy.pub")
	cfg.Release.EmergencyStopFile = filepath.Join(dir, "EMERGENCY_STOP")
	cfg.Release.MinimumObserveSeconds = 0
	cfg.Release.MinimumCanarySeconds = 0
	cfg.XDR.Enabled = false

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	if err := os.WriteFile(cfg.Runtime.KeyFile, key, 0o600); err != nil {
		t.Fatalf("write settings key: %v", err)
	}

	settings, err := NewSettingsStore(cfg.Runtime.SettingsFile, cfg.Runtime.KeyFile, cfg)
	if err != nil {
		t.Fatalf("settings store: %v", err)
	}
	state := NewState("test", cfg)
	verifiedAt := time.Now().UTC()
	state.SetSensorCoverage(SensorCoverage{
		Name: "xdp_ingress", Layer: LayerIngressNetwork, Status: CoverageOnline, Required: true,
		LastOK: &verifiedAt, SelfTest: "pass", CoverageReason: "verified fixture",
	})

	policy, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatalf("policy store: %v", err)
	}
	state.SetPolicyStatus(policy.Status())
	state.SetCore(true, "native")
	state.SetAllowlistReady(true)
	state.UpdateXDRScan(1, 0, state.started, false, "", 1)
	core := &releaseCoreStub{}
	release := NewReleaseController(cfg, state, core, policy, settings)
	if err := release.InitializeStartup("observe", true); err != nil {
		t.Fatalf("initialize startup: %v", err)
	}
	return cfg, state, settings, release
}

func TestV6SafeAutoArmOnEnforceAndRespectOverride(t *testing.T) {
	_, _, settings, release := v6AutoArmFixture(t)

	initial := settings.Get()
	if initial.Styx.Enabled || initial.TitanExec.Enabled || initial.ParserCells.Enabled || initial.Lockdown.Enabled || initial.Witness.Enabled {
		t.Fatalf("expected V6 subsystems disabled in initial observe state")
	}

	var hookFired bool
	var hookSettings RuntimeSettings
	release.SetEnforceSettingsHook(func(updated RuntimeSettings) {
		hookFired = true
		hookSettings = updated
	})

	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "promote through canary before enforce"); err != nil {
		t.Fatalf("promote canary: %v", err)
	}
	if settings.Get().V6AutoArmedApplied {
		t.Fatalf("did not expect V6 auto-arm during canary phase")
	}
	if _, err := release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "activate V6 safe defaults on arming"); err != nil {
		t.Fatalf("promote enforce: %v", err)
	}
	if !hookFired {
		t.Fatalf("expected SetEnforceSettingsHook to fire after enforce transition")
	}

	got := settings.Get()
	if !got.V6AutoArmedApplied {
		t.Fatalf("expected V6AutoArmedApplied=true")
	}
	if !got.Styx.Enabled || got.Styx.Mode != StyxModeMonitor || !got.Styx.LogFlows {
		t.Fatalf("unexpected Styx defaults on enforce: %+v", got.Styx)
	}
	if !got.TitanExec.Enabled || got.TitanExec.Mode != TitanExecModeContain {
		t.Fatalf("unexpected TitanExec defaults on enforce: %+v", got.TitanExec)
	}
	if !got.ParserCells.Enabled {
		t.Fatalf("expected ParserCells enabled on enforce")
	}
	if got.Lockdown.Enabled || got.Lockdown.AutoArm {
		t.Fatalf("expected Emergency Lockdown to stay opt-in (avoid automatic remote XDP_DROP lockout): %+v", got.Lockdown)
	}
	if got.Witness.Enabled || got.Witness.Mode != witnessModeOff {
		t.Fatalf("expected Witness to stay opt-in: %+v", got.Witness)
	}
	if !hookSettings.Styx.Enabled || !hookSettings.TitanExec.Enabled {
		t.Fatalf("expected hook callback to receive promoted settings")
	}

	// An explicit operator disable must remain sticky across subsequent restart checks.
	override := settings.Get()
	override.Styx.Enabled = false
	override.Styx.Mode = StyxModeOff
	if _, err := settings.Update(override); err != nil {
		t.Fatalf("explicit override update: %v", err)
	}
	afterRestart, activatedAgain, err := settings.ApplySafeV6DefaultsOnEnforce()
	if err != nil {
		t.Fatalf("repeat auto-arm: %v", err)
	}
	if activatedAgain || afterRestart.Styx.Enabled {
		t.Fatalf("expected explicit operator disable to remain sticky after restart")
	}
}
