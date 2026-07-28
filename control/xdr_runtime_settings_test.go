package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBehaviorLearningFollowsRuntimeToggle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.XDR.StorageKeyFile = ""
	cfg.Runtime.StorageKeyFile = ""
	cfg.XDR.LogKeyFile = filepath.Join(dir, "xdr.key")
	cfg.XDR.BehaviorProfileFile = filepath.Join(dir, "behavior.json")
	cfg.Runtime.KeyFile = filepath.Join(dir, "runtime.key")
	cfg.Runtime.SettingsFile = filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(cfg.XDR.LogKeyFile, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Runtime.KeyFile, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := NewSettingsStore(cfg.Runtime.SettingsFile, cfg.Runtime.KeyFile, cfg)
	if err != nil {
		t.Fatal(err)
	}
	next := settings.Get()
	next.BehaviorEnabled = false
	if _, err := settings.Update(next); err != nil {
		t.Fatal(err)
	}
	model, err := NewBehaviorModel(cfg.XDR)
	if err != nil {
		t.Fatal(err)
	}
	engine := &XDREngine{
		cfg:      cfg,
		state:    NewState(version, cfg),
		settings: settings,
		behavior: model,
		rules:    NewXDRRuleEngine(),
		selfPID:  -1,
		dedupe:   map[string]time.Time{},
	}
	engine.evaluate(ProcessSample{PID: 10001, StartTicks: 1, Comm: "runtime-toggle-a", Exe: "/usr/bin/runtime-toggle-a"}, nil, "exec")
	if got := model.Summary().Profiles; got != 0 {
		t.Fatalf("behavior learning ran while disabled: profiles=%d", got)
	}
	next = settings.Get()
	next.BehaviorEnabled = true
	if _, err := settings.Update(next); err != nil {
		t.Fatal(err)
	}
	engine.evaluate(ProcessSample{PID: 10002, StartTicks: 2, Comm: "runtime-toggle-b", Exe: "/usr/bin/runtime-toggle-b"}, nil, "exec")
	if got := model.Summary().Profiles; got != 1 {
		t.Fatalf("behavior learning did not activate live: profiles=%d", got)
	}
}
