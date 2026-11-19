package main

// POINT 2 / P2-T3 settings tests: defaults, reject-not-repair validation, the
// v14->v15 migration, clone/effective behaviour and the disabled-draft contract.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParserCellsSettingsDefaultsAndCaps(t *testing.T) {
	defaults := defaultParserCellsFabricSettings()
	if defaults.Enabled || defaults.TTLSeconds != 120 || defaults.MaxConcurrent != 4 ||
		defaults.MaxInputBytes != 8<<20 || defaults.MaxExportBytes != 2<<20 ||
		!defaults.BurnOnIncident || defaults.IncidentScore != 80 || defaults.CooldownSeconds != 300 ||
		defaults.RequireHostLayers || len(defaults.Profiles) != 0 {
		t.Fatalf("parser cell defaults are wrong: %+v", defaults)
	}
	settings := defaults
	if err := validateParserCellsFabricSettings(&settings); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	// A disabled namespace may carry a draft: enabled=false is the explicit
	// nothing-claimed state, so a draft is permitted exactly like titan_exec's.
	draft := defaults
	draft.Profiles = []string{"pdf-viewer", "media-thumb"}
	draft.TTLSeconds = 60
	if err := validateParserCellsFabricSettings(&draft); err != nil {
		t.Fatalf("disabled draft must be allowed: %v", err)
	}
	// Reject-not-repair: every cap refuses instead of clamping.
	invalid := []ParserCellsFabricSettings{}
	for _, mutate := range []func(*ParserCellsFabricSettings){
		func(s *ParserCellsFabricSettings) { s.TTLSeconds = 4 },
		func(s *ParserCellsFabricSettings) { s.TTLSeconds = 3601 },
		func(s *ParserCellsFabricSettings) { s.MaxConcurrent = 0 },
		func(s *ParserCellsFabricSettings) { s.MaxConcurrent = 17 },
		func(s *ParserCellsFabricSettings) { s.MaxInputBytes = 1023 },
		func(s *ParserCellsFabricSettings) { s.MaxInputBytes = 8<<20 + 1 },
		func(s *ParserCellsFabricSettings) { s.MaxExportBytes = 0 },
		func(s *ParserCellsFabricSettings) { s.MaxExportBytes = 2<<20 + 1 },
		func(s *ParserCellsFabricSettings) { s.IncidentScore = 0 },
		func(s *ParserCellsFabricSettings) { s.IncidentScore = 251 },
		func(s *ParserCellsFabricSettings) { s.CooldownSeconds = -1 },
		func(s *ParserCellsFabricSettings) { s.CooldownSeconds = 86401 },
		func(s *ParserCellsFabricSettings) { s.Profiles = []string{"bad profile"} },
		func(s *ParserCellsFabricSettings) { s.Profiles = []string{"dup", "dup"} },
		func(s *ParserCellsFabricSettings) {
			for index := 0; index <= parserCellsMaxProfiles; index++ {
				s.Profiles = append(s.Profiles, "profile-"+string(rune('a'+index)))
			}
		},
	} {
		candidate := defaultParserCellsFabricSettings()
		mutate(&candidate)
		invalid = append(invalid, candidate)
	}
	for index := range invalid {
		if err := validateParserCellsFabricSettings(&invalid[index]); err == nil {
			t.Fatalf("invalid parser cell settings %d were accepted", index)
		}
	}
	// Allowed profiles are canonicalised (sorted) but never rewritten.
	valid := defaultParserCellsFabricSettings()
	valid.Enabled = true
	valid.Profiles = []string{"media-thumb", "pdf-viewer"}
	if err := validateParserCellsFabricSettings(&valid); err != nil {
		t.Fatalf("valid settings rejected: %v", err)
	}
	if valid.Profiles[0] != "media-thumb" || valid.Profiles[1] != "pdf-viewer" {
		t.Fatalf("profiles were not canonicalised: %v", valid.Profiles)
	}
	if !parserCellProfileAllowed(valid, "pdf-viewer") || parserCellProfileAllowed(valid, "other") {
		t.Fatal("explicit profile allowlist is not enforced")
	}
	if !parserCellProfileAllowed(defaultParserCellsFabricSettings(), "anything") {
		t.Fatal("an empty profile list must allow every helper profile")
	}
}

func TestParserCellsSettingsUpgradeV14ToV15(t *testing.T) {
	bootstrap := defaultRuntimeSettings(defaultConfig())
	document := RuntimeSettings{FabricVersion: 14, Revision: 7}
	if upgraded := upgradeRuntimeSettings(&document, bootstrap); !upgraded {
		t.Fatal("a v14 document must be upgraded")
	}
	if document.FabricVersion != fabricSettingsVersion || fabricSettingsVersion != 18 {
		// POINT 5 / P5-T3 bumped the Fabric schema to v16 (lockdown namespace),
		// POINT 4 / P4-T2 to v17 (witness namespace) and GeDefense 6.1.0 to v18
		// (the five A-E namespaces); this test guards the v14->v15 parser-cell
		// seeding, which the v18 document still performs and names exactly as
		// before.
		t.Fatalf("schema version is %d, want 18", document.FabricVersion)
	}
	if document.ParserCells == nil || document.ParserCells.Enabled {
		t.Fatalf("v15 must seed parser cells disabled: %+v", document.ParserCells)
	}
	named := false
	for _, migration := range document.Migrations {
		if strings.Contains(migration, "parser_cells") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the v14->v15 migration is not named: %v", document.Migrations)
	}
	// An older document receives the namespace silently (several namespaces change
	// at once), exactly like the earlier additive modules.
	older := RuntimeSettings{FabricVersion: 12}
	upgradeRuntimeSettings(&older, bootstrap)
	for _, migration := range older.Migrations {
		if strings.Contains(migration, "parser_cells") {
			t.Fatalf("pre-v14 document must not name the parser_cells migration: %v", older.Migrations)
		}
	}
	// An existing operator namespace is never rewritten by the migration.
	existing := ParserCellsFabricSettings{Enabled: true, Profiles: []string{"pdf-viewer"}, TTLSeconds: 30,
		MaxConcurrent: 2, MaxInputBytes: 1024, MaxExportBytes: 1024, BurnOnIncident: false,
		IncidentScore: 10, CooldownSeconds: 0}
	kept := RuntimeSettings{FabricVersion: 14, ParserCells: &existing}
	upgradeRuntimeSettings(&kept, bootstrap)
	if kept.ParserCells == nil || !kept.ParserCells.Enabled || kept.ParserCells.TTLSeconds != 30 || !parserCellProfileAllowed(*kept.ParserCells, "pdf-viewer") {
		t.Fatalf("migration rewrote operator values: %+v", kept.ParserCells)
	}
}

func TestParserCellsSettingsCloneAndEffective(t *testing.T) {
	source := defaultParserCellsFabricSettings()
	source.Enabled = true
	source.Profiles = []string{"pdf-viewer"}
	clone := cloneParserCellsFabricSettings(source)
	clone.Profiles[0] = "changed"
	if source.Profiles[0] != "pdf-viewer" {
		t.Fatal("clone shares the profile slice with the original")
	}
	document := RuntimeSettings{}
	if effective := effectiveParserCellsSettings(document); effective.Enabled || effective.TTLSeconds != 120 {
		t.Fatalf("effective settings without a namespace must be the disabled defaults: %+v", effective)
	}
	document.ParserCells = &source
	if effective := effectiveParserCellsSettings(document); !effective.Enabled {
		t.Fatalf("effective settings ignored the persisted namespace: %+v", effective)
	}
}

func TestParserCellsSettingsPersistenceAndValidation(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.Runtime.StorageKeyFile = ""
	store, err := NewSettingsStore(filepath.Join(dir, "runtime.json"), keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	current := store.Get()
	if current.FabricVersion != fabricSettingsVersion || current.ParserCells == nil || current.ParserCells.Enabled {
		t.Fatalf("fresh store is not the current parser-cells-disabled schema: v=%d cells=%+v", current.FabricVersion, current.ParserCells)
	}
	next := current
	enabled := *current.ParserCells
	enabled.Enabled = true
	enabled.Profiles = []string{"pdf-viewer"}
	next.ParserCells = &enabled
	updated, err := store.Update(next)
	if err != nil {
		t.Fatalf("valid parser cell settings were rejected: %v", err)
	}
	if !updated.ParserCells.Enabled || len(updated.ParserCells.Profiles) != 1 {
		t.Fatalf("parser cell settings were not persisted: %+v", updated.ParserCells)
	}
	invalid := updated
	bad := *updated.ParserCells
	bad.MaxConcurrent = 99
	invalid.ParserCells = &bad
	if _, err := store.Update(invalid); err == nil {
		t.Fatal("out-of-cap parser cell settings were persisted")
	}
	if stored := store.Get(); stored.ParserCells.MaxConcurrent != 4 {
		t.Fatalf("rejected update mutated the persisted revision: %+v", stored.ParserCells)
	}
}
