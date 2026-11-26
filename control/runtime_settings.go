package main

import (
	"errors"
	"fmt"
	"os"
	"time"
)

const runtimeSettingsSchema = "vgt-gedefense-runtime-settings-v1"

var supportedRuleModules = []string{
	"baseline",
	"command",
	"lineage",
	"masquerading",
	"origin",
	"threat-intel",
}

// The settings document version is bumped only when an upgrade actually has to
// migrate something. v13 adds the StyX kernel-egress namespace: a document
// written before it existed loads unchanged, receives the namespace with
// enabled=false/mode=off and therefore keeps the exact kernel behaviour of 5.2.0.
// v14 adds the Titan exec-gate namespace (docs/POINT1-TITAN-EXEC-GATE.md §7.1) with
// the same additive contract: enabled=false/mode=off and empty lists leave the
// kernel behaviour of a 5.2.0 node unchanged.
// v15 adds the ephemeral parser-cell namespace (docs/POINT2-PARSER-CELLS.md §6):
// enabled=false and no cell may be created; the helper is not contacted and the
// upgrade changes no host behaviour at all.
// v16 adds the Emergency Lockdown namespace (docs/POINT5-LOCKDOWN.md §7): enabled=false
// means no LOCKDOWN_* command, no trigger ticker traffic and no event; an upgrade keeps
// the exact host behaviour of 5.2.0 and the namespace is named in the migration record
// for a v15 document.
// v17 adds the Out-of-Band Witness namespace (docs/POINT4-WITNESS.md §7): enabled=false
// and mode=off mean no checkpoint, no witness request, no export and no event; an
// upgrade keeps the exact host behaviour of 5.2.0 and the namespace is named in the
// migration record for a v16 document.
// v18 adds the five 6.1.0 namespaces (docs/V6.1.0-BLUEPRINT.md §3.3):
// web_exposure (read-only sensor, enabled), worker_guard, tls_sensor and lpe_guard
// (disabled) and edge_proxy (enabled=false, loopback listener unbound). A v17
// document receives each namespace with its inert default and the migration record
// names it; no kernel or host behaviour changes on upgrade.
const fabricSettingsVersion = 18
const runtimeSettingsHistoryLimit = 32

func NewSettingsStore(path, keyPath string, cfg Config) (*SettingsStore, error) {
	if path == "" {
		return nil, errors.New("runtime settings path is empty")
	}
	key, err := loadPrivateKeyFile(keyPath, 32)
	if err != nil {
		return nil, fmt.Errorf("runtime settings key: %w", err)
	}
	storage, err := NewStorageCipher(cfg.Runtime.StorageKeyFile, cfg.Node.Name)
	if err != nil {
		return nil, fmt.Errorf("runtime settings encryption: %w", err)
	}
	defaults := defaultRuntimeSettings(cfg)
	s := &SettingsStore{path: path, key: key, crypto: storage, defaults: cloneRuntimeSettings(defaults), current: defaults}
	if err := s.load(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := s.persistLocked(s.current); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *SettingsStore) Get() RuntimeSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRuntimeSettings(s.current)
}

func (s *SettingsStore) History() []RuntimeSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRuntimeSettingsHistory(s.history)
}

func (s *SettingsStore) Revision(revision uint64) (RuntimeSettings, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current.Revision == revision {
		return cloneRuntimeSettings(s.current), nil
	}
	for i := len(s.history) - 1; i >= 0; i-- {
		if s.history[i].Revision == revision {
			return cloneRuntimeSettings(s.history[i]), nil
		}
	}
	return RuntimeSettings{}, os.ErrNotExist
}

func (s *SettingsStore) Update(next RuntimeSettings) (RuntimeSettings, error) {
	return s.updateLocked(next, 0, false)
}

// UpdateIfRevision atomically commits next only if the current revision still matches expectedRevision.
func (s *SettingsStore) UpdateIfRevision(expectedRevision uint64, next RuntimeSettings) (RuntimeSettings, error) {
	return s.updateLocked(next, expectedRevision, true)
}

func (s *SettingsStore) updateLocked(next RuntimeSettings, expectedRevision uint64, checkRevision bool) (RuntimeSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if checkRevision && (expectedRevision == 0 || s.current.Revision != expectedRevision) {
		return cloneRuntimeSettings(s.current), fmt.Errorf("runtime settings revision conflict: expected %d current %d", expectedRevision, s.current.Revision)
	}
	next.FabricVersion = fabricSettingsVersion
	if err := validateRuntimeSettings(&next); err != nil {
		return cloneRuntimeSettings(s.current), err
	}
	if effectiveForensicsSettings(next).Quarantine.RestoreFileMode & ^effectiveForensicsSettings(s.current).Quarantine.RestoreFileMode != 0 {
		return cloneRuntimeSettings(s.current), errors.New("quarantine restore permissions must not widen")
	}
	next.Revision = s.current.Revision + 1
	next.UpdatedAt = time.Now().UTC()
	oldHistory := cloneRuntimeSettingsHistory(s.history)
	s.history = append(s.history, cloneRuntimeSettings(s.current))
	if len(s.history) > runtimeSettingsHistoryLimit {
		s.history = append([]RuntimeSettings(nil), s.history[len(s.history)-runtimeSettingsHistoryLimit:]...)
	}
	if err := s.persistLocked(next); err != nil {
		s.history = oldHistory
		return cloneRuntimeSettings(s.current), err
	}
	return cloneRuntimeSettings(s.current), nil
}

func (s *SettingsStore) Rollback(revision uint64) (RuntimeSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var target *RuntimeSettings
	for i := len(s.history) - 1; i >= 0; i-- {
		if s.history[i].Revision == revision {
			copy := cloneRuntimeSettings(s.history[i])
			target = &copy
			break
		}
	}
	if target == nil {
		return cloneRuntimeSettings(s.current), os.ErrNotExist
	}
	next := cloneRuntimeSettings(*target)
	if effectiveForensicsSettings(next).Quarantine.RestoreFileMode & ^effectiveForensicsSettings(s.current).Quarantine.RestoreFileMode != 0 {
		return cloneRuntimeSettings(s.current), errors.New("quarantine restore permissions must not widen")
	}
	next.FabricVersion = fabricSettingsVersion
	next.Revision = s.current.Revision + 1
	next.UpdatedAt = time.Now().UTC()
	if err := validateRuntimeSettings(&next); err != nil {
		return cloneRuntimeSettings(s.current), err
	}
	oldHistory := cloneRuntimeSettingsHistory(s.history)
	s.history = append(s.history, cloneRuntimeSettings(s.current))
	if len(s.history) > runtimeSettingsHistoryLimit {
		s.history = append([]RuntimeSettings(nil), s.history[len(s.history)-runtimeSettingsHistoryLimit:]...)
	}
	if err := s.persistLocked(next); err != nil {
		s.history = oldHistory
		return cloneRuntimeSettings(s.current), err
	}
	return cloneRuntimeSettings(s.current), nil
}

func (s *SettingsStore) AddAllowlist(target string) (RuntimeSettings, string, error) {
	normalized, err := normalizeTarget(target)
	if err != nil {
		return s.Get(), "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneRuntimeSettings(s.current)
	for _, value := range next.ManagementAllowlist {
		if value == normalized {
			return next, normalized, nil
		}
	}
	next.ManagementAllowlist = append(next.ManagementAllowlist, normalized)
	next.Revision++
	next.UpdatedAt = time.Now().UTC()
	if err := s.persistLocked(next); err != nil {
		return cloneRuntimeSettings(s.current), "", err
	}
	return cloneRuntimeSettings(s.current), normalized, nil
}

func (s *SettingsStore) RemoveAllowlist(target string) (RuntimeSettings, string, error) {
	normalized, err := normalizeTarget(target)
	if err != nil {
		return s.Get(), "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.current.ManagementAllowlist) <= 1 {
		return cloneRuntimeSettings(s.current), "", errors.New("the final management allowlist entry cannot be removed")
	}
	next := cloneRuntimeSettings(s.current)
	found := false
	out := next.ManagementAllowlist[:0]
	for _, value := range next.ManagementAllowlist {
		if value == normalized {
			found = true
			continue
		}
		out = append(out, value)
	}
	if !found {
		return cloneRuntimeSettings(s.current), "", os.ErrNotExist
	}
	next.ManagementAllowlist = append([]string(nil), out...)
	next.Revision++
	next.UpdatedAt = time.Now().UTC()
	if err := s.persistLocked(next); err != nil {
		return cloneRuntimeSettings(s.current), "", err
	}
	return cloneRuntimeSettings(s.current), normalized, nil
}

// ApplySafeV6DefaultsOnEnforce enables the non-breaking V6 defense subsystems
// when GeDefense arms into enforce (unless previously applied or already configured):
// StyX moves to monitor (with flow telemetry for C2/beacon detection), Titan Exec
// moves to contain, and Parser Cells enables fail-closed admission. Both Emergency
// Lockdown (which can sever remote SSH/HTTP via XDP_DROP on a single trigger)
// and Witness remain explicit opt-in until configured by the operator.
func (s *SettingsStore) ApplySafeV6DefaultsOnEnforce() (RuntimeSettings, bool, error) {
	if s == nil {
		return RuntimeSettings{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.V6AutoArmedApplied {
		return cloneRuntimeSettings(s.current), false, nil
	}
	next := cloneRuntimeSettings(s.current)
	activated := false

	styx := effectiveStyxFabricSettings(next)
	if !styx.Enabled && styx.Mode == StyxModeOff {
		styx.Enabled = true
		styx.Mode = StyxModeMonitor
		styx.LogFlows = true
		next.Styx = &styx
		activated = true
	}

	titan := effectiveTitanExecFabricSettings(next)
	if !titan.Enabled && titan.Mode == TitanExecModeOff {
		titan.Enabled = true
		titan.Mode = TitanExecModeContain
		next.TitanExec = &titan
		activated = true
	}

	parserCells := effectiveParserCellsSettings(next)
	if !parserCells.Enabled {
		parserCells.Enabled = true
		next.ParserCells = &parserCells
		activated = true
	}

	next.V6AutoArmedApplied = true
	next.FabricVersion = fabricSettingsVersion
	if err := validateRuntimeSettings(&next); err != nil {
		return cloneRuntimeSettings(s.current), false, err
	}
	next.Revision = s.current.Revision + 1
	next.UpdatedAt = time.Now().UTC()
	oldHistory := cloneRuntimeSettingsHistory(s.history)
	s.history = append(s.history, cloneRuntimeSettings(s.current))
	if len(s.history) > runtimeSettingsHistoryLimit {
		s.history = append([]RuntimeSettings(nil), s.history[len(s.history)-runtimeSettingsHistoryLimit:]...)
	}
	if err := s.persistLocked(next); err != nil {
		s.history = oldHistory
		return cloneRuntimeSettings(s.current), false, err
	}
	return cloneRuntimeSettings(s.current), activated, nil
}
