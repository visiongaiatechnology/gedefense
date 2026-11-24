// STATUS: DIAMANT VGT SUPREME
// Authenticated runtime-settings persistence, load and schema upgrade,
// split out of runtime_settings.go (refactoring wave 1b, structure-only).
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func loadPrivateKeyFile(path string, expected int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("key must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("key must not be group/world accessible")
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != expected {
		return nil, fmt.Errorf("key must contain exactly %d bytes", expected)
	}
	return key, nil
}

func (s *SettingsStore) load() error {
	data, err := readBoundedPrivateFile(s.path, 4<<20)
	if err != nil {
		return err
	}
	legacy := false
	if s.crypto != nil {
		// Explicit migration read: the document MAC authenticates the settings independently of
		// the envelope, so a plaintext document written before the storage key existed can be
		// upgraded. The strict Decrypt is used everywhere else.
		data, legacy, err = s.crypto.DecryptForMigration(s.path, "runtime-settings", data, nil)
		if err != nil {
			return fmt.Errorf("runtime settings decrypt: %w", err)
		}
	}
	var document runtimeSettingsEnvelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&document); err != nil {
		return fmt.Errorf("runtime settings decode: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("runtime settings contain trailing data")
	}
	if document.Schema != runtimeSettingsSchema {
		return errors.New("runtime settings schema mismatch")
	}
	// Authenticate the document exactly as it was persisted before applying any schema upgrade.
	expected, err := s.mac(document.Settings)
	if err != nil {
		return err
	}
	provided, err := hex.DecodeString(document.MAC)
	if err != nil {
		return errors.New("runtime settings authentication failed")
	}
	// Earlier writers signed a deep clone which normalized empty lists to null.
	// Verify that authenticated representation too, without changing the document.
	legacyExpected, err := s.mac(cloneRuntimeSettings(document.Settings))
	if err != nil {
		return err
	}
	validWire := hmac.Equal(expected, provided)
	validLegacy := hmac.Equal(legacyExpected, provided)
	if !validWire && !validLegacy {
		return errors.New("runtime settings authentication failed")
	}
	// The history is the rollback surface: restoring an entry from it changes the operator's
	// configuration. It used to be authenticated only when the writer supplied a MAC, so a
	// document with an empty HistoryMAC loaded without checking the history at all. An attacker
	// with write access to the state file could plant settings that an operator rollback would
	// later activate. Every writer of this format emits a history MAC, so a missing one is an
	// integrity failure and never a reason to skip the check.
	if document.HistoryMAC == "" {
		return errors.New("runtime settings history authentication failed: history MAC is missing")
	}
	expectedHistory, err := s.macHistory(document.History)
	if err != nil {
		return err
	}
	providedHistory, err := hex.DecodeString(document.HistoryMAC)
	if err != nil {
		return errors.New("runtime settings history authentication failed")
	}
	legacyHistory, err := s.macHistory(cloneRuntimeSettingsHistory(document.History))
	if err != nil {
		return err
	}
	validHistory := hmac.Equal(expectedHistory, providedHistory)
	validLegacyHistory := hmac.Equal(legacyHistory, providedHistory)
	if !validHistory && !validLegacyHistory {
		return errors.New("runtime settings history authentication failed")
	}
	upgraded := upgradeRuntimeSettings(&document.Settings, s.defaults)
	for i := range document.History {
		upgradeRuntimeSettings(&document.History[i], s.defaults)
	}
	if err := validateRuntimeSettings(&document.Settings); err != nil {
		return fmt.Errorf("runtime settings validation: %w", err)
	}
	s.history = cloneRuntimeSettingsHistory(document.History)
	if len(s.history) > runtimeSettingsHistoryLimit {
		s.history = append([]RuntimeSettings(nil), s.history[len(s.history)-runtimeSettingsHistoryLimit:]...)
	}
	s.current = cloneRuntimeSettings(document.Settings)
	if upgraded || (legacy && s.crypto != nil) {
		if err := s.persistLocked(s.current); err != nil {
			return fmt.Errorf("runtime settings migration: %w", err)
		}
	}
	return nil
}

// upgradeRuntimeSettings migrates an authenticated document to the current
// Fabric schema. Namespaces that already existed keep their operator values;
// only genuinely new namespaces are seeded from the bootstrap configuration.
func upgradeRuntimeSettings(settings *RuntimeSettings, defaults RuntimeSettings) bool {
	if settings == nil || settings.FabricVersion >= fabricSettingsVersion {
		return false
	}
	if settings.FabricVersion < 2 {
		// v1 carried no per-module namespaces at all.
		settings.Kinetic = cloneKineticRuntimeSettings(defaults.Kinetic)
		settings.Network = defaults.Network
		settings.Protection = defaults.Protection
		settings.XDRFabric = cloneXDRFabricSettings(defaults.XDRFabric)
	}
	if settings.L7 == nil {
		l7Fabric := cloneL7FabricSettings(l7Defaults(defaults))
		settings.L7 = &l7Fabric
	}
	if settings.ThreatIntel == nil {
		threatIntel := cloneThreatIntelFabricSettings(threatIntelDefaults(defaults))
		// The document's existing operator intent wins over the bootstrap seed.
		threatIntel.Enabled = settings.FeedsEnabled
		threatIntel.AutoSync = settings.AutoFeedSync
		settings.ThreatIntel = &threatIntel
	}
	if settings.Hardening == nil {
		hardening := cloneHardeningFabricSettings(hardeningDefaults(defaults))
		settings.Hardening = &hardening
	}
	if settings.Integrity == nil {
		integrity := cloneIntegrityFabricSettings(integrityDefaults(defaults))
		settings.Integrity = &integrity
	}
	if settings.BootTrust == nil {
		bootTrust := cloneBootTrustFabricSettings(bootTrustDefaults(defaults))
		settings.BootTrust = &bootTrust
	}
	if settings.PolicyTrust == nil {
		policyTrust := policyTrustDefaults(defaults)
		settings.PolicyTrust = &policyTrust
	}
	if settings.Forensics == nil {
		forensics := forensicsDefaults(defaults)
		settings.Forensics = &forensics
	}
	if settings.System == nil {
		system := systemDefaults(defaults)
		settings.System = &system
	}
	// v13: the StyX kernel-egress namespace. Seeding it is deliberately silent for
	// documents older than v12 (they receive several namespaces at once, exactly like
	// the earlier additive modules); a v12 document is the real upgrade path this
	// release ships to, so there the new namespace is named in the migration record -
	// an upgrade must never look like it changed the operator's configuration.
	if settings.Styx == nil {
		styx := styxDefaults(defaults)
		settings.Styx = &styx
		if settings.FabricVersion >= 12 {
			settings.Migrations = append(settings.Migrations,
				"styX namespace added with enabled=false and mode=off: kernel egress behaviour is unchanged until an operator enables it (docs/POINT3-EGRESS-BEACON.md §12)")
		}
	}
	// v14: the Titan exec-gate namespace. Seeding it is silent for documents older
	// than v13 (they receive several namespaces at once, exactly like the earlier
	// additive modules); a v13 document is the real upgrade path this release ships
	// to, so there the new namespace is named in the migration record - an upgrade
	// must never look like it changed the operator's configuration.
	if settings.TitanExec == nil {
		titanExec := titanExecDefaults(defaults)
		settings.TitanExec = &titanExec
		if settings.FabricVersion >= 13 {
			settings.Migrations = append(settings.Migrations,
				"titan_exec namespace added with enabled=false and mode=off: kernel exec behaviour is unchanged until an operator enables it (docs/POINT1-TITAN-EXEC-GATE.md §7.1)")
		}
	}
	// v15: the ephemeral parser-cell namespace. A v14 document is the real upgrade
	// path this release ships to, so the seeded namespace is named in the migration
	// record; older documents receive several namespaces at once, exactly like the
	// earlier additive modules. Nothing is claimed and no helper is contacted while
	// the namespace stays disabled (docs/POINT2-PARSER-CELLS.md §6, §8).
	if settings.ParserCells == nil {
		parserCells := parserCellsDefaults(defaults)
		settings.ParserCells = &parserCells
		if settings.FabricVersion >= 14 {
			settings.Migrations = append(settings.Migrations,
				"parser_cells namespace added with enabled=false: no parser cell is created, no privileged helper is contacted and host behaviour is unchanged until an operator enables it (docs/POINT2-PARSER-CELLS.md §6)")
		}
	}
	// v16: the Emergency Lockdown namespace. A v15 document is the real upgrade path
	// this release ships to, so the seeded namespace is named in the migration record;
	// older documents receive several namespaces at once, exactly like the earlier
	// additive modules. Nothing is armed and no core command is issued while the
	// namespace stays disabled (docs/POINT5-LOCKDOWN.md §7, §9).
	if settings.Lockdown == nil {
		lockdown := lockdownDefaults(defaults)
		settings.Lockdown = &lockdown
		if settings.FabricVersion >= 15 {
			settings.Migrations = append(settings.Migrations, lockdownMigrationNote)
		}
	}
	// v17: the Out-of-Band Witness namespace. A v16 document is the real upgrade
	// path this release ships to, so the seeded namespace is named in the migration
	// record; older documents receive several namespaces at once, exactly like the
	// earlier additive modules. Nothing is checkpointed, sent or exported while the
	// namespace stays disabled (docs/POINT4-WITNESS.md §1, §7).
	if settings.Witness == nil {
		witness := witnessDefaults(defaults)
		settings.Witness = &witness
		if settings.FabricVersion >= 16 {
			settings.Migrations = append(settings.Migrations, witnessMigrationNote)
		}
	}
	// v18: the five 6.1.0 namespaces (docs/V6.1.0-BLUEPRINT.md §3.3). A v17
	// document is the real upgrade path this release ships to, so every seeded
	// namespace is named in the migration record; older documents receive them
	// together with the earlier additive namespaces, exactly like v13..v17.
	// Every default is inert: web_exposure is read-only, worker_guard/tls_sensor/
	// lpe_guard are disabled and edge_proxy binds nothing.
	if settings.WebExposure == nil {
		webExposure := webExposureDefaults(defaults)
		settings.WebExposure = &webExposure
		if settings.FabricVersion >= 17 {
			settings.Migrations = append(settings.Migrations, webExposureMigrationNote)
		}
	}
	if settings.WorkerGuard == nil {
		workerGuard := workerGuardDefaults(defaults)
		settings.WorkerGuard = &workerGuard
		if settings.FabricVersion >= 17 {
			settings.Migrations = append(settings.Migrations, workerGuardMigrationNote)
		}
	}
	if settings.TLSSensor == nil {
		tlsSensor := tlsSensorDefaults(defaults)
		settings.TLSSensor = &tlsSensor
		if settings.FabricVersion >= 17 {
			settings.Migrations = append(settings.Migrations, tlsSensorMigrationNote)
		}
	}
	if settings.LPEGuard == nil {
		lpeGuard := lpeGuardDefaults(defaults)
		settings.LPEGuard = &lpeGuard
		if settings.FabricVersion >= 17 {
			settings.Migrations = append(settings.Migrations, lpeGuardMigrationNote)
		}
	}
	if settings.EdgeProxy == nil {
		edgeProxy := edgeProxyDefaults(defaults)
		settings.EdgeProxy = &edgeProxy
		if settings.FabricVersion >= 17 {
			settings.Migrations = append(settings.Migrations, edgeProxyMigrationNote)
		}
	}
	// v10 narrows one feed action.
	//
	// FireHOL Level 1 is an aggregate of networks already observed attacking or abusing
	// hosts, and upstream documents it as safe to block. Correlating it meant the engine
	// recorded known-bad sources and then let them through. The compiled-in default was
	// corrected, but the default only reaches a fresh installation: an existing document
	// carries the old value forever, which is why the correction never took effect.
	//
	// Exactly one entry is touched, matched by ID, and it is only raised - never lowered -
	// so a deployment that had already escalated the feed by hand is left alone.
	//
	// The caller records the change in the evidence ledger. An operator setting is being
	// changed on the operator's behalf, and that is not something to do silently.
	if settings.FabricVersion < 10 && settings.ThreatIntel != nil {
		for index := range settings.ThreatIntel.Feeds {
			feed := &settings.ThreatIntel.Feeds[index]
			if feed.ID != fireholLevelOneFeedID {
				continue
			}
			if feed.Action != string(FeedActionBlock) {
				feed.Action = string(FeedActionBlock)
				settings.Migrations = append(settings.Migrations,
					"feed "+fireholLevelOneFeedID+": action raised to BLOCK (upstream documents this list as safe to block; correlating it recorded known-bad sources and then admitted them)")
			}
		}
	}
	// v11 relocates the shipped decoys from host paths the unprivileged control
	// plane can never write into the root-owned canary jail observed by the
	// privileged core. Only the two shipped defaults are moved; operator-defined
	// canaries are left untouched and skipped visibly by the apply path when they
	// are outside the jail (no silent re-pointing).
	if settings.FabricVersion < 11 && settings.Hardening != nil {
		for index := range settings.Hardening.Deception.Canaries {
			canary := &settings.Hardening.Deception.Canaries[index]
			relocated := ""
			switch canary.Path {
			case "/tmp/.aws_credentials":
				relocated = "/var/lib/vgt/gedefense/canaries/.aws_credentials"
			case "/etc/shadow.bak":
				relocated = "/var/lib/vgt/gedefense/canaries/shadow.bak"
			default:
				continue
			}
			canary.Path = relocated
			canary.OwnerUID = 0
			canary.FileMode = 0o600
			settings.Migrations = append(settings.Migrations,
				"deception canary relocated into the privileged canary root: "+relocated)
		}
	}
	// v12: the shipped singleton L7 enforcement scope ("only the PHP upload-progress
	// rule may block") turned every other built-in signature into an alert-only rule.
	// That is not full application defense: SQLi, XSS, traversal, command injection and
	// the other high-score rules were visible but could never block. The migration
	// widens only the unchanged legacy singleton; an operator who narrowed or widened
	// the list deliberately is left alone.
	if settings.FabricVersion < 12 && settings.L7 != nil {
		legacy := settings.L7.EnforceRules
		if len(legacy) == 1 && strings.TrimSpace(legacy[0]) == "L7.PHP.SESSION_UPLOAD_PROGRESS" {
			settings.L7.EnforceRules = nil
			settings.Migrations = append(settings.Migrations,
				"L7 enforcement scope expanded from the legacy PHP upload-progress singleton to every built-in rule with block eligibility (empty list = all non-alert-only rules); narrow it again in Observe/Degraded if required")
		}
	}
	settings.FabricVersion = fabricSettingsVersion
	return true
}

func systemDefaults(defaults RuntimeSettings) SystemFabricSettings {
	if defaults.System != nil {
		return *defaults.System
	}
	return defaultSystemFabricSettings(Config{})
}

func forensicsDefaults(defaults RuntimeSettings) ForensicsFabricSettings {
	if defaults.Forensics != nil {
		return *defaults.Forensics
	}
	return defaultForensicsFabricSettings()
}

func bootTrustDefaults(defaults RuntimeSettings) BootTrustFabricSettings {
	if defaults.BootTrust != nil {
		return *defaults.BootTrust
	}
	return defaultBootTrustFabricSettings()
}

func policyTrustDefaults(defaults RuntimeSettings) PolicyTrustFabricSettings {
	if defaults.PolicyTrust != nil {
		return *defaults.PolicyTrust
	}
	return defaultPolicyTrustFabricSettings()
}

func integrityDefaults(defaults RuntimeSettings) IntegrityFabricSettings {
	if defaults.Integrity != nil {
		return *defaults.Integrity
	}
	return defaultIntegrityFabricSettings(Config{})
}

func hardeningDefaults(defaults RuntimeSettings) HardeningFabricSettings {
	if defaults.Hardening != nil {
		return *defaults.Hardening
	}
	return defaultHardeningFabricSettings(Config{}, "")
}

func threatIntelDefaults(defaults RuntimeSettings) ThreatIntelFabricSettings {
	if defaults.ThreatIntel != nil {
		return *defaults.ThreatIntel
	}
	return defaultThreatIntelFabricSettings(FeedConfig{}, DefaultThreatFeedSources)
}

func l7Defaults(defaults RuntimeSettings) L7FabricSettings {
	if defaults.L7 != nil {
		return *defaults.L7
	}
	return L7FabricSettings{TLSUnknownFingerprint: "allow", TLSUnknownFingerprintScore: 35, Rules: []L7RuleOverride{}}
}

func (s *SettingsStore) mac(settings RuntimeSettings) ([]byte, error) {
	// Preserve nil versus empty collections in the authenticated wire representation.
	canonical := settings
	canonical.UpdatedAt = canonical.UpdatedAt.UTC()
	data, err := json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(runtimeSettingsSchema))
	mac.Write([]byte{0})
	mac.Write(data)
	return mac.Sum(nil), nil
}

func (s *SettingsStore) macHistory(history []RuntimeSettings) ([]byte, error) {
	canonical := make([]RuntimeSettings, 0, len(history))
	for _, entry := range history {
		copy := entry
		copy.UpdatedAt = copy.UpdatedAt.UTC()
		canonical = append(canonical, copy)
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(runtimeSettingsSchema))
	mac.Write([]byte{0})
	mac.Write([]byte("history"))
	mac.Write([]byte{0})
	mac.Write(data)
	return mac.Sum(nil), nil
}

func (s *SettingsStore) persistLocked(settings RuntimeSettings) error {
	if err := validateRuntimeSettings(&settings); err != nil {
		return err
	}
	mac, err := s.mac(settings)
	if err != nil {
		return err
	}
	historyMAC, err := s.macHistory(s.history)
	if err != nil {
		return err
	}
	document := runtimeSettingsEnvelope{Schema: runtimeSettingsSchema, Settings: settings, MAC: hex.EncodeToString(mac), History: cloneRuntimeSettingsHistory(s.history), HistoryMAC: hex.EncodeToString(historyMAC)}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if s.crypto != nil {
		data, err = s.crypto.Encrypt(s.path, "runtime-settings", 0, data)
		if err != nil {
			return err
		}
		data = append(data, '\n')
	}
	if err := atomicWriteFile(s.path, data, 0o600); err != nil {
		return err
	}
	s.current = cloneRuntimeSettings(settings)
	return nil
}
