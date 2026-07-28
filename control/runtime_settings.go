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
	"regexp"
	"sort"
	"strings"
	"sync"
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

type CustomRule struct {
	ID       string `json:"id"`
	Enabled  bool   `json:"enabled"`
	Category string `json:"category"`
	Summary  string `json:"summary"`
	Pattern  string `json:"pattern"`
	Score    int    `json:"score"`
}

type RuntimeSettings struct {
	Revision               uint64       `json:"revision"`
	UpdatedAt              time.Time    `json:"updated_at"`
	XDREnabled             bool         `json:"xdr_enabled"`
	NetworkSensorEnabled   bool         `json:"network_sensor_enabled"`
	BehaviorEnabled        bool         `json:"behavior_enabled"`
	FeedsEnabled           bool         `json:"feeds_enabled"`
	AutoFeedSync           bool         `json:"auto_feed_sync"`
	AutoDegrade            bool         `json:"auto_degrade"`
	ScanIntervalMillis     int          `json:"scan_interval_millis"`
	NetworkIntervalSeconds int          `json:"network_interval_seconds"`
	AlertScore             int          `json:"alert_score"`
	ContainScore           int          `json:"contain_score"`
	KillScore              int          `json:"kill_score"`
	ManagementAllowlist    []string     `json:"management_allowlist"`
	EnabledRuleModules     []string     `json:"enabled_rule_modules,omitempty"`
	CustomRules            []CustomRule `json:"custom_rules,omitempty"`
}

type runtimeSettingsEnvelope struct {
	Schema   string          `json:"schema"`
	Settings RuntimeSettings `json:"settings"`
	MAC      string          `json:"mac"`
}

type SettingsStore struct {
	mu      sync.RWMutex
	path    string
	key     []byte
	crypto  *StorageCipher
	current RuntimeSettings
}

func defaultRuntimeSettings(cfg Config) RuntimeSettings {
	return RuntimeSettings{
		Revision:               1,
		UpdatedAt:              time.Now().UTC(),
		XDREnabled:             cfg.XDR.Enabled,
		NetworkSensorEnabled:   true,
		BehaviorEnabled:        cfg.XDR.BehaviorEnabled,
		FeedsEnabled:           cfg.Feeds.Enabled,
		AutoFeedSync:           false,
		AutoDegrade:            cfg.Release.AutoDegrade,
		ScanIntervalMillis:     cfg.XDR.ScanIntervalMillis,
		NetworkIntervalSeconds: cfg.XDR.NetworkIntervalSeconds,
		AlertScore:             cfg.XDR.AlertScore,
		ContainScore:           cfg.XDR.ContainScore,
		KillScore:              cfg.XDR.KillScore,
		ManagementAllowlist:    append(make([]string, 0, len(cfg.Defense.Allowlist)), cfg.Defense.Allowlist...),
		EnabledRuleModules:     append([]string(nil), supportedRuleModules...),
		CustomRules:            []CustomRule{},
	}
}

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
	s := &SettingsStore{path: path, key: key, crypto: storage, current: defaultRuntimeSettings(cfg)}
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
		data, legacy, err = s.crypto.Decrypt(s.path, "runtime-settings", data, nil)
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
	if err := validateRuntimeSettings(&document.Settings); err != nil {
		return fmt.Errorf("runtime settings validation: %w", err)
	}
	expected, err := s.mac(document.Settings)
	if err != nil {
		return err
	}
	provided, err := hex.DecodeString(document.MAC)
	if err != nil || !hmac.Equal(expected, provided) {
		return errors.New("runtime settings authentication failed")
	}
	s.current = cloneRuntimeSettings(document.Settings)
	if legacy && s.crypto != nil {
		if err := s.persistLocked(s.current); err != nil {
			return fmt.Errorf("runtime settings migration: %w", err)
		}
	}
	return nil
}

func cloneRuntimeSettings(in RuntimeSettings) RuntimeSettings {
	out := in
	out.ManagementAllowlist = append(make([]string, 0, len(in.ManagementAllowlist)), in.ManagementAllowlist...)
	if in.EnabledRuleModules != nil {
		out.EnabledRuleModules = append([]string{}, in.EnabledRuleModules...)
	}
	if in.CustomRules != nil {
		out.CustomRules = append([]CustomRule{}, in.CustomRules...)
	}
	return out
}

func validateRuntimeSettings(settings *RuntimeSettings) error {
	if settings.ScanIntervalMillis < 100 || settings.ScanIntervalMillis > 60000 {
		return errors.New("scan interval must be between 100 and 60000 milliseconds")
	}
	if settings.NetworkIntervalSeconds < 1 || settings.NetworkIntervalSeconds > 300 {
		return errors.New("network interval must be between 1 and 300 seconds")
	}
	if settings.AlertScore < 1 || settings.KillScore > 250 || !(settings.AlertScore < settings.ContainScore && settings.ContainScore < settings.KillScore) {
		return errors.New("scores must satisfy 1 <= alert < contain < kill <= 250")
	}
	if settings.AutoFeedSync && !settings.FeedsEnabled {
		return errors.New("automatic feed synchronization requires feeds to be enabled")
	}
	if len(settings.ManagementAllowlist) > 1024 {
		return errors.New("management allowlist exceeds 1024 entries")
	}
	seen := make(map[string]struct{}, len(settings.ManagementAllowlist))
	normalized := make([]string, 0, len(settings.ManagementAllowlist))
	for _, target := range settings.ManagementAllowlist {
		value, err := normalizeTarget(target)
		if err != nil {
			return fmt.Errorf("management allowlist %q: %w", target, err)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	settings.ManagementAllowlist = normalized
	if len(settings.EnabledRuleModules) > len(supportedRuleModules) {
		return errors.New("enabled rule modules exceed supported module count")
	}
	supported := make(map[string]struct{}, len(supportedRuleModules))
	for _, module := range supportedRuleModules {
		supported[module] = struct{}{}
	}
	if settings.EnabledRuleModules != nil {
		moduleSeen := make(map[string]struct{}, len(settings.EnabledRuleModules))
		modules := make([]string, 0, len(settings.EnabledRuleModules))
		for _, module := range settings.EnabledRuleModules {
			module = strings.ToLower(strings.TrimSpace(module))
			if _, ok := supported[module]; !ok {
				return fmt.Errorf("unsupported rule module %q", module)
			}
			if _, duplicate := moduleSeen[module]; duplicate {
				continue
			}
			moduleSeen[module] = struct{}{}
			modules = append(modules, module)
		}
		sort.Strings(modules)
		settings.EnabledRuleModules = modules
	}
	if len(settings.CustomRules) > 64 {
		return errors.New("custom rule limit of 64 exceeded")
	}
	ruleIDs := make(map[string]struct{}, len(settings.CustomRules))
	for index := range settings.CustomRules {
		rule := &settings.CustomRules[index]
		rule.ID = strings.ToUpper(strings.TrimSpace(rule.ID))
		rule.Category = strings.ToLower(strings.TrimSpace(rule.Category))
		rule.Summary = strings.TrimSpace(rule.Summary)
		if !strings.HasPrefix(rule.ID, "CUSTOM.") || len(rule.ID) > 64 || !protocolFieldValid(rule.ID) {
			return fmt.Errorf("custom rule %d ID must be a protocol-safe CUSTOM.* identifier", index)
		}
		if _, duplicate := ruleIDs[rule.ID]; duplicate {
			return fmt.Errorf("duplicate custom rule ID %q", rule.ID)
		}
		ruleIDs[rule.ID] = struct{}{}
		if len(rule.Category) < 2 || len(rule.Category) > 32 || !protocolFieldValid(rule.Category) {
			return fmt.Errorf("custom rule %s category is invalid", rule.ID)
		}
		if len(rule.Summary) < 3 || len(rule.Summary) > 160 || strings.ContainsAny(rule.Summary, "\r\n\x00") {
			return fmt.Errorf("custom rule %s summary must contain 3-160 single-line characters", rule.ID)
		}
		if len(rule.Pattern) < 1 || len(rule.Pattern) > 512 || strings.TrimSpace(rule.Pattern) == "" || strings.ContainsRune(rule.Pattern, '\x00') {
			return fmt.Errorf("custom rule %s pattern must contain 1-512 characters", rule.ID)
		}
		if rule.Score < 1 || rule.Score > 100 {
			return fmt.Errorf("custom rule %s score must be between 1 and 100", rule.ID)
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("custom rule %s is not valid RE2 syntax: %w", rule.ID, err)
		}
	}
	sort.Slice(settings.CustomRules, func(i, j int) bool {
		return settings.CustomRules[i].ID < settings.CustomRules[j].ID
	})
	return nil
}

func effectiveRuleModules(settings RuntimeSettings) map[string]bool {
	modules := settings.EnabledRuleModules
	if modules == nil {
		modules = supportedRuleModules
	}
	out := make(map[string]bool, len(modules))
	for _, module := range modules {
		out[module] = true
	}
	return out
}

func (s *SettingsStore) mac(settings RuntimeSettings) ([]byte, error) {
	canonical := cloneRuntimeSettings(settings)
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

func (s *SettingsStore) persistLocked(settings RuntimeSettings) error {
	if err := validateRuntimeSettings(&settings); err != nil {
		return err
	}
	mac, err := s.mac(settings)
	if err != nil {
		return err
	}
	document := runtimeSettingsEnvelope{Schema: runtimeSettingsSchema, Settings: settings, MAC: hex.EncodeToString(mac)}
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

func (s *SettingsStore) Get() RuntimeSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRuntimeSettings(s.current)
}

func (s *SettingsStore) Update(next RuntimeSettings) (RuntimeSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateRuntimeSettings(&next); err != nil {
		return cloneRuntimeSettings(s.current), err
	}
	next.Revision = s.current.Revision + 1
	next.UpdatedAt = time.Now().UTC()
	if err := s.persistLocked(next); err != nil {
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
