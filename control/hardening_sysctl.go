// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

type SysctlProfile struct {
	Name   string            `json:"name"`
	Values map[string]string `json:"values"`
}

type SysctlTransactionApplier struct {
	core     SysctlCore
	profiles map[string]SysctlProfile
}

type SysctlCore interface {
	SysctlGet(key string) (string, error)
	SysctlCompareSet(key, expected, desired string) error
	HardeningProfileState() (string, error)
	HardeningProfileCompareSet(expected, desired string) error
}

func NewSysctlTransactionApplier(core SysctlCore) *SysctlTransactionApplier {
	return &SysctlTransactionApplier{
		core: core,
		profiles: map[string]SysctlProfile{
			"linux-server-balanced": {
				Name: "linux-server-balanced",
				Values: map[string]string{
					"kernel.kptr_restrict":                   "2",
					"kernel.dmesg_restrict":                  "1",
					"kernel.randomize_va_space":              "2",
					"fs.protected_fifos":                     "2",
					"fs.protected_regular":                   "2",
					"fs.suid_dumpable":                       "0",
					"net.ipv4.tcp_syncookies":                "1",
					"net.ipv4.conf.all.accept_redirects":     "0",
					"net.ipv4.conf.default.accept_redirects": "0",
					"net.ipv4.conf.all.send_redirects":       "0",
					"net.ipv4.conf.default.send_redirects":   "0",
					"net.ipv6.conf.all.accept_redirects":     "0",
					"net.ipv6.conf.default.accept_redirects": "0",
				},
			},
			"gaiaos-workstation-strict": {
				Name: "gaiaos-workstation-strict",
				Values: map[string]string{
					"kernel.kptr_restrict":                   "2",
					"kernel.dmesg_restrict":                  "1",
					"kernel.randomize_va_space":              "2",
					"kernel.yama.ptrace_scope":               "2",
					"kernel.unprivileged_bpf_disabled":       "1",
					"fs.protected_fifos":                     "2",
					"fs.protected_regular":                   "2",
					"fs.suid_dumpable":                       "0",
					"net.ipv4.tcp_syncookies":                "1",
					"net.ipv4.conf.all.accept_redirects":     "0",
					"net.ipv4.conf.default.accept_redirects": "0",
					"net.ipv4.conf.all.send_redirects":       "0",
					"net.ipv4.conf.default.send_redirects":   "0",
					"net.ipv6.conf.all.accept_redirects":     "0",
					"net.ipv6.conf.default.accept_redirects": "0",
				},
			},
		},
	}
}

func (a *SysctlTransactionApplier) Type() string {
	return "hardening.sysctl-profile"
}

func (a *SysctlTransactionApplier) Preview(
	payload json.RawMessage,
) (json.RawMessage, json.RawMessage, error) {
	if a.core == nil {
		return nil, nil, errors.New("privileged core is unavailable")
	}
	profileName, err := decodeSysctlProfileRequest(payload)
	if err != nil {
		return nil, nil, err
	}
	profile, exists := a.profiles[profileName]
	if !exists {
		return nil, nil, errors.New("hardening profile is not supported")
	}
	before := make(map[string]string, len(profile.Values))
	for _, key := range sortedJSONMapKeys(profile.Values) {
		value, err := a.core.SysctlGet(key)
		if err != nil {
			return nil, nil, fmt.Errorf("hardening pre-state unavailable for %s: %w", key, err)
		}
		before[key] = value
	}
	persistent, err := a.core.HardeningProfileState()
	if err != nil {
		return nil, nil, fmt.Errorf("persistent hardening pre-state unavailable: %w", err)
	}
	plan, err := json.Marshal(profile)
	if err != nil {
		return nil, nil, err
	}
	captured, err := json.Marshal(map[string]any{
		"profile":    profile.Name,
		"values":     before,
		"persistent": persistent,
	})
	return plan, captured, err
}

func decodeSysctlProfileRequest(payload json.RawMessage) (string, error) {
	var request struct {
		Profile string `json:"profile"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return "", errors.New("invalid hardening profile request")
	}
	if request.Profile == "" || len(request.Profile) > 64 {
		return "", errors.New("hardening profile is required")
	}
	return request.Profile, nil
}

func decodeSysctlState(raw json.RawMessage) (string, map[string]string, string, error) {
	var state struct {
		Profile    string            `json:"profile"`
		Values     map[string]string `json:"values"`
		Persistent string            `json:"persistent"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || state.Profile == "" || len(state.Values) == 0 {
		return "", nil, "", errors.New("hardening transaction state is malformed")
	}
	for key, value := range state.Values {
		if !validSysctlKey(key) || !validSysctlToken(value) {
			return "", nil, "", errors.New("hardening transaction state contains an invalid value")
		}
	}
	if !validHardeningState(state.Persistent) {
		return "", nil, "", errors.New("hardening transaction persistence state is invalid")
	}
	return state.Profile, state.Values, state.Persistent, nil
}

func decodeSysctlPlan(raw json.RawMessage) (SysctlProfile, error) {
	var profile SysctlProfile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil || profile.Name == "" || len(profile.Values) == 0 {
		return SysctlProfile{}, errors.New("hardening transaction plan is malformed")
	}
	for key, value := range profile.Values {
		if !validSysctlKey(key) || !validSysctlToken(value) {
			return SysctlProfile{}, errors.New("hardening transaction plan contains an invalid value")
		}
	}
	return profile, nil
}

func (a *SysctlTransactionApplier) Apply(
	planRaw json.RawMessage,
	beforeRaw json.RawMessage,
) (json.RawMessage, error) {
	profile, err := decodeSysctlPlan(planRaw)
	if err != nil {
		return nil, err
	}
	beforeProfile, before, beforePersistent, err := decodeSysctlState(beforeRaw)
	if err != nil || beforeProfile != profile.Name {
		return nil, errors.New("hardening pre-state does not match the plan")
	}
	applied := make(map[string]string, len(profile.Values))
	keys := sortedJSONMapKeys(profile.Values)
	for _, key := range keys {
		expected, exists := before[key]
		if !exists {
			return nil, errors.New("hardening pre-state is incomplete")
		}
		desired := profile.Values[key]
		current, err := a.core.SysctlGet(key)
		if err != nil {
			rollbackErr := a.restore(applied, before)
			return nil, errors.Join(err, rollbackErr)
		}
		if current != expected && current != desired {
			rollbackErr := a.restore(applied, before)
			return nil, errors.Join(
				fmt.Errorf("hardening precondition failed for %s", key),
				rollbackErr,
			)
		}
		if current != desired {
			if err := a.core.SysctlCompareSet(key, expected, desired); err != nil {
				rollbackErr := a.restore(applied, before)
				if rollbackErr != nil {
					return nil, &RecoveryRequiredError{
						Stage: "apply_rollback", Err: errors.Join(err, rollbackErr),
					}
				}
				return nil, err
			}
		}
		applied[key] = desired
	}
	if err := a.core.HardeningProfileCompareSet(beforePersistent, profile.Name); err != nil {
		rollbackErr := a.restore(applied, before)
		if rollbackErr != nil {
			return nil, &RecoveryRequiredError{
				Stage: "persistence_apply_rollback", Err: errors.Join(err, rollbackErr),
			}
		}
		return nil, err
	}
	return json.Marshal(map[string]any{
		"profile":    profile.Name,
		"values":     applied,
		"persistent": profile.Name,
	})
}

func (a *SysctlTransactionApplier) Verify(
	planRaw json.RawMessage,
	afterRaw json.RawMessage,
) error {
	profile, err := decodeSysctlPlan(planRaw)
	if err != nil {
		return err
	}
	afterProfile, after, afterPersistent, err := decodeSysctlState(afterRaw)
	if err != nil || afterProfile != profile.Name || afterPersistent != profile.Name {
		return errors.New("hardening post-state does not match the plan")
	}
	for _, key := range sortedJSONMapKeys(profile.Values) {
		current, err := a.core.SysctlGet(key)
		if err != nil || current != profile.Values[key] || after[key] != current {
			return fmt.Errorf("hardening post-state verification failed for %s", key)
		}
	}
	persistent, err := a.core.HardeningProfileState()
	if err != nil || persistent != profile.Name {
		return errors.New("persistent hardening post-state verification failed")
	}
	return nil
}

func (a *SysctlTransactionApplier) Reverse(
	beforeRaw json.RawMessage,
	afterRaw json.RawMessage,
) error {
	beforeProfile, before, beforePersistent, err := decodeSysctlState(beforeRaw)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(afterRaw)) == 0 {
		profile, exists := a.profiles[beforeProfile]
		if !exists {
			return errors.New("hardening recovery profile is unavailable")
		}
		currentPersistent, persistentErr := a.core.HardeningProfileState()
		if persistentErr != nil {
			return persistentErr
		}
		if currentPersistent != beforePersistent {
			if err := a.core.HardeningProfileCompareSet(currentPersistent, beforePersistent); err != nil {
				return err
			}
		}
		return a.restore(profile.Values, before)
	}
	afterProfile, after, afterPersistent, err := decodeSysctlState(afterRaw)
	if err != nil || afterProfile != beforeProfile {
		return errors.New("hardening reverse-state does not match")
	}
	if err := a.core.HardeningProfileCompareSet(afterPersistent, beforePersistent); err != nil {
		return err
	}
	if err := a.restore(after, before); err != nil {
		persistenceRollbackErr := a.core.HardeningProfileCompareSet(beforePersistent, afterPersistent)
		return &RecoveryRequiredError{
			Stage: "reverse_runtime",
			Err:   errors.Join(err, persistenceRollbackErr),
		}
	}
	return nil
}

func (a *SysctlTransactionApplier) restore(
	current map[string]string,
	before map[string]string,
) error {
	keys := sortedJSONMapKeys(current)
	var result error
	for index := len(keys) - 1; index >= 0; index-- {
		key := keys[index]
		expected := current[key]
		desired, exists := before[key]
		if !exists {
			result = errors.Join(result, fmt.Errorf("missing reverse value for %s", key))
			continue
		}
		actual, readErr := a.core.SysctlGet(key)
		if readErr != nil {
			result = errors.Join(result, fmt.Errorf("read reverse state %s: %w", key, readErr))
			continue
		}
		if actual == desired {
			continue
		}
		if actual != expected {
			result = errors.Join(result, fmt.Errorf("reverse precondition failed for %s", key))
			continue
		}
		if err := a.core.SysctlCompareSet(key, expected, desired); err != nil {
			result = errors.Join(result, fmt.Errorf("reverse %s: %w", key, err))
		}
	}
	return result
}
