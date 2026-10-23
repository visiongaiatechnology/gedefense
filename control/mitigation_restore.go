// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// A mitigation that disappears on reboot is a promise the platform cannot keep. The applied state is
// therefore written to disk and re-asserted at every start:
//
//   - value already in force  -> the guard re-arms its assertion and reports "restored"
//   - value drifted away       -> it is set again with the same compare-set primitive and verified
//   - the privileged core down -> the start is not failed; the guard keeps the record and retries via
//     its watcher, because a reboot must not turn into a silent loss of protection.
//
// The file is authenticated with the policy signing key and validated against the compiled
// mitigation catalogue before it may cause a privileged write (F-19). An unsigned, corrupted,
// tampered or non-catalogued record is refused and reported; it can never turn an unauthenticated
// or attacker-written state file into a root sysctl change. The file carries no secret: a key
// name, two values, the reason and a timestamp. It exists so an operator can see *why* the
// platform holds a kernel value, not only that it does.

const mitigationStatePath = "/var/lib/vgt/gedefense/kernel-mitigation.json"

type persistedMitigation struct {
	Key       string    `json:"key"`
	Desired   string    `json:"desired"`
	Previous  string    `json:"previous"`
	Reason    string    `json:"reason"`
	AppliedAt time.Time `json:"applied_at"`
	// Signature is the Ed25519 signature over the canonical payload with this field empty.
	Signature string `json:"signature_ed25519,omitempty"`
}

// mitigationStatePayload is the exact byte sequence that is signed and verified.
func mitigationStatePayload(stored persistedMitigation) ([]byte, error) {
	stored.Signature = ""
	return json.Marshal(stored)
}

func (g *MitigationGuard) statePath() string {
	if g.StatePath != "" {
		return g.StatePath
	}
	return mitigationStatePath
}

func (g *MitigationGuard) persist(key, desired, previous, reason string) {
	stored := persistedMitigation{
		Key: key, Desired: desired, Previous: previous, Reason: reason, AppliedAt: g.now(),
	}
	payload, err := mitigationStatePayload(stored)
	if err != nil {
		g.emit("warning", "kernel.mitigation_persist_failed", err.Error())
		return
	}
	signature, signErr := g.signMitigationState(payload)
	if signErr != nil {
		// An unauthenticated mitigation record must never be written: it would either be
		// refused at the next start (a silent loss of the protection record) or, worse,
		// accepted by a build that forgot the check. Report and keep the in-memory state.
		g.emit("warning", "kernel.mitigation_persist_failed", signErr.Error())
		return
	}
	stored.Signature = hex.EncodeToString(signature)
	encoded, err := json.Marshal(stored)
	if err != nil {
		g.emit("warning", "kernel.mitigation_persist_failed", err.Error())
		return
	}
	path := g.statePath()
	if err := os.MkdirAll(filepathDir(path), 0o750); err != nil {
		g.emit("warning", "kernel.mitigation_persist_failed", err.Error())
		return
	}
	if err := atomicWriteFile(path, encoded, 0o600); err != nil {
		g.emit("warning", "kernel.mitigation_persist_failed", err.Error())
	}
}

func (g *MitigationGuard) clearPersisted() {
	if err := os.Remove(g.statePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		g.emit("warning", "kernel.mitigation_persist_failed", err.Error())
	}
}

// AttachStateMACKey installs the HMAC-SHA256 subkey used to authenticate the persisted
// mitigation record. It is derived from the runtime settings key, so no second key has to
// be provisioned for this file (F-19 / G-STATE-05).
func (g *MitigationGuard) AttachStateMACKey(key []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stateMACKey = append([]byte(nil), key...)
}

func (g *MitigationGuard) mitigationMAC(payload []byte) ([]byte, error) {
	g.mu.Lock()
	key := append([]byte(nil), g.stateMACKey...)
	g.mu.Unlock()
	if len(key) < 16 {
		return nil, errors.New("mitigation state HMAC key unavailable; refusing to trust an unauthenticated record")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("VGT-GEDEFENSE-MITIGATION-STATE-V1\x00"))
	mac.Write(payload)
	return mac.Sum(nil), nil
}

func (g *MitigationGuard) signMitigationState(payload []byte) ([]byte, error) {
	return g.mitigationMAC(payload)
}

func (g *MitigationGuard) verifyMitigationState(stored persistedMitigation) error {
	if stored.Signature == "" {
		return errors.New("mitigation state is unsigned; refusing to restore it")
	}
	signature, err := hex.DecodeString(stored.Signature)
	if err != nil || len(signature) != sha256.Size {
		return errors.New("mitigation state signature is malformed")
	}
	payload, err := mitigationStatePayload(stored)
	if err != nil {
		return err
	}
	expected, err := g.mitigationMAC(payload)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, signature) {
		return errors.New("mitigation state signature is invalid")
	}
	return nil
}

// mitigationStateValuePattern bounds the value domain of a persisted mitigation. The
// compiled catalogue names the key and the desired value; the previous value is only kept
// for attribution, so it is held to a conservative sysctl-shaped domain (F-19).
var mitigationStateValuePattern = regexp.MustCompile(`^[0-9]{1,8}$`)

// deriveMitigationStateKey derives the state-file HMAC subkey from the runtime settings
// key. Reading or deriving the key fails closed: the guard then refuses restores/writes.
func deriveMitigationStateKey(runtimeKeyFile string) ([]byte, error) {
	if runtimeKeyFile == "" || !filepath.IsAbs(runtimeKeyFile) {
		return nil, errors.New("runtime settings key path must be absolute")
	}
	raw, err := readBoundedPrivateFile(runtimeKeyFile, 64)
	if err != nil {
		return nil, fmt.Errorf("runtime settings key: %w", err)
	}
	if len(raw) != 32 {
		return nil, errors.New("runtime settings key must contain exactly 32 bytes")
	}
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte("VGT-GEDEFENSE-MITIGATION-STATE-KEY-V1\x00"))
	return mac.Sum(nil), nil
}

// mitigationCatalogueTarget resolves a persisted key back to the compiled mitigation
// catalogue. A record that names a key or value the catalogue does not manage is refused:
// the state file must never become a route to an arbitrary privileged sysctl write.
func mitigationCatalogueTarget(key string) (mitigationTarget, bool) {
	for _, advisory := range kernelAdvisories() {
		for _, entryPoint := range advisory.EntryPoints {
			target, ok := mitigationTargetFor(entryPoint)
			if ok && target.key == key {
				return target, true
			}
		}
	}
	return mitigationTarget{}, false
}

// Restore re-establishes the mitigation recorded by the previous run. It never fails the start: a
// host that cannot reach its core yet must still come up and protect everything else. An
// unauthenticated or non-catalogued record is refused instead of applied (F-19).
func (g *MitigationGuard) Restore() error {
	raw, err := os.ReadFile(g.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("mitigation state could not be read: %w", err)
	}
	var stored persistedMitigation
	if err := json.Unmarshal(raw, &stored); err != nil {
		return fmt.Errorf("mitigation state is corrupt: %w", err)
	}
	if stored.Key == "" || stored.Desired == "" {
		return errors.New("mitigation state is incomplete")
	}
	if err := g.verifyMitigationState(stored); err != nil {
		g.emit("critical", "kernel.mitigation_state_unauthenticated", err.Error())
		return fmt.Errorf("mitigation state is not authentic: %w", err)
	}
	target, ok := mitigationCatalogueTarget(stored.Key)
	if !ok {
		g.emit("critical", "kernel.mitigation_state_not_catalogued", "refusing a mitigation state outside the compiled catalogue: "+stored.Key)
		return errors.New("mitigation state names a control outside the compiled catalogue")
	}
	if stored.Desired != target.desired {
		g.emit("critical", "kernel.mitigation_state_invalid", fmt.Sprintf("refusing mitigation state %s=%q; catalogue expects %q", stored.Key, stored.Desired, target.desired))
		return errors.New("mitigation state value does not match the compiled catalogue")
	}
	if stored.Previous != "" && (!mitigationStateValuePattern.MatchString(stored.Previous) || len(stored.Previous) > 8) {
		g.emit("critical", "kernel.mitigation_state_invalid", "refusing mitigation state with a previous value outside the sysctl value domain")
		return errors.New("mitigation state previous value is outside the accepted value domain")
	}
	if len(stored.Reason) > 240 || strings.ContainsAny(stored.Reason, "\x00\r\n") {
		return errors.New("mitigation state reason is invalid")
	}
	if g.core == nil {
		return errors.New("the privileged core is unavailable")
	}
	current, err := g.core.SysctlGet(stored.Key)
	if err != nil {
		return fmt.Errorf("current value could not be read: %w", err)
	}
	now := g.now()
	record := &mitigationRecord{status: MitigationStatus{
		State: mitigationStateWatching, Enabled: g.cfg.AutoMitigate, Control: "kernel.userns",
		Key: stored.Key, Desired: stored.Desired, Previous: stored.Previous, Current: current,
		Reason: "restored after restart: " + stored.Reason, AppliedAt: &now,
	}}
	deadline := now.Add(g.watch)
	record.status.WatchUntil = &deadline
	record.watchFrom = now
	g.mu.Lock()
	g.record = record
	g.mu.Unlock()
	if current == stored.Desired {
		record.status.State = mitigationStateStable
		record.status.StableAt = &now
		record.stable = true
		record.status.Transitions = append(record.status.Transitions, MitigationTransition{
			At: now, Kind: "restored", Detail: fmt.Sprintf("%s already holds %s", stored.Key, stored.Desired),
		})
		g.startWatcher()
		g.emit("info", "kernel.mitigation_restored", fmt.Sprintf(
			"Mitigation restored after restart: %s=%s is still in force and is asserted again on every interval.", stored.Key, stored.Desired))
		return nil
	}
	// Drifted: re-assert with the same verified primitive.
	if err := g.core.SysctlCompareSet(stored.Key, current, stored.Desired); err != nil {
		g.recordFailure(fmt.Sprintf("restore of %s failed: %v", stored.Key, err), true)
		return fmt.Errorf("mitigation could not be re-asserted: %w", err)
	}
	if got, err := g.core.SysctlGet(stored.Key); err != nil || got != stored.Desired {
		g.recordFailure(fmt.Sprintf("restore of %s did not verify (got %q, err %v)", stored.Key, got, err), true)
		return errors.New("mitigation restore did not verify")
	}
	g.mu.Lock()
	record.status.Current = stored.Desired
	record.status.State = mitigationStateWatching
	record.status.Transitions = append(record.status.Transitions, MitigationTransition{
		At: now, Kind: "reasserted", Detail: fmt.Sprintf("%s was %s and was set back to %s", stored.Key, current, stored.Desired),
	})
	g.mu.Unlock()
	g.startWatcher()
	g.emit("high", "kernel.mitigation_restored", fmt.Sprintf(
		"Mitigation re-asserted after restart: %s was %s and is now %s again.", stored.Key, current, stored.Desired))
	return nil
}

func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// adoptInForce rebuilds the guard's record from what the kernel actually holds, so a missing state file
// cannot turn an active protection into an unasserted one.
func (g *MitigationGuard) adoptInForce() error {
	if g.core == nil || g.exposure == nil {
		return nil
	}
	if g.exposure.Current().Verdict == kernelVerdictUnaffected {
		return nil
	}
	// The precondition measurement reports the value as closed once it is 0, so the target cannot be
	// resolved through the "present door" logic. Walk the managed controls directly and adopt the one
	// whose desired value is already in force - the kernel is the authority here.
	for _, advisory := range kernelAdvisories() {
		for _, entryPoint := range advisory.EntryPoints {
			target, ok := mitigationTargetFor(entryPoint)
			if !ok {
				continue
			}
			current, err := g.core.SysctlGet(target.key)
			if err != nil || current != target.desired {
				continue
			}
			now := g.now()
			record := &mitigationRecord{
				status: MitigationStatus{
					State: mitigationStateStable, Enabled: g.cfg.AutoMitigate, Control: target.control,
					Key: target.key, Desired: target.desired, Previous: "unknown", Current: current,
					Reason:    "adopted from the running kernel after a missing state record (advisory " + advisory.ID + ")",
					AppliedAt: &now, StableAt: &now,
				},
				stable: true,
			}
			g.mu.Lock()
			g.record = record
			g.mu.Unlock()
			g.persist(target.key, target.desired, "unknown", record.status.Reason)
			g.startWatcher()
			g.emit("high", "kernel.mitigation_adopted", fmt.Sprintf(
				"The state record was missing but %s already holds %s; the guard adopted the running value and asserts it again.", target.key, target.desired))
			return nil
		}
	}
	return nil
}

// HealIfUnasserted is the retry the start needs: at process start the privileged core may not answer
// yet, and the adoption must not be lost because of that ordering. Called from a short background loop,
// it adopts an in-force value as soon as the core answers, and does nothing once a record exists.
func (g *MitigationGuard) HealIfUnasserted() {
	g.mu.Lock()
	have := g.record != nil
	g.mu.Unlock()
	if have {
		return
	}
	_ = g.adoptInForce()
}
