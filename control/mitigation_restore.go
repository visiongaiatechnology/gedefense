// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
// The file carries no secret: a key name, two values, the reason and a timestamp. It exists so an
// operator can see *why* the platform holds a kernel value, not only that it does.

const mitigationStatePath = "/var/lib/vgt/gedefense/kernel-mitigation.json"

type persistedMitigation struct {
	Key       string    `json:"key"`
	Desired   string    `json:"desired"`
	Previous  string    `json:"previous"`
	Reason    string    `json:"reason"`
	AppliedAt time.Time `json:"applied_at"`
}

func (g *MitigationGuard) statePath() string {
	if g.StatePath != "" {
		return g.StatePath
	}
	return mitigationStatePath
}

func (g *MitigationGuard) persist(key, desired, previous, reason string) {
	payload, err := json.Marshal(persistedMitigation{
		Key: key, Desired: desired, Previous: previous, Reason: reason, AppliedAt: g.now(),
	})
	if err != nil {
		g.emit("warning", "kernel.mitigation_persist_failed", err.Error())
		return
	}
	path := g.statePath()
	if err := os.MkdirAll(filepathDir(path), 0o750); err != nil {
		g.emit("warning", "kernel.mitigation_persist_failed", err.Error())
		return
	}
	if err := atomicWriteFile(path, payload, 0o600); err != nil {
		g.emit("warning", "kernel.mitigation_persist_failed", err.Error())
	}
}

func (g *MitigationGuard) clearPersisted() {
	if err := os.Remove(g.statePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		g.emit("warning", "kernel.mitigation_persist_failed", err.Error())
	}
}

// Restore re-establishes the mitigation recorded by the previous run. It never fails the start: a host
// that cannot reach its core yet must still come up and protect everything else.
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
					Reason: "adopted from the running kernel after a missing state record (advisory " + advisory.ID + ")",
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
