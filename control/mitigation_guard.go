// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// The mitigation guard closes an entry point and proves that closing it did not break the host.
//
// Closing a door costs something: disabling unprivileged user namespaces stops rootless containers,
// bubblewrap sandboxes and anything else that expects to create one. A monitoring plane that flips a
// kernel switch and walks away is therefore not a mitigation, it is a second incident. This guard makes
// the change a bounded experiment with an owner:
//
//	measure -> snapshot the health -> apply -> watch -> revert if the host regresses
//
// Three properties are deliberate and each one is a design decision, not an implementation detail:
//
//  1. **Reversible.** The previous value is captured before the write and restored by the same
//     compare-set primitive, so a revert is as verified as the apply.
//  2. **Bounded.** The watch window is short and finite. A guard that keeps a host in a broken state
//     for hours because it is "still observing" is worse than no guard.
//  3. **Manipulation-evident, not just tamper-loud.** The applied value is re-asserted on every tick.
//     If something outside GeDefense changes it, the guard puts it back and records the drift. If it
//     cannot be re-asserted, the guard reverts to the safe value and says so - it never pretends the
//     door is closed while it is open.
//
// The guard writes nothing into a report path: every transition is an event on the platform's own
// stream, which the evidence ledger signs.

// errMitigationProbeUnavailable marks a probe that cannot observe the host from this process
// (typically a permission boundary on a runtime socket). It is not a regression: treating it as one
// would revert a valid mitigation because the monitor cannot look, not because the host broke.
var errMitigationProbeUnavailable = errors.New("mitigation probe cannot observe the host")

const (
	mitigationStateIdle      = "idle"
	mitigationStateApplying  = "applying"
	mitigationStateWatching  = "watching"
	mitigationStateStable    = "held"
	mitigationStateReverted  = "reverted"
	mitigationStateFailed    = "failed"
	mitigationStateTampered  = "reasserted"
	mitigationStateDisabled  = "disabled"
	mitigationStateRefused   = "refused"
	mitigationMinWatchSecond = 30
)

// mitigationCore is the smallest privileged surface the guard needs. It is exactly the interface the
// transactional sysctl applier already uses, so the guard cannot grow a second way of writing kernel
// state.
type mitigationCore interface {
	SysctlGet(key string) (string, error)
	SysctlCompareSet(key, expected, desired string) error
}

// MitigationProbe is one answer to "is the host still doing its job". A probe must be cheap, read-only
// and independent of the change being made: a probe that the mitigation itself breaks cannot be used
// to prove the mitigation safe.
type MitigationProbe struct {
	Name  string
	Check func(context.Context) error
}

type MitigationTransition struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail"`
}

type MitigationStatus struct {
	State       string                 `json:"state"`
	Enabled     bool                   `json:"enabled"`
	Control     string                 `json:"control,omitempty"`
	Key         string                 `json:"key,omitempty"`
	Desired     string                 `json:"desired,omitempty"`
	Previous    string                 `json:"previous,omitempty"`
	Current     string                 `json:"current,omitempty"`
	Reason      string                 `json:"reason,omitempty"`
	AppliedAt   *time.Time             `json:"applied_at,omitempty"`
	StableAt    *time.Time             `json:"stable_at,omitempty"`
	WatchUntil  *time.Time             `json:"watch_until,omitempty"`
	Failures    int                    `json:"probing_failures"`
	Drift       int                    `json:"drift_corrections"`
	Warnings    []string               `json:"warnings,omitempty"`
	Auxiliary   []AuxiliaryMitigation  `json:"auxiliary,omitempty"`
	Transitions []MitigationTransition `json:"transitions,omitempty"`
}

// AuxiliaryMitigation is a second catalogue control the guard actively re-asserts while it is in
// force. It is not a replacement for the single probation-managed primary record; it closes the
// "both CVEs are active but only one is held by the guard" gap without inventing a second rollback
// state machine for controls that have no host probe of their own.
type AuxiliaryMitigation struct {
	Control   string `json:"control"`
	Key       string `json:"key"`
	Desired   string `json:"desired"`
	Previous  string `json:"previous,omitempty"`
	Current   string `json:"current,omitempty"`
	AdoptedAt string `json:"adopted_at,omitempty"`
}

type mitigationRecord struct {
	status    MitigationStatus
	watchFrom time.Time
	// stable marks the end of the probation window: from here the guard still re-asserts the value
	// (tamper detection) but no longer auto-reverts on a probe failure, because the host has proven it
	// tolerates the change.
	stable bool
}

// MitigationGuard applies one catalogue mitigation and watches the host while it is in force.
type MitigationGuard struct {
	mu        sync.Mutex
	core      mitigationCore
	exposure  *kernelExposureCache
	cfg       AdvisoryConfig
	state     *State
	probes    []MitigationProbe
	now       func() time.Time
	record    *mitigationRecord
	auxiliary []AuxiliaryMitigation
	cancel    context.CancelFunc
	watch     time.Duration
	interval  time.Duration
	// StatePath overrides where the applied mitigation is recorded (tests use a temp dir).
	StatePath string
	// stateMACKey is the HMAC-SHA256 subkey derived from the runtime settings key. It
	// authenticates the persisted mitigation record; a missing key makes a restore fail
	// closed (F-19 / G-STATE-05).
	stateMACKey []byte
}

func NewMitigationGuard(core mitigationCore, exposure *kernelExposureCache, cfg AdvisoryConfig, state *State, probes []MitigationProbe) *MitigationGuard {
	watch := time.Duration(cfg.MitigationWatchSeconds) * time.Second
	if watch < mitigationMinWatchSecond*time.Second {
		watch = 2 * time.Minute
	}
	interval := time.Duration(cfg.MitigationIntervalSeconds) * time.Second
	if interval < 5*time.Second {
		interval = 10 * time.Second
	}
	return &MitigationGuard{
		core: core, exposure: exposure, cfg: cfg, state: state, probes: probes,
		now:      func() time.Time { return time.Now().UTC() },
		watch:    watch,
		interval: interval,
	}
}

// Status reports the current mitigation, including the value the kernel actually holds right now -
// the stored state is never trusted over a fresh read.
func (g *MitigationGuard) Status() MitigationStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.record == nil {
		status := MitigationStatus{State: mitigationStateIdle, Enabled: g.cfg.AutoMitigate}
		status.Auxiliary = append([]AuxiliaryMitigation(nil), g.auxiliary...)
		if g.core != nil {
			for i := range status.Auxiliary {
				if current, err := g.core.SysctlGet(status.Auxiliary[i].Key); err == nil {
					status.Auxiliary[i].Current = current
				}
			}
		}
		return status
	}
	status := g.record.status
	status.Enabled = g.cfg.AutoMitigate
	if g.core != nil && status.Key != "" {
		if current, err := g.core.SysctlGet(status.Key); err == nil {
			status.Current = current
			if status.State == mitigationStateStable || status.State == mitigationStateWatching {
				if current != status.Desired {
					// Report the truth even before the next tick corrects it.
					status.State = mitigationStateTampered
				}
			}
		}
	}
	status.Auxiliary = append([]AuxiliaryMitigation(nil), g.auxiliary...)
	if g.core != nil {
		for i := range status.Auxiliary {
			if current, err := g.core.SysctlGet(status.Auxiliary[i].Key); err == nil {
				status.Auxiliary[i].Current = current
			}
		}
	}
	return status
}

// noteProbeUnobserved makes the visibility limit explicit instead of silently discarding it. It is
// deliberately not a failure: a control-plane process that cannot read a root-owned socket must not
// roll back a valid mitigation. The warning is surfaced in the status/evidence stream.
func (g *MitigationGuard) noteProbeUnobserved(name string, probeErr error) {
	message := fmt.Sprintf("health probe %q returned UNOBSERVED (permission/visibility limit: %v); it was not treated as a host regression", name, probeErr)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.record == nil {
		return
	}
	for _, existing := range g.record.status.Warnings {
		if existing == message {
			return
		}
	}
	g.record.status.Warnings = append(g.record.status.Warnings, message)
	g.record.status.Transitions = append(g.record.status.Transitions, MitigationTransition{At: g.now(), Kind: "probe-unobserved", Detail: message})
	go g.emit("warning", "kernel.mitigation_probe_unobserved", message)
}

// Plan answers what the guard would do without doing it. It is the dry-run an operator uses before
// allowing an automatic change to a production host.
type MitigationPlan struct {
	Applicable bool   `json:"applicable"`
	Reason     string `json:"reason"`
	Control    string `json:"control,omitempty"`
	Key        string `json:"key,omitempty"`
	Current    string `json:"current,omitempty"`
	Desired    string `json:"desired,omitempty"`
	AlreadyIn  bool   `json:"already_in_force"`
	Probes     int    `json:"probes"`
}

func (g *MitigationGuard) Plan() MitigationPlan {
	plan := MitigationPlan{Probes: len(g.probes)}
	target, reason := g.targetLocked()
	if target == nil {
		plan.Reason = reason
		return plan
	}
	plan.Control = target.control
	plan.Key = target.key
	plan.Desired = target.desired
	plan.Applicable = true
	plan.Reason = reason
	if g.core == nil {
		plan.Applicable = false
		plan.Reason = "the privileged core is unavailable"
		return plan
	}
	if current, err := g.core.SysctlGet(plan.Key); err == nil {
		plan.Current = current
		plan.AlreadyIn = current == plan.Desired
	} else {
		plan.Applicable = false
		plan.Reason = "the current value could not be read: " + err.Error()
	}
	return plan
}

type mitigationTarget struct {
	control string
	key     string
	desired string
}

// targetLocked decides whether an automatic mitigation is justified right now. The decision is
// conservative on purpose: only an advisory that is known to affect this build or cannot be excluded,
// only an entry point that is actually reachable, and only a control the catalogue names.
func (g *MitigationGuard) targetLocked() (*mitigationTarget, string) {
	if !g.cfg.Enabled {
		return nil, "kernel advisories are disabled"
	}
	if g.exposure == nil {
		return nil, "no kernel exposure measurement is attached"
	}
	exposure := g.exposure.Current()
	if exposure.Verdict == kernelVerdictUnaffected {
		return nil, "no advisory applies to this kernel build"
	}
	for _, match := range exposure.Advisories {
		if match.Verdict == kernelVerdictUnaffected || match.Reachability == 0 {
			continue
		}
		// Every present door of the advisory is considered, not just the first one: an entry point
		// without a managed switch must not hide the one that has it.
		for _, entryPoint := range match.EntryPoints {
			present := false
			for _, precondition := range exposure.Preconditions {
				if precondition.ID == entryPoint && precondition.Present {
					present = true
					break
				}
			}
			if !present {
				continue
			}
			if target, ok := mitigationTargetFor(entryPoint); ok {
				return &target, fmt.Sprintf("%s needs the %s entry point and this build is %s", match.ID, entryPoint, match.Verdict)
			}
		}
	}
	return nil, "no reachable entry point has a managed control"
}

// mitigationTargetFor maps a door to the managed control that closes it. Only doors with a real switch
// appear here; a mitigation that exists only as advice must not be executed as if it were a control.
func mitigationTargetFor(entryPoint string) (mitigationTarget, bool) {
	switch entryPoint {
	case "user-namespace":
		return mitigationTarget{control: "kernel.userns", key: "kernel.unprivileged_userns_clone", desired: "0"}, true
	case "mptcp-enabled":
		return mitigationTarget{control: "network.mptcp", key: "net.mptcp.enabled", desired: "0"}, true
	}
	return mitigationTarget{}, false
}

// AdoptAuxiliaryTargets closes every other reachable, catalogue-managed entry point while the
// guard is already holding the primary mitigation. It runs at startup (the two CVE-2026-98432 /
// CVE-2026-99999 controls are independent) and the watcher re-asserts the values on every tick.
// An auxiliary control has no probation state of its own: it is a sysctl switch, not a privileged
// host mutation, and the primary record remains the rollback authority.
func (g *MitigationGuard) AdoptAuxiliaryTargets(reason string) error {
	g.mu.Lock()
	if !g.cfg.Enabled || g.exposure == nil || g.core == nil {
		g.mu.Unlock()
		return nil
	}
	exposure := g.exposure.Current()
	primaryKey := ""
	if g.record != nil {
		primaryKey = g.record.status.Key
	}
	g.mu.Unlock()

	adopted := false
	for _, match := range exposure.Advisories {
		if match.Verdict == kernelVerdictUnaffected || match.Reachability == 0 {
			continue
		}
		for _, entryPoint := range match.EntryPoints {
			target, ok := mitigationTargetFor(entryPoint)
			if !ok || target.key == primaryKey {
				continue
			}
			// Adopt every catalogued auxiliary control for a reachable advisory, even when
			// its precondition is already closed: the point is that the guard, not a static
			// sysctl.d file, keeps holding the value across drift and restarts.
			g.mu.Lock()
			before := len(g.auxiliary)
			err := g.adoptAuxiliaryTargetLocked(target, reason)
			after := len(g.auxiliary)
			g.mu.Unlock()
			if err != nil {
				// A missing/unsupported auxiliary sysctl is not a reason to fail the
				// primary mitigation; log the visibility limit and continue.
				log.Printf("kernel mitigation: auxiliary %s not adoptable: %v", target.key, err)
				continue
			}
			if after > before {
				adopted = true
			}
		}
	}
	if adopted {
		g.startWatcher()
	}
	return nil
}

// adoptAuxiliaryTargetLocked adds one target to the guard-held auxiliary set. The caller holds
// g.mu; the privileged read/write is bounded to the same compare-set path as the primary control.
func (g *MitigationGuard) adoptAuxiliaryTargetLocked(target mitigationTarget, reason string) error {
	for _, existing := range g.auxiliary {
		if existing.Key == target.key {
			return nil
		}
	}
	current, err := g.core.SysctlGet(target.key)
	if err != nil {
		return fmt.Errorf("auxiliary mitigation %s could not be read: %w", target.key, err)
	}
	if current != target.desired {
		if err := g.core.SysctlCompareSet(target.key, current, target.desired); err != nil {
			return fmt.Errorf("auxiliary mitigation %s was refused: %w", target.key, err)
		}
	}
	got, err := g.core.SysctlGet(target.key)
	if err != nil || got != target.desired {
		return fmt.Errorf("auxiliary mitigation %s did not verify (got %q, err %v)", target.key, got, err)
	}
	adopted := AuxiliaryMitigation{
		Control: target.control, Key: target.key, Desired: target.desired,
		Previous: current, Current: got, AdoptedAt: g.now().Format(time.RFC3339),
	}
	g.auxiliary = append(g.auxiliary, adopted)
	go g.emit("info", "kernel.mitigation_auxiliary_adopted", fmt.Sprintf(
		"Auxiliary managed control %s=%s is now held and re-asserted by the mitigation guard (was %s; %s)",
		target.key, target.desired, current, reason))
	return nil
}

// assertAuxiliary re-asserts every guard-held auxiliary value outside the primary probation window.
func (g *MitigationGuard) assertAuxiliary() {
	g.mu.Lock()
	aux := append([]AuxiliaryMitigation(nil), g.auxiliary...)
	g.mu.Unlock()
	for i := range aux {
		current, err := g.core.SysctlGet(aux[i].Key)
		if err != nil {
			g.emit("warning", "kernel.mitigation_auxiliary_unreadable", fmt.Sprintf(
				"Auxiliary managed control %s could not be read: %v", aux[i].Key, err))
			continue
		}
		if current != aux[i].Desired {
			if err := g.core.SysctlCompareSet(aux[i].Key, current, aux[i].Desired); err != nil {
				g.emit("high", "kernel.mitigation_auxiliary_drift_failed", fmt.Sprintf(
					"Auxiliary managed control %s drifted to %q and could not be re-asserted: %v", aux[i].Key, current, err))
				continue
			}
			g.emit("high", "kernel.mitigation_auxiliary_drift", fmt.Sprintf(
				"Auxiliary managed control %s was changed outside GeDefense to %q and has been re-asserted to %s",
				aux[i].Key, current, aux[i].Desired))
		}
		g.mu.Lock()
		for j := range g.auxiliary {
			if g.auxiliary[j].Key == aux[i].Key {
				g.auxiliary[j].Current = aux[i].Desired
			}
		}
		g.mu.Unlock()
	}
}

// Apply is the operator's explicit intervention. It changes the value even when the automatic path is
// off, because that is the difference between the platform deciding by itself and an operator deciding:
// the switch only governs autonomy, never the operator's own authority. The probation watch, the
// verification and the rollback still apply, so a manual intervention is as guarded as an automatic one.
func (g *MitigationGuard) Apply(reason string) (MitigationStatus, error) {
	return g.apply(reason, false)
}

// ApplyAutomatic closes the door without an operator in the loop. This is the path that requires
// advisories.auto_mitigate, and it is what the startup goroutine calls.
func (g *MitigationGuard) ApplyAutomatic(reason string) (MitigationStatus, error) {
	return g.apply(reason, true)
}

func (g *MitigationGuard) apply(reason string, automatic bool) (MitigationStatus, error) {
	g.mu.Lock()
	if automatic && !g.cfg.AutoMitigate {
		g.mu.Unlock()
		return g.Status(), errors.New("automatic mitigation is disabled (advisories.auto_mitigate = false)")
	}
	if !g.cfg.Enabled {
		g.mu.Unlock()
		return g.Status(), errors.New("kernel advisories are disabled")
	}
	if g.record != nil && (g.record.status.State == mitigationStateWatching || g.record.status.State == mitigationStateStable) {
		status := g.record.status
		g.mu.Unlock()
		return status, errors.New("a mitigation is already in force")
	}
	target, why := g.targetLocked()
	if target == nil {
		g.mu.Unlock()
		return g.Status(), errors.New(why)
	}
	if g.core == nil {
		g.mu.Unlock()
		return g.Status(), errors.New("the privileged core is unavailable")
	}
	current, err := g.core.SysctlGet(target.key)
	if err != nil {
		g.mu.Unlock()
		return g.Status(), fmt.Errorf("current value could not be read: %w", err)
	}
	record := &mitigationRecord{status: MitigationStatus{
		State: mitigationStateApplying, Enabled: true, Control: target.control, Key: target.key,
		Desired: target.desired, Previous: current, Current: current, Reason: reasonForMitigation(reason, why),
	}}
	g.record = record
	g.mu.Unlock()

	if current == target.desired {
		return g.finish(target, "the entry point was already closed; no write was necessary", true)
	}
	if err := g.core.SysctlCompareSet(target.key, current, target.desired); err != nil {
		return g.fail(target, fmt.Sprintf("the kernel refused the change: %v", err))
	}
	if got, err := g.core.SysctlGet(target.key); err != nil || got != target.desired {
		return g.fail(target, fmt.Sprintf("the post-state did not verify (got %q, err %v)", got, err))
	}
	g.mu.Lock()
	now := g.now()
	record.status.State = mitigationStateWatching
	record.status.Current = target.desired
	record.status.AppliedAt = &now
	deadline := now.Add(g.watch)
	record.status.WatchUntil = &deadline
	record.watchFrom = now
	record.status.Transitions = append(record.status.Transitions, MitigationTransition{
		At: now, Kind: "applied", Detail: fmt.Sprintf("%s set to %s (was %s)", target.key, target.desired, current),
	})
	status := record.status
	g.mu.Unlock()

	g.emit("high", "kernel.mitigation_applied", fmt.Sprintf(
		"Entry point closed: %s=%s (was %s). Probation window %s; the host is watched for regressions and the value is reverted automatically if one appears.",
		target.key, target.desired, current, g.watch))
	g.persist(target.key, target.desired, current, reasonForMitigation(reason, why))
	g.startWatcher()
	return status, nil
}

func reasonForMitigation(reason, why string) string {
	if reason != "" {
		return reason + " (" + why + ")"
	}
	return why
}

func (g *MitigationGuard) fail(target *mitigationTarget, detail string) (MitigationStatus, error) {
	g.mu.Lock()
	if g.record != nil {
		g.record.status.State = mitigationStateFailed
		g.record.status.Transitions = append(g.record.status.Transitions, MitigationTransition{At: g.now(), Kind: "failed", Detail: detail})
	}
	status := MitigationStatus{State: mitigationStateFailed, Enabled: true, Reason: detail}
	if g.record != nil {
		status = g.record.status
	}
	g.mu.Unlock()
	g.emit("critical", "kernel.mitigation_failed", "Automatic mitigation could not be established: "+detail)
	return status, errors.New(detail)
}

func (g *MitigationGuard) finish(target *mitigationTarget, detail string, alreadyIn bool) (MitigationStatus, error) {
	g.mu.Lock()
	now := g.now()
	if g.record != nil {
		g.record.status.State = mitigationStateStable
		g.record.status.StableAt = &now
		g.record.stable = true
		g.record.status.Transitions = append(g.record.status.Transitions, MitigationTransition{At: now, Kind: "in-force", Detail: detail})
	}
	status := g.record.status
	g.mu.Unlock()
	if !alreadyIn {
		g.emit("info", "kernel.mitigation_in_force", detail)
	}
	return status, nil
}

// Rollback restores the previous value. It is the operator's undo and the guard's own escape hatch.
func (g *MitigationGuard) Rollback(reason string) (MitigationStatus, error) {
	g.mu.Lock()
	record := g.record
	if record == nil {
		g.mu.Unlock()
		return MitigationStatus{State: mitigationStateIdle, Enabled: g.cfg.AutoMitigate}, errors.New("no mitigation is in force")
	}
	switch record.status.State {
	case mitigationStateWatching, mitigationStateStable, mitigationStateApplying, mitigationStateTampered:
	default:
		// idle, reverted, failed: there is nothing to undo, and a second rollback must not rewrite a
		// value the operator already has.
		g.mu.Unlock()
		return record.status, errors.New("no mitigation is in force")
	}
	key, previous := record.status.Key, record.status.Previous
	cancel := g.cancel
	g.cancel = nil
	g.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if g.core == nil {
		return g.Status(), errors.New("the privileged core is unavailable")
	}
	current, err := g.core.SysctlGet(key)
	if err != nil {
		return g.Status(), fmt.Errorf("current value could not be read: %w", err)
	}
	if current != previous {
		if err := g.core.SysctlCompareSet(key, current, previous); err != nil {
			g.emit("critical", "kernel.mitigation_revert_failed", fmt.Sprintf("Rollback of %s to %s failed: %v", key, previous, err))
			return g.Status(), fmt.Errorf("revert failed: %w", err)
		}
	}
	if got, err := g.core.SysctlGet(key); err != nil || got != previous {
		g.emit("critical", "kernel.mitigation_revert_failed", fmt.Sprintf("Rollback of %s did not verify (got %q, err %v)", key, got, err))
		return g.Status(), errors.New("revert did not verify")
	}
	g.mu.Lock()
	now := g.now()
	record.status.State = mitigationStateReverted
	record.status.Current = previous
	record.stable = false
	record.status.Transitions = append(record.status.Transitions, MitigationTransition{
		At: now, Kind: "reverted", Detail: fmt.Sprintf("%s restored to %s (%s)", key, previous, reason),
	})
	status := record.status
	g.mu.Unlock()
	g.emit("high", "kernel.mitigation_reverted", fmt.Sprintf(
		"Entry point reopened: %s restored to %s. Reason: %s", key, previous, reason))
	g.clearPersisted()
	return status, nil
}

// startWatcher runs the probation window and the permanent tamper assertion.
func (g *MitigationGuard) startWatcher() {
	g.mu.Lock()
	if g.cancel != nil {
		g.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	g.mu.Unlock()
	go g.watchLoop(ctx)
}

func (g *MitigationGuard) watchLoop(ctx context.Context) {
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if stop := g.tick(ctx); stop {
			return
		}
	}
}

// tick performs one assertion cycle. It returns true when the guard has nothing left to do, so a
// finished guard does not keep a permanent timer alive for the life of the process.
func (g *MitigationGuard) tick(ctx context.Context) bool {
	g.mu.Lock()
	record := g.record
	hasAuxiliary := len(g.auxiliary) > 0
	if record == nil {
		g.mu.Unlock()
		if hasAuxiliary {
			g.assertAuxiliary()
		}
		return !hasAuxiliary
	}
	key, desired := record.status.Key, record.status.Desired
	inWindow := !record.stable && g.now().Before(*record.status.WatchUntil)
	g.mu.Unlock()

	// 1. Tamper assertion: the platform does not accept a silently changed door.
	current, err := g.core.SysctlGet(key)
	if err != nil {
		g.recordFailure(fmt.Sprintf("the value of %s could not be read: %v", key, err), inWindow)
		return false
	}
	if current != desired {
		if err := g.core.SysctlCompareSet(key, current, desired); err != nil {
			g.recordFailure(fmt.Sprintf("%s drifted to %q and could not be re-asserted: %v", key, current, err), inWindow)
			return false
		}
		g.mu.Lock()
		record.status.Drift++
		record.status.Transitions = append(record.status.Transitions, MitigationTransition{
			At: g.now(), Kind: "drift-corrected", Detail: fmt.Sprintf("%s drifted to %q and was put back to %s", key, current, desired),
		})
		g.mu.Unlock()
		g.emit("high", "kernel.mitigation_drift", fmt.Sprintf(
			"%s was changed outside GeDefense to %q and has been re-asserted to %s", key, current, desired))
	}

	// 1b. Auxiliary controls have no probation; re-assert them on every cycle.
	g.assertAuxiliary()

	// 2. Probation: probes run while the host is still proving that it tolerates the change, and the
	// window closes on the first tick that lands after its deadline - including the case where no tick
	// happened for the whole window.
	if inWindow {
		if err := g.probeAll(ctx); err != nil {
			g.recordFailure(err.Error(), true)
			return false
		}
	}
	if !inWindow || !g.now().Before(*record.status.WatchUntil) {
		g.mu.Lock()
		if record.stable {
			g.mu.Unlock()
			return true
		}
		now := g.now()
		record.stable = true
		record.status.Failures = 0
		record.status.State = mitigationStateStable
		record.status.StableAt = &now
		record.status.Transitions = append(record.status.Transitions, MitigationTransition{
			At: now, Kind: "probation-passed",
			Detail: fmt.Sprintf("the host stayed healthy for the whole probation window; %s remains in force", key),
		})
		g.mu.Unlock()
		g.emit("info", "kernel.mitigation_held", fmt.Sprintf(
			"The probation window passed without a regression; %s=%s stays in force. The value continues to be re-asserted.", key, desired))
		return true
	}
	return false
}

func (g *MitigationGuard) probeAll(ctx context.Context) error {
	for _, probe := range g.probes {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := probe.Check(probeCtx)
		cancel()
		if errors.Is(err, errMitigationProbeUnavailable) {
			log.Printf("kernel mitigation: probe %q cannot observe the host; not treating it as a regression", probe.Name)
			g.noteProbeUnobserved(probe.Name, err)
			continue
		}
		if err != nil {
			return fmt.Errorf("health probe %q failed after the change: %w", probe.Name, err)
		}
	}
	return nil
}

// recordFailure counts a failure and reverts when the configured tolerance is reached. A single failed
// probe is not enough: transient hiccups happen, and reverting on the first one would make the
// mitigation flap. It reverts when the failure persists, which is what "the change broke something"
// actually looks like.
func (g *MitigationGuard) recordFailure(detail string, inWindow bool) {
	g.mu.Lock()
	record := g.record
	if record == nil {
		g.mu.Unlock()
		return
	}
	record.status.Failures++
	failures := record.status.Failures
	limit := g.cfg.MitigationFailures
	if limit < 1 {
		limit = 2
	}
	key, previous := record.status.Key, record.status.Previous
	g.mu.Unlock()
	g.emit("warning", "kernel.mitigation_probe_failed", detail)
	if !inWindow || failures < limit {
		return
	}
	log.Printf("kernel mitigation: %s failed %d times, reverting %s", detail, failures, key)
	if _, err := g.Rollback("automatic revert after " + detail); err != nil {
		g.emit("critical", "kernel.mitigation_revert_failed", fmt.Sprintf(
			"Automatic revert of %s to %s failed after a regression: %v", key, previous, err))
		return
	}
}

func (g *MitigationGuard) emit(severity, kind, message string) {
	if g.state == nil {
		return
	}
	g.state.AddEvent(Event{Severity: severity, Kind: kind, Source: "advisories", Message: message})
}

// Close stops the watcher. It deliberately does not revert: process shutdown is the wrong moment to
// change a kernel setting, and the next start re-evaluates the exposure from scratch.
func (g *MitigationGuard) Close() {
	g.mu.Lock()
	cancel := g.cancel
	g.cancel = nil
	g.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// ---------------------------------------------------------------- default probes

// DefaultMitigationProbes returns the health checks the guard uses when it runs inside the control
// plane. They are chosen so that they fail when the *host's* services break, not when GeDefense itself
// hiccups: the core IPC (the privileged path), the local web stack (the thing this server exists for)
// and the container runtime (the capability the user-namespace switch can take away).
func DefaultMitigationProbes(corePing func(context.Context) error) []MitigationProbe {
	probes := []MitigationProbe{{
		Name: "core-ipc",
		Check: func(ctx context.Context) error {
			if corePing == nil {
				return nil
			}
			return corePing(ctx)
		},
	}, {
		Name: "local-web-stack",
		Check: func(ctx context.Context) error {
			request, err := http.NewRequestWithContext(ctx, http.MethodHead, "http://127.0.0.1/", nil)
			if err != nil {
				return err
			}
			client := &http.Client{Timeout: 3 * time.Second}
			response, err := client.Do(request)
			if err != nil {
				return err
			}
			defer response.Body.Close()
			if response.StatusCode >= 500 {
				return fmt.Errorf("the local web stack answered %d", response.StatusCode)
			}
			return nil
		},
	}, {
		Name: "container-runtime",
		Check: func(ctx context.Context) error {
			socket := "/var/run/docker.sock"
			if _, err := os.Stat(socket); err != nil {
				return nil // no runtime installed: nothing can break
			}
			dialer := net.Dialer{Timeout: 3 * time.Second}
			connection, err := dialer.DialContext(ctx, "unix", socket)
			if err != nil {
				// The control plane runs as an unprivileged user. A socket that exists but is
				// not reachable from this uid is a visibility limit, not evidence that the
				// runtime broke; returning a failure here would auto-revert a valid mitigation.
				if errors.Is(err, os.ErrPermission) || strings.Contains(strings.ToLower(err.Error()), "permission denied") {
					return errMitigationProbeUnavailable
				}
				return fmt.Errorf("the container runtime socket is not answering: %w", err)
			}
			return connection.Close()
		},
	}}
	return probes
}
