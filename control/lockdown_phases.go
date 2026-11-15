// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// POINT 5 / P5-T3: the phase orchestration of the Emergency Lockdown (§6).
// Every phase reports the acknowledgement of the dedicated subsystem and never
// an assumption; the phase-2 facts (sessions, device-mapper, kernel lockdown)
// are reported unsupported with their reason.

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ------------------------------------------------------------ phase execution

// runPhases executes the documented order: core kernel phases, the Go-side
// process freeze, the cell freeze, the parser-cell burn, and the honest
// unsupported phase-2 facts. Every result is the acknowledgement of the
// dedicated subsystem, never an assumption. The second return value carries the
// TransactionEngine ids of the applied cell freezes so the authenticated clear
// can reverse them.
func (e *LockdownEngine) runPhases(settings LockdownFabricSettings, candidate lockdownTriggerCandidate) ([]LockdownPhaseView, []string) {
	results := make(map[string]LockdownPhaseView, len(lockdownPhaseOrder))
	for name, phase := range e.runCorePhases(settings, candidate) {
		results[name] = phase
	}
	results[lockdownPhaseNameProcesses] = e.runProcessPhase(settings, candidate)
	cellPhase, cellTransactions := e.runCellPhase(settings)
	results[lockdownPhaseNameCells] = cellPhase
	results[lockdownPhaseNameParserCells] = e.runParserCellPhase(settings)
	results[lockdownPhaseNameSessions] = LockdownPhaseView{
		Phase: lockdownPhaseNameSessions, Status: lockdownPhaseUnsupported,
		Detail: "phase-2: no D-Bus/session broker is reachable from the unprivileged control plane",
	}
	results[lockdownPhaseNameDM] = LockdownPhaseView{
		Phase: lockdownPhaseNameDM, Status: lockdownPhaseUnsupported,
		Detail: "phase-2: no /dev/mapper (PrivateDevices=true) so no device-mapper suspend is possible",
	}
	results[lockdownPhaseNameKernelLockdown] = LockdownPhaseView{
		Phase: lockdownPhaseNameKernelLockdown, Status: lockdownPhaseUnsupported,
		Detail: "kernel lockdown is a boot parameter and cannot be toggled at runtime",
	}
	ordered := make([]LockdownPhaseView, 0, len(results))
	for _, name := range lockdownPhaseOrder {
		if phase, ok := results[name]; ok {
			ordered = append(ordered, phase)
		}
	}
	return ordered, cellTransactions
}

// processPhaseApplied reports whether the process freeze succeeded, so the
// engine persists the identity the clear has to resume.
func (e *LockdownEngine) processPhaseApplied(pid int, phases []LockdownPhaseView) bool {
	if pid <= 0 {
		return false
	}
	for _, phase := range phases {
		if phase.Phase == lockdownPhaseNameProcesses {
			return phase.Status == lockdownPhaseApplied
		}
	}
	return false
}

// runCorePhases asks the privileged core for the kernel phases and adopts its
// acknowledgement. A missing command family is a capability fact, not an error
// claim: the phase is then "unavailable".
func (e *LockdownEngine) runCorePhases(settings LockdownFabricSettings, candidate lockdownTriggerCandidate) map[string]LockdownPhaseView {
	out := make(map[string]LockdownPhaseView, len(lockdownCorePhaseNames))
	enabled := map[string]bool{
		lockdownPhaseNameNet:       settings.NetworkLockdown,
		lockdownPhaseNameUSB:       e.lockedMode() == lockdownModeLocked,
		lockdownPhaseNameTB:        e.lockedMode() == lockdownModeLocked,
		lockdownPhaseNameHardening: settings.HardeningApply,
		lockdownPhaseNameBrokers:   settings.FreezeBrokers,
	}
	flags := lockdownCoreFlags(settings)
	wantCore := flags != 0 || e.lockedMode() == lockdownModeLocked
	if !wantCore {
		for _, name := range lockdownCorePhaseNames {
			out[name] = LockdownPhaseView{Phase: name, Status: lockdownPhaseUnsupported, Detail: "disabled by settings; arm mode is unlocked and no kernel phase was requested"}
		}
		return out
	}
	if e.core == nil {
		e.stateMu.Lock()
		e.coreCapability = "unavailable"
		e.coreLastErr = "kernel core is unavailable"
		e.stateMu.Unlock()
		for _, name := range lockdownCorePhaseNames {
			out[name] = e.corePhaseFallback(name, enabled[name], "kernel core is unavailable")
		}
		return out
	}
	result, err := e.core.LockdownTrigger(candidate.Source, candidate.Reason, flags)
	if err != nil {
		capabilityErr := errors.Is(err, ErrLockdownUnavailable)
		e.stateMu.Lock()
		if capabilityErr {
			e.coreCapability = "missing"
		} else {
			e.coreCapability = "unavailable"
		}
		e.coreLastErr = lockdownReasonText(err.Error())
		e.stateMu.Unlock()
		detail := "core rejected LOCKDOWN_TRIGGER: " + lockdownReasonText(err.Error())
		if capabilityErr {
			detail = "core does not implement LOCKDOWN_* (capability-missing)"
		}
		for _, name := range lockdownCorePhaseNames {
			out[name] = e.corePhaseFallback(name, enabled[name], detail)
		}
		return out
	}
	// Read-back mandate (§6): the applied claim must be the core's verified
	// LOCKDOWN_STATUS phase list, not only the TRIGGER acknowledgement. One bounded
	// STATUS call follows the trigger; without it the phases stay "unavailable"
	// instead of being claimed from a write that was never verified.
	applied := make(map[string]bool, len(result.Applied))
	unsupported := make(map[string]bool, len(result.Unsupported))
	for _, name := range result.Unsupported {
		unsupported[name] = true
	}
	verified := false
	if status, statusErr := e.core.LockdownStatus(); statusErr == nil {
		verified = true
		e.setCoreStatus(status, nil)
		for _, name := range status.Applied {
			applied[name] = true
		}
		for _, name := range status.Unsupported {
			unsupported[name] = true
		}
	} else {
		e.setCoreStatus(CoreLockdownStatus{}, statusErr)
		// Without a verified read-back, the write acknowledgement is all the
		// evidence there is; the detail names that limitation.
		for _, name := range result.Applied {
			applied[name] = true
		}
	}
	for _, name := range lockdownCorePhaseNames {
		switch {
		case applied[name]:
			out[name] = LockdownPhaseView{Phase: name, Status: lockdownPhaseApplied}
		case unsupported[name]:
			out[name] = LockdownPhaseView{Phase: name, Status: lockdownPhaseUnsupported, Detail: "core reported the phase unsupported on this host"}
		case enabled[name]:
			// The core answered but did not confirm the phase: never claim it.
			detail := "core reported neither applied nor unsupported for this phase"
			if !verified {
				detail = "core did not confirm the phase in a LOCKDOWN_STATUS read-back"
			}
			out[name] = LockdownPhaseView{Phase: name, Status: lockdownPhaseUnavailable, Detail: detail}
		default:
			out[name] = LockdownPhaseView{Phase: name, Status: lockdownPhaseUnsupported, Detail: "disabled by settings"}
		}
	}
	e.stateMu.Lock()
	e.coreCapability = "available"
	if !verified {
		e.coreEpoch = result.Epoch
		e.coreApplied = append([]string{}, result.Applied...)
		e.coreUnsupported = append([]string{}, result.Unsupported...)
	}
	e.coreLastErr = ""
	e.stateMu.Unlock()
	return out
}

func (e *LockdownEngine) corePhaseFallback(name string, enabled bool, detail string) LockdownPhaseView {
	if !enabled {
		return LockdownPhaseView{Phase: name, Status: lockdownPhaseUnsupported, Detail: "disabled by settings"}
	}
	return LockdownPhaseView{Phase: name, Status: lockdownPhaseUnavailable, Detail: detail}
}

// runProcessPhase freezes the incident-bound process through the existing core
// response channel. It is bounded to one target and never touches UID 0 by
// default.
func (e *LockdownEngine) runProcessPhase(settings LockdownFabricSettings, candidate lockdownTriggerCandidate) LockdownPhaseView {
	phase := LockdownPhaseView{Phase: lockdownPhaseNameProcesses}
	if !settings.FreezeProcesses {
		phase.Status, phase.Detail = lockdownPhaseUnsupported, "disabled by settings"
		return phase
	}
	if candidate.PID <= 0 {
		phase.Status, phase.Detail = lockdownPhaseUnavailable, "no incident-bound process target is available for this trigger"
		return phase
	}
	if settings.ExcludeUID0 && candidate.UID == 0 {
		phase.Status, phase.Detail = lockdownPhaseUnsupported, "uid-0 process excluded by settings"
		return phase
	}
	if e.core == nil {
		phase.Status, phase.Detail = lockdownPhaseUnavailable, "kernel core is unavailable"
		return phase
	}
	if err := e.core.FreezeProcess(candidate.PID, candidate.StartTicks, "LOCKDOWN"); err != nil {
		phase.Status, phase.Detail = lockdownPhaseFailed, "core rejected the process freeze: "+lockdownReasonText(err.Error())
		return phase
	}
	phase.Status, phase.Targets = lockdownPhaseApplied, 1
	return phase
}

// runCellPhase freezes live Gaia Cells through the existing CellGuard /
// TransactionEngine path (§6.5 takes this phase out of the core on purpose).
func (e *LockdownEngine) runCellPhase(settings LockdownFabricSettings) (LockdownPhaseView, []string) {
	phase := LockdownPhaseView{Phase: lockdownPhaseNameCells}
	if !settings.FreezeCells {
		phase.Status, phase.Detail = lockdownPhaseUnsupported, "disabled by settings"
		return phase, nil
	}
	if e.state == nil || e.state.Cells() == nil {
		phase.Status, phase.Detail = lockdownPhaseUnavailable, "Gaia Cells adapter is unavailable"
		return phase, nil
	}
	adapter := e.state.Cells()
	if !adapter.Status(false).Enabled {
		phase.Status, phase.Detail = lockdownPhaseUnavailable, "Gaia Cells runtime is not enabled on this host"
		return phase, nil
	}
	cells, err := adapter.List()
	if err != nil {
		phase.Status, phase.Detail = lockdownPhaseUnavailable, "Gaia Cells runtime could not be listed: "+lockdownReasonText(err.Error())
		return phase, nil
	}
	if e.cellGuard == nil {
		phase.Status, phase.Detail = lockdownPhaseUnavailable, "no CellGuard is attached; no cell can be frozen through the transaction engine"
		return phase, nil
	}
	targets := 0
	failures := 0
	bounded := false
	transactions := make([]string, 0, 8)
	for index := range cells {
		cell := cells[index]
		if !lockdownCellInScope(settings.CellScope, cell) {
			continue
		}
		if cell.State != "running" {
			// Already frozen or stopped: the isolation holds, nothing to do.
			continue
		}
		if targets >= settings.MaxTargets {
			bounded = true
			break
		}
		targets++
		result, confineErr := e.cellGuard.Confine(cell.CgroupID, cellActionFreeze,
			"emergency lockdown: freeze cell "+cell.UUID)
		if confineErr != nil {
			failures++
			continue
		}
		if result.Transaction != "" {
			transactions = append(transactions, result.Transaction)
		}
	}
	if targets == 0 {
		phase.Status, phase.Detail = lockdownPhaseUnsupported, "no live Gaia Cell is in the configured scope"
		return phase, nil
	}
	phase.Targets = targets
	switch {
	case failures == 0:
		phase.Status = lockdownPhaseApplied
	case failures == targets:
		phase.Status, phase.Detail = lockdownPhaseFailed, "every in-scope cell freeze was refused"
	default:
		phase.Status = lockdownPhasePartial
		phase.Detail = fmt.Sprintf("%d of %d cell freezes were refused", failures, targets)
	}
	if bounded {
		phase.Detail = strings.TrimSpace(phase.Detail + fmt.Sprintf("; bounded to max_targets=%d", settings.MaxTargets))
	}
	return phase, transactions
}

// lockdownCellInScope applies the documented CellScope: "all" freezes every cell
// class, "high-risk" only the untrusted execution substrates and keeps the
// vault/workspace cells usable for the recovery console.
func lockdownCellInScope(scope string, cell GaiaCell) bool {
	if scope != lockdownCellScopeHighRisk {
		return true
	}
	switch cell.Class {
	case "application", "microvm":
		return true
	}
	return false
}

// runParserCellPhase burns managed parser-ephemeral cells. It never freezes one:
// the parser cell contract is ephemeral destruction (§6.5, POINT2 §5).
func (e *LockdownEngine) runParserCellPhase(settings LockdownFabricSettings) LockdownPhaseView {
	phase := LockdownPhaseView{Phase: lockdownPhaseNameParserCells}
	if !settings.FreezeParserCells {
		phase.Status, phase.Detail = lockdownPhaseUnsupported, "disabled by settings"
		return phase
	}
	if e.state == nil {
		phase.Status, phase.Detail = lockdownPhaseUnavailable, "no state is attached"
		return phase
	}
	manager := e.state.ParserCells()
	if manager == nil {
		phase.Status, phase.Detail = lockdownPhaseUnavailable, "parser cell manager is unavailable"
		return phase
	}
	status := manager.Status()
	if !status.Enabled {
		phase.Status, phase.Detail = lockdownPhaseUnsupported, "parser cells are disabled by settings"
		return phase
	}
	targets, failures, handled := 0, 0, 0
	for _, cell := range status.Cells {
		if cell.Terminal || cell.CgroupID == 0 {
			continue
		}
		if targets >= settings.MaxTargets {
			break
		}
		targets++
		burned, err := manager.BurnForIncident(cell.CgroupID, 250, "lockdown",
			"emergency lockdown: burn parser cell "+cell.UUID)
		if !burned {
			continue
		}
		handled++
		if err != nil {
			failures++
		}
	}
	if handled == 0 {
		phase.Status, phase.Detail = lockdownPhaseUnsupported, "no active managed parser cell is present"
		return phase
	}
	phase.Targets = handled
	switch {
	case failures == 0:
		phase.Status = lockdownPhaseApplied
	case failures == handled:
		phase.Status, phase.Detail = lockdownPhaseFailed, "every parser-cell burn was refused"
	default:
		phase.Status = lockdownPhasePartial
		phase.Detail = fmt.Sprintf("%d of %d parser-cell burns were refused", failures, handled)
	}
	return phase
}

// lockdownPhaseSummary is the bounded one-line outcome used in events/evidence.
func lockdownPhaseSummary(phases []LockdownPhaseView) string {
	counts := map[string]int{}
	for _, phase := range phases {
		counts[phase.Status]++
	}
	parts := make([]string, 0, len(lockdownPhaseOrder))
	for _, name := range lockdownPhaseOrder {
		for _, phase := range phases {
			if phase.Phase == name && phase.Status != lockdownPhaseUnsupported {
				parts = append(parts, name+"="+phase.Status)
				break
			}
		}
	}
	summary := fmt.Sprintf("applied=%d partial=%d unavailable=%d failed=%d unsupported=%d",
		counts[lockdownPhaseApplied], counts[lockdownPhasePartial], counts[lockdownPhaseUnavailable],
		counts[lockdownPhaseFailed], counts[lockdownPhaseUnsupported])
	if len(parts) > 0 {
		sort.Strings(parts)
		summary += " (" + strings.Join(parts, ", ") + ")"
	}
	return lockdownTruncateText(summary, 480)
}
