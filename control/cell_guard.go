// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// Automatic cell isolation.
//
// A Gaia Cell is the only place where GeDefense can actually take a capability away from a workload:
// freezing it stops it, revoking its network cuts it off from both directions. Until now that action
// existed only when an operator clicked it. This guard closes the loop - when an incident's score
// reaches the isolation threshold and the workload is bound to a cell, the cell is isolated through the
// same transaction engine the UI uses, so the before/after state is recorded and reversible.
//
// Three rules make it safe to run unattended:
//
//  1. **Only cell-bound workloads.** A cgroup that no cell owns is not isolated and the reason is
//     stated. Guessing a cell for a workload would isolate the wrong thing.
//  2. **Only through the transaction engine.** Preview, apply and the recorded pre/post state come from
//     the same engine the operator uses, so an automatic isolation is as auditable and as reversible
//     as a manual one.
//  3. **Bounded.** One isolation per workload per cooldown, and only the least destructive action the
//     configuration allows (network revocation before freezing).

const (
	cellActionFreeze        = "freeze"
	cellActionRevokeNetwork = "revoke-network"
)

type CellConfinementStatus struct {
	Enabled        bool                `json:"enabled"`
	Action         string              `json:"action"`
	Threshold      int                 `json:"threshold"`
	IntervalSecs   int                 `json:"interval_seconds"`
	CooldownSecs   int                 `json:"cooldown_seconds"`
	Isolated       int                 `json:"isolated"`
	Refused        int                 `json:"refused"`
	LastError      string              `json:"last_error,omitempty"`
	CellsAvailable bool                `json:"cells_available"`
	Recent         []CellConfineResult `json:"recent,omitempty"`
}

type CellConfineResult struct {
	At          time.Time `json:"at"`
	CgroupID    uint64    `json:"cgroup_id"`
	CellUUID    string    `json:"cell_uuid"`
	Action      string    `json:"action"`
	Transaction string    `json:"transaction,omitempty"`
	State       string    `json:"state"`
	Note        string    `json:"note,omitempty"`
}

type CellGuard struct {
	mu       sync.Mutex
	state    *State
	cfg      CellsConfig
	now      func() time.Time
	last     map[uint64]time.Time
	recent   []CellConfineResult
	isolated int
	refused  int
	lastErr  string
	cancel   context.CancelFunc
}

func NewCellGuard(state *State, cfg CellsConfig) *CellGuard {
	return &CellGuard{
		state: state, cfg: cfg, now: func() time.Time { return time.Now().UTC() },
		last: make(map[uint64]time.Time, 64),
	}
}

// Status reports what the guard is configured to do and what it has done.
func (g *CellGuard) Status() CellConfinementStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	status := CellConfinementStatus{
		Enabled: g.cfg.AutoConfine, Action: g.cfg.AutoConfineAction, Threshold: g.cfg.AutoConfineScore,
		IntervalSecs: g.cfg.AutoConfineIntervalSeconds, CooldownSecs: g.cfg.AutoConfineCooldownSeconds,
		Isolated: g.isolated, Refused: g.refused, LastError: g.lastErr,
	}
	if adapter := g.state.Cells(); adapter != nil {
		status.CellsAvailable = adapter.Status(false).Enabled
	}
	status.Recent = append([]CellConfineResult(nil), g.recent...)
	return status
}

// Run scans the incident stream on a fixed cadence. It is deliberately a scanner instead of a hook:
// the isolation decision then survives a restart of the XDR engine and cannot be lost in a channel.
func (g *CellGuard) Run(ctx context.Context) {
	if g == nil || !g.cfg.AutoConfine {
		return
	}
	interval := time.Duration(g.cfg.AutoConfineIntervalSeconds) * time.Second
	if interval < 5*time.Second {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.scan()
		}
	}
}

// scan isolates every recent incident that crossed the threshold and whose workload no cell owns yet.
func (g *CellGuard) scan() {
	if !g.cfg.AutoConfine {
		// Defence in depth: the background loop already checks the switch, and the scan refuses on its
		// own as well so no future caller can isolate a workload by calling it directly.
		return
	}
	snapshot := g.state.Snapshot()
	if len(snapshot.Incidents) == 0 {
		return
	}
	threshold := g.cfg.AutoConfineScore
	if threshold <= 0 {
		threshold = 80
	}
	for _, incident := range snapshot.Incidents {
		if incident.CellCgroupID == 0 || incident.Score < threshold {
			continue
		}
		if g.coolingDown(incident.CellCgroupID) {
			continue
		}
		reason := fmt.Sprintf("automatic: incident %s scored %d (threshold %d)", incident.ID, incident.Score, threshold)
		if _, err := g.Confine(incident.CellCgroupID, g.cfg.AutoConfineAction, reason); err != nil {
			g.recordRefusal(incident.CellCgroupID, err)
			continue
		}
	}
}

func (g *CellGuard) coolingDown(cgroupID uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	seen, ok := g.last[cgroupID]
	if !ok {
		return false
	}
	return g.now().Sub(seen) < time.Duration(g.cfg.AutoConfineCooldownSeconds)*time.Second
}

// Confine isolates one workload through the transaction engine. It is the same path the dashboard uses,
// which is what makes an automatic isolation auditable and reversible.
func (g *CellGuard) Confine(cgroupID uint64, action, reason string) (CellConfineResult, error) {
	result := CellConfineResult{At: g.now(), CgroupID: cgroupID, Action: action}
	if cgroupID == 0 {
		return result, errors.New("no cgroup is bound to this incident, so no Gaia Cell can be resolved")
	}
	action = normalizeCellAction(action)
	if action == "" {
		return result, fmt.Errorf("unsupported cell action %q", action)
	}
	adapter := g.state.Cells()
	if adapter == nil {
		return result, errors.New("the Gaia Cells adapter is unavailable")
	}
	status := adapter.Status(false)
	if !status.Enabled {
		return result, errors.New("the Gaia Cells runtime is not enabled on this host")
	}
	cells, err := adapter.List()
	if err != nil {
		return result, fmt.Errorf("the Gaia Cells runtime could not be listed: %w", err)
	}
	var cell *GaiaCell
	for index := range cells {
		if cells[index].CgroupID == cgroupID {
			cell = &cells[index]
			break
		}
	}
	if cell == nil {
		return result, fmt.Errorf("no Gaia Cell covers cgroup %d; a workload outside a cell cannot be isolated", cgroupID)
	}
	if action == cellActionFreeze && cell.State != "running" {
		return result, fmt.Errorf("cell %s is %q and cannot be frozen", cell.UUID, cell.State)
	}
	engine := g.state.Transactions()
	if engine == nil {
		return result, errors.New("the transaction engine is unavailable")
	}
	payload, err := json.Marshal(cellIsolationRequest{
		UUID: cell.UUID, Generation: cell.Generation, CgroupID: cgroupID, Action: action,
	})
	if err != nil {
		return result, err
	}
	summary := fmt.Sprintf("Isolate cell %s (%s)", cell.UUID, action)
	preview, err := engine.Preview(cellTransactionType, summary, boundReason(reason), payload)
	if err != nil {
		return result, fmt.Errorf("cell isolation preview rejected: %w", err)
	}
	applied, err := engine.Apply(preview.ID, "APPLY "+preview.ID)
	if err != nil {
		return result, fmt.Errorf("cell isolation apply failed: %w", err)
	}
	result.CellUUID = cell.UUID
	result.Transaction = applied.ID
	result.State = applied.Status
	g.mu.Lock()
	g.last[cgroupID] = g.now()
	g.isolated++
	g.recent = append([]CellConfineResult{result}, g.recent...)
	if len(g.recent) > 10 {
		g.recent = g.recent[:10]
	}
	g.mu.Unlock()
	g.emit("high", "cells.isolated", fmt.Sprintf(
		"Workload isolated into Gaia Cell %s (%s) via %s. Reason: %s", cell.UUID, action, applied.ID, reason))
	return result, nil
}

func boundReason(reason string) string {
	// The transaction engine stores a bounded reason; keep the operator's text verbatim inside it.
	if len([]rune(reason)) > 240 {
		return string([]rune(reason)[:240])
	}
	if len([]rune(reason)) < 3 {
		return "automatic cell isolation"
	}
	return reason
}

func normalizeCellAction(action string) string {
	switch action {
	case "", cellActionRevokeNetwork:
		return cellActionRevokeNetwork
	case cellActionFreeze:
		return cellActionFreeze
	}
	return ""
}

func (g *CellGuard) recordRefusal(cgroupID uint64, err error) {
	g.mu.Lock()
	g.refused++
	g.lastErr = err.Error()
	// A refusal is retried after the cooldown, not on every tick that hits the same incident.
	g.last[cgroupID] = g.now()
	g.mu.Unlock()
	log.Printf("cell guard: cgroup %d not isolated: %v", cgroupID, err)
	g.emit("warning", "cells.isolation_refused", fmt.Sprintf("cgroup %d was not isolated: %v", cgroupID, err))
}

func (g *CellGuard) emit(severity, kind, message string) {
	if g.state == nil {
		return
	}
	g.state.AddEvent(Event{Severity: severity, Kind: kind, Source: "cells", Message: message})
}

// Close stops the background scan without changing any isolation that is in force: an isolation is a
// security state, not a session, and shutting a process down must never release it.
func (g *CellGuard) Close() {
	g.mu.Lock()
	cancel := g.cancel
	g.cancel = nil
	g.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// ConfineIncident resolves an incident by id and isolates the workload behind it. It is the manual
// path the dashboard offers next to the automatic one.
func (g *CellGuard) ConfineIncident(incidentID, action, reason string) (CellConfineResult, error) {
	if len(incidentID) < 3 {
		return CellConfineResult{}, errors.New("an incident id is required")
	}
	snapshot := g.state.Snapshot()
	for _, incident := range snapshot.Incidents {
		if incident.ID != incidentID {
			continue
		}
		if incident.CellCgroupID == 0 {
			return CellConfineResult{}, fmt.Errorf("incident %s carries no cell cgroup; the workload runs outside a Gaia Cell", incidentID)
		}
		return g.Confine(incident.CellCgroupID, action, boundReason(reason))
	}
	return CellConfineResult{}, fmt.Errorf("incident %s is not in the current window", incidentID)
}
