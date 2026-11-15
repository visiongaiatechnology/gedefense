// STATUS: DIAMANT VGT SUPREME
package main

// POINT 2 / P2-T3: ParserCellManager supervisor - helper health/epoch detection,
// ledger reconciliation, bounded export import and the TTL deadline watchdog. The
// manager is split into three bounded files; nothing here claims isolation the
// helper or the privileged core has not attested.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

// reconcile rebuilds the local view from the authoritative helper ledger after a
// control-plane restart and re-asserts the dynamic host scopes (§8 restart row).
func (m *ParserCellManager) reconcile(now time.Time) {
	m.mu.Lock()
	enabled := m.desired.Enabled
	client := m.client
	m.mu.Unlock()
	if !enabled || client == nil {
		return
	}
	remote, err := client.List()
	if err != nil {
		m.helperFailure(err)
	} else {
		remoteUUIDs := make(map[string]struct{}, len(remote))
		for _, row := range remote {
			remoteUUIDs[row.UUID] = struct{}{}
		}
		m.mu.Lock()
		adoptedUUIDs := make([]string, 0)
		for _, row := range remote {
			if cell, exists := m.cells[row.UUID]; exists {
				if !cell.Terminal {
					cell.State = row.State
					if row.PID > 0 {
						cell.PID = row.PID
					}
				}
				continue
			}
			if len(adoptedUUIDs) >= parserCellMaxListCells {
				break
			}
			adoptedUUIDs = append(adoptedUUIDs, row.UUID)
			cell := &ParserCellRuntime{UUID: row.UUID, CellClass: parserCellsClassEphemeral, Profile: row.Profile,
				Generation: row.Generation, CgroupID: row.CgroupID, PID: row.PID, State: row.State,
				ExpiresAt: time.Unix(row.ExpiresAt, 0).UTC(), Adopted: true,
				Layers: ParserCellLayerStatus{Sandbox: "adopted-unverified", CellLSM: parserCellLayerUnavailable,
					StyxEgress: parserCellLayerUnavailable, TitanExec: parserCellLayerUnavailable}}
			cell.Terminal = row.State == parserCellStateBurned || row.State == parserCellStateFailed
			m.cells[row.UUID] = cell
			if !cell.Terminal {
				m.active++
			}
		}
		missing := make([]string, 0)
		for uuid, cell := range m.cells {
			if cell.Terminal {
				continue
			}
			if _, live := remoteUUIDs[uuid]; !live {
				missing = append(missing, uuid)
			}
		}
		m.mu.Unlock()
		for _, uuid := range adoptedUUIDs {
			m.applyAdoptedHostLayers(uuid)
		}
		for _, uuid := range missing {
			m.reconcileLost(uuid)
		}
	}
	availability := parserCellKernelAvailability{CellLSM: parserCellLayerUnavailable + ":core-unavailable",
		StyxEgress: parserCellLayerUnavailable + ":core-unavailable", TitanExec: parserCellLayerUnavailable + ":core-unavailable"}
	if m.kernel != nil {
		availability = m.kernel.Availability(m.runtimeSettings())
	}
	m.mu.Lock()
	m.availability = availability
	m.lastReconcile = now
	activeCgroups := make([]uint64, 0, len(m.cells))
	for _, cell := range m.cells {
		if !cell.Terminal && cell.CgroupID != 0 {
			activeCgroups = append(activeCgroups, cell.CgroupID)
		}
	}
	m.mu.Unlock()
	if m.kernel != nil {
		m.kernel.Reassert(m.runtimeSettings(), activeCgroups)
	}
}

// applyAdoptedHostLayers re-attaches the dynamic host scopes of a cell this control
// plane adopted from the helper ledger after a restart. The helper ledger implies
// L1 (the helper only lists cells it spawned); L2/L3/L4 must be re-requested and
// are reported per layer. A failed or missing required layer keeps the cell
// degraded - it is never reported as isolated on an unproven claim.
func (m *ParserCellManager) applyAdoptedHostLayers(uuid string) {
	m.mu.Lock()
	cell := m.cells[uuid]
	if cell == nil || cell.Terminal {
		m.mu.Unlock()
		return
	}
	cgroupID := cell.CgroupID
	desired := m.desired
	m.mu.Unlock()
	if cgroupID == 0 {
		return
	}
	layers := ParserCellLayerStatus{Sandbox: "adopted-unverified", CellLSM: parserCellLayerUnavailable,
		StyxEgress: parserCellLayerUnavailable, TitanExec: parserCellLayerUnavailable}
	var layerErr error
	if m.kernel != nil {
		layers, layerErr = m.kernel.Apply(cgroupID, m.runtimeSettings())
		layers.Sandbox = "adopted-unverified"
	}
	layers.Required = desired.RequireHostLayers
	layers.Satisfied = parserCellHostLayersSatisfied(desired.RequireHostLayers, layers)
	m.mu.Lock()
	if cell = m.cells[uuid]; cell == nil || cell.Terminal {
		m.mu.Unlock()
		return
	}
	cell.Layers = layers
	switch {
	case layerErr != nil:
		cell.State = parserCellStateDegraded
		cell.LastError = parserCellBoundedError(layerErr)
	case desired.RequireHostLayers && !layers.Satisfied:
		cell.State = parserCellStateDegraded
		cell.LastError = "adopted cell: required host layers are not applied"
	case m.kernel == nil:
		cell.LastError = "adopted cell: no kernel client attached, host layers unverified"
	}
	m.mu.Unlock()
	m.addEvent(Event{Severity: "info", Kind: parserCellKindReconciled, Source: parserCellEvidenceSource,
		Message: fmt.Sprintf("Adopted parser cell %s: host layers lsm=%s styx=%s titan=%s (required=%t)",
			uuid, layers.CellLSM, layers.StyxEgress, layers.TitanExec, desired.RequireHostLayers), Target: uuid})
}

func (m *ParserCellManager) reconcileLost(uuid string) {
	m.mu.Lock()
	cell := m.cells[uuid]
	if cell == nil || cell.Terminal {
		m.mu.Unlock()
		return
	}
	cell.State = parserCellStateBurned
	cell.Terminal = true
	cell.BurnReason = "helper no longer reports the cell"
	cgroupID := cell.CgroupID
	m.burned++
	if m.active > 0 {
		m.active--
	}
	m.mu.Unlock()
	if cgroupID != 0 && m.kernel != nil {
		_ = m.kernel.Remove(cgroupID)
	}
	_ = m.evidence(EvidenceRecord{Severity: "high", Kind: parserCellKindReconciled, Source: parserCellEvidenceSource,
		Message: "The helper no longer reports a parser cell the control plane tracked; it is recorded as ended (helper TTL timer or restart)", Target: uuid})
	m.addEvent(Event{Severity: "warning", Kind: parserCellKindReconciled, Source: parserCellEvidenceSource,
		Message: "Parser cell " + uuid + " ended outside the control plane and was reconciled from the helper ledger", Target: uuid})
}

// health polls the helper and detects a restart (the epoch fact): a restarted
// helper has killed every cell via PR_SET_PDEATHSIG, so no cell is claimed alive.
func (m *ParserCellManager) health(now time.Time) {
	m.mu.Lock()
	client, enabled := m.client, m.desired.Enabled
	m.mu.Unlock()
	if !enabled || client == nil {
		return
	}
	health, err := client.Health()
	if err != nil {
		m.helperFailure(err)
		return
	}
	m.mu.Lock()
	previousDown, previousKnown, previousStart := m.helperDown, m.helperKnown, m.helperHealth.StartedAt
	m.helperDown, m.helperErr, m.helperHealth, m.helperKnown, m.helperAt = false, "", health, true, now
	restarted := previousKnown && previousStart != 0 && health.StartedAt != previousStart
	if previousDown {
		m.degradedWhy = ""
	}
	m.mu.Unlock()
	if previousDown {
		m.addEvent(Event{Severity: "info", Kind: parserCellKindHelperUp, Source: parserCellEvidenceSource,
			Message: "The parser-cell helper is reachable again; capability and ledger facts are re-probed"})
	}
	if health.State == "degraded" {
		m.setDegraded("helper reports degraded: " + parserCellBoundedString(health.LastError, 120))
	}
	if restarted {
		m.markLiveCellsLost(now, "helper-restart", "The parser-cell helper restarted; PDEATHSIG terminated its cells")
	}
}

func (m *ParserCellManager) helperFailure(err error) {
	message := parserCellBoundedError(err)
	m.mu.Lock()
	first := !m.helperDown
	m.helperDown = true
	m.helperErr = message
	m.lastErr = message
	m.degradedWhy = "helper unavailable: " + message
	m.mu.Unlock()
	if !first {
		return
	}
	m.addEvent(Event{Severity: "critical", Kind: parserCellKindHelperDown, Source: parserCellEvidenceSource,
		Message: "The parser-cell helper is unreachable; no cell is created and no isolation is claimed. This is a capability fact, not a degraded detection mode"})
}

func (m *ParserCellManager) markLiveCellsLost(now time.Time, reason, message string) {
	m.mu.Lock()
	lost := make([]string, 0, len(m.cells))
	for uuid, cell := range m.cells {
		if cell.Terminal {
			continue
		}
		cell.State = parserCellStateFailed
		cell.Terminal = true
		cell.BurnReason = reason
		cell.LastError = parserCellBoundedString(message, 160)
		m.failed++
		lost = append(lost, uuid)
	}
	m.active = 0
	m.recordLocked(ParserCellResult{At: now, Action: "reconcile", State: parserCellStateFailed, Reason: reason})
	m.mu.Unlock()
	for _, uuid := range lost {
		_ = m.evidence(EvidenceRecord{Severity: "critical", Kind: parserCellKindReconciled, Source: parserCellEvidenceSource,
			Message: message, Target: uuid})
	}
	if len(lost) > 0 {
		m.addEvent(Event{Severity: "critical", Kind: "cells.parser.cells_lost", Source: parserCellEvidenceSource,
			Message: fmt.Sprintf("%s (%d parser cell(s) recorded as ended)", message, len(lost))})
	}
}

func (m *ParserCellManager) refreshCapabilities(now time.Time) (ParserCellCapabilities, error) {
	m.mu.Lock()
	client, clientErr, caps, known, at := m.client, m.clientErr, m.caps, m.capsKnown, m.capsAt
	m.mu.Unlock()
	if client == nil {
		return ParserCellCapabilities{}, fmt.Errorf("%w: %v", ErrParserCellsRuntimeUnavailable, clientErr)
	}
	if known && now.Sub(at) < parserCellCapsPeriod {
		return caps, nil
	}
	caps, err := client.Capabilities()
	if err != nil {
		if errors.Is(err, ErrParserCellsRuntimeUnavailable) {
			m.helperFailure(err)
		}
		return ParserCellCapabilities{}, err
	}
	m.mu.Lock()
	m.caps, m.capsKnown, m.capsAt = caps, true, now
	m.helperDown, m.helperErr = false, ""
	m.mu.Unlock()
	return caps, nil
}

// validateStagedInput re-verifies the staged file before the helper is asked to
// bind it (O_NOFOLLOW, bounded read, size/hash equality). The path is manager-owned.
func (m *ParserCellManager) validateStagedInput(token, sha string, size int64, maxInput int) (parserCellStagedInput, error) {
	m.mu.Lock()
	staged, ok := m.staged[token]
	m.mu.Unlock()
	if !ok {
		return parserCellStagedInput{}, &ParserCellError{Code: "input-missing"}
	}
	if size <= 0 || size > int64(maxInput) || size != staged.Size || sha != staged.SHA256 {
		return parserCellStagedInput{}, &ParserCellError{Code: "input-invalid"}
	}
	file, err := os.OpenFile(staged.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return parserCellStagedInput{}, &ParserCellError{Code: "input-missing"}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return parserCellStagedInput{}, &ParserCellError{Code: "input-invalid"}
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maxInput)+1))
	if err != nil || len(data) > maxInput {
		return parserCellStagedInput{}, &ParserCellError{Code: "input-invalid"}
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != sha {
		return parserCellStagedInput{}, &ParserCellError{Code: "input-invalid"}
	}
	return staged, nil
}

// superviseTTL is the Go-side deadline watchdog: it commits the destruction intent
// before the deadline and asks the helper to burn. The helper timer stays
// authoritative, so a control-plane outage can never keep a cell alive (§4.6).
func (m *ParserCellManager) superviseTTL(now time.Time) {
	m.mu.Lock()
	enabled := m.desired.Enabled
	candidates := make([]string, 0)
	late := make([]string, 0)
	for uuid, cell := range m.cells {
		if cell.Terminal || cell.State == parserCellStateBurning || cell.ExpiresAt.IsZero() {
			continue
		}
		grace := time.Duration(cell.TTLSeconds) * time.Second / 5
		if grace > parserCellTTLGraceMax {
			grace = parserCellTTLGraceMax
		}
		if !now.Add(grace).Before(cell.ExpiresAt) {
			if now.After(cell.ExpiresAt.Add(30 * time.Second)) {
				late = append(late, uuid)
			} else {
				candidates = append(candidates, uuid)
			}
		}
	}
	m.mu.Unlock()
	if !enabled {
		return
	}
	for _, uuid := range late {
		m.markLateCell(uuid)
	}
	for _, uuid := range candidates {
		m.mu.Lock()
		cell := m.cells[uuid]
		if cell == nil || cell.Terminal || cell.State == parserCellStateBurning {
			m.mu.Unlock()
			continue
		}
		cell.State = parserCellStateExpiring
		precommitted := cell.EvidenceID != ""
		if !precommitted {
			cell.EvidenceID = "PC-" + randomID()
		}
		m.mu.Unlock()
		if !precommitted {
			if err := m.evidence(EvidenceRecord{Severity: "high", Kind: parserCellKindBurnIntent, Source: parserCellEvidenceSource,
				Message: "TTL deadline reached: parser cell destruction intent recorded before the helper burn", Target: uuid}); err != nil {
				m.addEvent(Event{Severity: "critical", Kind: "cells.parser.evidence_unavailable", Source: parserCellEvidenceSource,
					Message: "Evidence commit for the TTL burn intent failed; the burn still runs because destroying the ephemeral cell is the security-relevant action", Target: uuid})
			}
		}
		_, _ = m.burnCell(uuid, parserCellKindBurnIntent, parserCellGoBurnReasonTTL, now)
	}
}

func (m *ParserCellManager) markLateCell(uuid string) {
	m.mu.Lock()
	cell := m.cells[uuid]
	if cell != nil && !cell.Terminal {
		cell.State = parserCellStateFailed
		cell.Terminal = true
		cell.LastError = "the helper TTL timer ended the cell before the control plane could burn it"
		m.failed++
		if m.active > 0 {
			m.active--
		}
	}
	m.mu.Unlock()
	_ = m.evidence(EvidenceRecord{Severity: "high", Kind: parserCellKindReconciled, Source: parserCellEvidenceSource,
		Message: "The authoritative helper TTL timer already ended this parser cell; the delayed control-plane burn is recorded as unobserved", Target: uuid})
	m.addEvent(Event{Severity: "warning", Kind: "cells.parser.ttl_unobserved", Source: parserCellEvidenceSource,
		Message: "Parser cell " + uuid + " ended by the helper TTL timer before the control-plane burn intent", Target: uuid})
}

// ---------------------------------------------------------------- helpers
