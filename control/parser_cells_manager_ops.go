// STATUS: DIAMANT VGT SUPREME
package main

// POINT 2 / P2-T3: ParserCellManager operations - evidence-first burn/incident
// destruction, freeze/unfreeze, export download, bounded export import and shared
// helpers. The admission/state core lives in parser_cells_manager.go, the periodic
// supervisor (health, reconcile, TTL) in parser_cells_supervision.go.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Burn is the operator/API path: a confirm-gated, evidence-first destruction.
func (m *ParserCellManager) Burn(uuid, reason string) (ParserCellRuntime, error) {
	if len(reason) < 3 {
		reason = parserCellGoBurnReasonOp
	}
	return m.burnCell(uuid, parserCellKindBurnIntent, reason, m.now())
}

// BurnForIncident is the CellGuard dispatch: only a managed parser-ephemeral cell
// is burned, only when namespace, score, switch and cooldown allow it. The bool
// reports "this cgroup was handled" so the guard never falls through to freezing a
// parser cell through the legacy transaction path.
func (m *ParserCellManager) BurnForIncident(cgroupID uint64, score int, incidentID, reason string) (bool, error) {
	if m == nil || cgroupID == 0 {
		return false, nil
	}
	m.mu.Lock()
	s := m.desired
	uuid := ""
	for candidate, cell := range m.cells {
		if cell.CgroupID == cgroupID && !cell.Terminal {
			uuid = candidate
			break
		}
	}
	if uuid == "" || !s.Enabled || !s.BurnOnIncident || score < s.IncidentScore {
		m.mu.Unlock()
		return false, nil
	}
	now := m.now()
	if last, cooled := m.cooldown[cgroupID]; cooled && now.Sub(last) < time.Duration(s.CooldownSeconds)*time.Second {
		m.mu.Unlock()
		return true, fmt.Errorf("parser cell incident burn for cgroup %d is cooling down", cgroupID)
	}
	m.cooldown[cgroupID] = now
	m.mu.Unlock()
	detail := parserCellToken(incidentID)
	if text := parserCellToken(strings.TrimSpace(reason)); text != "-" {
		detail += " " + text
	}
	_, err := m.burnCell(uuid, parserCellKindIncident, "incident "+detail, now)
	return true, err
}

func (m *ParserCellManager) burnCell(uuid, kind, reason string, now time.Time) (ParserCellRuntime, error) {
	m.mu.Lock()
	cell, ok := m.cells[uuid]
	if !ok {
		m.mu.Unlock()
		return ParserCellRuntime{}, &ParserCellError{Code: "unknown-cell"}
	}
	if cell.Terminal || cell.State == parserCellStateBurning {
		snapshot := cloneParserCellRuntime(cell)
		m.mu.Unlock()
		return snapshot, nil
	}
	client, clientErr := m.client, m.clientErr
	precommitted := cell.EvidenceID != ""
	if !precommitted {
		cell.EvidenceID = "PC-" + randomID()
	}
	evidenceID := cell.EvidenceID
	cell.State = parserCellStateBurning
	cell.BurnReason = parserCellBoundedString(reason, parserCellsErrorMaxBytes)
	generation, cgroupID, inputToken := cell.Generation, cell.CgroupID, cell.InputToken
	m.mu.Unlock()
	if clientErr != nil || client == nil {
		m.failCell(uuid, now, fmt.Errorf("%w: %v", ErrParserCellsRuntimeUnavailable, clientErr))
		return ParserCellRuntime{}, fmt.Errorf("%w: %v", ErrParserCellsRuntimeUnavailable, clientErr)
	}
	if !precommitted {
		message := fmt.Sprintf("Parser cell %s destruction intent recorded before the helper burn (reason: %s)", uuid, parserCellBoundedString(reason, 120))
		if err := m.evidence(EvidenceRecord{Severity: "high", Kind: kind, Source: parserCellEvidenceSource, Message: message, Target: uuid}); err != nil {
			m.addEvent(Event{Severity: "critical", Kind: "cells.parser.evidence_unavailable", Source: parserCellEvidenceSource,
				Message: "Evidence commit for a parser cell burn failed; the burn still runs because destroying the ephemeral cell is the security-relevant action"})
		}
	}
	result, err := client.Burn(uuid, generation, cgroupID, evidenceID, reason)
	if err != nil {
		m.failCell(uuid, now, err)
		m.addEvent(Event{Severity: "critical", Kind: "cells.parser.burn_failed", Source: parserCellEvidenceSource,
			Message: fmt.Sprintf("Parser cell %s could not be burned: %v", uuid, err), Target: uuid})
		return ParserCellRuntime{}, err
	}
	m.mu.Lock()
	if current := m.cells[uuid]; current != nil {
		current.State = parserCellStateBurned
		current.Terminal = true
		current.Export = nil
		if m.active > 0 {
			m.active--
		}
	}
	m.burned++
	m.recordLocked(ParserCellResult{At: now, UUID: uuid, Cgroup: cgroupID, Action: "burn", State: parserCellStateBurned, Reason: parserCellBoundedString(reason, 120)})
	delete(m.staged, inputToken)
	m.mu.Unlock()
	if inputToken != "" {
		_ = os.Remove(filepath.Join(m.cfg.InputDir, inputToken+parserCellInputSuffix))
	}
	if m.kernel != nil {
		if removeErr := m.kernel.Remove(cgroupID); removeErr != nil {
			m.setDegraded("kernel layer removal: " + parserCellBoundedError(removeErr))
		}
	}
	m.importExport(uuid, generation, cgroupID, result.ExportSize, result.ExportSHA, now)
	m.addEvent(Event{Severity: "high", Kind: parserCellKindBurned, Source: parserCellEvidenceSource,
		Message: fmt.Sprintf("Parser cell %s burned (reason: %s); export preserved as untrusted evidence", uuid, parserCellBoundedString(reason, 120)), Target: uuid})
	return m.runtimeSnapshot(uuid), nil
}

// Freeze/Unfreeze are the operator controls on a live cell; freeze is never used by
// the automatic path (an incident burns a parser cell, it does not pause it).
func (m *ParserCellManager) Freeze(uuid string) (ParserCellRuntime, error) {
	return m.setFrozen(uuid, true)
}

func (m *ParserCellManager) Unfreeze(uuid string) (ParserCellRuntime, error) {
	return m.setFrozen(uuid, false)
}

func (m *ParserCellManager) setFrozen(uuid string, freeze bool) (ParserCellRuntime, error) {
	m.mu.Lock()
	cell, ok := m.cells[uuid]
	if !ok {
		m.mu.Unlock()
		return ParserCellRuntime{}, &ParserCellError{Code: "unknown-cell"}
	}
	if cell.Terminal {
		snapshot := cloneParserCellRuntime(cell)
		m.mu.Unlock()
		return snapshot, &ParserCellError{Code: "conflict"}
	}
	generation, cgroupID := cell.Generation, cell.CgroupID
	client, clientErr := m.client, m.clientErr
	m.mu.Unlock()
	if clientErr != nil || client == nil {
		return ParserCellRuntime{}, fmt.Errorf("%w: %v", ErrParserCellsRuntimeUnavailable, clientErr)
	}
	var err error
	action := "unfreeze"
	if freeze {
		action = "freeze"
		err = client.Freeze(uuid, generation, cgroupID)
	} else {
		err = client.Unfreeze(uuid, generation, cgroupID)
	}
	if err != nil {
		m.addEvent(Event{Severity: "warning", Kind: "cells.parser." + action + "_failed", Source: parserCellEvidenceSource,
			Message: fmt.Sprintf("Parser cell %s %s failed: %v", uuid, action, err), Target: uuid})
		return ParserCellRuntime{}, err
	}
	m.mu.Lock()
	m.recordLocked(ParserCellResult{At: m.now(), UUID: uuid, Cgroup: cgroupID, Action: action, State: "applied"})
	m.mu.Unlock()
	return m.runtimeSnapshot(uuid), nil
}

// ExportDownload reads a bounded, previously imported export for the operator. The
// bytes are untrusted evidence from the control-owned parser-imports root only;
// they are served as an attachment, never rendered. O_NOFOLLOW plus a regular-file,
// owner, mode, size and digest check make the download path as strict as the
// import path.
func (m *ParserCellManager) ExportDownload(uuid string) ([]byte, ParserCellExportMeta, error) {
	m.mu.Lock()
	maxBytes := m.desired.MaxExportBytes
	importsDir := m.cfg.ImportsDir
	meta := ParserCellExportMeta{}
	if cell := m.cells[uuid]; cell != nil && cell.Export != nil {
		meta = *cell.Export
	}
	m.mu.Unlock()
	if meta.Path == "" || importsDir == "" || filepath.Dir(meta.Path) != filepath.Clean(importsDir) {
		return nil, meta, &ParserCellError{Code: "export-missing"}
	}
	file, err := os.OpenFile(meta.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, meta, &ParserCellError{Code: "export-missing"}
	}
	defer file.Close()
	info, err := file.Stat()
	stat, _ := info.Sys().(*syscall.Stat_t)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 ||
		stat == nil || int(stat.Uid) != os.Getuid() || info.Size() != meta.Size {
		return nil, meta, &ParserCellError{Code: "export-missing"}
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil || len(data) > maxBytes {
		return nil, meta, &ParserCellError{Code: "export-overflow"}
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != meta.SHA256 {
		return nil, meta, parserCellProtocol("stored export digest mismatch")
	}
	return data, meta, nil
}

func (m *ParserCellManager) runtimeSnapshot(uuid string) ParserCellRuntime {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cell := m.cells[uuid]; cell != nil {
		return cloneParserCellRuntime(cell)
	}
	return ParserCellRuntime{UUID: uuid, State: parserCellStateFailed}
}

func (m *ParserCellManager) runtimeSettings() RuntimeSettings {
	if m != nil && m.settings != nil {
		return m.settings.Get()
	}
	return defaultRuntimeSettings(Config{})
}

func (m *ParserCellManager) failCell(uuid string, now time.Time, err error) {
	m.mu.Lock()
	if cell := m.cells[uuid]; cell != nil && !cell.Terminal {
		cell.State = parserCellStateFailed
		cell.Terminal = true
		cell.LastError = parserCellBoundedError(err)
		m.failed++
		if m.active > 0 {
			m.active--
		}
	}
	m.recordLocked(ParserCellResult{At: now, UUID: uuid, Action: "burn", State: parserCellStateFailed, Detail: parserCellBoundedError(err)})
	m.mu.Unlock()
	m.addEvent(Event{Severity: "critical", Kind: "cells.parser.cell_failed", Source: parserCellEvidenceSource,
		Message: "Parser cell " + uuid + " failed: " + parserCellBoundedError(err), Target: uuid})
}

func (m *ParserCellManager) refuse(action, profile string, err error) {
	m.mu.Lock()
	m.refused++
	m.lastErr = parserCellBoundedError(err)
	m.recordLocked(ParserCellResult{At: m.now(), UUID: profile, Action: action, State: "refused", Detail: parserCellBoundedError(err)})
	m.mu.Unlock()
	m.addEvent(Event{Severity: "warning", Kind: "cells.parser.refused", Source: parserCellEvidenceSource,
		Message: "Parser cell " + action + " refused: " + parserCellBoundedError(err)})
}

func (m *ParserCellManager) setDegraded(reason string) {
	reason = parserCellBoundedString(reason, parserCellsErrorMaxBytes)
	m.mu.Lock()
	already := m.degradedWhy != ""
	m.degradedWhy = reason
	m.mu.Unlock()
	if already {
		return
	}
	m.addEvent(Event{Severity: "warning", Kind: "cells.parser.degraded", Source: parserCellEvidenceSource,
		Message: "Parser cell runtime degraded: " + reason})
}

func (m *ParserCellManager) recordLocked(result ParserCellResult) {
	m.recent = append([]ParserCellResult{result}, m.recent...)
	if len(m.recent) > parserCellHistoryLimit {
		m.recent = m.recent[:parserCellHistoryLimit]
	}
}

// Cell returns one bounded cell snapshot for the export surface.
func (m *ParserCellManager) Cell(uuid string) (ParserCellRuntime, bool) {
	if m == nil {
		return ParserCellRuntime{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cell, ok := m.cells[uuid]
	if !ok {
		return ParserCellRuntime{}, false
	}
	return cloneParserCellRuntime(cell), true
}

func cloneParserCellRuntime(in *ParserCellRuntime) ParserCellRuntime {
	if in == nil {
		return ParserCellRuntime{}
	}
	out := *in
	if in.Export != nil {
		export := *in.Export
		out.Export = &export
	}
	return out
}

func parserCellPruneStaged(staged map[string]parserCellStagedInput, now time.Time) {
	for token, entry := range staged {
		if now.Sub(entry.Created) > parserCellStagedTTL {
			_ = os.Remove(entry.Path)
			delete(staged, token)
		}
	}
	for len(staged) > parserCellStagedLimit {
		oldestToken, oldest := "", parserCellStagedInput{}
		for token, entry := range staged {
			if oldestToken == "" || entry.Created.Before(oldest.Created) {
				oldestToken, oldest = token, entry
			}
		}
		_ = os.Remove(oldest.Path)
		delete(staged, oldestToken)
	}
}

func parserCellContains(list []string, wanted string) bool {
	for _, value := range list {
		if value == wanted {
			return true
		}
	}
	return false
}

func parserCellBoundedString(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		value = value[:max]
	}
	return value
}

// importExport imports one burned export as bounded untrusted evidence. The bytes
// arrive exclusively through the sealed memfd descriptor of CELL_EXPORT_READ; the
// durable copy is written to the control-owned parser-imports root (never to the
// helper's root:gedefense parser-exports root) with O_EXCL|O_NOFOLLOW, fsync,
// mode 0640 and a full size+owner+mode+SHA-256 read-back. "stored" is claimed only
// after the write, that read-back and the evidence commit all succeeded.
func (m *ParserCellManager) importExport(uuid string, generation, cgroupID uint64, size int64, sha string, now time.Time) {
	if size <= 0 || len(sha) != 64 {
		return
	}
	m.mu.Lock()
	client, maxBytes, dir := m.client, m.desired.MaxExportBytes, m.cfg.ImportsDir
	m.mu.Unlock()
	if client == nil {
		return
	}
	file, meta, err := client.ExportRead(uuid, generation, int64(maxBytes))
	if err != nil {
		m.addEvent(Event{Severity: "warning", Kind: "cells.parser.export_missing", Source: parserCellEvidenceSource,
			Message: "Parser cell export was announced but the bounded descriptor could not be read: " + parserCellBoundedError(err), Target: uuid})
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil || len(data) > maxBytes {
		m.addEvent(Event{Severity: "critical", Kind: "cells.parser.export_overflow", Source: parserCellEvidenceSource,
			Message: "Parser cell export exceeded the configured bound and was discarded", Target: uuid})
		return
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if digest != meta.SHA256 || (sha != "" && sha != "-" && sha != meta.SHA256) {
		m.addEvent(Event{Severity: "critical", Kind: "cells.parser.export_mismatch", Source: parserCellEvidenceSource,
			Message: "Parser cell export digest did not match the helper metadata and was discarded", Target: uuid})
		return
	}
	scan := "airlock-unavailable"
	if m.airlock != nil {
		if result, scanErr := m.airlock.InspectBytes(uuid+".bin", data); scanErr == nil {
			switch {
			case !result.IsClean:
				scan = "untrusted:" + parserCellToken(result.ThreatType)
			case result.Sanitized:
				scan = "sanitized"
			default:
				scan = "clean"
			}
		} else {
			scan = "airlock-error"
		}
	}
	path, storeErr := parserCellStoreImport(dir, uuid, data)
	if storeErr != nil {
		m.markExportFailed(uuid, now, "export import write failed: "+parserCellBoundedError(storeErr))
		return
	}
	if err := m.evidence(EvidenceRecord{Severity: "high", Kind: parserCellKindExport, Source: parserCellEvidenceSource,
		Message: "Burned parser cell export imported as untrusted evidence (scan: " + scan + "); it is never rendered or executed", Target: uuid}); err != nil {
		// No stored claim without the mandatory evidence record: remove the file
		// instead of leaving an unaudited artifact behind.
		_ = os.Remove(path)
		m.markExportFailed(uuid, now, "export evidence commit failed: "+parserCellBoundedError(err))
		return
	}
	m.mu.Lock()
	if cell := m.cells[uuid]; cell != nil {
		cell.Export = &ParserCellExportMeta{Size: int64(len(data)), SHA256: digest, Kind: meta.Kind,
			Path: path, Scan: scan, ImportedAt: now}
	}
	m.mu.Unlock()
	m.addEvent(Event{Severity: "info", Kind: "cells.parser.export_imported", Source: parserCellEvidenceSource,
		Message: fmt.Sprintf("Parser cell export imported as untrusted evidence with %d bytes (sha256 %s, scan %s)", len(data), digest, scan), Target: uuid})
}

// markExportFailed records a failed import without claiming a stored export: the
// cell stays burned, but the operator-visible status says the export was not kept.
func (m *ParserCellManager) markExportFailed(uuid string, now time.Time, reason string) {
	m.mu.Lock()
	if cell := m.cells[uuid]; cell != nil {
		cell.Export = nil
		cell.LastError = parserCellBoundedString(reason, parserCellsErrorMaxBytes)
	}
	m.recordLocked(ParserCellResult{At: now, UUID: uuid, Action: "export", State: parserCellStateFailed, Detail: parserCellBoundedString(reason, 160)})
	m.mu.Unlock()
	m.addEvent(Event{Severity: "critical", Kind: "cells.parser.export_failed", Source: parserCellEvidenceSource,
		Message: "Parser cell export was not imported; no stored evidence is claimed: " + parserCellBoundedString(reason, 160), Target: uuid})
}

// parserCellStoreImport writes the untrusted copy durably and proves on read-back
// that exactly those bytes with the expected mode/owner/size are on disk.
func parserCellStoreImport(dir, uuid string, data []byte) (string, error) {
	if dir == "" {
		return "", errors.New("parser cell imports directory is not configured")
	}
	path := filepath.Join(dir, uuid+parserCellExportSuffix)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		return "", err
	}
	// The control unit runs with UMask=0077, so the requested 0640 create mode is
	// masked to 0600. The import contract (and the download path) requires exactly
	// 0640, so the mode is enforced explicitly through the open descriptor before
	// the bytes are written - an fchmod is umask-independent.
	if err := file.Chmod(0o640); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", errors.Join(errors.New("imported export mode could not be enforced"), err)
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return "", errors.Join(writeErr, syncErr, closeErr)
	}
	back, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	defer back.Close()
	info, statErr := back.Stat()
	stat, _ := info.Sys().(*syscall.Stat_t)
	if statErr != nil || !info.Mode().IsRegular() || info.Size() != int64(len(data)) ||
		info.Mode().Perm() != 0o640 || stat == nil || int(stat.Uid) != os.Getuid() {
		_ = os.Remove(path)
		return "", errors.New("imported export failed the size/mode/owner read-back")
	}
	stored, err := io.ReadAll(io.LimitReader(back, int64(len(data))+1))
	if err != nil || len(stored) != len(data) {
		_ = os.Remove(path)
		return "", errors.New("imported export read-back failed")
	}
	want := sha256.Sum256(data)
	got := sha256.Sum256(stored)
	if want != got {
		_ = os.Remove(path)
		return "", errors.New("imported export read-back digest mismatch")
	}
	return path, nil
}
