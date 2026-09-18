package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const incidentRecoveryManifestVersion = 1

type IncidentIntegrityStatus struct {
	Healthy         bool   `json:"healthy"`
	Quarantined     bool   `json:"quarantined"`
	ReasonCode      string `json:"reason_code,omitempty"`
	FailureRecord   uint64 `json:"failure_record,omitempty"`
	VerifiedRecords uint64 `json:"verified_records"`
	Recoverable     bool   `json:"recoverable"`
}

type IncidentRecoveryResult struct {
	ArchiveID      string                  `json:"archive_id"`
	ManifestSHA256 string                  `json:"manifest_sha256"`
	RecoveredAt    time.Time               `json:"recovered_at"`
	Integrity      IncidentIntegrityStatus `json:"integrity"`
}

type incidentRecoveryFile struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Size    int64  `json:"size"`
	Mode    uint32 `json:"mode"`
	SHA256  string `json:"sha256,omitempty"`
}

type incidentRecoveryManifest struct {
	Version         int                     `json:"version"`
	ArchiveID       string                  `json:"archive_id"`
	CreatedAt       time.Time               `json:"created_at"`
	SoftwareVersion string                  `json:"software_version"`
	NodeName        string                  `json:"node_name"`
	ReasonSHA256    string                  `json:"reason_sha256"`
	Failure         IncidentIntegrityStatus `json:"failure"`
	IncidentLog     incidentRecoveryFile    `json:"incident_log"`
	HeadCheckpoint  incidentRecoveryFile    `json:"head_checkpoint"`
}

var (
	errIncidentRecoveryNotRequired = errors.New("incident ledger recovery is not required")
	errIncidentRecoveryNotAllowed  = errors.New("incident ledger recovery is not allowed for the current integrity state")
)

func (l *IncidentLogger) IntegrityStatus() IncidentIntegrityStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.integrityStatusLocked()
}

func (l *IncidentLogger) integrityStatusLocked() IncidentIntegrityStatus {
	status := classifyIncidentIntegrityError(l.integrityErr)
	status.Quarantined = l.integrityErr != nil
	if l.integrityErr == nil {
		last, count, _, err := verifyIncidentLogWithStorage(l.path, l.key, l.crypto)
		if err == nil {
			err = verifyHeadCheckpointWithStorage(l.headPath, last, l.crypto)
		}
		if err == nil {
			if last != l.prevHash || count != l.sequence {
				err = errors.New("incident log advanced outside the trusted logger")
			} else if st, statErr := os.Stat(l.path); statErr == nil {
				if st.Size() != l.expectedSize {
					err = errors.New("incident log size changed outside the trusted logger")
				}
			} else if !errors.Is(statErr, os.ErrNotExist) || l.expectedSize != 0 {
				err = statErr
			}
		}
		if err == nil {
			return IncidentIntegrityStatus{Healthy: true, VerifiedRecords: count}
		}
		status = classifyIncidentIntegrityError(err)
		status.VerifiedRecords = verifiedPrefix(status.FailureRecord)
	}
	return status
}

func classifyIncidentIntegrityError(err error) IncidentIntegrityStatus {
	if err == nil {
		return IncidentIntegrityStatus{Healthy: true}
	}
	msg := strings.ToLower(err.Error())
	line := extractIncidentLine(msg)
	status := IncidentIntegrityStatus{
		Healthy:         false,
		FailureRecord:   line,
		VerifiedRecords: verifiedPrefix(line),
	}
	switch {
	case strings.Contains(msg, "authentication failed"):
		status.ReasonCode, status.Recoverable = "AUTHENTICATION_FAILED", true
	case strings.Contains(msg, "chain break"):
		status.ReasonCode, status.Recoverable = "CHAIN_BREAK", true
	case strings.Contains(msg, "head checkpoint is missing"):
		status.ReasonCode, status.Recoverable = "HEAD_MISSING", true
	case strings.Contains(msg, "head checkpoint does not match"):
		status.ReasonCode, status.Recoverable = "HEAD_MISMATCH", true
	case strings.Contains(msg, "malformed"):
		status.ReasonCode, status.Recoverable = "MALFORMED_RECORD", true
	case strings.Contains(msg, "unsupported version"):
		status.ReasonCode, status.Recoverable = "UNSUPPORTED_RECORD", true
	case strings.Contains(msg, "invalid hash length"):
		status.ReasonCode, status.Recoverable = "INVALID_RECORD_HASH", true
	case strings.Contains(msg, "mixes plaintext and encrypted records"):
		status.ReasonCode, status.Recoverable = "MIXED_RECORD_FORMAT", true
	case strings.Contains(msg, "advanced outside the trusted logger"):
		status.ReasonCode, status.Recoverable = "UNTRUSTED_APPEND", true
	case strings.Contains(msg, "size changed outside the trusted logger"):
		status.ReasonCode, status.Recoverable = "UNTRUSTED_SIZE_CHANGE", true
	case strings.Contains(msg, "must not be group/world accessible"):
		status.ReasonCode, status.Recoverable = "INSECURE_PERMISSIONS", true
	case strings.Contains(msg, "size budget"):
		status.ReasonCode, status.Recoverable = "SIZE_BUDGET_EXHAUSTED", false
	case strings.Contains(msg, "symbolic link"):
		status.ReasonCode, status.Recoverable = "SYMLINK_REJECTED", false
	default:
		status.ReasonCode = "INTEGRITY_FAILURE"
	}
	return status
}

func extractIncidentLine(message string) uint64 {
	idx := strings.LastIndex(message, "line ")
	if idx < 0 {
		return 0
	}
	rest := message[idx+len("line "):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	line, err := strconv.ParseUint(rest[:end], 10, 64)
	if err != nil {
		return 0
	}
	return line
}

func verifiedPrefix(failureRecord uint64) uint64 {
	if failureRecord == 0 {
		return 0
	}
	return failureRecord - 1
}

func (l *IncidentLogger) Recover(ctx context.Context, reasonSHA256 string) (IncidentRecoveryResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return IncidentRecoveryResult{}, err
	}
	failure := l.integrityStatusLocked()
	if failure.Healthy && !failure.Quarantined {
		return IncidentRecoveryResult{}, errIncidentRecoveryNotRequired
	}
	if !failure.Recoverable {
		return IncidentRecoveryResult{}, errIncidentRecoveryNotAllowed
	}

	parent := filepath.Clean(filepath.Dir(l.path))
	if err := rejectSymlinkedDirectory(parent); err != nil {
		return IncidentRecoveryResult{}, fmt.Errorf("incident recovery storage root: %w", err)
	}
	recoveryRoot := filepath.Join(parent, "xdr-recovery")
	if err := ensurePrivateRecoveryDirectory(recoveryRoot); err != nil {
		return IncidentRecoveryResult{}, err
	}
	archiveID, err := newRecoveryArchiveID()
	if err != nil {
		return IncidentRecoveryResult{}, err
	}
	archiveDir := filepath.Join(recoveryRoot, archiveID)
	if err := os.Mkdir(archiveDir, 0o700); err != nil {
		return IncidentRecoveryResult{}, err
	}
	if err := syncDirectory(recoveryRoot); err != nil {
		return IncidentRecoveryResult{}, err
	}

	logMeta, err := archiveRecoveryFile(ctx, l.path, filepath.Join(archiveDir, "incident-log.bin"), l.maxBytes)
	if err != nil {
		return IncidentRecoveryResult{}, fmt.Errorf("archive incident log: %w", err)
	}
	headMeta, err := archiveRecoveryFile(ctx, l.headPath, filepath.Join(archiveDir, "incident-head.bin"), 64<<10)
	if err != nil {
		return IncidentRecoveryResult{}, fmt.Errorf("archive incident head: %w", err)
	}

	now := time.Now().UTC()
	manifest := incidentRecoveryManifest{
		Version: incidentRecoveryManifestVersion, ArchiveID: archiveID, CreatedAt: now,
		SoftwareVersion: version, NodeName: l.nodeName, ReasonSHA256: reasonSHA256,
		Failure: failure, IncidentLog: logMeta, HeadCheckpoint: headMeta,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return IncidentRecoveryResult{}, err
	}
	manifestBytes = append(manifestBytes, '\n')
	manifestPath := filepath.Join(archiveDir, "manifest.json")
	if err := atomicWriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		return IncidentRecoveryResult{}, fmt.Errorf("write recovery manifest: %w", err)
	}
	if err := syncDirectory(archiveDir); err != nil {
		return IncidentRecoveryResult{}, err
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	if err := verifyRecoverySourceStable(ctx, l.path, logMeta, l.maxBytes); err != nil {
		return IncidentRecoveryResult{}, fmt.Errorf("incident log changed during recovery: %w", err)
	}
	if err := verifyRecoverySourceStable(ctx, l.headPath, headMeta, 64<<10); err != nil {
		return IncidentRecoveryResult{}, fmt.Errorf("incident head changed during recovery: %w", err)
	}

	if err := replaceWithFreshIncidentChain(l); err != nil {
		return IncidentRecoveryResult{}, err
	}
	last, count, _, err := verifyIncidentLogWithStorage(l.path, l.key, l.crypto)
	if err == nil {
		err = verifyHeadCheckpointWithStorage(l.headPath, last, l.crypto)
	}
	if err != nil || last != "" || count != 0 {
		if err == nil {
			err = errors.New("fresh incident chain did not verify as empty")
		}
		return IncidentRecoveryResult{}, fmt.Errorf("verify fresh incident chain: %w", err)
	}
	l.prevHash = ""
	l.sequence = 0
	l.expectedSize = 0
	l.integrityErr = nil

	return IncidentRecoveryResult{
		ArchiveID:      archiveID,
		ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		RecoveredAt:    now,
		Integrity:      IncidentIntegrityStatus{Healthy: true, VerifiedRecords: 0},
	}, nil
}

func verifyRecoverySourceStable(ctx context.Context, source string, archived incidentRecoveryFile, maxBytes int64) error {
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		if archived.Present {
			return errors.New("source disappeared after archival")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !archived.Present {
		return errors.New("source appeared after archival")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("source is no longer a regular non-symlink file")
	}
	if info.Size() != archived.Size || (maxBytes > 0 && info.Size() > maxBytes) {
		return errors.New("source size changed after archival")
	}
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return errors.New("source identity changed while verifying archive")
	}
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var read int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := f.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
			read += int64(n)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if read != archived.Size || hex.EncodeToString(h.Sum(nil)) != archived.SHA256 {
		return errors.New("source digest no longer matches archived evidence")
	}
	return nil
}

func rejectSymlinkedDirectory(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if filepath.Clean(resolved) != filepath.Clean(path) {
		return errors.New("recovery directory ancestry contains a symbolic link")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("recovery storage root must be a real directory")
	}
	return nil
}

func ensurePrivateRecoveryDirectory(path string) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("recovery path must be a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("recovery directory must not be group/world accessible")
	}
	return nil
}

func newRecoveryArchiveID() (string, error) {
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(entropy[:]), nil
}

func archiveRecoveryFile(ctx context.Context, source, destination string, maxBytes int64) (incidentRecoveryFile, error) {
	meta := incidentRecoveryFile{Name: filepath.Base(destination)}
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		return meta, nil
	}
	if err != nil {
		return meta, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return meta, errors.New("source evidence must be a regular non-symlink file")
	}
	if info.Size() < 0 || (maxBytes > 0 && info.Size() > maxBytes) {
		return meta, errors.New("source evidence exceeds recovery archive bound")
	}
	in, err := os.Open(source)
	if err != nil {
		return meta, err
	}
	defer in.Close()
	openedInfo, err := in.Stat()
	if err != nil {
		return meta, err
	}
	if !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() {
		return meta, errors.New("source evidence identity changed while opening")
	}

	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return meta, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = out.Close()
		}
	}()
	hash := sha256.New()
	buf := make([]byte, 64<<10)
	var copied int64
	for {
		if err := ctx.Err(); err != nil {
			return meta, err
		}
		n, readErr := in.Read(buf)
		if n > 0 {
			if maxBytes > 0 && copied+int64(n) > maxBytes {
				return meta, errors.New("source evidence exceeded recovery archive bound while reading")
			}
			if _, err := out.Write(buf[:n]); err != nil {
				return meta, err
			}
			_, _ = hash.Write(buf[:n])
			copied += int64(n)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return meta, readErr
		}
	}
	if copied != openedInfo.Size() {
		return meta, errors.New("source evidence size changed while archiving")
	}
	if err := out.Sync(); err != nil {
		return meta, err
	}
	if err := out.Close(); err != nil {
		return meta, err
	}
	closed = true
	if err := os.Chmod(destination, 0o600); err != nil {
		return meta, err
	}
	meta.Present = true
	meta.Size = copied
	meta.Mode = uint32(info.Mode().Perm())
	meta.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return meta, nil
}

func replaceWithFreshIncidentChain(l *IncidentLogger) error {
	parent := filepath.Dir(l.path)
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return err
	}
	suffix := ".recovery-new-" + hex.EncodeToString(entropy[:])
	logTmp := l.path + suffix
	headTmp := l.headPath + suffix
	defer os.Remove(logTmp)
	defer os.Remove(headTmp)

	logFile, err := os.OpenFile(logTmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := logFile.Sync(); err != nil {
		_ = logFile.Close()
		return err
	}
	if err := logFile.Close(); err != nil {
		return err
	}

	headData := []byte("\n")
	if l.crypto != nil {
		sealed, err := l.crypto.Encrypt(l.headPath, "incident-head", 0, headData)
		if err != nil {
			return err
		}
		headData = append(sealed, '\n')
	}
	headFile, err := os.OpenFile(headTmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := headFile.Write(headData); err == nil {
		err = headFile.Sync()
	}
	closeErr := headFile.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}

	// Head first is intentional. If the host crashes between the two renames,
	// the old corrupt log and the fresh head still fail closed on the next boot.
	if err := os.Rename(headTmp, l.headPath); err != nil {
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	if err := os.Rename(logTmp, l.path); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

type XDRIntegrityReport struct {
	Component       string                  `json:"component"`
	Health          string                  `json:"health"`
	XDRDegraded     bool                    `json:"xdr_degraded"`
	DegradedReason  string                  `json:"degraded_reason,omitempty"`
	RecoveryAllowed bool                    `json:"recovery_allowed"`
	Ledger          IncidentIntegrityStatus `json:"ledger"`
}

func (e *XDREngine) IncidentIntegrityReport() XDRIntegrityReport {
	if e == nil || e.logger == nil {
		return XDRIntegrityReport{
			Component: "xdr_incident_ledger", Health: "unavailable", XDRDegraded: true,
			DegradedReason: "incident logger unavailable",
			Ledger:         IncidentIntegrityStatus{Healthy: false, ReasonCode: "LOGGER_UNAVAILABLE"},
		}
	}
	status := e.logger.IntegrityStatus()
	degraded, reason := e.degradedState()
	health := "healthy"
	if !status.Healthy || degraded {
		health = "degraded"
	}
	return XDRIntegrityReport{
		Component: "xdr_incident_ledger", Health: health, XDRDegraded: degraded,
		DegradedReason: reason, RecoveryAllowed: e.incidentRecoveryAllowed() && status.Recoverable,
		Ledger: status,
	}
}

func (e *XDREngine) VerifyIncidentIntegrity(ctx context.Context) (XDRIntegrityReport, error) {
	if e == nil || e.logger == nil {
		return e.IncidentIntegrityReport(), errors.New("incident logger unavailable")
	}
	if err := ctx.Err(); err != nil {
		return e.IncidentIntegrityReport(), err
	}
	if err := e.logger.Verify(); err != nil {
		e.markDegradedCause("incident_log", "incident log verification failed: "+err.Error())
		return e.IncidentIntegrityReport(), err
	}
	return e.IncidentIntegrityReport(), nil
}

func (e *XDREngine) RecoverIncidentLedger(ctx context.Context, reason string) (IncidentRecoveryResult, error) {
	if e == nil || e.logger == nil {
		return IncidentRecoveryResult{}, errors.New("incident logger unavailable")
	}
	select {
	case <-ctx.Done():
		return IncidentRecoveryResult{}, ctx.Err()
	case <-e.recoveryGate:
	}
	defer func() { e.recoveryGate <- struct{}{} }()

	enforcement, _ := e.state.Modes()
	if enforcement != "observe" {
		return IncidentRecoveryResult{}, errors.New("XDR incident-ledger recovery requires observe enforcement")
	}

	if !e.incidentRecoveryAllowed() {
		return IncidentRecoveryResult{}, errors.New("XDR has additional degraded causes or no recoverable incident-ledger degradation")
	}
	status := e.logger.IntegrityStatus()
	if status.Healthy && !status.Quarantined {
		return IncidentRecoveryResult{}, errIncidentRecoveryNotRequired
	}
	if !status.Recoverable {
		return IncidentRecoveryResult{}, errIncidentRecoveryNotAllowed
	}
	if e.state == nil || e.state.EvidenceLedger() == nil {
		return IncidentRecoveryResult{}, errors.New("mandatory evidence ledger unavailable")
	}

	reasonDigest := sha256.Sum256([]byte(reason))
	reasonSHA := hex.EncodeToString(reasonDigest[:])
	started := EvidenceRecord{
		Severity: "high", Kind: "xdr.recovery_started", Source: "operator",
		Message: "Operator-authorized XDR incident-ledger recovery started",
		Target:  "reason_sha256:" + reasonSHA,
	}
	if err := e.state.RecordEvidence(started); err != nil {
		e.markDegradedCause("evidence", "mandatory evidence ledger unavailable during XDR recovery")
		return IncidentRecoveryResult{}, err
	}

	result, err := e.logger.Recover(ctx, reasonSHA)
	if err != nil {
		_ = e.state.RecordEvidence(EvidenceRecord{
			Severity: "critical", Kind: "xdr.recovery_failed", Source: "xdr",
			Message: "XDR incident-ledger recovery failed; fail-closed state retained",
			Target:  "reason_sha256:" + reasonSHA,
		})
		return IncidentRecoveryResult{}, err
	}

	if err := e.state.RecordEvidence(EvidenceRecord{
		Severity: "high", Kind: "xdr.corrupt_chain_archived", Source: "xdr",
		Message: "Corrupt XDR incident chain archived before reinitialization",
		Target:  "archive:" + result.ArchiveID + " manifest_sha256:" + result.ManifestSHA256,
	}); err != nil {
		e.markDegradedCause("evidence", "mandatory evidence ledger unavailable during XDR recovery")
		return IncidentRecoveryResult{}, err
	}
	if err := e.logger.Verify(); err != nil {
		e.markDegradedCause("incident_log", "fresh incident log verification failed: "+err.Error())
		return IncidentRecoveryResult{}, err
	}
	if e.behavior != nil {
		if summary := e.behavior.Summary(); e.cfg.XDR.BehaviorEnabled && !summary.IntegrityOK {
			e.markDegradedCause("behavior", "behavior profile integrity failure: "+summary.Error)
			return IncidentRecoveryResult{}, errors.New("behavior profile integrity is not healthy")
		}
	}
	if err := e.state.RecordEvidence(EvidenceRecord{
		Severity: "info", Kind: "xdr.new_chain_verified", Source: "xdr",
		Message: "Fresh XDR incident chain verified after forensic recovery",
		Target:  "archive:" + result.ArchiveID,
	}); err != nil {
		e.markDegradedCause("evidence", "mandatory evidence ledger unavailable during XDR recovery")
		return IncidentRecoveryResult{}, err
	}
	if err := e.state.RecordEvidence(EvidenceRecord{
		Severity: "info", Kind: "xdr.recovery_completed", Source: "xdr",
		Message: "XDR incident-ledger recovery completed; protection promotion remains operator-controlled",
		Target:  "archive:" + result.ArchiveID,
	}); err != nil {
		e.markDegradedCause("evidence", "mandatory evidence ledger unavailable during XDR recovery")
		return IncidentRecoveryResult{}, err
	}

	e.clearDegradedCause("incident_log")
	result.Integrity = e.logger.IntegrityStatus()
	return result, nil
}
