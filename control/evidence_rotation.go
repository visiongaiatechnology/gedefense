// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// The evidence ledger is a forensic record, and a forensic record that stops recording is worse
// than a short one. Rotation is therefore part of the retention design rather than an operator
// routine: at the budget the sealed segment is archived with a manifest and a fresh chain
// continues.
//
// A full ledger was previously a terminal condition. It stopped recording, reported a capacity
// condition that degraded XDR, and that degradation pauses the automatic response - so the
// retention limit of a log quietly disabled part of the protection, and only an operator could
// clear it.
//
// The order is deliberately copy-then-replace: the live files are touched only after the archive
// exists and its manifest digest is recorded, so a crash before the swap leaves a working
// ledger, and a crash during the swap is completed by the next start from the rotation marker.
// Nothing is removed before it has been preserved.

const (
	evidenceRotationMarkerName = "evidence-rotation.json"
	evidenceRotationVersion    = 1
	// evidenceRotationThresholdPercent is when a rotation starts. Rotating at the budget would
	// mean rotating only after recording has already stopped, so it happens while there is still
	// room to write the records that describe the rotation.
	evidenceRotationThresholdPercent = 90
)

// EvidenceRotationResult describes what a rotation sealed and where it went.
type EvidenceRotationResult struct {
	ArchiveID      string    `json:"archive_id"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	RotatedAt      time.Time `json:"rotated_at"`
	SealedRecords  uint64    `json:"sealed_records"`
	SealedHead     string    `json:"sealed_head"`
}

type evidenceRotationManifest struct {
	Version         int                  `json:"version"`
	ArchiveID       string               `json:"archive_id"`
	CreatedAt       time.Time            `json:"created_at"`
	SoftwareVersion string               `json:"software_version"`
	NodeName        string               `json:"node_name"`
	ReasonSHA256    string               `json:"reason_sha256"`
	SealedRecords   uint64               `json:"sealed_records"`
	SealedHeadHash  string               `json:"sealed_head_hash"`
	VerifiedScope   string               `json:"verified_scope"`
	Ledger          incidentRecoveryFile `json:"ledger"`
	Checkpoint      incidentRecoveryFile `json:"checkpoint"`
	Watermark       incidentRecoveryFile `json:"watermark"`
}

// evidenceRotationMarker is what the next start needs in order to finish an interrupted
// rotation. It is written before the live files are replaced and removed afterwards.
type evidenceRotationMarker struct {
	Version        int    `json:"version"`
	ArchiveID      string `json:"archive_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

func (l *EvidenceLedger) rotationMarkerPath() string {
	return filepath.Join(filepath.Dir(l.path), evidenceRotationMarkerName)
}

// Rotate archives the sealed chain and starts a fresh one.
func (l *EvidenceLedger) Rotate(ctx context.Context, reason string) (EvidenceRotationResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.integrityErr != nil {
		return EvidenceRotationResult{}, fmt.Errorf("evidence ledger is quarantined: %w", l.integrityErr)
	}
	if l.sequence == 0 && l.expectedSize == 0 {
		return EvidenceRotationResult{}, errors.New("evidence ledger holds nothing to seal")
	}
	archiveID, manifestSHA, err := l.sealLocked(ctx, reason)
	if err != nil {
		return EvidenceRotationResult{}, err
	}
	sealedRecords, sealedHead := l.sequence, l.headHash
	if err := l.writeRotationMarkerLocked(archiveID, manifestSHA); err != nil {
		return EvidenceRotationResult{}, err
	}
	if err := l.replaceWithFreshChainLocked(); err != nil {
		return EvidenceRotationResult{}, fmt.Errorf("replace the sealed chain: %w", err)
	}
	if err := os.Remove(l.rotationMarkerPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return EvidenceRotationResult{}, fmt.Errorf("clear rotation marker: %w", err)
	}
	return EvidenceRotationResult{
		ArchiveID: archiveID, ManifestSHA256: manifestSHA,
		RotatedAt: time.Now().UTC(), SealedRecords: sealedRecords, SealedHead: sealedHead,
	}, nil
}

// evidenceArchiveRetention is the hard ceiling on rotation archives. Rotation happens automatically at
// the size budget, so without a ceiling a long-running node fills its disk with sealed history - and
// that disk is what the live ledger, the kernel state and the recovery path need.
const evidenceArchiveRetention = 24

// pruneArchivesLocked applies the evidence ceiling. The rule itself lives in pruneCompleteArchives so
// both ledgers - evidence and incident - follow one behaviour instead of two that drift apart.
func (l *EvidenceLedger) pruneArchivesLocked(keep int) (int, error) {
	archiveRoot := filepath.Join(filepath.Dir(l.path), "archive")
	protected := ""
	if raw, err := os.ReadFile(l.rotationMarkerPath()); err == nil {
		var marker evidenceRotationMarker
		if json.Unmarshal(raw, &marker) == nil {
			protected = marker.ArchiveID
		}
	}
	return pruneCompleteArchives(archiveRoot, "evidence-", keep, protected)
}

// pruneCompleteArchives keeps the newest archives in a root and removes the oldest complete ones.
// Two things are never removed: an archive that is still being written (it has no manifest yet), and
// the archive named by the caller as protected - a start-up that finds a recovery marker without its
// archive refuses to run, so retention must not be able to create exactly that state. Archive
// identifiers are timestamp-prefixed and os.ReadDir returns entries sorted by name, so oldest-first
// needs no extra ordering.
func pruneCompleteArchives(archiveRoot, prefix string, keep int, protected string) (int, error) {
	if keep < 1 {
		keep = 1
	}
	entries, err := os.ReadDir(archiveRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	complete := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || len(name) <= len(prefix) || name[:len(prefix)] != prefix {
			continue
		}
		dir := filepath.Join(archiveRoot, name)
		if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
			continue
		}
		complete = append(complete, dir)
	}
	removed := 0
	for _, dir := range complete {
		if len(complete)-removed <= keep {
			break
		}
		if protected != "" && filepath.Base(dir) == prefix+protected {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// sealLocked copies the chain and its checkpoint into an archive and writes the manifest. The
// live files are not touched here, which is what makes a crash at any point before the marker
// harmless. The caller holds the lock.
func (l *EvidenceLedger) sealLocked(ctx context.Context, reason string) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	dir := filepath.Clean(filepath.Dir(l.path))
	if err := rejectSymlinkedDirectory(dir); err != nil {
		return "", "", fmt.Errorf("evidence rotation storage root: %w", err)
	}
	archiveRoot := filepath.Join(dir, "archive")
	if err := ensurePrivateRecoveryDirectory(archiveRoot); err != nil {
		return "", "", err
	}
	archiveID, err := newRecoveryArchiveID()
	if err != nil {
		return "", "", err
	}
	archiveDir := filepath.Join(archiveRoot, "evidence-"+archiveID)
	if err := os.Mkdir(archiveDir, 0o700); err != nil {
		return "", "", err
	}
	if err := syncDirectory(archiveRoot); err != nil {
		return "", "", err
	}

	budget := l.effectiveMaxBytesLocked()
	ledgerMeta, err := archiveRecoveryFile(ctx, l.path, filepath.Join(archiveDir, "evidence.jsonl"), budget)
	if err != nil {
		return "", "", fmt.Errorf("archive evidence ledger: %w", err)
	}
	headMeta, err := archiveRecoveryFile(ctx, l.headPath, filepath.Join(archiveDir, "evidence.jsonl.head"), 128<<10)
	if err != nil {
		return "", "", fmt.Errorf("archive evidence checkpoint: %w", err)
	}
	watermarkMeta, err := archiveRecoveryFile(ctx, l.watermarkPath(), filepath.Join(archiveDir, "evidence.jsonl.verified"), 64<<10)
	if err != nil {
		return "", "", fmt.Errorf("archive evidence watermark: %w", err)
	}

	now := time.Now().UTC()
	reasonDigest := sha256.Sum256([]byte(reason))
	manifest := evidenceRotationManifest{
		Version: evidenceRotationVersion, ArchiveID: archiveID, CreatedAt: now,
		SoftwareVersion: version, NodeName: l.cryptoNodeName(), ReasonSHA256: hex.EncodeToString(reasonDigest[:]),
		SealedRecords: l.sequence, SealedHeadHash: l.headHash, VerifiedScope: l.verifyScope,
		Ledger: ledgerMeta, Checkpoint: headMeta, Watermark: watermarkMeta,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := atomicWriteFile(filepath.Join(archiveDir, "manifest.json"), manifestBytes, 0o600); err != nil {
		return "", "", fmt.Errorf("write rotation manifest: %w", err)
	}
	if err := syncDirectory(archiveDir); err != nil {
		return "", "", err
	}
	digest := sha256.Sum256(manifestBytes)
	// Retention runs after the new archive is complete, so the ceiling counts it. A failed prune never
	// fails the rotation: the archive is sealed and the seal is what matters; the disk report is a
	// warning the operator can act on.
	if removed, pruneErr := l.pruneArchivesLocked(evidenceArchiveRetention); pruneErr != nil {
		log.Printf("evidence archive retention: %v", pruneErr)
	} else if removed > 0 {
		log.Printf("evidence archive retention: removed %d of %d sealed archives", removed, evidenceArchiveRetention)
	}
	return archiveID, hex.EncodeToString(digest[:]), nil
}

// writeRotationMarkerLocked records that the swap is pending. The caller holds the lock.
func (l *EvidenceLedger) writeRotationMarkerLocked(archiveID, manifestSHA string) error {
	markerBytes, err := json.Marshal(evidenceRotationMarker{
		Version: evidenceRotationVersion, ArchiveID: archiveID, ManifestSHA256: manifestSHA,
	})
	if err != nil {
		return err
	}
	if err := atomicWriteFile(l.rotationMarkerPath(), markerBytes, 0o600); err != nil {
		return fmt.Errorf("write rotation marker: %w", err)
	}
	return nil
}

// cryptoNodeName reports the node the manifest belongs to without exposing the cipher itself.
func (l *EvidenceLedger) cryptoNodeName() string {
	if l.crypto == nil {
		return ""
	}
	return l.crypto.nodeName
}

// replaceWithFreshChainLocked swaps the live log for an empty one and resets the checkpoint, so
// the next append starts a new chain. The caller holds the lock.
func (l *EvidenceLedger) replaceWithFreshChainLocked() error {
	dir := filepath.Dir(l.path)
	temp, err := os.CreateTemp(dir, ".evidence-fresh-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, l.path); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := syncDirectory(dir); err != nil {
		return err
	}
	if err := writeEvidenceCheckpoint(l.headPath, 0, "", l.crypto); err != nil {
		return err
	}
	if err := os.Remove(l.watermarkPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	l.headHash = ""
	l.sequence = 0
	l.expectedSize = 0
	l.recent = nil
	l.budgetExhausted = false
	l.integrityErr = nil
	l.verifyScope = "empty"
	l.fullVerifiedAt = nil
	return nil
}

// finishInterruptedEvidenceRotation completes a rotation that a crash interrupted.
//
// The marker is written before the live files are replaced, so its presence means the sealed
// segment is already archived and verified and only the swap is missing. Refusing to start over
// that would repeat the failure this whole change came from: a file operation interrupted by a
// crash taking the platform down. The archive is therefore checked against the marker and the
// swap is repeated, which is idempotent.
func finishInterruptedEvidenceRotation(path, headPath string, storage *StorageCipher) error {
	dir := filepath.Clean(filepath.Dir(path))
	markerPath := filepath.Join(dir, evidenceRotationMarkerName)
	data, err := readBoundedPrivateFile(markerPath, 16<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var marker evidenceRotationMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return fmt.Errorf("evidence rotation marker: %w", err)
	}
	if marker.Version != evidenceRotationVersion || marker.ArchiveID == "" || marker.ManifestSHA256 == "" {
		return errors.New("evidence rotation marker is not usable; out-of-band verification required")
	}
	manifestPath := filepath.Join(dir, "archive", "evidence-"+marker.ArchiveID, "manifest.json")
	manifestBytes, err := readBoundedPrivateFile(manifestPath, 1<<20)
	if err != nil {
		return fmt.Errorf("evidence rotation manifest: %w", err)
	}
	digest := sha256.Sum256(manifestBytes)
	if hex.EncodeToString(digest[:]) != marker.ManifestSHA256 {
		return errors.New("evidence rotation manifest does not match its marker")
	}
	ledger := &EvidenceLedger{path: path, headPath: headPath, crypto: storage}
	if err := ledger.replaceWithFreshChainLocked(); err != nil {
		return fmt.Errorf("complete the interrupted rotation: %w", err)
	}
	if err := os.Remove(markerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear the rotation marker: %w", err)
	}
	return nil
}
