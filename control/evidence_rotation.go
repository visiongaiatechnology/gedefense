// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
// exists and its manifest digest is recorded, so a crash before the swap leaves a working ledger,
// and a crash before the live files are replaced is completed by the next start from the rotation
// marker. A crash after the fresh epoch checkpoint is durable leaves only the marker behind, which
// the next start clears. One window is deliberately fail-closed instead of completed: once the
// fresh chain file has replaced the live log but before its authenticated epoch checkpoint exists,
// the next start sees 0 records where the marker names the sealed segment and refuses. The sealed
// archive and the predecessor epoch checkpoint stay intact - the epoch does not move, so there is
// no rollback vector a witness could observe - but the ledger stays quarantined until an operator
// restores the sealed segment from the archive and clears the marker. Nothing is removed before it
// has been preserved, and no code path claims that this window is completed automatically.

const (
	evidenceRotationMarkerName = "evidence-rotation.json"
	// evidenceRotationMarkerPurpose binds the marker envelope to its role and its path in the
	// node storage key, so a marker copied from another purpose or from another file name can
	// never authenticate.
	evidenceRotationMarkerPurpose = "evidence-rotation-marker"
	evidenceRotationVersion       = 1
	// evidenceRotationThresholdPercent is when a rotation starts. Rotating at the budget would
	// mean rotating only after recording has already stopped, so it happens while there is still
	// room to write the records that describe the rotation.
	evidenceRotationThresholdPercent = 90
)

// evidenceArchiveIDPattern describes the only identifiers a marker may name. The identifier
// ends up in a path below <state-dir>/archive, so it is restricted to characters that cannot
// express traversal, an absolute path or a directory separator. Generated identifiers use the
// same alphabet (see newEvidenceArchiveID).
var evidenceArchiveIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

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
//
// It is authenticated with the node storage key (AEAD, purpose- and path-bound) exactly like the
// chain files it describes. Without that, the marker was an unauthenticated JSON file in the
// state directory: anyone able to write there could plant one that named a manifest of their
// own making, and the next start would replace the live evidence chain with an empty one. The
// sealed head and sequence bind the marker to the authenticated predecessor checkpoint, so a
// marker replayed after a later rotation cannot reset a chain it does not describe.
type evidenceRotationMarker struct {
	Version        int    `json:"version"`
	ArchiveID      string `json:"archive_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	SealedHead     string `json:"sealed_head"`
	SealedSequence uint64 `json:"sealed_sequence"`
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
	// The recovery marker has to be authenticated with the node storage key: an unauthenticated
	// marker is exactly the forgery the interrupted-rotation path must not accept. Refusing a
	// rotation in a key-less mode is therefore the safe answer - a production start refuses that
	// configuration anyway.
	if l.crypto == nil {
		return EvidenceRotationResult{}, errors.New("evidence rotation needs a configured storage key to authenticate its recovery marker")
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
	// Retention only protects an archive named by a marker it can authenticate. A plaintext
	// marker is not evidence of anything and is ignored here; the interrupted-rotation path
	// refuses it outright.
	if marker, err := l.readRotationMarkerLocked(); err == nil {
		protected = marker.ArchiveID
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
	archiveID, err := newEvidenceArchiveID()
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
//
// The marker is sealed with the node storage cipher exactly like the chain it describes: the
// purpose and the marker path are bound into the AEAD associated data, so it cannot be forged,
// copied from another file or replayed under a different identity. A key-less ledger cannot
// produce an authenticated marker, which is why Rotate refuses in that mode instead of writing
// a marker no start could safely trust.
func (l *EvidenceLedger) writeRotationMarkerLocked(archiveID, manifestSHA string) error {
	marker := evidenceRotationMarker{
		Version:        evidenceRotationVersion,
		ArchiveID:      archiveID,
		ManifestSHA256: manifestSHA,
		SealedHead:     l.headHash,
		SealedSequence: l.sequence,
	}
	markerBytes, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	if l.crypto == nil {
		return errors.New("rotation marker cannot be authenticated without a storage key")
	}
	sealed, err := l.crypto.Encrypt(l.rotationMarkerPath(), evidenceRotationMarkerPurpose, 0, markerBytes)
	if err != nil {
		return fmt.Errorf("encrypt rotation marker: %w", err)
	}
	if err := atomicWriteFile(l.rotationMarkerPath(), append(sealed, '\n'), 0o600); err != nil {
		return fmt.Errorf("write rotation marker: %w", err)
	}
	return nil
}

// readRotationMarkerLocked reads and authenticates the pending-rotation marker. The caller holds
// the lock.
//
// A plaintext marker is accepted only for a key-less ledger, where it is used for retention
// bookkeeping and never for completing a rotation. With a storage key configured, anything but
// an envelope of evidenceRotationMarkerPurpose is an error.
func (l *EvidenceLedger) readRotationMarkerLocked() (evidenceRotationMarker, error) {
	markerPath := l.rotationMarkerPath()
	data, err := readBoundedPrivateFile(markerPath, 16<<10)
	if err != nil {
		return evidenceRotationMarker{}, err
	}
	if l.crypto != nil {
		plain, legacy, err := l.crypto.Decrypt(markerPath, evidenceRotationMarkerPurpose, data, nil)
		if err != nil {
			return evidenceRotationMarker{}, err
		}
		if legacy {
			return evidenceRotationMarker{}, errors.New("evidence rotation marker is not authenticated")
		}
		data = plain
	}
	return decodeRotationMarker(data)
}

func decodeRotationMarker(data []byte) (evidenceRotationMarker, error) {
	var marker evidenceRotationMarker
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&marker); err != nil {
		return evidenceRotationMarker{}, fmt.Errorf("evidence rotation marker: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return evidenceRotationMarker{}, errors.New("evidence rotation marker contains trailing data")
	}
	return marker, nil
}

// newEvidenceArchiveID returns an archive identifier that satisfies evidenceArchiveIDPattern.
//
// The canonical timestamp form contains a fractional-second dot; the evidence archive identifier
// is kept inside the validation alphabet by writing that separator as '-'. The identifier stays
// unique (timestamp plus random suffix) and sortable (the replacement is position-stable).
func newEvidenceArchiveID() (string, error) {
	id, err := newRecoveryArchiveID()
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(id, ".", "-"), nil
}

// evidenceArchiveManifestPath resolves the manifest path a marker names and proves that the
// result stays inside the archive directory. The identifier pattern already excludes path
// syntax; the filepath.Rel boundary is a second, independent check against a future pattern
// change or a platform-specific path separator.
func evidenceArchiveManifestPath(stateDir, archiveID string) (string, error) {
	if !evidenceArchiveIDPattern.MatchString(archiveID) {
		return "", errors.New("evidence rotation marker names an invalid archive identifier")
	}
	archiveRoot := filepath.Join(stateDir, "archive")
	archiveDir := filepath.Join(archiveRoot, "evidence-"+archiveID)
	rel, err := filepath.Rel(archiveRoot, archiveDir)
	if err != nil || filepath.IsAbs(rel) || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.ContainsRune(rel, filepath.Separator) {
		return "", errors.New("evidence rotation marker names an archive outside the archive directory")
	}
	manifestPath := filepath.Join(archiveDir, "manifest.json")
	relManifest, err := filepath.Rel(archiveRoot, manifestPath)
	if err != nil || filepath.IsAbs(relManifest) || relManifest == ".." || strings.HasPrefix(relManifest, ".."+string(filepath.Separator)) {
		return "", errors.New("evidence rotation manifest is outside the archive directory")
	}
	return manifestPath, nil
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
//
// It has one deliberately fail-closed crash window: the rename below makes the live chain empty
// before the fresh epoch checkpoint is written. A crash in that window is not completed by the
// next start - the pending marker names the sealed segment while the live chain holds 0 records,
// so recovery refuses and the ledger stays quarantined. The archive and the predecessor epoch
// checkpoint are untouched (no epoch regression), so the documented operator recovery remains
// available: restore the sealed segment from the archive, clear the marker, restart, retry the
// rotation.
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
	// The rotation is what makes the sequence go back to 0, so the generation it belongs to has
	// to be persisted with the fresh checkpoint. Once this write is durable the epoch is
	// crash-safe: a start after a completed swap reads it from the authenticated checkpoint. A
	// crash between the rename above and this write is the fail-closed window documented on the
	// function; recovery refuses there instead of deriving an epoch. An exhausted counter is
	// refused rather than wrapped: a wrap would look like a rollback.
	if l.ledgerEpoch == ^uint64(0) {
		return errors.New("evidence ledger epoch is exhausted")
	}
	nextEpoch := l.ledgerEpoch + 1
	if err := writeEvidenceCheckpoint(l.headPath, 0, "", nextEpoch, l.crypto); err != nil {
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
	l.ledgerEpoch = nextEpoch
	// A verification pass that captured the old chain uses this token to tell a rotation from
	// damage: it must not report the replacement it raced with as corruption.
	l.generation++
	return nil
}

// rejectEvidenceRotation logs and returns a refusal of an interrupted rotation. The live chain is
// never touched on this path: a marker that does not authenticate, does not match its archive or
// does not name the authenticated predecessor head is a forgery or a replay, and completing it
// would reset a chain that the marker does not describe.
func rejectEvidenceRotation(format string, args ...any) error {
	err := fmt.Errorf(format, args...)
	log.Printf("evidence rotation marker refused: %v", err)
	return err
}

// finishInterruptedEvidenceRotation completes a rotation that a crash interrupted before the
// live files were replaced.
//
// The marker is written before the live files are replaced, so its presence means the sealed
// segment is already archived and verified and only the swap is missing. Refusing to start over
// that would repeat the failure this whole change came from: a file operation interrupted by a
// crash taking the platform down. The archive is therefore checked against the marker and the
// swap is repeated, which is idempotent while the live chain still holds the sealed records.
//
// The window after the fresh chain file replaced the live log but before the fresh epoch
// checkpoint exists is NOT completed here. The live chain holds 0 records where the marker names
// the sealed segment, so the check below refuses rather than guessing. That is the documented
// fail-closed window: the archive and the predecessor checkpoint are intact and the epoch does
// not move (no rollback vector), and an operator performs the recovery out of band.
//
// The marker is authenticated (AEAD, node storage key, purpose- and path-bound) and is bound to
// the authenticated predecessor checkpoint: the sealed head and sequence it names must be the
// head and sequence the live checkpoint seals. That is what stops a forged marker - or a marker
// replayed from an older rotation - from resetting evidence it does not describe. Every refusal
// leaves the live chain byte-for-byte unchanged and is reported as an integrity error.
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
	if storage == nil {
		return rejectEvidenceRotation("evidence rotation marker cannot be authenticated without a configured storage key; out-of-band verification required")
	}
	plain, legacy, err := storage.Decrypt(markerPath, evidenceRotationMarkerPurpose, data, nil)
	if err != nil {
		return rejectEvidenceRotation("evidence rotation marker is not authenticated: %v", err)
	}
	if legacy {
		return rejectEvidenceRotation("evidence rotation marker is not authenticated")
	}
	marker, err := decodeRotationMarker(plain)
	if err != nil {
		return rejectEvidenceRotation("evidence rotation marker is malformed: %v", err)
	}
	if marker.Version != evidenceRotationVersion || marker.ArchiveID == "" || marker.ManifestSHA256 == "" ||
		marker.SealedHead == "" || marker.SealedSequence == 0 {
		return rejectEvidenceRotation("evidence rotation marker is not usable; out-of-band verification required")
	}
	if !evidenceArchiveIDPattern.MatchString(marker.ArchiveID) {
		return rejectEvidenceRotation("evidence rotation marker names an invalid archive identifier")
	}
	archiveRoot := filepath.Join(dir, "archive")
	manifestPath, err := evidenceArchiveManifestPath(dir, marker.ArchiveID)
	if err != nil {
		return rejectEvidenceRotation("%v", err)
	}
	// Validate the archive directory ancestry before reading the manifest. A missing archive is
	// reported by the manifest read below, which names the cause for the operator.
	if _, statErr := os.Lstat(archiveRoot); statErr == nil {
		if err := rejectSymlinkedDirectory(archiveRoot); err != nil {
			return rejectEvidenceRotation("evidence rotation archive root is not a real directory: %v", err)
		}
		if err := rejectSymlink(filepath.Dir(manifestPath)); err != nil {
			return rejectEvidenceRotation("evidence rotation archive is not a real directory: %v", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return rejectEvidenceRotation("evidence rotation archive root is not readable: %v", statErr)
	}
	manifestBytes, err := readBoundedPrivateFile(manifestPath, 1<<20)
	if err != nil {
		return rejectEvidenceRotation("evidence rotation manifest is not readable: %v", err)
	}
	digest := sha256.Sum256(manifestBytes)
	if hex.EncodeToString(digest[:]) != marker.ManifestSHA256 {
		return rejectEvidenceRotation("evidence rotation manifest does not match its authenticated marker")
	}
	var manifest evidenceRotationManifest
	dec := json.NewDecoder(bytes.NewReader(manifestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return rejectEvidenceRotation("evidence rotation manifest is malformed: %v", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return rejectEvidenceRotation("evidence rotation manifest contains trailing data")
	}
	if manifest.Version != evidenceRotationVersion || manifest.ArchiveID != marker.ArchiveID ||
		manifest.SealedHeadHash != marker.SealedHead || manifest.SealedRecords != marker.SealedSequence {
		return rejectEvidenceRotation("evidence rotation manifest does not describe the sealed predecessor head")
	}
	// The predecessor the marker names has to be the chain that is live right now. A marker
	// replayed after a newer rotation names a head the current checkpoint does not seal, and
	// completing it would destroy evidence that rotation never described.
	checkpoint, err := readEvidenceCheckpoint(headPath, storage)
	if err != nil {
		return rejectEvidenceRotation("evidence rotation predecessor checkpoint is not readable: %v", err)
	}
	if checkpoint.Version != evidenceRecordVersion {
		return rejectEvidenceRotation("evidence rotation predecessor checkpoint has an unsupported version")
	}
	if checkpoint.Sequence == 0 && checkpoint.HeadHash == "" {
		// The swap already completed before the crash; only the marker was left behind. The
		// fresh chain is left untouched and the marker is cleared.
		if err := os.Remove(markerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("clear the rotation marker: %w", err)
		}
		return nil
	}
	if checkpoint.Sequence != marker.SealedSequence || checkpoint.HeadHash != marker.SealedHead {
		return rejectEvidenceRotation("evidence rotation marker does not name the authenticated predecessor head; out-of-band verification required")
	}
	lines, _, err := evidenceLineWindow(path, 0, 0)
	if err != nil {
		return rejectEvidenceRotation("evidence ledger is not readable: %v", err)
	}
	if lines != marker.SealedSequence {
		return rejectEvidenceRotation("evidence rotation marker does not describe the live chain (%d records, marker names %d)", lines, marker.SealedSequence)
	}
	// The completion is the same swap Rotate performs, so it has to derive the same generation
	// from the authenticated predecessor checkpoint instead of starting from zero: otherwise a
	// crash-recovered rotation would move the witness-visible epoch backwards.
	ledger := &EvidenceLedger{path: path, headPath: headPath, crypto: storage, ledgerEpoch: checkpoint.LedgerEpoch}
	if err := ledger.replaceWithFreshChainLocked(); err != nil {
		return fmt.Errorf("complete the interrupted rotation: %w", err)
	}
	if err := os.Remove(markerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear the rotation marker: %w", err)
	}
	return nil
}
