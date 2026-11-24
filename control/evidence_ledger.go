// STATUS: DIAMANT VGT SUPREME

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	evidenceRecordVersion = 1
	evidenceDomain        = "VGT-GEDEFENSE-EVIDENCE-V1\x00"
	evidenceRecentLimit   = 4096
)

type EvidenceRecord struct {
	Version   int       `json:"version"`
	Sequence  uint64    `json:"sequence"`
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Severity  string    `json:"severity"`
	Kind      string    `json:"kind"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
	Target    string    `json:"target,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
	Signature string    `json:"signature"`
}

type evidencePayload struct {
	Version   int       `json:"version"`
	Sequence  uint64    `json:"sequence"`
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Severity  string    `json:"severity"`
	Kind      string    `json:"kind"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
	Target    string    `json:"target,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	PrevHash  string    `json:"prev_hash"`
}

type evidenceCheckpoint struct {
	Version  int    `json:"version"`
	Sequence uint64 `json:"sequence"`
	HeadHash string `json:"head_hash"`
	// LedgerEpoch is the rotation generation of the chain this checkpoint seals. The field is
	// additive: a checkpoint written before it existed decodes as epoch 0, so every old .head
	// stays readable. A rotation increments it, which is what lets an out-of-band witness tell a
	// legitimate sequence reset apart from a rollback or a fork (docs/POINT4-WITNESS.md §2, §3).
	LedgerEpoch uint64 `json:"ledger_epoch,omitempty"`
}

// errEvidenceBudgetExhausted is a capacity condition, not an integrity condition.
//
// The two were previously the same thing: reaching the size budget set integrityErr,
// which quarantines the ledger permanently and - through State.RecordEvidence - reports
// XDR as degraded with "mandatory evidence ledger unavailable". A full ledger is not a
// corrupt ledger, and treating it as one had a second, worse effect: integrityErr is
// sticky, so raising the administrable budget afterwards could not clear it. The
// operator's own retention control became unusable at exactly the moment it was needed.
var errEvidenceBudgetExhausted = errors.New("evidence ledger size budget exhausted")

type EvidenceLedger struct {
	mu           sync.Mutex
	path         string
	headPath     string
	keyPath      string
	publicPath   string
	privateKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	crypto       *StorageCipher
	sequence     uint64
	headHash     string
	expectedSize int64
	maxBytes     int64
	integrityErr error
	// budgetExhausted tracks the capacity condition separately from integrityErr, so a
	// full ledger never quarantines and never has to be cleared by hand.
	budgetExhausted bool
	recent          []EvidenceRecord
	policy          EvidenceFabricSettings
	// verifyScope names how much of the chain this process has actually verified, and
	// fullVerifiedAt records when the whole history was last covered end to end. Startup
	// verifies an authenticated checkpoint plus a bounded tail, so a status surface has to be
	// able to say which of the two happened instead of implying the stronger one.
	verifyScope    string
	fullVerifiedAt *time.Time
	// incrementalChunk bounds one background verification pass. It is a field rather than a
	// constant so a test can exercise the chunking without writing tens of thousands of records.
	incrementalChunk uint64
	// generation is bumped whenever the live chain is replaced (rotation). It is the token a
	// verification pass compares against after its walk, so a rotation that happened while the
	// pass ran is told apart from damage: the pass must not quarantine a chain it never read.
	generation uint64
	// ledgerEpoch is the rotation generation persisted in the authenticated checkpoint. It is
	// read from that checkpoint at construction, incremented when a rotation replaces the chain,
	// and written with every append, so a witness can order checkpoints across rotations.
	ledgerEpoch uint64
}

func NewEvidenceLedger(path, keyPath, storageKeyPath, nodeName string, maxBytes int64) (*EvidenceLedger, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(keyPath) {
		return nil, errors.New("evidence ledger and signing key paths must be absolute")
	}
	if maxBytes < 1<<20 {
		maxBytes = 64 << 20
	}
	for _, candidate := range []string{path, path + ".head", keyPath, keyPath + ".pub"} {
		if err := os.MkdirAll(filepath.Dir(candidate), 0o700); err != nil {
			return nil, err
		}
		if err := rejectSymlink(candidate); err != nil {
			return nil, err
		}
	}
	storage, err := NewStorageCipher(storageKeyPath, nodeName)
	if err != nil {
		return nil, fmt.Errorf("evidence encryption: %w", err)
	}
	publicKey, privateKey, err := loadOrCreateEvidenceKey(keyPath, storage)
	if err != nil {
		return nil, err
	}
	// Construction must not reject a ledger the running service would accept.
	//
	// The administrable budget is not known yet at this point - the settings document is
	// applied afterwards - so checking against the constructor argument alone refused a
	// ledger that had legitimately grown under a raised policy. The failure was fatal and
	// happened before anything could report it: NewEvidenceLedger returned an error, the
	// caller exited, and the service would not start until the file was cut back by hand.
	// The operator was locked out by the very budget they had been told to raise.
	//
	// The order is deliberate: permissive at construction, strict at runtime, where the
	// effective budget is finally known. A budget that is later lowered is still enforced
	// by the append path against effectiveMaxBytesLocked().
	constructionBudget := maxBytes
	if fallback := defaultIntegrityFabricSettings(Config{}).Evidence.MaxBytes; fallback > constructionBudget {
		constructionBudget = fallback
	}
	// The effective budget starts as this constructor budget, floored the same way.
	//
	// The policy used to be seeded with the compiled-in default alone, and
	// effectiveMaxBytesLocked prefers the policy whenever it is set. A ledger built with
	// the operator's raised budget therefore still enforced 64 MiB: the administration
	// surface reported 256 MiB, the ledger stopped at 64 MiB, and once the file reached it
	// every append failed while Status() still called the ledger healthy. The platform
	// silently stopped recording evidence - the incident log and the forensic ledger both
	// went quiet - and every start logged "evidence ledger size budget exhausted" without
	// naming the disagreement that caused it. The two budgets have to start out equal.
	fabricDefaults := defaultIntegrityFabricSettings(Config{}).Evidence
	fabricDefaults.MaxBytes = constructionBudget
	ledger := &EvidenceLedger{
		path: path, headPath: path + ".head", keyPath: keyPath, publicPath: keyPath + ".pub",
		privateKey: privateKey, publicKey: publicKey, crypto: storage, maxBytes: maxBytes,
		policy:           fabricDefaults,
		recent:           make([]EvidenceRecord, 0, 256),
		incrementalChunk: evidenceIncrementalChunkRecords,
	}
	if err := ledger.writeOrVerifyPublicKey(); err != nil {
		return nil, err
	}
	// A rotation that a crash interrupted is completed before anything is verified. The marker
	// means the sealed segment is already archived and its manifest matches, so only the swap is
	// missing; refusing to start over a half-finished file operation would repeat the failure
	// this change came from.
	if err := finishInterruptedEvidenceRotation(path, ledger.headPath, storage); err != nil {
		ledger.integrityErr = err
		return ledger, nil
	}
	// Startup verifies the authenticated checkpoint and a bounded tail of the chain.
	//
	// The whole history is covered by the incremental watermark pass after readiness, and by
	// the operator on demand. Paying for the history here meant the service could not start at
	// all once the ledger was large - the platform lost its dashboard and its release gate
	// because a forensic log had grown.
	head, sequence, recent, size, scope, verifyErr := verifyEvidenceFilesBounded(path, ledger.headPath, publicKey, storage, constructionBudget, evidenceRecentLimit)
	ledger.headHash = head
	ledger.sequence = sequence
	ledger.recent = recent
	ledger.expectedSize = size
	ledger.integrityErr = verifyErr
	ledger.verifyScope = scope
	if verifyErr == nil {
		// The epoch belongs to the authenticated checkpoint, not to the chain walk, so it is read
		// from the checkpoint the bounded verification just accepted. A missing checkpoint is the
		// normal empty-ledger state and means epoch 0; any other read failure is an integrity
		// condition and must not silently become a witness-visible epoch.
		if checkpoint, checkpointErr := readEvidenceCheckpoint(ledger.headPath, storage); checkpointErr == nil {
			ledger.ledgerEpoch = checkpoint.LedgerEpoch
		} else if !errors.Is(checkpointErr, os.ErrNotExist) {
			ledger.integrityErr = checkpointErr
		}
	}
	if scope == "full" && sequence > 0 && verifyErr == nil {
		// The bounded window covered the whole chain, so coverage is complete and the
		// authenticated watermark may say so. Later passes then only have to cover what is
		// written after this point instead of walking the history again.
		if err := ledger.writeWatermark(evidenceWatermark{Version: evidenceRecordVersion, Sequence: sequence, HeadHash: head}); err != nil {
			ledger.verifyScope = "tail"
		} else {
			now := time.Now().UTC()
			ledger.fullVerifiedAt = &now
		}
	}
	return ledger, nil
}

func (l *EvidenceLedger) Append(record EvidenceRecord) (EvidenceRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.integrityErr != nil {
		return EvidenceRecord{}, fmt.Errorf("evidence ledger is quarantined: %w", l.integrityErr)
	}
	if record.ID == "" {
		record.ID = randomID()
	}
	if record.Time.IsZero() {
		record.Time = time.Now().UTC()
	}
	record.Version = evidenceRecordVersion
	record.Sequence = l.sequence + 1
	record.Time = record.Time.UTC()
	record.PrevHash = l.headHash
	record.Hash = ""
	record.Signature = ""
	if err := validateEvidenceText(record); err != nil {
		return EvidenceRecord{}, err
	}
	if err := l.verifyUnchangedLocked(); err != nil {
		l.integrityErr = err
		return EvidenceRecord{}, err
	}
	canonical, err := evidenceCanonical(record)
	if err != nil {
		return EvidenceRecord{}, err
	}
	digest := evidenceHash(canonical)
	record.Hash = hex.EncodeToString(digest)
	record.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(l.privateKey, digest))
	line, err := json.Marshal(record)
	if err != nil {
		return EvidenceRecord{}, err
	}
	if l.crypto != nil {
		line, err = l.crypto.Encrypt(l.path, "evidence-record", record.Sequence, line)
		if err != nil {
			return EvidenceRecord{}, err
		}
	}
	nextSize := l.expectedSize + int64(len(line)+1)
	if nextSize > l.effectiveMaxBytesLocked() {
		// Nothing is written and nothing is quarantined. The record is refused with a
		// condition the caller can tell apart from corruption, and the ledger keeps
		// taking writes as soon as the budget is raised.
		l.budgetExhausted = true
		return EvidenceRecord{}, errEvidenceBudgetExhausted
	}
	l.budgetExhausted = false
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|noFollowFlag, 0o600)
	if err != nil {
		return EvidenceRecord{}, err
	}
	if _, err = file.Write(append(line, '\n')); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return EvidenceRecord{}, err
	}
	if closeErr != nil {
		return EvidenceRecord{}, closeErr
	}
	if err := writeEvidenceCheckpoint(l.headPath, record.Sequence, record.Hash, l.ledgerEpoch, l.crypto); err != nil {
		l.integrityErr = fmt.Errorf("evidence checkpoint commit failed: %w", err)
		return EvidenceRecord{}, l.integrityErr
	}
	l.sequence = record.Sequence
	l.headHash = record.Hash
	l.expectedSize = nextSize
	l.recent = append(l.recent, record)
	if len(l.recent) > evidenceRecentLimit {
		l.recent = append([]EvidenceRecord(nil), l.recent[len(l.recent)-evidenceRecentLimit:]...)
	}
	return record, nil
}

func (l *EvidenceLedger) verifyUnchangedLocked() error {
	if err := rejectSymlink(l.path); err != nil {
		return err
	}
	if err := verifyEvidenceCheckpoint(l.headPath, l.sequence, l.headHash, l.ledgerEpoch, l.crypto); err != nil {
		return err
	}
	info, err := os.Lstat(l.path)
	if errors.Is(err, os.ErrNotExist) && l.expectedSize == 0 {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("evidence ledger file policy changed")
	}
	if info.Size() != l.expectedSize {
		return errors.New("evidence ledger size changed outside the trusted writer")
	}
	return nil
}

// Verify walks the chain from the beginning and checks the checkpoint against its end.
//
// This is the operator's path (GET /api/v1/evidence/verify) and the fallback for a ledger whose
// watermark is missing. It is deliberately not a startup path: the walk decrypts and verifies
// every record, so its cost is proportional to the whole history, and it holds the ledger lock
// for the duration.
func (l *EvidenceLedger) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.integrityErr != nil {
		return l.integrityErr
	}
	// The same limit the append path enforces. These two disagreed: Append consulted
	// effectiveMaxBytesLocked(), which prefers the administrable policy, while Verify
	// consulted the constructor value alone. An operator who raised the budget, let the
	// ledger grow past the old bound and then restarted the service had it rejected at
	// boot as "exceeds its size budget" - the ledger they had just been told to enlarge,
	// refused by the process that was told to accept it. One budget, read the same way
	// from both sides.
	head, sequence, _, size, err := verifyEvidenceFiles(l.path, l.headPath, l.publicKey, l.crypto, l.effectiveMaxBytesLocked(), l.ledgerEpoch)
	if err == nil && (head != l.headHash || sequence != l.sequence || size != l.expectedSize) {
		err = errors.New("evidence ledger advanced outside the trusted writer")
	}
	if err != nil {
		l.integrityErr = err
		return err
	}
	if err := l.writeWatermark(evidenceWatermark{Version: evidenceRecordVersion, Sequence: sequence, HeadHash: head}); err != nil {
		// The walk just verified every record; only the durable coverage hint could not be
		// written. Treating that as an integrity error quarantined a healthy chain because of a
		// disk condition - a false-positive degradation. The next full walk retries the write.
		log.Printf("evidence watermark commit failed after a full verification: %v", err)
	}
	l.markFullVerifiedLocked()
	return nil
}

// VerifyIncremental extends the verified range by one bounded chunk.
//
// Complete verification used to mean re-reading the whole history, on a timer, every fifteen
// minutes. At 260 MB one pass takes minutes, so the timer could never keep up and the pass
// itself became a permanent CPU load. The walk now starts at the authenticated watermark and
// ends at the authenticated checkpoint, so its cost is proportional to what has been written
// since the last pass - milliseconds once it has caught up - while every record is still
// verified exactly once, in order, by one pass or another.
//
// The checkpoint, the watermark and the ledger size are read together under the ledger lock, so
// an append cannot move them between the reads. The walk then runs on the captured size outside
// the lock - the append path is never blocked, and the walk can never read a record an append is
// still writing. A rotation that replaced the chain while the walk ran is recognized by the
// generation token and is not treated as damage.
func (l *EvidenceLedger) VerifyIncremental() error {
	l.mu.Lock()
	if l.integrityErr != nil {
		err := l.integrityErr
		l.mu.Unlock()
		return err
	}
	maxBytes := l.effectiveMaxBytesLocked()
	chunk := l.incrementalChunk
	if chunk == 0 {
		chunk = evidenceIncrementalChunkRecords
	}
	generation := l.generation
	sequence := l.sequence
	headHash := l.headHash
	snapshotSize := l.expectedSize

	checkpoint, err := readEvidenceCheckpoint(l.headPath, l.crypto)
	if err != nil {
		l.mu.Unlock()
		if errors.Is(err, os.ErrNotExist) && sequence == 0 && snapshotSize == 0 {
			// An empty ledger has no checkpoint to authenticate yet. That is the normal state
			// between construction and the first append, not an integrity failure.
			return nil
		}
		return l.recordIntegrity(fmt.Errorf("evidence checkpoint: %w", err))
	}
	if checkpoint.Version != evidenceRecordVersion {
		l.mu.Unlock()
		return l.recordIntegrity(errors.New("evidence checkpoint has an unsupported version"))
	}
	if checkpoint.Sequence != sequence || checkpoint.HeadHash != headHash {
		// The checkpoint on disk is not the one the trusted writer just sealed; the ledger lock
		// rules out a concurrent append, so this is an external change.
		l.mu.Unlock()
		return l.recordIntegrity(errors.New("evidence checkpoint does not match the trusted writer state"))
	}

	from := uint64(1)
	prev := ""
	if mark, markErr := l.readWatermark(); markErr == nil {
		from = mark.Sequence + 1
		prev = mark.HeadHash
	}
	l.mu.Unlock()

	if from > checkpoint.Sequence {
		l.mu.Lock()
		defer l.mu.Unlock()
		// Only call the coverage complete if the chain that was just covered is still the live
		// one; a rotation in the meantime already reset the coverage state.
		if l.generation == generation {
			l.markFullVerifiedLocked()
		}
		return nil
	}
	to := from + chunk - 1
	if to > checkpoint.Sequence {
		to = checkpoint.Sequence
	}

	head, walked, _, _, err := verifyEvidenceChain(l.path, l.publicKey, l.crypto, maxBytes,
		evidenceWalkBounds{From: from, To: to, PrevHash: prev, SnapshotSize: snapshotSize})
	if err != nil {
		// A rotation replaces the ledger while the walk runs. That is a new chain, not evidence
		// of damage, so it must not quarantine the ledger; the next pass covers the fresh chain.
		l.mu.Lock()
		rotated := l.generation != generation
		l.mu.Unlock()
		if rotated {
			return nil
		}
		return l.recordIntegrity(err)
	}

	l.mu.Lock()
	if l.generation != generation {
		l.mu.Unlock()
		return nil
	}
	if walked != to {
		l.mu.Unlock()
		// Not a lock-held record: appended above the snapshot boundary. Reading fewer verified
		// records than the captured checkpoint seals means the ledger shrank behind the writer.
		return l.recordIntegrity(fmt.Errorf("evidence ledger holds %d records, fewer than the verified range ends at", walked))
	}
	if err := l.writeWatermark(evidenceWatermark{Version: evidenceRecordVersion, Sequence: to, HeadHash: head}); err != nil {
		// A watermark is a durable coverage hint, not the chain's integrity: the records were
		// verified just now. Failing the pass as an integrity error quarantined a healthy
		// ledger because a file could not be written, and the whole following pass would have
		// had to re-read the history from the start.
		log.Printf("evidence watermark commit failed for range %d..%d: %v", from, to, err)
	}
	if to == checkpoint.Sequence {
		l.markFullVerifiedLocked()
	} else {
		// Say exactly how far the chain has been covered instead of implying the whole of it.
		// A watermark that is behind means records exist that no pass has verified yet.
		l.verifyScope = fmt.Sprintf("partial:%d/%d", to, checkpoint.Sequence)
	}
	l.mu.Unlock()
	return nil
}
