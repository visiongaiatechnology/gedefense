package main

// POINT 4 / P4-T2: the checkpoint/push worker, the equivocation detector and the
// authenticated acknowledgement baseline of the witness engine
// (docs/POINT4-WITNESS.md §4, §5, §7).
//
// The engine is split across two files only to keep each one reviewable: the
// construction, the runtime loop and the bounded status projection live in
// witness.go, the per-cycle work (checkpoint, outbox push, ack persistence,
// fork/rollback detection) lives here. Both are additive and inert while the
// namespace is disabled.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	witnessAckSchema  = "vgt-gedefense-witness-ack-v1"
	witnessAckPurpose = "witness-ack"
)

// PushNow is the operator-triggered push. It creates a checkpoint when the queue
// is empty, then pushes the oldest pending entry regardless of its backoff.
func (e *WitnessEngine) PushNow(ctx context.Context) (WitnessReceipt, error) {
	if !e.opsMu.TryLock() {
		return WitnessReceipt{}, errWitnessBusy
	}
	defer e.opsMu.Unlock()
	e.mu.Lock()
	mode := e.settings.Mode
	disabled := !witnessModeActive(e.settings)
	failClosed := e.failClosed
	transport := e.transport
	e.mu.Unlock()
	if disabled {
		return WitnessReceipt{}, errWitnessDisabled
	}
	if mode != witnessModeHTTP || transport == nil {
		return WitnessReceipt{}, errors.New("witness push requires http mode")
	}
	if failClosed != "" {
		return WitnessReceipt{}, errors.New(failClosed)
	}
	if e.outbox == nil {
		return WitnessReceipt{}, errors.New("witness outbox is unavailable")
	}
	if e.outbox.depth() == 0 {
		if _, err := e.checkpointLocked(ctx); err != nil {
			return WitnessReceipt{}, err
		}
	}
	entry, ok := e.outbox.pendingFirst()
	if !ok {
		return WitnessReceipt{}, errors.New("no pending witness checkpoint")
	}
	return e.pushEntry(ctx, entry)
}

// checkpointLocked builds, signs and queues one checkpoint. The caller holds
// opsMu.
func (e *WitnessEngine) checkpointLocked(ctx context.Context) (WitnessCheckpoint, error) {
	_ = ctx
	e.mu.Lock()
	settings := e.settings
	failClosed := e.failClosed
	e.mu.Unlock()
	if !witnessModeActive(settings) {
		return WitnessCheckpoint{}, errWitnessDisabled
	}
	if failClosed != "" {
		return WitnessCheckpoint{}, errors.New(failClosed)
	}
	if settings.Mode == witnessModeHTTP && e.outbox != nil && e.outbox.full() {
		e.markOutboxFull()
		return WitnessCheckpoint{}, errWitnessOutboxFull
	}
	if e.cfg.Ledger == nil {
		return WitnessCheckpoint{}, errors.New("witness ledger is unavailable")
	}
	view, err := e.cfg.Ledger.Checkpoint()
	if err != nil {
		e.setLastError("evidence ledger is quarantined")
		return WitnessCheckpoint{}, errors.New("evidence ledger is quarantined")
	}
	e.observeHead(witnessHead{epoch: view.LedgerEpoch, sequence: view.Sequence, headHash: view.HeadHash})
	policy := e.cfg.Settings.Get()
	policyDigest, err := PolicyDigest(policy)
	if err != nil {
		return WitnessCheckpoint{}, errors.New("policy digest could not be computed")
	}
	bootPosture, bootDigest := e.bootPosture()
	sensorState := e.sensorState()
	checkpointID, err := NewWitnessCheckpointID()
	if err != nil {
		return WitnessCheckpoint{}, errors.New("checkpoint id could not be generated")
	}
	checkpoint := WitnessCheckpoint{
		Schema: WitnessCheckpointSchema, Version: witnessCheckpointVersion, NodeID: e.nodeID,
		CheckpointID: checkpointID, CreatedAt: e.now().UTC().Format(time.RFC3339),
		LedgerEpoch: view.LedgerEpoch, Sequence: view.Sequence, HeadHash: view.HeadHash,
		Records: view.Records, SigningKeyFP: view.PublicKeyFingerprint, BootPosture: bootPosture,
		BootPostureDigest: bootDigest, QuoteKind: witnessQuoteKindNone,
		PolicyRevision: policy.Revision, PolicyDigest: policyDigest,
		SensorState: sensorState, Challenge: "",
	}
	signed, err := SignWitnessCheckpoint(checkpoint, e.cfg.Ledger.WitnessCheckpointSigner())
	if err != nil {
		e.setLastError("checkpoint could not be signed")
		return WitnessCheckpoint{}, errors.New("checkpoint could not be signed")
	}
	if settings.Mode == witnessModeHTTP && e.outbox != nil {
		if _, err := e.outbox.enqueue(signed); err != nil {
			if errors.Is(err, errWitnessOutboxFull) {
				e.markOutboxFull()
			}
			e.setLastError("checkpoint could not be queued")
			return WitnessCheckpoint{}, errors.New("checkpoint could not be queued")
		}
	}
	e.mu.Lock()
	e.lastCheckpoint = &signed
	e.mu.Unlock()
	// The creation record is written after the signed artifact exists, so the
	// evidence chain names the exact checkpoint id it can be correlated with.
	e.recordEvent("info", "witness.checkpoint.created",
		"Signed out-of-band witness checkpoint created for the authenticated ledger head (epoch "+fmt.Sprint(signed.LedgerEpoch)+", sequence "+fmt.Sprint(signed.Sequence)+")")
	return signed, nil
}

// pushPendingLocked drains a bounded number of due entries. One cycle never
// spins: a broken witness is retried on the next ticker, not in a loop.
func (e *WitnessEngine) pushPendingLocked(ctx context.Context) {
	e.mu.Lock()
	mode := e.settings.Mode
	transport := e.transport
	e.mu.Unlock()
	if mode != witnessModeHTTP || transport == nil || e.outbox == nil {
		return
	}
	for processed := 0; processed < 4; processed++ {
		entry, ok := e.outbox.nextDue(e.now())
		if !ok {
			return
		}
		if _, err := e.pushEntry(ctx, entry); err != nil {
			return
		}
	}
}

// pushEntry performs one challenge/checkpoint/receipt exchange for one entry.
func (e *WitnessEngine) pushEntry(ctx context.Context, entry witnessOutboxEntry) (WitnessReceipt, error) {
	e.mu.Lock()
	transport := e.transport
	settings := e.settings
	e.mu.Unlock()
	if transport == nil || e.outbox == nil {
		return WitnessReceipt{}, errors.New("witness transport is unavailable")
	}
	if e.cfg.Ledger == nil {
		return WitnessReceipt{}, errors.New("witness ledger is unavailable")
	}
	challenge, err := transport.Challenge(ctx)
	if err != nil {
		e.notePushFailure(entry, err)
		return WitnessReceipt{}, err
	}
	checkpoint := entry.Checkpoint
	checkpoint.Challenge = challenge
	signed, err := SignWitnessCheckpoint(checkpoint, e.cfg.Ledger.WitnessCheckpointSigner())
	if err != nil {
		e.notePushFailure(entry, &witnessClientError{reason: "checkpoint could not be re-signed", permanent: true})
		return WitnessReceipt{}, errors.New("checkpoint could not be re-signed")
	}
	if err := e.outbox.replaceCheckpoint(entry.LocalSeq, signed); err != nil {
		e.notePushFailure(entry, &witnessClientError{reason: "outbox could not store the fresh signature", permanent: true})
		return WitnessReceipt{}, errors.New("witness outbox write failed")
	}
	entry.Checkpoint = signed
	receipt, err := transport.Push(ctx, signed)
	if err != nil {
		e.notePushFailure(entry, err)
		return WitnessReceipt{}, err
	}
	if err := e.outbox.ack(entry.LocalSeq); err != nil {
		e.notePushFailure(entry, &witnessClientError{reason: "outbox acknowledgement could not be persisted", permanent: true})
		return WitnessReceipt{}, errors.New("witness outbox write failed")
	}
	e.recordAck(receipt, signed)
	e.mu.Lock()
	e.failures = 0
	e.degraded = false
	e.lastError = ""
	e.mu.Unlock()
	_ = settings
	e.recordEvent("info", "witness.acked",
		"Out-of-band witness acknowledged the checkpoint (witness_sequence "+fmt.Sprint(receipt.WitnessSeq)+")")
	return receipt, nil
}

// notePushFailure persists the attempt counter and the backoff. A permanent or
// authorization failure is not retried in a storm; network and 5xx failures use
// the bounded exponential backoff.
func (e *WitnessEngine) notePushFailure(entry witnessOutboxEntry, err error) {
	e.mu.Lock()
	settings := e.settings
	e.failures++
	failures := e.failures
	e.mu.Unlock()
	backoff := time.Duration(settings.RetryBackoffSeconds) * time.Second
	attempts := entry.Attempts + 1
	next := e.now().Add(backoff)
	if witnessPermanent(err) || witnessAuthFailure(err) {
		// A 4xx/pin/auth answer is an operator problem, not a transient one. Push
		// it far enough out that the queue cannot become a retry storm, but keep
		// the evidence: the entry stays pending and fail-closed.
		next = e.now().Add(backoff * 10)
	} else {
		for i := 1; i < attempts && i < 8; i++ {
			next = next.Add(backoff)
		}
	}
	if cap := e.now().Add(time.Hour); next.After(cap) {
		next = cap
	}
	if e.outbox != nil {
		if err := e.outbox.recordAttempt(entry.LocalSeq, attempts, next); err != nil {
			e.setLastError("witness outbox write failed")
		}
	}
	reason := "witness request failed"
	if witnessAuthFailure(err) {
		reason = "witness authorization or pin was rejected"
	} else if witnessPermanent(err) {
		reason = "witness request was permanently rejected"
	}
	e.mu.Lock()
	e.lastError = reason
	if failures >= settings.DegradeAfterFailures {
		e.degraded = true
	}
	e.mu.Unlock()
	e.recordEventOnce("push-failed", "warning", "witness.push.failed",
		"An out-of-band witness push failed and stays queued; the local evidence chain is unaffected")
}

// recordAck persists the monotonic acknowledgement baseline. The epoch, sequence
// and head are taken from the exact checkpoint the receipt binds, not from the
// newest checkpoint in memory: when a backlog is drained, the acknowledged head
// is the queued one.
func (e *WitnessEngine) recordAck(receipt WitnessReceipt, checkpoint WitnessCheckpoint) {
	e.mu.Lock()
	previous := e.ack
	e.ack.LastWitnessID = receipt.WitnessID
	e.ack.LastWitnessSeq = receipt.WitnessSeq
	e.ack.LastCheckpointID = receipt.CheckpointID
	e.ack.LastAcceptedAt = receipt.AcceptedAt
	e.ack.LastEpoch = checkpoint.LedgerEpoch
	e.ack.LastSequence = checkpoint.Sequence
	e.ack.LastHeadHash = checkpoint.HeadHash
	ack := e.ack
	path := e.cfg.AckPath
	storage := e.cfg.Storage
	e.mu.Unlock()
	if path != "" && storage != nil {
		if err := saveWitnessAckState(path, storage, ack); err != nil {
			e.setLastError("witness acknowledgement baseline could not be persisted")
			e.mu.Lock()
			e.ack = previous
			e.mu.Unlock()
			return
		}
	}
}

// observeHead compares a checkpoint head with the last observed and last
// acknowledged triple. Rotation (epoch+1) is not an alarm; a lower epoch or
// sequence is a rollback and the same (epoch, sequence) with another head is a
// fork.
func (e *WitnessEngine) observeHead(head witnessHead) {
	e.mu.Lock()
	previous := e.observed
	ack := e.ack
	e.mu.Unlock()
	kind := ""
	if previous != nil {
		kind = compareWitnessHeads(*previous, head)
	}
	if kind == "" && ack.LastHeadHash != "" && ack.LastSequence > 0 {
		kind = compareWitnessHeads(witnessHead{epoch: ack.LastEpoch, sequence: ack.LastSequence, headHash: ack.LastHeadHash}, head)
	}
	e.mu.Lock()
	if kind == "" || e.observed == nil || witnessHeadAdvances(*e.observed, head) {
		copy := head
		e.observed = &copy
	}
	e.mu.Unlock()
	if kind != "" {
		e.flagEquivocation(kind)
	}
}

// witnessHeadAdvances reports whether head is at or beyond previous.
func witnessHeadAdvances(previous, head witnessHead) bool {
	if head.epoch != previous.epoch {
		return head.epoch > previous.epoch
	}
	return head.sequence >= previous.sequence
}

// compareWitnessHeads returns "fork", "rollback" or "".
func compareWitnessHeads(previous, head witnessHead) string {
	if head.epoch < previous.epoch {
		return "rollback"
	}
	if head.epoch > previous.epoch {
		return "" // a rotation is legitimate
	}
	if head.sequence < previous.sequence {
		return "rollback"
	}
	if head.sequence == previous.sequence && previous.headHash != "" && head.headHash != "" && head.headHash != previous.headHash {
		return "fork"
	}
	return ""
}

// flagEquivocation publishes one critical record. The evidence is always
// written; the alarm (event, incident) and the optional P5 trigger are the parts
// the operator controls.
func (e *WitnessEngine) flagEquivocation(kind string) {
	e.mu.Lock()
	already := e.equivocation
	now := e.now()
	if !already {
		e.equivocation = true
		at := now
		e.equivocationAt = &at
		e.equivocationKind = kind
	}
	settings := e.settings
	state := e.cfg.State
	lockdown := e.cfg.Lockdown
	previous := e.ack
	e.ack.Equivocation = true
	e.ack.EquivocationAt = e.equivocationAt
	e.ack.EquivocationKind = kind
	ack := e.ack
	path := e.cfg.AckPath
	storage := e.cfg.Storage
	e.mu.Unlock()
	if already {
		return
	}
	if path != "" && storage != nil {
		if err := saveWitnessAckState(path, storage, ack); err != nil {
			e.setLastError("witness acknowledgement baseline could not be persisted")
			e.mu.Lock()
			e.ack = previous
			e.mu.Unlock()
		}
	}
	summary := "Witness checkpoints disagree about the evidence chain (" + witnessBoundText(kind, 32) + "): epoch/sequence/head no longer match the last acknowledged or observed checkpoint"
	if settings.EquivocationAlarm && state != nil {
		state.AddEvent(Event{Severity: "critical", Kind: "witness.equivocation", Source: "witness", Message: summary})
		state.AddIncident(XDRIncident{
			ID: randomID(), Time: now, Severity: "critical", Score: 100,
			RuleIDs: []string{"WITNESS.EQUIVOCATION"}, Categories: []string{"witness"},
			Process: "gedefense-control", Summary: summary, Decision: "alert", Action: "none", Outcome: "alerted",
		})
	} else if state != nil {
		_ = state.RecordEvidence(EvidenceRecord{
			Severity: "critical", Kind: "witness.equivocation", Source: "witness", Message: summary,
		})
	}
	if settings.TriggerLockdownOnEquivocation && lockdown != nil {
		fingerprint := witnessEquivocationFingerprint(kind)
		if err := lockdown.TriggerWitnessEquivocation(fingerprint); err != nil {
			e.setLastError("witness equivocation lockdown trigger was not accepted")
		}
	}
}

// witnessEquivocationFingerprint is a bounded, non-reversible dedupe identity.
func witnessEquivocationFingerprint(kind string) string {
	digest := sha256.Sum256([]byte("witness-equivocation\x00" + kind))
	return fmt.Sprintf("%x", digest[:8])
}

// witnessAckState is the authenticated monotonicity baseline. It stores hashes,
// ids and counters only - never a token, path or key.
type witnessAckState struct {
	Schema           string     `json:"schema"`
	LastWitnessID    string     `json:"last_witness_id,omitempty"`
	LastWitnessSeq   uint64     `json:"last_witness_seq"`
	LastCheckpointID string     `json:"last_checkpoint_id,omitempty"`
	LastAcceptedAt   string     `json:"last_accepted_at,omitempty"`
	LastEpoch        uint64     `json:"last_ledger_epoch"`
	LastSequence     uint64     `json:"last_sequence"`
	LastHeadHash     string     `json:"last_head_hash,omitempty"`
	Equivocation     bool       `json:"equivocation,omitempty"`
	EquivocationAt   *time.Time `json:"equivocation_at,omitempty"`
	EquivocationKind string     `json:"equivocation_kind,omitempty"`
}

func loadWitnessAckState(path string, cipher *StorageCipher) (witnessAckState, error) {
	state := witnessAckState{Schema: witnessAckSchema}
	if path == "" || cipher == nil {
		return state, nil
	}
	if !filepath.IsAbs(path) {
		return state, errors.New("witness ack path must be absolute")
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	plaintext, _, err := cipher.Decrypt(path, witnessAckPurpose, raw, nil)
	if err != nil {
		return state, err
	}
	var decoded witnessAckState
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil || decoded.Schema != witnessAckSchema {
		return state, errors.New("witness ack document is malformed")
	}
	if decoded.LastWitnessSeq > witnessCheckpointMaxCounter || decoded.LastEpoch > witnessCheckpointMaxCounter || decoded.LastSequence > witnessCheckpointMaxCounter {
		return state, errors.New("witness ack counters exceed their JSON-safe bound")
	}
	if decoded.LastCheckpointID != "" && (len(decoded.LastCheckpointID) != 2*witnessCheckpointIDBytes || !validWitnessLowerHex(decoded.LastCheckpointID)) {
		return state, errors.New("witness ack checkpoint id is invalid")
	}
	if decoded.LastHeadHash != "" && !validWitnessDigest(decoded.LastHeadHash) {
		return state, errors.New("witness ack head hash is invalid")
	}
	return decoded, nil
}

func saveWitnessAckState(path string, cipher *StorageCipher, state witnessAckState) error {
	if path == "" || cipher == nil {
		return nil
	}
	if !filepath.IsAbs(path) {
		return errors.New("witness ack path must be absolute")
	}
	state.Schema = witnessAckSchema
	plaintext, err := json.Marshal(state)
	if err != nil {
		return err
	}
	sealed, err := cipher.Encrypt(path, witnessAckPurpose, 0, plaintext)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicWriteFile(path, append(sealed, '\n'), 0o600)
}

// ------------------------------------------------------------------- export API

// witnessHead is the triple the equivocation detector compares.
type witnessHead struct {
	epoch    uint64
	sequence uint64
	headHash string
}
