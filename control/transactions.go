// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	transactionSchema     = "vgt-gedefense-transactions-v1"
	transactionPurpose    = "security-transactions"
	transactionMaxBytes   = int64(16 << 20)
	transactionMaxRecords = 2048
	transactionPreviewTTL = 15 * time.Minute
)

type TransactionApplier interface {
	Type() string
	Preview(payload json.RawMessage) (plan json.RawMessage, before json.RawMessage, err error)
	Apply(plan json.RawMessage, before json.RawMessage) (after json.RawMessage, err error)
	Verify(plan json.RawMessage, after json.RawMessage) error
	Reverse(before json.RawMessage, after json.RawMessage) error
}

type TransactionExclusivity interface {
	ExclusiveTransactionType() bool
}

type SecurityTransaction struct {
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	Summary      string          `json:"summary"`
	Reason       string          `json:"reason"`
	Status       string          `json:"status"`
	CreatedAt    time.Time       `json:"created_at"`
	AppliedAt    *time.Time      `json:"applied_at,omitempty"`
	ReversedAt   *time.Time      `json:"reversed_at,omitempty"`
	Plan         json.RawMessage `json:"plan"`
	Before       json.RawMessage `json:"before"`
	After        json.RawMessage `json:"after,omitempty"`
	PreviewHash  string          `json:"preview_hash"`
	FailureStage string          `json:"failure_stage,omitempty"`
}

type TransactionView struct {
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	Summary      string          `json:"summary"`
	Reason       string          `json:"reason"`
	Status       string          `json:"status"`
	CreatedAt    time.Time       `json:"created_at"`
	AppliedAt    *time.Time      `json:"applied_at,omitempty"`
	ReversedAt   *time.Time      `json:"reversed_at,omitempty"`
	Plan         json.RawMessage `json:"plan,omitempty"`
	PreviewHash  string          `json:"preview_hash"`
	FailureStage string          `json:"failure_stage,omitempty"`
}

type TransactionStatus struct {
	Healthy          bool              `json:"healthy"`
	Revision         uint64            `json:"revision"`
	Count            int               `json:"count"`
	RecoveryRequired bool              `json:"recovery_required"`
	Transactions     []TransactionView `json:"transactions"`
	Error            string            `json:"error,omitempty"`
}

type transactionStore struct {
	Schema   string                `json:"schema"`
	Revision uint64                `json:"revision"`
	Records  []SecurityTransaction `json:"records"`
}

type TransactionEngine struct {
	mu        sync.Mutex
	path      string
	storage   *StorageCipher
	revision  uint64
	records   []SecurityTransaction
	appliers  map[string]TransactionApplier
	integrity error
	evidence  func(EvidenceRecord) error
	now       func() time.Time
}

type RecoveryRequiredError struct {
	Stage string
	Err   error
}

func (e *RecoveryRequiredError) Error() string {
	return fmt.Sprintf("transaction recovery required at %s: %v", e.Stage, e.Err)
}

func (e *RecoveryRequiredError) Unwrap() error {
	return e.Err
}

func NewTransactionEngine(
	path string,
	storage *StorageCipher,
	evidence func(EvidenceRecord) error,
	appliers ...TransactionApplier,
) (*TransactionEngine, error) {
	if storage == nil {
		return nil, errors.New("transaction storage encryption is required")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("transaction store path must be absolute")
	}
	engine := &TransactionEngine{
		path: path, storage: storage, evidence: evidence, now: func() time.Time { return time.Now().UTC() },
		records: make([]SecurityTransaction, 0), appliers: make(map[string]TransactionApplier),
	}
	for _, applier := range appliers {
		if applier == nil || applier.Type() == "" {
			return nil, errors.New("transaction applier is invalid")
		}
		if _, exists := engine.appliers[applier.Type()]; exists {
			return nil, fmt.Errorf("duplicate transaction applier: %s", applier.Type())
		}
		engine.appliers[applier.Type()] = applier
	}
	if len(engine.appliers) == 0 {
		return nil, errors.New("at least one transaction applier is required")
	}
	if err := engine.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		engine.integrity = err
	}
	return engine, nil
}

func (e *TransactionEngine) load() error {
	raw, err := readBoundedPrivateFile(e.path, transactionMaxBytes)
	if err != nil {
		return err
	}
	envelope, err := decodeEncryptedStorageEnvelope(bytes.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("transaction store envelope: %w", err)
	}
	expectedSequence := envelope.Sequence
	plaintext, legacy, err := e.storage.Decrypt(
		e.path, transactionPurpose, raw, &expectedSequence,
	)
	if err != nil {
		return fmt.Errorf("transaction store authentication failed: %w", err)
	}
	if legacy {
		return errors.New("unencrypted transaction history is rejected")
	}
	store, err := decodeTransactionStore(plaintext)
	if err != nil {
		return err
	}
	if store.Revision != expectedSequence {
		return errors.New("transaction store revision binding mismatch")
	}
	for index := range store.Records {
		record := &store.Records[index]
		if record.Status == "applying" || record.Status == "reversing" {
			record.Status = "recovery_required"
			record.FailureStage = "interrupted"
		}
	}
	e.revision = store.Revision
	e.records = store.Records
	return nil
}

func decodeTransactionStore(raw []byte) (transactionStore, error) {
	var store transactionStore
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&store); err != nil {
		return transactionStore{}, fmt.Errorf("transaction store decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return transactionStore{}, errors.New("transaction store contains trailing data")
	}
	if store.Schema != transactionSchema || store.Revision == 0 ||
		len(store.Records) > transactionMaxRecords {
		return transactionStore{}, errors.New("transaction store metadata is invalid")
	}
	seen := make(map[string]struct{}, len(store.Records))
	for _, record := range store.Records {
		if err := validateTransactionRecord(record); err != nil {
			return transactionStore{}, err
		}
		if _, exists := seen[record.ID]; exists {
			return transactionStore{}, errors.New("transaction store contains duplicate IDs")
		}
		seen[record.ID] = struct{}{}
	}
	return store, nil
}

func validateTransactionRecord(record SecurityTransaction) error {
	if !validTransactionID(record.ID) || record.Type == "" || len(record.Type) > 64 ||
		len(record.Summary) < 3 || len(record.Summary) > 160 ||
		len(record.Reason) < 3 || len(record.Reason) > 240 ||
		record.CreatedAt.IsZero() || len(record.Plan) == 0 || len(record.Plan) > 64<<10 ||
		len(record.Before) == 0 || len(record.Before) > 64<<10 ||
		len(record.After) > 64<<10 || len(record.PreviewHash) != 64 {
		return errors.New("transaction record violates structural bounds")
	}
	switch record.Status {
	case "previewed", "applying", "applied", "reversing", "reversed", "failed", "recovery_required":
	default:
		return errors.New("transaction record contains an invalid status")
	}
	providedHash, err := hex.DecodeString(record.PreviewHash)
	if err != nil {
		return errors.New("transaction record contains an invalid preview digest")
	}
	expectedHash, err := hex.DecodeString(
		transactionPreviewHash(record.Type, record.Plan, record.Before),
	)
	if err != nil || subtle.ConstantTimeCompare(providedHash, expectedHash) != 1 {
		return errors.New("transaction record preview digest mismatch")
	}
	return nil
}

func validTransactionID(id string) bool {
	if len(id) != 19 || !strings.HasPrefix(id, "TX-") {
		return false
	}
	for _, character := range id[3:] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func transactionPreviewHash(kind string, plan, before json.RawMessage) string {
	digest := sha256.New()
	digest.Write([]byte("VGT-GEDEFENSE-TRANSACTION-PREVIEW-V1\x00"))
	digest.Write([]byte(kind))
	digest.Write([]byte{0})
	digest.Write(plan)
	digest.Write([]byte{0})
	digest.Write(before)
	return hex.EncodeToString(digest.Sum(nil))
}

func (e *TransactionEngine) persistLocked() error {
	if len(e.records) > transactionMaxRecords {
		return errors.New("transaction history capacity exhausted")
	}
	nextRevision := e.revision + 1
	store := transactionStore{
		Schema: transactionSchema, Revision: nextRevision,
		Records: append([]SecurityTransaction(nil), e.records...),
	}
	plaintext, err := json.Marshal(store)
	if err != nil {
		return err
	}
	if int64(len(plaintext)) > transactionMaxBytes {
		return errors.New("transaction history size budget exhausted")
	}
	sealed, err := e.storage.Encrypt(e.path, transactionPurpose, nextRevision, plaintext)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.path), 0o700); err != nil {
		return err
	}
	if err := atomicWriteFile(e.path, sealed, 0o600); err != nil {
		return err
	}
	e.revision = nextRevision
	return nil
}

func (e *TransactionEngine) Preview(
	kind, summary, reason string,
	payload json.RawMessage,
) (TransactionView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.readyLocked(); err != nil {
		return TransactionView{}, err
	}
	if len(e.records) >= transactionMaxRecords {
		return TransactionView{}, errors.New("transaction history capacity exhausted")
	}
	if len(summary) < 3 || len(summary) > 160 || len(reason) < 3 || len(reason) > 240 {
		return TransactionView{}, errors.New("transaction summary or reason is outside bounds")
	}
	if len(payload) == 0 || len(payload) > 16<<10 {
		return TransactionView{}, errors.New("transaction payload is outside bounds")
	}
	applier, exists := e.appliers[kind]
	if !exists {
		return TransactionView{}, errors.New("transaction type is not supported")
	}
	exclusive := true
	if policy, ok := applier.(TransactionExclusivity); ok {
		exclusive = policy.ExclusiveTransactionType()
	}
	if exclusive {
		for _, existing := range e.records {
			if existing.Type == kind &&
				(existing.Status == "applied" || existing.Status == "applying" ||
					existing.Status == "reversing" || existing.Status == "recovery_required") {
				return TransactionView{}, errors.New(
					"an active transaction of this type must be reversed first",
				)
			}
		}
	}
	plan, before, err := applier.Preview(payload)
	if err != nil {
		return TransactionView{}, err
	}
	if !json.Valid(plan) || !json.Valid(before) || len(plan) > 64<<10 || len(before) > 64<<10 {
		return TransactionView{}, errors.New("transaction applier returned an invalid preview")
	}
	record := SecurityTransaction{
		ID: "TX-" + randomID(), Type: kind, Summary: summary, Reason: reason,
		Status: "previewed", CreatedAt: e.now(), Plan: append([]byte(nil), plan...),
		Before:      append([]byte(nil), before...),
		PreviewHash: transactionPreviewHash(kind, plan, before),
	}
	e.records = append(e.records, record)
	if err := e.persistLocked(); err != nil {
		e.records = e.records[:len(e.records)-1]
		e.integrity = err
		return TransactionView{}, err
	}
	return transactionView(record, true), nil
}

func (e *TransactionEngine) Apply(id, confirmation string) (TransactionView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.readyLocked(); err != nil {
		return TransactionView{}, err
	}
	index := e.indexLocked(id)
	if index < 0 {
		return TransactionView{}, errors.New("transaction not found")
	}
	record := e.records[index]
	if record.Status != "previewed" {
		return TransactionView{}, errors.New("transaction is not in previewed state")
	}
	if e.now().Sub(record.CreatedAt) > transactionPreviewTTL {
		return TransactionView{}, errors.New("transaction preview expired")
	}
	expectedConfirmation := "APPLY " + record.ID
	if subtle.ConstantTimeCompare([]byte(confirmation), []byte(expectedConfirmation)) != 1 {
		return TransactionView{}, errors.New("transaction confirmation rejected")
	}
	if err := e.commitEvidenceLocked(record, "transaction.apply.intent", "high"); err != nil {
		return TransactionView{}, err
	}
	applier := e.appliers[record.Type]
	record.Status = "applying"
	e.records[index] = record
	if err := e.persistLocked(); err != nil {
		e.integrity = err
		return TransactionView{}, err
	}

	after, applyErr := applier.Apply(record.Plan, record.Before)
	if applyErr == nil {
		applyErr = applier.Verify(record.Plan, after)
	}
	if applyErr != nil {
		return e.failApplyLocked(index, record, after, applier, applyErr)
	}

	now := e.now()
	record.Status = "applied"
	record.AppliedAt = &now
	record.After = append([]byte(nil), after...)
	record.FailureStage = ""
	e.records[index] = record
	if err := e.persistLocked(); err != nil {
		reverseErr := applier.Reverse(record.Before, record.After)
		record.Status = "failed"
		record.FailureStage = "commit"
		if reverseErr != nil {
			record.Status = "recovery_required"
			record.FailureStage = "commit_and_reverse"
		}
		e.records[index] = record
		e.integrity = errors.Join(err, reverseErr)
		return transactionView(record, false), e.integrity
	}
	return transactionView(record, false), nil
}

func (e *TransactionEngine) failApplyLocked(
	index int,
	record SecurityTransaction,
	after json.RawMessage,
	applier TransactionApplier,
	applyErr error,
) (TransactionView, error) {
	record.After = append([]byte(nil), after...)
	record.Status = "failed"
	record.FailureStage = "apply_or_verify"
	var recovery *RecoveryRequiredError
	if errors.As(applyErr, &recovery) {
		record.Status = "recovery_required"
		record.FailureStage = recovery.Stage
	} else if len(after) > 0 {
		if reverseErr := applier.Reverse(record.Before, after); reverseErr != nil {
			record.Status = "recovery_required"
			record.FailureStage = "verify_and_reverse"
			applyErr = errors.Join(applyErr, reverseErr)
		}
	}
	e.records[index] = record
	if persistErr := e.persistLocked(); persistErr != nil {
		e.integrity = persistErr
		applyErr = errors.Join(applyErr, persistErr)
	}
	return transactionView(record, false), applyErr
}

func (e *TransactionEngine) Reverse(id, confirmation string) (TransactionView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.integrity != nil {
		return TransactionView{}, e.integrity
	}
	index := e.indexLocked(id)
	if index < 0 {
		return TransactionView{}, errors.New("transaction not found")
	}
	record := e.records[index]
	if record.Status != "applied" && record.Status != "recovery_required" {
		return TransactionView{}, errors.New("transaction is not reversible")
	}
	expectedConfirmation := "REVERSE " + record.ID
	if subtle.ConstantTimeCompare([]byte(confirmation), []byte(expectedConfirmation)) != 1 {
		return TransactionView{}, errors.New("transaction confirmation rejected")
	}
	if err := e.commitEvidenceLocked(record, "transaction.reverse.intent", "critical"); err != nil {
		return TransactionView{}, err
	}
	applier, exists := e.appliers[record.Type]
	if !exists {
		return TransactionView{}, errors.New("transaction applier is unavailable")
	}
	record.Status = "reversing"
	e.records[index] = record
	if err := e.persistLocked(); err != nil {
		e.integrity = err
		return TransactionView{}, err
	}
	if err := applier.Reverse(record.Before, record.After); err != nil {
		record.Status = "recovery_required"
		record.FailureStage = "reverse"
		e.records[index] = record
		if persistErr := e.persistLocked(); persistErr != nil {
			e.integrity = persistErr
			err = errors.Join(err, persistErr)
		}
		return transactionView(record, false), err
	}
	now := e.now()
	record.Status = "reversed"
	record.ReversedAt = &now
	record.FailureStage = ""
	e.records[index] = record
	if err := e.persistLocked(); err != nil {
		e.integrity = err
		return transactionView(record, false), err
	}
	return transactionView(record, false), nil
}

func (e *TransactionEngine) ReconcileApplied() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.readyLocked(); err != nil {
		return err
	}
	for index := range e.records {
		record := e.records[index]
		if record.Status != "applied" {
			continue
		}
		applier, exists := e.appliers[record.Type]
		if !exists {
			return errors.New("active transaction applier is unavailable")
		}
		if err := applier.Verify(record.Plan, record.After); err == nil {
			continue
		}
		if err := e.commitEvidenceLocked(
			record, "transaction.reconcile.intent", "high",
		); err != nil {
			return err
		}
		record.Status = "applying"
		record.FailureStage = "startup_reconcile"
		e.records[index] = record
		if err := e.persistLocked(); err != nil {
			e.integrity = err
			return err
		}
		after, err := applier.Apply(record.Plan, record.Before)
		if err == nil {
			err = applier.Verify(record.Plan, after)
		}
		if err != nil {
			record.Status = "recovery_required"
			record.FailureStage = "startup_reconcile"
			record.After = append([]byte(nil), after...)
			e.records[index] = record
			if persistErr := e.persistLocked(); persistErr != nil {
				e.integrity = persistErr
				err = errors.Join(err, persistErr)
			}
			return err
		}
		record.Status = "applied"
		record.FailureStage = ""
		record.After = append([]byte(nil), after...)
		e.records[index] = record
		if err := e.persistLocked(); err != nil {
			e.integrity = err
			return err
		}
	}
	return nil
}

func (e *TransactionEngine) VerifyApplied() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.readyLocked(); err != nil {
		return err
	}
	for index := range e.records {
		record := e.records[index]
		if record.Status != "applied" {
			continue
		}
		applier, exists := e.appliers[record.Type]
		if !exists {
			return errors.New("active transaction applier is unavailable")
		}
		if err := applier.Verify(record.Plan, record.After); err != nil {
			record.Status = "recovery_required"
			record.FailureStage = "runtime_drift"
			e.records[index] = record
			evidenceErr := e.commitEvidenceLocked(
				record, "transaction.drift", "critical",
			)
			persistErr := e.persistLocked()
			if persistErr != nil {
				e.integrity = persistErr
			}
			return errors.Join(err, evidenceErr, persistErr)
		}
	}
	return nil
}

func runTransactionVerification(
	ctx context.Context,
	state *State,
	engine *TransactionEngine,
	interval time.Duration,
) {
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	reported := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := engine.VerifyApplied()
			if err != nil && !reported {
				reported = true
				state.AddEvent(Event{
					Severity: "critical", Kind: "transaction.runtime_drift",
					Source:  "transaction-engine",
					Message: "Applied security transaction drifted; new mutations are blocked",
				})
			}
			if err == nil {
				reported = false
			}
		}
	}
}

func (e *TransactionEngine) commitEvidenceLocked(
	record SecurityTransaction,
	kind, severity string,
) error {
	if e.evidence == nil {
		return errors.New("mandatory transaction evidence sink is unavailable")
	}
	return e.evidence(EvidenceRecord{
		Severity: severity, Kind: kind, Source: "transaction-engine",
		Message: "Durable security transaction authorized",
		Target:  record.ID + " " + record.Type,
	})
}

func (e *TransactionEngine) readyLocked() error {
	if e.integrity != nil {
		return e.integrity
	}
	for _, record := range e.records {
		if record.Status == "recovery_required" {
			return errors.New("transaction recovery is required before new mutations")
		}
	}
	return nil
}

func (e *TransactionEngine) indexLocked(id string) int {
	for index := range e.records {
		if e.records[index].ID == id {
			return index
		}
	}
	return -1
}

func transactionView(record SecurityTransaction, includePlan bool) TransactionView {
	view := TransactionView{
		ID: record.ID, Type: record.Type, Summary: record.Summary, Reason: record.Reason,
		Status: record.Status, CreatedAt: record.CreatedAt, AppliedAt: record.AppliedAt,
		ReversedAt: record.ReversedAt, PreviewHash: record.PreviewHash,
		FailureStage: record.FailureStage,
	}
	if includePlan {
		view.Plan = append([]byte(nil), record.Plan...)
	}
	return view
}

func (e *TransactionEngine) Status(limit int) TransactionStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit < 1 || limit > 500 {
		limit = 100
	}
	start := len(e.records) - limit
	if start < 0 {
		start = 0
	}
	views := make([]TransactionView, 0, len(e.records)-start)
	recovery := false
	for _, record := range e.records {
		if record.Status == "recovery_required" {
			recovery = true
			break
		}
	}
	for index := len(e.records) - 1; index >= start; index-- {
		record := e.records[index]
		views = append(views, transactionView(record, record.Status == "previewed"))
	}
	status := TransactionStatus{
		Healthy: e.integrity == nil && !recovery, Revision: e.revision,
		Count: len(e.records), RecoveryRequired: recovery, Transactions: views,
	}
	if e.integrity != nil {
		status.Error = "transaction history integrity unavailable"
	}
	return status
}

func (e *TransactionEngine) recordsByType(kind string) []SecurityTransaction {
	e.mu.Lock()
	defer e.mu.Unlock()
	records := make([]SecurityTransaction, 0)
	for _, record := range e.records {
		if record.Type != kind {
			continue
		}
		cloned := record
		cloned.Plan = append(json.RawMessage(nil), record.Plan...)
		cloned.Before = append(json.RawMessage(nil), record.Before...)
		cloned.After = append(json.RawMessage(nil), record.After...)
		records = append(records, cloned)
	}
	return records
}

func sortedJSONMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
