package main

// POINT 4 / P4-T2: Mode B - air-gapped export/import (docs/POINT4-WITNESS.md §5).
//
// Export is a deterministic JSON document {checkpoint, signature} plus the compact
// vgtw1:<base64url> form (≤2 KiB) an offline tool can turn into a QR code. It is
// verifiable without this process: schema, Ed25519 signature against the known
// public-key fingerprint and (epoch, sequence) monotonicity.
//
// Import accepts only signed witness receipts (or import confirmations) - never a
// command or policy channel. It verifies the pinned witness key, the
// checkpoint_id binding to a local export, the witness_seq monotonicity and the
// epoch/sequence monotonicity; every rejection has a precise evidence reason, and
// an import that regresses the ledger epoch or sequence also raises the rollback
// alarm.
//
// The receipt contract (schema, strict decoder and domain-separated signature
// verification) is the import artifact and therefore lives here; the
// authenticated acknowledgement baseline and the push worker live in
// witness_engine.go, and the hardened transport lives in witness_client.go.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	witnessExportSchema  = "vgt-gedefense-witness-export-v1"
	witnessExportVersion = 1
	// witnessExportCompactPrefix identifies the offline form.
	witnessExportCompactPrefix = "vgtw1:"
	// witnessExportMaxCompactBytes is the §5 target: one compact export fits in
	// 2 KiB, comfortably inside a QR symbol.
	witnessExportMaxCompactBytes = 2048
	// witnessExportMaxBytes bounds the JSON document an importer will decode.
	witnessExportMaxBytes = 16 << 10
)

// witnessExportPayload is the signed/compact subset of the export document.
type witnessExportPayload struct {
	Schema     string            `json:"schema"`
	Version    int               `json:"version"`
	Checkpoint WitnessCheckpoint `json:"checkpoint"`
	Signature  string            `json:"signature"`
}

// witnessExportDocument is the JSON form served by GET /api/v1/witness/export.
type witnessExportDocument struct {
	Schema     string            `json:"schema"`
	Version    int               `json:"version"`
	Checkpoint WitnessCheckpoint `json:"checkpoint"`
	Signature  string            `json:"signature"`
	Compact    string            `json:"compact"`
}

// BuildWitnessExport builds the deterministic export document and its compact
// form. Equal checkpoints always produce byte-identical exports.
func BuildWitnessExport(checkpoint WitnessCheckpoint) (witnessExportDocument, error) {
	if err := ValidateWitnessCheckpoint(checkpoint); err != nil {
		return witnessExportDocument{}, err
	}
	payload := witnessExportPayload{
		Schema: witnessExportSchema, Version: witnessExportVersion,
		Checkpoint: checkpoint, Signature: checkpoint.Signature,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return witnessExportDocument{}, err
	}
	compact := witnessExportCompactPrefix + base64.RawURLEncoding.EncodeToString(raw)
	if len(compact) > witnessExportMaxCompactBytes {
		return witnessExportDocument{}, errors.New("witness export exceeds the 2 KiB compact bound")
	}
	return witnessExportDocument{
		Schema: witnessExportSchema, Version: witnessExportVersion,
		Checkpoint: checkpoint, Signature: checkpoint.Signature, Compact: compact,
	}, nil
}

// EncodeWitnessExportJSON returns the canonical JSON form.
func EncodeWitnessExportJSON(document witnessExportDocument) ([]byte, error) {
	if err := validateWitnessExportDocument(document); err != nil {
		return nil, err
	}
	return json.Marshal(document)
}

// DecodeWitnessExportCompact parses the vgtw1 form for offline verification.
func DecodeWitnessExportCompact(compact string) (witnessExportDocument, error) {
	if len(compact) > witnessExportMaxCompactBytes || len(compact) <= len(witnessExportCompactPrefix) {
		return witnessExportDocument{}, errors.New("compact witness export is empty or oversized")
	}
	if compact[:len(witnessExportCompactPrefix)] != witnessExportCompactPrefix {
		return witnessExportDocument{}, errors.New("compact witness export has an unknown prefix")
	}
	raw, err := base64.RawURLEncoding.DecodeString(compact[len(witnessExportCompactPrefix):])
	if err != nil {
		return witnessExportDocument{}, errors.New("compact witness export is not canonical base64url")
	}
	if len(raw) > witnessExportMaxBytes {
		return witnessExportDocument{}, errors.New("compact witness export payload is oversized")
	}
	var payload witnessExportPayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return witnessExportDocument{}, errors.New("compact witness export is malformed")
	}
	document := witnessExportDocument{
		Schema: payload.Schema, Version: payload.Version,
		Checkpoint: payload.Checkpoint, Signature: payload.Signature,
	}
	if err := validateWitnessExportDocument(document); err != nil {
		return witnessExportDocument{}, err
	}
	return document, nil
}

// VerifyWitnessExport verifies a decoded export offline: schema, version,
// signature/checkpoint agreement and the Ed25519 checkpoint signature against the
// known public key. Sequence monotonicity is the caller's persisted state.
func VerifyWitnessExport(document witnessExportDocument, publicKey []byte) (WitnessCheckpoint, error) {
	if err := validateWitnessExportDocument(document); err != nil {
		return WitnessCheckpoint{}, err
	}
	if len(publicKey) != 32 {
		return WitnessCheckpoint{}, errors.New("witness export verification key is invalid")
	}
	if err := VerifyWitnessCheckpoint(document.Checkpoint, publicKey); err != nil {
		return WitnessCheckpoint{}, err
	}
	return document.Checkpoint, nil
}

// VerifyWitnessExportMonotonic verifies an export offline and enforces
// (ledger_epoch, sequence) monotonicity against the last export/receipt an
// offline verifier already accepted. A rotation (higher epoch) is legitimate; a
// lower epoch or a lower sequence inside the same epoch is refused, so an old
// chain generation cannot be replayed as current.
func VerifyWitnessExportMonotonic(document witnessExportDocument, publicKey []byte, lastEpoch, lastSequence uint64) (WitnessCheckpoint, error) {
	checkpoint, err := VerifyWitnessExport(document, publicKey)
	if err != nil {
		return WitnessCheckpoint{}, err
	}
	if checkpoint.LedgerEpoch < lastEpoch ||
		(checkpoint.LedgerEpoch == lastEpoch && checkpoint.Sequence < lastSequence) {
		return WitnessCheckpoint{}, errors.New("witness export regresses the known ledger epoch or sequence")
	}
	return checkpoint, nil
}

func validateWitnessExportDocument(document witnessExportDocument) error {
	if document.Schema != witnessExportSchema {
		return fmt.Errorf("witness export schema %q is not %q", document.Schema, witnessExportSchema)
	}
	if document.Version != witnessExportVersion {
		return fmt.Errorf("witness export version %d is not %d", document.Version, witnessExportVersion)
	}
	if document.Signature != document.Checkpoint.Signature {
		return errors.New("witness export signature does not match its checkpoint")
	}
	return ValidateWitnessCheckpoint(document.Checkpoint)
}

// ------------------------------------------------------------------ ack store

// ExportDocument returns the deterministic export for the current ledger head.
// It reuses the last checkpoint when it still seals the current head and creates
// one otherwise, so a GET never invents a stale export.
func (e *WitnessEngine) ExportDocument(ctx context.Context) (witnessExportDocument, error) {
	e.mu.Lock()
	settings := e.settings
	failClosed := e.failClosed
	last := e.lastCheckpoint
	e.mu.Unlock()
	if !witnessModeActive(settings) {
		return witnessExportDocument{}, errWitnessDisabled
	}
	if failClosed != "" {
		return witnessExportDocument{}, errors.New(failClosed)
	}
	checkpoint := last
	if checkpoint == nil || !e.checkpointSealsHead(*checkpoint) {
		created, err := e.CheckpointNow(ctx)
		if err != nil {
			return witnessExportDocument{}, err
		}
		checkpoint = &created
	}
	document, err := BuildWitnessExport(*checkpoint)
	if err != nil {
		return witnessExportDocument{}, err
	}
	e.mu.Lock()
	copy := *checkpoint
	e.lastExport = &copy
	e.mu.Unlock()
	e.recordEvent("info", "witness.export_created",
		"Air-gapped witness export created (compact form bounded to 2 KiB)")
	return document, nil
}

// checkpointSealsHead reports whether a checkpoint still names the live head.
func (e *WitnessEngine) checkpointSealsHead(checkpoint WitnessCheckpoint) bool {
	if e.cfg.Ledger == nil {
		return false
	}
	view, err := e.cfg.Ledger.Checkpoint()
	if err != nil {
		return false
	}
	return checkpoint.LedgerEpoch == view.LedgerEpoch && checkpoint.Sequence == view.Sequence && checkpoint.HeadHash == view.HeadHash
}

// ImportReceipt accepts only a verified signed witness receipt bound to a local
// export. Any rejection is recorded as witness.import_rejected with a precise,
// bounded reason; an epoch/sequence regression additionally raises the rollback
// alarm.
func (e *WitnessEngine) ImportReceipt(_ context.Context, raw []byte) (WitnessReceipt, error) {
	e.opsMu.Lock()
	defer e.opsMu.Unlock()
	e.mu.Lock()
	settings := e.settings
	failClosed := e.failClosed
	export := e.lastExport
	ack := e.ack
	e.mu.Unlock()
	if !witnessModeActive(settings) {
		return WitnessReceipt{}, errWitnessDisabled
	}
	if failClosed != "" {
		return WitnessReceipt{}, errors.New(failClosed)
	}
	receipt, err := decodeImportedReceipt(raw)
	if err != nil {
		e.rejectImport("receipt is malformed", err)
		return WitnessReceipt{}, err
	}
	if settings.PinnedServerKeyFile == "" {
		err := errors.New("witness import requires a pinned receipt key")
		e.rejectImport("no pinned witness receipt key is configured", err)
		return WitnessReceipt{}, err
	}
	pinned, err := loadWitnessPinnedReceiptKey(settings.PinnedServerKeyFile)
	if err != nil {
		e.rejectImport("pinned witness receipt key is unavailable", err)
		return WitnessReceipt{}, errors.New("pinned witness receipt key is unavailable")
	}
	if err := VerifyWitnessReceipt(receipt, pinned); err != nil {
		e.rejectImport("receipt signature does not verify", err)
		return WitnessReceipt{}, errors.New("witness receipt signature does not verify")
	}
	if export == nil {
		err := errors.New("no local witness export is known")
		e.rejectImport("no local export exists; export a checkpoint before importing a receipt", err)
		return WitnessReceipt{}, err
	}
	if receipt.CheckpointID != export.CheckpointID {
		err := errors.New("receipt does not bind the local export")
		e.rejectImport("receipt checkpoint id does not match the local export", err)
		return WitnessReceipt{}, err
	}
	if acceptedAt, parseErr := time.Parse(time.RFC3339, receipt.AcceptedAt); parseErr != nil || acceptedAt.After(e.now().Add(witnessFutureSkew)) {
		err := errors.New("receipt timestamp is not plausible")
		e.rejectImport("receipt accepted_at is not plausible", err)
		return WitnessReceipt{}, err
	}
	if receipt.WitnessSeq <= ack.LastWitnessSeq {
		e.rejectImport("receipt sequence is not strictly monotonic (replay)", nil)
		return WitnessReceipt{}, errors.New("witness receipt sequence is not strictly monotonic")
	}
	if export.LedgerEpoch < ack.LastEpoch || (export.LedgerEpoch == ack.LastEpoch && export.Sequence < ack.LastSequence) {
		// An import that acknowledges an older epoch/sequence than the baseline is
		// not a receipt problem: it is evidence that the chain rolled back.
		e.flagEquivocation("rollback")
		e.rejectImport("import regressed the acknowledged ledger epoch or sequence", nil)
		return WitnessReceipt{}, errors.New("witness import regressed the ledger epoch or sequence")
	}
	previous := ack
	e.mu.Lock()
	e.ack.LastWitnessID = receipt.WitnessID
	e.ack.LastWitnessSeq = receipt.WitnessSeq
	e.ack.LastCheckpointID = receipt.CheckpointID
	e.ack.LastAcceptedAt = receipt.AcceptedAt
	e.ack.LastEpoch = export.LedgerEpoch
	e.ack.LastSequence = export.Sequence
	e.ack.LastHeadHash = export.HeadHash
	updated := e.ack
	path := e.cfg.AckPath
	storage := e.cfg.Storage
	e.mu.Unlock()
	if err := saveWitnessAckState(path, storage, updated); err != nil {
		e.mu.Lock()
		e.ack = previous
		e.mu.Unlock()
		e.rejectImport("acknowledgement baseline could not be persisted", err)
		return WitnessReceipt{}, errors.New("witness acknowledgement baseline could not be persisted")
	}
	e.mu.Lock()
	e.failures = 0
	e.degraded = false
	e.lastError = ""
	e.mu.Unlock()
	e.recordEvent("info", "witness.acked",
		"Imported witness receipt acknowledged the checkpoint (witness_sequence "+fmt.Sprint(receipt.WitnessSeq)+")")
	return receipt, nil
}

// decodeImportedReceipt accepts the bare receipt object and the {receipt: ...}
// envelope, and nothing else.
func decodeImportedReceipt(raw []byte) (WitnessReceipt, error) {
	if receipt, err := DecodeWitnessReceipt(raw); err == nil {
		return receipt, nil
	}
	var envelope struct {
		Receipt json.RawMessage `json:"receipt"`
	}
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || len(envelope.Receipt) == 0 {
		return WitnessReceipt{}, errors.New("witness import body is neither a receipt nor a receipt envelope")
	}
	return DecodeWitnessReceipt(envelope.Receipt)
}

// rejectImport records the bounded rejection reason as evidence.
func (e *WitnessEngine) rejectImport(reason string, cause error) {
	e.setLastError("witness import rejected")
	e.recordEvent("warning", "witness.import_rejected", "Witness receipt import rejected: "+witnessBoundText(reason, witnessMaxReasonBytes))
	_ = cause
}

// ------------------------------------------------------------------ receipts

const (
	// witnessReceiptSchema names the signed receipt wire object.
	witnessReceiptSchema = "vgt-gedefense-witness-receipt-v1"
	// witnessReceiptDomain separates a witness receipt signature from every other
	// Ed25519 signature.
	witnessReceiptDomain = "VGT-GEDEFENSE-WITNESS-RECEIPT-V1\x00"
	// witnessReceiptMaxBytes bounds the receipt document a decoder will look at.
	witnessReceiptMaxBytes = 8 << 10
)

var witnessReceiptFieldNames = []string{"witness_id", "witness_seq", "checkpoint_id", "accepted_at", "signature"}

// WitnessReceipt is the signed acknowledgement of one checkpoint (§4).
type WitnessReceipt struct {
	WitnessID    string `json:"witness_id"`
	WitnessSeq   uint64 `json:"witness_seq"`
	CheckpointID string `json:"checkpoint_id"`
	AcceptedAt   string `json:"accepted_at"`
	Signature    string `json:"signature"`
}

type witnessReceiptPayload struct {
	WitnessID    string `json:"witness_id"`
	WitnessSeq   uint64 `json:"witness_seq"`
	CheckpointID string `json:"checkpoint_id"`
	AcceptedAt   string `json:"accepted_at"`
}

func witnessReceiptCanonicalPayload(receipt WitnessReceipt) ([]byte, error) {
	return json.Marshal(witnessReceiptPayload{
		WitnessID: receipt.WitnessID, WitnessSeq: receipt.WitnessSeq,
		CheckpointID: receipt.CheckpointID, AcceptedAt: receipt.AcceptedAt,
	})
}

func witnessReceiptDigest(payload []byte) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(witnessReceiptDomain))
	_, _ = hash.Write(payload)
	return hash.Sum(nil)
}

// ValidateWitnessReceipt checks the unsigned shape of a receipt. It rejects
// instead of repairing: unknown counters, non-canonical timestamps, foreign
// checkpoint ids and malformed signatures never reach an ack store.
func ValidateWitnessReceipt(receipt WitnessReceipt) error {
	if receipt.WitnessID == "" || len(receipt.WitnessID) > witnessMaxWitnessIDBytes {
		return errors.New("witness receipt id is empty or oversized")
	}
	for i := 0; i < len(receipt.WitnessID); i++ {
		c := receipt.WitnessID[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && c != '.' && c != '-' && c != '_' && c != ':' {
			return errors.New("witness receipt id contains an unsupported character")
		}
	}
	if receipt.WitnessSeq == 0 || receipt.WitnessSeq > witnessCheckpointMaxCounter {
		return errors.New("witness receipt sequence is zero or exceeds its JSON-safe bound")
	}
	if len(receipt.CheckpointID) != 2*witnessCheckpointIDBytes || !validWitnessLowerHex(receipt.CheckpointID) {
		return errors.New("witness receipt checkpoint id is not 16 bytes of lowercase hex")
	}
	if err := validateWitnessCreatedAt(receipt.AcceptedAt); err != nil {
		return errors.New("witness receipt accepted_at is not canonical UTC")
	}
	signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != receipt.Signature {
		return errors.New("witness receipt signature is not a canonical base64url Ed25519 signature")
	}
	return nil
}

// DecodeWitnessReceipt parses a receipt strictly. Unknown, duplicate, missing and
// null fields, trailing data and oversized documents are rejected, never repaired.
func DecodeWitnessReceipt(data []byte) (WitnessReceipt, error) {
	if len(data) > witnessReceiptMaxBytes {
		return WitnessReceipt{}, errors.New("witness receipt document exceeds its size bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(data)))
	if token, err := decoder.Token(); err != nil {
		return WitnessReceipt{}, fmt.Errorf("witness receipt is not valid JSON: %w", err)
	} else if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return WitnessReceipt{}, errors.New("witness receipt must be a JSON object")
	}
	allowed := make(map[string]struct{}, len(witnessReceiptFieldNames))
	for _, name := range witnessReceiptFieldNames {
		allowed[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(witnessReceiptFieldNames))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return WitnessReceipt{}, fmt.Errorf("witness receipt is malformed: %w", err)
		}
		name, ok := token.(string)
		if !ok {
			return WitnessReceipt{}, errors.New("witness receipt contains a non-string field name")
		}
		if _, ok := allowed[name]; !ok {
			return WitnessReceipt{}, fmt.Errorf("witness receipt contains unknown field %q", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return WitnessReceipt{}, fmt.Errorf("witness receipt contains duplicate field %q", name)
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return WitnessReceipt{}, fmt.Errorf("witness receipt field %q is not valid JSON: %w", name, err)
		}
		if string(bytes.TrimSpace(value)) == "null" {
			return WitnessReceipt{}, fmt.Errorf("witness receipt field %q is null", name)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return WitnessReceipt{}, fmt.Errorf("witness receipt is malformed: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return WitnessReceipt{}, errors.New("witness receipt contains trailing data")
	}
	for _, name := range witnessReceiptFieldNames {
		if _, present := seen[name]; !present {
			return WitnessReceipt{}, fmt.Errorf("witness receipt is missing field %q", name)
		}
	}
	var receipt WitnessReceipt
	if err := json.Unmarshal(bytes.TrimSpace(data), &receipt); err != nil {
		return WitnessReceipt{}, fmt.Errorf("witness receipt is malformed: %w", err)
	}
	if err := ValidateWitnessReceipt(receipt); err != nil {
		return WitnessReceipt{}, err
	}
	return receipt, nil
}

// VerifyWitnessReceipt verifies the domain-separated Ed25519 receipt signature.
func VerifyWitnessReceipt(receipt WitnessReceipt, publicKey ed25519.PublicKey) error {
	if err := ValidateWitnessReceipt(receipt); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("witness receipt verification key is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil {
		return errors.New("witness receipt signature is not canonical base64url")
	}
	payload, err := witnessReceiptCanonicalPayload(receipt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, witnessReceiptDigest(payload), signature) {
		return errors.New("witness receipt signature does not verify")
	}
	return nil
}
