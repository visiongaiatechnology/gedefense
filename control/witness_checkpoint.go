// STATUS: DIAMANT VGT SUPREME

package main

// Out-of-band witness checkpoint contract (docs/POINT4-WITNESS.md §3).
//
// A checkpoint is the only thing that ever leaves this process for a witness: the authenticated
// ledger head, a boot-posture digest, a policy digest, a sensor enum and a signature. It carries
// no paths, no content, no targets and no key material. The signing key stays in the ledger; this
// file only defines the callback through which the ledger signs, and verification against a
// public key. Decoding rejects instead of repairing: exact schema, exact field set, bounded
// counters, lowercase hex, canonical UTC, fixed enums and a canonical base64url signature.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

const (
	// WitnessCheckpointSchema is the only accepted schema. Forward compatibility is expressed
	// by a new schema version, never by tolerating additional fields in this one.
	WitnessCheckpointSchema = "vgt-gedefense-witness-checkpoint-v1"

	witnessCheckpointVersion = 1
	// witnessCheckpointDomain separates a checkpoint signature from every other evidence
	// signature that uses the same ledger key.
	witnessCheckpointDomain = "VGT-GEDEFENSE-WITNESS-CHECKPOINT-V1\x00"

	witnessCheckpointIDBytes           = 16
	witnessCheckpointMaxNodeIDBytes    = 128
	witnessCheckpointMaxChallengeBytes = 128
	// witnessCheckpointMaxBytes bounds the document a decoder will even look at. A checkpoint is
	// a small fixed-shape object (export target ≤2 KiB); anything larger is not one, and bound
	// checking keeps the decoder cheap for a hostile import.
	witnessCheckpointMaxBytes = 64 << 10
	// witnessCheckpointMaxCounter bounds every counter to the integer range a JSON consumer can
	// hold exactly (2^53). A witness implemented in another language must never see a rounded
	// sequence; real ledgers are orders of magnitude below this.
	witnessCheckpointMaxCounter = 1 << 53

	witnessQuoteKindNone = "none"
)

var (
	witnessCheckpointFieldNames = []string{
		"schema", "version", "node_id", "checkpoint_id", "created_at", "ledger_epoch",
		"sequence", "head_hash", "records", "signing_key_fp", "boot_posture",
		"boot_posture_digest", "quote_kind", "policy_revision", "policy_digest",
		"sensor_state", "challenge", "signature",
	}
	witnessCheckpointAllowedFields = func() map[string]struct{} {
		set := make(map[string]struct{}, len(witnessCheckpointFieldNames))
		for _, name := range witnessCheckpointFieldNames {
			set[name] = struct{}{}
		}
		return set
	}()
	witnessBootPostures = map[string]struct{}{"VERIFIED": {}, "OBSERVE": {}, "NOT_SUPPORTED": {}}
	witnessSensorStates = map[string]struct{}{"online": {}, "degraded": {}, "offline": {}, "disabled": {}}
)

// WitnessCheckpoint is the exact §3 wire object. Field order is the canonical order: the JSON
// encoder emits these fields in declaration order, and the signable payload repeats the same
// order without the trailing signature.
type WitnessCheckpoint struct {
	Schema            string `json:"schema"`
	Version           int    `json:"version"`
	NodeID            string `json:"node_id"`
	CheckpointID      string `json:"checkpoint_id"`
	CreatedAt         string `json:"created_at"`
	LedgerEpoch       uint64 `json:"ledger_epoch"`
	Sequence          uint64 `json:"sequence"`
	HeadHash          string `json:"head_hash"`
	Records           uint64 `json:"records"`
	SigningKeyFP      string `json:"signing_key_fp"`
	BootPosture       string `json:"boot_posture"`
	BootPostureDigest string `json:"boot_posture_digest"`
	QuoteKind         string `json:"quote_kind"`
	PolicyRevision    uint64 `json:"policy_revision"`
	PolicyDigest      string `json:"policy_digest"`
	SensorState       string `json:"sensor_state"`
	Challenge         string `json:"challenge"`
	Signature         string `json:"signature"`
}

// witnessCheckpointPayload is the signed subset: everything except the signature. It is a
// distinct type so the encoder cannot accidentally include a signature that is being replaced.
type witnessCheckpointPayload struct {
	Schema            string `json:"schema"`
	Version           int    `json:"version"`
	NodeID            string `json:"node_id"`
	CheckpointID      string `json:"checkpoint_id"`
	CreatedAt         string `json:"created_at"`
	LedgerEpoch       uint64 `json:"ledger_epoch"`
	Sequence          uint64 `json:"sequence"`
	HeadHash          string `json:"head_hash"`
	Records           uint64 `json:"records"`
	SigningKeyFP      string `json:"signing_key_fp"`
	BootPosture       string `json:"boot_posture"`
	BootPostureDigest string `json:"boot_posture_digest"`
	QuoteKind         string `json:"quote_kind"`
	PolicyRevision    uint64 `json:"policy_revision"`
	PolicyDigest      string `json:"policy_digest"`
	SensorState       string `json:"sensor_state"`
	Challenge         string `json:"challenge"`
}

// WitnessCheckpointSigner signs a checkpoint digest. The ledger owns the Ed25519 key and returns
// this callback, so neither key material nor a signer interface with key access lives here.
type WitnessCheckpointSigner func(digest []byte) ([]byte, error)

// evidencePublicKeyFingerprint is SHA-256 over the raw Ed25519 public key, 64 lowercase hex
// characters. It identifies the key without exporting it.
func evidencePublicKeyFingerprint(publicKey ed25519.PublicKey) string {
	if len(publicKey) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// NewWitnessCheckpointID returns a fresh 16-byte random checkpoint identifier as 32 lowercase hex
// characters, the form §3 requires.
func NewWitnessCheckpointID() (string, error) {
	raw := make([]byte, witnessCheckpointIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("witness checkpoint id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// witnessPostureItem is the canonical boot-posture subset: identity, verdict and digest only.
// Source paths, evidence text, summaries, cmdline snippets and operator notes are deliberately
// absent from the former.
type witnessPostureItem struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Digest string `json:"digest"`
}

// BootPostureDigest hashes the canonical boot-trust item subset {id,state,digest}.
//
// It reports "the same boot posture as last seen" without leaking what the posture was derived
// from: two hosts that differ only in cmdline text, source paths or evidence prose produce the
// same digest, while a different item state or digest changes it. Items are sorted, so a report
// that lists them in another order is still the same posture.
func BootPostureDigest(report BootTrustReport) string {
	items := make([]witnessPostureItem, 0, len(report.Items))
	for _, item := range report.Items {
		items = append(items, witnessPostureItem{ID: item.ID, State: item.State, Digest: item.Digest})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		if items[i].State != items[j].State {
			return items[i].State < items[j].State
		}
		return items[i].Digest < items[j].Digest
	})
	// json.Marshal of a struct of strings cannot fail.
	data, _ := json.Marshal(items)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// PolicyDigest hashes the canonical runtime-settings JSON. The canonical form is the one the
// settings MAC already covers (UpdatedAt normalized to UTC, json.Marshal of the struct), so the
// digest names exactly the policy document the operator signed off on without carrying it.
func PolicyDigest(settings RuntimeSettings) (string, error) {
	canonical := settings
	canonical.UpdatedAt = canonical.UpdatedAt.UTC()
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("canonical runtime settings: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// EncodeWitnessCheckpoint returns the canonical JSON form of a signed checkpoint. The field order
// is fixed by the struct, so equal checkpoints always encode byte-identically.
func EncodeWitnessCheckpoint(checkpoint WitnessCheckpoint) ([]byte, error) {
	if err := ValidateWitnessCheckpoint(checkpoint); err != nil {
		return nil, err
	}
	return json.Marshal(checkpoint)
}

// DecodeWitnessCheckpoint parses and validates a checkpoint. It rejects unknown, duplicate and
// missing fields, trailing data and any value outside the §3 contract; it never repairs.
func DecodeWitnessCheckpoint(data []byte) (WitnessCheckpoint, error) {
	if len(data) > witnessCheckpointMaxBytes {
		return WitnessCheckpoint{}, errors.New("witness checkpoint document exceeds its size bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(data)))
	if token, err := decoder.Token(); err != nil {
		return WitnessCheckpoint{}, fmt.Errorf("witness checkpoint is not valid JSON: %w", err)
	} else if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return WitnessCheckpoint{}, errors.New("witness checkpoint must be a JSON object")
	}
	seen := make(map[string]struct{}, len(witnessCheckpointFieldNames))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return WitnessCheckpoint{}, fmt.Errorf("witness checkpoint is malformed: %w", err)
		}
		name, ok := token.(string)
		if !ok {
			return WitnessCheckpoint{}, errors.New("witness checkpoint contains a non-string field name")
		}
		if _, allowed := witnessCheckpointAllowedFields[name]; !allowed {
			return WitnessCheckpoint{}, fmt.Errorf("witness checkpoint contains unknown field %q", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return WitnessCheckpoint{}, fmt.Errorf("witness checkpoint contains duplicate field %q", name)
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return WitnessCheckpoint{}, fmt.Errorf("witness checkpoint field %q is not valid JSON: %w", name, err)
		}
		// Every field is required and typed; null is not one of the forms it may take, and
		// encoding/json would otherwise decode it into the zero value ("repair").
		if string(bytes.TrimSpace(value)) == "null" {
			return WitnessCheckpoint{}, fmt.Errorf("witness checkpoint field %q is null", name)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return WitnessCheckpoint{}, fmt.Errorf("witness checkpoint is malformed: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return WitnessCheckpoint{}, errors.New("witness checkpoint contains trailing data")
	}
	for _, name := range witnessCheckpointFieldNames {
		if _, present := seen[name]; !present {
			return WitnessCheckpoint{}, fmt.Errorf("witness checkpoint is missing field %q", name)
		}
	}
	var checkpoint WitnessCheckpoint
	if err := json.Unmarshal(bytes.TrimSpace(data), &checkpoint); err != nil {
		return WitnessCheckpoint{}, fmt.Errorf("witness checkpoint is malformed: %w", err)
	}
	if err := ValidateWitnessCheckpoint(checkpoint); err != nil {
		return WitnessCheckpoint{}, err
	}
	return checkpoint, nil
}

// SignWitnessCheckpoint signs the canonical payload with the ledger's callback. Ed25519 is
// deterministic, so signing the same checkpoint twice yields the same signature.
func SignWitnessCheckpoint(checkpoint WitnessCheckpoint, signer WitnessCheckpointSigner) (WitnessCheckpoint, error) {
	checkpoint.Signature = ""
	if err := validateWitnessCheckpointPayload(checkpoint); err != nil {
		return WitnessCheckpoint{}, err
	}
	if signer == nil {
		return WitnessCheckpoint{}, errors.New("witness checkpoint signer is not configured")
	}
	payload, err := witnessCheckpointCanonicalPayload(checkpoint)
	if err != nil {
		return WitnessCheckpoint{}, err
	}
	signature, err := signer(witnessCheckpointDigest(payload))
	if err != nil {
		return WitnessCheckpoint{}, fmt.Errorf("sign witness checkpoint: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return WitnessCheckpoint{}, errors.New("witness checkpoint signer returned an invalid signature size")
	}
	checkpoint.Signature = base64.RawURLEncoding.EncodeToString(signature)
	if err := ValidateWitnessCheckpoint(checkpoint); err != nil {
		return WitnessCheckpoint{}, err
	}
	return checkpoint, nil
}

// VerifyWitnessCheckpoint validates the checkpoint and its Ed25519 signature against a public
// key. Verification is over the domain-separated digest of the canonical payload.
func VerifyWitnessCheckpoint(checkpoint WitnessCheckpoint, publicKey ed25519.PublicKey) error {
	if err := ValidateWitnessCheckpoint(checkpoint); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("witness checkpoint verification key is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(checkpoint.Signature)
	if err != nil {
		return errors.New("witness checkpoint signature is not canonical base64url")
	}
	payload, err := witnessCheckpointCanonicalPayload(checkpoint)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, witnessCheckpointDigest(payload), signature) {
		return errors.New("witness checkpoint signature does not verify")
	}
	return nil
}

// VerifyWitnessCheckpointJSON decodes and verifies one checkpoint document, which is the export
// and air-gap import form.
func VerifyWitnessCheckpointJSON(data []byte, publicKey ed25519.PublicKey) (WitnessCheckpoint, error) {
	checkpoint, err := DecodeWitnessCheckpoint(data)
	if err != nil {
		return WitnessCheckpoint{}, err
	}
	if err := VerifyWitnessCheckpoint(checkpoint, publicKey); err != nil {
		return WitnessCheckpoint{}, err
	}
	return checkpoint, nil
}

// ValidateWitnessCheckpoint checks the full signed contract.
func ValidateWitnessCheckpoint(checkpoint WitnessCheckpoint) error {
	if err := validateWitnessCheckpointPayload(checkpoint); err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(checkpoint.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != checkpoint.Signature {
		return errors.New("witness checkpoint signature is not a canonical base64url Ed25519 signature")
	}
	return nil
}

func validateWitnessCheckpointPayload(checkpoint WitnessCheckpoint) error {
	if checkpoint.Schema != WitnessCheckpointSchema {
		return fmt.Errorf("witness checkpoint schema %q is not %q", checkpoint.Schema, WitnessCheckpointSchema)
	}
	if checkpoint.Version != witnessCheckpointVersion {
		return fmt.Errorf("witness checkpoint version %d is not %d", checkpoint.Version, witnessCheckpointVersion)
	}
	if err := validateWitnessNodeID(checkpoint.NodeID); err != nil {
		return err
	}
	if len(checkpoint.CheckpointID) != 2*witnessCheckpointIDBytes || !validWitnessLowerHex(checkpoint.CheckpointID) {
		return errors.New("witness checkpoint id is not 16 bytes of lowercase hex")
	}
	if err := validateWitnessCreatedAt(checkpoint.CreatedAt); err != nil {
		return err
	}
	if checkpoint.LedgerEpoch > witnessCheckpointMaxCounter || checkpoint.Sequence > witnessCheckpointMaxCounter ||
		checkpoint.Records > witnessCheckpointMaxCounter || checkpoint.PolicyRevision > witnessCheckpointMaxCounter {
		return errors.New("witness checkpoint counter exceeds its JSON-safe bound")
	}
	if checkpoint.Records != checkpoint.Sequence {
		return errors.New("witness checkpoint records do not match its sequence")
	}
	if checkpoint.Sequence == 0 {
		// An empty chain has no head. A head without records (or records without a head) is a
		// claim the ledger cannot make and a witness must not accept.
		if checkpoint.HeadHash != "" {
			return errors.New("witness checkpoint names a head without any record")
		}
	} else if !validWitnessDigest(checkpoint.HeadHash) {
		return errors.New("witness checkpoint head hash is not a SHA-256 digest")
	}
	if !validWitnessDigest(checkpoint.SigningKeyFP) {
		return errors.New("witness checkpoint signing key fingerprint is not a SHA-256 digest")
	}
	if _, ok := witnessBootPostures[checkpoint.BootPosture]; !ok {
		return errors.New("witness checkpoint boot posture is not a supported verdict")
	}
	if !validWitnessDigest(checkpoint.BootPostureDigest) {
		return errors.New("witness checkpoint boot posture digest is not a SHA-256 digest")
	}
	if checkpoint.QuoteKind != witnessQuoteKindNone {
		return errors.New("witness checkpoint quote kind is not \"none\"")
	}
	if !validWitnessDigest(checkpoint.PolicyDigest) {
		return errors.New("witness checkpoint policy digest is not a SHA-256 digest")
	}
	if _, ok := witnessSensorStates[checkpoint.SensorState]; !ok {
		return errors.New("witness checkpoint sensor state is not a supported value")
	}
	if err := validateWitnessChallenge(checkpoint.Challenge); err != nil {
		return err
	}
	return nil
}

func witnessCheckpointCanonicalPayload(checkpoint WitnessCheckpoint) ([]byte, error) {
	return json.Marshal(witnessCheckpointPayload{
		Schema: checkpoint.Schema, Version: checkpoint.Version, NodeID: checkpoint.NodeID,
		CheckpointID: checkpoint.CheckpointID, CreatedAt: checkpoint.CreatedAt,
		LedgerEpoch: checkpoint.LedgerEpoch, Sequence: checkpoint.Sequence,
		HeadHash: checkpoint.HeadHash, Records: checkpoint.Records,
		SigningKeyFP: checkpoint.SigningKeyFP, BootPosture: checkpoint.BootPosture,
		BootPostureDigest: checkpoint.BootPostureDigest, QuoteKind: checkpoint.QuoteKind,
		PolicyRevision: checkpoint.PolicyRevision, PolicyDigest: checkpoint.PolicyDigest,
		SensorState: checkpoint.SensorState, Challenge: checkpoint.Challenge,
	})
}

func witnessCheckpointDigest(payload []byte) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(witnessCheckpointDomain))
	_, _ = hash.Write(payload)
	return hash.Sum(nil)
}

func validateWitnessNodeID(value string) error {
	if value == "" || len(value) > witnessCheckpointMaxNodeIDBytes {
		return errors.New("witness checkpoint node id is empty or oversized")
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && c != '.' && c != '-' && c != '_' && c != ':' {
			return errors.New("witness checkpoint node id contains an unsupported character")
		}
	}
	return nil
}

// validateWitnessCreatedAt accepts only the canonical spelling of a UTC RFC3339 timestamp. An
// offset form or a fractional second would allow several encodings of one instant, and the
// signature covers the spelling.
func validateWitnessCreatedAt(value string) error {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return errors.New("witness checkpoint created_at is not RFC3339")
	}
	if parsed.UTC().Format(time.RFC3339) != value {
		return errors.New("witness checkpoint created_at is not canonical UTC")
	}
	return nil
}

func validateWitnessChallenge(value string) error {
	if value == "" {
		return nil
	}
	if len(value)%2 != 0 || len(value)/2 > witnessCheckpointMaxChallengeBytes {
		return errors.New("witness checkpoint challenge is not bounded hex")
	}
	if !validWitnessLowerHex(value) {
		return errors.New("witness checkpoint challenge is not lowercase hex")
	}
	return nil
}

func validWitnessDigest(value string) bool {
	return len(value) == 64 && validWitnessLowerHex(value)
}

func validWitnessLowerHex(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
