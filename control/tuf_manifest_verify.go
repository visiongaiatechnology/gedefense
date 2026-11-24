// AP-9 / S09 — strict parser and verifier for the TUF-grade threshold
// manifest envelope declared in tuf_manifest.go.
//
// Every function here is a rejecting parser: an invalid, non-canonical,
// replayed, expired or under-signed envelope is refused with a typed TUFError
// carrying a stable reason code. There is no partially trusted acceptance path.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// parseTUFManifestEnvelope strictly decodes one envelope and proves that the
// raw bytes are exactly the canonical encoding. The canonical-form comparison
// is what rejects duplicate JSON keys, reordered fields, alternate number
// spellings and formatting: encoding/json silently accepts all of them, and a
// re-marshalled document differs from the raw bytes in every such case.
func parseTUFManifestEnvelope(raw []byte) (TUFManifestEnvelope, []byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope TUFManifestEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return TUFManifestEnvelope{}, nil, newTUFError(TUFReasonSchema, "envelope JSON rejected")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return TUFManifestEnvelope{}, nil, newTUFError(TUFReasonSchema, "envelope trailing data rejected")
	}
	canonical, err := json.Marshal(envelope)
	if err != nil {
		return TUFManifestEnvelope{}, nil, newTUFError(TUFReasonSchema, "envelope re-encoding failed")
	}
	if !bytes.Equal(canonical, raw) {
		return TUFManifestEnvelope{}, nil, newTUFError(TUFReasonSchema,
			"envelope is not canonical JSON (duplicate keys, reordered fields or formatting)")
	}
	signedBytes, err := json.Marshal(envelope.Signed)
	if err != nil {
		return TUFManifestEnvelope{}, nil, newTUFError(TUFReasonSchema, "signed section re-encoding failed")
	}
	return envelope, signedBytes, nil
}

// tufCanonicalKeyID accepts only the canonical lowercase hex SHA-256 key
// identity; empty, upper-case, short and all-zero identifiers are rejected.
func tufCanonicalKeyID(field, value string) (string, error) {
	if len(value) != 64 {
		return "", newTUFError(TUFReasonSchema, field+" is not a 64-character key id")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return "", newTUFError(TUFReasonSchema, field+" is not canonical lowercase hex")
	}
	zero := true
	for _, b := range decoded {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return "", newTUFError(TUFReasonSchema, field+" is the zero key id")
	}
	return value, nil
}

func tufCanonicalContentDigest(value string) (string, error) {
	if len(value) != 64 {
		return "", newTUFError(TUFReasonSchema, "content_sha256 is not a 64-character digest")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return "", newTUFError(TUFReasonSchema, "content_sha256 is not canonical lowercase hex")
	}
	return value, nil
}

func tufCanonicalBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, newTUFError(TUFReasonSignatureThreshold, "signature is not canonical base64")
	}
	return decoded, nil
}

// parseTUFCanonicalTime requires a canonical UTC RFC3339Nano timestamp so the
// same semantic time can only ever have one signed representation.
func parseTUFCanonicalTime(field, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, newTUFError(TUFReasonSchema, field+" is required")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, newTUFError(TUFReasonSchema, field+" is not an RFC3339 timestamp")
	}
	if parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, newTUFError(TUFReasonSchema, field+" is not canonical UTC RFC3339Nano")
	}
	return parsed.UTC(), nil
}

// validateTUFRoleDocument validates one role document against its trusted key
// and the caller-supplied clock. It returns the signed expiry.
func validateTUFRoleDocument(role string, document TUFRoleDocument, trustedKey ed25519.PublicKey, trustedID string, now time.Time, limits TUFLimits) (time.Time, error) {
	if document.Schema != tufRoleSchema {
		return time.Time{}, newTUFError(TUFReasonSchema, role+" role schema rejected")
	}
	if document.Role != role {
		return time.Time{}, newTUFError(TUFReasonSchema, role+" role name mismatch")
	}
	keyID, err := tufCanonicalKeyID(role+" role key id", document.KeyID)
	if err != nil {
		return time.Time{}, err
	}
	if trustedID == "" || keyID != trustedID {
		return time.Time{}, newTUFError(TUFReasonSignatureThreshold, role+" role does not name the trusted role key")
	}
	if len(trustedKey) != ed25519.PublicKeySize || tufKeyID(trustedKey) != keyID {
		return time.Time{}, newTUFError(TUFReasonSignatureThreshold, role+" role key binding is inconsistent")
	}
	issued, err := parseTUFCanonicalTime(role+" issued_at", document.IssuedAt)
	if err != nil {
		return time.Time{}, err
	}
	expires, err := parseTUFCanonicalTime(role+" expires_at", document.ExpiresAt)
	if err != nil {
		return time.Time{}, err
	}
	if !expires.After(issued) {
		return time.Time{}, newTUFError(TUFReasonSchema, role+" validity window is inverted")
	}
	var maxTTL time.Duration
	switch role {
	case tufRoleRoot:
		maxTTL = limits.MaxRootTTL
		if document.SnapshotKeyID == "" {
			return time.Time{}, newTUFError(TUFReasonSchema, "root role must bind the snapshot key id")
		}
		if document.ContentSHA256 != "" {
			return time.Time{}, newTUFError(TUFReasonSchema, "root role must not bind content")
		}
	case tufRoleContent:
		maxTTL = limits.MaxContentTTL
		if document.SnapshotKeyID != "" {
			return time.Time{}, newTUFError(TUFReasonSchema, "content role must not bind a snapshot key")
		}
	case tufRoleSnapshot:
		maxTTL = limits.MaxSnapshotTTL
		if document.SnapshotKeyID != "" {
			return time.Time{}, newTUFError(TUFReasonSchema, "snapshot role must not bind a snapshot key")
		}
	default:
		return time.Time{}, newTUFError(TUFReasonSchema, "unknown role document")
	}
	if expires.Sub(issued) > maxTTL {
		return time.Time{}, newTUFError(TUFReasonExpired,
			fmt.Sprintf("%s role validity window exceeds the %s upper bound", role, maxTTL))
	}
	if issued.After(now.Add(limits.ClockSkew)) {
		return time.Time{}, newTUFError(TUFReasonExpired, role+" role was issued in the future")
	}
	if !now.Before(expires) {
		return time.Time{}, newTUFError(TUFReasonExpired, role+" role has expired")
	}
	return expires, nil
}

// verifyTUFManifestEnvelope verifies one threshold-signed envelope. Every
// failure is fail-closed and carries a stable TUFReason* code.
func verifyTUFManifestEnvelope(raw []byte, trust *TUFTrustSet, options TUFVerifyOptions) (*TUFVerifiedManifest, error) {
	if trust == nil {
		return nil, newTUFError(TUFReasonCapabilityUnavailable, "no root/content/snapshot trust set is available")
	}
	if len(raw) == 0 {
		return nil, newTUFError(TUFReasonSchema, "TUF manifest envelope is empty")
	}
	if len(raw) > tufMaxEnvelopeBytes {
		return nil, newTUFError(TUFReasonSchema, "TUF manifest envelope exceeds the bounded size")
	}
	now := options.Now.UTC()
	if now.IsZero() {
		return nil, newTUFError(TUFReasonSchema, "verification time is required")
	}
	limits := options.Limits.normalised()
	envelope, signedBytes, err := parseTUFManifestEnvelope(raw)
	if err != nil {
		return nil, err
	}
	signed := envelope.Signed
	if signed.Schema != tufEnvelopeSchema {
		return nil, newTUFError(TUFReasonSchema, "TUF manifest envelope schema rejected")
	}
	if signed.Epoch == 0 {
		return nil, newTUFError(TUFReasonSchema, "TUF manifest epoch must be strictly positive")
	}
	if signed.Epoch <= options.HighWaterEpoch {
		return nil, newTUFError(TUFReasonEpochRollback,
			fmt.Sprintf("epoch %d is not strictly greater than the high-water epoch %d", signed.Epoch, options.HighWaterEpoch))
	}
	if len(envelope.Signatures) == 0 || len(envelope.Signatures) > tufMaxSignatures {
		return nil, newTUFError(TUFReasonSchema, "signature count is outside the 2-of-3 envelope")
	}
	contentDigest, err := tufCanonicalContentDigest(signed.ContentSHA256)
	if err != nil {
		return nil, err
	}
	if signed.Root.Role != tufRoleRoot || signed.Content.Role != tufRoleContent || signed.Snapshot.Role != tufRoleSnapshot {
		return nil, newTUFError(TUFReasonSchema, "role documents are not ordered root/content/snapshot")
	}
	if _, err := validateTUFRoleDocument(tufRoleRoot, signed.Root, trust.Root, trust.RootID, now, limits); err != nil {
		return nil, err
	}
	if _, err := validateTUFRoleDocument(tufRoleContent, signed.Content, trust.Content, trust.ContentID, now, limits); err != nil {
		return nil, err
	}
	snapshotExpiry, err := validateTUFRoleDocument(tufRoleSnapshot, signed.Snapshot, trust.Snapshot, trust.SnapshotID, now, limits)
	if err != nil {
		return nil, err
	}
	if signed.Root.SnapshotKeyID != trust.SnapshotID {
		return nil, newTUFError(TUFReasonSignatureThreshold, "root role does not bind the trusted snapshot key")
	}
	contentRoleDigest, err := tufCanonicalContentDigest(signed.Content.ContentSHA256)
	if err != nil {
		return nil, err
	}
	snapshotRoleDigest, err := tufCanonicalContentDigest(signed.Snapshot.ContentSHA256)
	if err != nil {
		return nil, err
	}
	if contentRoleDigest != contentDigest || snapshotRoleDigest != contentDigest {
		return nil, newTUFError(TUFReasonContentBinding, "role documents disagree about the content digest")
	}
	if strings.TrimSpace(options.ExpectedContentSHA256) == "" {
		return nil, newTUFError(TUFReasonSchema, "the caller did not supply the expected content digest")
	}
	expectedDigest, err := tufCanonicalContentDigest(options.ExpectedContentSHA256)
	if err != nil {
		return nil, err
	}
	if expectedDigest != contentDigest {
		return nil, newTUFError(TUFReasonContentBinding, "envelope does not bind the expected content document")
	}
	// Threshold: at least two valid signatures from distinct roles over the
	// exact canonical bytes of the signed section.
	seenRoles := make(map[string]struct{}, len(envelope.Signatures))
	validSignatures := 0
	for _, signature := range envelope.Signatures {
		roleKey, roleKeyID, known := trust.keyForRole(signature.Role)
		if !known {
			return nil, newTUFError(TUFReasonSignatureThreshold, "signature names an unknown role")
		}
		if _, duplicate := seenRoles[signature.Role]; duplicate {
			return nil, newTUFError(TUFReasonSignatureThreshold, "duplicate signature role rejected")
		}
		keyID, err := tufCanonicalKeyID("signature key id", signature.KeyID)
		if err != nil {
			return nil, newTUFError(TUFReasonSignatureThreshold, err.Error())
		}
		if keyID != roleKeyID {
			return nil, newTUFError(TUFReasonSignatureThreshold, "signature key id does not match its role key")
		}
		signatureBytes, err := tufCanonicalBase64(signature.Signature)
		if err != nil {
			return nil, err
		}
		if len(signatureBytes) != ed25519.SignatureSize || !ed25519.Verify(roleKey, signedBytes, signatureBytes) {
			return nil, newTUFError(TUFReasonSignatureThreshold, "signature verification failed")
		}
		seenRoles[signature.Role] = struct{}{}
		validSignatures++
	}
	if validSignatures < tufSignatureThreshold {
		return nil, newTUFError(TUFReasonSignatureThreshold,
			fmt.Sprintf("%d valid role signatures, %d required", validSignatures, tufSignatureThreshold))
	}
	digest := sha256.Sum256(signedBytes)
	return &TUFVerifiedManifest{
		Epoch: signed.Epoch, ContentSHA256: contentDigest,
		SnapshotSHA256: hex.EncodeToString(digest[:]), ExpiresAt: snapshotExpiry,
	}, nil
}

// readTUFManifestFile reads a bounded, regular, non-symlink envelope file that
// is not writable by group or world.
func readTUFManifestFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, newTUFError(TUFReasonSchema, "TUF manifest envelope is missing or unreadable")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, newTUFError(TUFReasonSchema, "TUF manifest envelope must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > tufMaxEnvelopeBytes {
		return nil, newTUFError(TUFReasonSchema, "TUF manifest envelope size rejected")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, newTUFError(TUFReasonSchema, "TUF manifest envelope must not be group/world writable")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, newTUFError(TUFReasonSchema, "TUF manifest envelope could not be read")
	}
	return raw, nil
}

// tufFeedManifestContentDigest is the content digest the threshold envelope must
// bind: the canonical signed feed-manifest message (the legacy manifest without
// its detached signature). Both layers therefore authenticate exactly the same
// feed content.
func tufFeedManifestContentDigest(document threatFeedManifestDocument) string {
	digest := sha256.Sum256(threatFeedManifestMessageFor(document))
	return hex.EncodeToString(digest[:])
}
