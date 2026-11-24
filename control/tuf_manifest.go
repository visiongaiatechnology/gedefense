// AP-9 / S09 — TUF-grade threshold manifest envelope for feed and rule
// documents (local guard, Go standard library only).
//
// The existing feed pipeline authenticates a download with one detached Ed25519
// manifest (F-03 / CHAIN-009). This file adds the TUF-grade layer required by
// S09 on top of it, without changing the existing trust model:
//
//   - Role separation: three trusted Ed25519 keys are derived deterministically
//     from the already-configured feeds.trusted_signing_keys list, in order:
//     index 0 = root, index 1 = content, index 2 = snapshot. No configuration
//     schema change is involved. Fewer than three pinned keys means the
//     capability is unavailable (reported honestly by the manager), never
//     silently permissive.
//
//   - Threshold: the canonical bytes of the "signed" section require at least
//     two valid signatures from distinct roles (2-of-3). Two signatures from
//     the same role, a signature by a key that is not the role key, an unknown
//     role and a wrong signature count are all rejected.
//
//   - Freeze protection: the snapshot role document carries a short validity
//     window (bound to at most 24 h of issue-to-expiry time by default, with a
//     caller-supplied upper bound) and binds the SHA-256 of the content
//     document. Because the snapshot document is part of the threshold-signed
//     canonical bytes, a replayed older envelope fails either the expiry check
//     or the strictly monotonic anti-rollback epoch.
//
//   - Key rotation: the root role document names the snapshot key it anchors
//     (snapshot_key_id). Rotating the snapshot key requires a new root document
//     signed by the configured root key, and the configured trust anchor must
//     agree with the named key, so a rotated key set can never become valid by
//     presenting an envelope alone.
//
//   - Anti-rollback: the caller supplies the persisted high-water epoch; an
//     envelope whose epoch is not strictly greater is rejected. The epoch is an
//     unsigned 64-bit integer and is signed as part of the canonical bytes.
//
//   - Strict parser: bounded payload (4 MiB), JSON decoding with
//     DisallowUnknownFields, trailing-data rejection, canonical-form comparison
//     after re-marshalling (which rejects duplicate keys, reordered fields and
//     pretty-printing), canonical lowercase hex and canonical base64 only,
//     non-zero and pairwise-distinct role key identifiers, and required,
//     canonical UTC timestamps.
//
// The verification half lives in tuf_manifest_verify.go; the signing helper
// lives in the _test.go corpus: production code only verifies. The envelope
// binds an externally published content digest; the feed integration binds the
// canonical signed feed-manifest message so the threshold envelope and the
// legacy single-signature manifest can never disagree about which feed content
// is meant.

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// tufEnvelopeSchema is the canonical envelope schema token.
	tufEnvelopeSchema = "vgt-gedefense-tuf-manifest-v1"
	// tufRoleSchema is the schema token of every role document inside the envelope.
	tufRoleSchema = "vgt-gedefense-tuf-role-v1"
	// tufManifestFilename is the envelope file name next to feeds.manifest_path.
	tufManifestFilename = "tuf-feed-manifest.json"
	// tufRequiredRoleKeys is the number of trusted_signing_keys entries the
	// TUF capability needs (root, content, snapshot in that order).
	tufRequiredRoleKeys = 3
	// tufSignatureThreshold is the 2-of-3 threshold over distinct roles.
	tufSignatureThreshold = 2
	// tufMaxSignatures is one signature per role.
	tufMaxSignatures = 3
	// tufMaxEnvelopeBytes bounds the envelope before any JSON decoding.
	tufMaxEnvelopeBytes = 4 << 20
	// tufClockSkew tolerates small publisher/host clock differences.
	tufClockSkew = 5 * time.Minute
	// tufMaxSnapshotTTL is the default upper bound for the short snapshot
	// validity window (freeze protection); callers may lower it, never silently
	// raise it beyond this default.
	tufMaxSnapshotTTL = 24 * time.Hour
	// tufMaxContentTTL bounds the content role document validity.
	tufMaxContentTTL = 7 * 24 * time.Hour
	// tufMaxRootTTL bounds the root role document validity (rotation cadence).
	tufMaxRootTTL = 365 * 24 * time.Hour
)

// Role names inside the envelope. Each role names exactly one trusted key.
const (
	tufRoleRoot     = "root"
	tufRoleContent  = "content"
	tufRoleSnapshot = "snapshot"
)

// Stable reason codes for the S09 guards. They are logged and surfaced verbatim
// as bounded state/telemetry reasons; they carry no secrets and no URLs.
const (
	TUFReasonSchema                = "tuf.schema"
	TUFReasonSignatureThreshold    = "tuf.signature_threshold"
	TUFReasonExpired               = "tuf.expired"
	TUFReasonEpochRollback         = "tuf.epoch_rollback"
	TUFReasonContentBinding        = "tuf.content_binding"
	TUFReasonCapabilityUnavailable = "tuf.capability_unavailable"
	TUFReasonStateCorrupt          = "tuf.state_corrupt"
	TUFReasonDiffBudget            = "tuf.diff_budget_exceeded"
	TUFReasonImmutableZone         = "tuf.immutable_zone"
	TUFReasonGlobalAllow           = "tuf.global_allow"
	TUFReasonRegexComplexity       = "tuf.regex_complexity"
	TUFReasonSystemPathInject      = "tuf.system_path_inject"
	TUFReasonShadowParse           = "tuf.shadow_parse"
	TUFReasonEntryBudget           = "tuf.entry_budget"
)

// TUFError is the typed rejection returned by every S09 guard. The Reason field
// is always one of the stable TUFReason* codes so a caller can log and surface
// it without parsing prose.
type TUFError struct {
	Reason string
	Detail string
}

func (e *TUFError) Error() string {
	if e == nil {
		return ""
	}
	if strings.TrimSpace(e.Detail) == "" {
		return e.Reason
	}
	return e.Reason + ": " + e.Detail
}

func newTUFError(reason, detail string) *TUFError {
	return &TUFError{Reason: reason, Detail: detail}
}

// tufErrorReason extracts the stable reason code from err, or "" when err is
// not a TUF rejection. It unwraps the ThreatIntel exception wrappers so a sync
// error keeps its machine-readable code.
func tufErrorReason(err error) string {
	var target *TUFError
	if errors.As(err, &target) {
		return target.Reason
	}
	return ""
}

// TUFLimits are the caller-supplied validity bounds. Zero values fall back to
// the defaults above; a caller may tighten but never silently widen them.
type TUFLimits struct {
	ClockSkew      time.Duration
	MaxSnapshotTTL time.Duration
	MaxContentTTL  time.Duration
	MaxRootTTL     time.Duration
}

// DefaultTUFLimits returns the conservative TUF validity bounds.
func DefaultTUFLimits() TUFLimits {
	return TUFLimits{
		ClockSkew:      tufClockSkew,
		MaxSnapshotTTL: tufMaxSnapshotTTL,
		MaxContentTTL:  tufMaxContentTTL,
		MaxRootTTL:     tufMaxRootTTL,
	}
}

func (l TUFLimits) normalised() TUFLimits {
	defaults := DefaultTUFLimits()
	if l.ClockSkew <= 0 {
		l.ClockSkew = defaults.ClockSkew
	}
	if l.MaxSnapshotTTL <= 0 || l.MaxSnapshotTTL > defaults.MaxSnapshotTTL {
		l.MaxSnapshotTTL = defaults.MaxSnapshotTTL
	}
	if l.MaxContentTTL <= 0 || l.MaxContentTTL > defaults.MaxContentTTL {
		l.MaxContentTTL = defaults.MaxContentTTL
	}
	if l.MaxRootTTL <= 0 || l.MaxRootTTL > defaults.MaxRootTTL {
		l.MaxRootTTL = defaults.MaxRootTTL
	}
	return l
}

// TUFRoleDocument is one role document inside the threshold-signed envelope.
// Every role names exactly one trusted Ed25519 public key by its key_id (the
// lowercase SHA-256 fingerprint of the raw 32-byte public key).
type TUFRoleDocument struct {
	Schema        string `json:"schema"`
	Role          string `json:"role"`
	KeyID         string `json:"key_id"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
	ContentSHA256 string `json:"content_sha256"`
	SnapshotKeyID string `json:"snapshot_key_id"`
}

// TUFSignedManifest is the part of the envelope covered by the threshold
// signatures. It contains no maps and no slices, so its encoding/json field
// order is deterministic across processes and versions.
type TUFSignedManifest struct {
	Schema        string          `json:"schema"`
	Epoch         uint64          `json:"epoch"`
	ContentSHA256 string          `json:"content_sha256"`
	Root          TUFRoleDocument `json:"root"`
	Content       TUFRoleDocument `json:"content"`
	Snapshot      TUFRoleDocument `json:"snapshot"`
}

// TUFEnvelopeSignature is one detached role signature over the canonical bytes
// of TUFSignedManifest.
type TUFEnvelopeSignature struct {
	Role      string `json:"role"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// TUFManifestEnvelope is the on-disk threshold-signed manifest envelope.
type TUFManifestEnvelope struct {
	Signed     TUFSignedManifest      `json:"signed"`
	Signatures []TUFEnvelopeSignature `json:"signatures"`
}

// TUFTrustSet is the role -> trusted key mapping derived from
// feeds.trusted_signing_keys in configuration order.
type TUFTrustSet struct {
	Root       ed25519.PublicKey
	Content    ed25519.PublicKey
	Snapshot   ed25519.PublicKey
	RootID     string
	ContentID  string
	SnapshotID string
}

// tufKeyID is the deterministic key identity: lowercase hex SHA-256 over the
// raw 32-byte Ed25519 public key.
func tufKeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:])
}

// newTUFTrustSet derives the role key set from the pinned keys in order. Fewer
// than three distinct keys means the TUF capability is unavailable; that is a
// capability state, not a silently permissive fallback.
func newTUFTrustSet(keys []ed25519.PublicKey) (*TUFTrustSet, error) {
	if len(keys) < tufRequiredRoleKeys {
		return nil, newTUFError(TUFReasonCapabilityUnavailable,
			fmt.Sprintf("%d pinned Ed25519 keys, %d required for root/content/snapshot", len(keys), tufRequiredRoleKeys))
	}
	for index := 0; index < tufRequiredRoleKeys; index++ {
		if len(keys[index]) != ed25519.PublicKeySize {
			return nil, newTUFError(TUFReasonSchema, "pinned role key is not an Ed25519 public key")
		}
	}
	trust := &TUFTrustSet{
		Root: keys[0], Content: keys[1], Snapshot: keys[2],
	}
	trust.RootID = tufKeyID(trust.Root)
	trust.ContentID = tufKeyID(trust.Content)
	trust.SnapshotID = tufKeyID(trust.Snapshot)
	if trust.RootID == trust.ContentID || trust.RootID == trust.SnapshotID || trust.ContentID == trust.SnapshotID {
		return nil, newTUFError(TUFReasonSchema, "pinned role keys must be pairwise distinct")
	}
	return trust, nil
}

func (t *TUFTrustSet) keyForRole(role string) (ed25519.PublicKey, string, bool) {
	if t == nil {
		return nil, "", false
	}
	switch role {
	case tufRoleRoot:
		return t.Root, t.RootID, true
	case tufRoleContent:
		return t.Content, t.ContentID, true
	case tufRoleSnapshot:
		return t.Snapshot, t.SnapshotID, true
	default:
		return nil, "", false
	}
}

// TUFVerifyOptions are the caller-supplied verification inputs. Now and
// HighWaterEpoch are mandatory; ExpectedContentSHA256 binds the envelope to the
// exact content document the caller verified.
type TUFVerifyOptions struct {
	Now                   time.Time
	HighWaterEpoch        uint64
	ExpectedContentSHA256 string
	Limits                TUFLimits
}

// TUFVerifiedManifest is the accepted result of envelope verification.
type TUFVerifiedManifest struct {
	Epoch          uint64
	ContentSHA256  string
	SnapshotSHA256 string
	ExpiresAt      time.Time
}
