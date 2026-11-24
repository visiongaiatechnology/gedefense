// AP-9 / S09 — negative and positive corpus for the threshold manifest
// envelope: 2-of-3 role signatures, role separation, freeze/expiry, strict
// monotonic epoch, anti-rollback high-water, canonical form and key binding.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func tufTestNow() time.Time {
	return time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
}

func tufTestDigest(seed string) string {
	digest := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(digest[:])
}

func tufTestCanonicalTime(at time.Time) string {
	return at.UTC().Format(time.RFC3339Nano)
}

type tufTestRoles struct {
	public  []ed25519.PublicKey
	private []ed25519.PrivateKey
	trust   *TUFTrustSet
}

func newTufTestRoles(t *testing.T) *tufTestRoles {
	t.Helper()
	roles := &tufTestRoles{}
	for index := 0; index < 3; index++ {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate role key: %v", err)
		}
		roles.public = append(roles.public, publicKey)
		roles.private = append(roles.private, privateKey)
	}
	trust, err := newTUFTrustSet(roles.public)
	if err != nil {
		t.Fatalf("derive trust set: %v", err)
	}
	roles.trust = trust
	return roles
}

func (r *tufTestRoles) roleIndex(role string) int {
	switch role {
	case tufRoleRoot:
		return 0
	case tufRoleContent:
		return 1
	case tufRoleSnapshot:
		return 2
	default:
		return -1
	}
}

func (r *tufTestRoles) signRole(t *testing.T, signed TUFSignedManifest, role string) TUFEnvelopeSignature {
	t.Helper()
	index := r.roleIndex(role)
	if index < 0 {
		t.Fatalf("unknown test role %q", role)
	}
	signedBytes, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal signed section: %v", err)
	}
	signature := ed25519.Sign(r.private[index], signedBytes)
	return TUFEnvelopeSignature{
		Role:      role,
		KeyID:     tufKeyID(r.public[index]),
		Signature: base64Std(signature),
	}
}

func base64Std(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

type tufTestEnvelopeSpec struct {
	Epoch             uint64
	ContentDigest     string
	Now               time.Time
	RootIssued        time.Time
	RootExpires       time.Time
	ContentIssued     time.Time
	ContentExpires    time.Time
	SnapshotIssued    time.Time
	SnapshotExpires   time.Time
	RootSnapshotKeyID string
	Roles             []string
	// Mutate runs after the role signatures are created, for negative cases.
	Mutate func(*TUFManifestEnvelope)
}

func (r *tufTestRoles) signedManifest(t *testing.T, spec tufTestEnvelopeSpec) TUFSignedManifest {
	t.Helper()
	now := spec.Now
	if now.IsZero() {
		now = tufTestNow()
	}
	if spec.Epoch == 0 {
		spec.Epoch = 1
	}
	if spec.ContentDigest == "" {
		spec.ContentDigest = tufTestDigest("content")
	}
	rootIssued := spec.RootIssued
	if rootIssued.IsZero() {
		rootIssued = now.Add(-time.Minute)
	}
	rootExpires := spec.RootExpires
	if rootExpires.IsZero() {
		rootExpires = now.Add(24 * time.Hour)
	}
	contentIssued := spec.ContentIssued
	if contentIssued.IsZero() {
		contentIssued = now.Add(-time.Minute)
	}
	contentExpires := spec.ContentExpires
	if contentExpires.IsZero() {
		contentExpires = now.Add(2 * time.Hour)
	}
	snapshotIssued := spec.SnapshotIssued
	if snapshotIssued.IsZero() {
		snapshotIssued = now.Add(-time.Minute)
	}
	snapshotExpires := spec.SnapshotExpires
	if snapshotExpires.IsZero() {
		snapshotExpires = now.Add(30 * time.Minute)
	}
	rootSnapshotKeyID := spec.RootSnapshotKeyID
	if rootSnapshotKeyID == "" {
		rootSnapshotKeyID = r.trust.SnapshotID
	}
	return TUFSignedManifest{
		Schema:        tufEnvelopeSchema,
		Epoch:         spec.Epoch,
		ContentSHA256: spec.ContentDigest,
		Root: TUFRoleDocument{
			Schema: tufRoleSchema, Role: tufRoleRoot, KeyID: r.trust.RootID,
			IssuedAt: tufTestCanonicalTime(rootIssued), ExpiresAt: tufTestCanonicalTime(rootExpires),
			SnapshotKeyID: rootSnapshotKeyID,
		},
		Content: TUFRoleDocument{
			Schema: tufRoleSchema, Role: tufRoleContent, KeyID: r.trust.ContentID,
			IssuedAt: tufTestCanonicalTime(contentIssued), ExpiresAt: tufTestCanonicalTime(contentExpires),
			ContentSHA256: spec.ContentDigest,
		},
		Snapshot: TUFRoleDocument{
			Schema: tufRoleSchema, Role: tufRoleSnapshot, KeyID: r.trust.SnapshotID,
			IssuedAt: tufTestCanonicalTime(snapshotIssued), ExpiresAt: tufTestCanonicalTime(snapshotExpires),
			ContentSHA256: spec.ContentDigest,
		},
	}
}

func (r *tufTestRoles) envelope(t *testing.T, spec tufTestEnvelopeSpec) TUFManifestEnvelope {
	t.Helper()
	signed := r.signedManifest(t, spec)
	signatureRoles := spec.Roles
	if signatureRoles == nil {
		signatureRoles = []string{tufRoleRoot, tufRoleContent}
	}
	envelope := TUFManifestEnvelope{Signed: signed}
	for _, role := range signatureRoles {
		envelope.Signatures = append(envelope.Signatures, r.signRole(t, signed, role))
	}
	if spec.Mutate != nil {
		spec.Mutate(&envelope)
	}
	return envelope
}

func (r *tufTestRoles) envelopeBytes(t *testing.T, spec tufTestEnvelopeSpec) []byte {
	t.Helper()
	raw, err := json.Marshal(r.envelope(t, spec))
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return raw
}

func (r *tufTestRoles) verify(t *testing.T, raw []byte, options TUFVerifyOptions) (*TUFVerifiedManifest, error) {
	t.Helper()
	return verifyTUFManifestEnvelope(raw, r.trust, options)
}

func tufTestVerifyOptions(now time.Time, highWater uint64, digest string) TUFVerifyOptions {
	return TUFVerifyOptions{Now: now, HighWaterEpoch: highWater, ExpectedContentSHA256: digest, Limits: DefaultTUFLimits()}
}

func tufTestRequireReason(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a %q rejection, got nil", want)
	}
	if got := tufErrorReason(err); got != want {
		t.Fatalf("rejection reason = %q (%v), want %q", got, err, want)
	}
}

func TestTufManifestAcceptsTwoDistinctRoles(t *testing.T) {
	roles := newTufTestRoles(t)
	now := tufTestNow()
	digest := tufTestDigest("content")
	cases := [][]string{
		{tufRoleRoot, tufRoleContent},
		{tufRoleRoot, tufRoleSnapshot},
		{tufRoleContent, tufRoleSnapshot},
	}
	for _, signatureRoles := range cases {
		signatureRoles := signatureRoles
		t.Run(strings.Join(signatureRoles, "+"), func(t *testing.T) {
			raw := roles.envelopeBytes(t, tufTestEnvelopeSpec{ContentDigest: digest, Roles: signatureRoles})
			verified, err := roles.verify(t, raw, tufTestVerifyOptions(now, 0, digest))
			if err != nil {
				t.Fatalf("2-of-3 envelope with %v rejected: %v", signatureRoles, err)
			}
			if verified.Epoch != 1 || verified.ContentSHA256 != digest {
				t.Fatalf("verified projection = %+v", verified)
			}
			if len(verified.SnapshotSHA256) != 64 {
				t.Fatalf("verified snapshot digest = %q", verified.SnapshotSHA256)
			}
		})
	}
}

func TestTufManifestRejectsInsufficientThreshold(t *testing.T) {
	roles := newTufTestRoles(t)
	now := tufTestNow()
	digest := tufTestDigest("content")

	oneSignature := roles.envelopeBytes(t, tufTestEnvelopeSpec{ContentDigest: digest, Roles: []string{tufRoleContent}})
	if _, err := roles.verify(t, oneSignature, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("1-of-3 signature set was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonSignatureThreshold)
	}

	noSignatures := roles.envelopeBytes(t, tufTestEnvelopeSpec{ContentDigest: digest, Roles: []string{}})
	if _, err := roles.verify(t, noSignatures, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("unsigned envelope was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonSchema)
	}

	duplicateRole := roles.envelope(t, tufTestEnvelopeSpec{ContentDigest: digest, Roles: []string{tufRoleContent}})
	signed := duplicateRole.Signed
	repeated := roles.signRole(t, signed, tufRoleContent)
	duplicateRole.Signatures = append(duplicateRole.Signatures, repeated)
	raw, err := json.Marshal(duplicateRole)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roles.verify(t, raw, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("two signatures from the same role were accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonSignatureThreshold)
	}

	// A signature that claims the root role but is produced by the content key.
	mismatched := roles.envelope(t, tufTestEnvelopeSpec{ContentDigest: digest, Roles: []string{tufRoleContent}})
	signedBytes, err := json.Marshal(mismatched.Signed)
	if err != nil {
		t.Fatal(err)
	}
	mismatched.Signatures = append(mismatched.Signatures, TUFEnvelopeSignature{
		Role: tufRoleRoot, KeyID: tufKeyID(roles.public[1]), Signature: base64Std(ed25519.Sign(roles.private[1], signedBytes)),
	})
	raw, err = json.Marshal(mismatched)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roles.verify(t, raw, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("signature role/key binding mismatch was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonSignatureThreshold)
	}

	// More signatures than roles exist is structurally outside the envelope.
	overflow := roles.envelope(t, tufTestEnvelopeSpec{ContentDigest: digest})
	overflow.Signatures = append(overflow.Signatures, overflow.Signatures[0], overflow.Signatures[1])
	raw, err = json.Marshal(overflow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roles.verify(t, raw, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("signature count above the role count was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonSchema)
	}
}

func TestTufManifestRejectsExpiredAndAbsurdSnapshot(t *testing.T) {
	roles := newTufTestRoles(t)
	now := tufTestNow()
	digest := tufTestDigest("content")

	expired := roles.envelopeBytes(t, tufTestEnvelopeSpec{
		ContentDigest: digest, SnapshotIssued: now.Add(-2 * time.Hour), SnapshotExpires: now.Add(-time.Hour),
	})
	if _, err := roles.verify(t, expired, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("expired snapshot role was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonExpired)
	}

	absurdTTL := roles.envelopeBytes(t, tufTestEnvelopeSpec{
		ContentDigest: digest, SnapshotIssued: now.Add(-time.Minute), SnapshotExpires: now.Add(48 * time.Hour),
	})
	if _, err := roles.verify(t, absurdTTL, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("snapshot role with an absurd TTL was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonExpired)
	}

	futureIssued := roles.envelopeBytes(t, tufTestEnvelopeSpec{
		ContentDigest: digest, SnapshotIssued: now.Add(time.Hour), SnapshotExpires: now.Add(2 * time.Hour),
	})
	if _, err := roles.verify(t, futureIssued, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("snapshot role issued in the future was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonExpired)
	}
}

func TestTufManifestEpochStrictlyMonotonic(t *testing.T) {
	roles := newTufTestRoles(t)
	now := tufTestNow()
	digest := tufTestDigest("content")

	for _, epoch := range []uint64{5, 4, 1} {
		epoch := epoch
		raw := roles.envelopeBytes(t, tufTestEnvelopeSpec{Epoch: epoch, ContentDigest: digest})
		if _, err := roles.verify(t, raw, tufTestVerifyOptions(now, 5, digest)); err == nil {
			t.Fatalf("epoch %d was accepted at high-water 5", epoch)
		} else {
			tufTestRequireReason(t, err, TUFReasonEpochRollback)
		}
	}
	higher := roles.envelopeBytes(t, tufTestEnvelopeSpec{Epoch: 6, ContentDigest: digest})
	if _, err := roles.verify(t, higher, tufTestVerifyOptions(now, 5, digest)); err != nil {
		t.Fatalf("strictly higher epoch rejected: %v", err)
	}
	zero := roles.envelopeBytes(t, tufTestEnvelopeSpec{Epoch: 1, ContentDigest: digest})
	zeroEnvelope := roles.envelope(t, tufTestEnvelopeSpec{Epoch: 1, ContentDigest: digest})
	zeroEnvelope.Signed.Epoch = 0
	raw, err := json.Marshal(zeroEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	_ = zero
	if _, err := roles.verify(t, raw, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("epoch zero was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonSchema)
	}
}

func TestTufManifestRejectsContentBindingMismatch(t *testing.T) {
	roles := newTufTestRoles(t)
	now := tufTestNow()
	digest := tufTestDigest("content")
	raw := roles.envelopeBytes(t, tufTestEnvelopeSpec{ContentDigest: digest})
	if _, err := roles.verify(t, raw, tufTestVerifyOptions(now, 0, tufTestDigest("different"))); err == nil {
		t.Fatal("envelope for another content document was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonContentBinding)
	}

	rolesDigestMismatch := roles.envelope(t, tufTestEnvelopeSpec{ContentDigest: digest})
	rolesDigestMismatch.Signed.Snapshot.ContentSHA256 = tufTestDigest("other")
	raw, err := json.Marshal(rolesDigestMismatch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roles.verify(t, raw, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("role documents disagreeing about content were accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonContentBinding)
	}
}
