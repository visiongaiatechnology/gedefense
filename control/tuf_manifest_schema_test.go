// AP-9 / S09 — strict parser, canonicalization and trust-set derivation corpus
// for the threshold manifest envelope.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func TestTufManifestRejectsNonCanonicalAndMalformedInput(t *testing.T) {
	roles := newTufTestRoles(t)
	now := tufTestNow()
	digest := tufTestDigest("content")
	valid := roles.envelope(t, tufTestEnvelopeSpec{ContentDigest: digest})
	canonical, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}

	pretty, err := json.MarshalIndent(valid, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	duplicateKey := bytes.Replace(canonical,
		[]byte(`"schema":"`+tufEnvelopeSchema+`","epoch":1,`),
		[]byte(`"schema":"`+tufEnvelopeSchema+`","epoch":1,"epoch":2,`), 1)
	unknownField := append([]byte(nil), canonical...)
	unknownField = append(unknownField[:len(unknownField)-1], []byte(`,"unexpected":1}`)...)
	badBase64 := roles.envelope(t, tufTestEnvelopeSpec{ContentDigest: digest})
	badBase64.Signatures[0].Signature = "!!!not-canonical-base64!!!"
	badBase64Raw, err := json.Marshal(badBase64)
	if err != nil {
		t.Fatal(err)
	}
	uppercaseDigest := roles.envelope(t, tufTestEnvelopeSpec{ContentDigest: digest})
	uppercaseDigest.Signed.ContentSHA256 = strings.ToUpper(digest)
	uppercaseRaw, err := json.Marshal(uppercaseDigest)
	if err != nil {
		t.Fatal(err)
	}
	zeroKeyID := roles.envelope(t, tufTestEnvelopeSpec{ContentDigest: digest})
	zeroKeyID.Signed.Root.KeyID = strings.Repeat("0", 64)
	zeroKeyRaw, err := json.Marshal(zeroKeyID)
	if err != nil {
		t.Fatal(err)
	}
	trailing := append(append([]byte(nil), canonical...), []byte(`{}`)...)
	oversized := append(append([]byte(nil), canonical...), bytes.Repeat([]byte(" "), tufMaxEnvelopeBytes)...)

	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"pretty-printed-non-canonical", pretty, TUFReasonSchema},
		{"duplicate-json-key", duplicateKey, TUFReasonSchema},
		{"unknown-json-field", unknownField, TUFReasonSchema},
		{"trailing-data", trailing, TUFReasonSchema},
		{"oversized-payload", oversized, TUFReasonSchema},
		{"bad-base64-signature", badBase64Raw, TUFReasonSignatureThreshold},
		{"uppercase-hex-digest", uppercaseRaw, TUFReasonSchema},
		{"zero-key-id", zeroKeyRaw, TUFReasonSchema},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := roles.verify(t, testCase.raw, tufTestVerifyOptions(now, 0, digest)); err == nil {
				t.Fatalf("%s was accepted", testCase.name)
			} else {
				tufTestRequireReason(t, err, testCase.want)
			}
		})
	}
}

func TestTufManifestDeterministicCanonicalBytes(t *testing.T) {
	roles := newTufTestRoles(t)
	digest := tufTestDigest("content")
	first := roles.envelope(t, tufTestEnvelopeSpec{ContentDigest: digest, Roles: []string{tufRoleRoot, tufRoleContent}})
	second := roles.envelope(t, tufTestEnvelopeSpec{ContentDigest: digest, Roles: []string{tufRoleContent, tufRoleRoot}})
	firstRaw, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstRaw, secondRaw) {
		t.Fatal("signature ordering was expected to differ in the envelope bytes")
	}
	_, firstSigned, err := parseTUFManifestEnvelope(firstRaw)
	if err != nil {
		t.Fatal(err)
	}
	_, secondSigned, err := parseTUFManifestEnvelope(secondRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstSigned, secondSigned) {
		t.Fatal("same semantic manifest produced different canonical signed bytes")
	}
	// The canonical bytes are a fixed point of the encoder.
	reencoded, err := json.Marshal(first.Signed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, firstSigned) {
		t.Fatal("canonical signed bytes are not a fixed point of encoding/json")
	}
}

func TestTufManifestRootBindsSnapshotKey(t *testing.T) {
	roles := newTufTestRoles(t)
	now := tufTestNow()
	digest := tufTestDigest("content")
	wrongBinding := roles.envelopeBytes(t, tufTestEnvelopeSpec{
		ContentDigest: digest, RootSnapshotKeyID: tufKeyID(roles.public[0]),
	})
	if _, err := roles.verify(t, wrongBinding, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("root role binding a foreign snapshot key was accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonSignatureThreshold)
	}

	// Key rotation: a new snapshot key set changes the trusted snapshot id, and
	// the old envelope (root still naming the old key) must not verify.
	rotated := &TUFTrustSet{
		Root: roles.trust.Root, Content: roles.trust.Content, Snapshot: roles.public[0],
		RootID: roles.trust.RootID, ContentID: roles.trust.ContentID, SnapshotID: tufKeyID(roles.public[0]),
	}
	rotatedRaw := roles.envelopeBytes(t, tufTestEnvelopeSpec{ContentDigest: digest})
	if _, err := verifyTUFManifestEnvelope(rotatedRaw, rotated, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("envelope accepted after an unanchored snapshot key rotation")
	}
}

func TestTufManifestTrustSetDerivation(t *testing.T) {
	roles := newTufTestRoles(t)
	if roles.trust.RootID != tufKeyID(roles.public[0]) || roles.trust.ContentID != tufKeyID(roles.public[1]) || roles.trust.SnapshotID != tufKeyID(roles.public[2]) {
		t.Fatal("role keys are not derived in trusted_signing_keys order")
	}
	if _, err := newTUFTrustSet(roles.public[:2]); err == nil {
		t.Fatal("two pinned keys were accepted as a TUF trust set")
	} else {
		tufTestRequireReason(t, err, TUFReasonCapabilityUnavailable)
	}
	duplicated := []ed25519.PublicKey{roles.public[0], roles.public[1], roles.public[0]}
	if _, err := newTUFTrustSet(duplicated); err == nil {
		t.Fatal("duplicate role keys were accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonSchema)
	}
	for _, role := range []string{tufRoleRoot, tufRoleContent, tufRoleSnapshot} {
		key, keyID, known := roles.trust.keyForRole(role)
		if !known || len(key) != ed25519.PublicKeySize || keyID != tufKeyID(key) {
			t.Fatalf("keyForRole(%q) mapping is inconsistent", role)
		}
	}
	if _, _, known := roles.trust.keyForRole("timestamp"); known {
		t.Fatal("unknown role mapped to a trusted key")
	}
}

func TestTufManifestRejectsDuplicateRoleKeyAndRoleOrder(t *testing.T) {
	roles := newTufTestRoles(t)
	now := tufTestNow()
	digest := tufTestDigest("content")

	duplicateKeyID := roles.envelope(t, tufTestEnvelopeSpec{ContentDigest: digest})
	duplicateKeyID.Signed.Root.KeyID = duplicateKeyID.Signed.Content.KeyID
	raw, err := json.Marshal(duplicateKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roles.verify(t, raw, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("two role documents naming the same key were accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonSignatureThreshold)
	}

	swappedRoles := roles.envelope(t, tufTestEnvelopeSpec{ContentDigest: digest})
	swappedRoles.Signed.Root, swappedRoles.Signed.Content = swappedRoles.Signed.Content, swappedRoles.Signed.Root
	raw, err = json.Marshal(swappedRoles)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roles.verify(t, raw, tufTestVerifyOptions(now, 0, digest)); err == nil {
		t.Fatal("role documents in the wrong order were accepted")
	} else {
		tufTestRequireReason(t, err, TUFReasonSchema)
	}
}
