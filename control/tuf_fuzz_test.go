// V6.3.0 AP-9/S09: fuzz target for the TUF-grade feed/rule manifest envelope.
package main

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// FuzzTufFeedManifest feeds arbitrary bytes into the rejecting TUF envelope
// parser and the threshold verifier. The contract: no panic, no acceptance of
// malformed input, and a clean typed error for every rejection. It complements
// the deterministic negative corpus in tuf_manifest_test.go.
func FuzzTufFeedManifest(f *testing.F) {
	seeds := [][]byte{
		{},
		[]byte("{}"),
		[]byte(`{"schema":"vgt-gedefense-tuf-manifest-v1"}`),
		[]byte(`{"schema":"vgt-gedefense-tuf-manifest-v1","epoch":1}`),
		[]byte(`{"signed":{},"signatures":[]}`),
		[]byte("\x00\x01\x02\xff"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	// Fixed, test-only keys: verification must fail cleanly for forged bytes.
	makeKey := func(seedByte byte) ed25519.PublicKey {
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = seedByte
		}
		return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	}
	trust, err := newTUFTrustSet([]ed25519.PublicKey{makeKey(1), makeKey(2), makeKey(3)})
	if err != nil {
		f.Fatalf("build test trust set: %v", err)
	}
	options := TUFVerifyOptions{Now: time.Now().UTC(), Limits: DefaultTUFLimits()}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if _, _, err := parseTUFManifestEnvelope(raw); err != nil {
			return
		}
		// Random bytes that parse may still never verify under a test-only key
		// set; the verifier must return a typed rejection, never panic.
		if _, err := verifyTUFManifestEnvelope(raw, trust, options); err == nil {
			t.Fatalf("hostile TUF envelope verified: %.80q", raw)
		}
	})
}
