package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func FuzzCoreResponseParser(f *testing.F) {
	key := []byte("0123456789abcdef0123456789abcdef")
	nonce := "0123456789abcdef0123456789abcdef"
	payload := base64.RawURLEncoding.EncodeToString([]byte("empty"))
	tag := coreProtocol + "R"
	valid := strings.Join([]string{tag, nonce, "OK", payload, coreMAC(key, tag, nonce, "OK", payload)}, " ") + "\n"
	f.Add(valid)
	f.Add("")
	f.Add(strings.Repeat("A", maxCoreResponseBytes+1))
	f.Fuzz(func(t *testing.T, response string) {
		message, err := parseCoreResponse(response, nonce, key)
		if err == nil && len(message) > 2048 {
			t.Fatalf("accepted oversized authenticated payload: %d", len(message))
		}
	})
}

func FuzzPolicyDocumentParser(f *testing.F) {
	f.Add([]byte(`{"envelope":{"version":1,"generation":0,"node_name":"n","enforcement":"observe","xdr_mode":"observe","updated_at":"2026-01-01T00:00:00Z","blocks":[]},"signature":""}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{} {}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		doc, err := decodePolicyDocument(data)
		if err == nil {
			if doc.Envelope.Version != policyDocumentVersion {
				t.Fatalf("accepted unsupported version %d", doc.Envelope.Version)
			}
			if _, err := canonicalPolicy(doc.Envelope); err != nil {
				t.Fatalf("accepted document cannot be canonicalized: %v", err)
			}
		}
	})
}

func FuzzEncryptedEnvelopeParser(f *testing.F) {
	f.Add([]byte(`{"schema":"vgt-encrypted-state-v1","cipher":"AES-256-GCM","purpose":"test","sequence":1,"aad_hash":"","nonce":"","ciphertext":""}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema":"vgt-encrypted-state-v1"} trailing`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		envelope, err := decodeEncryptedStorageEnvelope(data)
		if err == nil && envelope.Schema == "" {
			// Structural decoding may accept zero values, but it must remain
			// distinguishable from the authenticated schema.
			return
		}
	})
}
