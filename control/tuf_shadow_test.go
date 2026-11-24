// AP-9 / S09 / R5 interim isolation — bounded shadow-parse corpus for
// untrusted feed bytes.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestTufShadowParseAcceptsBoundedDocuments(t *testing.T) {
	text := []byte("# comment\n203.0.113.7\n198.51.100.9 ; annotation\n2001:db8::9\n")
	document, err := ShadowParseFeedBytes(text, DefaultTUFShadowLimits(1000, 1<<20))
	if err != nil {
		t.Fatalf("valid line document rejected: %v", err)
	}
	if document.Format != "lines" || document.Candidates != 3 || document.DuplicateCandidates != 0 {
		t.Fatalf("line document representation = %+v", document)
	}
	digest := sha256.Sum256(text)
	if document.DigestSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("shadow parse digest does not bind the raw bytes")
	}

	jsonDocument := []byte(`[{"cidr":"203.0.113.0/24"},{"cidr":"198.51.100.0/24"}]`)
	document, err = ShadowParseFeedBytes(jsonDocument, DefaultTUFShadowLimits(1000, 1<<20))
	if err != nil {
		t.Fatalf("valid JSON document rejected: %v", err)
	}
	if document.Format != "json" {
		t.Fatalf("format = %q, want json", document.Format)
	}

	duplicates := []byte("203.0.113.7\n203.0.113.7\n198.51.100.9\n")
	document, err = ShadowParseFeedBytes(duplicates, DefaultTUFShadowLimits(1000, 1<<20))
	if err != nil {
		t.Fatalf("document with duplicate indicators rejected: %v", err)
	}
	if document.Candidates != 3 || document.DuplicateCandidates != 1 {
		t.Fatalf("duplicate census = %+v", document)
	}
}

func TestTufShadowParseRejectsOutOfBoundDocuments(t *testing.T) {
	baseLimits := DefaultTUFShadowLimits(1000, 1<<20)

	tooLarge := make([]byte, 4096)
	for index := range tooLarge {
		tooLarge[index] = 'a'
	}
	smallByteLimits := baseLimits
	smallByteLimits.MaxBytes = 1024
	if _, err := ShadowParseFeedBytes(tooLarge, smallByteLimits); err == nil {
		t.Fatal("oversized document passed the shadow parse")
	} else {
		tufTestRequireReason(t, err, TUFReasonShadowParse)
	}

	if _, err := ShadowParseFeedBytes([]byte("203.0.113.7\n\x00\n"), baseLimits); err == nil {
		t.Fatal("NUL byte passed the shadow parse")
	} else {
		tufTestRequireReason(t, err, TUFReasonShadowParse)
	}

	smallLineLimits := baseLimits
	smallLineLimits.MaxLineBytes = 8
	if _, err := ShadowParseFeedBytes([]byte("203.0.113.7\n"), smallLineLimits); err == nil {
		t.Fatal("oversized line passed the shadow parse")
	}

	smallLineCount := baseLimits
	smallLineCount.MaxLines = 2
	if _, err := ShadowParseFeedBytes([]byte("203.0.113.7\n198.51.100.9\n2001:db8::9\n"), smallLineCount); err == nil {
		t.Fatal("excessive line count passed the shadow parse")
	}

	smallNesting := baseLimits
	smallNesting.MaxNesting = 2
	if _, err := ShadowParseFeedBytes([]byte(`[[[{"cidr":"203.0.113.0/24"}]]]`), smallNesting); err == nil {
		t.Fatal("excessive JSON nesting passed the shadow parse")
	} else {
		tufTestRequireReason(t, err, TUFReasonShadowParse)
	}

	if _, err := ShadowParseFeedBytes([]byte(`[{"cidr":"203.0.113.0/24"}`), baseLimits); err == nil {
		t.Fatal("truncated JSON document passed the shadow parse")
	}
	if _, err := ShadowParseFeedBytes([]byte(`[{"cidr":"x"}}]`), baseLimits); err == nil {
		t.Fatal("unbalanced JSON brackets passed the shadow parse")
	}
}

func TestTufShadowValidateFeedBytesIntegrationPoint(t *testing.T) {
	if err := tufShadowValidateFeedBytes(nil, 100, 1<<20); err != nil {
		t.Fatalf("empty document must keep the existing empty-download semantics: %v", err)
	}
	if err := tufShadowValidateFeedBytes([]byte(" \n\t\n"), 100, 1<<20); err != nil {
		t.Fatalf("whitespace-only document must keep the existing semantics: %v", err)
	}
	if err := tufShadowValidateFeedBytes([]byte("203.0.113.7\n"), 100, 1<<20); err != nil {
		t.Fatalf("valid document was rejected: %v", err)
	}
	err := tufShadowValidateFeedBytes([]byte("203.0.113.7\x01\n"), 100, 1<<20)
	if err == nil {
		t.Fatal("control character document passed the integration point")
	}
	if reason := tufErrorReason(err); reason != TUFReasonShadowParse {
		t.Fatalf("integration reason = %q, want %q", reason, TUFReasonShadowParse)
	}
	if !strings.Contains(err.Error(), "shadow parser") {
		t.Fatalf("integration error does not name the shadow parser: %v", err)
	}
}
