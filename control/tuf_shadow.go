// AP-9 / S09 / R5 interim parser isolation — bounded Go-side shadow parse of
// untrusted feed bytes.
//
// R5 requires feed/rule/YARA bundles to be parsed inside the sandboxed
// gedefense-cell-helper first. The helper protocol (CELL_CREATE / CELL_EXPORT_READ)
// can run a pinned parser in a seccomp+namespace cell, but there is no feed / rule
// bundle profile and no bounded structured-IR contract yet, so routing feeds
// through it today would be a protocol change outside the S09 file ownership.
//
// Until that integration exists, every downloaded feed document is first walked
// by this shadow parser: a bounded, allocation-light structural pass that proves
// the document fits a small intermediate representation (size, line count, line
// length, encoding/canonical control characters, JSON nesting depth, duplicate
// census) before the existing feed parser ever sees it. The status projection
// reports r5_isolation=shadow and r5_helper_isolation=helper-pending rather than
// claiming a cell isolation that is not wired.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// TUFShadowFeedDocument is the bounded intermediate representation returned by
// the shadow parse. It holds no raw untrusted content, only counters and a
// digest, so downstream code cannot accidentally treat it as trusted data.
type TUFShadowFeedDocument struct {
	Format              string
	Bytes               int64
	Lines               int
	Candidates          int
	DuplicateCandidates int
	MaxNesting          int
	DigestSHA256        string
}

// TUFShadowLimits bounds the shadow parse work.
type TUFShadowLimits struct {
	MaxBytes         int64
	MaxLines         int
	MaxLineBytes     int
	MaxNesting       int
	MaxTrackedTokens int
}

// DefaultTUFShadowLimits derives the shadow bounds from the administrable
// per-feed bounds. maxBytes comes from the feed configuration (bounded to
// 64 MiB by the threat-intelligence fabric); maxEntries from the same source.
func DefaultTUFShadowLimits(maxEntries int, maxBytes int64) TUFShadowLimits {
	if maxEntries < 1 {
		maxEntries = 1
	}
	maxLines := maxEntries*2 + 4096
	if maxLines < 4096 {
		maxLines = 4096
	}
	if maxLines > 1<<24 {
		maxLines = 1 << 24
	}
	if maxBytes <= 0 {
		maxBytes = 16 << 20
	}
	return TUFShadowLimits{
		MaxBytes:         maxBytes,
		MaxLines:         maxLines,
		MaxLineBytes:     64 << 10,
		MaxNesting:       16,
		MaxTrackedTokens: 8192,
	}
}

func (l TUFShadowLimits) normalised() TUFShadowLimits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = 16 << 20
	}
	if l.MaxLines <= 0 {
		l.MaxLines = 1 << 20
	}
	if l.MaxLineBytes <= 0 {
		l.MaxLineBytes = 64 << 10
	}
	if l.MaxNesting <= 0 {
		l.MaxNesting = 16
	}
	if l.MaxTrackedTokens <= 0 {
		l.MaxTrackedTokens = 8192
	}
	return l
}

// ShadowParseFeedBytes walks one untrusted feed document and returns the
// bounded intermediate representation. It rejects oversized payloads, excessive
// line counts or line lengths, control characters/NUL bytes, JSON nesting beyond
// the bound, and unbalanced JSON bracket structure. Duplicate candidates are
// counted (the feed parser deduplicates later) but not rejected: repeated
// indicators are a normal, harmless property of aggregated feeds.
func ShadowParseFeedBytes(raw []byte, limits TUFShadowLimits) (*TUFShadowFeedDocument, error) {
	limits = limits.normalised()
	if int64(len(raw)) > limits.MaxBytes {
		return nil, newTUFError(TUFReasonShadowParse, "feed document exceeds the bounded shadow-parse size")
	}
	if len(raw) == 0 {
		return nil, newTUFError(TUFReasonShadowParse, "feed document is empty")
	}
	document := &TUFShadowFeedDocument{Bytes: int64(len(raw)), Format: "lines"}
	first := 0
	for first < len(raw) && (raw[first] == ' ' || raw[first] == '\t' || raw[first] == '\r' || raw[first] == '\n') {
		first++
	}
	if first < len(raw) && (raw[first] == '[' || raw[first] == '{') {
		document.Format = "json"
	}
	lineBound := limits.MaxLineBytes
	if document.Format == "json" {
		// A legitimate JSON producer may publish one large minified document;
		// the byte bound above is the structural bound for that shape.
		lineBound = len(raw)
	}
	tracked := make(map[string]struct{}, 64)
	depth := 0
	inString := false
	escaped := false
	lineStart := 0
	for position := 0; position <= len(raw); position++ {
		var b byte
		if position < len(raw) {
			b = raw[position]
			if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
				return nil, newTUFError(TUFReasonShadowParse, "feed document contains a control character")
			}
			if document.Format == "json" {
				if inString {
					if escaped {
						escaped = false
					} else if b == '\\' {
						escaped = true
					} else if b == '"' {
						inString = false
					}
				} else {
					switch b {
					case '"':
						inString = true
					case '[', '{':
						depth++
						if depth > document.MaxNesting {
							document.MaxNesting = depth
						}
						if depth > limits.MaxNesting {
							return nil, newTUFError(TUFReasonShadowParse, "JSON nesting exceeds the bounded depth")
						}
					case ']', '}':
						depth--
						if depth < 0 {
							return nil, newTUFError(TUFReasonShadowParse, "JSON bracket structure is unbalanced")
						}
					}
				}
			}
			if b != '\n' {
				continue
			}
		}
		lineEnd := position
		if lineEnd > lineStart && raw[lineEnd-1] == '\r' {
			lineEnd--
		}
		line := raw[lineStart:lineEnd]
		lineStart = position + 1
		document.Lines++
		if document.Lines > limits.MaxLines {
			return nil, newTUFError(TUFReasonShadowParse, "feed document exceeds the bounded line count")
		}
		if len(line) > lineBound {
			return nil, newTUFError(TUFReasonShadowParse, "feed document contains an oversized line")
		}
		candidate := trimShadowLine(line)
		if len(candidate) == 0 || candidate[0] == '#' || candidate[0] == ';' {
			continue
		}
		document.Candidates++
		if document.Candidates > limits.MaxLines {
			return nil, newTUFError(TUFReasonShadowParse, "feed document exceeds the bounded candidate count")
		}
		if len(tracked) < limits.MaxTrackedTokens {
			key := string(candidate)
			if _, duplicate := tracked[key]; duplicate {
				document.DuplicateCandidates++
			} else {
				tracked[key] = struct{}{}
			}
		}
	}
	if document.Format == "json" {
		if inString || depth != 0 {
			return nil, newTUFError(TUFReasonShadowParse, "JSON document is truncated or unbalanced")
		}
	}
	digest := sha256.Sum256(raw)
	document.DigestSHA256 = hex.EncodeToString(digest[:])
	return document, nil
}

// trimShadowLine trims ASCII whitespace without copying when nothing changes.
func trimShadowLine(line []byte) []byte {
	start := 0
	for start < len(line) && (line[start] == ' ' || line[start] == '\t') {
		start++
	}
	end := len(line)
	for end > start && (line[end-1] == ' ' || line[end-1] == '\t') {
		end--
	}
	return line[start:end]
}

// tufShadowValidateFeedBytes is the feed-pipeline entry point of the interim R5
// mitigation: it shadow-parses the exact untrusted raw bytes before the existing
// feed parser or the signed-manifest verifier consumes them. An empty document
// is passed through so the existing empty-download handling keeps its exact
// error/status semantics.
func tufShadowValidateFeedBytes(raw []byte, maxEntries int, maxBytes int64) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	limits := DefaultTUFShadowLimits(maxEntries, maxBytes)
	if _, err := ShadowParseFeedBytes(raw, limits); err != nil {
		return NewThreatIntelSecurityException("untrusted feed document rejected by the bounded shadow parser", err)
	}
	return nil
}

// ShadowParseSummary is the log/status-safe one-line summary of a shadow parse.
func ShadowParseSummary(document *TUFShadowFeedDocument) string {
	if document == nil {
		return "shadow-parse=not-run"
	}
	return fmt.Sprintf("shadow-parse format=%s bytes=%d lines=%d candidates=%d duplicates=%d digests=%s",
		document.Format, document.Bytes, document.Lines, document.Candidates, document.DuplicateCandidates, document.DigestSHA256)
}
