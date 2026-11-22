// STATUS: DIAMANT VGT SUPREME
package main

// M1.3: raw HTTP request-body malware inspection.
//
// Airlock already scanned file uploads, but a plain POST/PUT with
// application/octet-stream (or no content type at all) reached the origin
// without any malware inspection: the EICAR/webshell bytes were only visible to
// the multipart path. This method runs the same bounded streaming scan over an
// in-memory request body and maps a marker to the documented reject score.
//
// It never stages or quarantines request bytes on disk (there is no file), and it
// never changes the streaming scan bounds: the scan is chunked, overlap-safe and
// hard-capped by airlockScanBudgetBytes.

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

const (
	// airlockRequestBodyScanMaxBytes is the additional request-path cap. A body
	// above it is only inspected up to the cap (the L7 body budget already bounds
	// the request itself); no partial scan is presented as a clean full scan.
	airlockRequestBodyScanMaxBytes = 2 << 20
)

// InspectRequestBody inspects one non-multipart request body. A nil inspector or
// a disabled Airlock policy keeps the historical allow behaviour.
func (a *AirlockInspector) InspectRequestBody(contentType string, body []byte) (*AirlockInspectionResult, error) {
	if a == nil || len(body) == 0 {
		return nil, nil
	}
	policy := a.policySnapshot()
	if !policy.enabled {
		return nil, nil
	}
	scanned := body
	if len(scanned) > airlockRequestBodyScanMaxBytes {
		scanned = scanned[:airlockRequestBodyScanMaxBytes]
	}
	if len(scanned) > airlockScanBudgetBytes {
		scanned = scanned[:airlockScanBudgetBytes]
	}
	digest := sha256.Sum256(scanned)
	prefixEnd := len(scanned)
	if prefixEnd > airlockInspectHeaderBytes {
		prefixEnd = airlockInspectHeaderBytes
	}
	result := &AirlockInspectionResult{
		IsClean: true, DetectedMime: contentType, DeclaredExtension: "",
		FileSize: int64(len(body)), SHA256: hex.EncodeToString(digest[:]),
		RiskScore: 0, Timestamp: time.Now().UTC(),
	}
	if result.DetectedMime == "" {
		result.DetectedMime = DetectMagicType(scanned[:prefixEnd])
	}
	signals := newAirlockContentSignals()
	scanAirlockBytes(scanned, &signals)

	// Ordering mirrors evaluateInspection: the most specific evidence wins.
	if signals.malwareMarker {
		result.IsClean = false
		result.RiskScore = clampScore(policy.escalateScore(250))
		result.ThreatType = "MALWARE_MARKER"
		return result, NewAirlockSecurityException("request body contains a malware or webshell marker", nil)
	}
	if signals.polyglotIndex >= 0 {
		result.IsClean = false
		result.RiskScore = clampScore(policy.escalateScore(230))
		result.ThreatType = "SCRIPT_PAYLOAD"
		return result, NewAirlockSecurityException("request body contains an executable script payload", nil)
	}
	if signals.htmlActiveContent {
		result.IsClean = false
		result.RiskScore = clampScore(policy.escalateScore(200))
		result.ThreatType = "HTML_ACTIVE_CONTENT"
		return result, NewAirlockSecurityException("request body contains active HTML content", nil)
	}
	return result, nil
}
