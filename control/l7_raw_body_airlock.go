// STATUS: DIAMANT VGT SUPREME
package main

// M1.3: the L7 detector for raw (non-multipart) request bodies. The multipart
// path keeps its own upload detector; this one covers POST/PUT bodies whose
// content type is octet-stream, text or unknown, which previously skipped the
// malware markers entirely (the MAL-EICAR-HTTP class).

import (
	"context"
	"strings"
)

type l7RawBodyAirlockDetector struct {
	engine *L7Engine
}

func (d l7RawBodyAirlockDetector) Detect(ctx context.Context, req l7NormalizedRequest, _ *l7RuntimeSnapshot) ([]L7Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.engine == nil || d.engine.airlock == nil || len(req.Body) == 0 {
		return nil, nil
	}
	switch strings.ToUpper(req.Method) {
	case "POST", "PUT", "PATCH":
	default:
		return nil, nil
	}
	// Structured bodies are already parsed and inspected field by field; the raw
	// scan is for opaque payloads. Multipart has its own upload detector.
	switch {
	case req.ContentType == "multipart/form-data",
		isL7JSONMediaType(req.ContentType),
		isL7XMLMediaType(req.ContentType),
		req.ContentType == "application/x-www-form-urlencoded":
		return nil, nil
	}
	result, inspectErr := d.engine.airlock.InspectRequestBody(req.ContentType, req.Body)
	if inspectErr == nil || result == nil {
		return nil, nil
	}
	finding := newL7Finding(
		"L7.UPLOAD."+result.ThreatType, "file-upload", "critical",
		clampScore(result.RiskScore), 96, "body.raw", result.SHA256,
		"Airlock rejected marker content in a raw request body",
	)
	return []L7Finding{finding}, nil
}
