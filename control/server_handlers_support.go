// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// JSON response writers, the opaque fault helpers and the strict request decoder
// split out of server.go (refactoring wave 1a, structure-only). Every handler
// family uses them; they carry no route registration.

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
)

// writePublicError answers with a caller-facing reason. It is used by the operator endpoints whose
// message is actionable (a refused mitigation names the setting that enabled it) and never carries
// internal detail.
func writePublicError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// opaqueFaultMessage maps a status code to a stable, non-descriptive client text.
// The operator correlates it through the returned error identifier, which is the
// only value that ties the response to the internal log line.
func opaqueFaultMessage(status int) string {
	switch {
	case status == http.StatusBadRequest:
		return "request rejected"
	case status == http.StatusUnauthorized:
		return "authorization required"
	case status == http.StatusForbidden:
		return "request rejected"
	case status == http.StatusNotFound:
		return "resource not found"
	case status == http.StatusConflict:
		return "request conflicts with the current state"
	case status == http.StatusTooManyRequests:
		return "rate limit exceeded"
	case status >= 500:
		return "internal fault"
	default:
		return "request rejected"
	}
}

// apiFault reports an internal fault opaquely. The client receives a stable text
// and an identifier; the detail goes to the log only.
func apiFault(w http.ResponseWriter, status int, internal error) {
	id := randomID()
	if internal != nil {
		log.Printf("api fault id=%s status=%d: %v", id, status, internal)
	}
	writeJSON(w, status, map[string]string{"error": opaqueFaultMessage(status), "error_id": id})
}

// apiError publishes only explicitly approved operator messages. Unknown text
// and messages identical to an internal cause are opaque, even without a cause.
func apiError(w http.ResponseWriter, status int, publicMessage string, internal error) {
	// Only registered operator messages may cross the disclosure boundary.
	if _, approved := operatorMessages[publicMessage]; !approved {
		if internal == nil {
			internal = errors.New(publicMessage)
		}
		apiFault(w, status, internal)
		return
	}
	if internal != nil {
		if publicMessage == "" || publicMessage == internal.Error() {
			apiFault(w, status, internal)
			return
		}
	}
	if publicMessage == "" {
		apiFault(w, status, nil)
		return
	}
	id := randomID()
	if internal != nil {
		log.Printf("api fault id=%s status=%d: %v", id, status, internal)
	}
	writeJSON(w, status, map[string]string{"error": publicMessage, "error_id": id})
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, max int64, dst any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, max)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}
