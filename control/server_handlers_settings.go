// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Undo surface for protection-removing actions split out of server.go
// (refactoring wave 1a, structure-only). The config/runtime/fabric settings
// handlers live in server_settings.go and fabric_surface_api.go; this file owns
// the short-lived server-side undo tokens and the block undo handler. The mux
// registration stays in server.go.

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// undoEntry is the short-lived, server-side reversal record for a protection-removing
// action. The operator receives an opaque token; only this process can turn it back into
// the removed block or allowlist entry (F-22).
type undoEntry struct {
	kind    string
	block   BlockEntry
	target  string
	expires time.Time
}

const undoEntryTTL = 5 * time.Minute

// confirmationRequest is the body of a protection-removing action (F-22). The phrase is
// derived from the target, so it proves deliberate intent rather than authority.
type confirmationRequest struct {
	Confirmation string `json:"confirmation"`
	Reason       string `json:"reason"`
}

// requireProtectionRemovalConfirmation enforces the typed phrase and an operator reason
// before a block or allowlist entry can be removed. Removal reduces protection, so it is
// never a one-click action server-side - independent of what the browser shows.
func (s *APIServer) requireProtectionRemovalConfirmation(w http.ResponseWriter, r *http.Request, expected string) (string, bool) {
	var in confirmationRequest
	if err := decodeStrictJSON(w, r, 8<<10, &in); err != nil {
		writePublicError(w, http.StatusBadRequest, "confirmation required: "+expected)
		return "", false
	}
	reason := strings.TrimSpace(in.Reason)
	if runes := []rune(reason); len(runes) < 8 || len(runes) > 240 {
		writePublicError(w, http.StatusBadRequest, "a reason of 8-240 characters is required")
		return "", false
	}
	if strings.TrimSpace(in.Confirmation) != expected {
		writePublicError(w, http.StatusBadRequest, "confirmation required: "+expected)
		return "", false
	}
	return reason, true
}

// newUndoToken records a short-lived, server-side undo for a protection-removing action.
func (s *APIServer) newUndoToken(entry undoEntry) (string, error) {
	token, err := randomBytesHex(16)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	s.undoMu.Lock()
	if s.undoEntries == nil {
		s.undoEntries = make(map[string]undoEntry)
	}
	for key, existing := range s.undoEntries {
		if !existing.expires.After(now) {
			delete(s.undoEntries, key)
		}
	}
	if len(s.undoEntries) >= 256 {
		s.undoMu.Unlock()
		return "", errors.New("undo capacity reached")
	}
	entry.expires = now.Add(undoEntryTTL)
	s.undoEntries[token] = entry
	s.undoMu.Unlock()
	return token, nil
}

func (s *APIServer) takeUndoToken(token, kind string) (undoEntry, bool) {
	s.undoMu.Lock()
	defer s.undoMu.Unlock()
	entry, ok := s.undoEntries[strings.TrimSpace(token)]
	if !ok || entry.kind != kind || !entry.expires.After(time.Now().UTC()) {
		if ok {
			delete(s.undoEntries, strings.TrimSpace(token))
		}
		return undoEntry{}, false
	}
	delete(s.undoEntries, strings.TrimSpace(token))
	return entry, true
}

// undoBlock restores a block that an operator removed within the undo window. The undo is
// server-side: the operator only holds an opaque token, never the authority to re-add an
// arbitrary rule without the normal validation path.
func (s *APIServer) undoBlock(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if err := decodeStrictJSON(w, r, 4<<10, &in); err != nil {
		apiError(w, http.StatusBadRequest, "invalid undo request", err)
		return
	}
	entry, ok := s.takeUndoToken(in.Token, "block")
	if !ok {
		writePublicError(w, http.StatusNotFound, "undo token is unknown or expired")
		return
	}
	network := NetworkRuntimeSettings{DefaultTTLSeconds: s.cfg.Defense.DefaultTTLSeconds, MaxTTLSeconds: s.cfg.Defense.MaxTTLSeconds, MaxBlockEntries: s.cfg.Defense.MaxBlockEntries}
	if s.settings != nil {
		network = s.settings.Get().Network
	}
	remaining := time.Until(entry.block.ExpiresAt)
	if remaining < time.Minute {
		remaining = time.Minute
	}
	if remaining > time.Duration(network.MaxTTLSeconds)*time.Second {
		remaining = time.Duration(network.MaxTTLSeconds) * time.Second
	}
	enforced := false
	if enforcement, _ := s.state.Modes(); enforcement == "enforce" {
		if err := s.core.Add(entry.block.Target); err != nil {
			s.state.SetCore(false, "offline")
			apiError(w, http.StatusServiceUnavailable, "kernel core unavailable", err)
			return
		}
		enforced = true
	}
	restored, err := s.state.AddBlock(entry.block.Target, entry.block.Reason, "operator.undo", remaining, enforced, network.MaxBlockEntries)
	if err != nil {
		if enforced {
			_ = s.core.Delete(entry.block.Target)
		}
		apiError(w, http.StatusConflict, "undo rejected", err)
		return
	}
	if err := persistPolicy(s.policy, s.cfg, s.state); err != nil {
		s.state.RemoveBlockByID(restored.ID)
		if enforced {
			if rollbackErr := s.core.Delete(restored.Target); rollbackErr != nil {
				_ = s.release.FailSafe("block undo policy rollback failed")
				apiError(w, http.StatusServiceUnavailable, "kernel transaction reconciliation failed", errors.Join(err, rollbackErr))
				return
			}
		}
		apiError(w, http.StatusInternalServerError, "signed policy persistence failed", err)
		return
	}
	s.state.AddEvent(Event{Severity: "high", Kind: "block.restored", Source: "operator", Message: "Removed block rule restored through the server-side undo window", Target: restored.Target})
	writeJSON(w, http.StatusCreated, restored)
}
