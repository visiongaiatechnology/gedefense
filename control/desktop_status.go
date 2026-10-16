// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// The desktop status socket.
//
// A per-user desktop indicator needs neither privilege nor a secret: it needs a truthful, bounded
// statement about the protection. The two existing channels are unusable for that - the dashboard
// API requires the operator token (root-owned, 0600) and the core IPC is VGT3-authenticated for the
// control plane - so this socket exists as a third, deliberately minimal surface: exactly one
// read-only operation, hard size and time limits, peer-credential auditing, and no field that names
// a path, a hash or a secret.
//
// Every value in the telegram is derived from the state the operator sees in the interface, so the
// indicator cannot tell a different story than the panel.

const (
	desktopStatusProtocolVersion = 1
	desktopRequestLimit          = 256
	desktopResponseLimit         = 4096
	desktopRequestTimeout        = 3 * time.Second
	desktopWriteTimeout          = 2 * time.Second
	desktopSummaryLimit          = 160
)

// Desktop states, ordered by severity. The tray maps them to an icon; the icon carries the state
// by shape as well as by colour, so the indicator stays readable without colour perception.
const (
	desktopStateSecure  = "secure"
	desktopStateWarning = "warning"
	desktopStateAlert   = "alert"
	desktopStateStopped = "stopped"
)

// DesktopConfig configures the read-only status socket for desktop indicators.
//
// The default is deliberately the narrow one: mode 0660 with a dedicated group. A socket every local
// user may read would widen access to incident summaries that the dashboard protects with a token -
// so the group exists, the packaging adds the desktop user to it, and a missing group is an error
// the operator sees in the journal instead of a silent permission downgrade.
type DesktopConfig struct {
	Enabled               bool
	SocketPath            string
	SocketMode            string
	SocketGroup           string
	AlertWindowSeconds    int
	MaxConnectionsPerUser int
	RateLimitPerMinute    int
	RateLimitBurst        int
}

const (
	defaultDesktopSocketPath            = "/run/gedefense/gedefense.sock"
	defaultDesktopSocketMode            = "0660"
	defaultDesktopSocketGroup           = "gedefense-desktop"
	defaultDesktopAlertWindowSeconds    = 600
	defaultDesktopMaxConnectionsPerUser = 2
	defaultDesktopRateLimitPerMinute    = 60
	defaultDesktopRateLimitBurst        = 10
	desktopMaxTrackedClients            = 4096
)

func defaultDesktopConfig() DesktopConfig {
	return DesktopConfig{
		Enabled:               true,
		SocketPath:            defaultDesktopSocketPath,
		SocketMode:            defaultDesktopSocketMode,
		SocketGroup:           defaultDesktopSocketGroup,
		AlertWindowSeconds:    defaultDesktopAlertWindowSeconds,
		MaxConnectionsPerUser: defaultDesktopMaxConnectionsPerUser,
		RateLimitPerMinute:    defaultDesktopRateLimitPerMinute,
		RateLimitBurst:        defaultDesktopRateLimitBurst,
	}
}

type desktopStatusRequest struct {
	Version int    `json:"v"`
	Op      string `json:"op"`
}

type desktopStatusAlert struct {
	Summary  string `json:"summary"`
	Severity string `json:"severity"`
	Since    string `json:"since"`
}

type desktopStatusPayload struct {
	Version          int                 `json:"v"`
	Status           string              `json:"status"`
	StatusReason     string              `json:"status_reason"`
	GeneratedAt      string              `json:"generated_at"`
	ProductVersion   string              `json:"product_version"`
	NodeName         string              `json:"node_name"`
	ReleasePhase     string              `json:"release_phase"`
	Enforcement      string              `json:"enforcement"`
	KernelPolicy     string              `json:"kernel_policy"`
	EBPFActive       bool                `json:"ebpf_active"`
	Sensor           string              `json:"sensor"`
	ThreatCountToday int                 `json:"threat_count_today"`
	BlockedActive    int                 `json:"blocked_active"`
	LastAnomalyAt    string              `json:"last_anomaly_at"`
	LastAnomalyText  string              `json:"last_anomaly_summary"`
	ActiveAlert      *desktopStatusAlert `json:"active_alert"`
}

// desktopStatusDecision is the derivation result: a state and the sentence that explains it.
//
// The reason is not decoration. A badge that reports a condition without naming it is the defect
// this product has already had to fix twice, so the telegram always carries the cause.
type desktopStatusDecision struct {
	Status string
	Reason string
}

// deriveDesktopStatus maps the state to the indicator.
//
// Deliberate deviation from the original sketch: an attack that was *blocked* does not turn the
// indicator red. Blocking is the product working, and on an exposed host it happens hundreds of
// times a day - a permanent red light is alarm fatigue and the security-UI rule forbids it. Red is
// reserved for what is unresolved: violated integrity, a critical finding inside the window, or a
// protection that is not active at all.
func deriveDesktopStatus(snap Snapshot, now time.Time, window time.Duration) desktopStatusDecision {
	if !snap.CoreConnected {
		return desktopStatusDecision{desktopStateStopped, "Kern nicht verbunden – keine Durchsetzung im Datenpfad"}
	}
	if enforcement := strings.ToLower(strings.TrimSpace(snap.Enforcement)); enforcement != "enforce" {
		state := desktopStateStopped
		label := enforcement
		if label == "" {
			label = "unbekannt"
		}
		return desktopStatusDecision{state, "Schutz nicht aktiv: Durchsetzung " + label}
	}
	if strings.EqualFold(strings.TrimSpace(snap.FIM.Health), "TAMPERED") {
		return desktopStatusDecision{desktopStateAlert, "Systemintegrität verletzt: überwachte Datei verändert"}
	}
	if incident, ok := worstIncidentWithin(snap.Incidents, now, window, "critical"); ok {
		return desktopStatusDecision{desktopStateAlert, "Kritischer Vorfall: " + boundedSummary(incident.Summary)}
	}
	if snap.XDR.Degraded {
		reason := strings.TrimSpace(snap.XDR.DegradedReason)
		if reason == "" {
			reason = "Ursache nicht benannt"
		}
		return desktopStatusDecision{desktopStateWarning, "Automatik ausgesetzt, Kernel-Durchsetzung bleibt aktiv: " + boundedSummary(reason)}
	}
	if phase := strings.ToLower(strings.TrimSpace(snap.Release.Phase)); phase != "" && phase != ReleasePhaseEnforce {
		return desktopStatusDecision{desktopStateWarning, "Freigabephase " + phase + " – noch keine volle Schärfe"}
	}
	if !snap.Evidence.Healthy && snap.Evidence.Enabled {
		return desktopStatusDecision{desktopStateWarning, "Forensik-Ledger nicht gesund"}
	}
	if incident, ok := worstIncidentWithin(snap.Incidents, now, window, "high"); ok {
		return desktopStatusDecision{desktopStateWarning, "Vorfall hoher Schwere: " + boundedSummary(incident.Summary)}
	}
	return desktopStatusDecision{desktopStateSecure, "Kernel-Durchsetzung aktiv und bestätigt, keine offenen Alarme"}
}

func worstIncidentWithin(incidents []XDRIncident, now time.Time, window time.Duration, severity string) (XDRIncident, bool) {
	cutoff := now.Add(-window)
	var (
		best    XDRIncident
		found   bool
		bestAge time.Duration
	)
	for _, incident := range incidents {
		if incident.Time.IsZero() || incident.Time.Before(cutoff) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(incident.Severity), severity) {
			continue
		}
		age := now.Sub(incident.Time)
		if !found || age < bestAge {
			best, bestAge, found = incident, age, true
		}
	}
	return best, found
}

// buildDesktopStatus assembles the telegram. It is separated from the transport so the derivation
// and the field limits are testable without a socket.
func buildDesktopStatus(snap Snapshot, now time.Time, window time.Duration) desktopStatusPayload {
	decision := deriveDesktopStatus(snap, now, window)
	payload := desktopStatusPayload{
		Version:          desktopStatusProtocolVersion,
		Status:           decision.Status,
		StatusReason:     boundedSummary(decision.Reason),
		GeneratedAt:      now.UTC().Format(time.RFC3339),
		ProductVersion:   boundedText(snap.Version, 32),
		NodeName:         boundedText(snap.NodeName, 64),
		ReleasePhase:     boundedText(strings.ToLower(snap.Release.Phase), 16),
		Enforcement:      boundedText(strings.ToLower(snap.Enforcement), 16),
		KernelPolicy:     boundedText(strings.ToLower(snap.Release.KernelPolicyState), 24),
		EBPFActive:       snap.CoreConnected,
		Sensor:           boundedText(snap.XDR.Sensor, 96),
		BlockedActive:    enforcedBlockCount(snap.Blocks),
		ThreatCountToday: threatsToday(snap.Blocks, now),
	}
	if latest, ok := latestIncident(snap.Incidents); ok {
		payload.LastAnomalyAt = latest.Time.UTC().Format(time.RFC3339)
		payload.LastAnomalyText = boundedSummary(latest.Summary)
	}
	if decision.Status == desktopStateAlert {
		if incident, ok := worstIncidentWithin(snap.Incidents, now, window, "critical"); ok {
			payload.ActiveAlert = &desktopStatusAlert{
				Summary:  boundedSummary(incident.Summary),
				Severity: boundedText(strings.ToLower(incident.Severity), 16),
				Since:    incident.Time.UTC().Format(time.RFC3339),
			}
		} else if strings.EqualFold(strings.TrimSpace(snap.FIM.Health), "TAMPERED") {
			payload.ActiveAlert = &desktopStatusAlert{
				Summary:  "Systemintegrität verletzt: überwachte Datei verändert",
				Severity: "high",
				Since:    payload.GeneratedAt,
			}
		}
	}
	return payload
}

func enforcedBlockCount(blocks []BlockEntry) int {
	count := 0
	for _, block := range blocks {
		if block.Enforced {
			count++
		}
	}
	return count
}

// threatsToday counts the blocks that were applied since local midnight. The counter in the kinetic
// telemetry is a lifetime total and would make the indicator claim a number that never resets.
func threatsToday(blocks []BlockEntry, now time.Time) int {
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	count := 0
	for _, block := range blocks {
		if block.CreatedAt.IsZero() {
			continue
		}
		if !block.CreatedAt.Before(midnight) {
			count++
		}
	}
	return count
}

func latestIncident(incidents []XDRIncident) (XDRIncident, bool) {
	var (
		latest XDRIncident
		found  bool
	)
	for _, incident := range incidents {
		if incident.Time.IsZero() {
			continue
		}
		if !found || incident.Time.After(latest.Time) {
			latest, found = incident, true
		}
	}
	return latest, found
}

// boundedSummary keeps one line of operator-facing text inside the response budget and strips
// control characters, so a hostile incident summary cannot break the framing or the display.
func boundedSummary(value string) string {
	return boundedText(strings.Join(strings.Fields(value), " "), desktopSummaryLimit)
}

func boundedText(value string, limit int) string {
	trimmed := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	if limit <= 0 || len(trimmed) <= limit {
		return trimmed
	}
	// A byte cut can split a multi-byte rune; step back until the prefix is valid UTF-8 so the
	// telegram never carries a broken sequence.
	clipped := trimmed[:limit]
	for len(clipped) > 0 && !utf8.ValidString(clipped) {
		clipped = clipped[:len(clipped)-1]
	}
	return clipped
}

func encodeDesktopPayload(payload desktopStatusPayload) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal desktop status: %w", err)
	}
	if len(data)+1 > desktopResponseLimit {
		return nil, fmt.Errorf("desktop status telegram exceeds %d bytes", desktopResponseLimit)
	}
	return append(data, '\n'), nil
}
