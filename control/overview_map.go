// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The overview threat map answers one question the per-area views cannot: where is all of this coming
// from, right now, across every detection path at once.
//
// It deliberately reads from only two places, because the platform already unifies the rest:
//
//   - the kinetic engine's source matrix (packet-level offenders, with their block state), and
//   - the incident stream, which carries the layer-7 findings, the post-exploitation chain and the
//     correlation between them in one record.
//
// Nothing is guessed. A source the local GeoIP matrix cannot place keeps its counters and simply has no
// coordinates; an incident without a remote endpoint is not drawn at all, because a point on a map is a
// claim about where something came from.
const (
	overviewThreatMapDefaultSources = 250
	overviewThreatMapMaxSources     = 500
	overviewThreatMapDefaultEvents  = 120
	overviewThreatMapMaxEvents      = 300
)

// OverviewThreatMapSource is one origin on the map. Kinetic sources carry hit counters and the block
// state; incident-based sources carry what was detected and how it was answered.
type OverviewThreatMapSource struct {
	IP          string            `json:"ip"`
	Area        string            `json:"area"`
	Areas       []string          `json:"areas,omitempty"`
	CountryCode string            `json:"country_code,omitempty"`
	Country     string            `json:"country,omitempty"`
	ASN         string            `json:"asn,omitempty"`
	ASName      string            `json:"as_name,omitempty"`
	Latitude    *float64          `json:"latitude,omitempty"`
	Longitude   *float64          `json:"longitude,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	Blocked     bool              `json:"blocked"`
	Hits        int               `json:"hits,omitempty"`
	Attempts    int               `json:"attempts,omitempty"`
	Score       int               `json:"score,omitempty"`
	Service     string            `json:"service,omitempty"`
	LastSeen    time.Time         `json:"last_seen"`
	Summary     string            `json:"summary,omitempty"`
	Rules       []string          `json:"rules,omitempty"`
	Story       []AttackStoryNode `json:"story,omitempty"`
}

// OverviewThreatMapCountry is the per-country roll-up the map draws its heat and its list from. The
// per-area counters are kept apart so the panel can show which path saw what.
type OverviewThreatMapCountry struct {
	CountryCode string   `json:"country_code"`
	Country     string   `json:"country"`
	Total       int      `json:"total"`
	Kinetic     int      `json:"kinetic"`
	L7          int      `json:"l7"`
	XDR         int      `json:"xdr"`
	Blocked     int      `json:"blocked"`
	Severity    string   `json:"severity,omitempty"`
	Latitude    *float64 `json:"latitude,omitempty"`
	Longitude   *float64 `json:"longitude,omitempty"`
}

// OverviewThreatMapEvent is one line of the live activity band under the map. Unlike a map source it
// does not need coordinates: an event without a remote endpoint is still an event, and the band must
// keep showing the newest ones even when nothing is arriving right now - the incident ledger is the
// history, and a quiet minute is not an empty panel.
type OverviewThreatMapEvent struct {
	ID          string    `json:"id"`
	Time        time.Time `json:"time"`
	Area        string    `json:"area"`
	Severity    string    `json:"severity,omitempty"`
	Score       int       `json:"score,omitempty"`
	Remote      string    `json:"remote,omitempty"`
	Country     string    `json:"country,omitempty"`
	CountryCode string    `json:"country_code,omitempty"`
	Process     string    `json:"process,omitempty"`
	Method      string    `json:"method,omitempty"`
	Host        string    `json:"host,omitempty"`
	Path        string    `json:"path,omitempty"`
	Summary     string    `json:"summary,omitempty"`
	Rules       []string  `json:"rules,omitempty"`
	Decision    string    `json:"decision,omitempty"`
	Blocked     bool      `json:"blocked"`
}

type OverviewThreatMapResponse struct {
	Sources    []OverviewThreatMapSource  `json:"sources"`
	Countries  []OverviewThreatMapCountry `json:"countries"`
	Recent     []OverviewThreatMapEvent   `json:"recent"`
	Origin     KineticOrigin              `json:"origin"`
	OriginNote string                     `json:"origin_note"`
	Geo        any                        `json:"geo,omitempty"`
	Totals     map[string]int             `json:"totals"`
	Generated  time.Time                  `json:"generated"`
}

// severityRank orders severities so that a merged source keeps the worst one it was reported with.
func severityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func worstSeverity(current, candidate string) string {
	if severityRank(candidate) > severityRank(current) {
		return candidate
	}
	return current
}

// overviewThreatMap serves the aggregated map data. It never invents a position: a source without
// coordinates is still returned, with its counters, so the panel can count it and say that it could not
// be placed.
func (s *APIServer) overviewThreatMap(w http.ResponseWriter, r *http.Request) {
	limit := overviewThreatMapDefaultSources
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= overviewThreatMapMaxSources {
			limit = parsed
		}
	}
	events := overviewThreatMapDefaultEvents
	if raw := strings.TrimSpace(r.URL.Query().Get("events")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= overviewThreatMapMaxEvents {
			events = parsed
		}
	}

	byIP := make(map[string]*OverviewThreatMapSource)
	order := make([]string, 0, limit)

	add := func(source OverviewThreatMapSource) {
		if source.IP == "" {
			return
		}
		existing, ok := byIP[source.IP]
		if !ok {
			copied := source
			if copied.Areas == nil {
				copied.Areas = []string{source.Area}
			}
			byIP[source.IP] = &copied
			order = append(order, source.IP)
			return
		}
		// The same address can be seen by the packet path and by an inspection path. Merge instead of
		// drawing it twice: the panel must not show one attacker as two.
		existing.Severity = worstSeverity(existing.Severity, source.Severity)
		existing.Blocked = existing.Blocked || source.Blocked
		if source.Hits > existing.Hits {
			existing.Hits = source.Hits
		}
		if source.Attempts > existing.Attempts {
			existing.Attempts = source.Attempts
		}
		if source.Score > existing.Score {
			existing.Score = source.Score
		}
		if existing.Service == "" {
			existing.Service = source.Service
		}
		if existing.Summary == "" {
			existing.Summary = source.Summary
		}
		if len(existing.Rules) == 0 {
			existing.Rules = source.Rules
		}
		if len(existing.Story) == 0 {
			existing.Story = source.Story
		}
		if source.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = source.LastSeen
		}
		for _, area := range source.Areas {
			known := false
			for _, have := range existing.Areas {
				if have == area {
					known = true
					break
				}
			}
			if !known {
				existing.Areas = append(existing.Areas, area)
			}
		}
	}

	// 1. Packet-level offenders, with their block state.
	if s.kinetic != nil {
		for _, src := range s.kinetic.SourceSnapshot(limit) {
			severity := ""
			switch {
			case src.Blocked:
				severity = "high"
			case src.Score >= 70:
				severity = "medium"
			}
			add(OverviewThreatMapSource{
				IP: src.SourceIP, Area: "kinetic", Severity: severity, Blocked: src.Blocked,
				Hits: src.Hits, Attempts: src.Attempts, Score: src.Score, Service: src.Service,
				LastSeen: src.LastSeen, Rules: nonEmptyRule(src.LastRule),
			})
		}
	}

	// 2. The incident stream: layer-7 findings, post-exploitation chains and their correlation.
	snap := s.state.Snapshot()
	for i := len(snap.Incidents) - 1; i >= 0 && len(order) < overviewThreatMapMaxSources; i-- {
		inc := snap.Incidents[i]
		area := "xdr"
		if inc.RequestID != "" || inc.HTTPHost != "" || strings.HasPrefix(inc.Decision, "deny-http") {
			area = "l7"
		}
		if len(order) >= limit && area == "kinetic" {
			break
		}
		remote := strings.TrimSpace(inc.Remote)
		if remote == "" {
			// No remote endpoint: nothing to place. Skipping is the honest answer; a guessed position
			// would put a dot on the map that no evidence supports.
			continue
		}
		if host, _, err := net.SplitHostPort(remote); err == nil {
			remote = host
		}
		add(OverviewThreatMapSource{
			IP: remote, Area: area, Severity: inc.Severity, Blocked: incidentBlocked(inc.Decision, inc.Action),
			Score: inc.Score, LastSeen: inc.Time, Summary: inc.Summary, Rules: inc.RuleIDs,
			Story: inc.AttackStory,
		})
		if len(order) >= limit {
			break
		}
	}

	sources := make([]OverviewThreatMapSource, 0, len(order))
	for _, ip := range order {
		sources = append(sources, *byIP[ip])
	}

	// 3. Place them with the local GeoIP matrix. Unplaceable sources stay, without coordinates.
	if s.geo != nil {
		for i := range sources {
			geo, ok := s.geo.Lookup(net.ParseIP(sources[i].IP))
			if !ok {
				continue
			}
			sources[i].CountryCode = geo.CountryCode
			sources[i].Country = geo.Country
			sources[i].ASN = geo.ASN
			sources[i].ASName = geo.ASName
			lat, lon := geo.Latitude, geo.Longitude
			sources[i].Latitude, sources[i].Longitude = &lat, &lon
		}
	}

	countries := aggregateOverviewCountries(sources)

	// The activity band reads the ledger backwards, newest first. It deliberately keeps events that the
	// map had to skip: no remote endpoint means no dot, but it is still something that happened.
	recent := make([]OverviewThreatMapEvent, 0, events)
	for i := len(snap.Incidents) - 1; i >= 0 && len(recent) < events; i-- {
		inc := snap.Incidents[i]
		item := OverviewThreatMapEvent{
			ID: inc.ID, Time: inc.Time, Severity: inc.Severity, Score: inc.Score,
			Process: inc.Process, Method: inc.HTTPMethod, Host: inc.HTTPHost, Path: inc.HTTPPath,
			Summary: inc.Summary, Rules: inc.RuleIDs, Decision: inc.Decision,
			Blocked: incidentBlocked(inc.Decision, inc.Action),
		}
		item.Area = "xdr"
		if inc.RequestID != "" || inc.HTTPHost != "" || strings.HasPrefix(inc.Decision, "deny-http") {
			item.Area = "l7"
		}
		remote := strings.TrimSpace(inc.Remote)
		if remote != "" {
			if host, _, err := net.SplitHostPort(remote); err == nil {
				remote = host
			}
			item.Remote = remote
			if s.geo != nil {
				if geo, ok := s.geo.Lookup(net.ParseIP(remote)); ok {
					item.Country, item.CountryCode = geo.Country, geo.CountryCode
				}
			}
		} else if item.Area == "xdr" {
			item.Area = "host"
		}
		recent = append(recent, item)
	}

	origin := s.resolveKineticOrigin()
	totals := map[string]int{
		"sources":     len(sources),
		"placed":      countPlaced(sources),
		"blocked":     countBlocked(sources),
		"kinetic":     countArea(sources, "kinetic"),
		"l7":          countArea(sources, "l7"),
		"xdr":         countArea(sources, "xdr"),
		"countries":   len(countries),
		"events_read": events,
	}
	writeJSON(w, http.StatusOK, OverviewThreatMapResponse{
		Sources: sources, Countries: countries, Recent: recent,
		Origin: origin, OriginNote: describeOrigin(origin),
		Geo: s.geoStatusOrNil(), Totals: totals, Generated: time.Now().UTC(),
	})
}

// geoStatusOrNil reports the GeoIP matrix state so the panel can say when the map is running without
// placement data instead of showing an empty world.
func (s *APIServer) geoStatusOrNil() any {
	if s.geo == nil {
		return nil
	}
	return s.geo.Status()
}

func nonEmptyRule(rule string) []string {
	if strings.TrimSpace(rule) == "" {
		return nil
	}
	return []string{rule}
}

// incidentBlocked reads the answer the platform already recorded rather than inferring one.
func incidentBlocked(decision, action string) bool {
	for _, value := range []string{decision, action} {
		lowered := strings.ToLower(strings.TrimSpace(value))
		if strings.HasPrefix(lowered, "deny") || strings.Contains(lowered, "block") || strings.Contains(lowered, "kill") {
			return true
		}
	}
	return false
}

func aggregateOverviewCountries(sources []OverviewThreatMapSource) []OverviewThreatMapCountry {
	byCode := make(map[string]*OverviewThreatMapCountry)
	for _, source := range sources {
		if source.CountryCode == "" {
			continue
		}
		entry, ok := byCode[source.CountryCode]
		if !ok {
			entry = &OverviewThreatMapCountry{CountryCode: source.CountryCode, Country: source.Country}
			byCode[source.CountryCode] = entry
		}
		entry.Total++
		if source.Blocked {
			entry.Blocked++
		}
		entry.Severity = worstSeverity(entry.Severity, source.Severity)
		for _, area := range source.Areas {
			switch area {
			case "kinetic":
				entry.Kinetic++
			case "l7":
				entry.L7++
			case "xdr":
				entry.XDR++
			}
		}
		if entry.Latitude == nil && source.Latitude != nil {
			entry.Latitude, entry.Longitude = source.Latitude, source.Longitude
		}
	}
	out := make([]OverviewThreatMapCountry, 0, len(byCode))
	for _, entry := range byCode {
		out = append(out, *entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total != out[j].Total {
			return out[i].Total > out[j].Total
		}
		return out[i].CountryCode < out[j].CountryCode
	})
	return out
}

func countPlaced(sources []OverviewThreatMapSource) int {
	placed := 0
	for _, source := range sources {
		if source.Latitude != nil && source.Longitude != nil {
			placed++
		}
	}
	return placed
}

func countBlocked(sources []OverviewThreatMapSource) int {
	blocked := 0
	for _, source := range sources {
		if source.Blocked {
			blocked++
		}
	}
	return blocked
}

func countArea(sources []OverviewThreatMapSource, area string) int {
	count := 0
	for _, source := range sources {
		for _, have := range source.Areas {
			if have == area {
				count++
				break
			}
		}
	}
	return count
}
