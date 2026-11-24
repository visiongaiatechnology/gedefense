// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Kinetic telemetry HTTP surface split out of server.go (refactoring wave 1a,
// structure-only). The mux registration stays in server.go.

import (
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type kineticLiveBounds struct {
	SourceLimit                int    `json:"source_limit"`
	EventLimit                 int    `json:"event_limit"`
	EventCapacity              int    `json:"event_capacity"`
	EventDropsTotal            uint64 `json:"event_drops_total"`
	EventHistoryComplete       bool   `json:"event_history_complete"`
	SourceRetentionSeconds     int64  `json:"source_retention_seconds"`
	SourceHistoryComplete      bool   `json:"source_history_complete"`
	AggregationHistoryComplete bool   `json:"aggregation_history_complete"`
	AggregateEvictionsTotal    uint64 `json:"aggregate_evictions_total"`
	SourceBucketResolution     string `json:"source_bucket_resolution"`
	TopPortsBasis              string `json:"top_ports_basis"`
	TopRulesBasis              string `json:"top_rules_basis"`
	Bounded                    bool   `json:"bounded"`
}

type kineticLiveResponse struct {
	GeneratedAt   time.Time                 `json:"generated_at"`
	Window        string                    `json:"window"`
	WindowSeconds int64                     `json:"window_seconds"`
	StateFilter   string                    `json:"state_filter"`
	ActiveBlocks  int                       `json:"active_blocks"`
	Status        KineticTelemetry          `json:"status"`
	Traffic       KineticTrafficWindow      `json:"traffic"`
	Sources       []KineticSourceSnapshot   `json:"sources"`
	Events        []KineticEvent            `json:"events"`
	Decisions     []KineticEvent            `json:"decisions"`
	Subnets       []KineticSubnetAggregate  `json:"subnets"`
	TopRules      []KineticTopRule          `json:"top_rules"`
	TopPorts      []KineticTopPort          `json:"top_ports"`
	Countries     []kineticCountryAggregate `json:"countries"`
	Geo           GeoStatus                 `json:"geo"`
	Bounds        kineticLiveBounds         `json:"bounds"`
}

func kineticRequestLimit(r *http.Request, fallback int) (int, error) {
	limit := fallback
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 250 {
			return 0, errors.New("limit must be between 1 and 250")
		}
		limit = parsed
	}
	return limit, nil
}

func filterKineticSourcesByState(sources []KineticSourceSnapshot, stateFilter string) ([]KineticSourceSnapshot, bool) {
	stateFilter = strings.ToLower(strings.TrimSpace(stateFilter))
	if stateFilter == "" {
		stateFilter = "all"
	}
	if stateFilter != "all" && stateFilter != "suspicious" && stateFilter != "blocked" {
		return nil, false
	}
	if stateFilter == "all" {
		return sources, true
	}
	out := make([]KineticSourceSnapshot, 0, len(sources))
	for _, src := range sources {
		state := strings.ToUpper(src.State)
		switch stateFilter {
		case "blocked":
			if src.Blocked || state == "BLOCKED" {
				out = append(out, src)
			}
		case "suspicious":
			if src.Blocked || src.Score >= 40 || state == "SUSPICIOUS" || state == "SCAN" || state == "BURST" || state == "THREAT" || state == "BLOCKED" {
				out = append(out, src)
			}
		}
	}
	return out, true
}

func kineticSourceBucketResolution(spec KineticWindowSpec) string {
	if spec.Duration <= time.Minute {
		return "60s-calendar"
	}
	if spec.Duration <= time.Hour {
		return "5m"
	}
	return "1h"
}

func activeKineticBlockCount(state *State, now time.Time) int {
	if state == nil {
		return 0
	}
	count := 0
	for _, entry := range state.BlocksSnapshot() {
		if !entry.Enforced {
			continue
		}
		if !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now) {
			continue
		}
		count++
	}
	return count
}

func (s *APIServer) getKineticLive(w http.ResponseWriter, r *http.Request) {
	spec, ok := parseKineticWindow(r.URL.Query().Get("window"))
	if !ok {
		apiError(w, http.StatusBadRequest, "invalid kinetic window", errors.New("supported windows: live, 1m, 5m, 15m, 1h, 24h"))
		return
	}
	limit, err := kineticRequestLimit(r, 100)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid source limit", err)
		return
	}
	stateFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))
	if stateFilter == "" {
		stateFilter = "all"
	}
	now := time.Now().UTC()
	if s.kinetic == nil {
		if _, valid := filterKineticSourcesByState(nil, stateFilter); !valid {
			apiError(w, http.StatusBadRequest, "invalid kinetic state filter", errors.New("supported filters: all, suspicious, blocked"))
			return
		}
		writeJSON(w, http.StatusOK, kineticLiveResponse{
			GeneratedAt: now, Window: spec.Name, WindowSeconds: int64(spec.Duration / time.Second), StateFilter: stateFilter, ActiveBlocks: activeKineticBlockCount(s.state, now),
			Status: DefaultKineticTelemetry(), Traffic: KineticTrafficWindow{Name: spec.Name, Seconds: int64(spec.Duration / time.Second), GeneratedAt: now},
			Sources: []KineticSourceSnapshot{}, Events: []KineticEvent{}, Decisions: []KineticEvent{}, Subnets: []KineticSubnetAggregate{},
			TopRules: []KineticTopRule{}, TopPorts: []KineticTopPort{}, Countries: []kineticCountryAggregate{}, Geo: s.geo.Status(),
			Bounds: kineticLiveBounds{SourceLimit: limit, EventLimit: limit, SourceRetentionSeconds: int64(kineticSourceRetention / time.Second),
				SourceBucketResolution: kineticSourceBucketResolution(spec), TopPortsBasis: "security_events", TopRulesBasis: "security_events", Bounded: true},
		})
		return
	}

	status := s.kinetic.SnapshotTelemetry()
	traffic := s.kinetic.TrafficWindow(spec, now)
	sources := s.kinetic.SourceSnapshotForWindow(limit, spec, now)
	s.enrichKineticSources(sources)
	filtered, valid := filterKineticSourcesByState(sources, stateFilter)
	if !valid {
		apiError(w, http.StatusBadRequest, "invalid kinetic state filter", errors.New("supported filters: all, suspicious, blocked"))
		return
	}
	events, drops, eventsComplete := s.kinetic.RecentEventsForWindow(spec, now, limit)
	countries := aggregateKineticCountries(filtered)
	sourceComplete := spec.Duration <= kineticSourceRetention && traffic.HistoryComplete && status.TrackingEvictionsTotal == 0
	writeJSON(w, http.StatusOK, kineticLiveResponse{
		GeneratedAt: now, Window: spec.Name, WindowSeconds: int64(spec.Duration / time.Second), StateFilter: stateFilter, ActiveBlocks: activeKineticBlockCount(s.state, now),
		Status: status, Traffic: traffic, Sources: filtered, Events: events, Decisions: kineticDecisions(events, minInt(limit, 50)),
		Subnets: aggregateKineticSubnets(filtered, 20), TopRules: aggregateKineticRules(events, 12), TopPorts: aggregateKineticPorts(events, 12),
		Countries: countries, Geo: s.geo.Status(),
		Bounds: kineticLiveBounds{
			SourceLimit: limit, EventLimit: limit, EventCapacity: s.kinetic.eventQueue.Capacity(), EventDropsTotal: drops,
			EventHistoryComplete: eventsComplete, SourceRetentionSeconds: int64(kineticSourceRetention / time.Second),
			SourceHistoryComplete: sourceComplete, AggregationHistoryComplete: status.AggregateEvictionsTotal == 0, AggregateEvictionsTotal: status.AggregateEvictionsTotal, SourceBucketResolution: kineticSourceBucketResolution(spec),
			TopPortsBasis: "security_events", TopRulesBasis: "security_events", Bounded: true,
		},
	})
}

func (s *APIServer) getKineticStatus(w http.ResponseWriter, r *http.Request) {
	if s.kinetic == nil {
		writeJSON(w, http.StatusOK, DefaultKineticTelemetry())
		return
	}
	writeJSON(w, http.StatusOK, s.kinetic.SnapshotTelemetry())
}

func (s *APIServer) getKineticEvents(w http.ResponseWriter, r *http.Request) {
	if s.kinetic == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []KineticEvent{}, "drops": uint64(0)})
		return
	}
	if rawWindow := strings.TrimSpace(r.URL.Query().Get("window")); rawWindow != "" {
		spec, ok := parseKineticWindow(rawWindow)
		if !ok {
			apiError(w, http.StatusBadRequest, "invalid kinetic window", errors.New("supported windows: live, 1m, 5m, 15m, 1h, 24h"))
			return
		}
		limit, err := kineticRequestLimit(r, 100)
		if err != nil {
			apiError(w, http.StatusBadRequest, "invalid event limit", err)
			return
		}
		events, drops, complete := s.kinetic.RecentEventsForWindow(spec, time.Now().UTC(), limit)
		writeJSON(w, http.StatusOK, map[string]any{"events": events, "drops": drops, "window": spec.Name, "history_complete": complete})
		return
	}
	events, drops := s.kinetic.RecentEvents()
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"drops":  drops,
	})
}

func (s *APIServer) getKineticSources(w http.ResponseWriter, r *http.Request) {
	if s.kinetic == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sources": []KineticSourceSnapshot{}})
		return
	}
	limit, err := kineticRequestLimit(r, 100)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid source limit", err)
		return
	}
	var sources []KineticSourceSnapshot
	windowName := ""
	if rawWindow := strings.TrimSpace(r.URL.Query().Get("window")); rawWindow != "" {
		spec, ok := parseKineticWindow(rawWindow)
		if !ok {
			apiError(w, http.StatusBadRequest, "invalid kinetic window", errors.New("supported windows: live, 1m, 5m, 15m, 1h, 24h"))
			return
		}
		windowName = spec.Name
		sources = s.kinetic.SourceSnapshotForWindow(limit, spec, time.Now().UTC())
	} else {
		sources = s.kinetic.SourceSnapshot(limit)
	}
	s.enrichKineticSources(sources)
	if stateFilter := strings.TrimSpace(r.URL.Query().Get("state")); stateFilter != "" {
		filtered, ok := filterKineticSourcesByState(sources, stateFilter)
		if !ok {
			apiError(w, http.StatusBadRequest, "invalid kinetic state filter", errors.New("supported filters: all, suspicious, blocked"))
			return
		}
		sources = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": sources, "geo": s.geo.Status(), "window": windowName})
}

type kineticCountryAggregate struct {
	Code    string  `json:"code"`
	Name    string  `json:"name"`
	Events  int     `json:"events"`
	Blocked int     `json:"blocked"`
	Hits    int     `json:"hits"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

func aggregateKineticCountries(sources []KineticSourceSnapshot) []kineticCountryAggregate {
	byCountry := make(map[string]*kineticCountryAggregate)
	for _, source := range sources {
		if source.CountryCode == "" || source.Latitude == nil || source.Longitude == nil {
			continue
		}
		agg := byCountry[source.CountryCode]
		if agg == nil {
			agg = &kineticCountryAggregate{Code: source.CountryCode, Name: source.Country}
			byCountry[source.CountryCode] = agg
		}
		agg.Events++
		n := float64(agg.Events)
		agg.Lat += (*source.Latitude - agg.Lat) / n
		agg.Lon += (*source.Longitude - agg.Lon) / n
		hits := source.WindowHits
		if hits <= 0 {
			hits = source.Hits
		}
		agg.Hits += hits
		if source.Blocked {
			agg.Blocked++
		}
	}
	countries := make([]kineticCountryAggregate, 0, len(byCountry))
	for _, agg := range byCountry {
		countries = append(countries, *agg)
	}
	sort.Slice(countries, func(i, j int) bool {
		if countries[i].Hits != countries[j].Hits {
			return countries[i].Hits > countries[j].Hits
		}
		return countries[i].Code < countries[j].Code
	})
	return countries
}

func (s *APIServer) getKineticMap(w http.ResponseWriter, r *http.Request) {
	if s.kinetic == nil {
		writeJSON(w, http.StatusOK, map[string]any{"countries": []kineticCountryAggregate{}, "sources": []KineticSourceSnapshot{}, "geo": s.geo.Status(), "origin": s.resolveKineticOrigin()})
		return
	}
	var sources []KineticSourceSnapshot
	windowName := ""
	if rawWindow := strings.TrimSpace(r.URL.Query().Get("window")); rawWindow != "" {
		spec, ok := parseKineticWindow(rawWindow)
		if !ok {
			apiError(w, http.StatusBadRequest, "invalid kinetic window", errors.New("supported windows: live, 1m, 5m, 15m, 1h, 24h"))
			return
		}
		windowName = spec.Name
		sources = s.kinetic.SourceSnapshotForWindow(250, spec, time.Now().UTC())
	} else {
		sources = s.kinetic.SourceSnapshot(250)
	}
	s.enrichKineticSources(sources)
	countries := aggregateKineticCountries(sources)
	// The host's own position travels with the map so the client can draw the origin
	// marker and the arcs. It is resolved from this host's addresses, never guessed,
	// and carries a reason when it could not be resolved.
	origin := s.resolveKineticOrigin()
	writeJSON(w, http.StatusOK, map[string]any{
		"countries": countries, "sources": sources, "geo": s.geo.Status(),
		"window": windowName, "origin": origin, "origin_note": describeOrigin(origin),
	})
}

func (s *APIServer) enrichKineticSources(sources []KineticSourceSnapshot) {
	if s.geo == nil {
		return
	}
	for i := range sources {
		geo, ok := s.geo.Lookup(net.ParseIP(sources[i].SourceIP))
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

func (s *APIServer) reconcileKinetic(w http.ResponseWriter, r *http.Request) {
	// Policy TTL expiry has exactly one owner: the central transactional worker in
	// main.go. This endpoint only forces detector ageing, otherwise an operator
	// click could race the expiry worker and lose signed-policy evidence.
	now := time.Now().UTC()
	if s.kinetic != nil {
		s.kinetic.Sweep(now)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"reconciled": 0,
		"entries":    []BlockEntry{},
		"note":       "detector state swept; policy TTL expiry is owned by the central transactional worker",
	})
}
