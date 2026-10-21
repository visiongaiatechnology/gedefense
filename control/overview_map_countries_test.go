// STATUS: DIAMANT VGT SUPREME
package main

import (
	"testing"
	"time"
)

// The dashboard states a 24-hour window, so the server publishes that window next to the all-source
// roll-up. This test pins the cutoff: a source last seen two days ago must not leak into
// countries_24h, while the all-source roll-up still counts it. Two windows, one computation.
func TestAggregateOverviewCountriesHonoursWindow(t *testing.T) {
	now := time.Now().UTC()
	sources := []OverviewThreatMapSource{
		{
			IP: "198.51.100.1", CountryCode: "US", Country: "United States",
			Area: "kinetic", Areas: []string{"kinetic"}, LastSeen: now.Add(-2 * time.Hour), Blocked: true,
		},
		{
			IP: "198.51.100.2", CountryCode: "US", Country: "United States",
			Area: "kinetic", Areas: []string{"kinetic"}, LastSeen: now.Add(-48 * time.Hour),
		},
		{
			IP: "203.0.113.7", CountryCode: "DE", Country: "Germany",
			Area: "xdr", Areas: []string{"xdr"}, LastSeen: now.Add(-3 * time.Hour), Severity: "high",
		},
	}

	all := aggregateOverviewCountries(sources, time.Time{})
	if len(all) != 2 {
		t.Fatalf("expected two countries without a window, got %d: %+v", len(all), all)
	}
	if all[0].CountryCode != "US" || all[0].Total != 2 || all[0].Kinetic != 2 || all[0].Blocked != 1 {
		t.Fatalf("unexpected all-source roll-up: %+v", all[0])
	}

	day := aggregateOverviewCountries(sources, now.Add(-24*time.Hour))
	if len(day) != 2 {
		t.Fatalf("expected two countries inside the 24-hour window, got %d: %+v", len(day), day)
	}
	if day[0].CountryCode != "DE" || day[0].Total != 1 || day[0].XDR != 1 {
		t.Fatalf("the 24-hour roll-up must not count the 48-hour-old source: %+v", day)
	}
	for _, entry := range day {
		if entry.CountryCode == "US" && entry.Total != 1 {
			t.Fatalf("US must drop to a single source inside the window, got total=%d", entry.Total)
		}
	}
}

func TestOverviewCountriesKeepBlockedAndAreaCounters(t *testing.T) {
	now := time.Now().UTC()
	sources := []OverviewThreatMapSource{
		{IP: "198.51.100.9", CountryCode: "NL", Country: "Netherlands", Areas: []string{"kinetic"}, LastSeen: now, Blocked: true},
		{IP: "198.51.100.10", CountryCode: "NL", Country: "Netherlands", Areas: []string{"kinetic", "l7"}, LastSeen: now, Blocked: true},
		{IP: "198.51.100.11", CountryCode: "NL", Country: "Netherlands", Areas: []string{"xdr"}, LastSeen: now},
	}
	countries := aggregateOverviewCountries(sources, now.Add(-24*time.Hour))
	if len(countries) != 1 {
		t.Fatalf("expected one country, got %d", len(countries))
	}
	entry := countries[0]
	if entry.Total != 3 || entry.Blocked != 2 || entry.Kinetic != 2 || entry.L7 != 1 || entry.XDR != 1 {
		t.Fatalf("unexpected per-country counters: %+v", entry)
	}
}
