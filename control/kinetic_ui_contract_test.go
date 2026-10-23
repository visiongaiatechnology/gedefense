package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestKineticUIUsesConsolidatedLiveContract(t *testing.T) {
	js, err := os.ReadFile("web/kinetic.js")
	if err != nil {
		t.Fatal(err)
	}
	body := string(js)
	if !strings.Contains(body, "getKineticLive(currentWindow, SOURCE_LIMIT, currentStateFilter)") {
		t.Fatal("Kinetic UI is not wired to the consolidated server-side live contract")
	}
	for _, legacy := range []string{"getKineticStatus()", "getKineticEvents()", "getKineticSources(", "getKineticMap()", "Promise.all(["} {
		if strings.Contains(body, legacy) {
			t.Fatalf("legacy multi-request Kinetic polling path still present: %s", legacy)
		}
	}
	if strings.Contains(body, "WINDOW_MILLIS") || strings.Contains(body, "filterByWindow(") || strings.Contains(body, "function filterSources") {
		t.Fatal("browser-owned Kinetic time-window filtering returned; windows must remain server authoritative")
	}
	if !strings.Contains(body, "kineticReloadPending") {
		t.Fatal("Kinetic refresh coalescing guard missing")
	}
}

func TestKineticUIExposesServerWindowAndHistoryTruth(t *testing.T) {
	html, err := os.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(html)
	for _, required := range []string{
		`id="kineticHistoryBadge"`,
		`id="kineticWindowTruth"`,
		`id="kineticHistoryNote"`,
		`data-kinetic-window="1m"`,
		`id="kineticAttemptsWindow"`,
		`id="kineticTopRules"`,
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("Kinetic operator surface missing %s", required)
		}
	}
	if strings.Count(body, `class="kinetic-filter-stack"`) != 0 {
		t.Fatal("legacy table-local Kinetic filter stack should not remain")
	}
}

func TestDashboardHTMLIDsAreUnique(t *testing.T) {
	html, err := os.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`\bid="([^"]+)"`)
	seen := make(map[string]bool)
	for _, match := range re.FindAllStringSubmatch(string(html), -1) {
		id := match[1]
		if seen[id] {
			t.Fatalf("duplicate dashboard DOM id %q", id)
		}
		seen[id] = true
	}
}

func TestKineticMapIsLocallyEnrichedAndBounded(t *testing.T) {
	js, err := os.ReadFile("web/kinetic.js")
	if err != nil {
		t.Fatal(err)
	}
	body := string(js)
	for _, required := range []string{
		"GEO_MAP_LIMITS",
		"updateKineticGeoMap(",
		"source_modified_at",
		"Keine kartierbaren Quellen im gewählten Fenster",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("Kinetic map contract missing %q", required)
		}
	}
	geo := embeddedWebFile(t, "geo-map.js")
	for _, required := range []string{"export const GEO_MAP_LIMITS = Object.freeze({", "tracked: 96", "blocked: 48", "pulsing: 24", "countries: 192"} {
		if !strings.Contains(geo, required) {
			t.Fatalf("geo map budget missing %q", required)
		}
	}
	if strings.Contains(body, "fetch('http") || strings.Contains(body, "fetch(\"http") {
		t.Fatal("Kinetic map must not perform direct third-party geolocation fetches")
	}
}
