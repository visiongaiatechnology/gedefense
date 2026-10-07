package main

import (
	"os"
	"strings"
	"testing"
)

func TestThreatIntelUIExposesAuthoritativeOperationalState(t *testing.T) {
	html, err := os.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(html)
	for _, required := range []string{
		`id="threatIntelTruthStrip"`,
		`id="threatIntelKernelGeneration"`,
		`id="threatIntelKernelAppliedAt"`,
		`id="threatIntelKernelDelta"`,
		`id="threatIntelGenerationRelation"`,
		`id="threatIntelLastPartialSync"`,
		`id="threatIntelOperationStrip"`,
		`id="threatIntelHealthySources"`,
		`id="threatIntelProblemSources"`,
		`id="threatIntelFeedOKCount"`,
		`id="threatIntelFeedStaleCount"`,
		`id="threatIntelFeedErrorCount"`,
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("Threat Intelligence operator surface missing %s", required)
		}
	}
}

func TestThreatIntelUIRefreshIsSingleFlightAndDoesNotInventHistory(t *testing.T) {
	js, err := os.ReadFile("web/threat-intel.js")
	if err != nil {
		t.Fatal(err)
	}
	body := string(js)
	for _, required := range []string{
		"threatIntelRefreshInFlight",
		"threatIntelRefreshPending",
		"kernel_generation",
		"kernel_apply_last_at",
		"last_partial_successful_sync_at",
		"last_fully_successful_sync_at",
		"last_kernel_added",
		"last_kernel_deleted",
		"handleThreatIntelStreamEvent",
		"feeds.kernel_applying",
		"last_good_gen",
		"last_good_at",
		"renderThreatIntelOffline",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("Threat Intelligence UI contract missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"syncHistory",
		"fakeHistory",
		"mockFeed",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("Threat Intelligence UI must not invent unsupported history: %s", forbidden)
		}
	}
}

func TestThreatIntelWarningPillsHaveAVisibleStyle(t *testing.T) {
	css, err := os.ReadFile("web/v4.css")
	if err != nil {
		t.Fatal(err)
	}
	body := string(css)
	if !strings.Contains(body, ".status-pill.warning") {
		t.Fatal("legacy warning pill alias missing; warning states can silently render neutral")
	}
}
