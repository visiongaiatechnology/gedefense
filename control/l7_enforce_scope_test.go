// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func l7ScopeEngine(t *testing.T, rules []string) *L7Engine {
	t.Helper()
	cfg := l7TestConfig()
	cfg.Mode = "block"
	cfg.EnforceRules = append([]string(nil), rules...)
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.canBlock = func() bool { return true }
	return engine
}

// A deployment may run mode=block while only the validated mitigation rule is allowed to block.
// The XSS finding must remain visible and raise the alert score, but it must not authorise a block.
func TestL7EnforceScopeLimitsBlockingToNamedRules(t *testing.T) {
	engine := l7ScopeEngine(t, []string{"L7.PHP.SESSION_UPLOAD_PROGRESS"})

	xss := l7Request("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
	response, err := engine.Inspect(context.Background(), xss)
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.XSS.SCRIPT_TAG") {
		t.Fatalf("the unscoped finding must still be recorded: %#v", response.Findings)
	}
	if response.Enforced || response.Decision == "block" {
		t.Fatalf("a rule outside the enforcement scope blocked the request: %#v", response)
	}

	body, contentType := phpProgressMultipartBody(t, "PHP_SESSION_UPLOAD_PROGRESS", true)
	response, err = engine.Inspect(context.Background(), phpProgressRequest(t, body, contentType))
	if err != nil {
		t.Fatal(err)
	}
	if !response.Enforced || response.Decision != "block" {
		t.Fatalf("the scoped mitigation rule did not block: %#v", response)
	}
	if !findingByID(response.Findings, "L7.PHP.SESSION_UPLOAD_PROGRESS") {
		t.Fatalf("the blocking finding is missing: %#v", response.Findings)
	}
}

func TestL7EnforceScopeEmptyKeepsHistoricalBlocking(t *testing.T) {
	engine := l7ScopeEngine(t, nil)
	response, err := engine.Inspect(context.Background(), l7Request("/search?q=%3Cscript%3Ealert(1)%3C/script%3E"))
	if err != nil {
		t.Fatal(err)
	}
	if !response.Enforced {
		t.Fatalf("an empty enforcement scope must keep every rule block-eligible: %#v", response)
	}
}

func TestL7EnforceScopeSupportsFamilies(t *testing.T) {
	settings := defaultL7FabricSettings(l7TestConfig())
	settings.EnforceRules = []string{"L7.UPLOAD"}
	if err := validateL7FabricSettings(&settings); err != nil {
		t.Fatal(err)
	}
	snapshot := buildL7RuntimeSnapshot(settings, 1)
	if !snapshot.blockEligible("L7.UPLOAD.PART_BUDGET") || !snapshot.blockEligible("L7.UPLOAD.SIZE_BUDGET") {
		t.Fatal("a rule below the L7.UPLOAD family is not block-eligible")
	}
	if snapshot.blockEligible("L7.PHP.SESSION_UPLOAD_PROGRESS") || snapshot.blockEligible("L7.XSS.SCRIPT_TAG") {
		t.Fatal("a rule outside the L7.UPLOAD family became block-eligible")
	}

	settings.EnforceRules = []string{"L7.PHP.SESSION_UPLOAD_PROGRESS"}
	if err := validateL7FabricSettings(&settings); err != nil {
		t.Fatal(err)
	}
	snapshot = buildL7RuntimeSnapshot(settings, 2)
	if !snapshot.blockEligible("L7.PHP.SESSION_UPLOAD_PROGRESS") {
		t.Fatal("the explicitly scoped rule is not block-eligible")
	}
	if snapshot.blockEligible("L7.UPLOAD.PART_BUDGET") {
		t.Fatal("an unlisted rule became block-eligible next to the scoped rule")
	}
}

func TestL7EnforceRulesValidation(t *testing.T) {
	settings := defaultL7FabricSettings(l7TestConfig())
	settings.EnforceRules = []string{"l7.php.session_upload_progress", "L7.php.session_upload_progress", "L7.UPLOAD"}
	if err := validateL7FabricSettings(&settings); err != nil {
		t.Fatal(err)
	}
	if len(settings.EnforceRules) != 2 {
		t.Fatalf("expected the duplicate to collapse into two entries, got %v", settings.EnforceRules)
	}
	if settings.EnforceRules[0] != "L7.PHP.SESSION_UPLOAD_PROGRESS" || settings.EnforceRules[1] != "L7.UPLOAD" {
		t.Fatalf("enforcement scope was not normalized: %v", settings.EnforceRules)
	}

	settings.EnforceRules = []string{"L7.NOT.A.REAL.RULE"}
	if err := validateL7FabricSettings(&settings); err == nil {
		t.Fatal("an unknown enforcement rule was accepted")
	}
}

// The runtime settings document is authenticated over its canonical JSON. A new field that is
// serialized even when empty changes the canonical bytes of every existing document, and the control
// plane then refuses to start with "runtime settings authentication failed". The empty scope must
// therefore stay absent from the JSON while a populated scope must be covered.
func TestL7EnforceRulesJSONStaysCompatibleWithExistingDocuments(t *testing.T) {
	legacy := defaultL7FabricSettings(l7TestConfig())
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "enforce_rules") {
		t.Fatalf("an empty enforcement scope must not be serialized: %s", data)
	}
	var decoded L7FabricSettings
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	roundTrip, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(roundTrip) != string(data) {
		t.Fatalf("a legacy settings document changed on round trip:\nbefore=%s\nafter=%s", data, roundTrip)
	}

	decoded.EnforceRules = []string{"L7.PHP.SESSION_UPLOAD_PROGRESS"}
	withScope, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(withScope), `"enforce_rules":["L7.PHP.SESSION_UPLOAD_PROGRESS"]`) {
		t.Fatalf("a populated enforcement scope is not covered by the document: %s", withScope)
	}
}

// A settings revision may flip mode to block without any traffic. The operator-visible status must
// follow the active snapshot immediately; otherwise the dashboard reports observe while the edge
// is already blocking.
func TestL7FabricApplyRefreshesPublishedStatusMode(t *testing.T) {
	cfg := l7TestConfig()
	cfg.Enabled = true
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState("test", Config{L7: cfg})
	if got := state.L7Status().Mode; got != "observe" {
		t.Fatalf("fixture starts with mode %q", got)
	}
	settings := defaultL7FabricSettings(cfg)
	settings.Mode = "block"
	settings.EnforceRules = []string{"L7.PHP.SESSION_UPLOAD_PROGRESS"}
	if _, applyErr := applyL7FabricSettings(engine, settings, 7); applyErr != nil {
		t.Fatal(applyErr)
	}
	syncL7StatusFromLive(state, engine)
	if got := state.L7Status().Mode; got != "block" {
		t.Fatalf("published status mode is %q after the engine was switched to block", got)
	}
}
