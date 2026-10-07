// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The Fabric Settings surface is rendered from the server schema. These tests
// lock the contract between the two: the dashboard must not carry its own copy
// of any setting, every internal-navigation anchor must resolve to a real
// element, and every module that advertises a Settings tab must be served by
// the module API.

var (
	webAnchorTargetPattern = regexp.MustCompile(`target:\s*'([A-Za-z0-9_-]+)'`)
	webElementIDPattern    = regexp.MustCompile(`id="([A-Za-z0-9_-]+)"`)
	webCSSClassPattern     = regexp.MustCompile(`\.([a-z][a-z0-9-]{3,})`)
)

func embeddedWebFile(t *testing.T, name string) string {
	t.Helper()
	body, err := webAssets.ReadFile("web/" + name)
	if err != nil {
		t.Fatalf("embedded asset %s: %v", name, err)
	}
	return string(body)
}

func TestFabricSettingsUIFrameworkIsBundled(t *testing.T) {
	app := embeddedWebFile(t, "app.js")
	framework := embeddedWebFile(t, "fabric-settings.js")
	api := embeddedWebFile(t, "api.js")

	if !strings.Contains(app, "initFabricSettingsTabs") {
		t.Fatal("app.js does not initialize the Fabric Settings framework")
	}
	for _, required := range []string{
		"initFabricSettingsTabs", "refreshFabricModule",
		"previewFabricSettings", "updateFabricSettings", "rollbackFabricSettings", "getFabricSettingsHistory",
		"UNSAVED CHANGES", "restart-class",
		"settings-rule-table", "settings-feed-table",
	} {
		if !strings.Contains(framework, required) {
			t.Fatalf("fabric settings UI missing %q", required)
		}
	}
	for _, required := range []string{"getFabricSettingsSchema", "/api/v1/settings/schema"} {
		if !strings.Contains(api, required) {
			t.Fatalf("fabric settings API helper missing %q", required)
		}
	}
	if !strings.Contains(framework, "getFabricSettingsSchema") {
		t.Fatal("the settings surface is not rendered from the server schema")
	}
}

func TestFabricSettingsUIRendersEverySettingFromTheServerSchema(t *testing.T) {
	framework := embeddedWebFile(t, "fabric-settings.js")

	// A hand-maintained copy of the setting catalogue in the client is a
	// correctness defect: it can silently drift from what the backend enforces.
	for _, forbidden := range []string{
		"MODULE_SCHEMAS", "syn_threshold", "auto_contain_ipv4_subnet", "service_ports_admin",
		"management_allowlist", "minimum_canary_seconds", "behavior_exec_burst",
		"containment_ttl_seconds", "max_command_bytes", "enabled_rule_modules", "rule_overrides",
	} {
		if strings.Contains(framework, forbidden) {
			t.Fatalf("the dashboard still hard-codes the setting catalogue entry %q", forbidden)
		}
	}

	for _, forbidden := range []string{".innerHTML", "outerHTML", "document.write", "eval(", "new Function"} {
		if strings.Contains(framework, forbidden) {
			t.Fatalf("fabric settings UI must not build state with %q", forbidden)
		}
	}
}

func TestFabricSettingsSubnavAnchorsResolveToRealElements(t *testing.T) {
	framework := embeddedWebFile(t, "fabric-settings.js")
	document := embeddedWebFile(t, "index.html")

	ids := map[string]bool{}
	for _, match := range webElementIDPattern.FindAllStringSubmatch(document, -1) {
		ids[match[1]] = true
	}
	targets := webAnchorTargetPattern.FindAllStringSubmatch(framework, -1)
	if len(targets) == 0 {
		t.Fatal("the internal sub-navigation declares no anchors")
	}
	for _, match := range targets {
		if !ids[match[1]] {
			t.Fatalf("internal navigation anchor %q has no matching element in index.html", match[1])
		}
	}

	// Every module that can host a workbench must resolve to a real view. A
	// Fabric module name and its page are not always identical
	// (threat_intel -> threat-intel), and a mismatch means the Settings tab
	// silently never mounts.
	pages := map[string]bool{}
	for _, match := range regexp.MustCompile(`data-page="([A-Za-z0-9_-]+)"`).FindAllStringSubmatch(document, -1) {
		pages[match[1]] = true
	}
	presentation := regexp.MustCompile(`(?s)MODULE_PRESENTATION\s*=\s*\{(.*?)\n\};`).FindStringSubmatch(framework)
	if presentation == nil {
		t.Fatal("the dashboard declares no module presentation table")
	}
	presented := map[string]bool{}
	keyPattern := regexp.MustCompile(`^\s*'?([A-Za-z0-9_-]+)'?:\s*\{`)
	pagePattern := regexp.MustCompile(`page:\s*'([A-Za-z0-9_-]+)'`)
	entries := 0
	for _, line := range strings.Split(presentation[1], "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key := keyPattern.FindStringSubmatch(line)
		if key == nil {
			t.Fatalf("module presentation entry is not on a single line: %q", strings.TrimSpace(line))
		}
		presented[key[1]] = true
		page := key[1]
		if override := pagePattern.FindStringSubmatch(line); override != nil {
			page = override[1]
		}
		if !pages[page] {
			t.Fatalf("module %q resolves to view %q which does not exist in index.html", key[1], page)
		}
		entries++
	}
	if entries < 10 {
		t.Fatalf("module presentation table looks truncated: %d entries", entries)
	}

	// Every Fabric module must be presentable, otherwise its Settings tab could
	// never mount, and no presentation entry may exist for a view without an
	// administrable namespace.
	declaration := regexp.MustCompile(`FABRIC_MODULES\s*=\s*new Set\(\[([^\]]*)\]\)`).FindStringSubmatch(framework)
	if declaration == nil {
		t.Fatal("the dashboard does not declare which modules expose a Settings tab")
	}
	fabricModules := map[string]bool{}
	for _, raw := range strings.Split(declaration[1], ",") {
		name := strings.Trim(strings.TrimSpace(raw), `'"`)
		if name == "" {
			continue
		}
		fabricModules[name] = true
	}
	for module := range fabricModules {
		if !presented[module] {
			t.Fatalf("Fabric module %q has no presentation entry and could never mount a Settings tab", module)
		}
	}
	for module := range presented {
		if !fabricModules[module] && module != "overview" && module != "release" && module != "settings" {
			t.Fatalf("unexpected presentation-only entry %q", module)
		}
	}
	if !strings.Contains(framework, "for (const module of FABRIC_MODULES)") {
		t.Fatal("Settings tabs must mount only for administrable modules")
	}
}

func TestFabricSettingsStylesCoverTheRenderedStructure(t *testing.T) {
	framework := embeddedWebFile(t, "fabric-settings.js")
	stylesheet := embeddedWebFile(t, "v4.css")

	defined := map[string]bool{}
	for _, match := range webCSSClassPattern.FindAllStringSubmatch(stylesheet, -1) {
		defined[match[1]] = true
	}
	for _, required := range []string{
		"fabric-subnav", "fabric-subtab", "settings-workbench", "settings-head", "settings-rail",
		"settings-rail-button", "settings-editor", "settings-group", "settings-row", "settings-row-control",
		"settings-switch", "settings-rules", "settings-rule-table", "settings-preview", "settings-diff-row",
		"settings-actions", "settings-dirty", "settings-history",
		"settings-feeds", "settings-feed-table", "settings-feed-state", "settings-feed-error",
		"settings-chip", "settings-control-catalog",
	} {
		if !defined[required] {
			t.Fatalf("stylesheet does not define .%s", required)
		}
		if !strings.Contains(framework, required) {
			t.Fatalf("renderer never produces .%s", required)
		}
	}
	if !strings.Contains(stylesheet, "prefers-reduced-motion") {
		t.Fatal("the Fabric Settings stylesheet ignores reduced-motion preferences")
	}
}

// TestFabricSettingsSchemaEndpointCoversEveryAdvertisedModule verifies that the
// client and the server agree on which modules expose a Settings tab.
func TestFabricSettingsSchemaEndpointCoversEveryAdvertisedModule(t *testing.T) {
	framework := embeddedWebFile(t, "fabric-settings.js")
	declaration := regexp.MustCompile(`FABRIC_MODULES\s*=\s*new Set\(\[([^\]]*)\]\)`).FindStringSubmatch(framework)
	if declaration == nil {
		t.Fatal("the dashboard does not declare which modules expose a Settings tab")
	}
	advertised := map[string]bool{}
	for _, match := range regexp.MustCompile(`'([a-z0-9_]+)'`).FindAllStringSubmatch(declaration[1], -1) {
		advertised[match[1]] = true
	}
	if len(advertised) == 0 {
		t.Fatal("no module advertises a Settings tab")
	}

	cfg := defaultConfig()
	server := NewAPIServer(cfg, NewState("test", cfg), nil, nil, nil, nil, nil, nil, fabricTestToken)
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/schema", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("schema endpoint status=%d", rec.Code)
	}
	var schema struct {
		Modules  []string                `json:"modules"`
		Settings []FabricSettingMetadata `json:"settings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &schema); err != nil {
		t.Fatalf("schema decode: %v", err)
	}
	served := map[string]bool{}
	for _, module := range schema.Modules {
		served[module] = true
	}
	persisted := defaultRuntimeSettings(cfg)
	for module := range advertised {
		if !served[module] {
			t.Fatalf("the dashboard advertises Settings for %q but the server publishes no schema", module)
		}
		// The registry, the module-name allowlist and the snapshot builder must
		// agree, otherwise the tab would render and then 404 on load.
		if _, ok := fabricModuleName(module); !ok {
			t.Fatalf("module %q is published in the schema but rejected by the module allowlist", module)
		}
		if _, err := fabricModuleSnapshot(persisted, module); err != nil {
			t.Fatalf("module %q is advertised but has no settings snapshot: %v", module, err)
		}
	}
	for _, module := range schema.Modules {
		if _, ok := fabricModuleName(module); !ok {
			t.Fatalf("schema advertises module %q which the module allowlist rejects", module)
		}
	}
	// The upstream Threat Intelligence view must offer the explicit kernel
	// publication action that pairs with automatic publication being optional.
	document := embeddedWebFile(t, "index.html")
	if !strings.Contains(document, "threatIntelApplyBtn") {
		t.Fatal("the Threat Intelligence view offers no explicit kernel publication action")
	}
	threatIntel := embeddedWebFile(t, "threat-intel.js")
	if !strings.Contains(threatIntel, "applyFeeds") {
		t.Fatal("the Threat Intelligence view does not call the explicit publication endpoint")
	}
	if len(schema.Settings) == 0 {
		t.Fatal("the schema endpoint publishes no settings")
	}
	for _, meta := range schema.Settings {
		if meta.Key == "" || meta.Module == "" || meta.Group == "" || meta.Label == "" {
			t.Fatalf("incomplete setting metadata: %+v", meta)
		}
		if meta.ApplyClass == "" || meta.Risk == "" || meta.Description == "" {
			t.Fatalf("setting %s.%s is missing class, risk or description", meta.Module, meta.Key)
		}
		if meta.Type == "" {
			t.Fatalf("setting %s.%s has no declared type", meta.Module, meta.Key)
		}
	}
}

// TestOperationalViewsDoNotUseTheCardAutopilot locks the composition rule the
// operational views were rebuilt around. A row of identical statistic cards gives
// every figure the same visual weight, so the question the view exists to answer
// ends up below a wall of equal boxes. Counters live in the grouped telemetry rail.
func TestOperationalViewsDoNotUseTheCardAutopilot(t *testing.T) {
	document := embeddedWebFile(t, "index.html")
	views := servedViewBodies(t, document)
	if len(views) < 5 {
		t.Fatalf("only %d view bodies were extracted; the document scan looks wrong", len(views))
	}
	for _, page := range []string{"overview", "kinetic", "threat-intel", "l7", "xdr"} {
		body, ok := views[page]
		if !ok {
			t.Fatalf("view %q was not found in the served document", page)
		}
		if strings.Contains(body, "metric-card") {
			t.Errorf("view %q still renders equal-weight statistic cards instead of the telemetry rail", page)
		}
		if !strings.Contains(body, "defense-telemetry") {
			t.Errorf("view %q has no telemetry rail", page)
		}
		// An interactive row is a button. role="button" on a non-button element
		// means keyboard activation had to be reimplemented by hand.
		if strings.Contains(body, `role="button"`) {
			t.Errorf("view %q substitutes role=\"button\" for a real button element", page)
		}
		// Identity values (an inspected address, a policy fingerprint) may carry
		// the signature accent; counter values may not, because a colour that is
		// always on carries no information.
		for _, rail := range servedTelemetryRails(body) {
			if strings.Contains(rail, "text-cyan") {
				t.Errorf("view %q marks a counter value with the decorative accent colour", page)
			}
		}
	}
}

// servedViewBodies splits the served document into view bodies by view boundary.
// A regex terminated by the first closing tag would truncate any view that nests a
// section, and a truncated body makes the assertions below pass vacuously.
func servedViewBodies(t *testing.T, document string) map[string]string {
	t.Helper()
	markers := regexp.MustCompile(`<section class="view[^"]*" data-page="([a-z0-9_-]+)"`).FindAllStringSubmatchIndex(document, -1)
	views := make(map[string]string, len(markers))
	for index, marker := range markers {
		end := len(document)
		if index+1 < len(markers) {
			end = markers[index+1][0]
		}
		views[document[marker[2]:marker[3]]] = document[marker[1]:end]
	}
	return views
}

// servedTelemetryRails returns each telemetry rail block inside a view body.
func servedTelemetryRails(body string) []string {
	blocks := []string{}
	for _, match := range regexp.MustCompile(`(?s)<div class="defense-telemetry[^"]*"[^>]*>(.*?)\n          </div>`).FindAllStringSubmatch(body, -1) {
		blocks = append(blocks, match[1])
	}
	return blocks
}

// TestTelemetryRailHasStyles guards the grouped counter rail against losing its
// layout in a stylesheet edit: the groups must be rendered as label/value rows,
// not as unstyled blocks.
func TestTelemetryRailHasStyles(t *testing.T) {
	stylesheet := embeddedWebFile(t, "v4.css")
	for _, selector := range []string{
		".defense-telemetry", ".telemetry-group", ".telemetry-list",
		".telemetry-row dt", ".telemetry-row dd", ".telemetry-note",
		".vector-track", ".kinetic-command-bar", ".kinetic-verdict",
		".telemetry-action", ".telemetry-action:focus-visible", ".telemetry-trail", ".node-board",
	} {
		if !strings.Contains(stylesheet, selector) {
			t.Errorf("stylesheet does not define %q", selector)
		}
	}
	// The value column must not reflow while live numbers change width.
	if !strings.Contains(stylesheet, "tabular-nums") {
		t.Error("telemetry values do not use tabular numerals, so live updates will shift the column")
	}
}
