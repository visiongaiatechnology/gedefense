// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"strings"
	"testing"
)

// TestIntegrationPathRejectsInjection is the security test for the generator. Its
// output is a configuration file for a privileged daemon, so a value that carries a
// newline, a semicolon or a quote could append arbitrary directives to a web server
// configuration. The validator must refuse rather than escape.
func TestIntegrationPathRejectsInjection(t *testing.T) {
	hostile := []struct {
		name  string
		value string
	}{
		{"newline directive injection", "/run/vgt-gedefense-l7/edge.sock;\n    root /etc;"},
		{"carriage return", "/run/edge.sock\r\nadd_header X-Evil 1;"},
		{"semicolon", "/run/edge.sock;"},
		{"double quote", "/run/edge\".sock"},
		{"single quote", "/run/edge'.sock"},
		{"brace", "/run/edge}.sock"},
		{"dollar expansion", "/run/$HOME/edge.sock"},
		{"backtick", "/run/`id`/edge.sock"},
		{"space", "/run/edge socket"},
		{"tab", "/run/edge\tsocket"},
		{"null byte", "/run/edge\x00.sock"},
		{"relative path", "run/edge.sock"},
		{"parent traversal", "/run/../etc/edge.sock"},
		{"not cleaned", "/run//edge.sock"},
		{"empty", ""},
		{"only whitespace", "   "},
		{"too long", "/" + strings.Repeat("a", 300)},
	}
	for _, tc := range hostile {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := validateIntegrationPath("socket", tc.value); err == nil {
				t.Fatalf("hostile path %q was accepted as %q", tc.value, got)
			}
		})
	}

	// The legitimate case must still work, otherwise the validator is simply broken.
	if got, err := validateIntegrationPath("socket", "/run/vgt-gedefense-l7/edge.sock"); err != nil || got != "/run/vgt-gedefense-l7/edge.sock" {
		t.Fatalf("a legitimate socket path was rejected: %q %v", got, err)
	}
}

// TestIntegrationUpstreamMustBeLoopback proves the edge cannot be pointed at another
// machine. A remote upstream would make GeDefense a forward proxy for traffic it
// cannot account for, and would move the trust boundary off the host.
func TestIntegrationUpstreamMustBeLoopback(t *testing.T) {
	hostile := []string{
		"http://example.com:8080",
		"http://10.0.0.5:8080",
		"http://169.254.169.254:80",
		"http://user:pass@127.0.0.1:8080",
		"ftp://127.0.0.1:8080",
		"http://127.0.0.1",
		"http://127.0.0.1:0",
		"http://127.0.0.1:99999",
		"http://127.0.0.1:8080/admin",
		"http://127.0.0.1:8080/?x=1",
		"",
	}
	for _, value := range hostile {
		if _, _, _, err := validateIntegrationUpstream(value); err == nil {
			t.Errorf("hostile upstream %q was accepted", value)
		}
	}
	legitimate := map[string]int{
		"http://127.0.0.1:8080": 8080,
		"http://[::1]:8080":     8080,
		"http://localhost:3000": 3000,
	}
	for value, wantPort := range legitimate {
		_, _, port, err := validateIntegrationUpstream(value)
		if err != nil {
			t.Errorf("legitimate upstream %q was rejected: %v", value, err)
			continue
		}
		if port != wantPort {
			t.Errorf("upstream %q produced port %d, want %d", value, port, wantPort)
		}
	}
}

func TestIntegrationHostRejectsMalformed(t *testing.T) {
	for _, value := range []string{"", "exa mple.test", "example.test;", "-bad.test", ".bad.test", "bad.test.", "a..b", "host\nname"} {
		if got, err := validateIntegrationHost("server name", value); err == nil {
			t.Errorf("malformed host %q was accepted as %q", value, got)
		}
	}
	for _, value := range []string{"example.test", "www.example.test", "a-b.example.test", "localhost"} {
		if _, err := validateIntegrationHost("server name", value); err != nil {
			t.Errorf("legitimate host %q was rejected: %v", value, err)
		}
	}
}

// TestGeneratedSnippetsCarryNoInjection proves the validators are actually wired into
// the generator: a plan built from hostile configuration must not contain the hostile
// text anywhere in its output.
func TestGeneratedSnippetsCarryNoInjection(t *testing.T) {
	cfg := defaultConfig().L7
	cfg.Enabled = true
	cfg.InlineEnabled = true
	cfg.InlineSocket = "/run/vgt-gedefense-l7/edge.sock"
	cfg.Socket = "/run/vgt-gedefense-l7/inspect.sock"
	cfg.InlineUpstream = "http://127.0.0.1:8080"
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState("test", Config{L7: cfg, XDR: defaultConfig().XDR, Release: defaultConfig().Release})
	service, err := NewL7Service(cfg, engine, state)
	if err != nil {
		t.Fatal(err)
	}

	plan := service.BuildIntegrationPlan(IntegrationRequest{ServerName: "example.test", ListenPort: 443})
	if !plan.Generated {
		t.Fatalf("a legitimate plan was not generated: %s", plan.Reason)
	}
	if len(plan.Snippets) == 0 {
		t.Fatal("a generated plan carried no snippets")
	}
	for _, snippet := range plan.Snippets {
		if strings.Contains(snippet.Body, "root /etc") || strings.Contains(snippet.Body, "add_header X-Evil") {
			t.Fatalf("snippet %q carries injected content", snippet.Target)
		}
		if !strings.Contains(snippet.Body, "/run/vgt-gedefense-l7/") {
			t.Fatalf("snippet %q does not reference the configured socket", snippet.Target)
		}
		// Every snippet must state how to verify it, otherwise it is a suggestion.
		if snippet.VerifyHint == "" || snippet.ApplyHint == "" {
			t.Fatalf("snippet %q does not state how to apply or verify it", snippet.Target)
		}
	}

	// A hostile server name must be refused, not interpolated.
	hostile := service.BuildIntegrationPlan(IntegrationRequest{ServerName: "example.test;\n    root /etc;"})
	if hostile.Generated {
		t.Fatal("a hostile server name produced a plan")
	}
	if hostile.Reason == "" {
		t.Fatal("a refused plan must state why")
	}
}

// TestIntegrationPlanNeverClaimsProtection covers the truthfulness rule for the
// generator: a snippet is an instruction, not evidence that protection is in effect.
func TestIntegrationPlanNeverClaimsProtection(t *testing.T) {
	cfg := defaultConfig().L7
	cfg.Enabled = true
	cfg.InlineEnabled = false
	cfg.Socket = "/run/vgt-gedefense-l7/inspect.sock"
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState("test", Config{L7: cfg, XDR: defaultConfig().XDR, Release: defaultConfig().Release})
	service, err := NewL7Service(cfg, engine, state)
	if err != nil {
		t.Fatal(err)
	}
	plan := service.BuildIntegrationPlan(IntegrationRequest{})
	if !plan.Generated {
		t.Fatalf("plan not generated: %s", plan.Reason)
	}
	// With the inline edge disabled the plan must warn that applying the inline
	// snippets alone would point at a socket nobody listens on.
	found := false
	for _, warning := range plan.Warnings {
		if strings.Contains(warning, "inline_enabled is false") {
			found = true
		}
	}
	if !found {
		t.Fatal("a plan whose inline snippets cannot work did not say so")
	}
	if plan.SelfTestHint == "" {
		t.Fatal("a plan must direct the operator to verify it")
	}
}

// TestSelfTestReportsNotAttachedWithoutPretending covers the outcome contract: an
// engine with nothing attached must not report PASS.
func TestSelfTestReportsNotAttachedWithoutPretending(t *testing.T) {
	cfg := defaultConfig().L7
	cfg.Enabled = true
	cfg.InlineEnabled = false
	cfg.Socket = ""
	cfg.InlineSocket = ""
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState("test", Config{L7: cfg, XDR: defaultConfig().XDR, Release: defaultConfig().Release})
	service, err := NewL7Service(cfg, engine, state)
	if err != nil {
		t.Fatal(err)
	}
	result := service.RunSelfTest(context.Background())
	if result.Outcome == L7SelfTestPass {
		t.Fatal("a self-test with no configured path reported PASS")
	}
	if result.Outcome != L7SelfTestNotAttached {
		t.Fatalf("outcome = %q, want NOT_ATTACHED", result.Outcome)
	}
	if result.Detail == "" {
		t.Fatal("a NOT_ATTACHED result must explain what is missing")
	}

	// A disabled engine reports DISABLED rather than a failure.
	disabled := defaultConfig().L7
	disabled.Enabled = false
	disabledEngine, err := NewL7Engine(disabled, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	disabledService, err := NewL7Service(disabled, disabledEngine, state)
	if err != nil {
		t.Fatal(err)
	}
	if got := disabledService.RunSelfTest(context.Background()).Outcome; got != L7SelfTestDisabled {
		t.Fatalf("a disabled engine reported %q, want DISABLED", got)
	}
}

// TestSelfTestFailsOnADeadSocket proves a configured-but-absent socket is reported as
// FAIL with a classified reason, not as a pass and not as a raw errno string.
func TestSelfTestFailsOnADeadSocket(t *testing.T) {
	cfg := defaultConfig().L7
	cfg.Enabled = true
	cfg.InlineEnabled = false
	cfg.Socket = "/run/gedefense-selftest-does-not-exist.sock"
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState("test", Config{L7: cfg, XDR: defaultConfig().XDR, Release: defaultConfig().Release})
	service, err := NewL7Service(cfg, engine, state)
	if err != nil {
		t.Fatal(err)
	}
	result := service.RunSelfTest(context.Background())
	if result.Outcome != L7SelfTestFail {
		t.Fatalf("outcome = %q, want FAIL", result.Outcome)
	}
	if !result.Ran {
		t.Fatal("a probe that attempted a connection must record that it ran")
	}
	// The detail must be classified prose, never the raw error: the raw text carries
	// the socket path and an errno, and this string is rendered in the dashboard.
	for _, leak := range []string{"no such file", "syscall", "errno", "connect:"} {
		if strings.Contains(result.Detail, leak) {
			t.Fatalf("self-test detail leaks raw error text %q: %s", leak, result.Detail)
		}
	}
	if result.Detail == "" {
		t.Fatal("a failure must carry a classified reason")
	}
}

// TestTLSCoverageIsOnlyRequiredWhenAsked pins the fix for the third over-aggressive
// verdict: TLS silence is a finding only when TLS coverage was requested.
func TestTLSCoverageIsOnlyRequiredWhenAsked(t *testing.T) {
	base := L7Status{Enabled: true, Healthy: true, TLSEnabled: true, RequestsTotal: 40}

	// TLS enabled but coverage not required: no finding, because nobody asked for it.
	notRequired := base
	notRequired.CoverageRequired = false
	if got := EvaluateL7Coverage(notRequired, 3600); got == "TLS_NOT_IN_PATH" {
		t.Fatal("TLS silence was reported although TLS coverage was never required")
	}

	// Coverage required and HTTP traffic flowing but no ClientHello: a real finding.
	required := base
	required.CoverageRequired = true
	if got := EvaluateL7Coverage(required, 3600); got != "TLS_NOT_IN_PATH" {
		t.Fatalf("TLS silence was not reported although coverage was required: %q", got)
	}
}
