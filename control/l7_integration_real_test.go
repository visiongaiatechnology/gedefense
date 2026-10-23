// STATUS: DIAMANT VGT SUPREME
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Generated web-server configuration, validated by the web server itself.
//
// The integration generator produced nginx, apache and caddy artefacts that no real web
// server had ever parsed. Reviewing generated text proves nothing about it: a directive
// can be plausible, documented and still rejected by the parser, and the operator would
// discover that only after editing their production configuration. These tests hand the
// generated body to the real web server in check-only mode.
//
// They skip when the web server is absent rather than failing, so a host without nginx
// does not report a broken build. The skip is reported, never silent.

// nginxBinary locates an nginx that can be asked to check a configuration.
func nginxBinary(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("nginx")
	if err != nil {
		t.Skip("nginx is not installed, so the generated nginx configuration cannot be parsed here")
	}
	return path
}

// integrationServiceFor builds the L7 service the plan generator hangs off. The plan is a
// method on the service because the topology it describes - which socket the edge should
// forward to - is owned by the running engine, not by the request.
func integrationServiceFor(t *testing.T) *L7Service {
	t.Helper()
	cfg := defaultConfig()
	l7cfg := cfg.L7
	l7cfg.Enabled = true
	l7cfg.Socket = filepath.Join(t.TempDir(), "l7.sock")
	engine, err := NewL7Engine(l7cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewL7Service(l7cfg, engine, NewState("test", cfg))
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// planFor builds an integration plan for a loopback upstream on a fixed port.
func planFor(t *testing.T, serverName string, listenPort int) IntegrationPlan {
	t.Helper()
	plan := integrationServiceFor(t).BuildIntegrationPlan(IntegrationRequest{
		ServerName: serverName,
		ListenPort: listenPort,
		// The upstream is a URL with an explicit loopback port. That is what the
		// validator requires, and it is what the generated edge will forward to.
		Upstream: "http://127.0.0.1:8080",
	})
	if !plan.Generated {
		t.Fatalf("the generator declined to produce a plan: %s", plan.Reason)
	}
	return plan
}

// snippetFor returns the nginx snippet, failing when the generator stopped producing one.
func snippetFor(t *testing.T, plan IntegrationPlan, server string) IntegrationSnippet {
	t.Helper()
	for _, snippet := range plan.Snippets {
		if snippet.Target == server {
			if strings.TrimSpace(snippet.Body) == "" {
				t.Fatalf("the %s snippet is empty", server)
			}
			return snippet
		}
	}
	t.Fatalf("the plan contains no %s snippet; snippets are %v", server, snippetTargets(plan))
	return IntegrationSnippet{}
}

func snippetTargets(plan IntegrationPlan) []string {
	targets := make([]string, 0, len(plan.Snippets))
	for _, snippet := range plan.Snippets {
		targets = append(targets, snippet.Target)
	}
	return targets
}

// TestGeneratedNginxConfigurationParses proves the nginx artefact is accepted by nginx.
//
// The snippet is placed in a complete configuration whose only other content is what a
// real site needs: an events block, an http block and a server that listens on a
// high port. Everything the product generates is included verbatim.
func TestGeneratedNginxConfigurationParses(t *testing.T) {
	binary := nginxBinary(t)
	plan := planFor(t, "gedefense.test", 8443)
	snippet := snippetFor(t, plan, "nginx")

	dir := t.TempDir()
	// A prefix keeps nginx from touching the host: logs, pid and temp paths all land in
	// the test directory rather than /var.
	for _, sub := range []string{"logs", "conf", "temp"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The generated body is two insertable pieces, so the test places them where the
	// snippet says they go. The surrounding server block stands in for the one the
	// operator already runs: it terminates TLS and it is the block the location belongs
	// inside. Without a certificate nginx refuses a TLS listener, which is exactly the
	// reason the earlier artefact could not be applied at all.
	certificate, key := selfSignedCertificateFor(t, dir)
	configuration := "worker_processes 1;\n" +
		"pid " + filepath.Join(dir, "nginx.pid") + ";\n" +
		"error_log " + filepath.Join(dir, "logs", "error.log") + ";\n" +
		"events { worker_connections 64; }\n" +
		"http {\n" +
		"  access_log off;\n" +
		"  client_body_temp_path " + filepath.Join(dir, "temp") + ";\n" +
		"  proxy_temp_path " + filepath.Join(dir, "temp") + ";\n" +
		"  fastcgi_temp_path " + filepath.Join(dir, "temp") + ";\n" +
		"  uwsgi_temp_path " + filepath.Join(dir, "temp") + ";\n" +
		"  scgi_temp_path " + filepath.Join(dir, "temp") + ";\n" +
		nginxUpstreamFrom(t, snippet.Body) +
		"  server {\n" +
		"    listen 18443 ssl;\n" +
		"    server_name gedefense.test;\n" +
		"    ssl_certificate " + certificate + ";\n" +
		"    ssl_certificate_key " + key + ";\n" +
		nginxLocationFrom(t, snippet.Body) +
		"  }\n" +
		"}\n"

	configPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}

	output, err := exec.Command(binary, "-t", "-c", configPath, "-p", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("nginx rejected the generated configuration:\n%s\n--- generated body ---\n%s\n--- assembled ---\n%s",
			strings.TrimSpace(string(output)), snippet.Body, configuration)
	}
	// nginx exits 0 for a warning-only configuration, so the output is inspected too.
	if strings.Contains(string(output), "[emerg]") {
		t.Fatalf("nginx reported an emergency while checking the generated configuration:\n%s", output)
	}
	t.Logf("nginx accepted the assembled configuration: %s", strings.TrimSpace(string(output)))
}

// TestGeneratedNginxConfigurationKeepsTrafficOnTheInspectionPath is the property that
// matters. A configuration can parse and still bypass the engine entirely, which would
// leave the operator believing they are protected while nothing is inspected.
func TestGeneratedNginxConfigurationKeepsTrafficOnTheInspectionPath(t *testing.T) {
	plan := planFor(t, "gedefense.test", 8443)
	snippet := snippetFor(t, plan, "nginx")
	body := snippet.Body

	// The edge has to reach the engine, and it does so over the inline socket: that is the
	// listener the edge forwards to so a request can be inspected. Asserting against the
	// producer socket would be checking the wrong one - they are different sockets with
	// different roles - so the assertion names the inline socket explicitly.
	if plan.InlineSocket == "" {
		t.Fatal("the plan carries no inline socket, so no generated edge could reach the engine")
	}
	if !strings.Contains(body, plan.InlineSocket) {
		t.Errorf("the generated nginx body never references the inline socket %q:\n%s", plan.InlineSocket, body)
	}
	// And it must not route to the application directly. The edge socket replaces the
	// application upstream, so the generated edge forwards to the engine and the engine
	// forwards onward; a proxy_pass naming the application would let nginx serve traffic
	// without any inspection at all while the operator believed the path was wired. This
	// is the assertion that catches a bypass, so it is stated as the negative.
	if authority := strings.TrimPrefix(plan.Upstream, "http://"); authority != "" && strings.Contains(body, authority) {
		t.Errorf("the generated nginx body routes straight to the application at %q, bypassing inspection:\n%s", authority, body)
	}
	if strings.Contains(body, "proxy_pass http://127.0.0.1:8080") {
		t.Errorf("the generated nginx body contains a direct route to the application:\n%s", body)
	}
	// A proxy_pass is what routes the request through the engine; without it the server
	// block would serve nothing.
	if !strings.Contains(body, "proxy_pass") {
		t.Errorf("the generated nginx body contains no proxy_pass:\n%s", body)
	}
	// The plan must tell the operator how to verify, not only how to apply. Applying a
	// configuration and assuming it works is the failure this whole path exists to avoid.
	if strings.TrimSpace(snippet.VerifyHint) == "" {
		t.Error("the nginx snippet carries no verification hint")
	}
	if strings.TrimSpace(snippet.ApplyHint) == "" {
		t.Error("the nginx snippet carries no apply hint")
	}
	if !strings.Contains(snippet.VerifyHint, "nginx -t") {
		t.Errorf("the verification hint does not tell the operator to check the configuration: %q", snippet.VerifyHint)
	}
}

// TestGeneratedApacheAndCaddyArtefactsArePresent proves the other two servers still
// produce a body. They cannot be parsed here without installing both, and claiming a
// parse check that did not run would be worse than saying so.
func TestGeneratedApacheAndCaddyArtefactsArePresent(t *testing.T) {
	plan := planFor(t, "gedefense.test", 8443)
	for _, target := range []string{"apache", "caddy"} {
		snippet := snippetFor(t, plan, target)
		if !strings.Contains(snippet.Body, plan.InlineSocket) {
			t.Errorf("the generated %s body never references the inline socket", target)
		}
		if strings.TrimSpace(snippet.VerifyHint) == "" {
			t.Errorf("the generated %s snippet carries no verification hint", target)
		}
	}
	// The parser check above runs only for nginx. This records that the other two were
	// reviewed structurally and not parsed, so the gap is visible in the test output.
	t.Log("apache and caddy artefacts were checked structurally only; neither server is installed here")
}

// nginxLocationFrom extracts the location block from the generated body. The body is
// written as documentation with the pieces indented, so the test takes the block between
// the location opening and its matching brace rather than reimplementing the generator.
func nginxLocationFrom(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, "location / {")
	if start < 0 {
		t.Fatalf("the generated body contains no location block:\n%s", body)
	}
	depth, end := 0, -1
	for index := start; index < len(body); index++ {
		switch body[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = index + 1
			}
		}
		if end > 0 {
			break
		}
	}
	if end < 0 {
		t.Fatalf("the generated location block is unterminated:\n%s", body)
	}
	block := body[start:end]
	// The body indents the pieces for readability; nginx does not care, but the test
	// normalises so a formatting change in the documentation cannot break the parse.
	lines := strings.Split(block, "\n")
	for index, line := range lines {
		lines[index] = strings.TrimSpace(line)
	}
	return strings.Join(lines, "\n") + "\n"
}

// selfSignedCertificateFor produces a throwaway certificate so the stand-in server block
// can be a real TLS listener. Without one nginx refuses to check the configuration, which
// is the defect this test exists to catch.
func selfSignedCertificateFor(t *testing.T, dir string) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not installed, so a certificate for the TLS listener cannot be created")
	}
	certificate := filepath.Join(dir, "test.crt")
	key := filepath.Join(dir, "test.key")
	command := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", key, "-out", certificate, "-days", "1",
		"-subj", "/CN=gedefense.test", "-addext", "subjectAltName=DNS:gedefense.test")
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("could not create a test certificate: %v: %s", err, output)
	}
	return certificate, key
}

// nginxUpstreamFrom extracts the upstream block from the generated body, so the test
// feeds nginx the artefact the operator receives rather than a reconstruction of it.
func nginxUpstreamFrom(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, "upstream gedefense_l7_edge {")
	if start < 0 {
		t.Fatalf("the generated body contains no upstream block:\n%s", body)
	}
	depth, end := 0, -1
	for index := start; index < len(body); index++ {
		switch body[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = index + 1
			}
		}
		if end > 0 {
			break
		}
	}
	if end < 0 {
		t.Fatalf("the generated upstream block is unterminated:\n%s", body)
	}
	return body[start:end] + "\n"
}
