package webposture

import (
	"strings"
	"testing"
)

// TestVersionRangeMatching locks the inclusive dotted-number comparison used by
// the advisory catalogue.
func TestVersionRangeMatching(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		version  string
		advisory Advisory
		want     bool
	}{
		{"below minimum", "1.28.9", Advisory{MinVersion: "1.29.0", MaxVersion: "1.30.6"}, false},
		{"at minimum", "1.29.0", Advisory{MinVersion: "1.29.0", MaxVersion: "1.30.6"}, true},
		{"inside", "1.29.4", Advisory{MinVersion: "1.29.0", MaxVersion: "1.30.6"}, true},
		{"at maximum", "1.30.6", Advisory{MinVersion: "1.29.0", MaxVersion: "1.30.6"}, true},
		{"above maximum", "1.30.7", Advisory{MinVersion: "1.29.0", MaxVersion: "1.30.6"}, false},
		{"unbounded maximum", "1.31.0", Advisory{MinVersion: "1.29.0"}, true},
		{"unbounded minimum", "1.0.1", Advisory{MaxVersion: "1.27.4"}, true},
		{"component count differs", "3.5", Advisory{MinVersion: "3.0.0", MaxVersion: "3.5.2"}, true},
		{"equal padded", "3.5.0", Advisory{MinVersion: "3.5", MaxVersion: "3.5"}, true},
		{"empty version never matches", "", Advisory{MinVersion: "1.0.0"}, false},
		{"unparsable range never matches", "1.2.3", Advisory{MinVersion: "banana"}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := versionInRange(tc.version, tc.advisory); got != tc.want {
				t.Fatalf("versionInRange(%q, %+v) = %t, want %t", tc.version, tc.advisory, got, tc.want)
			}
		})
	}
}

// TestAffectedOnlyWhenReachable locks the mission's rule: a version match alone
// is never an exposure. Every gate is exercised independently.
func TestAffectedOnlyWhenReachable(t *testing.T) {
	t.Parallel()
	base := Server{
		Comm: "nginx", Binary: "/usr/sbin/nginx", Version: "1.29.4",
		OpenSSL: "OpenSSL 3.5.2", HTTP2: true, QUIC: true,
		Reachable: true,
		ALPN:      ALPNResult{Checked: true, Protocol: "h2", Offered: []string{"h2", "http/1.1"}},
	}
	catalogue := Catalogue()

	// Fully reachable + h2 + quic + openssl: all three mission CVEs match.
	hits := MatchAdvisories(base, catalogue)
	ids := map[string]bool{}
	for _, hit := range hits {
		ids[hit.ID] = true
	}
	for _, want := range []string{"CVE-2026-123007", "CVE-2026-123633", "CVE-2026-121810"} {
		if !ids[want] {
			t.Fatalf("reachable server did not match %s (hits=%+v)", want, hits)
		}
	}

	// Loopback-only server: the h2 advisory (reachability implied by HTTP/2 being
	// active) still matches, but the openssl advisory that explicitly requires a
	// reachable listener must not.
	loopback := base
	loopback.Reachable = false
	loopback.ALPN = ALPNResult{Checked: true, Protocol: "http/1.1", Offered: []string{"http/1.1"}}
	loopback.HTTP2 = false
	loopback.QUIC = false
	hits = MatchAdvisories(loopback, catalogue)
	for _, hit := range hits {
		if hit.ID == "CVE-2026-121810" {
			t.Fatalf("an unreachable server was reported as affected by a reachability-gated advisory")
		}
		if hit.ID == "CVE-2026-123007" {
			t.Fatalf("an HTTP/2 advisory matched a server that does not offer HTTP/2")
		}
	}

	// A patched version is never affected, even when everything else is exposed.
	patched := base
	patched.Version = "1.31.0"
	patched.OpenSSL = "OpenSSL 3.6.0"
	if hits := MatchAdvisories(patched, catalogue); len(hits) != 0 {
		t.Fatalf("patched reachable server still reported affected: %+v", hits)
	}
}

// TestParseExtraAdvisoriesRejectsUnknownFields keeps operator typo safety.
func TestParseExtraAdvisoriesRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	if _, err := ParseExtraAdvisories([]byte(`[{"id":"OPS-1","product":"nginx","severity":"high","summary":"x","sevirity":"low"}]`)); err == nil {
		t.Fatal("unknown advisory field was accepted")
	}
	valid, err := ParseExtraAdvisories([]byte(`[{"id":"OPS-1","product":"nginx","severity":"high","summary":"operator advisory","min_version":"1.0.0","max_version":"1.9.9"}]`))
	if err != nil || len(valid) != 1 {
		t.Fatalf("valid advisory rejected: %v %+v", err, valid)
	}
	if _, err := ParseExtraAdvisories([]byte(`not json`)); err == nil {
		t.Fatal("malformed advisory JSON was accepted")
	}
}

// TestComputeSummaryGradesExposure locks the score/grade arithmetic, including
// the floor at zero.
func TestComputeSummaryGradesExposure(t *testing.T) {
	t.Parallel()
	if summary := ComputeSummary(nil); summary.Servers != 0 || summary.Grade != "A" || summary.Score != 100 {
		t.Fatalf("empty host summary = %+v", summary)
	}
	summary := ComputeSummary([]Server{
		{Posture: PostureExposed, Affected: []AdvisoryHit{{Severity: "critical"}, {Severity: "high"}, {Severity: "medium"}}},
		{Posture: PostureInternal},
		{Posture: PostureLoopback},
	})
	if summary.Servers != 3 || summary.Exposed != 1 {
		t.Fatalf("summary counts = %+v", summary)
	}
	if summary.AffectedCVEs != 3 {
		t.Fatalf("affected CVE count = %d, want 3", summary.AffectedCVEs)
	}
	if summary.Score >= 100 || summary.Grade == "A" {
		t.Fatalf("an exposed host with critical advisories kept grade A: %+v", summary)
	}
}

// TestClassifyPosture covers loopback/private/public listener classes.
func TestClassifyPosture(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		listeners []string
		want      string
	}{
		{"no listener", nil, PostureUnknown},
		{"loopback v4", []string{"127.0.0.1:443"}, PostureLoopback},
		{"loopback v6", []string{"[::1]:443"}, PostureLoopback},
		{"wildcard is public", []string{"0.0.0.0:443"}, PostureExposed},
		{"ipv6 wildcard is public", []string{"[::]:443"}, PostureExposed},
		{"private network", []string{"10.0.0.5:443"}, PostureInternal},
		{"mixed loopback and public", []string{"127.0.0.1:443", "192.0.2.10:443"}, PostureExposed},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := classifyPosture(Server{Listen: tc.listeners}); got != tc.want {
				t.Fatalf("classifyPosture(%v) = %q, want %q", tc.listeners, got, tc.want)
			}
		})
	}
}

// TestParseNginxConfig locks the config evidence shape from blueprint 3.2.
func TestParseNginxConfig(t *testing.T) {
	t.Parallel()
	config := `
server {
    listen 443 ssl http2;
    server_name example.org;
    ssl_certificate /etc/ssl/example.pem;
    location / { proxy_pass http://127.0.0.1:8080; }
}
`
	file := ParseConfig("/etc/nginx/nginx.conf", []byte(config), "nginx")
	if !file.TLS || !file.HTTP2 {
		t.Fatalf("nginx config flags = tls:%t http2:%t", file.TLS, file.HTTP2)
	}
	if len(file.ServerNames) != 1 || file.ServerNames[0] != "example.org" {
		t.Fatalf("server names = %+v", file.ServerNames)
	}
	if len(file.ListenPorts) != 1 || file.ListenPorts[0] != 443 {
		t.Fatalf("listen ports = %+v", file.ListenPorts)
	}
	found := false
	for _, hit := range file.Hits {
		if hit.Line == 3 && strings.HasPrefix(hit.Directive, "listen 443") {
			found = true
			if hit.Path != "/etc/nginx/nginx.conf" {
				t.Fatalf("hit path = %q", hit.Path)
			}
		}
	}
	if !found {
		t.Fatalf("listen evidence line missing: %+v", file.Hits)
	}
}

// TestParseConfigIgnoresComments keeps a commented-out directive from turning
// into a finding.
func TestParseConfigIgnoresComments(t *testing.T) {
	t.Parallel()
	file := ParseConfig("/etc/nginx/nginx.conf", []byte("# listen 443 ssl http2;\nlisten 80;\n"), "nginx")
	if file.TLS || file.HTTP2 {
		t.Fatalf("commented directives leaked into the parse: %+v", file)
	}
	if len(file.ListenPorts) != 1 || file.ListenPorts[0] != 80 {
		t.Fatalf("listen ports = %+v", file.ListenPorts)
	}
}
