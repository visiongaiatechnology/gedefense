// STATUS: DIAMANT VGT SUPREME
package main

// M4 regression tests: comment/whitespace SQLi normalisation, secret-file probe
// score, semicolon-chained query inspection, the large-body fast pass, the
// deterministic rate-limit classification and the English-prose guard.

import (
	"context"
	"strings"
	"testing"
	"time"
)

func l7BlockEngine(t *testing.T) *L7Engine {
	t.Helper()
	cfg := l7TestConfig()
	cfg.Mode = "block"
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.canBlock = func() bool { return true }
	return engine
}

func TestL7SQLCommentObfuscationIsCanonicalizedAndBlocked(t *testing.T) {
	engine := l7BlockEngine(t)
	response, err := engine.Inspect(context.Background(), l7Request("/?id=1/**/oR/**/1=1--"))
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.SQLI.BOOLEAN_TAUTOLOGY") {
		t.Fatalf("comment-obfuscated tautology was not detected: %+v", response.Findings)
	}
	if response.Decision != "block" || !response.Enforced {
		t.Fatalf("comment-obfuscated tautology was not blocked: %+v", response)
	}
}

func TestL7SQLSchemaProbeIsDetectedWithoutTrailingComment(t *testing.T) {
	engine := l7BlockEngine(t)
	response, err := engine.Inspect(context.Background(), l7Request("/?q=(select+group_concat(table_name)+from+information_schema.tables)"))
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.SQLI.SCHEMA_PROBE") {
		t.Fatalf("schema probe was not detected: %+v", response.Findings)
	}
}

func TestL7SecretFileProbeBlocksOnItsOwn(t *testing.T) {
	engine := l7BlockEngine(t)
	for _, uri := range []string{"/.env", "/.env.local", "/.git/config", "/wp-config.php.bak"} {
		response, err := engine.Inspect(context.Background(), l7Request(uri))
		if err != nil {
			t.Fatalf("%s: %v", uri, err)
		}
		if !findingByID(response.Findings, "L7.SCANNER.PROBE") {
			t.Fatalf("%s was not detected as a secret-file probe: %+v", uri, response.Findings)
		}
		if response.Decision != "block" {
			t.Fatalf("%s was not blocked: %+v", uri, response)
		}
	}
}

func TestL7SemicolonQueryChainIsInspectedNotRejected(t *testing.T) {
	engine := l7BlockEngine(t)
	response, err := engine.Inspect(context.Background(), l7Request("/?cmd=;cat%20/etc/passwd%23"))
	if err != nil {
		t.Fatalf("semicolon query chain was rejected instead of inspected: %v", err)
	}
	if !findingByID(response.Findings, "L7.CMD.SHELL_CHAIN") {
		t.Fatalf("semicolon command chain was not detected: %+v", response.Findings)
	}
	if response.Decision != "block" {
		t.Fatalf("semicolon command chain was not blocked: %+v", response)
	}
}

func TestL7EnglishSQLProseStaysClean(t *testing.T) {
	engine := l7BlockEngine(t)
	for _, uri := range []string{
		"/?q=Please+select+a+union+contract+from+our+table",
		"/?q=we+have+the+best+select+and+union+rates+for+the+table",
	} {
		response, err := engine.Inspect(context.Background(), l7Request(uri))
		if err != nil {
			t.Fatalf("%s: %v", uri, err)
		}
		for _, finding := range response.Findings {
			if strings.HasPrefix(finding.RuleID, "L7.SQLI.") {
				t.Fatalf("English prose produced a SQLi finding: %+v (%s)", finding, uri)
			}
		}
		if response.Enforced {
			t.Fatalf("English prose was enforced on: %+v", response)
		}
	}
}

func TestL7LargeBodyFastPassBlocksAndDoesNotTimeOut(t *testing.T) {
	engine := l7BlockEngine(t)
	body := []byte(strings.Repeat("harmless filler; ", 50000) + "<?php system($_GET['cmd']); ?>")
	if len(body) < 700<<10 {
		t.Fatalf("fixture body is too small: %d", len(body))
	}
	start := time.Now()
	response, _, err := engine.InspectRaw(context.Background(), L7InspectionRequest{
		Version: l7ProtocolVersion, RequestID: "0123456789abcdef", Method: "POST", Scheme: "https",
		Host: "example.test", URI: "/upload.php", RemoteIP: "198.51.100.10",
	}, body)
	if err != nil {
		t.Fatalf("large body was rejected instead of decided: %v", err)
	}
	if !findingByID(response.Findings, "L7.CODE.PHP_TAG") {
		t.Fatalf("PHP payload in a large body was not detected: %+v", response.Findings)
	}
	if response.Decision != "block" || !response.Enforced {
		t.Fatalf("large-body PHP payload was not blocked: %+v", response)
	}
	fastLimit := 500 * time.Millisecond * l7TestTimeoutScale
	if elapsed := time.Since(start); elapsed > fastLimit {
		t.Fatalf("large-body fast pass took %s (timeout regression > %s)", elapsed, fastLimit)
	}
}

func TestL7LargeBenignBodyIsInspectedWithinBudget(t *testing.T) {
	engine := l7BlockEngine(t)
	body := []byte(strings.Repeat("harmless filler text for a benign document ", 40000))
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond*l7TestTimeoutScale)
	defer cancel()
	response, _, err := engine.InspectRaw(ctx, L7InspectionRequest{
		Version: l7ProtocolVersion, RequestID: "0123456789abcdef", Method: "POST", Scheme: "https",
		Host: "example.test", URI: "/storage/document.txt", RemoteIP: "198.51.100.10",
	}, body)
	if err != nil {
		t.Fatalf("benign large body ended in an inspection error (historical 503): %v", err)
	}
	if response.Decision == "block" {
		t.Fatalf("benign large body was blocked: %+v", response)
	}
}

func TestL7RateLimitDecisionIsDeterministicAndSeparatedFromSecurityBlock(t *testing.T) {
	cfg := l7TestConfig()
	cfg.Mode = "block"
	cfg.ClientRatePerMinute = 1
	cfg.ClientRateBurst = 1
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.canBlock = func() bool { return true }
	if _, err := engine.Inspect(context.Background(), l7Request("/ordinary")); err != nil {
		t.Fatal(err)
	}
	limited, err := engine.Inspect(context.Background(), l7Request("/ordinary"))
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(limited.Findings, "L7.RATE_LIMIT.CLIENT") {
		t.Fatalf("rate-limit finding missing: %+v", limited.Findings)
	}
	if !limited.RateLimit || limited.RetryAfterSeconds != l7RateLimitRetryAfterSeconds {
		t.Fatalf("rate limit is not classified deterministically: %+v", limited)
	}
	// The socket decision string stays "block" so a producer that only knows the
	// block vocabulary can never fail open on a new value.
	if limited.Decision != "block" || !limited.Enforced {
		t.Fatalf("rate limit decision broke the block contract: %+v", limited)
	}

	// A mixed request keeps the security block classification (403), never 429.
	mixed, err := engine.Inspect(context.Background(), l7Request("/?q=%3Cscript%3Ealert(1)%3C/script%3E"))
	if err != nil {
		t.Fatal(err)
	}
	if mixed.RateLimit {
		t.Fatalf("a security finding was downgraded to a rate limit: %+v", mixed)
	}
}

func TestL7ScannerUserAgentIsSignalled(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := l7Request("/index.html")
	request.Headers = []L7Header{{Name: "User-Agent", Value: "sqlmap/1.8 (https://sqlmap.org)"}}
	response, err := engine.Inspect(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.SCANNER.USER_AGENT") {
		t.Fatalf("scanner user agent was not detected: %+v", response.Findings)
	}
}
