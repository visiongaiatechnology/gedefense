// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfTestService builds the smallest L7Service the upstream probe needs.
func selfTestService(t *testing.T, upstream string) *L7Service {
	t.Helper()
	cfg := defaultConfig()
	cfg.L7.Enabled = true
	cfg.L7.InlineEnabled = true
	cfg.L7.InlineUpstream = upstream
	cfg.L7.InlineSocket = filepath.Join(t.TempDir(), "edge.sock")
	cfg.L7.Socket = filepath.Join(t.TempDir(), "inspect.sock")
	return &L7Service{cfg: cfg.L7, state: NewState("test", cfg)}
}

// freeLoopbackPort returns a loopback address that was bound and then released, so the
// port is almost certainly closed. Racing another process for it is possible in theory
// and does not matter here: the test asserts on a connection failure, and a listener
// appearing would make it fail loudly rather than pass wrongly.
func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

// TestSelfTestReportsAnUnreachableUpstream covers the defect that misled a live
// deployment into believing its traffic path worked.
//
// The inline probe sends its request to the reserved self-test path, which the edge
// answers itself. It is never forwarded. So the self-test proved inspection worked and
// said nothing about whether an inspected request could go anywhere - and a host with
// nothing listening on its configured upstream reported PASS throughout.
func TestSelfTestReportsAnUnreachableUpstream(t *testing.T) {
	service := selfTestService(t, "http://"+freeLoopbackPort(t))

	result := service.probeInlineUpstream(context.Background(), L7SelfTestResult{
		Ran: true, Outcome: L7SelfTestPass, Path: "inline",
		Detail: "the inline edge inspected the request",
	})

	if result.UpstreamReachable {
		t.Fatal("an address nothing is listening on was reported reachable")
	}
	if result.Upstream == "" {
		t.Fatal("the result does not name the upstream it checked")
	}
	if !strings.Contains(result.UpstreamDetail, "cannot be forwarded") {
		t.Fatalf("the detail does not say what is wrong: %q", result.UpstreamDetail)
	}
	// A pass must not survive an unreachable upstream: the path cannot carry traffic.
	if result.Outcome != L7SelfTestUpstreamUnreachable {
		t.Fatalf("a passing inspection with a dead upstream reported %q", result.Outcome)
	}
	if !strings.Contains(result.Detail, "inspection works") {
		t.Fatalf("the detail blames the wrong half of the path: %q", result.Detail)
	}
}

// TestSelfTestKeepsPassWhenTheUpstreamAnswers is the counter-case: the probe must not
// turn a working deployment into a warning.
func TestSelfTestKeepsPassWhenTheUpstreamAnswers(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	service := selfTestService(t, "http://"+listener.Addr().String())
	result := service.probeInlineUpstream(context.Background(), L7SelfTestResult{
		Ran: true, Outcome: L7SelfTestPass, Path: "inline",
	})

	if !result.UpstreamReachable {
		t.Fatalf("a listening upstream was reported unreachable: %s", result.UpstreamDetail)
	}
	if result.Outcome != L7SelfTestPass {
		t.Fatalf("a working upstream changed the verdict to %q", result.Outcome)
	}
	if !strings.Contains(result.UpstreamDetail, "accepted a connection") {
		t.Fatalf("the detail does not record what was observed: %q", result.UpstreamDetail)
	}
}

// TestUpstreamProbeDoesNotMaskABrokenInspection pins the precedence. When the inspection
// itself failed, the upstream is not the interesting fact, and replacing the reason would
// point the operator at the wrong subsystem.
func TestUpstreamProbeDoesNotMaskABrokenInspection(t *testing.T) {
	service := selfTestService(t, "http://"+freeLoopbackPort(t))

	original := L7SelfTestResult{
		Ran: true, Outcome: L7SelfTestFail, Path: "inline",
		Detail: "the endpoint answered but no inspection counter moved",
	}
	result := service.probeInlineUpstream(context.Background(), original)

	if result.Outcome != L7SelfTestFail {
		t.Fatalf("a failed inspection was reclassified as %q", result.Outcome)
	}
	if result.Detail != original.Detail {
		t.Fatalf("the inspection failure reason was overwritten: %q", result.Detail)
	}
	// The upstream is still reported, because it is a fact either way.
	if result.UpstreamReachable {
		t.Fatal("the upstream was reported reachable")
	}
}

// TestUpstreamProbeRejectsAnUnusableValue covers configuration that cannot be dialled at
// all. Saying so is more useful than a connection error against a nonsense address.
func TestUpstreamProbeRejectsAnUnusableValue(t *testing.T) {
	for _, raw := range []string{"", "   ", "not a url", "http://10.0.0.1:8080", "http://127.0.0.1"} {
		service := selfTestService(t, raw)
		result := service.probeInlineUpstream(context.Background(), L7SelfTestResult{
			Ran: true, Outcome: L7SelfTestPass, Path: "inline",
		})
		if result.UpstreamReachable {
			t.Errorf("upstream %q was reported reachable", raw)
		}
		if result.UpstreamDetail == "" {
			t.Errorf("upstream %q produced no explanation", raw)
		}
		if raw != "" && result.Outcome == L7SelfTestPass {
			t.Errorf("upstream %q left the verdict at PASS", raw)
		}
	}
}

// TestUpstreamProbeIsBounded proves the probe cannot hang the diagnostic. It runs once
// with the self-test deadline and opens one connection; a probe that could be made to
// wait is a denial-of-service primitive aimed at the operator's own console.
func TestUpstreamProbeIsBounded(t *testing.T) {
	// A listener that accepts and never answers. The probe only connects, so it must
	// return promptly rather than waiting for a response that is never sent.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	service := selfTestService(t, "http://"+listener.Addr().String())
	start := time.Now()
	result := service.probeInlineUpstream(context.Background(), L7SelfTestResult{
		Ran: true, Outcome: L7SelfTestPass, Path: "inline",
	})
	if elapsed := time.Since(start); elapsed > l7SelfTestTimeout {
		t.Fatalf("the upstream probe took %s, beyond its own deadline", elapsed)
	}
	if !result.UpstreamReachable {
		t.Fatal("a listening socket was reported unreachable")
	}
}

// TestUpstreamProbeNamesTheTargetItChecked keeps the evidence auditable: an operator has
// to be able to see which address was verified, not only that something was.
func TestUpstreamProbeNamesTheTargetItChecked(t *testing.T) {
	target := freeLoopbackPort(t)
	service := selfTestService(t, "http://"+target)
	result := service.probeInlineUpstream(context.Background(), L7SelfTestResult{
		Ran: true, Outcome: L7SelfTestPass, Path: "inline",
	})
	if result.Upstream != "http://"+target {
		t.Fatalf("the result names %q instead of the configured upstream", result.Upstream)
	}
	if !strings.Contains(result.UpstreamDetail, target) {
		t.Fatalf("the detail does not name the address: %q", fmt.Sprint(result.UpstreamDetail))
	}
}
