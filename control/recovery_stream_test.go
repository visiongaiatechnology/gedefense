package main

import (
	"testing"
	"time"
)

func TestDashboardHTTPServerKeepsSSEWriteDeadlineUnbounded(t *testing.T) {
	cfg := defaultConfig()
	server := NewAPIServer(cfg, NewState("test", cfg), nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")

	if server.http.WriteTimeout != 0 {
		t.Fatalf("dashboard WriteTimeout=%s; SSE requires no global response write deadline", server.http.WriteTimeout)
	}
	if server.http.ReadHeaderTimeout <= 0 || server.http.ReadHeaderTimeout > 10*time.Second {
		t.Fatalf("unexpected ReadHeaderTimeout=%s", server.http.ReadHeaderTimeout)
	}
	if server.http.IdleTimeout < time.Minute {
		t.Fatalf("dashboard IdleTimeout=%s is too aggressive for long-lived browser sessions", server.http.IdleTimeout)
	}
}

func TestDefaultKineticTelemetryDoesNotClaimVerifiedIngress(t *testing.T) {
	telemetry := DefaultKineticTelemetry()
	sensor, ok := telemetry.Coverage.Sensors["xdp_ingress"]
	if !ok {
		t.Fatal("xdp_ingress coverage entry missing")
	}
	if sensor.Status == CoverageOnline {
		t.Fatal("default xdp_ingress coverage must not claim ONLINE before a verified producer is observed")
	}
	if sensor.SelfTest == "pass" {
		t.Fatal("default xdp_ingress self-test must not claim pass before runtime verification")
	}
	ingress := telemetry.Layers[LayerIngressNetwork]
	if ingress.DetectionHealthy || ingress.EnforcementHealthy {
		t.Fatalf("default ingress layer unexpectedly healthy: %+v", ingress)
	}
}
