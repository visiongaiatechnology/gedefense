package main

import "testing"

func TestParseCoreIngressEventsCarriesKernelWindowEpoch(t *testing.T) {
	events, err := parseCoreIngressEvents("4:6:2:2:54321:443:3:180:2:1:12345:cb007109:c000020a")
	if err != nil {
		t.Fatalf("parse ingress event: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one ingress event, got %d", len(events))
	}
	got := events[0]
	if got.WindowEpoch != 12345 || got.Packets != 3 || got.SYNCount != 2 || got.ACKCount != 1 || got.AttemptCount != 2 {
		t.Fatalf("unexpected ingress event: %+v", got)
	}
	if got.Source.String() != "203.0.113.9" || got.Destination.String() != "192.0.2.10" {
		t.Fatalf("unexpected addresses: %s -> %s", got.Source, got.Destination)
	}
}

func TestParseCoreIngressEventsRejectsMissingOrZeroKernelEpoch(t *testing.T) {
	bad := []string{
		"4:6:2:54321:443:1:60:1:0:cb007109:c000020a",       // old pre-attempt/epoch contract
		"4:6:2:1:54321:443:1:60:1:0:0:cb007109:c000020a",   // zero epoch
		"4:6:2:1:54321:443:1:60:2:0:123:cb007109:c000020a", // SYN > packets
		"4:6:2:0:54321:443:1:60:1:0:123:cb007109:c000020a", // TCP attempt count != SYN count
	}
	for _, payload := range bad {
		if _, err := parseCoreIngressEvents(payload); err == nil {
			t.Fatalf("expected payload to be rejected: %q", payload)
		}
	}
}

func TestParseCoreIngressEventsEnforcesResponseBatchBound(t *testing.T) {
	const one = "6:6:2:255:65535:65535:4294967295:4294967295:255:0:18446744073709551615:20010db8000000000000000000000001:20010db8000000000000000000000002"
	payload := one
	for i := 1; i < maxCoreIngressEventsPerResponse; i++ {
		payload += "," + one
	}
	if len(payload) >= 2048 {
		t.Fatalf("bounded 12-record raw IPC response unexpectedly exceeds Rust core response budget: %d", len(payload))
	}
	if events, err := parseCoreIngressEvents(payload); err != nil || len(events) != maxCoreIngressEventsPerResponse {
		t.Fatalf("expected bounded response to parse, events=%d err=%v", len(events), err)
	}
	if _, err := parseCoreIngressEvents(payload + "," + one); err == nil {
		t.Fatal("expected parser to reject more records than the bounded Rust core contract")
	}
}
