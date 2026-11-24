// STATUS: V6.3.0 AP-0
package main

// V6.3.0 AP-0 regression tests: the bounded, strict SELF_GUARD_STATUS /
// SELF_TAMPER_EVENTS parsers, the capability-fact mapping of a pre-6.3 core and
// the closed SELF_GUARD_SET answer. Every parser is all-or-nothing, so a hostile
// or corrupt core can only cause a rejected drain, never a partial record.

import (
	"errors"
	"strings"
	"testing"
)

func TestCoreSelfGuardStatusParserStrict(t *testing.T) {
	valid := "enabled=1:pins=3:missing=1:replaced=1:canary=active:canary_runs=4:canary_failures=1:events=5:dropped=2"
	status, err := parseCoreSelfGuardStatus(valid)
	if err != nil {
		t.Fatalf("valid self-guard status rejected: %v", err)
	}
	if !status.Enabled || !status.Armed || !status.PinsAvailable || status.PinsExpected != 3 ||
		status.PinsMissing != 1 || status.PinsReplaced != 1 || status.CanaryState != "active" ||
		status.CanaryRuns != 4 || status.CanaryFailures != 1 || status.Events != 5 || status.QueueDropped != 2 {
		t.Fatalf("self-guard status decoded wrong: %+v", status)
	}
	// The keys are a set, not an ordered layout: a different order is the same
	// bounded document.
	reordered := "pins=3:enabled=1:missing=1:replaced=1:canary=active:canary_runs=4:canary_failures=1:events=5:dropped=2"
	if _, err := parseCoreSelfGuardStatus(reordered); err != nil {
		t.Fatalf("reordered valid status rejected: %v", err)
	}
	unavailable := "enabled=0:pins=unavailable:missing=0:replaced=0:canary=unknown:canary_runs=0:canary_failures=0:events=0:dropped=0"
	status, err = parseCoreSelfGuardStatus(unavailable)
	if err != nil {
		t.Fatalf("valid unavailable status rejected: %v", err)
	}
	if status.PinsAvailable || status.PinsExpected != 0 || status.CanaryState != "unknown" {
		t.Fatalf("unavailable status decoded wrong: %+v", status)
	}

	invalid := []string{
		"",
		" ",
		"enabled=1:pins=3:missing=1:replaced=0:canary=active:canary_runs=4:canary_failures=1:events=2",
		valid + ":extra=1",
		"enabled=1:pins=3:missing=1:replaced=0:canary=active:canary_runs=4:canary_failures=1:events=2:dropped=0:",
		"enabled=1:pins=3:missing=1:replaced=0:canary=active:canary_runs=4:canary_failures=1:events=2:dropped",
		"enabled=1:pins=3:missing=1:replaced=0:canary=active:canary_runs=4:canary_failures=1:events=2:unknown=0",
		"enabled=1:pins=3:missing=1:replaced=0:canary=active:canary_runs=4:canary_failures=1:events=2:dropped=0:dropped=0",
		"enabled=2:pins=3:missing=1:replaced=0:canary=active:canary_runs=4:canary_failures=1:events=2:dropped=0",
		"enabled=1:pins=4097:missing=1:replaced=0:canary=active:canary_runs=4:canary_failures=1:events=2:dropped=0",
		"enabled=1:pins=x:missing=1:replaced=0:canary=active:canary_runs=4:canary_failures=1:events=2:dropped=0",
		"enabled=1:pins=-1:missing=1:replaced=0:canary=active:canary_runs=4:canary_failures=1:events=2:dropped=0",
		"enabled=1:pins=3:missing=1:replaced=0:canary=bogus:canary_runs=4:canary_failures=1:events=2:dropped=0",
		"enabled=1:pins=3:missing=3:replaced=1:canary=unknown:canary_runs=0:canary_failures=0:events=2:dropped=0",
		"enabled=1:pins=3:missing=1:replaced=0:canary=unknown:canary_runs=0:canary_failures=0:events=0:dropped=99999999999999999999999",
		"enabled=1:pins=3:missing=1:replaced=0:canary=unknown:canary_runs=0:canary_failures=0:events=4611686018427387905:dropped=0",
		"enabled=1:pins=3:missing=1:replaced=0:canary=unknown:canary_runs=0:canary_failures=0:events=0:dropped=0\x01",
		"\x00" + valid,
		" " + valid,
		valid + " ",
		strings.Repeat("1", maxSelfGuardStatusBytes+1),
	}
	for _, response := range invalid {
		if _, err := parseCoreSelfGuardStatus(response); err == nil {
			t.Fatalf("hostile self-guard status accepted: %.80q", response)
		}
	}
}

func TestCoreSelfGuardEventsParserStrict(t *testing.T) {
	// detail "EXEC_EVENTS" hex-encoded; two record kinds.
	valid := "2|1700000000000:1:1:455845435f4556454e5453,1700000000001:3:4:"
	events, dropped, err := parseCoreSelfTamperEvents(valid)
	if err != nil {
		t.Fatalf("valid self-tamper batch rejected: %v", err)
	}
	if dropped != 2 || len(events) != 2 {
		t.Fatalf("batch parsed to %d events dropped=%d", len(events), dropped)
	}
	if events[0].TsMS != 1700000000000 || events[0].Kind != SelfGuardKindPinMissing ||
		events[0].DetailCode != 1 || events[0].Detail != "EXEC_EVENTS" {
		t.Fatalf("first record decoded wrong: %+v", events[0])
	}
	if events[1].Kind != SelfGuardKindCanaryDead || events[1].DetailCode != 4 || events[1].Detail != "" {
		t.Fatalf("second record decoded wrong: %+v", events[1])
	}
	if events, dropped, err := parseCoreSelfTamperEvents("5|"); err != nil || dropped != 5 || events != nil {
		t.Fatalf("drop-only batch is wrong: dropped=%d err=%v", dropped, err)
	}
	if events, dropped, err := parseCoreSelfTamperEvents("empty"); err != nil || dropped != 0 || events != nil {
		t.Fatalf("empty batch is wrong: %v", err)
	}

	invalid := []string{
		"",
		" ",
		" 0|",
		"x|",
		"0",
		"0| ",
		"0|1700000000000:1:1:455845435f4556454e5453:extra",
		"0|1700000000000:1:1",
		"0|0:1:1:",
		"0|1700000000001:1:2:,1700000000000:1:2:",
		"0|1700000000000:0:1:",
		"0|1700000000000:7:1:",
		"0|1700000000000:1:1:4",  // odd hex
		"0|1700000000000:1:1:00", // decoded NUL control byte
		"0|1700000000000:1:1:" + strings.Repeat("41", maxSelfGuardDetailBytes+1),
		"0|1700000000000:1:1:zz",
		"0|4611686018427387905:1:1:",
		"0|1700000000000:1:4294967296:",
		"0|1700000000000:1:1:\x01",
		"9|" + strings.Repeat("1700000000000:1:1:,", maxSelfGuardEventsPerResponse),
		strings.Repeat("9", maxSelfGuardPayloadBytes+1),
	}
	for _, response := range invalid {
		if events, _, err := parseCoreSelfTamperEvents(response); err == nil || events != nil {
			t.Fatalf("hostile self-tamper batch accepted: %.80q", response)
		}
	}
}

func TestCoreSelfGuardCommandErrorMapping(t *testing.T) {
	if err := mapSelfGuardCommandError(nil); err != nil {
		t.Fatalf("nil error was mapped: %v", err)
	}
	for _, message := range []string{
		"core rejected command: unknown command",
		"core rejected command: unsupported command",
		"Core Rejected Command: UNKNOWN COMMAND",
	} {
		err := mapSelfGuardCommandError(errors.New(message))
		if !errors.Is(err, ErrSelfGuardUnavailable) {
			t.Fatalf("capability rejection %q not mapped: %v", message, err)
		}
	}
	transport := errors.New("dial unix: connection refused")
	mapped := mapSelfGuardCommandError(transport)
	if errors.Is(mapped, ErrSelfGuardUnavailable) || mapped.Error() != transport.Error() {
		t.Fatalf("transport error was reclassified as a capability fact: %v", mapped)
	}
}

func TestCoreSelfGuardSetResponseStrict(t *testing.T) {
	if err := parseCoreSelfGuardSetResponse(true, "armed"); err != nil {
		t.Fatalf("valid armed answer rejected: %v", err)
	}
	if err := parseCoreSelfGuardSetResponse(false, "disarmed"); err != nil {
		t.Fatalf("valid disarmed answer rejected: %v", err)
	}
	for _, testCase := range []struct {
		enabled  bool
		response string
	}{
		{true, "disarmed"},
		{false, "armed"},
		{true, ""},
		{true, "ok"},
		{true, "armed "},
		{true, "ARMED"},
	} {
		if err := parseCoreSelfGuardSetResponse(testCase.enabled, testCase.response); err == nil {
			t.Fatalf("hostile self-guard set answer accepted: enabled=%v response=%q", testCase.enabled, testCase.response)
		}
	}
}

func FuzzCoreSelfGuardParser(f *testing.F) {
	seeds := []string{
		"enabled=1:pins=3:missing=1:replaced=1:canary=active:canary_runs=4:canary_failures=1:events=5:dropped=2",
		"enabled=0:pins=unavailable:missing=0:replaced=0:canary=unknown:canary_runs=0:canary_failures=0:events=0:dropped=0",
		"2|1700000000000:1:1:455845435f4556454e5453,1700000000001:3:4:",
		"5|",
		"empty",
		"",
		"0|",
		"0|1700000000000:6:9:",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, response string) {
		status, statusErr := parseCoreSelfGuardStatus(response)
		if statusErr == nil {
			if status.Enabled != status.Armed {
				t.Fatalf("enabled/armed projection diverged: %+v", status)
			}
			if status.PinsExpected > maxSelfGuardPins {
				t.Fatalf("pin count above the ceiling: %+v", status)
			}
			if status.PinsMissing > status.Events || status.PinsReplaced > status.Events ||
				status.PinsMissing+status.PinsReplaced > status.Events {
				t.Fatalf("pin facts exceed the record counter: %+v", status)
			}
			switch status.CanaryState {
			case "active", "degraded", "unknown":
			default:
				t.Fatalf("unknown canary state accepted: %+v", status)
			}
		}
		events, dropped, err := parseCoreSelfTamperEvents(response)
		if err != nil {
			return
		}
		if len(events) > maxSelfGuardEventsPerResponse {
			t.Fatalf("accepted %d records", len(events))
		}
		if dropped > maxSelfGuardCounter {
			t.Fatalf("accepted drop counter %d", dropped)
		}
		var previous uint64
		for _, event := range events {
			if event.TsMS == 0 || event.TsMS > maxSelfGuardCounter {
				t.Fatalf("accepted timestamp %d", event.TsMS)
			}
			if event.Kind < SelfGuardKindPinMissing || event.Kind > SelfGuardKindCanaryRecovered {
				t.Fatalf("accepted kind %d", event.Kind)
			}
			if len(event.Detail) > maxSelfGuardDetailBytes {
				t.Fatalf("accepted detail of %d bytes", len(event.Detail))
			}
			for index := 0; index < len(event.Detail); index++ {
				character := event.Detail[index]
				if character < 0x20 || character > 0x7e {
					t.Fatalf("accepted control character in detail: %q", event.Detail)
				}
			}
			if event.TsMS < previous {
				t.Fatalf("accepted out-of-order record")
			}
			previous = event.TsMS
		}
	})
}
