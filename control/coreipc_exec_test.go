// STATUS: DIAMANT VGT SUPREME
package main

import "testing"

func TestParseCoreExecEventsUsesStrictBounds(t *testing.T) {
	events, err := parseCoreExecEvents("1482:1000:1000:66697265666f78")
	if err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	if len(events) != 1 || events[0].PID != 1482 || events[0].UID != 1000 ||
		events[0].GID != 1000 || events[0].Comm != "firefox" {
		t.Fatalf("unexpected decoded event: %#v", events)
	}
	for _, malicious := range []string{
		"0:0:0:726f6f74",
		"1:0:0:00",
		"1:0:0:zz",
		"1:0:0:4141414141414141414141414141414141",
		"1:0:0:61:extra",
	} {
		if _, err := parseCoreExecEvents(malicious); err == nil {
			t.Fatalf("malformed event accepted: %q", malicious)
		}
	}
}
