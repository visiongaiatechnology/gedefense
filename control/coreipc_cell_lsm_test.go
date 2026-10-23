// STATUS: DIAMANT VGT SUPREME
package main

import "testing"

func TestParseCoreCellLSMDenyEventsUsesStrictBounds(t *testing.T) {
	events, err := parseCoreCellLSMDenyEvents("99123:1482:1000:2,99124:1483:1001:10")
	if err != nil {
		t.Fatalf("parse valid Cell LSM events: %v", err)
	}
	if len(events) != 2 || events[0].CgroupID != 99123 || events[0].PID != 1482 ||
		events[0].UID != 1000 || events[0].Family != 2 || events[1].Family != 10 {
		t.Fatalf("unexpected Cell LSM events: %#v", events)
	}

	for _, malicious := range []string{
		"0:1:1000:2",
		"42:0:1000:2",
		"42:1:1000:1",
		"42:1:1000:256",
		"42:1:1000:-1",
		"42:1:1000",
		"42:1:1000:2:extra",
	} {
		if _, err := parseCoreCellLSMDenyEvents(malicious); err == nil {
			t.Fatalf("accepted malformed Cell LSM event %q", malicious)
		}
	}
}

func TestCoreCellPolicyRejectsInvalidIdentityBeforeTransport(t *testing.T) {
	client := &CoreClient{}
	if err := client.CellPolicySet(0, cellLSMDenyNonUnixSocket); err == nil {
		t.Fatal("accepted zero cgroup identity")
	}
	if err := client.CellPolicySet(42, 0); err == nil {
		t.Fatal("accepted empty Cell LSM flags")
	}
	if err := client.CellPolicyDelete(0); err == nil {
		t.Fatal("accepted zero cgroup identity for deletion")
	}
}
