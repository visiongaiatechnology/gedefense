// V6.3.0 AP-1 regression tests: strict executable-inode core IPC parsers and
// the fuzz target for the two text codecs. No socket is involved; every parser
// is exercised with synthetic core answers.

package main

import (
	"strings"
	"testing"
)

func TestCoreExecInodeStatusBoundedAndStrict(t *testing.T) {
	status, err := parseCoreExecInodeStatus(
		"enabled=1:offsets=1:trusted=4:missing=2:allowed=10:denied=3:events=13:drops=0:fallbacks=1:locks=2:expired=1")
	if err != nil {
		t.Fatalf("valid exec-inode status rejected: %v", err)
	}
	if !status.Enabled || !status.OffsetsOK || status.Trusted != 4 || status.Missing != 2 ||
		status.Allowed != 10 || status.Denied != 3 || status.Events != 13 ||
		status.Fallbacks != 1 || status.MalwareLocks != 2 || status.ExpiredLocks != 1 {
		t.Fatalf("status decoded wrong: %+v", status)
	}
	disarmed, err := parseCoreExecInodeStatus(
		"enabled=0:offsets=0:trusted=12:missing=1:allowed=0:denied=0:events=0:drops=0:fallbacks=0:locks=0:expired=0")
	if err != nil {
		t.Fatalf("disarmed exec-inode status rejected: %v", err)
	}
	if disarmed.Enabled || disarmed.OffsetsOK || disarmed.Trusted != 12 {
		t.Fatalf("disarmed status decoded wrong: %+v", disarmed)
	}
	invalid := []string{
		"",
		"  enabled=1:offsets=1:trusted=4:missing=2:allowed=10:denied=3:events=13:drops=0:fallbacks=1:locks=2:expired=1",
		"enabled=1:offsets=1:trusted=4:missing=2:allowed=10:denied=3:events=13:drops=0:fallbacks=1:locks=2",
		"enabled=1:offsets=1:trusted=4:missing=2:allowed=10:denied=3:events=13:drops=0:fallbacks=1:locks=2:expired=0:extra=1",
		"enabled=2:offsets=1:trusted=4:missing=2:allowed=10:denied=3:events=13:drops=0:fallbacks=1:locks=2:expired=0",
		"enabled=1:offsets=9:trusted=4:missing=2:allowed=10:denied=3:events=13:drops=0:fallbacks=1:locks=2:expired=0",
		"enabled=1:offset=1:trusted=4:missing=2:allowed=10:denied=3:events=13:drops=0:fallbacks=1:locks=2:expired=0",
		"enabled=1:offsets=1:trusted=-1:missing=2:allowed=10:denied=3:events=13:drops=0:fallbacks=1:locks=2:expired=0",
		"enabled=1:offsets=1:trusted=4:missing=2:allowed=10:denied=3:events=13:drops=0:fallbacks=1:locks=2:expired=0x1",
		strings.Repeat("enabled=1:", maxExecInodeStatusBytes),
	}
	for _, response := range invalid {
		if _, err := parseCoreExecInodeStatus(response); err == nil {
			t.Fatalf("hostile exec-inode status accepted: %.80q", response)
		}
	}
}

func TestCoreExecInodeEventsBoundedAndStrict(t *testing.T) {
	valid := "2|1700000000000000000:4242:4242:1000:8:123456:1:1:73736864," +
		"1700000000000000001:77:77:0:2049:99:0:3:6375726c"
	events, dropped, err := parseCoreExecInodeEvents(valid)
	if err != nil {
		t.Fatalf("valid exec-inode batch rejected: %v", err)
	}
	if dropped != 2 || len(events) != 2 {
		t.Fatalf("batch parsed to %d events dropped=%d", len(events), dropped)
	}
	if events[0].PID != 4242 || events[0].TGID != 4242 || events[0].ExeDev != 8 ||
		events[0].ExeIno != 123456 || events[0].TrustFlags != 1 ||
		events[0].Action != ExecInodeActionObservedMismatch || events[0].Comm != "sshd" {
		t.Fatalf("mismatch event decoded wrong: %+v", events[0])
	}
	if events[1].Action != ExecInodeActionFallbackComm || events[1].ExeDev != 2049 ||
		events[1].ExeIno != 99 || events[1].Comm != "curl" {
		t.Fatalf("fallback event decoded wrong: %+v", events[1])
	}
	if events, dropped, err := parseCoreExecInodeEvents("5|"); err != nil || dropped != 5 || events != nil {
		t.Fatalf("drop-only batch is wrong: dropped=%d err=%v", dropped, err)
	}
	if events, _, err := parseCoreExecInodeEvents("empty"); err != nil || events != nil {
		t.Fatalf("empty batch is wrong: %v", err)
	}
	invalid := []string{
		"", " 0|", "x|", "0",
		"0|1700000000000000000:4242:4242:1000:8:123456:1:1",                // missing comm
		"0|1700000000000000000:4242:4242:1000:8:123456:1:1:73736864:extra", // extra field
		"0|0:4242:4242:1000:8:123456:1:1:73736864",                         // zero ts
		"0|1700000000000000000:0:4242:1000:8:123456:1:1:73736864",          // zero pid
		"0|1700000000000000000:4242:4242:1000:8:123456:1:4:73736864",       // unknown action
		"0|1700000000000000000:4242:4242:1000:0:123456:1:2:73736864",       // deny without dev
		"0|1700000000000000000:4242:4242:1000:8:0:1:2:73736864",            // deny without ino
		"0|1700000000000000000:4242:4242:1000:8:123456:8:1:73736864",       // undefined flag bit
		"0|1700000000000000000:4242:4242:1000:8:123456:1:1:7",              // odd comm hex
		"0|1700000000000000000:4242:4242:1000:8:123456:1:1:00",             // NUL comm
		"0|1700000000000000000:4242:4242:1000:8:123456:1:1:",               // empty comm
		"0|" + strings.Repeat("4", maxExecInodePayloadBytes),               // oversized batch
	}
	for _, response := range invalid {
		if events, _, err := parseCoreExecInodeEvents(response); err == nil || events != nil {
			t.Fatalf("hostile exec-inode batch accepted: %.80q", response)
		}
	}
	tooMany := "0|" + strings.TrimSuffix(strings.Repeat(
		"1:1:1:0:8:9:0:2:7373,", maxExecInodeEventsPerResponse+1), ",")
	if _, _, err := parseCoreExecInodeEvents(tooMany); err == nil {
		t.Fatal("a batch above the exec-inode ceiling was accepted")
	}
	oversized := "0|" + strings.Repeat("A", maxExecInodeRecordBytes+1)
	if _, _, err := parseCoreExecInodeEvents(oversized); err == nil {
		t.Fatal("an oversized exec-inode record was accepted")
	}
}

// FuzzCoreExecInodeParser fuzzes both AP-1 text codecs. Every input must either
// be rejected or decode into a record that satisfies the documented producer
// contract; the parsers must never panic or allocate unboundedly.
func FuzzCoreExecInodeParser(f *testing.F) {
	seeds := []string{
		"enabled=1:offsets=1:trusted=4:missing=2:allowed=10:denied=3:events=13:drops=0:fallbacks=1:locks=2:expired=1",
		"enabled=0:offsets=0:trusted=0:missing=0:allowed=0:denied=0:events=0:drops=0:fallbacks=0:locks=0:expired=0",
		"",
		"0|1700000000000000000:4242:4242:1000:8:123456:1:1:73736864",
		"0|1700000000000000000:4242:4242:1000:8:123456:0:2:73736864",
		"1|1700000000000000000:77:77:0:0:0:0:3:6375726c",
		"empty",
		"0",
		"0|",
		"5|1:2",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, response string) {
		// Both codecs must either reject the input or return a record that
		// satisfies the documented producer contract; no panics, no unbounded
		// records.
		_, _ = parseCoreExecInodeStatus(response)
		events, dropped, err := parseCoreExecInodeEvents(response)
		if err != nil {
			if events != nil {
				t.Fatalf("rejected batch returned events")
			}
			return
		}
		if len(events) > maxExecInodeEventsPerResponse {
			t.Fatalf("parser returned %d events above the ceiling", len(events))
		}
		if dropped > 1<<40 {
			t.Fatalf("impossible drop counter %d", dropped)
		}
		for _, event := range events {
			if event.TsNS == 0 || event.PID <= 0 || event.TGID <= 0 || event.Comm == "" {
				t.Fatalf("decoded event violates the producer contract: %+v", event)
			}
			if event.Action < ExecInodeActionObservedMismatch || event.Action > ExecInodeActionFallbackComm {
				t.Fatalf("decoded event has an unknown action: %+v", event)
			}
			if event.TrustFlags&^uint32(ExecInodeAllowAll) != 0 {
				t.Fatalf("decoded event has undefined flags: %+v", event)
			}
		}
	})
}
