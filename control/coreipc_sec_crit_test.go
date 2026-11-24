// STATUS: V6.3.0 AP-9 (S12)
package main

// V6.3.0 AP-9 (S12) transport tests: the strict all-or-nothing decoder of the
// independent high-priority security evidence ring (`SEC_CRIT_*`), its closed
// source/kind/action sets and source-specific payload invariants, the capability
// mapping of a pre-6.3 core, and the fuzz target. No socket and no kernel are
// involved: every record is parsed from its documented text wire.

import (
	"errors"
	"strings"
	"testing"
)

func secCritValidStatus() string {
	return "enabled=1:events=17:drops=0:refused_unarmed=2:read_failures=1:suppressed=9:bucket_capacity=4096"
}

// secCritCredRecord is a valid credential-deny record (source 1).
func secCritCredRecord() string {
	return "1700000000000000000:1:1:2:33188:4242:4242:0:8:123456:66616b655f73736864:0000000000000000"
}

// secCritBpfRecord is a valid helper-risk record (source 2, mask 0b101).
func secCritBpfRecord() string {
	return "1700000000000000001:2:1:1:5:5150:5150:1000:0:0:726f6f746b6974:0000000000000000"
}

// secCritLkmRecord is a valid LKM-load record (source 3, taints in extra).
func secCritLkmRecord() string {
	return "1700000000000000002:3:1:1:0:616:616:0:0:0:6d6f64756c65:0100000041626364"
}

// secCritPersistenceRecord is a valid critical persistence record
// (source 7, class 3 LD_SO << 8 | kind 2 library mmap).
func secCritPersistenceRecord() string {
	return "1700000000000000003:7:1:1:770:777:777:1000:8:999:6c6962782e736f:2a00000000000000"
}

func TestSecCritStatusParserAcceptsDocumentedWire(t *testing.T) {
	status, err := parseCoreSecCritStatus(secCritValidStatus())
	if err != nil {
		t.Fatalf("valid status rejected: %v", err)
	}
	if !status.Enabled || status.Events != 17 || status.RefusedUnarmed != 2 ||
		status.ReadFailures != 1 || status.Suppressed != 9 || status.BucketCapacity != 4096 {
		t.Fatalf("status fields decoded incorrectly: %+v", status)
	}
	disarmed := "enabled=0:events=0:drops=0:refused_unarmed=0:read_failures=0:suppressed=0:bucket_capacity=0"
	if status, err := parseCoreSecCritStatus(disarmed); err != nil || status.Enabled {
		t.Fatalf("disarmed status rejected or mis-decoded: %+v err=%v", status, err)
	}
}

func TestSecCritStatusParserRejectsMalformedWire(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"leading space":  " " + secCritValidStatus(),
		"trailing space": secCritValidStatus() + " ",
		"nul byte":       "enabled=1\x00:events=0:drops=0:refused_unarmed=0:read_failures=0:suppressed=0:bucket_capacity=0",
		"unknown field":  "armed=1:events=0:drops=0:refused_unarmed=0:read_failures=0:suppressed=0:bucket_capacity=0",
		"reordered":      "events=0:enabled=1:drops=0:refused_unarmed=0:read_failures=0:suppressed=0:bucket_capacity=0",
		"missing field":  "enabled=1:events=0:drops=0:refused_unarmed=0:read_failures=0:suppressed=0",
		"extra field":    secCritValidStatus() + ":extra=1",
		"enabled flag":   "enabled=2:events=0:drops=0:refused_unarmed=0:read_failures=0:suppressed=0:bucket_capacity=0",
		"negative":       "enabled=1:events=-1:drops=0:refused_unarmed=0:read_failures=0:suppressed=0:bucket_capacity=0",
		"non decimal":    "enabled=1:events=0x10:drops=0:refused_unarmed=0:read_failures=0:suppressed=0:bucket_capacity=0",
		"empty value":    "enabled=:events=0:drops=0:refused_unarmed=0:read_failures=0:suppressed=0:bucket_capacity=0",
		"oversized":      "enabled=1:events=99999999999999999999999999:drops=0:refused_unarmed=0:read_failures=0:suppressed=0:bucket_capacity=0",
	}
	oversized := secCritValidStatus() + strings.Repeat("0", maxSecCritStatusBytes)
	for name, wire := range cases {
		if _, err := parseCoreSecCritStatus(wire); err == nil {
			t.Fatalf("%s status was accepted: %q", name, wire)
		}
	}
	if _, err := parseCoreSecCritStatus(oversized); err == nil {
		t.Fatal("oversized status was accepted")
	}
}

func TestSecCritEventsParserAcceptsDocumentedBatch(t *testing.T) {
	batch := "3|" + strings.Join([]string{
		secCritCredRecord(), secCritBpfRecord(), secCritLkmRecord(), secCritPersistenceRecord(),
	}, ",")
	events, dropped, err := parseCoreSecCritEvents(batch)
	if err != nil {
		t.Fatalf("valid batch rejected: %v", err)
	}
	if dropped != 3 || len(events) != 4 {
		t.Fatalf("batch decoded incorrectly: dropped=%d events=%d", dropped, len(events))
	}
	wantSources := []uint8{SecCritSourceCredGuard, SecCritSourceBpfGuard, SecCritSourceKernelHooks, SecCritSourcePersistence}
	for index, event := range events {
		if event.Source != wantSources[index] {
			t.Fatalf("event %d has source %d, want %d", index, event.Source, wantSources[index])
		}
		if event.Comm == "" || event.PID <= 0 || event.TGID <= 0 || event.TsNS == 0 {
			t.Fatalf("event %d lost identity fields: %+v", index, event)
		}
	}
	if events[0].Action != SecCritActionEnforce || events[0].Comm != "fake_sshd" {
		t.Fatalf("credential-deny decode mismatch: %+v", events[0])
	}
	if events[1].DetailCode != 5 || events[1].Comm != "rootkit" {
		t.Fatalf("bpf-guard decode mismatch: %+v", events[1])
	}
	if events[2].Extra != "0100000041626364" {
		t.Fatalf("lkm extra mismatch: %+v", events[2])
	}
	if events[3].DetailCode>>8 != 3 { // PERSIST_CLASS_LD_SO
		t.Fatalf("persistence class mismatch: %d", events[3].DetailCode>>8)
	}
	// Real-kernel ABI pin: the exact record produced by the WSL2 root smoke of
	// `gedefense_check_helper_call` (source 2, helper mask 1, comm =
	// "sec_crit::tests") must parse unchanged across the Go/Rust boundary.
	realRecord := "0|691074036194:2:1:1:1:15754:15753:0:0:0:7365635f637269743a3a7465737473:0000000000000000"
	realEvents, realDropped, err := parseCoreSecCritEvents(realRecord)
	if err != nil || realDropped != 0 || len(realEvents) != 1 {
		t.Fatalf("real-kernel smoke record rejected: %v", err)
	}
	if realEvents[0].Source != SecCritSourceBpfGuard || realEvents[0].Action != SecCritActionObserve ||
		realEvents[0].DetailCode != 1 || realEvents[0].PID != 15754 || realEvents[0].TGID != 15753 ||
		realEvents[0].Comm != "sec_crit::tests" {
		t.Fatalf("real-kernel smoke record decoded incorrectly: %+v", realEvents[0])
	}
	// "empty" and a drop-only answer are valid (no records).
	if events, dropped, err := parseCoreSecCritEvents("empty"); err != nil || len(events) != 0 || dropped != 0 {
		t.Fatalf("empty batch rejected: %v", err)
	}
	if events, dropped, err := parseCoreSecCritEvents("4|"); err != nil || len(events) != 0 || dropped != 4 {
		t.Fatalf("drop-only batch rejected: %v", err)
	}
}

func TestSecCritEventsParserRejectsMalformedBatch(t *testing.T) {
	record := secCritCredRecord()
	fields := strings.Split(record, ":")
	withField := func(index int, value string) string {
		copied := append([]string(nil), fields...)
		copied[index] = value
		return strings.Join(copied, ":")
	}
	bpfFields := strings.Split(secCritBpfRecord(), ":")
	bpfWithField := func(index int, value string) string {
		copied := append([]string(nil), bpfFields...)
		copied[index] = value
		return strings.Join(copied, ":")
	}
	lkmFields := strings.Split(secCritLkmRecord(), ":")
	lkmWithField := func(index int, value string) string {
		copied := append([]string(nil), lkmFields...)
		copied[index] = value
		return strings.Join(copied, ":")
	}
	persistFields := strings.Split(secCritPersistenceRecord(), ":")
	persistWithField := func(index int, value string) string {
		copied := append([]string(nil), persistFields...)
		copied[index] = value
		return strings.Join(copied, ":")
	}
	records := map[string]string{
		"empty payload":            "",
		"no drop prefix":           record,
		"bad drop counter":         "x|" + record,
		"too many records":         "0|" + strings.Repeat(record+",", maxSecCritEventsPerResponse) + record,
		"short record":             "0|" + record[:len(record)-2],
		"field count":              "0|" + withField(0, "1:2"),
		"zero timestamp":           "0|" + withField(0, "0"),
		"zero pid":                 "0|" + withField(5, "0"),
		"zero tgid":                "0|" + withField(6, "0"),
		"unknown source":           "0|" + withField(1, "8"),
		"zero source":              "0|" + withField(1, "0"),
		"unknown kind":             "0|" + withField(2, "2"),
		"zero kind":                "0|" + withField(2, "0"),
		"unknown action":           "0|" + withField(3, "3"),
		"zero action":              "0|" + withField(3, "0"),
		"bad comm hex":             "0|" + withField(10, "zz"),
		"odd comm hex":             "0|" + withField(10, "abc"),
		"empty comm":               "0|" + withField(10, ""),
		"non printable comm":       "0|" + withField(10, "01"),
		"oversized comm":           "0|" + withField(10, strings.Repeat("61", maxSecCritCommBytes+1)),
		"bad extra hex":            "0|" + withField(11, "zz"),
		"oversized extra":          "0|" + withField(11, strings.Repeat("00", maxSecCritExtraBytes+1)),
		"credential observe":       "0|" + withField(3, "1"),
		"credential without dev":   "0|" + withField(8, "0"),
		"credential nonzero extra": "0|" + withField(11, "0100000000000000"),
		"bpf no mask":              "0|" + bpfWithField(4, "0"),
		"bpf unknown mask":         "0|" + bpfWithField(4, "8"),
		"bpf wrong action":         "0|" + bpfWithField(3, "2"),
		"bpf dev set":              "0|" + bpfWithField(8, "8"),
		"lkm missing extra":        "0|" + lkmWithField(11, "00"),
		"lkm dev set":              "0|" + lkmWithField(8, "8"),
		"persist unknown class":    "0|" + persistWithField(4, "3074"), // class 12
		"persist unknown kind":     "0|" + persistWithField(4, "771"),  // kind 3
		"persist zero ino":         "0|" + persistWithField(9, "0"),
		"partial identity":         "0|" + withField(9, "0"),
	}
	for name, response := range records {
		if _, _, err := parseCoreSecCritEvents(response); err == nil {
			t.Fatalf("%s batch was accepted: %q", name, response)
		}
	}
	oversized := "0|" + secCritCredRecord() + strings.Repeat("0", maxSecCritPayloadBytes)
	if _, _, err := parseCoreSecCritEvents(oversized); err == nil {
		t.Fatal("oversized batch was accepted")
	}
	for _, wire := range []string{" ", secCritCredRecord() + " ", "0|" + record + "\x00"} {
		if _, _, err := parseCoreSecCritEvents(wire); err == nil {
			t.Fatalf("malformed batch was accepted: %q", wire)
		}
	}
	// All-or-nothing: one valid record followed by one invalid record rejects
	// the whole batch (never a partial ingest).
	if _, _, err := parseCoreSecCritEvents("0|" + secCritCredRecord() + "," + withField(1, "8")); err == nil {
		t.Fatal("partially valid batch was accepted")
	}
}

func TestSecCritUnavailableIsCapabilityFact(t *testing.T) {
	mapped := mapSecCritCommandError(errors.New("core rejected command: unknown command"))
	if !errors.Is(mapped, ErrSecCritUnavailable) {
		t.Fatalf("unknown-command error is not the capability sentinel: %v", mapped)
	}
	mapped = mapSecCritCommandError(errors.New("core rejected command: unsupported command"))
	if !errors.Is(mapped, ErrSecCritUnavailable) {
		t.Fatalf("unsupported-command error is not the capability sentinel: %v", mapped)
	}
	transport := errors.New("write unix /run/vgt-gedefense/core.sock: broken pipe")
	if mapped := mapSecCritCommandError(transport); errors.Is(mapped, ErrSecCritUnavailable) {
		t.Fatalf("transport error was wrongly classified as a capability fact: %v", mapped)
	}
	if mapped := mapSecCritCommandError(nil); mapped != nil {
		t.Fatalf("nil error mapped to %v", mapped)
	}
}

// FuzzCoreSecCritParser fuzzes the strict S12 parsers. Invariants: never panic,
// never return more than the documented record/drain bounds, and any accepted
// status keeps the documented invariants (enabled flag binary).
func FuzzCoreSecCritParser(f *testing.F) {
	seeds := []string{
		secCritValidStatus(),
		"empty",
		"3|" + secCritCredRecord() + "," + secCritBpfRecord(),
		"0|" + secCritLkmRecord() + "," + secCritPersistenceRecord(),
		"4|",
		"0|" + secCritCredRecord() + ",garbage",
		"enabled=0:events=0:drops=0:refused_unarmed=0:read_failures=0:suppressed=0:bucket_capacity=0",
		"",
		"\x00\x01\x02",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		events, dropped, err := parseCoreSecCritEvents(input)
		if err == nil {
			if len(events) > maxSecCritEventsPerResponse {
				t.Fatalf("accepted %d records (bound %d)", len(events), maxSecCritEventsPerResponse)
			}
			if dropped > 1<<63 {
				t.Fatalf("accepted an implausible drop counter %d", dropped)
			}
			for _, event := range events {
				if event.Source == 0 || event.Source > SecCritSourceMax {
					t.Fatalf("accepted an out-of-range source %d", event.Source)
				}
				if event.Kind == 0 || event.Kind > SecCritKindMax {
					t.Fatalf("accepted an out-of-range kind %d", event.Kind)
				}
				if event.Action == 0 || event.Action > SecCritActionMax {
					t.Fatalf("accepted an out-of-range action %d", event.Action)
				}
				if event.Comm == "" || event.PID <= 0 || event.TGID <= 0 || event.TsNS == 0 {
					t.Fatalf("accepted an event without identity: %+v", event)
				}
			}
		}
		if status, statusErr := parseCoreSecCritStatus(input); statusErr == nil {
			// An accepted status is always internally well formed; the enabled
			// flag is binary by construction of the parser.
			if status.Enabled && status.BucketCapacity > 1<<32 {
				t.Fatalf("accepted an implausible bucket capacity: %+v", status)
			}
		}
		if _, err := parseCoreSecCritEvent(input); err != nil {
			// Rejection is the expected default for arbitrary input; the only
			// invariant is that it never panics (and that a rejected input is
			// never silently reported as valid).
			_ = err
		}
	})
}
