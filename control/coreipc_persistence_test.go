// V6.3.0 AP-5 regression tests: bounded PERSIST_GUARD_* transport parsers
// (status, baseline, event text wire) and the fuzz target. No socket is
// involved; every parser is exercised with synthetic core answers. Every
// accepted record must satisfy the closed class/kind/action/identity contract;
// every rejected answer must be all-or-nothing.

package main

import (
	"strings"
	"testing"
)

const (
	persistenceValidStatus = "enabled=1:attached=2047:paths=12:execs=2:devices=3:secrets=4:" +
		"pkgdb=dpkg:roots=5:drifted=1:baseline_at_ms=1700000000000:events=7:drops=2:" +
		"sessions=3/2/1:idlehint=unavailable"

	persistenceValidIntegrity = "1700000000000000000:4242:4242:1000:1:1:1:1:8:123456:62617368:"
	persistenceValidMmap      = "1700000000000000001:4242:4242:1000:3:2:1:5:2049:99:73736864:"
	persistenceValidDevice    = "1700000000000000002:4242:4242:1000:20:3:1:3:8:777:7069706577697265:"
	persistenceValidSecret    = "1700000000000000003:4242:4242:1000:30:4:1:1000:8:888:62617368:"
	persistenceValidScrape    = "1700000000000000004:4242:4242:1000:0:5:1:1234:0:0:62617368:7265616476"
	persistenceValidPtrace    = "1700000000000000005:4242:4242:1000:0:6:1:1234:0:0:676462:33"
	persistenceValidDrift     = "1700000000000000006:4242:4242:0:6:7:1:1:8:42:6765646566656e73652d636f7265:"
	persistenceValidBaseline  = "1700000000000000007:99:99:0:0:8:1:5:0:0:6765646566656e73652d636f7265:"
)

func TestCorePersistenceStatusBoundedAndStrict(t *testing.T) {
	status, err := parseCorePersistenceStatus(persistenceValidStatus)
	if err != nil {
		t.Fatalf("valid persistence status rejected: %v", err)
	}
	if !status.Enabled || !status.Attached || !status.HookFileOpen || !status.HookMmap ||
		!status.HookPtrace || !status.HookReadv || !status.HookWritev ||
		!status.IdentityOffsetsOK || !status.PkgdbReady || !status.ReadvOffsetsOK ||
		!status.WritevOffsetsOK || !status.ReadFailuresSeen || !status.SessionsKnown {
		t.Fatalf("persistence status flags decoded wrong: %+v", status)
	}
	if status.Paths != 12 || status.Execs != 2 || status.Devices != 3 || status.Secrets != 4 ||
		status.Pkgdb != "dpkg" || status.Roots != 5 || status.Drifted != 1 ||
		status.BaselineAtMS != 1700000000000 || status.Events != 7 || status.Drops != 2 ||
		status.SessionsTotal != 3 || status.SessionsActive != 2 || status.SessionsInactive != 1 ||
		status.IdleHint != "unavailable" {
		t.Fatalf("persistence status counters decoded wrong: %+v", status)
	}
	disarmed, err := parseCorePersistenceStatus(
		"enabled=0:attached=0:paths=0:execs=0:devices=0:secrets=0:pkgdb=unsupported:roots=0:" +
			"drifted=0:baseline_at_ms=0:events=0:drops=0:sessions=0/0/0:idlehint=unavailable")
	if err != nil || disarmed.Enabled || disarmed.Attached {
		t.Fatalf("disarmed persistence status decoded wrong: %+v err=%v", disarmed, err)
	}
	invalid := []string{
		"",
		"enabled=1:attached=1",
		" attached=1:enabled=1:paths=12:execs=2:devices=3:secrets=4:pkgdb=dpkg:roots=5:drifted=1:" +
			"baseline_at_ms=1:events=7:drops=2:sessions=3/2/1:idlehint=unavailable",
		"enabled=2:attached=2047:paths=12:execs=2:devices=3:secrets=4:pkgdb=dpkg:roots=5:drifted=1:" +
			"baseline_at_ms=1:events=7:drops=2:sessions=3/2/1:idlehint=unavailable",
		"enabled=1:attached=4096:paths=12:execs=2:devices=3:secrets=4:pkgdb=dpkg:roots=5:drifted=1:" +
			"baseline_at_ms=1:events=7:drops=2:sessions=3/2/1:idlehint=unavailable",
		"enabled=1:attached=2047:paths=12:execs=2:devices=3:secrets=4:pkgdb=rpm:roots=5:drifted=1:" +
			"baseline_at_ms=1:events=7:drops=2:sessions=3/2/1:idlehint=unavailable",
		"enabled=1:attached=2047:paths=12:execs=2:devices=3:secrets=4:pkgdb=dpkg:roots=5:drifted=1:" +
			"baseline_at_ms=1:events=7:drops=2:sessions=2/2/1:idlehint=unavailable",
		"enabled=1:attached=2047:paths=12:execs=2:devices=3:secrets=4:pkgdb=dpkg:roots=5:drifted=1:" +
			"baseline_at_ms=1:events=7:drops=2:sessions=3/2/1:idlehint=available",
		"enabled=1:attached=2047:paths=12:execs=2:devices=3:secrets=4:pkgdb=dpkg:roots=5:drifted=1:" +
			"baseline_at_ms=1:events=7:drops=2:sessions=3/2/1:idlehint=unavailable:extra=1",
		strings.Repeat("enabled=1:", maxPersistenceStatusBytes),
	}
	for _, response := range invalid {
		if _, err := parseCorePersistenceStatus(response); err == nil {
			t.Fatalf("hostile persistence status accepted: %.80q", response)
		}
	}
}

func TestCorePersistenceBaselineStrict(t *testing.T) {
	baseline, err := parsePersistenceBaseline("roots=5:verified=5:drifted=1:at_ms=1700000000000")
	if err != nil {
		t.Fatalf("valid persistence baseline rejected: %v", err)
	}
	if baseline.Roots != 5 || baseline.Verified != 5 || baseline.Drifted != 1 || baseline.AtMS != 1700000000000 {
		t.Fatalf("persistence baseline decoded wrong: %+v", baseline)
	}
	for _, response := range []string{
		"", "roots=5", "roots=5:verified=5:drifted=1",
		"roots=5:verified=5:drifted=1:at_ms=1:extra=2",
		"at_ms=1:drifted=1:verified=5:roots=5",
		"roots=x:verified=5:drifted=1:at_ms=1",
		"roots=5:verified=5:drifted=1:at_ms=1\n",
	} {
		if _, err := parsePersistenceBaseline(response); err == nil {
			t.Fatalf("hostile persistence baseline accepted: %q", response)
		}
	}
}

func TestCorePersistenceEventsBoundedAndStrict(t *testing.T) {
	batch := "2|" + strings.Join([]string{
		persistenceValidIntegrity,
		persistenceValidMmap,
		persistenceValidDevice,
		persistenceValidSecret,
		persistenceValidScrape,
		persistenceValidPtrace,
		persistenceValidDrift,
		persistenceValidBaseline,
	}, ",")
	events, dropped, err := parseCorePersistenceEvents(batch)
	if err != nil {
		t.Fatalf("valid persistence batch rejected: %v", err)
	}
	if dropped != 2 || len(events) != 8 {
		t.Fatalf("batch parsed to %d events dropped=%d", len(events), dropped)
	}
	if events[0].Kind != PersistenceKindIntegrityWrite || events[0].Class != PersistenceClassLDPreload ||
		events[0].DetailCode != 1 || events[0].Comm != "bash" || events[0].Ino != 123456 {
		t.Fatalf("integrity event decoded wrong: %+v", events[0])
	}
	if events[1].Kind != PersistenceKindLibraryMmap || events[1].Class != PersistenceClassLDSO ||
		events[1].DetailCode != 5 || events[1].Comm != "sshd" {
		t.Fatalf("mmap event decoded wrong: %+v", events[1])
	}
	if events[2].DetailCode != PersistenceDetailSessionKnown|PersistenceDetailSessionActive ||
		events[2].Class != PersistenceClassDeviceCamera || events[2].Comm != "pipewire" {
		t.Fatalf("device event decoded wrong: %+v", events[2])
	}
	if events[3].Kind != PersistenceKindSecretOpen || events[3].DetailCode != 1000 ||
		events[3].Class != PersistenceClassSecretSSH {
		t.Fatalf("secret event decoded wrong: %+v", events[3])
	}
	if events[4].Detail != "readv" || events[4].DetailCode != 1234 || events[4].Dev != 0 {
		t.Fatalf("scrape event decoded wrong: %+v", events[4])
	}
	if events[5].Detail != "3" || events[5].Kind != PersistenceKindPtraceAccess {
		t.Fatalf("ptrace event decoded wrong: %+v", events[5])
	}
	if events[6].Kind != PersistenceKindDrift || events[6].DetailCode != PersistenceDriftContent ||
		events[6].Class != PersistenceClassSystemdGenerator {
		t.Fatalf("drift event decoded wrong: %+v", events[6])
	}
	if events[7].Kind != PersistenceKindBaseline || events[7].DetailCode != 5 {
		t.Fatalf("baseline marker decoded wrong: %+v", events[7])
	}
	if events, dropped, err := parseCorePersistenceEvents("5|"); err != nil || dropped != 5 || events != nil {
		t.Fatalf("drop-only batch is wrong: dropped=%d err=%v", dropped, err)
	}
	if events, _, err := parseCorePersistenceEvents("empty"); err != nil || events != nil {
		t.Fatalf("empty batch is wrong: %v", err)
	}
	invalid := []string{
		"", " 0|", "x|", "0",
		"0|" + persistenceValidIntegrity[:len(persistenceValidIntegrity)-1],  // 11 fields
		"0|0:4242:4242:1000:1:1:1:1:8:123456:62617368:",                      // zero ts
		"0|1700000000000000000:0:4242:1000:1:1:1:1:8:123456:62617368:",       // zero pid
		"0|1700000000000000000:4242:0:1000:1:1:1:1:8:123456:62617368:",       // zero tgid
		"0|1700000000000000000:4242:4242:1000:12:1:1:0:8:123456:62617368:",   // unknown class
		"0|1700000000000000000:4242:4242:1000:1:9:1:0:8:123456:62617368:",    // unknown kind
		"0|1700000000000000000:4242:4242:1000:1:1:9:0:8:123456:62617368:",    // unknown action
		"0|1700000000000000000:4242:4242:1000:1:1:1:4:8:123456:62617368:",    // intent code 4
		"0|1700000000000000000:4242:4242:1000:1:1:1:0:0:123456:62617368:",    // missing dev
		"0|1700000000000000000:4242:4242:1000:1:1:1:0:8:0:62617368:",         // missing ino
		"0|1700000000000000000:4242:4242:1000:0:5:1:0:8:1:62617368:",         // identity on scrape
		"0|1700000000000000000:4242:4242:1000:1:1:1:0:8:1:",                  // empty comm
		"0|1700000000000000000:4242:4242:1000:1:1:1:0:8:1:00",                // NUL comm
		"0|1700000000000000000:4242:4242:1000:1:1:1:0:8:1:7",                 // odd comm hex
		"0|1700000000000000000:4242:4242:1000:1:1:1:0:8:1:62617368:00",       // NUL detail
		"0|1700000000000000000:4242:4242:1000:20:3:1:4:8:1:70697065:",        // unknown session bits
		"0|1700000000000000000:4242:4242:1000:6:7:1:5:8:1:62617368:",         // unknown drift reason
		"0|1700000000000000000:4242:4242:1000:0:5:1:0:0:0:62617368:65786563", // bad scrape direction
		"0|1700000000000000000:4242:4242:1000:0:6:1:0:0:0:62617368:78",       // non-decimal ptrace mode
		"0|1700000000000000000:4242:4242:1000:1:2:1:0:8:1:73736864:",         // mmap with integrity class
		"0|1700000000000000000:4242:4242:1000:3:2:1:0:8:1:73736864:00",       // detail on mmap
		"0|" + strings.Repeat("4", maxPersistencePayloadBytes),               // oversized batch
	}
	for _, response := range invalid {
		if events, dropped, err := parseCorePersistenceEvents(response); err == nil || events != nil || dropped != 0 {
			t.Fatalf("hostile persistence batch accepted: %.90q", response)
		}
	}
	tooMany := "0|" + strings.TrimSuffix(strings.Repeat(persistenceValidIntegrity+",", maxPersistenceEventsPerResponse+1), ",")
	if _, _, err := parseCorePersistenceEvents(tooMany); err == nil {
		t.Fatal("a persistence batch above the core ceiling was accepted")
	}
}

func TestCorePersistenceClassKindContract(t *testing.T) {
	cases := map[uint8][]uint8{
		PersistenceKindIntegrityWrite: {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		PersistenceKindLibraryMmap:    {3},
		PersistenceKindPeripheralOpen: {20, 21, 22, 23},
		PersistenceKindSecretOpen:     {30, 31, 32, 33, 34},
		PersistenceKindMemoryScrape:   {0},
		PersistenceKindPtraceAccess:   {0},
		PersistenceKindDrift:          {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		PersistenceKindBaseline:       {0},
	}
	for kind := uint8(0); kind < 16; kind++ {
		for class := uint8(0); class < 64; class++ {
			want := false
			for _, allowed := range cases[kind] {
				if class == allowed {
					want = true
					break
				}
			}
			if got := persistenceClassKindValid(class, kind); got != want {
				t.Fatalf("class/kind matrix mismatch class=%d kind=%d got=%v want=%v", class, kind, got, want)
			}
		}
	}
	for class := uint8(0); class < 255; class++ {
		validKinds := 0
		for kind := uint8(1); kind <= PersistenceKindBaseline; kind++ {
			if persistenceClassKindValid(class, kind) {
				validKinds++
			}
		}
		// Class 0 is the documented "no path class" marker: it is valid only for
		// the identity-less kinds and is not a path class.
		wantKnown := validKinds > 0 && class != PersistenceClassUnspecified
		if persistenceClassKnown(class) != wantKnown {
			t.Fatalf("class %d known=%v but %d kind mappings", class, persistenceClassKnown(class), validKinds)
		}
	}
	if !persistenceKindKnown(PersistenceKindIntegrityWrite) || persistenceKindKnown(0) || persistenceKindKnown(9) {
		t.Fatal("persistence kind closure is wrong")
	}
	if !persistenceActionKnown(PersistenceActionAudit) || persistenceActionKnown(0) || persistenceActionKnown(4) {
		t.Fatal("persistence action closure is wrong")
	}
}

// FuzzCorePersistenceParser feeds arbitrary bytes into the PERSIST_* text
// parsers. A panic or an accepted record that violates the closed wire contract
// would mean the XDR engine can be tricked into acting on attacker-shaped data.
func FuzzCorePersistenceParser(f *testing.F) {
	for _, seed := range []string{
		"empty",
		"0|" + persistenceValidIntegrity,
		"2|" + persistenceValidMmap + "," + persistenceValidDrift,
		persistenceValidStatus,
		"roots=5:verified=5:drifted=1:at_ms=1",
		"0|",
		"x|",
		"0",
		strings.Repeat("A", 512),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		_, _ = parseCorePersistenceStatus(payload)
		_, _ = parsePersistenceBaseline(payload)
		events, dropped, err := parseCorePersistenceEvents(payload)
		if err != nil {
			if events != nil || dropped != 0 {
				t.Fatalf("rejected batch returned partial state: events=%d dropped=%d", len(events), dropped)
			}
			return
		}
		if len(events) > maxPersistenceEventsPerResponse {
			t.Fatalf("accepted more than the batch ceiling: %d", len(events))
		}
		for _, event := range events {
			if event.TsNS == 0 || event.PID == 0 || event.TGID == 0 || event.Comm == "" {
				t.Fatalf("accepted an event without identity: %+v", event)
			}
			if !persistenceKindKnown(event.Kind) || !persistenceActionKnown(event.Action) ||
				!persistenceClassKindValid(event.Class, event.Kind) {
				t.Fatalf("accepted an impossible event: %+v", event)
			}
			identityRequired := event.Kind != PersistenceKindMemoryScrape &&
				event.Kind != PersistenceKindPtraceAccess &&
				event.Kind != PersistenceKindBaseline
			if identityRequired && (event.Dev == 0 || event.Ino == 0) {
				t.Fatalf("accepted a path event without identity: %+v", event)
			}
			if !identityRequired && (event.Dev != 0 || event.Ino != 0) {
				t.Fatalf("accepted an identity-less event with identity: %+v", event)
			}
			for _, character := range []byte(event.Comm) {
				if character < 0x20 || character > 0x7e {
					t.Fatalf("accepted a non-printable comm: %+v", event)
				}
			}
		}
	})
}
