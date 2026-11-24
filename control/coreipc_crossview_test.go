// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-3 regression tests: the strict CROSS_VIEW_* transports (status,
// event text wire, report text) and the fuzz target for the parser family. Every
// accepted record must satisfy the closed domain/kind/severity contract; every
// rejected answer must be all-or-nothing and never panic.

import (
	"strings"
	"testing"
)

const (
	crossViewValidHiddenProg = "1700000000000000000:0:0:0:42:1:1:4:1:68696464656e2d70726f67"
	crossViewValidRawTap     = "1700000000000000001:4242:0:0:0:7:12:2:2:6468636c69656e74"
	crossViewValidPortless   = "1700000000000000002:500:0:0:7:2:6:3:4:62706664"
	crossViewValidStatus     = "enabled=1:scans=3:contradictions=2:events=5:drops=1:domains=6:age_ms=1234:tap=1:mods=1:procs=1:bpf=1:pkgdb=debian:trace=0"
	crossViewValidReport     = "bounds=ok:domains=8:contradictions=1:events=2:scans=3:drops=0:age_ms=10:tap=1:mods=1:procs=1:bpf=1:pkgdb=debian:trace=0:pins=23:reason=bpf_enum_denied,pins_unavailable"
)

func TestCoreCrossViewStatusBoundedAndStrict(t *testing.T) {
	status, err := parseCoreCrossViewStatus(crossViewValidStatus)
	if err != nil {
		t.Fatalf("valid cross-view status rejected: %v", err)
	}
	if !status.Enabled || status.Scans != 3 || status.Contradictions != 2 || status.Events != 5 ||
		status.Drops != 1 || status.Domains != 6 || status.LastScanAgeMS != 1234 ||
		!status.Tap || !status.Mods || !status.Procs || !status.BPF || status.Trace ||
		status.PkgDB != CrossViewPkgDBDebian {
		t.Fatalf("cross-view status decoded wrong: %+v", status)
	}
	// Degraded/unsupported package DB tokens are valid capability facts.
	for _, token := range []string{CrossViewPkgDBArch, CrossViewPkgDBUnsupported, CrossViewPkgDBDegraded} {
		response := strings.Replace(crossViewValidStatus, "pkgdb=debian", "pkgdb="+token, 1)
		if _, err := parseCoreCrossViewStatus(response); err != nil {
			t.Fatalf("valid cross-view pkgdb token %q rejected: %v", token, err)
		}
	}
	for _, response := range []string{
		"",
		"enabled=1:scans=3",
		crossViewValidStatus + ":extra=0",
		strings.Replace(crossViewValidStatus, "enabled=1", "enabled=2", 1),
		strings.Replace(crossViewValidStatus, "domains=6", "domains=9", 1),
		strings.Replace(crossViewValidStatus, "pkgdb=debian", "pkgdb=guessed", 1),
		strings.Replace(crossViewValidStatus, "scans=3", "scans=x", 1),
		strings.Replace(crossViewValidStatus, "events=5", "events=18446744073709551616", 1),
		strings.Replace(crossViewValidStatus, "enabled=1", " attached=1", 1),
		" " + crossViewValidStatus,
		crossViewValidStatus + " ",
		strings.Repeat("a", maxCrossViewStatusBytes+1),
	} {
		if _, err := parseCoreCrossViewStatus(response); err == nil {
			t.Fatalf("hostile cross-view status accepted: %.70q", response)
		}
	}
}

func TestCoreCrossViewEventsBoundedAndStrict(t *testing.T) {
	batch := "2|" + crossViewValidHiddenProg + "," + crossViewValidRawTap
	events, dropped, err := parseCoreCrossViewEvents(batch)
	if err != nil {
		t.Fatalf("valid cross-view batch rejected: %v", err)
	}
	if dropped != 2 || len(events) != 2 {
		t.Fatalf("batch parsed to %d events dropped=%d", len(events), dropped)
	}
	if events[0].Domain != CrossViewDomainEBPFIDGap || events[0].Kind != CrossViewKindHiddenProg ||
		events[0].Severity != CrossViewSeverityCritical || events[0].Ino != 42 ||
		events[0].Detail != "HIDDEN_PROG" || events[0].TsNS != 1700000000000000000 {
		t.Fatalf("hidden-prog event decoded wrong: %+v", events[0])
	}
	if events[1].Domain != CrossViewDomainNetlinkFilter || events[1].Kind != CrossViewKindRawTapFilter ||
		events[1].Severity != CrossViewSeverityMedium || events[1].PID != 4242 || events[1].Comm != "dhclient" {
		t.Fatalf("raw-tap event decoded wrong: %+v", events[1])
	}
	if got, dropped, err := parseCoreCrossViewEvents("empty"); err != nil || got != nil || dropped != 0 {
		t.Fatalf("empty cross-view batch is wrong: dropped=%d err=%v", dropped, err)
	}
	if got, dropped, err := parseCoreCrossViewEvents("5|"); err != nil || dropped != 5 || got != nil {
		t.Fatalf("drop-only cross-view batch is wrong: dropped=%d err=%v", dropped, err)
	}
	invalid := []string{
		"",
		" 0|",
		"x|",
		"0",
		"0|" + crossViewValidHiddenProg + ",",
		"0|1700000000000000000:0:0:0:42:1:1:4:1", // missing comm
		"0|" + crossViewValidHiddenProg + ":extra",    // extra field
		"0|0:0:0:0:42:1:1:4:1:6869",                   // zero ts
		"0|1700000000000000000:0:0:0:42:0:1:4:1:6869", // unknown domain
		"0|1700000000000000000:0:0:0:42:9:1:4:1:6869", // domain above max
		"0|1700000000000000000:0:0:0:42:1:0:4:1:6869", // unknown kind
		"0|1700000000000000000:0:0:0:42:1:13:4:1:6869",
		"0|1700000000000000000:0:0:0:42:1:12:2:2:6869",                            // kind outside its domain
		"0|1700000000000000000:0:0:0:42:6:1:4:1:6869",                             // pin domain with gap kind
		"0|1700000000000000000:0:0:0:42:1:1:0:1:6869",                             // severity 0
		"0|1700000000000000000:0:0:0:42:1:1:5:1:6869",                             // severity above max
		"0|1700000000000000000:2147483648:0:0:42:1:1:4:1:6869",                    // pid above 2^31-1
		"0|1700000000000000000:0:0:0:42:1:1:4:4294967296:6869",                    // detail above u32
		"0|1700000000000000000:0:0:0:42:1:1:4:1:",                                 // empty comm
		"0|1700000000000000000:0:0:0:42:1:1:4:1:6",                                // odd comm hex
		"0|1700000000000000000:0:0:0:42:1:1:4:1:1f",                               // control comm
		"0|1700000000000000000:0:0:0:42:1:1:4:1:6162636465666768696a6b6c6d6e6f70", // 16-byte comm (no NUL room)
		"0|" + strings.Repeat("4", maxCrossViewPayloadBytes),                      // oversized payload
	}
	for _, response := range invalid {
		if events, dropped, err := parseCoreCrossViewEvents(response); err == nil || events != nil || dropped != 0 {
			t.Fatalf("hostile cross-view batch accepted: %.70q", response)
		}
	}
	tooMany := "0|" + strings.TrimSuffix(strings.Repeat(crossViewValidRawTap+",", maxCrossViewEventsPerResponse+1), ",")
	if _, _, err := parseCoreCrossViewEvents(tooMany); err == nil {
		t.Fatal("a cross-view batch above the core ceiling was accepted")
	}
	oversizedRecord := "0|" + strings.Repeat("1", maxCrossViewRecordBytes+1)
	if _, _, err := parseCoreCrossViewEvents(oversizedRecord); err == nil {
		t.Fatal("an oversized cross-view record was accepted")
	}
}

func TestCoreCrossViewKindDomainContract(t *testing.T) {
	for domain := CrossViewDomainEBPFIDGap; domain <= CrossViewDomainMax; domain++ {
		accepted := 0
		for kind := CrossViewKindHiddenProg; kind <= CrossViewKindMax; kind++ {
			if CrossViewKindDomainValid(domain, kind) {
				accepted++
			}
		}
		if accepted == 0 {
			t.Fatalf("domain %d has no valid kind", domain)
		}
	}
	if CrossViewKindDomainValid(0, CrossViewKindHiddenProg) {
		t.Fatal("domain 0 accepted a kind")
	}
	if CrossViewKindDomainValid(CrossViewDomainEBPFIDGap, CrossViewKindRawTapFilter) {
		t.Fatal("id-gap domain accepted a raw-tap kind")
	}
	if !CrossViewKindDomainValid(CrossViewDomainMapNameView, CrossViewKindHiddenMap) {
		t.Fatal("map-name view rejected its hidden-map kind")
	}
	for kind := CrossViewKindHiddenProg; kind <= CrossViewKindMax; kind++ {
		if name := CrossViewKindName(kind); name == "" || name == "unknown" {
			t.Fatalf("kind %d lost its stable name", kind)
		}
	}
	for domain := CrossViewDomainEBPFIDGap; domain <= CrossViewDomainMax; domain++ {
		if name := CrossViewDomainName(domain); name == "" || name == "unknown" {
			t.Fatalf("domain %d lost its stable name", domain)
		}
	}
}

func TestCoreCrossViewReportBoundedAndStrict(t *testing.T) {
	report, err := parseCoreCrossViewReport(crossViewValidReport)
	if err != nil {
		t.Fatalf("valid cross-view report rejected: %v", err)
	}
	if !report.BoundsOK || report.Domains != 8 || report.Contradictions != 1 || report.Events != 2 ||
		report.Scans != 3 || report.Pins != 23 || len(report.Reasons) != 2 ||
		report.Reasons[0] != "bpf_enum_denied" || report.PkgDB != CrossViewPkgDBDebian {
		t.Fatalf("cross-view report decoded wrong: %+v", report)
	}
	degraded := "bounds=degraded:domains=3:contradictions=0:events=0:scans=1:drops=2:age_ms=5:tap=0:mods=1:procs=1:bpf=0:pkgdb=unsupported:trace=0:pins=0"
	if parsed, err := parseCoreCrossViewReport(degraded); err != nil || parsed.BoundsOK {
		t.Fatalf("degraded cross-view report rejected or misread: %+v %v", parsed, err)
	}
	for _, response := range []string{
		"",
		"bounds=maybe:domains=8",
		"domains=8", // missing bounds prefix
		"bounds=ok",
		"bounds=ok:domains=9",
		"bounds=ok:domains=8:domains=8",
		"bounds=ok:domains=8:unknown=1",
		"bounds=ok:domains=8:reason=BAD_TOKEN",
		"bounds=ok:domains=8:reason=../etc/passwd",
		"bounds=ok:domains=8:pkgdb=guessed",
		" bounds=ok:domains=8",
		strings.Repeat("a", maxCrossViewReportBytes+1),
	} {
		if _, err := parseCoreCrossViewReport(response); err == nil {
			t.Fatalf("hostile cross-view report accepted: %.70q", response)
		}
	}
}

// Real-wire samples captured from the AP-3 real-system smoke run on the WSL2
// 6.18 kernel (root, live eBPF object loaded). The Go parser must accept exactly
// the bytes the Rust core produced; a format drift between the two languages
// would break this test instead of the control plane.
func TestCoreCrossViewRealWireSamplesParse(t *testing.T) {
	status, err := parseCoreCrossViewStatus(
		"enabled=1:scans=1:contradictions=0:events=0:drops=0:domains=7:age_ms=70:tap=1:mods=1:procs=1:bpf=1:pkgdb=debian:trace=1")
	if err != nil || !status.Enabled || status.Domains != 7 || status.PkgDB != CrossViewPkgDBDebian {
		t.Fatalf("real status sample rejected: %+v %v", status, err)
	}
	report, err := parseCoreCrossViewReport(
		"bounds=ok:domains=7:contradictions=0:events=0:scans=1:drops=0:age_ms=0:tap=1:mods=1:procs=1:bpf=1:pkgdb=debian:trace=1:pins=0:reason=pins_unavailable")
	if err != nil || !report.BoundsOK || report.Domains != 7 || report.Pins != 0 ||
		len(report.Reasons) != 1 || report.Reasons[0] != "pins_unavailable" {
		t.Fatalf("real report sample rejected: %+v %v", report, err)
	}
	events, dropped, err := parseCoreCrossViewEvents(
		"0|1795513730755000000:0:0:0:3796890599080657700:4:9:3:23:736b5f6174746163685f66696c7465")
	if err != nil || dropped != 0 || len(events) != 1 {
		t.Fatalf("real event sample rejected: %+v %v", events, err)
	}
	if events[0].Domain != CrossViewDomainModuleTrace || events[0].Kind != CrossViewKindFtraceHook ||
		events[0].Comm != "sk_attach_filte" || events[0].Detail != "FTRACE_HOOK" {
		t.Fatalf("real event sample decoded wrong: %+v", events[0])
	}
}

func FuzzCoreCrossViewParser(f *testing.F) {
	f.Add(crossViewValidStatus)
	f.Add("empty")
	f.Add("0|" + crossViewValidHiddenProg + "," + crossViewValidRawTap + "," + crossViewValidPortless)
	f.Add(crossViewValidReport)
	f.Add("0|")
	f.Add("bounds=degraded:domains=0:reason=bpf_enum_denied")
	f.Fuzz(func(t *testing.T, response string) {
		if events, dropped, err := parseCoreCrossViewEvents(response); err == nil {
			if len(events) > maxCrossViewEventsPerResponse {
				t.Fatalf("accepted %d events above the ceiling", len(events))
			}
			_ = dropped
			for _, event := range events {
				if event.TsNS == 0 {
					t.Fatal("accepted a zero-timestamp event")
				}
				if !CrossViewKindDomainValid(event.Domain, event.Kind) {
					t.Fatalf("accepted event %d/%d outside the closed product", event.Domain, event.Kind)
				}
				if event.Severity < CrossViewSeverityInfo || event.Severity > CrossViewSeverityCritical {
					t.Fatalf("accepted severity %d", event.Severity)
				}
				if event.PID < 0 || event.PID > 2147483647 {
					t.Fatalf("accepted pid %d", event.PID)
				}
			}
		}
		if status, err := parseCoreCrossViewStatus(response); err == nil {
			if status.Domains > uint64(CrossViewDomainMax) {
				t.Fatalf("accepted %d domains", status.Domains)
			}
			if !crossViewPackageDBValid(status.PkgDB) {
				t.Fatalf("accepted package-DB token %q", status.PkgDB)
			}
		}
		if report, err := parseCoreCrossViewReport(response); err == nil {
			if report.Domains > uint64(CrossViewDomainMax) {
				t.Fatalf("accepted %d report domains", report.Domains)
			}
		}
	})
}
