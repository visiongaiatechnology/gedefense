// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-2 regression tests: bounded BPF_GUARD_* parsers (status, epoch,
// event text wire) and the fuzz target for the event parser. Every accepted
// record must satisfy the closed action/program-type/helper-bit contract; every
// rejected answer must be all-or-nothing.

import (
	"strings"
	"testing"
)

const (
	bpfGuardValidObserved = "1700000000000000000:4242:4241:1000:1:5:29:0:0:0:0:0:0:0:627066746f6f6c"
	bpfGuardValidRisk     = "1700000000000000001:5000:5000:0:2:5:2:3:36:58:0:0:0:0:726f6f746b6974"
)

func TestCoreBpfGuardStatusBoundedAndStrict(t *testing.T) {
	status, err := parseCoreBpfGuardStatus(
		"enabled=1:attached=1:lsm=1:tp=1:kprobe=0:events=12:drops=3:read_failures=1:loads=4:helper_risk=2")
	if err != nil {
		t.Fatalf("valid bpf-guard status rejected: %v", err)
	}
	if !status.Enabled || !status.Attached || !status.LSMAttached || !status.TPAttached ||
		status.KprobeAttached || status.Events != 12 || status.Drops != 3 ||
		status.ReadFailures != 1 || status.Loads != 4 || status.HelperRisk != 2 {
		t.Fatalf("bpf-guard status decoded wrong: %+v", status)
	}
	for _, response := range []string{
		"",
		"enabled=1:attached=1",
		"enabled=1:attached=1:lsm=1:tp=1:kprobe=0:events=12:drops=3:read_failures=1:loads=4:helper_risk=2:extra=0",
		"enabled=2:attached=1:lsm=1:tp=1:kprobe=0:events=12:drops=3:read_failures=1:loads=4:helper_risk=2",
		"attached=1:enabled=1:lsm=1:tp=1:kprobe=0:events=12:drops=3:read_failures=1:loads=4:helper_risk=2",
		"enabled=1:attached=1:lsm=1:tp=1:kprobe=0:events=x:drops=3:read_failures=1:loads=4:helper_risk=2",
		" enabled=1:attached=1:lsm=1:tp=1:kprobe=0:events=12:drops=3:read_failures=1:loads=4:helper_risk=2",
		"enabled=1:attached=1:lsm=1:tp=1:kprobe=0:events=12:drops=3:read_failures=1:loads=4:helper_risk=18446744073709551616",
		strings.Repeat("a", maxBpfGuardStatusBytes+1),
	} {
		if _, err := parseCoreBpfGuardStatus(response); err == nil {
			t.Fatalf("hostile bpf-guard status accepted: %.60q", response)
		}
	}
}

func TestCoreBpfGuardEpochValidation(t *testing.T) {
	epoch, err := parseBpfGuardEpoch("0123456789abcdef")
	if err != nil || epoch != "0123456789abcdef" {
		t.Fatalf("valid bpf-guard epoch rejected: %q %v", epoch, err)
	}
	for _, response := range []string{
		"", "0", "0123456789abcde", "0123456789abcdef0", "0123456789ABCDEF",
		"0123456789abcdeg", "0123456789abcde\n", " 0123456789abcdef",
	} {
		if _, err := parseBpfGuardEpoch(response); err == nil {
			t.Fatalf("hostile bpf-guard epoch accepted: %q", response)
		}
	}
}

func TestCoreBpfGuardEventsBoundedAndStrict(t *testing.T) {
	batch := "2|" + bpfGuardValidObserved + "," + bpfGuardValidRisk
	events, dropped, err := parseCoreBpfGuardEvents(batch)
	if err != nil {
		t.Fatalf("valid bpf-guard batch rejected: %v", err)
	}
	if dropped != 2 || len(events) != 2 {
		t.Fatalf("batch parsed to %d events dropped=%d", len(events), dropped)
	}
	if events[0].Action != BpfGuardActionObserved || events[0].Command != BpfGuardCommandProgLoad ||
		events[0].ProgType != BpfGuardProgTypeLSM || events[0].PID != 4242 || events[0].TGID != 4241 ||
		events[0].Comm != "bpftool" || events[0].HelperMask != 0 {
		t.Fatalf("observed event decoded wrong: %+v", events[0])
	}
	if events[1].Action != BpfGuardActionHelperRisk || events[1].HelperMask != 3 ||
		events[1].HelperIDs[0] != BpfGuardHelperIDProbeWriteUser ||
		events[1].HelperIDs[1] != BpfGuardHelperIDOverrideReturn ||
		events[1].HelperIDs[2] != 0 || events[1].Comm != "rootkit" {
		t.Fatalf("helper-risk event decoded wrong: %+v", events[1])
	}
	if events, dropped, err := parseCoreBpfGuardEvents("5|"); err != nil || dropped != 5 || events != nil {
		t.Fatalf("drop-only bpf-guard batch is wrong: dropped=%d err=%v", dropped, err)
	}
	if events, _, err := parseCoreBpfGuardEvents("empty"); err != nil || events != nil {
		t.Fatalf("empty bpf-guard batch is wrong: %v", err)
	}
	invalid := []string{
		"", " 0|", "x|", "0", "0|" + bpfGuardValidObserved + ",",
		"0|1700000000000000000:4242:4241:1000:1:5:29:0:0:0:0:0:0:0",          // missing comm
		"0|1700000000000000000:4242:4241:1000:1:5:29:0:0:0:0:0:0:0:62:extra", // extra field
		"0|0:4242:4241:1000:1:5:29:0:0:0:0:0:0:0:",                           // zero ts
		"0|1700000000000000000:0:4241:1000:1:5:29:0:0:0:0:0:0:0:",            // zero pid
		"0|1700000000000000000:4242:0:1000:1:5:29:0:0:0:0:0:0:0:",            // zero tgid
		"0|1700000000000000000:4242:4241:1000:9:5:29:0:0:0:0:0:0:0:",         // unknown action
		"0|1700000000000000000:4242:4241:1000:1:5:64:0:0:0:0:0:0:0:",         // out-of-range prog type
		"0|1700000000000000000:4242:4241:1000:1:5:29:8:0:0:0:0:0:0:",         // unknown helper bit
		"0|1700000000000000000:4242:4241:1000:2:5:29:0:0:0:0:0:0:0:",         // helper risk without mask
		"0|1700000000000000000:4242:4241:1000:1:5:29:3:36:58:0:0:0:0:",       // observed with helper mask
		"0|1700000000000000000:4242:4241:1000:2:5:29:3:0:36:0:0:0:0:",        // non-compact ids
		"0|1700000000000000000:4242:4241:1000:2:5:29:3:36:1025:0:0:0:0:",     // helper id above bound
		"0|1700000000000000000:4242:4241:1000:2:5:29:1:7:0:0:0:0:0:",         // non-risk helper id
		"0|1700000000000000000:4242:4241:1000:1:5:29:0:0:0:0:0:8:0:",         // half-null identity
		"0|1700000000000000000:4242:4241:1000:1:5:29:0:0:0:0:0:0:0:00",       // NUL comm
		"0|1700000000000000000:4242:4241:1000:1:5:29:0:0:0:0:0:0:0:0a",       // control comm
		"0|1700000000000000000:4242:4241:1000:1:5:29:0:0:0:0:0:0:0:6",        // odd comm hex
		"0|" + strings.Repeat("4", maxBpfGuardPayloadBytes),                  // oversized payload
	}
	for _, response := range invalid {
		if events, dropped, err := parseCoreBpfGuardEvents(response); err == nil || events != nil || dropped != 0 {
			t.Fatalf("hostile bpf-guard batch accepted: %.60q", response)
		}
	}
	tooMany := "0|" + strings.TrimSuffix(strings.Repeat(bpfGuardValidObserved+",", maxBpfGuardEventsPerResponse+1), ",")
	if _, _, err := parseCoreBpfGuardEvents(tooMany); err == nil {
		t.Fatal("a bpf-guard batch above the core ceiling was accepted")
	}
}

func TestCoreBpfGuardHelperBitContract(t *testing.T) {
	if BpfGuardHelperMaskAll != BpfGuardHelperBitProbeWriteUser|BpfGuardHelperBitOverrideReturn|BpfGuardHelperBitSendSignal {
		t.Fatal("helper mask does not cover every defined bit")
	}
	cases := map[uint32]uint32{
		BpfGuardHelperIDProbeWriteUser: BpfGuardHelperBitProbeWriteUser,
		BpfGuardHelperIDOverrideReturn: BpfGuardHelperBitOverrideReturn,
		BpfGuardHelperIDSendSignal:     BpfGuardHelperBitSendSignal,
		BpfGuardHelperIDSendSignalThre: BpfGuardHelperBitSendSignal,
		0:                              0,
		1:                              0,
		57:                             0,
		108:                            0,
		200:                            0,
	}
	for helperID, want := range cases {
		if got := BpfGuardHelperIDToBit(helperID); got != want {
			t.Fatalf("helper %d mapped to %#x, want %#x", helperID, got, want)
		}
	}
}

// FuzzCoreBpfGuardParser feeds arbitrary bytes into the BPF_GUARD event/status
// parser. A panic or an accepted record that violates the closed wire contract
// would mean the XDR engine can be tricked into acting on attacker-shaped data.
func FuzzCoreBpfGuardParser(f *testing.F) {
	f.Add("empty")
	f.Add("0|" + bpfGuardValidObserved)
	f.Add("2|" + bpfGuardValidObserved + "," + bpfGuardValidRisk)
	f.Add("0|" + bpfGuardValidRisk)
	f.Add("1|")
	f.Add("x|")
	f.Add("0|")
	f.Add(strings.Repeat("A", 4096))
	f.Fuzz(func(t *testing.T, payload string) {
		events, dropped, err := parseCoreBpfGuardEvents(payload)
		if err != nil {
			if events != nil || dropped != 0 {
				t.Fatalf("rejected batch returned partial state: events=%d dropped=%d", len(events), dropped)
			}
			return
		}
		if len(events) > maxBpfGuardEventsPerResponse {
			t.Fatalf("accepted more than the batch ceiling: %d", len(events))
		}
		for _, event := range events {
			if event.PID == 0 || event.TGID == 0 || event.TsNS == 0 {
				t.Fatal("accepted an event without identity or timestamp")
			}
			switch event.Action {
			case BpfGuardActionObserved, BpfGuardActionDenied:
				if event.HelperMask != 0 || event.HelperIDs != [BpfGuardHelperBitsPerEvent]uint32{} {
					t.Fatal("accepted helper metadata on a non-helper event")
				}
			case BpfGuardActionHelperRisk:
				if event.HelperMask == 0 || event.HelperIDs[0] == 0 {
					t.Fatal("accepted a helper-risk event without helpers")
				}
			default:
				t.Fatalf("accepted unknown action: %d", event.Action)
			}
			if event.ProgType > BpfGuardProgTypeMax {
				t.Fatalf("accepted out-of-range program type: %d", event.ProgType)
			}
			if event.HelperMask&^BpfGuardHelperMaskAll != 0 {
				t.Fatalf("accepted unknown helper bit: %#x", event.HelperMask)
			}
			if (event.ExeDev == 0) != (event.ExeIno == 0) {
				t.Fatal("accepted a half-null executable identity")
			}
			if len(event.Comm) > 16 {
				t.Fatalf("accepted an oversized comm: %d bytes", len(event.Comm))
			}
		}
	})
}
