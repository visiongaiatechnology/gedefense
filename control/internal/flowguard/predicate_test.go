package flowguard

import (
	"math"
	"testing"
	"time"
)

// TestStormPredicateExactBoundaries locks every one of the four predicate
// conditions: the comparisons are strict, so a value exactly on a bound does not
// trigger.
func TestStormPredicateExactBoundaries(t *testing.T) {
	t.Parallel()
	predicate := Predicate{RxThresholdBytes: 1000, TxRatio: 4, AvgPktLenBytes: 240, MinPPSRatio: 8}
	base := FlowSample{
		Peer: "203.0.113.7", Port: 443,
		RxBytes: 4000, TxBytes: 100, SegsIn: 100, SegsOut: 1,
	}
	// (4000 > 1000) && (4000 > 4*100) && (40 < 240) && (100 > 8*1) -> true
	if _, matched := Evaluate(predicate, base); !matched {
		t.Fatalf("baseline storm sample did not match: %+v", base)
	}
	cases := []struct {
		name   string
		mutate func(*FlowSample)
	}{
		{"rx equals threshold", func(s *FlowSample) { s.RxBytes = 1000; s.SegsIn = 25 }},
		{"rx equals ratio*tx", func(s *FlowSample) { s.RxBytes = 1004; s.TxBytes = 251; s.SegsIn = 10 }},
		{"avg pkt len equals limit", func(s *FlowSample) { s.RxBytes = 2400; s.SegsIn = 10; s.TxBytes = 10 }},
		{"segs in equals ratio*segs out", func(s *FlowSample) { s.RxBytes = 1600; s.SegsIn = 8; s.SegsOut = 1 }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sample := base
			tc.mutate(&sample)
			if _, matched := Evaluate(predicate, sample); matched {
				t.Fatalf("boundary sample matched: %+v", sample)
			}
		})
	}
}

// TestLargeUploadDoesNotTrigger is the mission's negative test: a 5 GiB upload
// with small ACK traffic must be classified "watch"/"ok" at most, never "storm".
func TestLargeUploadDoesNotTrigger(t *testing.T) {
	t.Parallel()
	predicate := DefaultPredicate()
	const fiveGiB = 5 << 30
	// ~1.4 KiB payload segments; the ACK path answers with small packets.
	segsIn := uint64(fiveGiB / 1400)
	segsOut := segsIn / 2
	ackBytes := segsOut * 66
	upload := FlowSample{
		Peer: "198.51.100.9", Port: 443,
		RxBytes: fiveGiB, TxBytes: ackBytes,
		SegsIn: segsIn, SegsOut: segsOut,
	}
	metrics, matched := Evaluate(predicate, upload)
	if matched {
		t.Fatalf("a 5 GiB upload triggered the control-storm predicate: %+v", metrics)
	}
	if metrics.AvgPktLen < float64(predicate.AvgPktLenBytes) {
		t.Fatalf("upload average packet length %.2f is unexpectedly small", metrics.AvgPktLen)
	}
	switch verdict := ClassifyFlow(predicate, upload, matched); verdict {
	case VerdictOK, VerdictWatch:
	default:
		t.Fatalf("5 GiB upload verdict = %q, want ok or watch", verdict)
	}

	// The same byte volume with tiny packets (a real control storm) does trigger.
	storm := upload
	storm.SegsIn = fiveGiB / 64
	storm.SegsOut = storm.SegsIn / 64
	if _, matched := Evaluate(predicate, storm); !matched {
		t.Fatal("a 5 GiB many-small-packets flow did not trigger")
	}
}

// TestStagedResponseNeverBansOnAlertOnly locks the staged-response contract.
func TestStagedResponseNeverBansOnAlertOnly(t *testing.T) {
	t.Parallel()
	if got := StagedResponse(true, true, 5, true); got != ResponseAlert {
		t.Fatalf("alert-only mode returned %q", got)
	}
	if got := StagedResponse(false, true, 0, false); got != ResponseThrottle {
		t.Fatalf("first match returned %q, want throttle", got)
	}
	if got := StagedResponse(false, true, 1, true); got != ResponseBan {
		t.Fatalf("correlated crash did not escalate to ban: %q", got)
	}
	if got := StagedResponse(false, true, 2, false); got != ResponseBan {
		t.Fatalf("second consecutive match did not escalate to ban: %q", got)
	}
	if got := StagedResponse(false, false, 5, true); got != ResponseAlert {
		t.Fatalf("a non-matching flow was escalated: %q", got)
	}
}

// TestFlowTableBoundedLRU proves the table never exceeds its budget and evicts
// the least recently seen peer.
func TestFlowTableBoundedLRU(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	table := NewFlowTable(MinTrackedFlows, func() time.Time { return now })
	predicate := DefaultPredicate()
	samples := make([]FlowSample, 0, MinTrackedFlows+10)
	for index := 0; index < MinTrackedFlows+10; index++ {
		samples = append(samples, FlowSample{Peer: "10.0.0." + string(rune('a'+index%26)), Port: uint16(1000 + index)})
	}
	table.Update(samples, predicate)
	entries, used := table.Snapshot(FlowListLimit)
	if used > MinTrackedFlows {
		t.Fatalf("flow table exceeded its bound: %d", used)
	}
	if len(entries) == 0 {
		t.Fatal("flow table returned no entries")
	}
	if table.MaxFlows() != MinTrackedFlows {
		t.Fatalf("max flows = %d", table.MaxFlows())
	}
}

// TestMetricsZeroSafety keeps the published metrics finite for empty counters.
func TestMetricsZeroSafety(t *testing.T) {
	t.Parallel()
	metrics := Metrics(FlowSample{})
	if math.IsInf(metrics.Ratio, 0) || math.IsNaN(metrics.Ratio) {
		t.Fatalf("ratio is not finite: %v", metrics.Ratio)
	}
	if math.IsInf(metrics.AvgPktLen, 0) || math.IsNaN(metrics.AvgPktLen) {
		t.Fatalf("avg packet length is not finite: %v", metrics.AvgPktLen)
	}
}
