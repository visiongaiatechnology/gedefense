// STATUS: DIAMANT VGT SUPREME
package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/flowguard"
	"github.com/visiongaiatechnology/gedefense/control/internal/webposture"
)

func TestBuildOverviewConnectionsPaginationAndClassification(t *testing.T) {
	now := time.Now().UTC()
	var flows []flowguard.FlowEntry
	for i := 1; i <= 15; i++ {
		flows = append(flows, flowguard.FlowEntry{
			Sample: flowguard.FlowSample{
				Peer: fmt.Sprintf("198.51.100.%d", i), Port: 443,
				RxBytes: uint64(i * 1000), TxBytes: uint64(i * 500),
				SegsIn: uint64(i * 4), SegsOut: uint64(i * 3),
			},
			Verdict: "normal",
		})
	}
	res1 := buildOverviewConnections(connectionsInput{
		Now:      now,
		Page:     1,
		PageSize: 10,
		Filter:   "all",
		Servers:  []webposture.Server{{Comm: "nginx", Listen: []string{"0.0.0.0:443"}}},
		TLSFlows: flows,
		Handshakes: []tlsSensorHandshakeView{
			{At: now, Peer: "198.51.100.15:51234", SNI: "app.example.test", ALPN: []string{"h2"}},
		},
		StyxFlows: []StyxBeaconFlowSnapshot{
			{Comm: "php-fpm", PID: 901, Remote: "203.0.113.9:443", TxBytes: 99000, RxBytes: 42000, Score: 65, Signals: []string{"PERIODIC"}},
		},
		BlockedIPs: map[string]struct{}{"198.51.100.14": {}},
	})
	if res1.Total != 16 || res1.TotalPages != 2 || len(res1.Items) != 10 {
		t.Fatalf("unexpected page 1 pagination: total=%d pages=%d items=%d", res1.Total, res1.TotalPages, len(res1.Items))
	}
	if res1.Items[0].App != "php-fpm" || res1.Items[0].Verdict != "flagged" {
		t.Fatalf("expected highest volume styx flow first & flagged, got %+v", res1.Items[0])
	}
	if res1.Items[1].Host != "app.example.test" || res1.Items[1].ALPN != "h2" {
		t.Fatalf("expected SNI/ALPN correlation on peer 15, got %+v", res1.Items[1])
	}
	if res1.Items[2].Verdict != "blocked" {
		t.Fatalf("expected blocked status from state blocklist, got %+v", res1.Items[2])
	}

	res2 := buildOverviewConnections(connectionsInput{
		Now: now, Page: 2, PageSize: 10, Filter: "all",
		TLSFlows: flows,
		StyxFlows: []StyxBeaconFlowSnapshot{
			{Comm: "php-fpm", PID: 901, Remote: "203.0.113.9:443", TxBytes: 99000},
		},
	})
	if res2.Page != 2 || len(res2.Items) != 6 {
		t.Fatalf("expected 6 remaining items on page 2, got page=%d len=%d", res2.Page, len(res2.Items))
	}
}
