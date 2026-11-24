package main

import (
	"fmt"
	"strings"
	"time"
)

// reportDnsOverflow publishes one rate-limited overflow event for a ring-drop
// batch; the counter itself is always accumulated.
func (e *XDREngine) reportDnsOverflow(dropped uint64, now time.Time) {
	if e == nil || e.dnsTunnel == nil || e.state == nil {
		return
	}
	t := e.dnsTunnel
	t.mu.Lock()
	rateLimited := !t.lastOverflow.IsZero() && now.Sub(t.lastOverflow) < dnsOverflowMinGap
	if !rateLimited {
		t.lastOverflow = now
	}
	t.mu.Unlock()
	if rateLimited {
		return
	}
	e.state.AddEvent(Event{Time: now, Severity: "warning", Kind: "xdr.dns_capture_overflow", Source: "kernel",
		Message: fmt.Sprintf("DNS capture dropped %d query observation(s) in the kernel ring; DNS tunnelling visibility is reduced (a drop is a blindspot, not evidence of absence)", dropped)})
}

// recordDnsTunnelIncident writes evidence first and then exactly one alert-only
// `XDR.DNS_TUNNEL` incident. No response action is derived and the finding is
// never kill-eligible (it carries no RuleMatch and never touches combineMatches).
func (e *XDREngine) recordDnsTunnelIncident(trigger dnsTunnelTrigger, now time.Time) {
	if e == nil || e.state == nil {
		return
	}
	signalsText := strings.Join(trigger.signals.names, ",")
	if signalsText == "" {
		return
	}
	sampleText := dnsBoundedText(strings.Join(trigger.sampleSubs, ","), 120)
	summary := fmt.Sprintf(
		"DNS tunnelling multi-signal detection for domain %s: %d/%d signals fired [%s] over a 5-minute window (%d queries, %d distinct subdomains, subdomain entropy %.2f bits/char, Zipf distinct ratio %.2f, %d distinct subdomains/hour, TXT/NULL share %.1f%%, long FQDN=%t)",
		trigger.domain, trigger.signals.count, len(dnsSignalNames), signalsText,
		trigger.queries, trigger.signals.distinct, trigger.signals.entropy,
		trigger.signals.zipfRatio, trigger.signals.hourlyDistinct,
		trigger.signals.txtShare*100, trigger.signals.fqdnLong)
	summary = dnsBoundedText(summary, dnsEventTextBytes)
	evidenceErr := e.state.RecordEvidence(EvidenceRecord{
		Severity: "high", Kind: "xdr.dns_tunnel", Source: "kernel",
		Message: "DNS tunnelling multi-signal evidence recorded before any response: " + summary,
		Target:  "domain:" + dnsBoundedText(trigger.domain, 96), Time: now,
	})
	outcome := "observed only; DNS tunnelling analytics are observe-only and no active response was derived"
	if evidenceErr != nil {
		outcome = "observed only; mandatory evidence commit failed, incident recorded without response: " + evidenceErr.Error()
	}
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("dnstunnel-%s-%d", dnsBoundedText(trigger.domain, 64), now.UnixNano()),
		Timestamp:  now,
		Sensor:     "dns-tunnel",
		Category:   "network",
		EventType:  "DNS_TUNNEL",
		EntityID:   "domain:" + dnsBoundedText(trigger.domain, 96),
		Actor:      fmt.Sprintf("pid:%d", trigger.firstPID),
		Severity:   "high",
		Confidence: 85,
		CausalEdge: EdgeEgressAttempted,
		EventUUID:  randomID(),
		Metadata: map[string]string{
			"observe_only":        "true",
			"signals":             dnsBoundedText(signalsText, 120),
			"signal_count":        fmt.Sprintf("%d", trigger.signals.count),
			"query_count":         fmt.Sprintf("%d", trigger.queries),
			"distinct_subdomains": fmt.Sprintf("%d", trigger.signals.distinct),
			"entropy_bits":        fmt.Sprintf("%.4f", trigger.signals.entropy),
			"zipf_ratio":          fmt.Sprintf("%.4f", trigger.signals.zipfRatio),
			"subdomains_hour":     fmt.Sprintf("%d", trigger.signals.hourlyDistinct),
			"txt_null_share":      fmt.Sprintf("%.4f", trigger.signals.txtShare),
			"fqdn_long":           fmt.Sprintf("%t", trigger.signals.fqdnLong),
			"sample_subdomains":   sampleText,
			"process_comm":        dnsBoundedText(trigger.firstComm, 16),
			"window_seconds":      fmt.Sprintf("%d", int64(dnsWindowBucketCount*dnsWindowBucketWidth/time.Second)),
			"domain_heuristic":    "last-two-labels",
		},
	}
	node.Digest = node.ComputeNodeDigest()
	incident := XDRIncident{
		ID: randomID(), Time: now, Severity: "high", Score: 100,
		PID: trigger.firstPID, UID: trigger.firstUID, Process: dnsBoundedText(trigger.firstComm, 16),
		RuleIDs: []string{"XDR.DNS_TUNNEL"}, Categories: []string{"network", "c2"},
		Summary: summary, Decision: "alert", Action: "none", Outcome: outcome,
		ExecutionChainID: node.NodeID, AttackStory: []AttackStoryNode{node},
		EvidenceRoot: node.Digest,
	}
	e.appendIncident(incident)
	t := e.dnsTunnel
	t.mu.Lock()
	t.incidents++
	t.mu.Unlock()
	e.state.AddEvent(Event{Time: now, Severity: "high", Kind: "xdr.dns_tunnel", Source: "kernel",
		Message: summary + "; " + outcome, Target: "domain:" + dnsBoundedText(trigger.domain, 96)})
}

func (e *XDREngine) dnsReportLockedProjection() DNSReport {
	report := DNSReport{
		Version:     "v6.3.0-ap6",
		State:       "unavailable",
		Capability:  "missing",
		Observation: "unavailable",
	}
	if e == nil || e.dnsTunnel == nil {
		return report
	}
	t := e.dnsTunnel
	t.mu.Lock()
	status := t.status
	statusErr := t.statusErr
	known := t.capabilityKnown
	sampled := t.statusAt
	report.Queries = t.queries
	report.TrackedDomains = len(t.domains)
	report.WindowObservations = t.observationCount
	report.WindowEvictions = t.windowEvictions
	report.Incidents = t.incidents
	report.Suppressed = t.suppressed
	t.mu.Unlock()
	report.Events = status.Events
	report.Drops = status.Drops
	report.ReadFailures = status.ReadFailures
	report.Enabled = status.Enabled
	report.Attached = status.Attached
	report.Sendto = status.AttachMask&1 != 0
	report.Sendmsg = status.AttachMask&2 != 0
	if known && !sampled.IsZero() {
		at := sampled
		report.SampledAt = &at
	}
	switch {
	case !known:
		// A missing command family is a capability fact, not an outage.
		report.State = "unavailable"
		report.Capability = "missing"
		report.Observation = "unavailable"
		report.Reason = "the privileged core does not advertise the DNS_CAPTURE_* command family"
		if statusErr != "" {
			report.State = "degraded"
			report.Reason = "dns capture " + statusErr
		}
		return report
	case statusErr != "":
		report.State = "degraded"
		report.Capability = "available"
		report.Observation = "unavailable"
		report.Reason = "dns capture " + statusErr
	case !status.Enabled:
		report.State = "disarmed"
		report.Capability = "available"
		report.Observation = "unavailable"
		report.Reason = "DNS capture is armed off (DNS_SET 0)"
	case !status.Attached:
		report.State = "degraded"
		report.Capability = "available"
		report.Observation = "unavailable"
		report.Reason = "DNS capture is armed but no sys_enter_sendto/sys_enter_sendmsg tracepoint is attached"
	default:
		report.State = "active"
		report.Capability = "available"
		report.Observation = "available"
		if !report.Sendto || !report.Sendmsg {
			report.Reason = "only one of the two DNS tracepoints is attached; visibility is partial"
		}
	}
	if status.ReadFailures > 0 && report.Reason == "" {
		report.Reason = fmt.Sprintf("%d kernel-side DNS read failure(s) reported by the capture", status.ReadFailures)
	}
	report.Reason = dnsBoundedText(report.Reason, dnsReportReasonBytes)
	return report
}

func dnsBoundedText(text string, limit int) string {
	text = strings.TrimSpace(strings.Join(strings.Fields(text), " "))
	if limit > 0 && len(text) > limit {
		text = text[:limit]
	}
	return text
}
