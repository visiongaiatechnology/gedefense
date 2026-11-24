package main

import (
	"fmt"
	"net"
	"time"
)

// IngestPacket processes incoming packet metadata and evaluates kinetic rules (Points 11–30).
func (e *KineticEngine) IngestPacket(pkt IngressPacket) []KineticEvent {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.cfg.Enabled || pkt.SrcIP == nil || e.isAllowlistedLocked(pkt.SrcIP) {
		return nil
	}

	sampleCount := int(pkt.Packets)
	if sampleCount <= 0 {
		sampleCount = 1
	}
	e.hitsTotal += uint64(sampleCount)
	now := pkt.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	secEpoch := now.Unix()
	if pkt.WindowEpoch > 0 {
		secEpoch = int64(pkt.WindowEpoch)
	}
	ipKey := pkt.SrcIP.String()

	// 1. Manage IP Tracking Bucket
	bucket, exists := e.ipBuckets[ipKey]
	if !exists {
		if len(e.ipBuckets) >= e.cfg.MaxTrackingIPs {
			e.evictStaleIPBucketLocked(now)
			if len(e.ipBuckets) >= e.cfg.MaxTrackingIPs {
				e.trackingDropsTotal++
				return nil
			}
		}
		isV6, _, _ := SubnetKeys(pkt.SrcIP)
		bucket = &IPTrackingBucket{
			SrcIP:           append(net.IP(nil), pkt.SrcIP...),
			IsV6:            isV6,
			FirstSeen:       now,
			LastSeen:        now,
			PortsSeen:       make(map[uint16]bool),
			PortAttempts:    make(map[uint16]uint16),
			CurrentSecEpoch: secEpoch,
			CurrentMinute:   secEpoch / 60,
			RuleLastSeen:    make(map[string]time.Time),
		}
		e.ipBuckets[ipKey] = bucket
	}

	// Normalize exact SYN/ACK deltas before any window accounting. Kernel
	// aggregates are authoritative; TCP-flag inference is only safe for a true
	// single-packet synthetic/compatibility sample.
	synDelta := int(pkt.SYNCount)
	ackDelta := int(pkt.ACKCount)
	if pkt.Protocol == 6 && sampleCount == 1 {
		isSYN := (pkt.TCPFlags & 0x02) != 0
		isACK := (pkt.TCPFlags & 0x10) != 0
		if synDelta == 0 && isSYN && !isACK {
			synDelta = 1
		}
		if ackDelta == 0 && isACK {
			ackDelta = 1
		}
	}

	// Rules that model scans/rates count connection or protocol activity, not
	// every TCP data/ACK packet. Otherwise a normal HTTPS download would hit the
	// old 35-hit threshold in seconds. For TCP and neutral carry-over samples the
	// exact SYN delta is the connection-attempt signal; non-TCP keeps packet
	// activity as the bounded approximation.
	activityCount := int(pkt.AttemptCount)
	if pkt.WindowEpoch == 0 {
		// Synthetic/compatibility callers predate the explicit kernel activity
		// counter. Infer their semantics without weakening the authenticated IPC
		// contract used by production.
		activityCount = sampleCount
		if pkt.Protocol == 6 || pkt.Protocol == 0 {
			activityCount = synDelta
		}
	}
	if activityCount < 0 || activityCount > sampleCount {
		activityCount = 0
	}

	// Update the exact 1-second connection-attempt window. The monotonic
	// WindowEpoch supplied by the kernel keeps different kernel seconds separate
	// even when several IPC batches are drained in one userspace poll. TCP
	// ACK/data packets do not inflate connection velocity; non-TCP activity uses
	// packet delta as its bounded approximation.
	if bucket.CurrentSecEpoch != secEpoch {
		bucket.CurrentSecEpoch = secEpoch
		bucket.Velocity1s = 0
	}
	if synDelta > 0 {
		// Neutral carry-over events still carry exact SYN deltas and a kernel
		// window epoch, so they can contribute to the correct historical second
		// without borrowing protocol/flag metadata from the next packet.
		bucket.Velocity1s += synDelta
	} else if pkt.Protocol != 0 && pkt.Protocol != 6 {
		bucket.Velocity1s += sampleCount
	}
	bucket.Hits += sampleCount
	bucket.Attempts += activityCount
	bucket.WindowHits += sampleCount
	bucket.LastSeen = now
	e.recordLongWindowsLocked(bucket, secEpoch, sampleCount, activityCount, synDelta, ackDelta)
	e.recordTrafficHistoryLocked(secEpoch, sampleCount, activityCount, synDelta, ackDelta)
	bucket.SYNCount += synDelta
	bucket.ACKCount += ackDelta

	// Track destination port diversity only for connection/activity attempts.
	// Established TCP ACK/data traffic must not manufacture a scanner profile.
	// Both the distinct-port set and per-port attempt counters are bounded.
	if activityCount > 0 && pkt.DstPort > 0 {
		if bucket.PortsSeen[pkt.DstPort] || len(bucket.PortsSeen) < 64 {
			bucket.PortsSeen[pkt.DstPort] = true
			if current := bucket.PortAttempts[pkt.DstPort]; current < ^uint16(0) {
				add := activityCount
				remaining := int(^uint16(0) - current)
				if add > remaining {
					add = remaining
				}
				if add > 0 {
					bucket.PortAttempts[pkt.DstPort] = current + uint16(add)
				}
			}
		}
	}

	// Track packet-level TCP flags only when the sample actually identifies TCP.
	if pkt.Protocol == 6 {
		isSYN := (pkt.TCPFlags & 0x02) != 0
		isRST := (pkt.TCPFlags & 0x04) != 0
		isFIN := (pkt.TCPFlags & 0x01) != 0
		isPSH := (pkt.TCPFlags & 0x08) != 0
		isURG := (pkt.TCPFlags & 0x20) != 0

		// Detect illegal TCP flag combinations (Point 8 & 29). Aggregated
		// samples inherit the flags of their trigger packet, so cap this counter
		// to one observation per aggregate instead of multiplying weak evidence.
		if pkt.TCPFlags == 0 || (isSYN && isRST) || (isFIN && isPSH && isURG) {
			bucket.MalformedCount++
		}
	}

	// 2. Update Subnet Aggregation Buckets
	isV6, subKey, wideKey := SubnetKeys(pkt.SrcIP)
	if !isV6 && subKey != "" && activityCount > 0 {
		v4b, exists := e.subnetV4Buckets[subKey]
		if !exists {
			if len(e.subnetV4Buckets) >= e.maxSubnetBuckets {
				e.evictOldestSubnetV4Locked()
			}
			v4b = &SubnetV4Bucket{
				Subnet: subKey, ActiveIPs: make(map[string]time.Time), WindowStart: now,
			}
			e.subnetV4Buckets[subKey] = v4b
		}
		if v4b.WindowStart.IsZero() || now.Sub(v4b.WindowStart) >= 5*time.Minute {
			v4b.AggregateHits = 0
			v4b.ActiveIPs = make(map[string]time.Time)
			v4b.WindowStart = now
		}
		v4b.AggregateHits += activityCount
		v4b.LastSeen = now
		if len(v4b.ActiveIPs) < 256 {
			v4b.ActiveIPs[ipKey] = now
		}

		if wideKey != "" {
			wb, exists := e.wideV4Buckets[wideKey]
			if !exists {
				if len(e.wideV4Buckets) >= e.maxWideBuckets {
					e.evictOldestWideV4Locked()
				}
				wb = &WideV4Bucket{
					Sector: wideKey, ActiveIPs: make(map[string]time.Time), WindowStart: now,
				}
				e.wideV4Buckets[wideKey] = wb
			}
			if wb.WindowStart.IsZero() || now.Sub(wb.WindowStart) >= 15*time.Minute {
				wb.AggregateHits = 0
				wb.ActiveIPs = make(map[string]time.Time)
				wb.WindowStart = now
			}
			wb.AggregateHits += activityCount
			wb.LastSeen = now
			if len(wb.ActiveIPs) < 1024 {
				wb.ActiveIPs[ipKey] = now
			}
		}
	} else if isV6 && subKey != "" && activityCount > 0 {
		v6b, exists := e.subnetV6Buckets[subKey]
		if !exists {
			if len(e.subnetV6Buckets) >= e.maxSubnetBuckets {
				e.evictOldestSubnetV6Locked()
			}
			v6b = &SubnetV6Bucket{
				Subnet: subKey, ActiveIPs: make(map[string]time.Time), WindowStart: now,
			}
			e.subnetV6Buckets[subKey] = v6b
		}
		if v6b.WindowStart.IsZero() || now.Sub(v6b.WindowStart) >= 5*time.Minute {
			v6b.AggregateHits = 0
			v6b.ActiveIPs = make(map[string]time.Time)
			v6b.WindowStart = now
		}
		v6b.AggregateHits += activityCount
		v6b.LastSeen = now
		if len(v6b.ActiveIPs) < 256 {
			v6b.ActiveIPs[ipKey] = now
		}
	}

	// 3. Rule Evaluation Pipeline
	var generatedEvents []KineticEvent

	// Correlation signal: live Threat Intelligence membership. This signal is
	// deliberately non-destructive by itself; feed BLOCK prefixes are already
	// enforced by the feed manager in kernel maps, while correlate-only feeds
	// enrich the decision chain without becoming a second hidden block path.
	threatMatch := e.threatCorrelate != nil && e.threatCorrelate.ContainsString(ipKey)
	feedBlockMatch := e.threatBlock != nil && e.threatBlock.ContainsString(ipKey)
	if (threatMatch || feedBlockMatch) && e.ruleReadyLocked(bucket, "NET.INGRESS.THREAT_INTEL_MATCH", now) {
		decision := "Threat-intelligence correlate prefix matched ingress source"
		if feedBlockMatch {
			decision = "Threat-intelligence BLOCK prefix matched ingress source; kernel feed policy owns enforcement"
		}
		evt := e.createEventLocked("NET.INGRESS.THREAT_INTEL_MATCH", pkt, bucket, subKey, decision, 80)
		if evt.Metadata == nil {
			evt.Metadata = map[string]interface{}{}
		}
		evt.Metadata["feed_block_match"] = feedBlockMatch
		evt.Metadata["feed_correlate_match"] = threatMatch
		generatedEvents = append(generatedEvents, evt)
	}

	// Rule 1: NET.INGRESS.MALFORMED_TCP
	if bucket.MalformedCount >= 3 && e.ruleReadyLocked(bucket, "NET.INGRESS.MALFORMED_TCP", now) {
		evt := e.createEventLocked("NET.INGRESS.MALFORMED_TCP", pkt, bucket, subKey, "Illegal TCP flag combination (NULL, SYN-RST, or XMAS)", 80)
		generatedEvents = append(generatedEvents, evt)
	}

	// Rule 2: NET.INGRESS.IP_VELOCITY (Burst Limit)
	if bucket.Velocity1s >= e.cfg.VelocityLimit && e.ruleReadyLocked(bucket, "NET.INGRESS.IP_VELOCITY", now) {
		e.velocityBurstsTotal++
		evt := e.createEventLocked("NET.INGRESS.IP_VELOCITY", pkt, bucket, subKey, fmt.Sprintf("High velocity burst: %d hits/sec", bucket.Velocity1s), 85)
		generatedEvents = append(generatedEvents, evt)
	}

	// Rule 3: NET.INGRESS.SYN_FLOOD
	if bucket.SYN1m >= e.cfg.SYNThreshold && (bucket.ACK1m == 0 || bucket.SYN1m >= bucket.ACK1m*e.cfg.SYNAckRatio) && e.ruleReadyLocked(bucket, "NET.INGRESS.SYN_FLOOD", now) {
		evt := e.createEventLocked("NET.INGRESS.SYN_FLOOD", pkt, bucket, subKey, fmt.Sprintf("SYN flood detected: %d SYNs vs %d ACKs in current 1m window", bucket.SYN1m, bucket.ACK1m), 90)
		generatedEvents = append(generatedEvents, evt)
	}

	// Rule 4: fast and low-and-slow port scans. Port diversity is retained for
	// one hour in bounded source buckets so one probe every few minutes cannot
	// evade the old Punisher capability by merely slowing down.
	service, _ := classifyKineticService(e.cfg, pkt.DstPort)
	if len(bucket.PortsSeen) >= e.cfg.PortscanThreshold && now.Sub(bucket.FirstSeen) >= time.Duration(e.cfg.LowSlowMinSeconds)*time.Second && bucket.Velocity1s < maxInt(2, e.cfg.VelocityLimit/2) && e.ruleReadyLocked(bucket, "NET.INGRESS.LOW_SLOW_SCAN", now) {
		e.portscansTotal++
		evt := e.createEventLocked("NET.INGRESS.LOW_SLOW_SCAN", pkt, bucket, subKey, fmt.Sprintf("Low-and-slow scan: %d distinct ports across %s (%d hits/15m)", len(bucket.PortsSeen), now.Sub(bucket.FirstSeen).Round(time.Second), e.windowHitsLocked(bucket, 15*time.Minute)), 92)
		generatedEvents = append(generatedEvents, evt)
	} else if len(bucket.PortsSeen) >= e.cfg.PortscanThreshold && e.ruleReadyLocked(bucket, "NET.INGRESS.PORT_SCAN", now) {
		e.portscansTotal++
		evt := e.createEventLocked("NET.INGRESS.PORT_SCAN", pkt, bucket, subKey, fmt.Sprintf("Portscan detected: %d distinct ports probed", len(bucket.PortsSeen)), 95)
		generatedEvents = append(generatedEvents, evt)
	} else if (service == "database" || service == "admin_panel") && bucket.PortAttempts[pkt.DstPort] >= 3 && e.ruleReadyLocked(bucket, "NET.INGRESS.PORT_SCAN", now) {
		// Dark port instant strike on critical internal ports
		e.portscansTotal++
		evt := e.createEventLocked("NET.INGRESS.PORT_SCAN", pkt, bucket, subKey, fmt.Sprintf("Connection probe to protected service port %d (%s)", pkt.DstPort, service), 95)
		generatedEvents = append(generatedEvents, evt)
	}

	// Rule 5: NET.INGRESS.IP_RATE (Sustained rate limit)
	if bucket.Attempts1m >= e.cfg.IPThreshold && e.ruleReadyLocked(bucket, "NET.INGRESS.IP_RATE", now) {
		evt := e.createEventLocked("NET.INGRESS.IP_RATE", pkt, bucket, subKey, fmt.Sprintf("Single IP connection/activity rate threshold reached: %d attempts/1m (%d attempts lifetime)", bucket.Attempts1m, bucket.Attempts), 75)
		generatedEvents = append(generatedEvents, evt)
	}

	// Rule 6: NET.INGRESS.SUBNET_V4 (Coordinated /24 flood)
	if !isV6 && subKey != "" {
		v4b := e.subnetV4Buckets[subKey]
		if v4b != nil && v4b.AggregateHits >= e.cfg.RangeThreshold && len(v4b.ActiveIPs) >= e.cfg.SubnetMinSources && now.Sub(v4b.LastStrikeAt) >= 30*time.Second {
			v4b.LastStrikeAt = now
			e.subnetStrikesTotal++
			evt := KineticEvent{
				ID:         generateEventID(),
				Time:       now,
				Layer:      LayerIngressNetwork,
				Sensor:     "radix_subnet_aggregator",
				RuleID:     "NET.INGRESS.SUBNET_V4",
				Category:   "botnet_aggregation",
				Severity:   "high",
				Score:      100,
				Confidence: 0.95,
				SourceIP:   ipKey,
				Subnet:     subKey,
				Hits:       v4b.AggregateHits,
				Metadata: map[string]interface{}{
					"active_sources": len(v4b.ActiveIPs),
				},
				Action:   e.resolveAction("NET.INGRESS.SUBNET_V4"),
				Decision: fmt.Sprintf("Coordinated IPv4 /24 flood: %d hits across %d IPs", v4b.AggregateHits, len(v4b.ActiveIPs)),
			}
			evt.ComputeFingerprint()
			e.eventQueue.Push(evt)
			generatedEvents = append(generatedEvents, evt)
		}
	}

	// Rule 7: NET.INGRESS.SUBNET_V6 (Coordinated /64 IPv6 flood)
	if isV6 && subKey != "" {
		v6b := e.subnetV6Buckets[subKey]
		if v6b != nil && v6b.AggregateHits >= e.cfg.IPv6SubThreshold && len(v6b.ActiveIPs) >= e.cfg.IPv6SubnetMinSources && now.Sub(v6b.LastStrikeAt) >= 30*time.Second {
			v6b.LastStrikeAt = now
			e.subnetStrikesTotal++
			evt := KineticEvent{
				ID:         generateEventID(),
				Time:       now,
				Layer:      LayerIngressNetwork,
				Sensor:     "radix_subnet_aggregator",
				RuleID:     "NET.INGRESS.SUBNET_V6",
				Category:   "botnet_aggregation",
				Severity:   "high",
				Score:      100,
				Confidence: 0.95,
				SourceIP:   ipKey,
				Subnet:     subKey,
				Hits:       v6b.AggregateHits,
				Metadata: map[string]interface{}{
					"active_sources": len(v6b.ActiveIPs),
				},
				Action:   e.resolveAction("NET.INGRESS.SUBNET_V6"),
				Decision: fmt.Sprintf("Coordinated IPv6 /64 flood: %d hits across %d IPs", v6b.AggregateHits, len(v6b.ActiveIPs)),
			}
			evt.ComputeFingerprint()
			e.eventQueue.Push(evt)
			generatedEvents = append(generatedEvents, evt)
		}
	}

	// Rule 8: NET.INGRESS.WIDE_V4 (Campaign level macro /16 aggregation)
	if !isV6 && wideKey != "" {
		wb := e.wideV4Buckets[wideKey]
		if wb != nil && wb.AggregateHits >= e.cfg.WideRangeThreshold && len(wb.ActiveIPs) >= e.cfg.WideMinSources && now.Sub(wb.LastStrikeAt) >= 60*time.Second {
			wb.LastStrikeAt = now
			evt := KineticEvent{
				ID:         generateEventID(),
				Time:       now,
				Layer:      LayerIngressNetwork,
				Sensor:     "radix_subnet_aggregator",
				RuleID:     "NET.INGRESS.WIDE_V4",
				Category:   "botnet_aggregation",
				Severity:   "critical",
				Score:      120,
				Confidence: 0.90,
				SourceIP:   ipKey,
				Subnet:     wideKey,
				Hits:       wb.AggregateHits,
				Action:     "warn", // Wide /16 is correlation-only by default (Point 26)
				Decision:   fmt.Sprintf("Mass campaign IPv4 /16 sector surge: %d hits across %d IPs", wb.AggregateHits, len(wb.ActiveIPs)),
			}
			evt.ComputeFingerprint()
			e.eventQueue.Push(evt)
			generatedEvents = append(generatedEvents, evt)
		}
	}

	// Update telemetry in state
	e.syncTelemetryStateLocked()

	return generatedEvents
}

// IngestTLSFindings correlates L7/TLS findings with recent ingress state and
// live threat intelligence. TLS findings may suggest network containment, but
// they can never authorize host-process termination.
func (e *KineticEngine) IngestTLSFindings(clientIP string, summary TLSClientHelloSummary, findings []L7Finding, now time.Time) []KineticEvent {
	if e == nil || len(findings) == 0 {
		return nil
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil
	}
	clientIP = ip.String()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	allowlisted := e.isAllowlistedLocked(ip)
	_, subnet, _ := SubnetKeys(ip)
	bucket := e.ipBuckets[clientIP]
	recentIngress := bucket != nil && now.Sub(bucket.LastSeen) <= time.Minute && bucket.Score >= 65
	feedBlock := e.threatBlock != nil && e.threatBlock.ContainsString(clientIP)
	feedCorrelate := e.threatCorrelate != nil && e.threatCorrelate.ContainsString(clientIP)

	generated := make([]KineticEvent, 0, len(findings))
	for _, finding := range findings {
		def, known := e.rules.Get(finding.RuleID)
		if !known || def.Layer != LayerApplicationL7 {
			continue
		}
		score := finding.Score
		if score <= 0 {
			score = def.DefaultScore
		}
		metadata := map[string]interface{}{
			"l7_finding":  true,
			"l7_location": finding.Location,
		}
		if finding.EvidenceSHA256 != "" {
			metadata["evidence_sha256"] = finding.EvidenceSHA256
		}
		if finding.FingerprintType != "" && finding.Fingerprint != "" {
			metadata["fingerprint_type"] = finding.FingerprintType
			metadata["fingerprint"] = finding.Fingerprint
		}
		if recentIngress {
			score += 15
			metadata["recent_ingress_correlation"] = true
		}
		if feedCorrelate {
			score += 10
			metadata["feed_correlate_match"] = true
		}
		if feedBlock {
			score += 20
			metadata["feed_block_match"] = true
		}
		if score > 180 {
			score = 180
		}
		action := e.resolveAction(finding.RuleID)
		if allowlisted {
			action = "warn"
			metadata["suppressed_by_management_allowlist"] = true
		}
		confidence := float64(finding.Confidence) / 100.0
		if confidence <= 0 || confidence > 1 {
			confidence = 0.8
		}
		if (recentIngress || feedBlock || feedCorrelate) && confidence < 0.99 {
			confidence += 0.04
			if confidence > 0.99 {
				confidence = 0.99
			}
		}

		event := KineticEvent{
			ID:             generateEventID(),
			Time:           now,
			Layer:          LayerApplicationL7,
			Sensor:         "l7_tls_parser",
			RuleID:         finding.RuleID,
			Category:       def.Category,
			Severity:       def.Severity,
			Score:          score,
			Confidence:     confidence,
			SourceIP:       clientIP,
			Protocol:       "tls",
			Domain:         summary.SNI,
			JA3Fingerprint: summary.JA3Hash,
			Subnet:         subnet,
			Action:         action,
			Decision:       finding.Summary,
			Metadata:       metadata,
		}
		event.ComputeFingerprint()
		e.eventQueue.Push(event)
		e.l7StrikesTotal++
		generated = append(generated, event)
		if e.state != nil {
			e.state.AddEvent(Event{
				ID: event.ID, Time: event.Time, Severity: event.Severity, Kind: "kinetic.l7_signal",
				Source: event.Sensor, Message: fmt.Sprintf("[%s] %s (IP: %s)", event.RuleID, event.Decision, event.SourceIP), Target: event.SourceIP,
			})
		}
	}
	e.syncTelemetryStateLocked()
	return generated
}
