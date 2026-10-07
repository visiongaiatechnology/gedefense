package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	kineticPollInterval      = 200 * time.Millisecond
	kineticHealthInterval    = 1 * time.Second
	kineticSweepInterval     = 5 * time.Second
	kineticOfflineAfterFails = 5
	kineticMaxDrainBatches   = 8
)

// startKineticRuntime closes the production path that previously existed only
// in tests: kernel RingBuf -> authenticated Core IPC -> KineticEngine -> safe
// response -> signed policy/evidence. The runtime is deliberately started only
// after the dashboard listener has been created, so startup failures remain
// observable through the normal service lifecycle.
func (s *APIServer) startKineticRuntime() {
	enabled := s.cfg.Kinetic.Enabled
	if s.settings != nil {
		enabled = s.settings.Get().Kinetic.Enabled
	}
	s.setKineticRuntimeEnabled(enabled)
}

func (s *APIServer) setKineticRuntimeEnabled(enabled bool) {
	s.kineticRuntimeMu.Lock()
	defer s.kineticRuntimeMu.Unlock()
	if !enabled {
		if s.kineticCancel != nil {
			s.kineticCancel()
			s.kineticCancel = nil
		}
		s.setKineticSensorState(CoverageDisabled, "disabled", "Kinetic Defense disabled by configuration")
		return
	}
	if s.kineticCancel != nil {
		return
	}
	if s.kinetic == nil {
		s.setKineticSensorState(CoverageOffline, "failed", "Kinetic Defense engine unavailable")
		return
	}
	if s.core == nil {
		s.setKineticSensorState(CoverageOffline, "failed", "Rust Core client unavailable")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.kineticCancel = cancel
	go s.runKineticRuntime(ctx)
}

func (s *APIServer) runKineticRuntime(ctx context.Context) {
	poll := time.NewTicker(kineticPollInterval)
	healthTick := time.NewTicker(kineticHealthInterval)
	sweep := time.NewTicker(kineticSweepInterval)
	defer poll.Stop()
	defer healthTick.Stop()
	defer sweep.Stop()

	eventFailures := 0
	healthFailures := 0
	var lastHealth *CoreIngressHealth

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-poll.C:
			var pollErr error
			for batch := 0; batch < kineticMaxDrainBatches; batch++ {
				events, err := s.core.IngressEvents()
				if err != nil {
					pollErr = err
					break
				}
				for _, raw := range events {
					generated := s.kinetic.IngestPacket(IngressPacket{
						Family: raw.Family, Protocol: raw.Protocol, TCPFlags: raw.TCPFlags, AttemptCount: uint32(raw.AttemptCount),
						SrcIP: raw.Source, DstIP: raw.Destination, SrcPort: raw.SrcPort, DstPort: raw.DstPort,
						Packets: raw.Packets, SYNCount: raw.SYNCount, ACKCount: raw.ACKCount, Bytes: raw.Bytes,
						WindowEpoch: raw.WindowEpoch, Timestamp: now.UTC(),
					})
					s.handleKineticDecisions(generated)
				}
				if len(events) == 0 {
					break
				}
			}
			if pollErr != nil {
				eventFailures++
				status, selfTest, reason := evaluateKineticSensorHealth(eventFailures, healthFailures, lastHealth, lastHealth)
				s.setKineticSensorState(status, selfTest, fmt.Sprintf("%s; event drain: %v", reason, pollErr))
				continue
			}
			eventFailures = 0
		case <-healthTick.C:
			current, err := s.core.IngressHealth()
			if err != nil {
				healthFailures++
				status, selfTest, reason := evaluateKineticSensorHealth(eventFailures, healthFailures, lastHealth, nil)
				s.setKineticSensorState(status, selfTest, fmt.Sprintf("%s; health query: %v", reason, err))
				continue
			}
			healthFailures = 0
			s.state.UpdateKineticTelemetry(func(t *KineticTelemetry) {
				t.KernelEventsEmitted = current.EventsEmitted
				t.KernelRingDrops = current.RingDrops
				t.KernelTrackInsertFailures = current.TrackInsertFailures
				t.IngressMode = current.Mode
			})
			status, selfTest, reason := evaluateKineticSensorHealth(eventFailures, healthFailures, lastHealth, &current)
			s.setKineticSensorState(status, selfTest, reason)
			copyHealth := current
			lastHealth = &copyHealth
		case now := <-sweep.C:
			// The Kinetic runtime owns only detector bucket ageing here. Temporary
			// network-policy expiry is owned by the single central expiry worker in
			// main.go. Having two independent expiry consumers raced State.Expired(),
			// which could make policy persistence/evidence nondeterministic.
			s.kinetic.Sweep(now.UTC())
		}
	}
}

func evaluateKineticSensorHealth(eventFailures, healthFailures int, previous, current *CoreIngressHealth) (SensorCoverageStatus, string, string) {
	if eventFailures >= kineticOfflineAfterFails || healthFailures >= kineticOfflineAfterFails {
		return CoverageOffline, "failed", fmt.Sprintf("kernel ingress channel unavailable (event_failures=%d health_failures=%d)", eventFailures, healthFailures)
	}
	if eventFailures > 0 || healthFailures > 0 {
		return CoverageDegraded, "degraded", fmt.Sprintf("kernel ingress channel unstable (event_failures=%d health_failures=%d)", eventFailures, healthFailures)
	}
	if current == nil {
		return CoverageOffline, "unverified", "kernel ingress health has not been verified"
	}
	if previous != nil && (current.RingDrops > previous.RingDrops || current.TrackInsertFailures > previous.TrackInsertFailures) {
		return CoverageDegraded, "degraded", fmt.Sprintf(
			"kernel ingress pressure detected (ring_drops=%d tracking_insert_failures=%d)",
			current.RingDrops, current.TrackInsertFailures,
		)
	}
	if current.EventsEmitted == 0 {
		return CoverageOnline, "pass", "kernel ingress program and bounded health maps verified; no ingress events emitted yet"
	}
	// The hook is named in the reason. A pass on native XDP and a pass on TC ingress are
	// not the same statement about a host, and reporting both as "verified kernel ingress
	// producer" hid which one the operator actually has.
	return CoverageOnline, "pass", fmt.Sprintf("verified kernel ingress producer via %s (%d events emitted)", describeIngressMode(current.Mode), current.EventsEmitted)
}

// describeIngressMode turns the mode token into something an operator can read, and
// states plainly when the core did not report one rather than implying native XDP.
func describeIngressMode(mode string) string {
	switch mode {
	case "NATIVE_XDP":
		return "native XDP in the driver path"
	case "GENERIC_XDP":
		return "generic XDP (the driver has no native hook)"
	case "TC_INGRESS":
		return "TC ingress (no XDP was available, enforcement is at the traffic-control layer)"
	case "":
		return "an unreported hook (the core did not state its enforcement mode)"
	default:
		return mode
	}
}

func (s *APIServer) setKineticSensorState(status SensorCoverageStatus, selfTest, reason string) {
	now := time.Now().UTC()
	coverage := SensorCoverage{
		Name: "xdp_ingress", Layer: LayerIngressNetwork, Status: status, Required: true,
		SelfTest: selfTest, CoverageReason: reason,
	}
	if status == CoverageOnline {
		coverage.LastOK = &now
	} else {
		coverage.LastError = reason
	}
	s.state.SetSensorCoverage(coverage)

	globalNetworkMode, _ := s.state.Modes()
	kinetic := KineticRuntimeSettings{Enabled: s.cfg.Kinetic.Enabled, EnforcementMode: s.cfg.Kinetic.EnforcementMode}
	if s.settings != nil {
		kinetic = s.settings.Get().Kinetic
	}
	s.state.UpdateKineticTelemetry(func(t *KineticTelemetry) {
		if t.Layers == nil {
			t.Layers = make(map[DefenseLayer]DefenseLayerState)
		}
		mode := EnforcementObserve
		if globalNetworkMode == "enforce" {
			switch kinetic.EnforcementMode {
			case "contain":
				mode = EnforcementContain
			case "block":
				mode = EnforcementBlock
			}
		}
		healthy := status == CoverageOnline
		t.Layers[LayerIngressNetwork] = DefenseLayerState{
			Layer: LayerIngressNetwork, DetectionEnabled: kinetic.Enabled,
			DetectionHealthy: healthy, EnforcementMode: mode,
			EnforcementHealthy: healthy || mode == EnforcementObserve,
			Coverage:           status, ModeReason: reason,
		}
	})
	if status != CoverageOnline && s.release != nil {
		// Do not wait for the slower periodic release evaluator while an enforced
		// Kinetic sensor is known to be degraded/offline. Evaluate immediately so
		// AutoDegrade can clear active response state before more decisions arrive.
		s.release.Evaluate()
	}
}

func (s *APIServer) handleKineticDecisions(events []KineticEvent) {
	if len(events) == 0 || s.kineticResponse == nil {
		return
	}
	// Several rules can fire for the same packet aggregate. Execute at most one
	// response per target per ingestion batch to avoid artificial reputation/TTL
	// escalation caused by correlated signals from the same observation.
	strongest := make(map[string]KineticEvent)
	for _, event := range events {
		if event.Action != "contain" && event.Action != "block" {
			continue
		}
		target := kineticEventTarget(event)
		if target == "" {
			continue
		}
		current, exists := strongest[target]
		if !exists || event.Score > current.Score || (event.Score == current.Score && event.Confidence > current.Confidence) {
			strongest[target] = event
		}
	}

	for target, event := range strongest {
		banTTL := s.cfg.Kinetic.BanTTLSeconds
		if s.settings != nil && s.settings.Get().Kinetic.BanTTLSeconds > 0 {
			banTTL = s.settings.Get().Kinetic.BanTTLSeconds
		}
		ttl := time.Duration(banTTL) * time.Second
		decision := NetworkDecision{
			Target: target, RuleIDs: []string{event.RuleID}, Score: event.Score,
			Confidence: event.Confidence, ContributorCount: kineticContributorCount(event), SuggestedAction: event.Action, BaseTTL: ttl,
			Reason: event.Decision, EvidenceRoot: event.EvidenceID, Timestamp: event.Time,
		}
		entry, err := s.kineticResponse.ExecuteDecision(decision)
		if err != nil {
			severity := "low"
			kind := "kinetic.response_suppressed"
			expectedSuppression := errors.Is(err, ErrAllowlistProtected) || errors.Is(err, ErrBroadSectorProtected) ||
				errors.Is(err, ErrSubnetEvidenceLow) || errors.Is(err, ErrRateLimitThrottled) ||
				errors.Is(err, ErrEmergencyStopActive) || errors.Is(err, ErrResponseNotReady) || errors.Is(err, ErrAutoContainDisabled)
			if expectedSuppression {
				s.kineticResponse.RecordSuppressed()
			} else {
				severity = "high"
				kind = "kinetic.response_failed"
				s.kineticResponse.RecordFailure()
			}
			s.state.AddEvent(Event{Time: event.Time, Severity: severity, Kind: kind, Source: "kinetic_response_engine", Message: fmt.Sprintf("%s: %v", event.RuleID, err), Target: target})
			if errors.Is(err, ErrKernelStateDivergent) && s.release != nil {
				_ = s.release.FailSafe("kinetic kernel apply compensation failed")
			}
			continue
		}
		if err := persistPolicy(s.policy, s.cfg, s.state); err != nil {
			rollbackErr := s.kineticResponse.RollbackApplied(entry)
			s.kineticResponse.RecordApplyRollback(decision, entry, err, rollbackErr)
			s.state.AddEvent(Event{Time: event.Time, Severity: "critical", Kind: "kinetic.policy_persist_failed", Source: "kinetic_runtime", Message: err.Error(), Target: entry.Target})
			if rollbackErr != nil && s.release != nil {
				_ = s.release.FailSafe("kinetic block policy rollback failed")
			}
			continue
		}
		if err := s.kineticResponse.CommitApplied(decision, entry); err != nil {
			s.kineticResponse.RecordFailure()
			s.state.AddEvent(Event{Time: event.Time, Severity: "critical", Kind: "kinetic.evidence_commit_failed", Source: "kinetic_response_engine", Message: err.Error(), Target: entry.Target})
			if s.release != nil {
				_ = s.release.FailSafe("kinetic containment evidence commit failed")
			}
			continue
		}
		s.state.AddEvent(Event{Time: event.Time, Severity: "high", Kind: "kinetic.block_applied", Source: "kinetic_response_engine", Message: fmt.Sprintf("%s applied for %s", event.RuleID, entry.Target), Target: entry.Target})
	}
}

func kineticContributorCount(event KineticEvent) int {
	if event.Metadata == nil {
		return 0
	}
	v, ok := event.Metadata["active_sources"]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case uint:
		return int(n)
	case uint32:
		return int(n)
	case uint64:
		if n > uint64(^uint(0)>>1) {
			return 0
		}
		return int(n)
	case float64:
		if n < 0 || n != float64(int(n)) {
			return 0
		}
		return int(n)
	default:
		return 0
	}
}

func kineticEventTarget(event KineticEvent) string {
	switch event.RuleID {
	case "NET.INGRESS.SUBNET_V4", "NET.INGRESS.SUBNET_V6":
		return event.Subnet
	case "NET.INGRESS.WIDE_V4":
		return "" // campaign correlation only; broad automatic blocks are forbidden.
	default:
		return event.SourceIP
	}
}
