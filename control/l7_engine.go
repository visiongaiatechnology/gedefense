// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// L7Engine evaluates one application-layer request or TLS handshake against a
// single immutable Fabric settings snapshot. Detection wiring is read from the
// snapshot, so an operator revision takes effect atomically on the next
// inspection and never mid-request.
type L7Engine struct {
	live             *l7Runtime
	normalizer       *L7Normalizer
	detectors        []l7Detector
	limiter          *L7RateLimiter
	xdr              *XDREngine
	release          *ReleaseController
	canBlock         func() bool
	responseDetector *l7ResponseDetector
	tls              *TLSSecurityEngine
	admissionSlots   chan struct{}
	inspectionSlots  chan struct{}
}

func NewL7Engine(cfg L7Config, xdr *XDREngine, release *ReleaseController) (*L7Engine, error) {
	if err := validateL7EngineConfig(cfg); err != nil {
		return nil, err
	}
	patternDetector, err := newL7PatternDetector()
	if err != nil {
		return nil, err
	}
	ssrfDetector, err := newL7SSRFDetector()
	if err != nil {
		return nil, err
	}
	responseDetector, err := newL7ResponseDetector()
	if err != nil {
		return nil, err
	}
	var airlock *AirlockInspector
	if xdr != nil {
		airlock = xdr.Airlock()
	}
	live := newL7Runtime(defaultL7FabricSettings(cfg), 0)
	engine := &L7Engine{
		live: live, normalizer: newL7NormalizerWithRuntime(cfg, live), limiter: newL7RateLimiterWithRuntime(cfg),
		xdr: xdr, release: release, responseDetector: responseDetector,
		admissionSlots:  make(chan struct{}, cfg.MaxConcurrent),
		inspectionSlots: make(chan struct{}, cfg.MaxConcurrent),
		detectors:       []l7Detector{patternDetector, ssrfDetector, l7ProtocolDetector{}, l7UploadDetector{live: live, airlock: airlock}},
	}
	if cfg.TLSEnabled {
		engine.tls = NewTLSSecurityEngine(cfg.TLSAllowedDomains, cfg.TLSFloodThreshold, cfg.TLSSNIStrikeThreshold, cfg.TLSAntiSpoof, cfg.MaxTrackedClients)
		if cfg.TLSJA3File != "" {
			if err := engine.tls.LoadFingerprintFile(cfg.TLSJA3File); err != nil {
				return nil, fmt.Errorf("load TLS fingerprint set: %w", err)
			}
		}
	}
	engine.canBlock = func() bool {
		if engine.release == nil {
			return false
		}
		status := engine.release.Status()
		return status.Phase == ReleasePhaseEnforce && !status.EmergencyStop && status.Ready
	}
	return engine, nil
}

func validateL7EngineConfig(cfg L7Config) error {
	if cfg.MaxConcurrent < 1 || cfg.MaxBodyBytes < 0 || cfg.MaxInspectionBytes < cfg.MaxBodyBytes || cfg.MaxDecodedValues < 1 {
		return fmt.Errorf("%w: invalid engine resource bounds", ErrL7InvalidRequest)
	}
	if cfg.AlertScore < 1 || cfg.BlockScore <= cfg.AlertScore || cfg.BlockScore > 250 {
		return fmt.Errorf("%w: invalid engine score thresholds", ErrL7InvalidRequest)
	}
	if cfg.ClientRatePerMinute < 1 || cfg.ClientRateBurst < 1 || cfg.SensitiveRatePerMinute < 1 || cfg.SensitiveRateBurst < 1 || cfg.SensitiveGlobalRatePerMinute < 1 || cfg.SensitiveGlobalRateBurst < 1 {
		return fmt.Errorf("%w: invalid engine rate limits", ErrL7InvalidRequest)
	}
	if cfg.MaxTrackedClients < 1 {
		return fmt.Errorf("%w: invalid engine tracking bound", ErrL7InvalidRequest)
	}
	return nil
}

// LiveSettings returns the fabric revision that is actually active in the
// running engine. Restart-class keys keep their boot value here until the
// process is restarted, which is what the module API reports.
func (e *L7Engine) LiveSettings() L7FabricSettings {
	if e == nil || e.live == nil {
		return L7FabricSettings{}
	}
	return e.live.activeFabric()
}

// LiveRevision returns the fabric revision projected onto the running engine.
func (e *L7Engine) LiveRevision() uint64 {
	if e == nil || e.live == nil {
		return 0
	}
	snapshot := e.live.current()
	if snapshot == nil {
		return 0
	}
	return snapshot.revision
}

func (e *L7Engine) acquireAdmission(ctx context.Context) error {
	if e == nil || e.admissionSlots == nil {
		return fmt.Errorf("%w: l7 admission gate unavailable", ErrL7InvalidRequest)
	}
	select {
	case e.admissionSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *L7Engine) releaseAdmission() {
	if e == nil || e.admissionSlots == nil {
		return
	}
	<-e.admissionSlots
}

func (e *L7Engine) Inspect(ctx context.Context, req L7InspectionRequest) (L7InspectionResponse, error) {
	response, _, err := e.inspect(ctx, req, nil, false)
	return response, err
}

func (e *L7Engine) InspectRaw(ctx context.Context, req L7InspectionRequest, body []byte) (L7InspectionResponse, l7NormalizedRequest, error) {
	return e.inspect(ctx, req, body, true)
}

func (e *L7Engine) inspect(ctx context.Context, req L7InspectionRequest, body []byte, raw bool) (L7InspectionResponse, l7NormalizedRequest, error) {
	if err := ctx.Err(); err != nil {
		return L7InspectionResponse{}, l7NormalizedRequest{}, err
	}
	snapshot := e.live.current()
	if snapshot == nil {
		return L7InspectionResponse{}, l7NormalizedRequest{}, fmt.Errorf("%w: l7 runtime configuration unavailable", ErrL7InvalidRequest)
	}
	select {
	case e.inspectionSlots <- struct{}{}:
		defer func() { <-e.inspectionSlots }()
	case <-ctx.Done():
		return L7InspectionResponse{}, l7NormalizedRequest{}, ctx.Err()
	}
	var normalized l7NormalizedRequest
	var err error
	if raw {
		normalized, err = e.normalizer.NormalizeRawWith(req, body, snapshot)
	} else {
		normalized, err = e.normalizer.NormalizeWith(req, snapshot)
	}
	if err != nil {
		return L7InspectionResponse{}, l7NormalizedRequest{}, err
	}
	now := time.Now().UTC()
	findings := make([]L7Finding, 0, 12)
	if allowed, scope := e.limiter.Evaluate(snapshot, normalized.RemoteIP, normalized.Host, normalized.RatePath, normalized.Method, now); !allowed {
		findings = append(findings, newL7Finding(
			"L7.RATE_LIMIT."+strings.ToUpper(strings.ReplaceAll(scope, "-", "_")), "rate-limit", "high", 95, 99,
			"request", normalized.RemoteIP+"|"+normalized.Host+"|"+normalized.Path, "Request rate exceeded the configured L7 budget",
		))
	}
	for _, detector := range e.detectors {
		if err := ctx.Err(); err != nil {
			return L7InspectionResponse{}, l7NormalizedRequest{}, err
		}
		detected, detectErr := detector.Detect(ctx, normalized, snapshot)
		if detectErr != nil {
			return L7InspectionResponse{}, l7NormalizedRequest{}, detectErr
		}
		findings = append(findings, detected...)
		if len(findings) >= 64 {
			findings = findings[:64]
			break
		}
	}
	if e.tls != nil && len(findings) < 64 {
		findings = append(findings, e.tls.RecordHTTPRequestForHost(normalized.RemoteIP, normalized.Host, now)...)
		if len(findings) > 64 {
			findings = findings[:64]
		}
	}
	kept, blockable := snapshot.applyRuleOverrides(findings)
	score, confidence, unique := aggregateL7Findings(kept)
	blockScore, _, _ := aggregateL7Findings(blockable)
	response := L7InspectionResponse{
		RequestID: normalized.RequestID, Decision: "allow", Score: score, Confidence: confidence,
		Reason: "no finding crossed the alert threshold", BodySHA256: normalized.BodySHA256, Findings: unique,
	}
	if score >= snapshot.cfg.AlertScore && len(unique) > 0 {
		response.Decision = "observe"
		response.Reason = "security findings recorded"
	}
	// Only findings that are not marked alert-only may authorise a block. With
	// an empty operator registry the block score equals the aggregate score and
	// the historical behaviour is preserved exactly.
	if blockScore >= snapshot.cfg.BlockScore && len(unique) > 0 {
		if snapshot.cfg.Mode == "block" && e.releaseGateAllowsBlock() {
			response.Decision = "block"
			response.Enforced = true
			response.Reason = "request blocked by L7 policy"
		} else {
			response.Decision = "observe"
			response.Reason = "block threshold reached; release gate keeps L7 in observe"
		}
	}
	if e.xdr != nil && len(unique) > 0 {
		e.xdr.RecordL7Inspection(normalized, response)
	}
	return response, normalized, nil
}

// InspectTLSHandshake evaluates one ClientHello against the active snapshot and
// applies the operator rule registry, including the administrable unknown
// fingerprint behaviour.
func (e *L7Engine) InspectTLSHandshake(clientIP string, payload []byte, now time.Time) (TLSClientHelloSummary, []L7Finding, error) {
	if e == nil || e.tls == nil {
		return TLSClientHelloSummary{}, nil, errors.New("TLS inspection is disabled")
	}
	snapshot := e.live.current()
	if snapshot == nil || !snapshot.cfg.TLSEnabled {
		return TLSClientHelloSummary{}, nil, errors.New("TLS inspection is disabled")
	}
	if len(payload) == 0 || len(payload) > snapshot.cfg.TLSMaxClientHelloBytes {
		return TLSClientHelloSummary{}, nil, fmt.Errorf("%w: TLS ClientHello exceeds configured bound", ErrL7ResourceLimit)
	}
	if net.ParseIP(clientIP) == nil {
		return TLSClientHelloSummary{}, nil, fmt.Errorf("%w: invalid TLS client IP", ErrL7InvalidRequest)
	}
	summary, findings := e.tls.InspectHandshakeDetailed(clientIP, payload, now)
	if len(findings) < 16 && snapshot.unknownFingerprint == "alert" && summary.JA3Hash != "" && !e.tls.KnowsFingerprint(summary.JA3Hash) {
		findings = append(findings, L7Finding{
			RuleID: "TLS.JA3.UNKNOWN", Category: "threat_signature", Severity: "low",
			Score: clampScore(snapshot.unknownFingerprintScore), Confidence: 70,
			Location: "tls.client_hello.ja3", FingerprintType: "ja3", Fingerprint: summary.JA3Hash,
			Summary: "TLS ClientHello used a structurally valid fingerprint that is not part of the local signature set",
		})
	}
	kept, _ := snapshot.applyRuleOverrides(findings)
	return summary, kept, nil
}

// InspectResponse is implemented in l7_response.go and applies the operator
// rule registry from the active snapshot.

func (e *L7Engine) TLSFingerprintStatus() (version int, source string, signatures, profiles int) {
	if e == nil || e.tls == nil {
		return 0, "", 0, 0
	}
	return e.tls.FingerprintStatus()
}

func (e *L7Engine) releaseGateAllowsBlock() bool {
	return e.canBlock != nil && e.canBlock()
}

func l7FindingSummary(findings []L7Finding) string {
	if len(findings) == 0 {
		return ""
	}
	ids := make([]string, 0, minInt(len(findings), 6))
	for i, finding := range findings {
		if i >= 6 {
			break
		}
		ids = append(ids, finding.RuleID)
	}
	return fmt.Sprintf("%d L7 finding(s): %s", len(findings), strings.Join(ids, ","))
}
