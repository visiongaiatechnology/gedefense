// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type L7Engine struct {
	cfg              L7Config
	normalizer       *L7Normalizer
	detectors        []l7Detector
	limiter          *L7RateLimiter
	xdr              *XDREngine
	release          *ReleaseController
	canBlock         func() bool
	responseDetector *l7ResponseDetector
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
	engine := &L7Engine{
		cfg: cfg, normalizer: NewL7Normalizer(cfg), limiter: NewL7RateLimiter(cfg), xdr: xdr, release: release, responseDetector: responseDetector,
		admissionSlots:  make(chan struct{}, cfg.MaxConcurrent),
		inspectionSlots: make(chan struct{}, cfg.MaxConcurrent),
		detectors:       []l7Detector{patternDetector, ssrfDetector, l7ProtocolDetector{}, l7UploadDetector{cfg: cfg, airlock: airlock}},
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
	if cfg.MaxConcurrent < 1 || cfg.MaxBodyBytes < 1 || cfg.MaxInspectionBytes < cfg.MaxBodyBytes || cfg.MaxDecodedValues < 1 {
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
	select {
	case e.inspectionSlots <- struct{}{}:
		defer func() { <-e.inspectionSlots }()
	case <-ctx.Done():
		return L7InspectionResponse{}, l7NormalizedRequest{}, ctx.Err()
	}
	var normalized l7NormalizedRequest
	var err error
	if raw {
		normalized, err = e.normalizer.NormalizeRaw(req, body)
	} else {
		normalized, err = e.normalizer.Normalize(req)
	}
	if err != nil {
		return L7InspectionResponse{}, l7NormalizedRequest{}, err
	}
	now := time.Now().UTC()
	findings := make([]L7Finding, 0, 12)
	if allowed, scope := e.limiter.Evaluate(normalized.RemoteIP, normalized.Host, normalized.RatePath, normalized.Method, now); !allowed {
		findings = append(findings, newL7Finding(
			"L7.RATE_LIMIT."+strings.ToUpper(strings.ReplaceAll(scope, "-", "_")), "rate-limit", "high", 95, 99,
			"request", normalized.RemoteIP+"|"+normalized.Host+"|"+normalized.Path, "Request rate exceeded the configured L7 budget",
		))
	}
	for _, detector := range e.detectors {
		if err := ctx.Err(); err != nil {
			return L7InspectionResponse{}, l7NormalizedRequest{}, err
		}
		detected, detectErr := detector.Detect(ctx, normalized)
		if detectErr != nil {
			return L7InspectionResponse{}, l7NormalizedRequest{}, detectErr
		}
		findings = append(findings, detected...)
		if len(findings) >= 64 {
			findings = findings[:64]
			break
		}
	}
	score, confidence, unique := aggregateL7Findings(findings)
	response := L7InspectionResponse{
		RequestID: normalized.RequestID, Decision: "allow", Score: score, Confidence: confidence,
		Reason: "no finding crossed the alert threshold", BodySHA256: normalized.BodySHA256, Findings: unique,
	}
	if score >= e.cfg.AlertScore && len(unique) > 0 {
		response.Decision = "observe"
		response.Reason = "security findings recorded"
	}
	if score >= e.cfg.BlockScore && len(unique) > 0 {
		if e.cfg.Mode == "block" && e.releaseGateAllowsBlock() {
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
