// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Periodic lifecycle loops and engine accessors split out of server.go
// (refactoring wave 1a, structure-only). Run/RunWithReady/Shutdown stay in
// server.go and start/stop these loops; the loop bodies (including the periodic
// hardening-posture evaluation) live here so server.go stays focused on the struct,
// constructor, routes and request pipeline.

import (
	"context"
	"fmt"
	"time"
)

// caseEngine returns the case engine when it is attached.
func (s *APIServer) caseEngine() *CaseEngine {
	if s.state == nil {
		return nil
	}
	return s.state.Cases()
}

// quarantineApplier returns the quarantine transaction applier when the
// transaction engine is attached. It is reached through the engine rather than
// stored separately, so there is one instance and no second policy target.
func (s *APIServer) quarantineApplier() *QuarantineTransactionApplier {
	if s.state == nil {
		return nil
	}
	engine := s.state.Transactions()
	if engine == nil {
		return nil
	}
	return engine.QuarantineApplier()
}

// startHardeningPosture runs the administrable periodic posture evaluation. It
// is the only place that raises a posture event, so the operator sees a change
// once instead of on every dashboard poll.
func (s *APIServer) startHardeningPosture() {
	if s.hardening == nil {
		return
	}
	s.hardeningMu.Lock()
	if s.hardeningCancel != nil {
		s.hardeningMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.hardeningCancel = cancel
	if s.hardeningMemo == nil {
		s.hardeningMemo = make(map[string]string)
	}
	s.hardeningMu.Unlock()

	go func() {
		for {
			interval := time.Duration(hardeningDefaultPostureIntervalSeconds) * time.Second
			autoScan := true
			if s.settings != nil {
				posture := effectiveHardeningSettings(s.settings.Get()).Posture
				autoScan = posture.AutoScan
				if posture.ScanIntervalSeconds > 0 {
					interval = time.Duration(posture.ScanIntervalSeconds) * time.Second
				}
			}
			if autoScan {
				s.evaluateHardeningPosture()
			} else {
				// A disabled automatic scan still re-reads the policy regularly so
				// re-enabling it does not require a restart.
				interval = 30 * time.Second
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func (s *APIServer) stopHardeningPosture() {
	s.hardeningMu.Lock()
	cancel := s.hardeningCancel
	s.hardeningCancel = nil
	s.hardeningMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// startTrustWatch re-verifies the signed policy document and the boot evidence
// requirements periodically. Without it a tampered state file, a replayed older
// revision or a boot anchor that changed after startup would only be noticed at
// the next operator action.
func (s *APIServer) startTrustWatch() {
	if s.policy == nil && s.bootTrust == nil {
		return
	}
	s.trustMu.Lock()
	if s.trustCancel != nil {
		s.trustMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.trustCancel = cancel
	s.trustMu.Unlock()

	go func() {
		lastVerified := true
		lastLevel := ""
		for {
			interval := time.Duration(defaultPolicyTrustFabricSettings().VerifyIntervalSeconds) * time.Second
			if s.settings != nil {
				configured := effectivePolicyTrustSettings(s.settings.Get()).VerifyIntervalSeconds
				if configured >= policyTrustVerifyFloor {
					interval = time.Duration(configured) * time.Second
				}
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if s.state == nil {
				continue
			}
			if s.policy != nil {
				if _, err := s.policy.Load(); err != nil {
					if lastVerified {
						s.state.AddEvent(Event{Severity: "critical", Kind: "policy.verification_failed", Source: "policy",
							Message: "Signed policy document failed periodic verification; the last known-good policy remains active"})
					}
					lastVerified = false
				} else {
					lastVerified = true
					s.state.SetPolicyStatus(s.policy.Status())
				}
			}
			if s.bootTrust != nil {
				report := s.bootTrust.Collect()
				if report.Summary != lastLevel {
					if lastLevel != "" {
						s.state.AddEvent(Event{Severity: "warning", Kind: "boot_trust.changed", Source: "boot",
							Message: "Boot trust evidence changed: " + report.Summary})
					}
					lastLevel = report.Summary
				}
			}
		}
	}()
}

func (s *APIServer) stopTrustWatch() {
	s.trustMu.Lock()
	cancel := s.trustCancel
	s.trustCancel = nil
	s.trustMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// startCaseSweep closes open cases that have been idle longer than the
// administrable age. A zero setting disables it, which is the default: closing a
// case is an operator judgement, and the sweep never touches a case an operator
// moved to a non-open status.
func (s *APIServer) startCaseSweep() {
	if s.caseEngine() == nil {
		return
	}
	s.trustMu.Lock()
	if s.caseCancel != nil {
		s.trustMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.caseCancel = cancel
	s.trustMu.Unlock()

	go func() {
		for {
			interval := 30 * time.Minute
			enabled := false
			if s.settings != nil {
				enabled = effectiveForensicsSettings(s.settings.Get()).Cases.AutoCloseAfterHours > 0
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if !enabled {
				continue
			}
			engine := s.caseEngine()
			if engine == nil {
				continue
			}
			policy := engine.policySnapshot()
			status := engine.Status(policy.listMaxLimit)
			now := time.Now().UTC()
			for _, record := range status.Cases {
				if !autoCloseCandidate(record, now, policy) {
					continue
				}
				if _, err := engine.SetStatus(record.ID, "resolved", "automatically closed after the configured inactivity window"); err != nil {
					continue
				}
				if s.state != nil {
					s.state.AddEvent(Event{Severity: "info", Kind: "case.auto_closed", Source: "forensics",
						Message: fmt.Sprintf("Case %s was closed automatically after %d hours without activity", record.ID, policy.autoCloseHours)})
				}
			}
		}
	}()
}

func (s *APIServer) stopCaseSweep() {
	s.trustMu.Lock()
	cancel := s.caseCancel
	s.caseCancel = nil
	s.trustMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// startPackageIntegrity runs the administrable package verification schedule. It
// re-reads enablement and cadence on every cycle, so an operator change needs no
// restart.
func (s *APIServer) startPackageIntegrity() {
	if s.packages == nil {
		return
	}
	s.packageMu.Lock()
	if s.packageCancel != nil {
		s.packageMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.packageCancel = cancel
	s.packageMu.Unlock()

	go func() {
		for {
			interval := time.Hour
			run := false
			if s.settings != nil {
				policy := effectiveIntegritySettings(s.settings.Get()).Packages
				if policy.IntervalHours >= 1 {
					interval = time.Duration(policy.IntervalHours) * time.Hour
				}
				run = policy.Enabled && policy.AutoScan
			}
			if run && !s.packages.Status().Running {
				s.packages.Start(s.recordPackageIntegrityOutcome)
			}
			if !run {
				interval = time.Minute
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func (s *APIServer) stopPackageIntegrity() {
	s.packageMu.Lock()
	cancel := s.packageCancel
	s.packageCancel = nil
	s.packageMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// recordPackageIntegrityOutcome publishes the scheduled scan result as an event.
func (s *APIServer) recordPackageIntegrityOutcome(status PackageIntegrityStatus) {
	if s.state == nil {
		return
	}
	if status.Modified > 0 || status.Missing > 0 || status.Errors > 0 {
		s.state.AddEvent(Event{Severity: "warning", Kind: "package_integrity.deviation", Source: "integrity",
			Message: fmt.Sprintf("Scheduled package verification found %d modified and %d missing file(s) across %d package(s)", status.Modified, status.Missing, status.Packages)})
		return
	}
	s.state.AddEvent(Event{Severity: "info", Kind: "package_integrity.verified", Source: "integrity",
		Message: fmt.Sprintf("Scheduled package verification confirmed %d package(s) and %d file(s)", status.Packages, status.Files)})
}

// evaluateHardeningPosture collects the live posture and reports a level change
// or a required-domain regression exactly once per transition.
func (s *APIServer) evaluateHardeningPosture() {
	if s.hardening == nil || s.state == nil {
		return
	}
	settings := HardeningPostureSettings{}
	if s.settings != nil {
		settings = effectiveHardeningSettings(s.settings.Get()).Posture
	}
	report := s.hardening.Collect(s.state.Snapshot(), s.bootTrust.Collect())
	report.Checks = append(report.Checks, packageIntegrityPostureCheck(s.packages.Status()))
	posture := summarizeHardening(report.CollectedAt, report.Checks, settings.thresholds())
	findings := assessHardeningPosture(posture, settings)

	s.hardeningMu.Lock()
	defer s.hardeningMu.Unlock()
	if posture.Level != s.hardeningLevel {
		severity := "info"
		switch posture.Level {
		case "CRITICAL":
			severity = "critical"
		case "BASIC":
			severity = "warning"
		}
		s.state.AddEvent(Event{Severity: severity, Kind: "hardening.posture_changed", Source: "hardening",
			Message: fmt.Sprintf("Host hardening posture is now %s at %d%% compliance", posture.Level, posture.Score)})
		s.hardeningLevel = posture.Level
	}
	for _, finding := range findings {
		previous, seen := s.hardeningMemo[finding.Domain]
		if seen && previous == finding.State {
			continue
		}
		s.hardeningMemo[finding.Domain] = finding.State
		if finding.State == "PROTECTED" {
			continue
		}
		severity := "warning"
		if finding.State == "CRITICAL" || finding.State == "UNAVAILABLE" {
			severity = "critical"
		}
		s.state.AddEvent(Event{Severity: severity, Kind: "hardening.required_domain", Source: "hardening",
			Message: fmt.Sprintf("Required posture domain %s is %s at %d%% (threshold %d): %s", finding.Title, finding.State, finding.Score, finding.Threshold, finding.Reason)})
	}
}
