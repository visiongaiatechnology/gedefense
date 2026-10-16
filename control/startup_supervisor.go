// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The startup self-check.
//
// After every restart the platform used to sit in the fail-safe for five minutes and then wait for
// the promotion gates, and when a module was genuinely down it stayed there until an operator
// clicked "activate protection". Both are the wrong answer to the same question: what has to be true
// for the platform to protect again, and who checks it?
//
// This supervisor checks it. It walks the modules that carry the protection, heals what can be
// healed with the canonical action that already exists for each module, verifies the result
// independently, and hands the outcome to the release controller - which re-arms immediately when
// the host is the one that was qualified, and falls back to the visible canary ladder when it is
// not.
//
// Two things it must never do, because they are trust decisions rather than repairs: accept a
// changed system file into the FIM baseline, and re-arm while the emergency stop is active. Both are
// reported as an operator decision, and both keep failing closed.

const (
	startupModuleOK       = "ok"
	startupModuleHealed   = "healed"
	startupModuleFailed   = "failed"
	startupModuleOperator = "operator"

	startupReArmArmed         = "armed"
	startupReArmLadder        = "ladder"
	startupReArmBlocked       = "blocked"
	startupReArmEmergencyStop = "emergency-stop"

	defaultStartupRounds            = 12
	defaultStartupRoundGapSeconds   = 5
	defaultStartupArmIntervalSecond = 300
	defaultStartupHealAttempts      = 3
)

// StartupModuleReport is one line of the self-check, and it is what the operator sees when the
// platform is not protecting: the module, what happened, and why.
type StartupModuleReport struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Detail   string `json:"detail,omitempty"`
	Healed   bool   `json:"healed"`
	Blocking bool   `json:"blocking"`
}

type StartupReport struct {
	CheckedAt      time.Time             `json:"checked_at"`
	Modules        []StartupModuleReport `json:"modules"`
	BlockingIssues int                   `json:"blocking_issues"`
	Healed         int                   `json:"healed"`
	ReArm          string                `json:"re_arm"`
	ReArmReason    string                `json:"re_arm_reason"`
	Fingerprint    string                `json:"fingerprint"`
}

// startupModule is data, not code: a probe that answers "is this module doing its job" and an
// optional heal that answers "make it do its job again". A module without a heal is checked and
// reported; it is never silently skipped.
//
// continuous marks the modules the watch keeps asking about after the startup pass. The expensive
// checks (bounded ledger verification, incident-chain verification) run at startup and on demand;
// the cheap state questions run for as long as the platform does, so a degradation at hour six is
// healed the same way as one at startup.
type startupModule struct {
	name        string
	blocking    bool
	continuous  bool
	description string
	probe       func(context.Context) error
	heal        func(context.Context) error
}

type StartupSupervisor struct {
	modules      []startupModule
	fingerprint  func(context.Context) (string, error)
	reArm        func(reason string) (ReleaseStatus, error)
	status       func() ReleaseStatus
	reportSink   func(StartupReport)
	now          func() time.Time
	rounds       int
	roundGap     time.Duration
	armInterval  time.Duration
	healAttempts int
	qualifyPath  string

	mu       sync.Mutex
	passes   int
	lastArm  time.Time
	lastSeen string
}

// StartupSupervisorConfig is the operator-facing shape of the settings.
type StartupSupervisorConfig struct {
	Enabled           bool
	Rounds            int
	RoundGapSeconds   int
	ArmIntervalSec    int
	HealAttempts      int
	QualificationFile string
}

func defaultStartupSupervisorConfig() StartupSupervisorConfig {
	return StartupSupervisorConfig{
		Enabled:           true,
		Rounds:            defaultStartupRounds,
		RoundGapSeconds:   defaultStartupRoundGapSeconds,
		ArmIntervalSec:    defaultStartupArmIntervalSecond,
		HealAttempts:      defaultStartupHealAttempts,
		QualificationFile: "/var/lib/vgt/gedefense/release-qualification.json",
	}
}

func (s *StartupSupervisor) Run(ctx context.Context) {
	if s == nil || len(s.modules) == 0 {
		return
	}
	healsUsed := make(map[string]int, len(s.modules))
	for round := 1; round <= s.rounds; round++ {
		if err := ctx.Err(); err != nil {
			return
		}
		report := s.checkOnce(ctx, healsUsed)
		s.publish(report)
		if report.BlockingIssues == 0 {
			s.passes++
			// Two clean passes, not one: the point of the wait was never the waiting, it was
			// evidence that the modules are stable. Two observations a few seconds apart are that
			// evidence; five minutes of standing still are not.
			if s.passes >= 2 {
				s.arm(ctx, report)
				break
			}
		} else {
			s.passes = 0
		}
		if round < s.rounds {
			if err := sleepContext(ctx, s.roundGap); err != nil {
				return
			}
		}
	}
	// The startup pass is over; the watch keeps the same questions answered for as long as the
	// platform runs. Without it the self-check would be a one-off, and a module that fails at hour
	// six would again wait for an operator.
	s.watch(ctx)
}

// watch re-checks the cheap modules on a fixed cadence, keeps the qualification current, and heals a
// degradation that appears long after startup - bounded by the same re-arm interval, so the platform
// can never oscillate.
func (s *StartupSupervisor) watch(ctx context.Context) {
	interval := s.armInterval / 5
	if interval < 15*time.Second {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	healsUsed := make(map[string]int, len(s.modules))
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		status := s.status()
		if status.EmergencyStop {
			// The operator owns this state; the watch stays quiet and the kernel keeps enforcing.
			continue
		}
		if status.Phase == ReleasePhaseEnforce && status.KernelPolicyState == "verified-enforce" && status.FailSafeVerified {
			// The platform is protecting. Being in this state is what "qualified" means, so the
			// fingerprint is recorded here and not only when the supervisor armed it itself - the
			// operator's own promotion has to count as a qualification too.
			if fingerprint, err := s.fingerprint(ctx); err == nil && fingerprint != "" {
				if stored, ok := s.readQualification(); !ok || stored != fingerprint {
					if err := s.writeQualification(fingerprint); err != nil {
						log.Printf("startup self-check: qualification could not be updated: %v", err)
					} else {
						log.Printf("startup self-check: host qualified while enforcing (%s)", fingerprint)
					}
				}
			}
			continue
		}
		report := s.checkOnceFiltered(ctx, healsUsed, true)
		s.publish(report)
		if report.BlockingIssues == 0 {
			s.arm(ctx, report)
		}
	}
}

// checkOnceFiltered runs the startup checklist, optionally restricted to the modules the watch owns.
// The report describes the platform, so a filtered pass only ever keeps or loses the re-arm - it
// never claims a module is healthy because it was not asked.
func (s *StartupSupervisor) checkOnceFiltered(ctx context.Context, healsUsed map[string]int, continuousOnly bool) StartupReport {
	if !continuousOnly {
		return s.checkOnce(ctx, healsUsed)
	}
	filtered := make([]startupModule, 0, len(s.modules))
	for _, module := range s.modules {
		if module.continuous {
			filtered = append(filtered, module)
		}
	}
	clone := *s
	clone.modules = filtered
	return clone.checkOnce(ctx, healsUsed)
}

func (s *StartupSupervisor) checkOnce(ctx context.Context, healsUsed map[string]int) StartupReport {
	report := StartupReport{CheckedAt: s.now().UTC()}
	for _, module := range s.modules {
		if err := ctx.Err(); err != nil {
			break
		}
		entry := StartupModuleReport{Name: module.name, Blocking: module.blocking, State: startupModuleOK}
		probeErr := module.probe(ctx)
		if probeErr != nil {
			entry.Detail = boundedSummary(probeErr.Error())
			healed, detail := s.tryHeal(ctx, module, healsUsed)
			entry.Healed = healed
			if detail != "" {
				entry.Detail = detail
			}
			switch {
			case healed:
				entry.State = startupModuleHealed
				report.Healed++
			case !module.blocking:
				entry.State = startupModuleOperator
			default:
				entry.State = startupModuleFailed
				report.BlockingIssues++
			}
		} else if !module.blocking {
			entry.State = startupModuleOK
		}
		report.Modules = append(report.Modules, entry)
	}
	return report
}

// tryHeal runs the module's canonical healing action and then probes again. An attempted heal that
// did not change the outcome is reported as a failure, never as a success.
func (s *StartupSupervisor) tryHeal(ctx context.Context, module startupModule, healsUsed map[string]int) (bool, string) {
	if module.heal == nil {
		return false, "no automatic repair exists for this module"
	}
	if healsUsed[module.name] >= s.healAttempts {
		return false, "healing attempts exhausted"
	}
	healsUsed[module.name]++
	if err := module.heal(ctx); err != nil {
		return false, "healing failed: " + boundedSummary(err.Error())
	}
	if err := module.probe(ctx); err != nil {
		return false, "healing did not restore the module: " + boundedSummary(err.Error())
	}
	return true, "repaired automatically"
}

func (s *StartupSupervisor) publish(report StartupReport) {
	s.mu.Lock()
	s.lastSeen = report.Fingerprint
	s.mu.Unlock()
	if s.reportSink != nil {
		s.reportSink(report)
	}
	failed := make([]string, 0, 4)
	for _, module := range report.Modules {
		if module.State == startupModuleFailed {
			failed = append(failed, module.Name+": "+module.Detail)
		}
	}
	if len(failed) > 0 {
		log.Printf("startup self-check: %d of %d modules need attention: %s", report.BlockingIssues, len(report.Modules), strings.Join(failed, "; "))
		return
	}
	log.Printf("startup self-check: all %d blocking modules verified (%d repaired automatically)", len(report.Modules), report.Healed)
}

func (s *StartupSupervisor) arm(ctx context.Context, report StartupReport) {
	fingerprint, err := s.fingerprint(ctx)
	if err != nil {
		log.Printf("startup self-check: host fingerprint unavailable, keeping the normal ladder: %v", err)
	}
	qualified, known := s.readQualification()
	decision, reason := decideStartupReArm(s.status(), fingerprint, qualified, known, s.lastArm, s.now(), s.armInterval)
	report.ReArm = decision
	report.ReArmReason = reason
	report.Fingerprint = fingerprint
	s.publish(report)

	switch decision {
	case startupReArmArmed:
		if _, err := s.reArm(reason); err != nil {
			log.Printf("startup self-check: re-arm refused: %v", err)
			return
		}
		s.mu.Lock()
		s.lastArm = s.now()
		s.mu.Unlock()
		if fingerprint != "" {
			if err := s.writeQualification(fingerprint); err != nil {
				log.Printf("startup self-check: qualification could not be persisted: %v", err)
			}
		}
		log.Printf("startup self-check: protection re-armed immediately; the host is the one that was qualified")
	case startupReArmLadder:
		log.Printf("startup self-check: %s - using the visible canary ladder instead of an immediate re-arm", reason)
	case startupReArmEmergencyStop:
		log.Printf("startup self-check: %s", reason)
	default:
		log.Printf("startup self-check: re-arm not possible: %s", reason)
	}
}

// decideStartupReArm is the whole safety question in one pure function, so it is testable and so
// nobody has to read the surrounding control flow to answer "why did it not arm".
func decideStartupReArm(status ReleaseStatus, fingerprint, qualified string, known bool, lastArm, now time.Time, armInterval time.Duration) (string, string) {
	if status.EmergencyStop {
		return startupReArmEmergencyStop, "emergency stop is active; only the operator re-arms the platform"
	}
	if status.Phase == ReleasePhaseEnforce {
		return startupReArmArmed, "already enforcing"
	}
	if status.KernelPolicyState != "verified-enforce" || !status.FailSafeVerified {
		return startupReArmBlocked, "kernel enforcement is not verified"
	}
	if len(status.Blockers) > 0 {
		return startupReArmBlocked, "release gates are not satisfied: " + status.Blockers[0]
	}
	if fingerprint == "" {
		return startupReArmLadder, "host fingerprint is unavailable; the host has to be re-qualified"
	}
	if !known || qualified == "" || qualified != fingerprint {
		// A new kernel, a new interface or a new release changes what the platform is protecting.
		// That is the case the canary exists for, and it stays visible and slow on purpose.
		return startupReArmLadder, "host fingerprint changed since the last qualified start; canary re-qualification required"
	}
	if !lastArm.IsZero() && now.Sub(lastArm) < armInterval {
		return startupReArmBlocked, fmt.Sprintf("an automatic re-arm happened %s ago", now.Sub(lastArm).Round(time.Second))
	}
	return startupReArmArmed, "all modules verified and the host is unchanged"
}

func (s *StartupSupervisor) readQualification() (string, bool) {
	if s.qualifyPath == "" {
		return "", false
	}
	raw, err := os.ReadFile(s.qualifyPath)
	if err != nil {
		return "", false
	}
	var stored struct {
		Fingerprint string    `json:"fingerprint"`
		QualifiedAt time.Time `json:"qualified_at"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return "", false
	}
	return stored.Fingerprint, stored.Fingerprint != ""
}

func (s *StartupSupervisor) writeQualification(fingerprint string) error {
	if s.qualifyPath == "" {
		return nil
	}
	payload, err := json.Marshal(struct {
		Fingerprint string    `json:"fingerprint"`
		QualifiedAt time.Time `json:"qualified_at"`
	}{Fingerprint: fingerprint, QualifiedAt: s.now().UTC()})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.qualifyPath), 0o750); err != nil {
		return err
	}
	return atomicWriteFile(s.qualifyPath, append(payload, '\n'), 0o600)
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var errStartupNoCore = errors.New("kernel core is not reachable")
