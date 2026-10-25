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

// startupIdentity separates what is protected (the host) from what protects it (the release).
//
// The two used to be one string. Installing an update - the most routine event on a defended host -
// therefore changed the "host" fingerprint, invalidated the qualification and sent every restart down
// the twenty-minute canary ladder, even though the self-check had just verified every module on the
// very same machine. What a qualification has to cover is the thing being defended: a new kernel, a
// renamed interface or a different node. A new release on that host is a planned change that the
// self-check re-verifies module by module, and it is exactly the case that must not crawl.
type startupIdentity struct {
	Host    string
	Release string
}

func (i startupIdentity) String() string {
	switch {
	case i.Host == "":
		return ""
	case i.Release == "":
		return i.Host
	}
	return "release=" + i.Release + "; " + i.Host
}

func (i startupIdentity) known() bool { return i.Host != "" }

// parseStartupIdentity reads a stored qualification. Files written before the split carry only the
// combined string, so the release element is lifted out of it to recover the host part; an operator
// who upgrades into this version keeps their qualification instead of re-qualifying by accident.
func parseStartupIdentity(host, release, legacy string) startupIdentity {
	if host != "" {
		return startupIdentity{Host: host, Release: release}
	}
	release = ""
	parts := make([]string, 0, 4)
	for _, part := range strings.Split(legacy, "; ") {
		part = strings.TrimSpace(part)
		switch {
		case part == "":
		case strings.HasPrefix(part, "release="):
			release = strings.TrimPrefix(part, "release=")
		default:
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return startupIdentity{}
	}
	return startupIdentity{Host: strings.Join(parts, "; "), Release: release}
}

// startupQualification is the on-disk record. Host and Release are the fields that decide; Fingerprint
// stays for operators and for backwards compatibility with files written by earlier releases.
type startupQualification struct {
	Fingerprint string    `json:"fingerprint"`
	Host        string    `json:"host"`
	Release     string    `json:"release"`
	QualifiedAt time.Time `json:"qualified_at"`
}

func (q startupQualification) identity() startupIdentity {
	return parseStartupIdentity(q.Host, q.Release, q.Fingerprint)
}

type StartupSupervisor struct {
	modules      []startupModule
	identity     func(context.Context) (startupIdentity, error)
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
			if current, err := s.identity(ctx); err == nil && current.known() {
				if stored, ok := s.readQualification(); !ok || stored.identity() != current {
					if err := s.writeQualification(current); err != nil {
						log.Printf("startup self-check: qualification could not be updated: %v", err)
					} else {
						log.Printf("startup self-check: host qualified while enforcing (%s)", current)
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
	return s.checkModules(ctx, filtered, healsUsed)
}

func (s *StartupSupervisor) checkOnce(ctx context.Context, healsUsed map[string]int) StartupReport {
	return s.checkModules(ctx, s.modules, healsUsed)
}

func (s *StartupSupervisor) checkModules(ctx context.Context, modules []startupModule, healsUsed map[string]int) StartupReport {
	report := StartupReport{CheckedAt: s.now().UTC()}
	for _, module := range modules {
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
	publishStartupReport(report)
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
	current, err := s.identity(ctx)
	if err != nil {
		log.Printf("startup self-check: host identity unavailable, keeping the normal ladder: %v", err)
	}
	qualified, known := s.readQualification()
	decision, reason := decideStartupReArm(s.status(), current, qualified, known, s.lastArm, s.now(), s.armInterval)
	report.ReArm = decision
	report.ReArmReason = reason
	report.Fingerprint = current.String()
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
		if current.known() {
			if err := s.writeQualification(current); err != nil {
				log.Printf("startup self-check: qualification could not be persisted: %v", err)
			}
		}
		log.Printf("startup self-check: protection re-armed immediately; %s", reason)
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
//
// The order is the safety argument. Nothing is decided before the kernel enforcement is verified and
// the gates are satisfied, and a host that is not the qualified one still has to walk the visible
// canary ladder. What changed is only the last step: an update on that same host is re-armed at once,
// because the self-check has just re-verified every module against it.
func decideStartupReArm(status ReleaseStatus, current startupIdentity, qualified startupQualification, known bool, lastArm, now time.Time, armInterval time.Duration) (string, string) {
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
	if !current.known() {
		return startupReArmLadder, "the host identity is unavailable; the host has to be re-qualified"
	}
	stored := qualified.identity()
	if !known || !stored.known() {
		// Never qualified, or a qualification from before this platform was trusted at all.
		return startupReArmLadder, "this host has not been qualified yet; canary re-qualification required"
	}
	if stored.Host != current.Host {
		// A new kernel, a new interface or a different node changes what the platform is protecting.
		// That is the case the canary exists for, and it stays visible and slow on purpose.
		return startupReArmLadder, "the host changed since the last qualified start (kernel, node or interface); canary re-qualification required"
	}
	if !lastArm.IsZero() && now.Sub(lastArm) < armInterval {
		return startupReArmBlocked, fmt.Sprintf("an automatic re-arm happened %s ago", now.Sub(lastArm).Round(time.Second))
	}
	if stored.Release != current.Release {
		return startupReArmArmed, fmt.Sprintf(
			"release %s replaced %s on the qualified host and the startup self-check verified every module",
			current.Release, stored.Release)
	}
	return startupReArmArmed, "all modules verified and the host is unchanged"
}

func (s *StartupSupervisor) readQualification() (startupQualification, bool) {
	if s.qualifyPath == "" {
		return startupQualification{}, false
	}
	raw, err := os.ReadFile(s.qualifyPath)
	if err != nil {
		return startupQualification{}, false
	}
	var stored startupQualification
	if err := json.Unmarshal(raw, &stored); err != nil {
		return startupQualification{}, false
	}
	if !stored.identity().known() {
		return startupQualification{}, false
	}
	return stored, true
}

func (s *StartupSupervisor) writeQualification(identity startupIdentity) error {
	if s.qualifyPath == "" {
		return nil
	}
	payload, err := json.Marshal(startupQualification{
		Fingerprint: identity.String(),
		Host:        identity.Host,
		Release:     identity.Release,
		QualifiedAt: s.now().UTC(),
	})
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

// ------------------------------------------------------------------ status
//
// The self-check produces the answer to "why is the platform not protecting
// again?" and until now that answer only reached the journal: the operator had
// to read logs to see which module needed attention. The report is published
// here into one process-wide, bounded view that the API can serve from
// /api/v1/status (or a dedicated endpoint) without reaching into the
// supervisor's goroutine or the journal.
//
// The view is deliberately a projection, not the report itself: module details
// are truncated, the module list is capped, and a report older than
// startupStatusMaxAge is marked stale so a dead supervisor is visible as such
// instead of showing its last healthy state forever.

const (
	startupStatusMaxModules = 32
	startupStatusMaxAge     = 30 * time.Minute
)

// StartupModuleStatus is one bounded line of the exposed self-check.
type StartupModuleStatus struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Detail   string `json:"detail,omitempty"`
	Healed   bool   `json:"healed"`
	Blocking bool   `json:"blocking"`
}

// StartupStatus is the bounded startup-supervisor view served by the API. It
// contains no secrets: module names, states, operator-facing refusals and the
// re-arm decision only.
type StartupStatus struct {
	CheckedAt      time.Time             `json:"checked_at"`
	Modules        []StartupModuleStatus `json:"modules"`
	BlockingIssues int                   `json:"blocking_issues"`
	Healed         int                   `json:"healed"`
	ReArm          string                `json:"re_arm"`
	ReArmReason    string                `json:"re_arm_reason,omitempty"`
	Fingerprint    string                `json:"fingerprint,omitempty"`
	ReportAgeSec   int64                 `json:"report_age_seconds"`
	Stale          bool                  `json:"stale"`
}

var startupReportStore struct {
	mu      sync.RWMutex
	report  StartupReport
	updated time.Time
	seq     uint64
}

// publishStartupReport stores the latest self-check report for the API view.
// It runs on every report the supervisor publishes, including the watch passes.
func publishStartupReport(report StartupReport) {
	startupReportStore.mu.Lock()
	defer startupReportStore.mu.Unlock()
	startupReportStore.report = cloneStartupReport(report)
	startupReportStore.updated = time.Now().UTC()
	startupReportStore.seq++
}

// CurrentStartupStatus returns the bounded self-check view. The boolean is false
// until the supervisor has published its first report, which is what the API
// must show instead of an invented healthy default.
func CurrentStartupStatus() (StartupStatus, bool) {
	return currentStartupStatusAt(time.Now().UTC())
}

func currentStartupStatusAt(now time.Time) (StartupStatus, bool) {
	startupReportStore.mu.RLock()
	report := cloneStartupReport(startupReportStore.report)
	updated := startupReportStore.updated
	startupReportStore.mu.RUnlock()
	if updated.IsZero() {
		return StartupStatus{}, false
	}
	return report.statusView(now, updated), true
}

// StartupStatusSequence is a cheap change marker for the UI: it increments with
// every published report and does not require copying the report.
func StartupStatusSequence() uint64 {
	startupReportStore.mu.RLock()
	defer startupReportStore.mu.RUnlock()
	return startupReportStore.seq
}

func (r StartupReport) statusView(now, updated time.Time) StartupStatus {
	view := StartupStatus{
		CheckedAt:      r.CheckedAt.UTC(),
		BlockingIssues: r.BlockingIssues,
		Healed:         r.Healed,
		ReArm:          r.ReArm,
		ReArmReason:    r.ReArmReason,
		Fingerprint:    r.Fingerprint,
		Modules:        make([]StartupModuleStatus, 0, len(r.Modules)),
	}
	if view.CheckedAt.IsZero() {
		view.CheckedAt = updated.UTC()
	}
	if !updated.IsZero() {
		view.ReportAgeSec = int64(now.Sub(updated).Round(time.Second) / time.Second)
		if view.ReportAgeSec < 0 {
			view.ReportAgeSec = 0
		}
		view.Stale = now.Sub(updated) > startupStatusMaxAge
	}
	for _, module := range r.Modules {
		if len(view.Modules) >= startupStatusMaxModules {
			break
		}
		view.Modules = append(view.Modules, StartupModuleStatus{
			Name: module.Name, State: module.State, Detail: boundedStartupDetail(module.Detail),
			Healed: module.Healed, Blocking: module.Blocking,
		})
	}
	return view
}

// boundedStartupDetail keeps a module refusal readable without letting a
// pathological error message grow the status document.
func boundedStartupDetail(detail string) string {
	const maxDetailRunes = 240
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return ""
	}
	runes := []rune(detail)
	if len(runes) > maxDetailRunes {
		return string(runes[:maxDetailRunes])
	}
	return detail
}

func cloneStartupReport(in StartupReport) StartupReport {
	out := in
	out.Modules = append([]StartupModuleReport(nil), in.Modules...)
	return out
}
