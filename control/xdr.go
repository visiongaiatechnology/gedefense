package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type protectedObject struct {
	path   string
	digest string
	mode   os.FileMode
	size   int64
}

type evaluationJob struct {
	process ProcessSample
	conns   []NetConnection
	source  string
}

type XDREngine struct {
	cfg        Config
	state      *State
	core       *CoreClient
	feeds      *FeedManager
	policy     *PolicyStore
	settings   *SettingsStore
	release    *ReleaseController
	rules      *XDRRuleEngine
	baseline   *XDRBaseline
	behavior   *BehaviorModel
	logger     *IncidentLogger
	selfPID    int
	seeded     bool
	seen       map[string]struct{}
	dedupe     map[string]time.Time
	protected  map[string]protectedObject
	degraded   bool
	degradeWhy string
	mu         sync.RWMutex
	highJobs   chan evaluationJob
	normalJobs chan evaluationJob
	workers    sync.WaitGroup
	drops      atomic.Uint64
	evaluated  atomic.Uint64
	anomalies  atomic.Uint64
}

func (e *XDREngine) SetReleaseController(release *ReleaseController) {
	e.release = release
}

func NewXDREngine(cfg Config, state *State, core *CoreClient, feeds *FeedManager, policy *PolicyStore, settings *SettingsStore, configPath string) (*XDREngine, error) {
	baseline, err := LoadXDRBaseline(cfg.XDR.BaselineFile)
	if err != nil {
		return nil, fmt.Errorf("xdr baseline: %w", err)
	}
	logger, err := NewIncidentLoggerWithStorage(cfg.XDR.IncidentLog, cfg.XDR.LogKeyFile, cfg.XDR.StorageKeyFile, cfg.Node.Name, cfg.XDR.MaxIncidentLogBytes)
	if err != nil {
		return nil, fmt.Errorf("xdr incident log: %w", err)
	}
	behavior, err := NewBehaviorModel(cfg.XDR, cfg.Node.Name)
	if err != nil {
		return nil, fmt.Errorf("xdr behavior model: %w", err)
	}
	highCap := cfg.XDR.QueueCapacity / 4
	if highCap < 16 {
		highCap = 16
	}
	normalCap := cfg.XDR.QueueCapacity - highCap
	if normalCap < 16 {
		normalCap = 16
	}
	e := &XDREngine{
		cfg: cfg, state: state, core: core, feeds: feeds, policy: policy, settings: settings, rules: NewXDRRuleEngine(), baseline: baseline,
		behavior: behavior, logger: logger, selfPID: os.Getpid(), seen: map[string]struct{}{}, dedupe: map[string]time.Time{},
		protected: map[string]protectedObject{}, highJobs: make(chan evaluationJob, highCap), normalJobs: make(chan evaluationJob, normalCap),
	}
	if err := logger.Healthy(); err != nil {
		e.degraded = true
		e.degradeWhy = "incident log integrity failure: " + err.Error()
	}
	if summary := behavior.Summary(); cfg.XDR.BehaviorEnabled && !summary.IntegrityOK {
		e.degraded = true
		e.degradeWhy = "behavior profile integrity failure: " + summary.Error
	}
	paths := append([]string{}, cfg.XDR.ProtectedPaths...)
	// Protect only immutable trust anchors. Mutable signed state (policy snapshots and
	// behavior profiles) is authenticated by its own signature/MAC and must not be
	// treated as a self-tamper event when it is legitimately updated.
	paths = append(paths, configPath, cfg.XDR.LogKeyFile, cfg.Core.AuthKeyFile, cfg.Policy.SigningKeyFile, cfg.Policy.PublicKeyFile, cfg.Runtime.StorageKeyFile)
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, exe)
	}
	paths = append(paths, baselineExecutables(baseline)...)
	e.captureProtected(paths)
	return e, nil
}

func (e *XDREngine) runtimeSettings() RuntimeSettings {
	if e.settings != nil {
		return e.settings.Get()
	}
	return defaultRuntimeSettings(e.cfg)
}

func (e *XDREngine) protectedPaths() []string {
	paths := make([]string, 0, len(e.protected))
	for path := range e.protected {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func (e *XDREngine) Run(ctx context.Context) {
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	for i := 0; i < e.cfg.XDR.WorkerCount; i++ {
		e.workers.Add(1)
		go e.worker(workerCtx)
	}
	defer e.workers.Wait()

	runtime := e.runtimeSettings()
	scanTick := time.NewTicker(time.Duration(runtime.ScanIntervalMillis) * time.Millisecond)
	netTick := time.NewTicker(time.Duration(runtime.NetworkIntervalSeconds) * time.Second)
	integrityTick := time.NewTicker(time.Duration(e.cfg.XDR.IntegrityIntervalSeconds) * time.Second)
	logVerifyTick := time.NewTicker(30 * time.Second)
	cleanupTick := time.NewTicker(time.Minute)
	behaviorSaveTick := time.NewTicker(5 * time.Minute)
	statusTick := time.NewTicker(time.Second)
	defer scanTick.Stop()
	defer netTick.Stop()
	defer integrityTick.Stop()
	defer logVerifyTick.Stop()
	defer cleanupTick.Stop()
	defer behaviorSaveTick.Stop()
	defer statusTick.Stop()

	integrityEvents, stopIntegrityWatch, watchErr := watchIntegrityChanges(ctx, e.protectedPaths())
	defer stopIntegrityWatch()
	if watchErr != nil {
		e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.integrity_watch_fallback", Source: "integrity", Message: "Native integrity event watch unavailable; bounded periodic verification remains active"})
	}

	_, runtimeXDRMode := e.state.Modes()
	runtime = e.runtimeSettings()
	sensor := "procfs-bounded"
	if !runtime.XDREnabled {
		sensor = "disabled-by-operator"
	}
	e.state.SetXDRStatus(XDRStatus{Enabled: runtime.XDREnabled, Mode: runtimeXDRMode, Sensor: sensor, ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
	if degraded, reason := e.degradedState(); degraded {
		e.state.MarkXDRDegraded(reason)
		e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.integrity_failure", Source: "integrity", Message: reason})
	}
	e.state.AddEvent(Event{Severity: "info", Kind: "xdr.online", Source: "xdr", Message: fmt.Sprintf("GeDefense XDR online: mode=%s workers=%d bounded_queue=%d", runtimeXDRMode, e.cfg.XDR.WorkerCount, cap(e.highJobs)+cap(e.normalJobs))})

	var processes map[string]ProcessSample
	for {
		select {
		case <-ctx.Done():
			if e.behavior != nil {
				_ = e.behavior.Persist()
			}
			cancelWorkers()
			return
		case <-scanTick.C:
			runtime = e.runtimeSettings()
			scanTick.Reset(time.Duration(runtime.ScanIntervalMillis) * time.Millisecond)
			if !runtime.XDREnabled {
				e.state.SetXDRStatus(XDRStatus{Enabled: false, Mode: "disabled", Sensor: "disabled-by-operator", ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
				continue
			}
			p, err := scanLinuxProcesses(e.cfg.XDR.MaxCommandBytes)
			if err != nil {
				e.markDegraded("process sensor unavailable: " + err.Error())
				continue
			}
			processes = p
			e.evaluateNewProcesses(p)
			now := time.Now().UTC()
			degraded, reason := e.degradedState()
			e.state.UpdateXDRScan(len(p), -1, now, degraded, reason, len(e.protected))
		case <-netTick.C:
			runtime = e.runtimeSettings()
			netTick.Reset(time.Duration(runtime.NetworkIntervalSeconds) * time.Second)
			if !runtime.XDREnabled || !runtime.NetworkSensorEnabled || processes == nil {
				continue
			}
			connections, total := correlateLinuxConnections(processes)
			queued := 0
			for key, p := range processes {
				if queued >= e.cfg.XDR.MaxEvaluationsPerScan {
					e.noteDrop("network scan evaluation budget exhausted")
					break
				}
				p.Connections = connections[key]
				if e.submit(evaluationJob{process: p, conns: p.Connections, source: "network"}, false) {
					queued++
				}
			}
			now := time.Now().UTC()
			degraded, reason := e.degradedState()
			e.state.UpdateXDRScan(len(processes), total, now, degraded, reason, len(e.protected))
		case _, ok := <-integrityEvents:
			if ok {
				e.checkProtected()
			}
		case <-integrityTick.C:
			e.checkProtected()
		case <-logVerifyTick.C:
			if e.logger != nil {
				if err := e.logger.Verify(); err != nil {
					e.markDegraded("incident log verification failed: " + err.Error())
				}
			}
		case <-behaviorSaveTick.C:
			if e.behavior != nil {
				if err := e.behavior.Persist(); err != nil {
					e.markDegraded("behavior profile persistence failed: " + err.Error())
				}
			}
		case now := <-cleanupTick.C:
			e.cleanupDedupe(now)
		case <-statusTick.C:
			runtime = e.runtimeSettings()
			e.state.UpdateXDRRuntime(len(e.highJobs)+len(e.normalJobs), cap(e.highJobs)+cap(e.normalJobs), e.drops.Load(), e.evaluated.Load(), e.anomalies.Load(), e.behavior.Summary())
			e.state.SetXDREnabled(runtime.XDREnabled, runtime.NetworkSensorEnabled)
		}
	}
}

func (e *XDREngine) worker(ctx context.Context) {
	defer e.workers.Done()
	for {
		var job evaluationJob
		var ok bool
		select {
		case <-ctx.Done():
			return
		case job, ok = <-e.highJobs:
			if !ok {
				return
			}
		default:
			select {
			case <-ctx.Done():
				return
			case job, ok = <-e.highJobs:
				if !ok {
					return
				}
			case job, ok = <-e.normalJobs:
				if !ok {
					return
				}
			}
		}
		e.evaluate(job.process, job.conns, job.source)
	}
}

func (e *XDREngine) submit(job evaluationJob, high bool) bool {
	ch := e.normalJobs
	if high {
		ch = e.highJobs
	}
	select {
	case ch <- job:
		return true
	default:
		e.noteDrop("XDR evaluation queue full")
		return false
	}
}

func (e *XDREngine) noteDrop(reason string) {
	n := e.drops.Add(1)
	if n == 1 || n&(n-1) == 0 {
		e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.backpressure", Source: "pipeline", Message: fmt.Sprintf("%s; dropped evaluations=%d", reason, n)})
	}
}

func (e *XDREngine) evaluateNewProcesses(processes map[string]ProcessSample) {
	e.mu.Lock()
	current := make(map[string]struct{}, len(processes))
	if !e.seeded {
		for key := range processes {
			e.seen[key] = struct{}{}
		}
		e.seeded = true
		e.mu.Unlock()
		return
	}
	var jobs []evaluationJob
	for key, p := range processes {
		current[key] = struct{}{}
		if _, known := e.seen[key]; known {
			continue
		}
		e.seen[key] = struct{}{}
		if p.PID == e.selfPID || e.allowedProcess(p.Exe) {
			continue
		}
		if len(jobs) < e.cfg.XDR.MaxEvaluationsPerScan {
			jobs = append(jobs, evaluationJob{process: p, source: "exec"})
		}
	}
	for key := range e.seen {
		if _, ok := current[key]; !ok {
			delete(e.seen, key)
		}
	}
	e.mu.Unlock()
	for _, job := range jobs {
		e.submit(job, true)
	}
	if len(jobs) >= e.cfg.XDR.MaxEvaluationsPerScan {
		e.noteDrop("process scan evaluation budget exhausted")
	}
}

func (e *XDREngine) allowedProcess(exe string) bool {
	exe = filepath.Clean(strings.TrimSuffix(exe, " (deleted)"))
	for _, allowed := range e.cfg.XDR.AllowProcesses {
		if filepath.Clean(allowed) == exe {
			return true
		}
	}
	return false
}

func (e *XDREngine) evaluate(p ProcessSample, conns []NetConnection, source string) {
	if p.PID <= 4 || p.PID == e.selfPID {
		return
	}
	runtime := e.runtimeSettings()
	if err := e.rules.Configure(runtime); err != nil {
		e.markDegraded("runtime rule configuration invalid")
		return
	}
	if !runtime.XDREnabled {
		return
	}
	e.evaluated.Add(1)
	var extra []RuleMatch
	if runtime.BehaviorEnabled && e.behavior != nil {
		now := time.Now().UTC()
		if source == "exec" {
			extra = e.behavior.ObserveExec(p, now)
		} else if source == "network" {
			extra = e.behavior.ObserveNetwork(p, conns, now)
		}
		if len(extra) > 0 {
			e.anomalies.Add(uint64(len(extra)))
		}
	}
	var index *ThreatIndex
	if runtime.FeedsEnabled && e.feeds != nil {
		index = e.feeds.index
	}
	decision := e.rules.EvaluateProcess(p, conns, index, e.baseline, extra...)
	if decision.Score < runtime.AlertScore || len(decision.RuleIDs) == 0 {
		return
	}
	decision.Decision = "alert"
	if decision.ResponseScore >= runtime.KillScore && decision.KillSignals >= 2 {
		decision.Decision = "kill"
	} else if decision.ResponseScore >= runtime.ContainScore {
		decision.Decision = "contain"
	}
	finger := fmt.Sprintf("%d:%d:%s:%s", p.PID, p.StartTicks, strings.Join(decision.RuleIDs, ","), decision.Remote)
	if !e.claimFingerprint(finger) {
		return
	}
	severity := "warning"
	if decision.ResponseScore >= runtime.ContainScore {
		severity = "high"
	}
	if decision.Decision == "kill" {
		severity = "critical"
	}
	incident := XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: severity, Score: decision.Score, ResponseScore: decision.ResponseScore, KillSignals: decision.KillSignals,
		PID: p.PID, PPID: p.PPID, StartTicks: p.StartTicks, UID: p.UID, Process: p.Comm, Executable: p.Exe,
		Parent: p.ParentExe, Remote: decision.Remote, CommandPreview: e.rules.RedactCommand(p.Cmdline, e.cfg.XDR.CommandPreviewBytes),
		CommandSHA256: p.CmdSHA256, RuleIDs: decision.RuleIDs, Categories: decision.Categories, Summary: decision.Summary,
		Decision: decision.Decision, Action: "none", Outcome: "observed",
	}
	incident.Action, incident.Outcome = e.respond(incident)
	if e.logger != nil {
		if h, err := e.logger.Append(incident); err == nil {
			incident.RecordHash = h
		} else {
			log.Printf("xdr incident log: %v", err)
			e.markDegraded("incident log unavailable")
		}
	}
	e.state.AddIncident(incident)
	e.state.AddEvent(Event{Severity: severity, Kind: "xdr." + incident.Decision, Source: source, Message: incident.Summary + " [" + strings.Join(incident.RuleIDs, ",") + "]", Target: fmt.Sprintf("pid:%d", p.PID)})
}

func (e *XDREngine) respond(i XDRIncident) (string, string) {
	if degraded, _ := e.degradedState(); degraded {
		return "none", "XDR degraded; active response disabled"
	}
	_, xdrMode := e.state.Modes()
	if xdrMode == "observe" || i.Decision == "alert" {
		return "none", "observe mode"
	}
	if e.core == nil {
		return "none", "response broker unavailable"
	}
	if e.state.EvidenceLedger() != nil {
		if err := e.state.RecordEvidence(EvidenceRecord{
			Severity: i.Severity, Kind: "xdr.response.intent", Source: "xdr",
			Message: "Automated response authorized by independently scored evidence",
			Target:  fmt.Sprintf("pid:%d:start:%d:decision:%s", i.PID, i.StartTicks, i.Decision),
		}); err != nil {
			return "none", "mandatory evidence commit failed; active response disabled"
		}
	}

	quarantined := false
	if i.Remote != "" && (containsString(i.RuleIDs, "XDR.THREAT_INTEL_C2") || containsString(i.RuleIDs, "KD.LINUX.REVERSE_SHELL")) {
		if err := e.quarantineRemote(i.Remote, i); err == nil {
			quarantined = true
		} else {
			e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.quarantine_failed", Source: "response", Message: err.Error(), Target: i.Remote})
		}
	}
	rule := responseRule(i.RuleIDs)
	if xdrMode == "contain" || i.Decision == "contain" {
		if err := e.core.Stop(i.PID, i.StartTicks, rule); err != nil {
			return actionName(quarantined, "stop"), "failed: " + err.Error()
		}
		return actionName(quarantined, "stop"), "process frozen through authenticated privileged broker"
	}
	if i.Decision == "kill" && xdrMode == "enforce" {
		if err := e.core.Kill(i.PID, i.StartTicks, rule); err != nil {
			if stopErr := e.core.Stop(i.PID, i.StartTicks, rule); stopErr != nil {
				return actionName(quarantined, "kill"), "broker rejected kill and containment failed: " + err.Error() + "; " + stopErr.Error()
			}
			return actionName(quarantined, "stop"), "broker rejected kill; process frozen for operator review: " + err.Error()
		}
		return actionName(quarantined, "kill"), "process terminated through authenticated pidfd broker"
	}
	return actionName(quarantined, "none"), "policy did not authorize active response"
}

func actionName(quarantined bool, action string) string {
	if quarantined {
		return "network-quarantine+" + action
	}
	return action
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func (e *XDREngine) quarantineRemote(remote string, incident XDRIncident) error {
	ip := net.ParseIP(remote)
	if ip == nil || !isPublicIP(ip.String()) {
		return fmt.Errorf("remote quarantine rejected invalid public IP")
	}
	target := ip.String()
	if ip.To4() != nil {
		target += "/32"
	} else {
		target += "/128"
	}
	enforced := false
	enforcement, xdrMode := e.state.Modes()
	if enforcement == "enforce" {
		if err := e.core.Add(target); err != nil {
			return fmt.Errorf("kernel quarantine failed: %w", err)
		}
		enforced = true
	}
	block, err := e.state.AddBlock(target, "XDR containment: "+strings.Join(incident.RuleIDs, ","), "xdr", 15*time.Minute, enforced, e.cfg.Defense.MaxBlockEntries)
	if err != nil {
		if enforced {
			if rollbackErr := e.core.Delete(target); rollbackErr != nil {
				var failSafeErr error
				if e.release != nil {
					failSafeErr = e.release.FailSafe("XDR quarantine rollback failed")
				}
				return errors.Join(err, fmt.Errorf("kernel rollback failed: %w", rollbackErr), failSafeErr)
			}
		}
		return err
	}
	if e.policy != nil {
		if err := e.policy.Persist(e.cfg.Node.Name, enforcement, xdrMode, e.state.BlocksSnapshot()); err != nil {
			e.state.RemoveBlockByID(block.ID)
			if enforced {
				if rollbackErr := e.core.Delete(target); rollbackErr != nil {
					var failSafeErr error
					if e.release != nil {
						failSafeErr = e.release.FailSafe("XDR quarantine policy rollback failed")
					}
					return errors.Join(err, fmt.Errorf("kernel rollback failed: %w", rollbackErr), failSafeErr)
				}
			}
			e.state.SetPolicyStatus(e.policy.Status())
			return fmt.Errorf("signed policy persistence failed: %w", err)
		}
		e.state.SetPolicyStatus(e.policy.Status())
	}
	e.state.AddEvent(Event{Severity: "high", Kind: "xdr.network_quarantine", Source: "response", Message: "Remote endpoint quarantined for 15 minutes", Target: target})
	return nil
}

func responseRule(ids []string) string {
	for _, preferred := range []string{"XDR.MEMFD_EXEC", "XDR.EXE_DELETED", "XDR.TEMP_EXEC", "KD.LINUX.DESTRUCTIVE"} {
		for _, id := range ids {
			if id == preferred {
				return id
			}
		}
	}
	if len(ids) == 0 {
		return "XDR.UNKNOWN"
	}
	return ids[0]
}

func (e *XDREngine) claimFingerprint(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	if until, ok := e.dedupe[key]; ok && now.Before(until) {
		return false
	}
	e.dedupe[key] = now.Add(time.Duration(e.cfg.XDR.DedupeSeconds) * time.Second)
	return true
}

func (e *XDREngine) cleanupDedupe(now time.Time) {
	e.mu.Lock()
	for k, until := range e.dedupe {
		if !until.After(now) {
			delete(e.dedupe, k)
		}
	}
	e.mu.Unlock()
}

func (e *XDREngine) captureProtected(paths []string) {
	uniq := map[string]struct{}{}
	for _, raw := range paths {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		p, err := filepath.Abs(raw)
		if err != nil {
			continue
		}
		p = filepath.Clean(p)
		if _, ok := uniq[p]; ok {
			continue
		}
		uniq[p] = struct{}{}
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		digest, err := hashFile(p)
		if err != nil {
			continue
		}
		e.protected[p] = protectedObject{path: p, digest: digest, mode: st.Mode().Perm(), size: st.Size()}
	}
}

func (e *XDREngine) checkProtected() {
	paths := make([]string, 0, len(e.protected))
	for p := range e.protected {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		old := e.protected[p]
		st, err := os.Stat(p)
		if err != nil {
			e.selfTamper(p, "protected object disappeared")
			continue
		}
		digest, err := hashFile(p)
		if err != nil || digest != old.digest || st.Mode().Perm() != old.mode || st.Size() != old.size {
			e.selfTamper(p, "protected object changed after XDR initialization")
		}
	}
}

func (e *XDREngine) selfTamper(path, reason string) {
	finger := "self:" + path + ":" + reason
	if !e.claimFingerprint(finger) {
		return
	}
	e.markDegraded(reason + ": " + path)
	i := XDRIncident{ID: randomID(), Time: time.Now().UTC(), Severity: "critical", Score: 250, Executable: path,
		RuleIDs: []string{"XDR.SELF_TAMPER"}, Categories: []string{"integrity"}, Summary: reason, Decision: "degrade", Action: "disable-response", Outcome: "active XDR response disabled until restart and verification"}
	if e.logger != nil {
		if h, err := e.logger.Append(i); err == nil {
			i.RecordHash = h
		}
	}
	e.state.AddIncident(i)
	e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.self_tamper", Source: "integrity", Message: reason, Target: path})
}

func (e *XDREngine) markDegraded(reason string) {
	e.mu.Lock()
	e.degraded = true
	e.degradeWhy = reason
	e.mu.Unlock()
	e.state.MarkXDRDegraded(reason)
}

func (e *XDREngine) degradedState() (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.degraded, e.degradeWhy
}
