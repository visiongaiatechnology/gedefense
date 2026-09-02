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
	"strconv"
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
	cfg             Config
	state           *State
	core            *CoreClient
	feeds           *FeedManager
	policy          *PolicyStore
	settings        *SettingsStore
	release         *ReleaseController
	rules           *XDRRuleEngine
	baseline        *XDRBaseline
	behavior        *BehaviorModel
	logger          *IncidentLogger
	selfPID         int
	seeded          bool
	seen            map[string]struct{}
	dedupe          map[string]time.Time
	protected       map[string]protectedObject
	cellPolicyEpoch string
	cellPolicies    map[uint64]uint8
	platformCaps    PlatformCapabilities
	correlator      *IncidentCorrelator
	responses       *ResponseEngine
	deception       *DeceptionEngine
	styx            *StyxEngine
	morpheus        *MorpheusRASP
	airlock         *AirlockInspector
	chronos         *ChronosScanner
	degraded        bool
	degradeWhy      string
	mu              sync.RWMutex
	highJobs        chan evaluationJob
	normalJobs      chan evaluationJob
	workers         sync.WaitGroup
	drops           atomic.Uint64
	evaluated       atomic.Uint64
	anomalies       atomic.Uint64
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
		protected: map[string]protectedObject{}, cellPolicies: map[uint64]uint8{},
		highJobs: make(chan evaluationJob, highCap), normalJobs: make(chan evaluationJob, normalCap),
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

	e.platformCaps = DetectPlatformCapabilities("/")
	e.correlator = NewIncidentCorrelator(30 * time.Minute)
	respCfg := DefaultResponseConfig()
	e.responses = NewResponseEngine(respCfg, core, func(action, target, details string, ts time.Time) error {
		if state.EvidenceLedger() != nil {
			return state.RecordEvidence(EvidenceRecord{
				Severity: "high",
				Kind:     "xdr.response",
				Source:   "response-engine",
				Message:  fmt.Sprintf("Action=%s Target=%s Details=%s", action, target, details),
				Target:   target,
				Time:     ts,
			})
		}
		return nil
	})
	storageDir := filepath.Dir(cfg.XDR.IncidentLog)
	if storageDir == "" || storageDir == "." {
		storageDir = "/var/lib/vgt-gedefense"
	}

	// Derive deception master key using storage key cipher purposeKey("deception-master-key")
	// or fallback to deterministic HMAC bound to storageDir and node identity.
	var deceptionKey []byte
	storageKeyPath := cfg.XDR.StorageKeyFile
	if storageKeyPath == "" {
		storageKeyPath = cfg.Runtime.StorageKeyFile
	}
	if storageKeyPath == "" {
		storageKeyPath = cfg.Policy.StorageKeyFile
	}
	if storageKeyPath != "" {
		if cipher, err := NewStorageCipher(storageKeyPath, cfg.Node.Name); err == nil && cipher != nil {
			if k, err := cipher.purposeKey("deception-master-key"); err == nil && len(k) >= 16 {
				deceptionKey = k
			}
		}
	}
	if len(deceptionKey) < 16 {
		log.Printf("[VGT-DECEPTION] Fail-closed: authenticated storage root key unavailable, deception engine offline")
	} else {
		if dec, err := NewDeceptionEngine(deceptionKey, e.responses, e.correlator, func(inc XDRIncident) error {
			e.appendIncident(inc)
			return nil
		}); err == nil {
			canaries := []struct {
				path string
				t    CanaryType
				uid  uint32
				mode uint32
			}{
				{"/tmp/.aws_credentials", CanaryCloudCred, 1000, 0600},
				{"/etc/shadow.bak", CanaryShadow, 0, 0600},
			}
			for _, c := range canaries {
				if _, regErr := dec.RegisterCanary(c.path, c.t, c.uid, c.mode); regErr == nil {
					_ = dec.DeployCanaryFile(c.path, c.t)
				}
			}
			e.deception = dec
		}
	}

	e.styx = NewStyxEngine(EgressModeMonitored, e.correlator, func(inc XDRIncident) error {
		e.appendIncident(inc)
		return nil
	})
	e.morpheus = NewMorpheusRASP("", e.correlator, func(inc XDRIncident) error {
		e.appendIncident(inc)
		return nil
	})
	if e.selfPID > 0 {
		e.morpheus.RegisterProtectedPID(e.selfPID)
	}
	if airlock, err := NewAirlockInspector(filepath.Join(storageDir, "airlock_quarantine"), 100<<20); err == nil {
		e.airlock = airlock
	}
	if chronos, err := NewChronosScanner([]string{"/usr/bin", "/etc"}, filepath.Join(storageDir, "chronos_checkpoint.json"), 100, time.Millisecond); err == nil {
		e.chronos = chronos
	}

	return e, nil
}

func (e *XDREngine) Responses() *ResponseEngine {
	return e.responses
}

func (e *XDREngine) Deception() *DeceptionEngine {
	return e.deception
}

func (e *XDREngine) Styx() *StyxEngine {
	return e.styx
}

func (e *XDREngine) Morpheus() *MorpheusRASP {
	return e.morpheus
}

func (e *XDREngine) Airlock() *AirlockInspector {
	return e.airlock
}

func (e *XDREngine) Chronos() *ChronosScanner {
	return e.chronos
}

func (e *XDREngine) PlatformCaps() PlatformCapabilities {
	return e.platformCaps
}

func (e *XDREngine) Correlator() *IncidentCorrelator {
	return e.correlator
}

func (e *XDREngine) runtimeSettings() RuntimeSettings {
	if e.settings != nil {
		return e.settings.Get()
	}
	return defaultRuntimeSettings(e.cfg)
}

func xdrSensorMode(execOnline, egressOnline, malwareOnline, cellLSMConfigured, cellLSMOnline bool) string {
	mode := "procfs-bounded-fallback"
	switch {
	case execOnline && egressOnline:
		mode = "ebpf-exec+cgroup-egress+procfs-fallback"
	case execOnline:
		mode = "ebpf-exec+procfs-fallback"
	case egressOnline:
		mode = "cgroup-egress+procfs-bounded-fallback"
	}
	if cellLSMConfigured {
		if cellLSMOnline {
			mode = "bpf-lsm-cell+" + mode
		} else {
			mode = "cell-lsm-unavailable+" + mode
		}
	}
	if malwareOnline {
		return "fanotify-exec+" + mode
	}
	return "malware-events-unavailable+" + mode
}

func desiredCellLSMPolicies(status GaiaCellsStatus) (map[uint64]uint8, error) {
	desired := make(map[uint64]uint8)
	if !status.Enabled {
		return desired, nil
	}
	if !status.Healthy || status.Availability != "online" {
		return nil, errors.New("authenticated Gaia Cells inventory is unavailable")
	}
	for _, cell := range status.Cells {
		if err := validateGaiaCell(cell); err != nil {
			return nil, err
		}
		if (cell.State == "running" || cell.State == "frozen") && cell.NetworkState == "none" {
			desired[cell.CgroupID] = cellLSMDenyNonUnixSocket
		}
	}
	return desired, nil
}

func (e *XDREngine) syncCellLSMPolicies() error {
	if !e.cfg.Cells.Enabled {
		return nil
	}
	if e.core == nil {
		return errors.New("GeDefense core is unavailable for Cell LSM synchronization")
	}
	epoch, err := e.core.CellPolicyEpoch()
	if err != nil {
		return err
	}
	adapter := e.state.Cells()
	if adapter == nil {
		return errors.New("Gaia Cells adapter is unavailable")
	}
	desired, err := desiredCellLSMPolicies(adapter.Status(false))
	if err != nil {
		return err
	}
	if epoch != e.cellPolicyEpoch {
		e.cellPolicyEpoch = epoch
		e.cellPolicies = make(map[uint64]uint8)
	}
	additions := make([]uint64, 0, len(desired))
	for cgroupID, flags := range desired {
		if current, exists := e.cellPolicies[cgroupID]; !exists || current != flags {
			additions = append(additions, cgroupID)
		}
	}
	sort.Slice(additions, func(left, right int) bool { return additions[left] < additions[right] })
	for _, cgroupID := range additions {
		flags := desired[cgroupID]
		if err := e.core.CellPolicySet(cgroupID, flags); err != nil {
			return fmt.Errorf("apply Cell LSM policy for cgroup %d: %w", cgroupID, err)
		}
		e.cellPolicies[cgroupID] = flags
	}
	removals := make([]uint64, 0)
	for cgroupID := range e.cellPolicies {
		if _, exists := desired[cgroupID]; !exists {
			removals = append(removals, cgroupID)
		}
	}
	sort.Slice(removals, func(left, right int) bool { return removals[left] < removals[right] })
	for _, cgroupID := range removals {
		if err := e.core.CellPolicyDelete(cgroupID); err != nil {
			return fmt.Errorf("delete stale Cell LSM policy for cgroup %d: %w", cgroupID, err)
		}
		delete(e.cellPolicies, cgroupID)
	}
	return nil
}

func (e *XDREngine) recordCellLSMDeny(event CoreCellLSMDenyEvent) {
	fingerprint := fmt.Sprintf("cell-lsm:%d:%d:%d", event.CgroupID, event.PID, event.Family)
	if !e.claimFingerprint(fingerprint) {
		return
	}
	summary := fmt.Sprintf(
		"BPF LSM denied socket creation in offline Gaia Cell: cgroup=%d family=%d pid=%d uid=%d",
		event.CgroupID, event.Family, event.PID, event.UID,
	)
	target := fmt.Sprintf("cgroup:%d", event.CgroupID)
	if err := e.state.RecordEvidence(EvidenceRecord{
		Severity: "high", Kind: "cell.lsm_socket_denied", Source: "bpf-lsm",
		Message: summary, Target: target,
	}); err != nil {
		e.markDegraded("Cell LSM evidence commit failed")
	}
	e.state.AddEvent(Event{
		Severity: "high", Kind: "cell.lsm_socket_denied", Source: "bpf-lsm",
		Message: summary, Target: target,
	})
	e.appendIncident(XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: "high", Score: 220, ResponseScore: 220,
		PID: event.PID, UID: event.UID, CellCgroupID: event.CgroupID, SocketFamily: event.Family,
		RuleIDs: []string{"CELL.LSM_SOCKET_DENY"}, Categories: []string{"cell-isolation", "lsm", "network"},
		Summary: summary, Decision: "deny-socket", Action: "deny", Outcome: "blocked by BPF LSM before socket creation",
	})
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
	execTick := time.NewTicker(100 * time.Millisecond)
	netTick := time.NewTicker(time.Duration(runtime.NetworkIntervalSeconds) * time.Second)
	integrityTick := time.NewTicker(time.Duration(e.cfg.XDR.IntegrityIntervalSeconds) * time.Second)
	chronosInterval := time.Duration(e.cfg.XDR.IntegrityIntervalSeconds) * time.Second
	if chronosInterval < 30*time.Second {
		chronosInterval = 30 * time.Second
	}
	chronosTick := time.NewTicker(chronosInterval)
	logVerifyTick := time.NewTicker(30 * time.Second)
	cleanupTick := time.NewTicker(time.Minute)
	behaviorSaveTick := time.NewTicker(5 * time.Minute)
	statusTick := time.NewTicker(time.Second)
	rollbackTick := time.NewTicker(15 * time.Second)
	defer scanTick.Stop()
	defer execTick.Stop()
	defer netTick.Stop()
	defer integrityTick.Stop()
	defer chronosTick.Stop()
	defer logVerifyTick.Stop()
	defer cleanupTick.Stop()
	defer behaviorSaveTick.Stop()
	defer statusTick.Stop()
	defer rollbackTick.Stop()

	integrityEvents, stopIntegrityWatch, watchErr := watchIntegrityChanges(ctx, e.protectedPaths())
	defer stopIntegrityWatch()
	if watchErr != nil {
		e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.integrity_watch_fallback", Source: "integrity", Message: "Native integrity event watch unavailable; bounded periodic verification remains active"})
	}

	_, runtimeXDRMode := e.state.Modes()
	runtime = e.runtimeSettings()
	cellLSMPolicyOnline := true
	if e.cfg.Cells.Enabled {
		if err := e.syncCellLSMPolicies(); err != nil {
			cellLSMPolicyOnline = false
			e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.cell_lsm_policy_unavailable", Source: "bpf-lsm", Message: "Gaia Cell BPF-LSM policy synchronization is unavailable; existing restrictive entries remain installed"})
		}
	}
	cellLSMEventOnline := true
	sensor := xdrSensorMode(true, true, true, e.cfg.Cells.Enabled, cellLSMPolicyOnline)
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
	execSensorOnline := true
	egressSensorOnline := true
	malwareSensorOnline := true
	var execRetryAfter time.Time
	var egressRetryAfter time.Time
	var malwareRetryAfter time.Time
	var cellLSMEventRetryAfter time.Time
	var cellLSMPolicyRetryAfter time.Time
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
		case now := <-execTick.C:
			runtime = e.runtimeSettings()
			if e.cfg.Cells.Enabled && !now.Before(cellLSMEventRetryAfter) {
				events, err := e.core.CellLSMEvents()
				if err != nil {
					if cellLSMEventOnline {
						cellLSMEventOnline = false
						e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.cell_lsm_event_unavailable", Source: "bpf-lsm", Message: "Gaia Cell BPF-LSM enforcement events are unavailable"})
						if runtime.XDREnabled {
							e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, true, false), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
						}
					}
					cellLSMEventRetryAfter = now.Add(10 * time.Second)
				} else {
					if !cellLSMEventOnline {
						cellLSMEventOnline = true
						e.state.AddEvent(Event{Severity: "info", Kind: "xdr.cell_lsm_event_recovered", Source: "bpf-lsm", Message: "Gaia Cell BPF-LSM enforcement event correlation recovered"})
					}
					for _, event := range events {
						e.recordCellLSMDeny(event)
					}
				}
			}
			if !runtime.XDREnabled {
				continue
			}
			if !now.Before(execRetryAfter) {
				events, err := e.core.ExecEvents()
				if err != nil {
					if execSensorOnline {
						execSensorOnline = false
						e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.exec_sensor_fallback", Source: "kernel", Message: "Kernel exec event stream unavailable; bounded procfs detection remains active"})
						e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, e.cfg.Cells.Enabled, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
					}
					execRetryAfter = now.Add(10 * time.Second)
				} else {
					if !execSensorOnline {
						execSensorOnline = true
						e.state.AddEvent(Event{Severity: "info", Kind: "xdr.exec_sensor_recovered", Source: "kernel", Message: "Kernel exec event stream recovered"})
						e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, e.cfg.Cells.Enabled, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
					}
					for _, event := range events {
						process, readErr := readExecProcess(event, e.cfg.XDR.MaxCommandBytes)
						if readErr != nil || process.PID == e.selfPID || e.allowedProcess(process.Exe) {
							continue
						}
						key := fmt.Sprintf("%d:%d", process.PID, process.StartTicks)
						e.mu.Lock()
						_, alreadySeen := e.seen[key]
						e.seen[key] = struct{}{}
						e.mu.Unlock()
						if alreadySeen {
							continue
						}
						e.submit(evaluationJob{process: process, source: "exec"}, true)
					}
				}
			}
			if !now.Before(malwareRetryAfter) {
				batch, err := e.core.MalwareEvents()
				if err != nil {
					if malwareSensorOnline {
						malwareSensorOnline = false
						e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.malware_sensor_unavailable", Source: "kernel", Message: "Fanotify execution decisions remain fail-closed, but their XDR event channel is unavailable"})
						e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, e.cfg.Cells.Enabled, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
					}
					malwareRetryAfter = now.Add(10 * time.Second)
				} else {
					if !malwareSensorOnline {
						malwareSensorOnline = true
						e.state.AddEvent(Event{Severity: "info", Kind: "xdr.malware_sensor_recovered", Source: "kernel", Message: "Fanotify execution block events are again correlated by XDR"})
						e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, e.cfg.Cells.Enabled, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
					}
					if batch.Dropped > 0 {
						e.recordMalwareOverflow(batch.Dropped)
					}
					for _, event := range batch.Events {
						e.recordMalwareEvent(event)
					}
				}
			}
			if now.Before(egressRetryAfter) {
				continue
			}
			egressEvents, err := e.core.EgressEvents()
			if err != nil {
				if egressSensorOnline {
					egressSensorOnline = false
					e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.egress_sensor_fallback", Source: "kernel", Message: "Kernel cgroup egress event stream unavailable; block policy remains owned by the Rust core"})
					e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, e.cfg.Cells.Enabled, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
				}
				egressRetryAfter = now.Add(10 * time.Second)
				continue
			}
			if !egressSensorOnline {
				egressSensorOnline = true
				e.state.AddEvent(Event{Severity: "info", Kind: "xdr.egress_sensor_recovered", Source: "kernel", Message: "Kernel cgroup egress event stream recovered"})
				e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, e.cfg.Cells.Enabled, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
			}
			for _, event := range egressEvents {
				target := event.Destination.String()
				fingerprint := fmt.Sprintf("kernel-egress:%d:%d:%s:%s", event.UID, event.Protocol, target, event.Comm)
				if !e.claimFingerprint(fingerprint) {
					continue
				}
				processName := event.Comm
				if processName == "" {
					processName = "unknown"
				}

				// REAL SENSOR -> STYX ENGINE -> DECISION -> RESPONSE ENGINE ENFORCEMENT
				if e.styx != nil {
					protoStr := "TCP"
					if event.Protocol == 17 {
						protoStr = "UDP"
					}
					allowed, reason, styxErr := e.styx.EvaluateEgress(ctx, "HOST", "DEFAULT", target, 0, protoStr, event.PID, processName)
					if !allowed || styxErr != nil {
						if e.responses != nil {
							_, _ = e.responses.ApplyResponse(
								ctx, now,
								fmt.Sprintf("egress-%d", now.UnixNano()),
								ActionContainIP, "IP", target,
								95, reason, "",
							)
						}
					}
				}

				e.state.AddEvent(Event{
					Severity: "high",
					Kind:     "xdr.egress_blocked",
					Source:   "kernel",
					Message:  fmt.Sprintf("Kernel blocked outbound protocol=%d process=%s pid=%d uid=%d", event.Protocol, processName, event.PID, event.UID),
					Target:   target,
				})
			}
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
		case <-chronosTick.C:
			if e.chronos != nil && runtime.XDREnabled {
				cp, err := e.chronos.Scan(ctx, true)
				if err != nil && !errors.Is(err, context.Canceled) {
					e.state.AddEvent(Event{
						Severity: "warning", Kind: "chronos.scan_failed", Source: "fim",
						Message: fmt.Sprintf("Chronos FIM scan error: %v", err),
					})
				} else if cp != nil && cp.Phase == "COMPLETED" {
					e.state.AddEvent(Event{
						Severity: "info", Kind: "chronos.merkle_verified", Source: "fim",
						Message: fmt.Sprintf("Chronos Merkle tree integrity verified: root=%s files=%d bytes=%d", cp.MerkleRoot, cp.FilesScanned, cp.BytesScanned),
					})
				}
			}
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
		case now := <-rollbackTick.C:
			if e.responses != nil {
				_, _ = e.responses.RollbackExpired(ctx, now)
			}
		case now := <-cleanupTick.C:
			e.cleanupDedupe(now)
		case now := <-statusTick.C:
			runtime = e.runtimeSettings()
			if e.cfg.Cells.Enabled && !now.Before(cellLSMPolicyRetryAfter) {
				if err := e.syncCellLSMPolicies(); err != nil {
					if cellLSMPolicyOnline {
						cellLSMPolicyOnline = false
						e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.cell_lsm_policy_unavailable", Source: "bpf-lsm", Message: "Gaia Cell BPF-LSM policy synchronization is unavailable; existing restrictive entries remain installed"})
					}
					cellLSMPolicyRetryAfter = now.Add(10 * time.Second)
				} else if !cellLSMPolicyOnline {
					cellLSMPolicyOnline = true
					e.state.AddEvent(Event{Severity: "info", Kind: "xdr.cell_lsm_policy_recovered", Source: "bpf-lsm", Message: "Gaia Cell BPF-LSM policy synchronization recovered"})
				}
				if runtime.XDREnabled {
					e.state.SetXDRStatus(XDRStatus{Enabled: true, Mode: runtimeXDRMode, Sensor: xdrSensorMode(execSensorOnline, egressSensorOnline, malwareSensorOnline, true, cellLSMEventOnline && cellLSMPolicyOnline), ProtectedObjects: len(e.protected), QueueCapacity: cap(e.highJobs) + cap(e.normalJobs), Behavior: e.behavior.Summary()})
				}
			}
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
	if !hasTrustedExecutableIdentity(p) {
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

	// Morpheus RASP: Active Memory-Scraping / Ptrace Inspection in Data Path
	if e.morpheus != nil {
		if raspEvt, raspErr := e.morpheus.InspectProcess(p); raspErr != nil && raspEvt != nil {
			now := time.Now().UTC()
			e.state.AddEvent(Event{
				Severity: "critical", Kind: "morpheus.memory_scraping_blocked", Source: "rasp",
				Message: fmt.Sprintf("Morpheus RASP blocked memory scraping by PID %d (%s)", p.PID, p.Comm),
			})
			if e.responses != nil {
				freezeTarget := fmt.Sprintf("%d:%d", p.PID, p.StartTicks)
				evDigest := raspEvt.EventID
				if raspEvt.AttackNode != nil {
					evDigest = raspEvt.AttackNode.ComputeNodeDigest()
				}
				_, _ = e.responses.ApplyResponse(
					context.Background(), now,
					raspEvt.EventID, ActionFreezeExecution, "PID", freezeTarget,
					100, "MORPHEUS_RASP_MEMORY_SCRAPING", evDigest,
				)
			}
		}
	}

	// Styx Egress Engine: Live Socket Connection Evaluation in Data Path
	if e.styx != nil && len(conns) > 0 {
		for _, c := range conns {
			if ip := net.ParseIP(c.RemoteIP); ip != nil {
				now := time.Now().UTC()
				if allowed, reason, styxErr := e.styx.EvaluateEgress(context.Background(), "CGROUP", p.Cgroup, c.RemoteIP, c.RemotePort, c.Protocol, p.PID, p.Comm); !allowed || styxErr != nil {
					if e.responses != nil {
						_, _ = e.responses.ApplyResponse(
							context.Background(), now,
							fmt.Sprintf("egress-conn-%d", now.UnixNano()),
							ActionContainIP, "IP", c.RemoteIP,
							95, reason, "",
						)
					}
				}
			}
		}
	}

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
	now := time.Now().UTC()
	incidentID := randomID()
	storyNode := AttackStoryNode{
		NodeID:     fmt.Sprintf("node-%d-%d", p.PID, now.UnixNano()),
		Timestamp:  now,
		Sensor:     source,
		Category:   strings.Join(decision.Categories, ","),
		EventType:  "PROCESS_EXEC",
		EntityID:   fmt.Sprintf("PID:%d", p.PID),
		Actor:      fmt.Sprintf("UID:%d", p.UID),
		Severity:   severity,
		Confidence: decision.ResponseScore,
		CausalEdge: EdgeForkedFrom,
		EventUUID:  incidentID,
		Metadata: map[string]string{
			"comm":   p.Comm,
			"exe":    p.Exe,
			"remote": decision.Remote,
		},
	}
	var storyNodes []AttackStoryNode
	recordHash := storyNode.ComputeNodeDigest()
	execChainID := storyNode.NodeID
	if e.correlator != nil {
		actorStr := fmt.Sprintf("UID:%d", p.UID)
		categoryStr := "EXEC"
		if len(decision.Categories) > 0 {
			categoryStr = decision.Categories[0]
		}
		graph, _, err := e.correlator.IngestEvent(now, actorStr, p.Comm, categoryStr, storyNode)
		if err == nil && graph != nil {
			storyNodes = graph.CloneNodes()
			recordHash = graph.EvidenceRoot()
			execChainID = graph.ChainID
		}
	}
	if len(storyNodes) == 0 {
		storyNodes = []AttackStoryNode{storyNode}
	}

	incident := XDRIncident{
		ID: incidentID, Time: now, Severity: severity, Score: decision.Score, ResponseScore: decision.ResponseScore, KillSignals: decision.KillSignals,
		PID: p.PID, PPID: p.PPID, StartTicks: p.StartTicks, UID: p.UID, Process: p.Comm, Executable: p.Exe,
		Parent: p.ParentExe, Remote: decision.Remote, CommandPreview: e.rules.RedactCommand(p.Cmdline, e.cfg.XDR.CommandPreviewBytes),
		CommandSHA256: p.CmdSHA256, RuleIDs: decision.RuleIDs, Categories: decision.Categories, Summary: decision.Summary,
		Decision: decision.Decision, Action: "none", Outcome: "observed",
		ExecutionChainID: execChainID, AttackStory: storyNodes, RecordHash: recordHash,
	}
	incident.Action, incident.Outcome = e.respond(incident)
	e.appendIncident(incident)
	e.state.AddEvent(Event{Severity: severity, Kind: "xdr." + incident.Decision, Source: source, Message: incident.Summary + " [" + strings.Join(incident.RuleIDs, ",") + "]", Target: fmt.Sprintf("pid:%d", p.PID)})
}

func (e *XDREngine) appendIncident(incident XDRIncident) {
	if e.logger != nil {
		if hash, err := e.logger.Append(incident); err == nil {
			incident.RecordHash = hash
		} else {
			log.Printf("xdr incident log: %v", err)
			e.markDegraded("incident log unavailable")
		}
	}
	e.state.AddIncident(incident)
}

func (e *XDREngine) recordMalwareEvent(event CoreMalwareEvent) {
	severity := "high"
	score := 180
	ruleID := "MALWARE.CONTENT_SUSPICIOUS"
	if event.State == "malicious" {
		severity = "critical"
		score = 250
		ruleID = "MALWARE.CONTENT_MATCH"
	} else if event.State == "blocked" {
		severity = "critical"
		score = 250
		ruleID = "MALWARE.SCAN_FAILURE"
	}
	message := fmt.Sprintf("Execution blocked before first instruction: type=%s reason=%s size=%d sha256=%s pid=%d uid=%d", event.Classification, event.Reason, event.Size, event.SHA256, event.PID, event.UID)
	e.state.AddEvent(Event{Severity: severity, Kind: "malware.execution_blocked", Source: "fanotify", Message: message, Target: event.Path})
	fingerprint := fmt.Sprintf("malware:%d:%s:%s:%s", event.PID, event.SHA256, event.State, event.Reason)
	if !e.claimFingerprint(fingerprint) {
		return
	}
	e.appendIncident(XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: severity, Score: score, ResponseScore: score,
		PID: event.PID, UID: event.UID, Executable: event.Path, CommandSHA256: event.SHA256,
		RuleIDs: []string{ruleID}, Categories: []string{"malware", "integrity"}, Summary: message,
		Decision: "deny-execution", Action: "deny-exec", Outcome: "blocked by fanotify before execution",
	})
}

func (e *XDREngine) recordManualMalwareFinding(path string, result MalwareScanResult) {
	severity := "high"
	score := 180
	ruleID := "MALWARE.MANUAL_SUSPICIOUS"
	if result.State == "malicious" {
		severity = "critical"
		score = 250
		ruleID = "MALWARE.MANUAL_MATCH"
	}
	fingerprint := fmt.Sprintf("manual-malware:%s:%s:%s", result.SHA256, result.State, result.Reason)
	if !e.claimFingerprint(fingerprint) {
		return
	}
	summary := fmt.Sprintf("Manual content scan %s: type=%s reason=%s size=%d sha256=%s", result.State, result.Classification, result.Reason, result.Size, result.SHA256)
	e.appendIncident(XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: severity, Score: score, ResponseScore: score,
		Executable: path, CommandSHA256: result.SHA256, RuleIDs: []string{ruleID}, Categories: []string{"malware", "manual-scan"},
		Summary: summary, Decision: "alert", Action: "none", Outcome: "operator scan recorded; quarantine authorization required",
	})
}

func (e *XDREngine) recordMalwareOverflow(dropped uint64) {
	reason := fmt.Sprintf("malware event queue overflow: %d records were dropped", dropped)
	e.markDegraded(reason)
	e.state.AddEvent(Event{Severity: "critical", Kind: "malware.event_queue_overflow", Source: "fanotify", Message: reason})
	fingerprint := fmt.Sprintf("malware-overflow:%d", dropped)
	if !e.claimFingerprint(fingerprint) {
		return
	}
	e.appendIncident(XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: "critical", Score: 250, ResponseScore: 250,
		RuleIDs: []string{"MALWARE.EVENT_QUEUE_OVERFLOW"}, Categories: []string{"malware", "sensor-health"}, Summary: reason,
		Decision: "degrade", Action: "disable-response", Outcome: "fanotify blocking remains fail-closed; XDR active response disabled",
	})
}

func hasTrustedExecutableIdentity(p ProcessSample) bool {
	executable := filepath.Clean(strings.TrimSuffix(p.Exe, " (deleted)"))
	return executable != "." && executable != string(filepath.Separator) &&
		filepath.IsAbs(executable)
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
		if e.responses != nil && i.PID > 0 {
			respRec, err := e.responses.ApplyResponse(
				context.Background(),
				time.Now().UTC(),
				i.ID,
				ActionFreezeExecution,
				"PID",
				strconv.Itoa(i.PID),
				i.Score,
				rule,
				i.RecordHash,
			)
			if err != nil {
				return actionName(quarantined, "stop"), "failed: " + err.Error()
			}
			return actionName(quarantined, "stop"), fmt.Sprintf("process frozen through reversible response engine (TTL=%s)", respRec.ExpiresAt.Sub(respRec.StartedAt))
		}
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
	e.appendIncident(i)
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
