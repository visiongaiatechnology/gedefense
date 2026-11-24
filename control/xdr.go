// STATUS: DIAMANT VGT SUPREME
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
	"unicode/utf8"
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
	cfg              Config
	state            *State
	core             *CoreClient
	feeds            *FeedManager
	policy           *PolicyStore
	settings         *SettingsStore
	release          *ReleaseController
	rules            *XDRRuleEngine
	baseline         *XDRBaseline
	behavior         *BehaviorModel
	logger           *IncidentLogger
	selfPID          int
	seeded           bool
	seen             map[string]struct{}
	dedupe           map[string]time.Time
	tamperSeen       map[string]string
	forensicFailures map[string]int
	protected        map[string]protectedObject
	cellPolicyEpoch  string
	cellPolicies     map[uint64]uint8
	platformCaps     PlatformCapabilities
	correlator       *IncidentCorrelator
	responses        *ResponseEngine
	deception        *DeceptionEngine
	styx             *StyxEngine
	// POINT 3 / P3-T5: the kernel-side StyX detector and the policy syncer are
	// separate from the Go-side StyxEngine above (which remains a MONITORED
	// userspace evaluator). Their state is reported separately and never folded
	// into the XDR sensor string.
	styxBeacon *StyxBeaconEngine
	styxPolicy *styxPolicySyncer
	// styxFlowMu guards the kernel flow-health sample; the detector keeps its own
	// mutexes and is never accessed through this one. The previous sample, the last
	// successful drain timestamp and the last reported telemetry state are kept
	// here (M2) so drop ratio, drain lag and a "telemetry degraded" transition can
	// be derived from real samples without blocking the core.
	styxFlowMu             sync.Mutex
	styxFlowHealth         CoreStyxFlowHealth
	styxFlowHealthAt       time.Time
	styxFlowHealthErr      string
	styxFlowHealthPrev     CoreStyxFlowHealth
	styxFlowHealthPrevAt   time.Time
	styxFlowLastDrainAt    time.Time
	styxFlowTelemetryState string
	// M2.2: kernel ransomware sensor integration. ransomCore is the subset of the
	// privileged client the freeze/escalation contract needs (interface so the
	// synthetic-answer tests need no socket).
	ransomCore            ransomCore
	ransomMu              sync.Mutex
	ransomStatus          CoreRansomStatus
	ransomStatusAt        time.Time
	ransomStatusErr       string
	ransomCapabilityKnown bool
	ransomSeen            map[string]time.Time
	ransomArmedRequested  bool
	ransomLastOverflow    time.Time
	// M2.4: kernel credential guard integration (same interface pattern as the
	// ransomware sensor, so the synthetic-answer tests need no socket).
	credCore            credGuardCore
	credMu              sync.Mutex
	credStatus          CoreCredGuardStatus
	credStatusAt        time.Time
	credStatusErr       string
	credCapabilityKnown bool
	credSeen            map[string]time.Time
	credArmedRequested  bool
	credLastOverflow    time.Time
	// V6.3.0 AP-0: kernel sensor self-protection (eBPF pin manifest, synthetic
	// canary self-test, bounded self-tamper queue) plus the ring-drop watchdog
	// that turns silent high-priority ring drops into SBC-EVID-08 evidence.
	selfGuardCore            selfGuardCore
	selfGuardMu              sync.Mutex
	selfGuardStatus          CoreSelfGuardStatus
	selfGuardStatusAt        time.Time
	selfGuardStatusErr       string
	selfGuardCapabilityKnown bool
	selfGuardSeen            map[string]time.Time
	selfGuardArmedRequested  bool
	selfGuardLastOverflow    time.Time
	selfGuardDropBaselines   map[string]uint64
	// V6.3.0 AP-1: executable-inode trust gate. The kernel keys on the real exe
	// inode; this projection only correlates name/path mismatch evidence.
	execInodeCore            execInodeCore
	execInodeMu              sync.Mutex
	execInodeStatus          CoreExecInodeStatus
	execInodeStatusAt        time.Time
	execInodeStatusErr       string
	execInodeCapabilityKnown bool
	execInodeSeen            map[string]time.Time
	execInodeLastOverflow    time.Time
	// V6.3.0 AP-2: attach-time eBPF guard (helper-risk bitmap, observe-only).
	bpfGuardCore            bpfGuardCore
	bpfGuardMu              sync.Mutex
	bpfGuardStatus          CoreBpfGuardStatus
	bpfGuardStatusAt        time.Time
	bpfGuardStatusErr       string
	bpfGuardCapabilityKnown bool
	bpfGuardSeen            map[string]time.Time
	bpfGuardArmedRequested  bool
	bpfGuardLastOverflow    time.Time
	bpfGuardEpoch           string
	// V6.3.0 AP-3: cross-view verifier (independent kernel/userland views).
	crossViewCore            crossViewCore
	crossViewMu              sync.Mutex
	crossViewStatus          CoreCrossViewStatus
	crossViewStatusAt        time.Time
	crossViewStatusErr       string
	crossViewCapabilityKnown bool
	crossViewSeen            map[string]time.Time
	crossViewLastOverflow    time.Time
	// V6.3.0 AP-4: io_uring/LKM hook observations.
	kernelHooksCore            kernelHooksCore
	kernelHooksMu              sync.Mutex
	kernelHooksStatus          CoreKernelHookStatus
	kernelHooksStatusAt        time.Time
	kernelHooksStatusErr       string
	kernelHooksCapabilityKnown bool
	kernelHooksSeen            map[string]time.Time
	kernelHooksArmedRequested  bool
	kernelHooksEpoch           string
	kernelHooksLastOverflow    time.Time
	// V6.3.0 AP-5: persistence/peripheral integrity guard.
	persistenceCore            persistenceCore
	persistenceMu              sync.Mutex
	persistenceStatus          CorePersistenceStatus
	persistenceStatusAt        time.Time
	persistenceStatusErr       string
	persistenceCapabilityKnown bool
	persistenceSeen            map[string]time.Time
	persistenceArmedRequested  bool
	persistenceLastOverflow    time.Time
	// V6.3.0 AP-6: StyX phase-2 (bidirectional PCR, IdleHint coupling), bounded
	// DNS tunnelling capture and the GIEF v1.0 / SBC finding envelopes.
	styxPhase2 *StyxPhase2Engine
	dnsTunnel  *DNSTunnelEngine
	gief       *GIEFEngine
	sbc        *SBCFusionEngine
	// V6.3.0 AP-7: unified PermitV1 broker and the persistent review queue.
	permits     *PermitBroker
	reviewQueue *ReviewQueue
	// V6.3.0 AP-9 (S12): independent high-priority security evidence ring and
	// the aggregated telemetry flood-suppression facts.
	secCrit                *SecCritEngine
	secCritCore            secCritCore
	secCritMu              sync.Mutex
	secCritStatus          CoreSecCritStatus
	secCritStatusAt        time.Time
	secCritStatusErr       string
	secCritCapabilityKnown bool
	secCritSeen            map[string]time.Time
	secCritLastOverflow    time.Time
	probeCore               xdrKernelCore
	probeMu                 sync.Mutex
	probeSeen               map[string]time.Time
	styxLastPrune           time.Time
	styxLastOverflowEvent   time.Time
	// POINT 1 / P1-T5: the Titan exec-gate policy syncer and the bounded kernel
	// decision drain. The syncer owns its own retry/epoch loop like the StyX one;
	// everything below is the read-only projection behind the API, guarded by
	// titanExecMu so a drain can never hold up a status render.
	titanExec                  *titanExecPolicySyncer
	titanExecMu                sync.Mutex
	titanExecCapability        string
	titanExecDrainErr          string
	titanExecHealth            CoreTitanExecHealth
	titanExecHealthAt          time.Time
	titanExecHealthErr         string
	titanExecHistory           []CoreTitanExecEvent
	titanExecStats             titanExecEventCounters
	titanExecLastOverflowEvent time.Time
	// POINT 2 / P2-T3: the ephemeral parser-cell manager. It owns its own helper
	// client and supervisor loop; the XDR engine only attaches it, starts it with the
	// engine context and projects the settings revision onto it.
	parserCells *ParserCellManager
	// POINT 5 / P5-T3: the Emergency Lockdown engine observes the incident stream
	// through appendIncident. It is optional: without it the XDR path is unchanged
	// and no lockdown event is ever created.
	lockdown       *LockdownEngine
	morpheus       *MorpheusRASP
	airlock        *AirlockInspector
	l7Recent       *L7CorrelationStore
	chronos        *ChronosScanner
	chronosRunning atomic.Bool
	degraded       bool
	degradeWhy     string
	degradeCauses  map[string]string
	recoveryGate   chan struct{}
	// updateWindow is the only sanctioned way to replace this installation's own binaries
	// while XDR runs. It is opened exclusively by BeginSignedUpdateWindow after a signed
	// release manifest verified; see selfTamper/checkProtected.
	updateWindow *xdrUpdateWindow
	mu           sync.RWMutex
	highJobs     chan evaluationJob
	normalJobs   chan evaluationJob
	workers      sync.WaitGroup
	drops        atomic.Uint64
	evaluated    atomic.Uint64
	anomalies    atomic.Uint64
}

func (e *XDREngine) SetReleaseController(release *ReleaseController) {
	e.release = release
}

// xdrUpdateWindow is an explicitly authorized, signed window in which this installation's
// own binaries may be replaced.
//
// The baseline comparison cannot tell an approved update from an attacker's replacement:
// both change the bytes. The sanctioned way to replace an own component is therefore an
// operator action that verifies the signed release manifest first and opens this bounded
// window. Outside it, every change to an own component is XDR.SELF_TAMPER plus a
// release-blocking degradation.
type xdrUpdateWindow struct {
	// ManifestSHA256 identifies the signed release manifest that opened the window.
	ManifestSHA256 string
	Reason         string
	GrantedAt      time.Time
	ExpiresAt      time.Time
	// Expected maps the installed artifact path to the SHA-256 the signed manifest requires
	// for it. An observation matching that digest is attributable to the release and is the
	// only change the window permits.
	Expected map[string]string
}

const (
	xdrUpdateWindowDefaultTTL = 15 * time.Minute
	xdrUpdateWindowMaxTTL     = time.Hour
)

// BeginSignedUpdateWindow verifies a signed release manifest and opens a bounded, attributable
// update window for this installation's own binaries.
//
// The manifest is checked with the same verifier the release pipeline uses: Ed25519 signature
// over the canonical envelope against the pinned release key, and every artifact digest below
// artifactDir. Only a manifest that verifies can open the window, and only the exact bytes it
// names may replace an own component while the window is open. Everything else remains
// tampering.
func (e *XDREngine) BeginSignedUpdateWindow(manifestPath, publicKeyPath, artifactDir, reason string, ttl time.Duration) error {
	if e == nil {
		return errors.New("XDR engine unavailable")
	}
	document, err := VerifyReleaseManifest(manifestPath, publicKeyPath, artifactDir)
	if err != nil {
		return fmt.Errorf("signed update window refused: %w", err)
	}
	manifestDigest, _, err := fileSHA256(manifestPath)
	if err != nil {
		return fmt.Errorf("signed update window refused: manifest digest: %w", err)
	}
	expected := make(map[string]string)
	for _, path := range productArtifactPaths() {
		artifact, ok := document.Envelope.Artifacts[filepath.Base(path)]
		if !ok {
			continue
		}
		expected[resolveBaselinePath(path)] = strings.ToLower(artifact.SHA256)
	}
	if len(expected) == 0 {
		return errors.New("signed update window refused: the release manifest names none of this installation's executables")
	}
	if ttl <= 0 {
		ttl = xdrUpdateWindowDefaultTTL
	}
	if ttl > xdrUpdateWindowMaxTTL {
		ttl = xdrUpdateWindowMaxTTL
	}
	now := time.Now().UTC()
	window := &xdrUpdateWindow{
		ManifestSHA256: manifestDigest,
		Reason:         strings.TrimSpace(reason),
		GrantedAt:      now,
		ExpiresAt:      now.Add(ttl),
		Expected:       expected,
	}
	e.mu.Lock()
	e.updateWindow = window
	e.mu.Unlock()
	e.state.AddEvent(Event{
		Severity: "high", Kind: "xdr.update_window_opened", Source: "integrity",
		Message: fmt.Sprintf("Signed package-update window opened for %d own executable(s); manifest=%s expires=%s",
			len(expected), manifestDigest, window.ExpiresAt.Format(time.RFC3339)),
		Target: productArtifactRoot(),
	})
	return nil
}

// EndSignedUpdateWindow closes an open window. An operator uses it when an update completed;
// the window also expires by itself.
func (e *XDREngine) EndSignedUpdateWindow(reason string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	open := e.updateWindow != nil
	e.updateWindow = nil
	e.mu.Unlock()
	if open {
		e.state.AddEvent(Event{Severity: "high", Kind: "xdr.update_window_closed", Source: "integrity",
			Message: "Signed package-update window closed: " + strings.TrimSpace(reason)})
	}
}

// SignedUpdateWindowActive reports whether a verified update window is currently open.
func (e *XDREngine) SignedUpdateWindowActive() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	window := e.updateWindow
	e.mu.RUnlock()
	return window != nil && time.Now().UTC().Before(window.ExpiresAt)
}

// updateWindowCovers reports whether a change to identity is attributable to the currently
// open, signed update window.
//
// A missing object is covered only while the window expects that exact artifact: an atomic
// package update replaces files by rename and can expose a short gap. A present object is
// covered only when its digest equals the digest the signed manifest requires. An expired
// window permits nothing.
func (e *XDREngine) updateWindowCovers(identity, digest string, missing bool) bool {
	e.mu.Lock()
	window := e.updateWindow
	if window == nil {
		e.mu.Unlock()
		return false
	}
	if !time.Now().UTC().Before(window.ExpiresAt) {
		e.updateWindow = nil
		e.mu.Unlock()
		e.state.AddEvent(Event{Severity: "high", Kind: "xdr.update_window_expired", Source: "integrity",
			Message: "Signed package-update window expired without completing; own-component changes are tampering again"})
		return false
	}
	want, ok := window.Expected[identity]
	if !ok {
		// A file being replaced atomically can be momentarily absent, which makes
		// EvalSymlinks(file) fail and leaves identity as the stable route (for example
		// .../current/bin/gedefense-control) instead of the release path the window recorded.
		// Resolving the parent keeps the transient gap attributable to the same artifact.
		if parent, err := filepath.EvalSymlinks(filepath.Dir(identity)); err == nil {
			want, ok = window.Expected[filepath.Join(parent, filepath.Base(identity))]
		}
	}
	e.mu.Unlock()
	if !ok {
		return false
	}
	if missing {
		return true
	}
	return digest != "" && strings.EqualFold(digest, want)
}

// applyAuthorizedUpdate records a change that the signed update window permitted and moves the
// in-memory baseline to the new bytes, so a completed update does not look like tampering on the
// next check. The window consumes the artifact it expected; when the last expected artifact has
// been observed the window closes on its own.
func (e *XDREngine) applyAuthorizedUpdate(path, identity, digest, observed string, missing bool, updated protectedObject) {
	if !e.claimTamper(identity, observed) {
		return
	}
	e.mu.Lock()
	window := e.updateWindow
	closed := false
	if window != nil {
		if !missing {
			delete(window.Expected, identity)
			if len(window.Expected) == 0 {
				e.updateWindow = nil
				closed = true
			}
		}
	}
	if !missing {
		for key, object := range e.protected {
			if resolvedIdentity(key) != identity {
				continue
			}
			// Keep the path the object was enrolled under; only its observed state changes.
			e.protected[key] = protectedObject{path: object.path, digest: updated.digest, mode: updated.mode, size: updated.size}
		}
	}
	e.mu.Unlock()
	e.state.AddEvent(Event{Severity: "high", Kind: "xdr.update_window_artifact_applied", Source: "integrity",
		Message: "GeDefense component replaced inside a verified signed update window", Target: path})
	if closed {
		e.state.AddEvent(Event{Severity: "high", Kind: "xdr.update_window_closed", Source: "integrity",
			Message: "Signed package-update window closed: every artifact named by the manifest was observed"})
	}
}

// newProtectedObject re-reads the observed state of path so an authorized update can move the
// in-memory baseline to it.
func newProtectedObject(path, digest string) (protectedObject, bool) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return protectedObject{}, false
	}
	return protectedObject{path: path, digest: digest, mode: st.Mode().Perm(), size: st.Size()}, true
}

func NewXDREngine(cfg Config, state *State, core *CoreClient, feeds *FeedManager, policy *PolicyStore, settings *SettingsStore, configPath string) (*XDREngine, error) {
	runtime := defaultRuntimeSettings(cfg)
	if settings != nil {
		runtime = settings.Get()
	}
	// Restart-class Fabric settings become the active boot configuration here.
	// They are deliberately not hot-swapped later because worker channels and
	// integrity watch roots are constructed once at engine startup.
	cfg.XDR.WorkerCount = runtime.XDRFabric.WorkerCount
	cfg.XDR.QueueCapacity = runtime.XDRFabric.QueueCapacity
	cfg.XDR.ProtectedPaths = append([]string(nil), runtime.XDRFabric.ProtectedPaths...)
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
	behavior.Configure(runtime.XDRFabric)
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
		tamperSeen: map[string]string{},
		protected:  map[string]protectedObject{}, cellPolicies: map[uint64]uint8{},
		degradeCauses: map[string]string{}, recoveryGate: make(chan struct{}, 1),
		highJobs: make(chan evaluationJob, highCap), normalJobs: make(chan evaluationJob, normalCap),
		titanExecCapability: titanExecCapabilityUnknown,
	}
	e.recoveryGate <- struct{}{}
	// V6.3.0 AP-6/AP-7: the phase-2 analytics, GIEF/SBC envelopes, PermitV1
	// broker and review queue are constructed inert. They enrich evidence and
	// can only suppress/downgrade - never create or escalate - a response.
	e.styxPhase2 = NewStyxPhase2Engine()
	e.dnsTunnel = NewDNSTunnelEngine()
	e.gief = NewGIEFEngine()
	e.sbc = NewSBCFusionEngine()
	e.permits = NewPermitBroker()
	e.reviewQueue = NewReviewQueue()
	// V6.3.0 AP-9 (S12): the high-priority ring engine is inert until the core
	// advertises the family; it can never create or escalate a response.
	e.secCrit = NewSecCritEngine()
	if core != nil {
		// M2.2: the same privileged client implements the RANSOM_* family; the
		// interface keeps the freeze/escalation contract testable without a socket.
		e.ransomCore = core
		// M2.4: the credential guard lives on the same authenticated channel.
		e.credCore = core
		e.probeCore = core
		// V6.3.0: sensor self-protection (AP-0), executable-inode trust (AP-1)
		// and the attach-time eBPF guard (AP-2) ride the same authenticated
		// VGT3 channel; each family keeps its own cadence and retry state.
		e.selfGuardCore = core
		e.execInodeCore = core
		e.bpfGuardCore = core
		// V6.3.0 AP-9 (S12): the high-priority security ring rides the same
		// authenticated channel.
		e.secCritCore = core
		// V6.3.0 AP-3/AP-4/AP-5: cross-view, io_uring/LKM hooks and
		// persistence/peripheral integrity ride the same authenticated channel.
		e.crossViewCore = core
		e.kernelHooksCore = core
		e.persistenceCore = core	}
	if err := logger.Healthy(); err != nil {
		e.markDegradedCause("incident_log", "incident log integrity failure: "+err.Error())
	} else if err := e.restoreIncidentHistory(); err != nil {		// The history could not be restored. Saying so is better than showing an empty
		// forensic view that looks like a host nothing has ever happened to.
		e.markDegradedCause("incident_log", "incident history could not be restored: "+err.Error())
	}
	if summary := behavior.Summary(); cfg.XDR.BehaviorEnabled && !summary.IntegrityOK {
		e.markDegradedCause("behavior", "behavior profile integrity failure: "+summary.Error)
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
	e.l7Recent = NewL7CorrelationStore(30*time.Second, 4096)
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
			// Deception decoys come exclusively from the administrated policy and
			// are deployed by the privileged core. Attach the transport BEFORE the
			// first ApplyPolicy projection (main.go applies the Hardening fabric
			// right after NewXDREngine), otherwise the engine falls back to writing
			// decoys with the unprivileged identity.
			AttachCanaryBroker(dec, core)
			e.deception = dec
		}
	}

	// G-DET-06 (documented limitation): the Go-side StyX engine runs in
	// MONITORED mode on purpose. It provides telemetry, correlation and incident
	// evidence; it is NOT a default-deny egress enforcement point. Kernel-level
	// egress enforcement is owned by the Rust core/eBPF layer (T4). Do not count
	// this engine as enforced egress control.
	e.styx = NewStyxEngine(EgressModeMonitored, e.correlator, func(inc XDRIncident) error {
		e.appendIncident(inc)
		return nil
	})
	if feeds != nil {
		e.styx.SetThreatIndex(feeds.BlockIndex())
	}
	// POINT 3 / P3-T5: the kernel-side StyX detector (aggregated per-cgroup flow
	// telemetry, docs/POINT3-EGRESS-BEACON.md §8.2) and the policy syncer. Both are
	// constructed inert: the detector only runs once the operator namespace enables
	// it and the core proved the capability, and the syncer only pushes what the
	// persisted revision says. The detector's sink is the only path from a beacon
	// finding into XDR.
	e.styxBeacon = NewStyxBeaconEngine(StyxBeaconConfig{
		Enabled:                 false,
		FlowCapabilityKnown:     false,
		DNSObservationAvailable: false,
		CanaryCorrelation:       e.styxCanaryCorrelation,
	}, e.correlator, e.emitStyxBeaconIncident)
	e.applyStyxBeaconSettings(runtime)
	e.styxPolicy = NewStyxPolicySyncer(core, state, runtime)
	// POINT 1 / P1-T5: the Titan exec-gate policy syncer is independent of the XDR
	// detection state for the same reason the StyX syncer is: the kernel policy is
	// not an XDR feature, and a slow or absent core must never roll back an
	// operator's settings revision. A nil core stays an honest "no client" fact
	// instead of a typed-nil interface that would panic on first use.
	var titanExecCore titanExecPolicyCore
	if core != nil {
		titanExecCore = core
	}
	e.titanExec = NewTitanExecPolicySyncer(titanExecCore, state, runtime, titanExecPlanDeps{})
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
	// The digest inventory is operational state, so the checkpoint is sealed with
	// the same storage cipher the FIM baseline and evidence ledger use.
	var chronosCipher *StorageCipher
	if storageKeyPath != "" {
		if cipher, cipherErr := NewStorageCipher(storageKeyPath, cfg.Node.Name); cipherErr == nil && cipher != nil {
			chronosCipher = cipher
		}
	}
	if chronos, err := NewChronosScanner([]string{"/usr/bin", "/etc"}, filepath.Join(storageDir, "chronos_checkpoint.json"), 100, time.Millisecond, chronosCipher); err == nil {
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

// AttachParserCells binds the ephemeral parser-cell manager to the engine lifetime.
// Additive: without wiring the status payload stays byte-identical and no helper
// socket is ever opened.
func (e *XDREngine) AttachParserCells(manager *ParserCellManager) {
	e.parserCells = manager
}

// ParserCells exposes the wired manager (nil without P2-T3 wiring) to the API and
// to the automatic CellGuard dispatch.
func (e *XDREngine) ParserCells() *ParserCellManager {
	if e == nil {
		return nil
	}
	return e.parserCells
}

// AttachLockdown binds the Emergency Lockdown engine (POINT 5 / P5-T3). Every
// incident recorded through appendIncident is offered to the engine's closed
// trigger vocabulary; without the wiring the XDR path is byte-identical.
func (e *XDREngine) AttachLockdown(engine *LockdownEngine) {
	e.lockdown = engine
}

// Lockdown exposes the wired engine (nil without POINT 5 wiring) so the settings
// module can report its honest runtime projection.
func (e *XDREngine) Lockdown() *LockdownEngine {
	if e == nil {
		return nil
	}
	return e.lockdown
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
		// The ledger owns this condition: State.RecordEvidence names it precisely and clears it
		// again when the ledger recovers. Marking it here as well produced a second, vaguer cause
		// that nothing could clear.
		log.Printf("cell lsm evidence commit failed: %v", err)
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
	e.mu.RLock()
	defer e.mu.RUnlock()
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

	// Kernel-observed deception canaries: fanotify events become incidents and
	// reversible responses without any manual API call.
	StartCanarySensor(ctx, e.core, e.deception, e.state)

	// The StyX policy syncer owns its own retry/epoch loop. Driving it from a
	// sensor tick would let a slow core delay event processing; it also has to work
	// when the XDR engine itself is disabled, because egress enforcement is a
	// kernel policy and not an XDR detection feature.
	if e.styxPolicy != nil {
		go e.styxPolicy.Run(ctx)
	}
	// POINT 1 / P1-T5: the Titan exec-gate syncer owns the same independent
	// retry/epoch loop; it also has to work when the XDR engine is disabled,
	// because the kernel exec policy is not an XDR detection feature.
	if e.titanExec != nil {
		go e.titanExec.Run(ctx)
	}
	// POINT 2 / P2-T3: the parser-cell manager owns the same independent supervisor
	// loop (helper health, TTL deadlines, ledger reconcile). It is inert while the
	// namespace is disabled, so this goroutine costs one ticker and no request.
	if e.parserCells != nil {
		go e.parserCells.Run(ctx)
	}

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
	// POINT 3 / P3-T5: independent rate limits for the kernel flow channel. The
	// 100 ms tick stays the clock, but the flow drain/health polls run on their own
	// 1 s / 10 s cadence so they can never delay exec, egress or malware ingestion.
	var styxFlowRetryAfter time.Time
	var styxHealthRetryAfter time.Time
	// POINT 1 / P1-T5: the kernel exec-gate drain/health own their rate limits too;
	// the 100 ms tick is only the clock, so neither can delay exec, egress or
	// malware ingestion.
	var titanExecDrainRetryAfter time.Time
	var titanExecHealthRetryAfter time.Time
	// M2.2: independent cadence for the kernel ransomware sensor (1 s events,
	// 10 s status) so a freeze record is never delayed behind other ingestion.
	var ransomDrainRetryAfter time.Time
	var ransomStatusRetryAfter time.Time
	// M2.4: independent cadence for the kernel credential guard (1 s decisions,
	// 10 s status).
	var credGuardDrainRetryAfter time.Time
	var credGuardStatusRetryAfter time.Time
	// V6.3.0: independent cadence per new kernel family so a slow status query
	// can never delay another sensor's drain.
	var selfGuardRetryAfter time.Time
	var execInodeRetryAfter time.Time
	var bpfGuardRetryAfter time.Time
	var crossViewRetryAfter time.Time
	var kernelHooksRetryAfter time.Time
	var persistenceRetryAfter time.Time
	// V6.3.0 AP-6/AP-7 cadences (phase-2 analytics, DNS, permit maintenance).
	var styxPhase2RetryAfter time.Time
	var dnsTunnelRetryAfter time.Time
	var permitRetryAfter time.Time
	// V6.3.0 AP-9 (S12): high-priority ring cadence and SBC corroboration drain.
	var secCritRetryAfter time.Time
	var sbcCorroborationRetryAfter time.Time
	var execArgvRetryAfter time.Time
	var kernelProbeRetryAfter time.Time
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
			p, err := scanLinuxProcesses(runtime.XDRFabric.MaxCommandBytes)
			if err != nil {
				// A failed /proc listing is a hiccup, not a sensor outage: it happens when the
				// descriptor table is momentarily full, and the scan a second later succeeds. It
				// degrades only once it repeats, and the next successful scan clears it again -
				// otherwise a single transient failure would pause the platform for good.
				if count, repeated := e.claimRepeatedFailure("process_sensor"); repeated {
					e.markDegradedCause("process_sensor", "process sensor unavailable: "+err.Error())
				} else {
					log.Printf("process sensor scan failed (%d/%d, not degrading yet): %v", count, forensicFailureThreshold, err)
				}
				continue
			}
			e.noteVerificationSuccess("process_sensor")
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
			// POINT 1 / P1-T5: drain the kernel exec-gate decisions on their own
			// bounded cadence. The records are kernel enforcement telemetry, not an
			// XDR detection feature, so the drain deliberately runs before the XDR
			// enablement gate: an operator pausing detection must not make the
			// kernel ring overflow and lose enforcement evidence.
			if e.core != nil && !now.Before(titanExecDrainRetryAfter) {
				payload, drainErr := e.core.TitanExecEvents()
				titanExecDrainRetryAfter = now.Add(e.consumeTitanExecDrain(payload, drainErr, now))
			}
			if e.core != nil && !now.Before(titanExecHealthRetryAfter) && e.titanExecCapabilityKnown() {
				health, healthErr := e.core.TitanExecHealth()
				e.consumeTitanExecHealth(health, healthErr, now)
				titanExecHealthRetryAfter = now.Add(titanExecHealthInterval)
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
						process, readErr := readExecProcess(event, runtime.XDRFabric.MaxCommandBytes)
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
					if runtime.XDRFabric.MalwareCorrelation {
						for _, event := range batch.Events {
							e.recordMalwareEvent(event)
						}
					}
				}
			}
			// POINT 3 / P3-T5: drain the kernel's aggregated flow telemetry on its own
			// bounded cadence. A failure here degrades only this sensor's own cause and
			// never delays the ingress/egress channels above.
			if runtime.XDREnabled && e.core != nil && !now.Before(styxFlowRetryAfter) {
				if !e.styxFlowPollEnabled() {
					// The operator namespace is disabled: nothing to drain, no claim.
					styxFlowRetryAfter = now.Add(10 * time.Second)
				} else {
					events, dropped, flowErr := e.core.StyxFlowEvents()
					switch {
					case errors.Is(flowErr, ErrStyxUnavailable):
						// A pre-StyX core is a capability fact, never an XDR degradation.
						e.setStyxBeaconCapability(false)
						styxFlowRetryAfter = now.Add(10 * time.Second)
					case flowErr != nil:
						e.recordStyxFlowHealthFailure(flowErr)
						e.noteVerificationFailure("styx_flow_sensor", "kernel styx flow telemetry unavailable: "+flowErr.Error())
						styxFlowRetryAfter = now.Add(10 * time.Second)
					default:
						e.noteVerificationSuccess("styx_flow_sensor")
						e.setStyxBeaconCapability(true)
						e.recordStyxFlowBatch(events, dropped, now)
						styxFlowRetryAfter = now.Add(time.Second)
					}
				}
			}
			if runtime.XDREnabled && e.core != nil && !now.Before(styxHealthRetryAfter) && e.styxFlowCapabilityKnown() {
				health, healthErr := e.core.StyxFlowHealth()
				if healthErr != nil {
					if errors.Is(healthErr, ErrStyxUnavailable) {
						e.setStyxBeaconCapability(false)
					} else {
						e.recordStyxFlowHealthFailure(healthErr)
						e.noteVerificationFailure("styx_flow_sensor", "kernel styx flow health unavailable: "+healthErr.Error())
					}
					styxHealthRetryAfter = now.Add(5 * time.Second)
				} else {
					e.recordStyxFlowHealth(health, now)
					styxHealthRetryAfter = now.Add(time.Second)
				}
			}
			// M2.2: kernel ransomware sensor. Status first (capability + arm
			// state), then the freeze-record drain on the 100 ms execTick so a
			// fast encryptor cannot finish the burst during a longer idle gap.
			// Every record is either escalated with evidence or the freeze is
			// released again - the Go side never leaves a group frozen silently.
			if runtime.XDREnabled && e.ransomCore != nil && !now.Before(ransomStatusRetryAfter) {
				status, statusErr := e.ransomCore.RansomStatus()
				e.consumeRansomStatus(status, statusErr, now)
				if statusErr == nil && !status.Armed && !e.ransomArmedRequested {
					e.ransomArmedRequested = true
					if err := e.ransomCore.RansomSet(true); err != nil {
						e.ransomArmedRequested = false
						e.ransomMu.Lock()
						e.ransomStatusErr = boundedStyxText(err)
						e.ransomMu.Unlock()
					}
				}
				ransomStatusRetryAfter = now.Add(10 * time.Second)
				e.state.SetXDRRansomSensor(e.RansomSensorReport())
			}
			if runtime.XDREnabled && e.ransomCore != nil && e.ransomCapabilityKnown && !now.Before(ransomDrainRetryAfter) {
				events, dropped, ransomErr := e.ransomCore.RansomEvents()
				ransomDrainRetryAfter = now.Add(e.consumeRansomEvents(events, dropped, ransomErr, now, e.ransomEscalationAllowed()))
			}
			// M2.4: kernel credential guard. Status first (capability + arm), then
			// the DENY/AUDIT drain. Active is only claimed when the core reports the
			// hook attached and at least one protected object watched.
			if runtime.XDREnabled && e.credCore != nil && !now.Before(credGuardStatusRetryAfter) {
				status, statusErr := e.credCore.CredGuardStatus()
				e.consumeCredGuardStatus(status, statusErr, now)
				if statusErr == nil && !status.Armed && !e.credArmedRequested {
					e.credArmedRequested = true
					if err := e.credCore.CredGuardSet(true); err != nil {
						e.credArmedRequested = false
						e.credMu.Lock()
						e.credStatusErr = boundedStyxText(err)
						e.credMu.Unlock()
					}
				}
				credGuardStatusRetryAfter = now.Add(10 * time.Second)
				e.state.SetXDRCredentialGuard(e.CredentialGuardReport())
			}
			if runtime.XDREnabled && e.credCore != nil && e.credCapabilityKnown && !now.Before(credGuardDrainRetryAfter) {
				events, dropped, credErr := e.credCore.CredGuardEvents()
				credGuardDrainRetryAfter = now.Add(e.consumeCredGuardEvents(events, dropped, credErr, now))
			}
			// V6.3.0 AP-0/AP-1/AP-2: sensor self-protection, executable-inode trust
			// and the attach-time eBPF guard. Each family owns its retry state.
			selfGuardRetryAfter = e.pollSelfGuard(runtime, now, selfGuardRetryAfter)
			execInodeRetryAfter = e.pollExecInode(runtime, now, execInodeRetryAfter)
			bpfGuardRetryAfter = e.pollBpfGuard(runtime, now, bpfGuardRetryAfter)
			// V6.3.0 AP-3/AP-4/AP-5: cross-view, io_uring/LKM and persistence/
			// peripheral families. Each owns its cadence and failure isolation.
			crossViewRetryAfter = e.pollCrossView(runtime, now, crossViewRetryAfter)
			kernelHooksRetryAfter = e.pollKernelHooks(runtime, now, kernelHooksRetryAfter)
			persistenceRetryAfter = e.pollPersistence(runtime, now, persistenceRetryAfter)
			// V6.3.0 AP-6/AP-7: phase-2 PCR/IdleHint analytics, DNS tunnelling
			// and PermitV1 maintenance. All are bounded and failure-isolated.
			styxPhase2RetryAfter = e.pollStyxPhase2(runtime, now, styxPhase2RetryAfter)
			dnsTunnelRetryAfter = e.pollDnsTunnel(runtime, now, dnsTunnelRetryAfter)
			permitRetryAfter = e.pollPermits(runtime, now, permitRetryAfter)
			// V6.3.0 AP-9 (S12): drain the high-priority security ring; its
			// cadence is independent of the bulk telemetry drains above.
			secCritRetryAfter = e.pollSecCrit(runtime, now, secCritRetryAfter)
			// V6.3.0 AP-6: drain bounded SBC corroboration events evidence-first.
			if e.sbc != nil && !now.Before(sbcCorroborationRetryAfter) {
				if _, err := e.recordSBCCorroborations(now); err != nil {
					e.state.AddEvent(Event{Severity: "warning", Kind: "xdr.sbc_corroboration_failed",
						Source: "xdr", Message: boundedStyxText(err)})
				}
				sbcCorroborationRetryAfter = now.Add(5 * time.Second)
			}
			if runtime.XDREnabled && e.probeCore != nil && !now.Before(execArgvRetryAfter) {
				var nextDelay time.Duration
				for batch := 0; batch < 12; batch++ {
					argvEvents, argvErr := e.probeCore.ExecArgvEvents()
					nextDelay = e.consumeExecArgvEvents(argvEvents, argvErr, runtime.XDRFabric.MaxCommandBytes)
					if argvErr != nil || len(argvEvents) < maxExecArgvEventsPerResponse {
						break
					}
				}
				execArgvRetryAfter = now.Add(nextDelay)
			}
			if runtime.XDREnabled && e.probeCore != nil && !now.Before(kernelProbeRetryAfter) {
				var nextDelay time.Duration
				for batch := 0; batch < 6; batch++ {
					probeEvents, probeErr := e.probeCore.KernelProbeEvents()
					nextDelay = e.consumeKernelProbeEvents(probeEvents, probeErr, now)
					if probeErr != nil || len(probeEvents) < maxKernelProbeEventsPerReply {
						break
					}
				}
				kernelProbeRetryAfter = now.Add(nextDelay)
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
				if queued >= runtime.XDRFabric.MaxEvaluationsPerScan {
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
			if e.chronos != nil && e.chronos.Enabled() && runtime.XDREnabled && e.chronosRunning.CompareAndSwap(false, true) {
				go func() {
					defer e.chronosRunning.Store(false)
					cp, err := e.chronos.Scan(ctx, true)
					if err != nil && !errors.Is(err, context.Canceled) {
						severity := "warning"
						if cp != nil && cp.Phase == "BOUNDED" {
							// A bounded walk is a policy outcome, not a fault: the digest
							// set is partial and says so instead of reporting success.
							severity = "info"
						}
						e.state.AddEvent(Event{
							Severity: severity, Kind: "chronos.scan_failed", Source: "fim",
							Message: fmt.Sprintf("Chronos FIM scan did not complete: %v", err),
						})
					} else if cp != nil && cp.Phase == "COMPLETED" {
						e.state.AddEvent(Event{
							Severity: "info", Kind: "chronos.merkle_verified", Source: "fim",
							Message: fmt.Sprintf("Chronos Merkle tree integrity verified: root=%s files=%d bytes=%d", cp.MerkleRoot, cp.FilesScanned, cp.BytesScanned),
						})
					}
				}()
			}
		case <-logVerifyTick.C:
			e.verifyForensicArtefacts(ctx)
		case <-behaviorSaveTick.C:
			if e.behavior != nil {
				if err := e.behavior.Persist(); err != nil {
					e.markDegradedCause("behavior", "behavior profile persistence failed: "+err.Error())
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
	runtime := e.runtimeSettings()
	budget := runtime.XDRFabric.MaxEvaluationsPerScan
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
		if p.PID == e.selfPID || allowedProcessRuntime(p.Exe, runtime.XDRFabric.AllowProcesses) {
			continue
		}
		if len(jobs) < budget {
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
	if len(jobs) >= budget {
		e.noteDrop("process scan evaluation budget exhausted")
	}
}

func allowedProcessRuntime(exe string, allowedProcesses []string) bool {
	exe = filepath.Clean(strings.TrimSuffix(exe, " (deleted)"))
	for _, allowed := range allowedProcesses {
		if filepath.Clean(allowed) == exe {
			return true
		}
	}
	return false
}

func (e *XDREngine) allowedProcess(exe string) bool {
	return allowedProcessRuntime(exe, e.runtimeSettings().XDRFabric.AllowProcesses)
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
		// Invalid rules mean no detection, so this degrades at once - but the next successful
		// configuration must clear it again, or a corrected setting would need a restart.
		e.markDegradedCause("rule_config", "runtime rule configuration invalid: "+err.Error())
		return
	}
	e.clearDegradedCause("rule_config")
	if !runtime.XDREnabled {
		return
	}
	e.evaluated.Add(1)

	// Morpheus RASP: Active Memory-Scraping / Ptrace Inspection in Data Path.
	//
	// A detection is signalled whether or not containment is armed. An alert-only RASP used to
	// return the event without an error, and this caller only dispatched on the error, so an
	// operator who chose alert-only got no XDR alarm at all. The RASP emits its own incident
	// through the sink in both cases; the event decides whether an active response follows.
	if e.morpheus != nil {
		if raspEvt, _ := e.morpheus.InspectProcess(p); raspEvt != nil {
			now := time.Now().UTC()
			containment := e.morpheus.ContainmentEnabled()
			kind := "morpheus.memory_scraping_detected"
			message := fmt.Sprintf("Morpheus RASP detected memory scraping by PID %d (%s)", p.PID, p.Comm)
			if containment {
				kind = "morpheus.memory_scraping_blocked"
				message = fmt.Sprintf("Morpheus RASP blocked memory scraping by PID %d (%s)", p.PID, p.Comm)
			}
			e.state.AddEvent(Event{
				Severity: "critical", Kind: kind, Source: "rasp",
				Message: message, Target: fmt.Sprintf("pid:%d", p.PID),
			})
			if containment && e.responses != nil {
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
	if e.l7Recent != nil {
		extra = append(extra, e.l7Recent.Match(conns, time.Now().UTC())...)
	}
	var index *ThreatIndex
	if runtime.FeedsEnabled && e.feeds != nil {
		index = e.feeds.CorrelateIndex()
	}
	decision := e.rules.EvaluateProcess(p, conns, index, e.baseline, extra...)
	// A digest mismatch on one of our own components is a trust-boundary event, not a process
	// that should be frozen or killed. The right answer is the fail-closed degradation that
	// XDR.SELF_TAMPER records - and a verified signed update window is the only thing that may
	// turn the same bytes into a deployment. This interception is why the baseline no longer
	// downgrades own artifacts to AlertOnly: nothing here may ever dispatch an "action: none"
	// incident for them.
	if containsString(decision.RuleIDs, "BASELINE.HASH_MISMATCH") && isProductArtifact(p.Exe) {
		expected, actual, mismatch := e.baseline.ProductArtifactMismatch(p.Exe)
		if mismatch {
			identity := resolvedIdentity(p.Exe)
			observed := actual
			if observed == "" {
				observed = "unreadable"
			}
			if e.updateWindowCovers(identity, actual, false) {
				if updated, ok := newProtectedObject(resolvedIdentity(p.Exe), actual); ok {
					e.applyAuthorizedUpdate(p.Exe, identity, actual, observed, false, updated)
				}
			} else {
				e.selfTamper(p.Exe, observed, fmt.Sprintf(
					"GeDefense component digest differs from the approved baseline (approved=%s observed=%s); an update requires a verified signed package-update window",
					expected, observed))
			}
			return
		}
	}
	if decision.Score < runtime.AlertScore || len(decision.RuleIDs) == 0 {
		return
	}
	// V6.3.0 AP-7: consult the PermitV1 broker before any active response is
	// planned. A matching permit can only suppress or downgrade — it never
	// authorizes a response, never raises the decision and never bypasses the
	// kill gate, which has already been applied by combineMatches above.
	permitDecision := e.evaluatePermitBroker(p, decision)
	if permitDecision != nil && permitDecision.TrustLevel == permitTrustAuthorized {
		e.recordAuthorizedPermitOutcome(p, decision, permitDecision)
		return
	}
	decision.Decision = "alert"
	if decision.ResponseScore >= runtime.KillScore && decision.KillSignals >= 2 {
		decision.Decision = "kill"
	} else if decision.ResponseScore >= runtime.ContainScore {
		decision.Decision = "contain"
	}
	if permitDecision != nil {
		// V6.3.0 AP-7: a TOLERATED / ANALYST_MODE permit keeps the evidence and
		// the scores but suppresses the active response. The helper is
		// suppression-only and can never elevate the decision.
		decision = applyPermitDecision(decision, permitDecision)
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
		Parent: p.ParentExe, Remote: decision.Remote, CommandPreview: e.rules.RedactCommand(p.Cmdline, runtime.XDRFabric.CommandPreviewBytes),
		CommandSHA256: p.CmdSHA256, RuleIDs: decision.RuleIDs, Categories: decision.Categories, Summary: decision.Summary,
		Decision: decision.Decision, Action: "none", Outcome: "observed",
		ExecutionChainID: execChainID, AttackStory: storyNodes, EvidenceRoot: recordHash,
	}
	if permitDecision != nil {
		// V6.3.0 AP-7: attach the bounded permit metadata to the downgraded
		// finding (absent for findings no permit explained).
		incident.Permit = permitDecision
	}
	incident.Action, incident.Outcome = e.respond(incident)
	e.appendIncident(incident)
	e.state.AddEvent(Event{Severity: severity, Kind: "xdr." + incident.Decision, Source: source, Message: incident.Summary + " [" + strings.Join(incident.RuleIDs, ",") + "]", Target: fmt.Sprintf("pid:%d", p.PID)})
}

// restoreIncidentHistory seeds the in-memory incident list from the log on disk.
//
// The engine's list is what every forensic surface reads, and it is in memory - so it
// began empty on every start while the log held every incident the host had ever seen. A
// host whose control plane had been restarted reported zero incidents in the operator's
// view next to a log file containing 220 of them. The record was never lost; there was
// simply nothing that read it back.
//
// The most recent incidents are restored, bounded by the same cap the live list uses, so
// the memory cost does not grow with the age of the installation.
func (e *XDREngine) restoreIncidentHistory() error {
	if e == nil || e.logger == nil || e.state == nil {
		return nil
	}
	limit := e.state.incidentCap
	if limit <= 0 {
		return nil
	}
	incidents, err := e.logger.ReadRecent(limit)
	if err != nil {
		return err
	}
	if len(incidents) == 0 {
		return nil
	}
	e.state.RestoreIncidents(incidents)
	return nil
}

func (e *XDREngine) appendIncident(incident XDRIncident) {
	// The incident log is the forensic record of what the sensors emitted. It must carry
	// the same normalised severity as the state and the case store, otherwise the same
	// incident reads differently in the log, in the dashboard and in the case list.
	incident.Severity = strings.ToLower(strings.TrimSpace(incident.Severity))
	// V6.3.0 AP-6/AP-7: attach the GIEF v1.0 envelope and the mandatory
	// explainability block before the forensic log record is sealed. Both are
	// metadata only: score, decision and action are never changed here.
	incident = e.attachGIEFEnvelope(incident)
	incident = e.attachFindingExplainability(incident)
	// V6.3.0 AP-9 (S08/S15): self-tamper/evidence findings go to the out-of-band
	// witness before the local forensic record is written, so a later local
	// truncation cannot erase the only copy.
	e.pushCriticalWitness(incident)
	// V6.3.0 AP-7: offer the sealed finding to the persistent review queue.
	// Storage failures degrade the queue; they never fail the XDR path.
	e.enqueueReviewFinding(incident)
	if e.logger != nil {
		if hash, err := e.logger.Append(incident); err == nil {
			incident.RecordHash = hash
		} else {
			log.Printf("xdr incident log: %v", err)
			e.markDegradedCause("incident_log", "incident log unavailable: "+err.Error())
		}
	}
	e.state.AddIncident(incident)
	// POINT 5 / P5-T3: the Emergency Lockdown observes the incident stream. The
	// hook is optional and inert unless the operator enabled the namespace; it never
	// changes the incident record and never fails the XDR path.
	if e.lockdown != nil {
		e.lockdown.ObserveIncident(incident)
	}
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
		// F-HOTFIX-3: every process freeze must be owned by the reversible
		// response engine so it carries a TTL and a rollback record. The
		// privileged core can SIGSTOP a process, but only the response engine
		// schedules the matching SIGCONT and keeps it across a restart. An
		// untracked fallback would leave the process frozen forever.
		if e.responses == nil || i.PID <= 0 {
			return actionName(quarantined, "none"), "failed: reversible response engine unavailable; untracked freeze refused"
		}
		respRec, err := e.responses.ApplyResponse(
			context.Background(),
			time.Now().UTC(),
			i.ID,
			ActionFreezeExecution,
			"PID",
			strconv.Itoa(i.PID),
			i.Score,
			rule,
			i.EvidenceRoot,
		)
		if err != nil {
			return actionName(quarantined, "none"), "failed: " + err.Error()
		}
		return actionName(quarantined, "stop"), fmt.Sprintf("process frozen through reversible response engine (TTL=%s)", respRec.ExpiresAt.Sub(respRec.StartedAt))
	}
	if i.Decision == "kill" && xdrMode == "enforce" {
		// M2.3: an evidence-backed ransom kill must terminate the whole process
		// tree (child workers otherwise keep encrypting). Every other kill keeps the
		// historical single-pidfd path.
		if strings.HasPrefix(rule, "XDR.RANSOM_") && e.core != nil {
			killed, killErr := e.core.KillTree(i.PID, i.StartTicks, rule)
			if killErr != nil {
				if stopErr := e.core.Stop(i.PID, i.StartTicks, rule); stopErr != nil {
					return actionName(quarantined, "kill-tree"), "tree kill rejected and containment failed: " + killErr.Error() + "; " + stopErr.Error()
				}
				return actionName(quarantined, "stop"), "tree kill rejected; process frozen for operator review: " + killErr.Error()
			}
			return actionName(quarantined, "kill-tree"), fmt.Sprintf("process tree terminated through authenticated tree-kill broker (%d process(es))", killed)
		}
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
	enforcement, _ := e.state.Modes()
	if enforcement == "enforce" {
		if err := e.core.Add(target); err != nil {
			return fmt.Errorf("kernel quarantine failed: %w", err)
		}
		enforced = true
	}
	maxBlocks := e.cfg.Defense.MaxBlockEntries
	if runtime := e.runtimeSettings(); runtime.Network.MaxBlockEntries > 0 {
		maxBlocks = runtime.Network.MaxBlockEntries
	}
	containTTL := 15 * time.Minute
	if runtime := e.runtimeSettings(); runtime.XDRFabric.ContainmentTTLSeconds > 0 {
		containTTL = time.Duration(runtime.XDRFabric.ContainmentTTLSeconds) * time.Second
	}
	block, err := e.state.AddBlock(target, "XDR containment: "+strings.Join(incident.RuleIDs, ","), "xdr", containTTL, enforced, maxBlocks)
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
		// Persist through the central funnel, never directly: it refuses to re-sign a policy
		// document the platform could not verify (errPolicyUnverified) and publishes the refusal
		// event. Writing e.policy.Persist here bypassed exactly that guard (FIND-013 funnel gap).
		if err := persistPolicy(e.policy, e.cfg, e.state); err != nil {
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
			return fmt.Errorf("signed policy persistence failed: %w", err)
		}
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
	e.dedupe[key] = now.Add(time.Duration(e.runtimeSettings().XDRFabric.DedupeSeconds) * time.Second)
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
	// The protected set is read under the lock because an authorized update window moves the
	// recorded state of an object while the XDR workers run.
	e.mu.RLock()
	objects := make(map[string]protectedObject, len(e.protected))
	for key, object := range e.protected {
		objects[key] = object
	}
	e.mu.RUnlock()
	paths := make([]string, 0, len(objects))
	for p := range objects {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		old := objects[p]
		identity := resolvedIdentity(p)
		st, err := os.Stat(p)
		if err != nil {
			if e.updateWindowCovers(identity, "", true) {
				e.applyAuthorizedUpdate(p, identity, "", "missing", true, protectedObject{})
				continue
			}
			e.selfTamper(p, "missing", "protected object disappeared")
			continue
		}
		digest, err := hashFile(p)
		observed := digest
		if err != nil {
			observed = "unreadable"
		}
		// Content, permissions and size are what the baseline recorded, so all three are
		// part of the state that is compared and announced.
		observed = fmt.Sprintf("%s:%04o:%d", observed, st.Mode().Perm(), st.Size())
		if err == nil && digest == old.digest && st.Mode().Perm() == old.mode && st.Size() == old.size {
			continue
		}
		// A signed, currently open update window is the only exception: the change has to
		// match the digest the verified release manifest names for exactly this artifact.
		if e.updateWindowCovers(identity, digest, false) {
			e.applyAuthorizedUpdate(p, identity, digest, observed, false,
				protectedObject{path: p, digest: digest, mode: st.Mode().Perm(), size: st.Size()})
			continue
		}
		e.selfTamper(p, observed, "protected object changed after XDR initialization")
	}
}

// resolvedIdentity names the object behind a protected path rather than the route to it.
//
// The protected set reaches the access gateway twice: once through
// /opt/vgt/gedefense/current/bin/gedefense-access, the stable name an operator knows, and
// once through /opt/vgt/gedefense/releases/<version>/bin/gedefense-access, which is what the
// running process resolves to. Both are the same file, so replacing it once was reported
// twice - two critical incidents for one change. Reporting the object collapses the pair,
// and it keeps working when /current is retargeted, because the resolved target is what the
// baseline actually hashed.
func resolvedIdentity(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// claimTamper reports whether this observed state of this object still needs announcing.
//
// A tamper is a state, not an event that repeats: the object keeps not matching until
// somebody changes it back or the service restarts against a fresh baseline. This used to
// be announced through the time-based dedupe window, so an unremediated change produced a
// fresh critical incident every dedupe interval - five minutes by default - and one fact
// buried the rest of the ledger. Keying on the object and its observed state reports each
// distinct change exactly once, and a further modification is still a new fact.
func (e *XDREngine) claimTamper(identity, observed string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tamperSeen == nil {
		e.tamperSeen = map[string]string{}
	}
	if announced, ok := e.tamperSeen[identity]; ok && announced == observed {
		return false
	}
	e.tamperSeen[identity] = observed
	return true
}

// selfTamper records that a protected object no longer matches the state this process
// started with. The object and the state it was found in decide whether this is news:
// see claimTamper.
//
// A change to one of GeDefense's own components is not exempt. The protected set contains
// this installation's own executables, and every legitimate update replaces them while the
// service runs - but that update has to be attributable, so the only sanctioned path is a
// verified signed release manifest that opened a bounded update window (see
// BeginSignedUpdateWindow). The window is checked by the observation path before this call;
// reaching this point with an own component therefore means the replacement is unauthorized,
// and it gets the same fail-closed treatment as a third-party object: a critical
// XDR.SELF_TAMPER incident, a release-blocking degradation, and no active response on top of
// a platform that has just declared its own trust boundary broken.
func (e *XDREngine) selfTamper(path, observed, reason string) {
	identity := resolvedIdentity(path)
	if !e.claimTamper(identity, observed) {
		return
	}
	// One cause per object, so the reported reason names everything that changed rather
	// than only the last thing that did.
	e.markDegradedCause("runtime:"+identity, reason+": "+path)
	i := XDRIncident{ID: randomID(), Time: time.Now().UTC(), Severity: "critical", Score: 250, Executable: path,
		RuleIDs: []string{"XDR.SELF_TAMPER"}, Categories: []string{"integrity"}, Summary: reason, Decision: "degrade", Action: "disable-response", Outcome: "active XDR response disabled until restart and verification"}
	e.appendIncident(i)
	e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.self_tamper", Source: "integrity", Message: reason, Target: path})
}

func (e *XDREngine) markDegraded(reason string) {
	e.markDegradedCause("runtime", reason)
}

// forensicFailureThreshold is how many consecutive failed checks a forensic artefact may produce
// before it degrades the platform.
//
// One failed check used to degrade XDR immediately, and XDR degraded means the automatic response
// pauses and stays paused until the calm holds again - so a single hiccup, a momentarily busy
// writer or a verification that read while a record was being appended became a visible
// fail-safe in the interface. A condition is what persists; a hiccup is what does not.
const forensicFailureThreshold = 2

// noteVerificationFailure applies that policy: the first failure is named in the journal, a
// repeated one degrades XDR. The journal line matters as much as the threshold - a degradation
// that cannot be seen in the journal cannot be diagnosed, which is what made this one take an
// afternoon of guessing.
func (e *XDREngine) noteVerificationFailure(cause, reason string) {
	count, repeated := e.claimRepeatedFailure(cause)
	if repeated {
		if count == forensicFailureThreshold {
			log.Printf("xdr degraded after %d consecutive failures: %s", count, reason)
		}
		e.markDegradedCause(cause, reason)
		return
	}
	log.Printf("xdr verification failed (%d/%d, not degrading yet): %s", count, forensicFailureThreshold, reason)
}

// noteVerificationSuccess clears the failure counter and the cause it may have set.
func (e *XDREngine) noteVerificationSuccess(cause string) {
	e.clearRepeatedFailure(cause)
	e.clearDegradedCause(cause)
}

func (e *XDREngine) claimRepeatedFailure(cause string) (int, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.forensicFailures == nil {
		e.forensicFailures = make(map[string]int)
	}
	e.forensicFailures[cause]++
	count := e.forensicFailures[cause]
	return count, count >= forensicFailureThreshold
}

func (e *XDREngine) clearRepeatedFailure(cause string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.forensicFailures, cause)
}

// verifyForensicArtefacts keeps the forensic artefacts and the degradation causes they set in
// step with each other.
//
// Verification used to run in one direction only: a failure recorded a cause, a success cleared
// nothing. Only a rotation or an operator recovery could clear one, so a single transient failure
// left XDR degraded - and a degraded XDR blocks every promotion and pauses the automatic response
// - until somebody restarted the control plane. That is what happened twice on the production
// host: the state was cleared by a restart rather than by the platform noticing that the problem
// had gone. A verification that succeeds is exactly that observation, so it clears the cause it
// would otherwise have set.
func (e *XDREngine) verifyForensicArtefacts(ctx context.Context) {
	if e.logger != nil {
		// Seal the chain before the budget is reached. A full incident ledger stops recording,
		// degrades XDR, and that degradation blocks every promotion and pauses the automatic
		// response until an operator archives the segment by hand - which is exactly what
		// happened twice on the production host, and what the retention design has to prevent
		// instead of reporting.
		if size, budget := e.logger.StoredBytes(); budget > 0 && size > 0 && size*100 >= budget*evidenceRotationThresholdPercent {
			result, rotateErr := e.logger.Rotate(ctx, "incident-log retention budget reached; sealing the segment before recording stops")
			switch {
			case rotateErr != nil:
				e.markDegradedCause("incident_log", "incident log rotation failed: "+rotateErr.Error())
			case e.state == nil:
				e.clearDegradedCause("incident_log")
			default:
				e.state.AddEvent(Event{Severity: "high", Kind: "xdr.incident_log_rotated", Source: "xdr",
					Message: fmt.Sprintf("Incident ledger sealed into %s and started a fresh chain", result.ArchiveID)})
				if err := e.state.RecordEvidence(EvidenceRecord{
					Severity: "high", Kind: "xdr.incident_log_rotated", Source: "xdr",
					Message: "Incident ledger sealed at its retention budget; a fresh chain continues",
					Target:  "archive:" + result.ArchiveID + " manifest_sha256:" + result.ManifestSHA256,
				}); err != nil {
					e.markDegradedCause("evidence", "mandatory evidence ledger unavailable during rotation")
				} else {
					e.clearDegradedCause("incident_log")
				}
			}
		} else if err := e.logger.Verify(); err != nil {
			e.noteVerificationFailure("incident_log", "incident log verification failed: "+err.Error())
		} else {
			e.noteVerificationSuccess("incident_log")
		}
	}
	if e.state == nil {
		return
	}
	// The evidence ledger has the same property: a healthy ledger means the cause recorded while
	// it was unavailable no longer holds.
	if ledger := e.state.EvidenceLedger(); ledger != nil {
		if err := ledger.Healthy(); err != nil {
			e.noteVerificationFailure("evidence", "mandatory evidence ledger unavailable: "+err.Error())
		} else {
			e.noteVerificationSuccess("evidence")
		}
	}
}

func (e *XDREngine) markDegradedCause(cause, reason string) {
	e.mu.Lock()
	if e.degradeCauses == nil {
		e.degradeCauses = make(map[string]string)
	}
	previous, existed := e.degradeCauses[cause]
	e.degradeCauses[cause] = reason
	e.recomputeDegradedLocked()
	degraded, degradedReason := e.degraded, e.degradeWhy
	e.mu.Unlock()
	e.state.SetXDRDegraded(degraded, degradedReason)
	// Logged once per distinct reason, not once per check: a persistent cause must be visible in
	// the journal without flooding it every thirty seconds.
	if !existed || previous != reason {
		log.Printf("xdr degraded: cause=%s reason=%s", cause, reason)
	}
}

func (e *XDREngine) clearDegradedCause(cause string) {
	e.mu.Lock()
	previous, existed := e.degradeCauses[cause]
	delete(e.degradeCauses, cause)
	e.recomputeDegradedLocked()
	degraded, reason := e.degraded, e.degradeWhy
	e.mu.Unlock()
	e.state.SetXDRDegraded(degraded, reason)
	if existed {
		log.Printf("xdr recovered: cause=%s was=%s", cause, previous)
	}
}

func (e *XDREngine) recomputeDegradedLocked() {
	if len(e.degradeCauses) == 0 {
		e.degraded = false
		e.degradeWhy = ""
		return
	}
	keys := make([]string, 0, len(e.degradeCauses))
	for key := range e.degradeCauses {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	reasons := make([]string, 0, len(keys))
	for _, key := range keys {
		reasons = append(reasons, e.degradeCauses[key])
	}
	e.degraded = true
	e.degradeWhy = strings.Join(reasons, "; ")
}

func (e *XDREngine) degradedState() (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.degraded, e.degradeWhy
}

func (e *XDREngine) incidentRecoveryAllowed() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.degradeCauses) != 1 {
		return false
	}
	_, ok := e.degradeCauses["incident_log"]
	return ok
}

// ApplyRuntimeSettings applies the hot-reloadable XDR settings. Queue capacity,
// worker count and integrity watch roots are persisted but require a controlled
// service restart because the underlying channels/watchers are created at boot.
// The Host Security namespace is projected onto the RASP, deception and Airlock
// engines from the same revision, so one apply never leaves them inconsistent.
func (e *XDREngine) ApplyRuntimeSettings(settings RuntimeSettings) error {
	if e == nil {
		return nil
	}
	if err := e.rules.Configure(settings); err != nil {
		return err
	}
	if e.behavior != nil {
		e.behavior.Configure(settings.XDRFabric)
	}
	hardening := effectiveHardeningSettings(settings)
	if err := applyHardeningPolicy(hardening, e.morpheus, e.airlock, e.deception); err != nil {
		return err
	}
	// POINT 3 / P3-T5: project the StyX namespace onto the detector immediately and
	// hand the desired kernel policy to the syncer. The syncer is asynchronous on
	// purpose: an old core or a temporary IPC failure must never roll back an
	// operator's settings revision. It reports applied/pending/failed/capability-
	// missing in its own status instead of pretending consent.
	e.applyStyxBeaconSettings(settings)
	if e.styxPolicy != nil {
		e.styxPolicy.Configure(settings)
	}
	// POINT 1 / P1-T5: hand the desired exec-gate revision to its syncer. It is
	// asynchronous on purpose: a pre-TitanExec core or a transient IPC failure must
	// never roll back the operator's settings, and the syncer reports
	// applied/pending/inactive/capability-missing in its own status.
	if e.titanExec != nil {
		e.titanExec.Configure(settings)
	}
	// POINT 2 / P2-T3: project the parser-cell namespace onto the manager. It never
	// contacts the helper here; the supervisor applies the revision asynchronously.
	if e.parserCells != nil {
		e.parserCells.Configure(settings)
	}
	return nil
}

// ------------------------------------------------- Titan exec-gate projection
//
// POINT 1 / P1-T5: read-only accessors for the kernel exec gate. None of them
// derives an enforcement claim: the sync status reports what the core applied,
// the sensor state reports whether decisions are actually being drained, and the
// kernel facts (path/lsm/offsets) are carried through verbatim.

// TitanExecPolicyStatus returns the structured sync status of the exec-gate
// policy syncer. It is the method fabric_settings.go's titanExecStatusSource
// detects, so the settings module recognizes the wired runtime automatically.
// Without a wired syncer the honest unavailable state is returned.
func (e *XDREngine) TitanExecPolicyStatus() TitanExecSyncStatus {
	if e == nil || e.titanExec == nil {
		return titanExecUnavailableStatus()
	}
	return e.titanExec.Snapshot()
}

// titanExecCapabilityKnown reports whether the core proved the TITAN_EXEC_* ABI.
func (e *XDREngine) titanExecCapabilityKnown() bool {
	if e == nil {
		return false
	}
	e.titanExecMu.Lock()
	defer e.titanExecMu.Unlock()
	return e.titanExecCapability == titanExecCapabilityAvailable
}

// setTitanExecCapability records the negotiated ABI fact. Only transitions are
// operator-visible, and a missing capability is a fact, never an XDR degradation
// (§7.3): an old core must not be reported as a detection outage.
func (e *XDREngine) setTitanExecCapability(available bool) {
	if e == nil {
		return
	}
	next := titanExecCapabilityMissing
	if available {
		next = titanExecCapabilityAvailable
	}
	e.titanExecMu.Lock()
	previous := e.titanExecCapability
	e.titanExecCapability = next
	e.titanExecMu.Unlock()
	if previous == next || e.state == nil {
		return
	}
	switch {
	case available && previous == titanExecCapabilityMissing:
		e.state.AddEvent(Event{Severity: "info", Kind: "titan_exec.capability_available", Source: "titan-exec",
			Message: "The privileged core advertises the TITAN_EXEC_* command family again; kernel exec-gate decisions are drained"})
	case !available && previous == titanExecCapabilityAvailable:
		e.state.AddEvent(Event{Severity: "info", Kind: "titan_exec.capability_missing", Source: "titan-exec",
			Message: "The privileged core no longer advertises the TITAN_EXEC_* command family; no kernel exec-gate decisions are available. This is a capability fact, not an XDR degradation"})
	}
}

// titanExecHealthSnapshot returns the last kernel health sample and the recorded
// per-channel errors (health command, event drain) for the status view.
func (e *XDREngine) titanExecHealthSnapshot() (CoreTitanExecHealth, *time.Time, string, string) {
	if e == nil {
		return CoreTitanExecHealth{}, nil, "", ""
	}
	e.titanExecMu.Lock()
	defer e.titanExecMu.Unlock()
	var at *time.Time
	if !e.titanExecHealthAt.IsZero() {
		sampled := e.titanExecHealthAt
		at = &sampled
	}
	return e.titanExecHealth, at, e.titanExecHealthErr, e.titanExecDrainErr
}

// titanExecSensorState derives the honest ingestion state. It never says
// "active" for a namespace whose kernel hook is not attached: unavailable
// capability and inactive/unattached sync states win over a configured mode.
func (e *XDREngine) titanExecSensorState() string {
	if e == nil || e.titanExec == nil {
		return "unavailable"
	}
	if !e.titanExecCapabilityKnown() {
		return "unavailable"
	}
	sync := e.TitanExecPolicyStatus()
	switch sync.State {
	case TitanExecSyncStateCapabilityMissing, TitanExecSyncStateUnavailable:
		return "unavailable"
	case TitanExecSyncStateInactive:
		return "inactive"
	case TitanExecSyncStateFailed:
		return "degraded"
	}
	if !sync.Enabled || sync.Mode == TitanExecModeOff {
		return "inactive"
	}
	if e.titanExecSensorCauseSet() {
		return "degraded"
	}
	if sync.State == TitanExecSyncStatePending {
		return "pending"
	}
	return "active"
}

// TitanExecStatusSnapshot builds the bounded field attached to /api/v1/status.
// It is nil for an engine without exec-gate wiring, so the payload of an
// installation that never enabled the gate stays byte-identical.
func (e *XDREngine) TitanExecStatusSnapshot() *TitanExecStatus {
	if e == nil || e.titanExec == nil {
		return nil
	}
	sync := e.TitanExecPolicyStatus()
	e.titanExecMu.Lock()
	stats := e.titanExecStats
	e.titanExecMu.Unlock()
	return &TitanExecStatus{
		State: sync.State, SensorState: e.titanExecSensorState(), Capability: sync.Capability,
		Enabled: sync.Enabled, Mode: sync.Mode, Path: sync.Path, LSM: sync.LSM, Offsets: sync.Offsets,
		Entries: sync.Entries, Scopes: sync.Scopes,
		EventsTotal: stats.EventsTotal, Denies: stats.Denies, Audits: stats.Audits,
		Dropped: stats.Dropped, ParseErrors: stats.ParseErrors, Incidents: stats.Incidents,
	}
}

// TitanExecStatusReport builds the GET /api/v1/titan/exec/status payload.
func (e *XDREngine) TitanExecStatusReport() TitanExecStatusView {
	view := TitanExecStatusView{
		State: TitanExecSyncStateUnavailable, SensorState: "unavailable", Capability: titanExecCapabilityUnknown,
		Sync:         titanExecUnavailableStatus(),
		Kernel:       TitanExecKernelView{Path: titanExecPathNone, LSM: titanExecLSMInactive, Offsets: titanExecOffsetsInvalid},
		HistoryLimit: titanExecEventHistoryLimit,
	}
	if e == nil {
		return view
	}
	sync := e.TitanExecPolicyStatus()
	health, healthAt, healthErr, drainErr := e.titanExecHealthSnapshot()
	e.titanExecMu.Lock()
	stats := e.titanExecStats
	e.titanExecMu.Unlock()
	view.State = sync.State
	view.Capability = sync.Capability
	view.SensorState = e.titanExecSensorState()
	view.Sync = sync
	view.Kernel = TitanExecKernelView{
		Path: sync.Path, LSM: sync.LSM, Offsets: sync.Offsets, Entries: sync.Entries, Scopes: sync.Scopes,
		Health: health, HealthAt: healthAt, HealthError: healthErr, DrainError: drainErr,
	}
	view.Counters = titanExecCountersView(stats)
	return view
}

// TitanExecEventsReport builds the bounded GET /api/v1/titan/exec/events payload:
// the newest `limit` events of the bounded history, newest first.
func (e *XDREngine) TitanExecEventsReport(limit int) TitanExecEventsView {
	if limit < 1 {
		limit = 1
	}
	if limit > titanExecEventHistoryLimit {
		limit = titanExecEventHistoryLimit
	}
	view := TitanExecEventsView{Events: []TitanExecEventView{}, Limit: limit, HistoryLimit: titanExecEventHistoryLimit}
	if e == nil {
		return view
	}
	e.titanExecMu.Lock()
	history := append([]CoreTitanExecEvent(nil), e.titanExecHistory...)
	stats := e.titanExecStats
	e.titanExecMu.Unlock()
	view.Available = len(history)
	view.Counters = titanExecCountersView(stats)
	start := len(history) - limit
	if start < 0 {
		start = 0
	}
	view.Events = make([]TitanExecEventView, 0, len(history)-start)
	for index := len(history) - 1; index >= start; index-- {
		view.Events = append(view.Events, titanExecEventViewOf(history[index]))
	}
	return view
}

func titanExecCountersView(stats titanExecEventCounters) TitanExecEventCountersView {
	return TitanExecEventCountersView{
		EventsTotal: stats.EventsTotal, Denies: stats.Denies, Audits: stats.Audits,
		Dropped: stats.Dropped, ParseErrors: stats.ParseErrors, Incidents: stats.Incidents,
	}
}

func titanExecEventViewOf(event CoreTitanExecEvent) TitanExecEventView {
	return TitanExecEventView{
		CgroupID: event.CgroupID, TsNS: event.TsNS, Dev: event.Dev, InodeMode: event.InodeMode,
		Ino: event.Ino, Generation: event.Generation, PID: event.PID, TGID: event.TGID,
		UID: event.UID, GID: event.GID, Prot: event.Prot, FFlags: event.FFlags,
		Hook: event.Hook, Action: event.Action, Reason: event.Reason, Flags: event.Flags,
		Comm: event.Comm, RuleID: titanExecRuleID(event),
	}
}

// ------------------------------------------------ Titan exec label helpers
//
// The operator-facing names of §3.1. They contain no policy decision; they only
// make a decoded record readable in evidence and in the event summary.

func titanExecHookName(hook uint8) string {
	if hook == titanExecHookMmap {
		return "mmap_file"
	}
	return "bprm_check_security"
}

func titanExecHookVerb(hook uint8) string {
	if hook == titanExecHookMmap {
		return "an executable memory mapping"
	}
	return "execution"
}

func titanExecActionName(action uint8) string {
	if action == titanExecActionDeny {
		return "denied"
	}
	return "audited"
}

func titanExecReasonName(reason uint8) string {
	switch reason {
	case titanExecReasonNone:
		return "NONE"
	case titanExecReasonUnlinked:
		return "UNLINKED"
	case titanExecReasonTmpfs:
		return "TMPFS"
	case titanExecReasonMemfd:
		return "MEMFD"
	case titanExecReasonNotAllowlist:
		return "NOT_ALLOWLISTED"
	case titanExecReasonWX:
		return "WX"
	case titanExecReasonAnonNoJit:
		return "ANON_NO_JIT"
	case titanExecReasonReadFailure:
		return "READ_FAILURE"
	case titanExecReasonStateNotRdy:
		return "STATE_NOT_READY"
	case titanExecReasonCtimeMismatch:
		return "CTIME_MISMATCH"
	case titanExecReasonFSHard:
		return "FS_HARD"
	default:
		return "UNKNOWN"
	}
}

// sanitizeTitanExecComm renders a raw kernel task name for operator surfaces.
// PR_SET_NAME lets a process choose arbitrary bytes, so the parser accepts them
// unconditionally (§3.2 comm contract); this renderer replaces every invalid or
// non-printable rune with '?' so the value can never forge a line or a field
// separator, while valid printable UTF-8 stays unchanged. It always terminates
// and never grows the value beyond its raw byte length.
func sanitizeTitanExecComm(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(raw))
	for len(raw) > 0 {
		character, size := utf8.DecodeRune(raw)
		switch {
		case character == utf8.RuneError && size == 1:
			builder.WriteByte('?')
		case strconv.IsPrint(character):
			builder.WriteRune(character)
		default:
			builder.WriteByte('?')
		}
		raw = raw[size:]
	}
	return builder.String()
}

// ------------------------------------------------ Titan exec drain / health
//
// The poll classification and the two-hit degradation policy of §7.4. Both are
// driven from the engine's 100 ms tick through consumeTitanExecDrain and
// consumeTitanExecHealth; keeping them here (next to the other sensor health
// paths) is why titan_exec_events.go stays the wire/parser + event bridge.

// consumeTitanExecDrain classifies one TITAN_EXEC_EVENTS answer and returns the
// delay until the next drain. A capability-missing answer is a fact, not an XDR
// degradation; only repeated real failures degrade, and only while the operator
// enabled the namespace.
func (e *XDREngine) consumeTitanExecDrain(payload string, drainErr error, now time.Time) time.Duration {
	if e == nil {
		return titanExecDrainBackoff
	}
	enabled := effectiveTitanExecFabricSettings(e.runtimeSettings()).Enabled
	switch {
	case errors.Is(drainErr, ErrTitanExecUnavailable):
		// The capability fact replaces a previously recorded transient error: a
		// downgraded core is not an event-drain failure any more.
		e.setTitanExecCapability(false)
		e.titanExecMu.Lock()
		e.titanExecDrainErr = ""
		e.titanExecMu.Unlock()
		return titanExecDrainBackoff
	case drainErr != nil:
		text := boundedTitanExecText(drainErr)
		e.titanExecMu.Lock()
		e.titanExecDrainErr = text
		e.titanExecMu.Unlock()
		if enabled {
			e.noteTitanExecSensorFailure("kernel titan exec event drain unavailable: " + text)
		}
		return titanExecDrainBackoff
	}
	e.setTitanExecCapability(true)
	e.titanExecMu.Lock()
	e.titanExecDrainErr = ""
	e.titanExecMu.Unlock()
	events, dropped, parseErr := parseCoreTitanExecEvents(payload)
	if parseErr != nil {
		text := boundedTitanExecText(parseErr)
		e.titanExecMu.Lock()
		e.titanExecStats.ParseErrors++
		e.titanExecMu.Unlock()
		if enabled {
			e.noteTitanExecSensorFailure("kernel titan exec event payload rejected: " + text)
		}
		return titanExecDrainBackoff
	}
	if e.recordTitanExecBatch(events, dropped, now) {
		e.noteTitanExecSensorSuccess()
	}
	if enabled {
		return titanExecDrainInterval
	}
	return titanExecDrainBackoff
}

// consumeTitanExecHealth stores the last kernel counter sample. The health
// channel is diagnostic: events are the authoritative ingestion path, so a
// failing health command is reported in the status view but never creates a
// second degradation cause for the same sensor.
func (e *XDREngine) consumeTitanExecHealth(health CoreTitanExecHealth, healthErr error, now time.Time) {
	if e == nil {
		return
	}
	if errors.Is(healthErr, ErrTitanExecUnavailable) {
		e.setTitanExecCapability(false)
		return
	}
	e.titanExecMu.Lock()
	defer e.titanExecMu.Unlock()
	if healthErr != nil {
		e.titanExecHealthErr = boundedTitanExecText(healthErr)
		return
	}
	e.titanExecHealth = health
	e.titanExecHealthAt = now
	e.titanExecHealthErr = ""
}

// noteTitanExecSensorFailure applies the two-hit policy of the existing engine:
// the first failure is journaled, a repeated one degrades this module only, and
// the transition is reported as an event.
func (e *XDREngine) noteTitanExecSensorFailure(reason string) {
	if e == nil || e.state == nil {
		return
	}
	wasDegraded, _ := e.degradedState()
	e.noteVerificationFailure(titanExecSensorCause, reason)
	if degraded, degradedReason := e.degradedState(); !wasDegraded && degraded {
		e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.titan_exec_sensor_degraded", Source: "titan-exec",
			Message: "Titan exec-gate XDR ingestion degraded after repeated failures; kernel enforcement is unaffected on its own path: " + degradedReason})
	}
}

// noteTitanExecSensorSuccess clears the failure counter and any cause this module
// set, and reports the recovery once.
func (e *XDREngine) noteTitanExecSensorSuccess() {
	if e == nil || e.state == nil {
		return
	}
	wasSet := e.titanExecSensorCauseSet()
	e.noteVerificationSuccess(titanExecSensorCause)
	if wasSet && !e.titanExecSensorCauseSet() {
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.titan_exec_sensor_recovered", Source: "titan-exec",
			Message: "Titan exec-gate XDR ingestion recovered after a clean drain"})
	}
}

func (e *XDREngine) titanExecSensorCauseSet() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, set := e.degradeCauses[titanExecSensorCause]
	return set
}
