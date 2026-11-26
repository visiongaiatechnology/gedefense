// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	execPathOverride func(int) string
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
	probeCore              xdrKernelCore
	probeMu                sync.Mutex
	probeSeen              map[string]time.Time
	styxLastPrune          time.Time
	styxLastOverflowEvent  time.Time
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
	updateWindow     *xdrUpdateWindow
	pinnedReleaseKey ed25519.PublicKey
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
	pinnedKey := e.pinnedReleaseKey
	if len(pinnedKey) == 0 {
		var keyErr error
		pinnedKey, keyErr = pinnedReleasePublicKey()
		if keyErr != nil {
			return fmt.Errorf("signed update window refused: %w", keyErr)
		}
	}
	document, err := VerifyPinnedReleaseManifest(manifestPath, publicKeyPath, artifactDir, pinnedKey)
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
	openMessage := fmt.Sprintf("Signed package-update window opened for %d own executable(s); manifest=%s reason=%s expires=%s",
		len(expected), manifestDigest, window.Reason, window.ExpiresAt.Format(time.RFC3339))
	if e.state != nil {
		if err := e.state.RecordEvidence(EvidenceRecord{
			Severity: "high", Kind: "xdr.update_window_opened", Source: "integrity",
			Message: openMessage, Target: productArtifactRoot(),
		}); err != nil && !errors.Is(err, errEvidenceBudgetExhausted) {
			return fmt.Errorf("signed update window refused: evidence commit: %w", err)
		}
	}
	e.mu.Lock()
	e.updateWindow = window
	e.mu.Unlock()
	if e.state != nil {
		e.state.AddEvent(Event{
			Severity: "high", Kind: "xdr.update_window_opened", Source: "integrity",
			Message: openMessage,
			Target:  productArtifactRoot(),
		})
	}
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
	if open && e.state != nil {
		msg := "Signed package-update window closed: " + strings.TrimSpace(reason)
		_ = e.state.RecordEvidence(EvidenceRecord{
			Severity: "high", Kind: "xdr.update_window_closed", Source: "integrity",
			Message: msg, Target: productArtifactRoot(),
		})
		e.state.AddEvent(Event{Severity: "high", Kind: "xdr.update_window_closed", Source: "integrity", Message: msg})
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
	if e.state != nil {
		_ = e.state.RecordEvidence(EvidenceRecord{
			Severity: "high", Kind: "xdr.update_window_artifact_applied", Source: "integrity",
			Message: fmt.Sprintf("GeDefense component replaced inside verified update window (sha256=%s)", updated.digest), Target: path,
		})
		e.state.AddEvent(Event{Severity: "high", Kind: "xdr.update_window_artifact_applied", Source: "integrity",
			Message: "GeDefense component replaced inside a verified signed update window", Target: path})
		if closed {
			const closedMsg = "Signed package-update window closed: every artifact named by the manifest was observed"
			_ = e.state.RecordEvidence(EvidenceRecord{
				Severity: "high", Kind: "xdr.update_window_closed", Source: "integrity",
				Message: closedMsg, Target: productArtifactRoot(),
			})
			e.state.AddEvent(Event{Severity: "high", Kind: "xdr.update_window_closed", Source: "integrity", Message: closedMsg})
		}
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
		e.persistenceCore = core
	}
	if err := logger.Healthy(); err != nil {
		e.markDegradedCause("incident_log", "incident log integrity failure: "+err.Error())
	} else if err := e.restoreIncidentHistory(); err != nil { // The history could not be restored. Saying so is better than showing an empty
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
		DNSAttribution:          e.DNSQueryObservedForPID,
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
