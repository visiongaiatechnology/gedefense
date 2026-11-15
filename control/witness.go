package main

// POINT 4 / P4-T2: the Out-of-Band Witness engine (docs/POINT4-WITNESS.md §4, §7, §8).
//
// The engine is the only component that turns a ledger head into a signed
// checkpoint, queues it and pushes it. It is additive and inert by default: while
// witness.enabled is false it starts no ticker, creates no checkpoint, sends no
// request and writes no event. Everything it reports is bounded (hashes, enums,
// counters); no path, endpoint, token or key material crosses the status surface.
//
// Failure direction is always fail-closed: a quarantined ledger refuses to sign,
// a full or corrupt outbox refuses new checkpoints, an unreachable witness only
// degrades (it never triggers a lockdown), and an equivocation or rollback of the
// (ledger_epoch, sequence, head_hash) triple is critical evidence plus an
// incident and - only when an operator asked for it - an additive P5 trigger.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	witnessKeyBinding     = "software"
	witnessEventCooldown  = 5 * time.Minute
	witnessMaxReasonBytes = 200
)

var (
	errWitnessDisabled = errors.New("witness is disabled")
	errWitnessBusy     = errors.New("a witness cycle is already running")
)

// WitnessLockdownTrigger is the additive P5 hook. The witness engine never talks
// to the core directly; it only asks the lockdown engine to evaluate an
// automatic candidate, whose dedupe/cooldown/source guards stay authoritative.
type WitnessLockdownTrigger interface {
	TriggerWitnessEquivocation(fingerprint string) error
}

// witnessTransport is the push side the engine needs. *witnessHTTPClient is the
// production implementation; tests inject a fake to exercise the engine without a
// network.
type witnessTransport interface {
	Challenge(ctx context.Context) (string, error)
	Push(ctx context.Context, checkpoint WitnessCheckpoint) (WitnessReceipt, error)
	LastWitnessSeq() uint64
	ChallengePending() bool
}

// WitnessEngineConfig is the construction set. Transport is the test injection;
// Storage, OutboxPath and AckPath are overridable for the same reason.
type WitnessEngineConfig struct {
	NodeID      string
	Ledger      *EvidenceLedger
	Settings    *SettingsStore
	State       *State
	Storage     *StorageCipher
	OutboxPath  string
	AckPath     string
	BootTrust   func() BootTrustReport
	SensorState func() string
	Lockdown    WitnessLockdownTrigger
	Transport   witnessTransport
	Now         func() time.Time
}

// WitnessEngine owns the ticker, the outbox, the receipt monotonicity baseline
// and the equivocation detector. opsMu serialises one cycle; the status read only
// takes mu for the projection.
type WitnessEngine struct {
	cfg              WitnessEngineConfig
	nodeID           string
	now              func() time.Time
	opsMu            sync.Mutex
	mu               sync.Mutex
	settings         WitnessFabricSettings
	outbox           *witnessOutbox
	transport        witnessTransport
	ack              witnessAckState
	failClosed       string
	lastCheckpoint   *WitnessCheckpoint
	lastExport       *WitnessCheckpoint
	observed         *witnessHead
	equivocation     bool
	equivocationAt   *time.Time
	equivocationKind string
	failures         int
	degraded         bool
	lastError        string
	eventSeen        map[string]time.Time
	wake             chan struct{}
}

// NewWitnessEngine loads the authenticated ack baseline and outbox. It never
// performs network I/O: a failing witness is a runtime condition, not a start
// condition.
func NewWitnessEngine(cfg WitnessEngineConfig) (*WitnessEngine, error) {
	if cfg.Settings == nil {
		return nil, errors.New("witness engine requires the runtime settings store")
	}
	if cfg.Transport == nil && cfg.Ledger == nil {
		return nil, errors.New("witness engine requires the evidence ledger")
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	engine := &WitnessEngine{
		cfg: cfg, nodeID: witnessNodeID(cfg.NodeID), now: now,
		settings:  effectiveWitnessSettings(cfg.Settings.Get()),
		eventSeen: make(map[string]time.Time), wake: make(chan struct{}, 1),
	}
	if !witnessModeActive(engine.settings) {
		// Default-off: no outbox read, no ack read, no client, no file writes.
		return engine, nil
	}
	if err := engine.activateLocked(); err != nil {
		return nil, err
	}
	return engine, nil
}

// activateLocked establishes the runtime wiring for the current settings. It is
// called from the constructor and from ApplyRuntimeSettings.
func (e *WitnessEngine) activateLocked() error {
	settings := e.settings
	if err := validateWitnessFabricSettings(&settings); err != nil {
		e.failClosed = "witness settings are invalid"
		return err
	}
	e.failClosed = ""
	if e.cfg.Storage == nil && e.cfg.Transport == nil {
		e.failClosed = "witness storage cipher is unavailable"
		return errors.New("witness storage cipher is unavailable")
	}
	if settings.Mode == witnessModeHTTP {
		outboxPath := e.cfg.OutboxPath
		if outboxPath == "" {
			e.failClosed = "witness outbox path is unavailable"
			return errors.New("witness outbox path is unavailable")
		}
		if e.outbox == nil {
			outbox, err := newWitnessOutbox(outboxPath, e.cfg.Storage, settings.OutboxMaxBytes, settings.OutboxMaxEntries, e.now)
			if outbox != nil && outbox.isCorrupt() {
				e.outbox = outbox
				e.failClosed = "witness outbox is corrupt"
				if err != nil {
					e.recordEventOnce("outbox-corrupt", "critical", "witness.outbox_full",
						"Witness outbox could not be authenticated; no new checkpoint is created until an operator repairs it")
				}
			} else if err != nil {
				e.failClosed = "witness outbox is unavailable"
				return err
			} else {
				e.outbox = outbox
			}
		}
		if e.cfg.Transport != nil {
			e.transport = e.cfg.Transport
		} else {
			client, err := newWitnessHTTPClient(witnessClientConfig{
				Settings: settings, Now: e.now, InitialWitnessSeq: e.ack.LastWitnessSeq,
			})
			if err != nil {
				e.failClosed = "witness transport could not be configured"
				return err
			}
			e.transport = client
		}
	} else {
		e.transport = nil
		if e.cfg.Transport != nil {
			e.transport = e.cfg.Transport
		}
	}
	if e.ack.Schema == "" && e.cfg.AckPath != "" && e.cfg.Storage != nil {
		ack, err := loadWitnessAckState(e.cfg.AckPath, e.cfg.Storage)
		if err != nil {
			e.failClosed = "witness ack baseline is corrupt"
			e.recordEventOnce("ack-corrupt", "critical", "witness.push.failed",
				"Witness acknowledgement baseline could not be authenticated; no checkpoint is pushed until an operator repairs it")
			return nil
		}
		e.ack = ack
		if ack.Equivocation {
			e.equivocation = true
			at := ack.EquivocationAt
			e.equivocationAt = at
			e.equivocationKind = ack.EquivocationKind
		}
	}
	if e.transport != nil && e.ack.LastWitnessSeq > 0 {
		if client, ok := e.transport.(*witnessHTTPClient); ok {
			client.seqMu.Lock()
			if e.ack.LastWitnessSeq > client.lastSeq {
				client.lastSeq = e.ack.LastWitnessSeq
			}
			client.seqMu.Unlock()
		}
	}
	if e.ack.LastHeadHash != "" {
		e.observed = &witnessHead{epoch: e.ack.LastEpoch, sequence: e.ack.LastSequence, headHash: e.ack.LastHeadHash}
	}
	return nil
}

// ApplyRuntimeSettings applies a committed settings revision to the engine.
func (e *WitnessEngine) ApplyRuntimeSettings(settings RuntimeSettings) error {
	e.mu.Lock()
	next := effectiveWitnessSettings(settings)
	if next == e.settings {
		e.mu.Unlock()
		return nil
	}
	previous := e.settings
	e.settings = next
	e.mu.Unlock()
	if err := e.activateLocked(); err != nil {
		e.mu.Lock()
		e.settings = previous
		e.failClosed = "witness settings could not be activated"
		e.mu.Unlock()
		return fmt.Errorf("witness settings: %w", err)
	}
	e.mu.Lock()
	e.degraded = false
	e.failures = 0
	e.mu.Unlock()
	e.wakeNow()
	return nil
}

func (e *WitnessEngine) wakeNow() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// interval returns the current checkpoint cadence.
func (e *WitnessEngine) interval() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	seconds := e.settings.CheckpointIntervalSeconds
	if seconds < 30 || seconds > 86400 {
		seconds = 300
	}
	return time.Duration(seconds) * time.Second
}

// Run drives the engine until the context is cancelled. While the namespace is
// inert it blocks without a timer, producing no traffic at all.
func (e *WitnessEngine) Run(ctx context.Context) {
	for {
		e.mu.Lock()
		active := witnessModeActive(e.settings)
		e.mu.Unlock()
		if !active {
			select {
			case <-ctx.Done():
				return
			case <-e.wake:
				continue
			}
		}
		timer := time.NewTimer(e.interval())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-e.wake:
			timer.Stop()
			continue
		case <-timer.C:
			e.cycle(ctx)
		}
	}
}

// cycle runs one checkpoint/push cycle. A second concurrent cycle is dropped:
// single-flight is what keeps a slow witness from stacking goroutines.
func (e *WitnessEngine) cycle(ctx context.Context) {
	if !e.opsMu.TryLock() {
		return
	}
	defer e.opsMu.Unlock()
	if _, err := e.checkpointLocked(ctx); err != nil {
		return
	}
	e.pushPendingLocked(ctx)
}

// CheckpointNow creates and queues one signed checkpoint on operator request. It
// writes the creation evidence before returning and never performs network I/O
// other than a challenge fetch during a subsequent push.
func (e *WitnessEngine) CheckpointNow(ctx context.Context) (WitnessCheckpoint, error) {
	if !e.opsMu.TryLock() {
		return WitnessCheckpoint{}, errWitnessBusy
	}
	defer e.opsMu.Unlock()
	checkpoint, err := e.checkpointLocked(ctx)
	if err != nil {
		return WitnessCheckpoint{}, err
	}
	return checkpoint, nil
}

// Challenge fetches one fresh, single-use nonce from the configured witness.
func (e *WitnessEngine) Challenge(ctx context.Context) (string, error) {
	e.mu.Lock()
	settings := e.settings
	failClosed := e.failClosed
	transport := e.transport
	e.mu.Unlock()
	if !witnessModeActive(settings) {
		return "", errWitnessDisabled
	}
	if failClosed != "" || transport == nil {
		return "", errors.New("witness transport is unavailable")
	}
	return transport.Challenge(ctx)
}

// NonceTTLSeconds reports the configured client-side challenge lifetime.
func (e *WitnessEngine) NonceTTLSeconds() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.settings.NonceTTLSeconds
}

// bootPosture returns the §3 boot-posture enum and its digest. Without a
// provider the honest value is NOT_SUPPORTED: no boot evidence is available.
func (e *WitnessEngine) bootPosture() (string, string) {
	if e.cfg.BootTrust == nil {
		return "NOT_SUPPORTED", BootPostureDigest(BootTrustReport{})
	}
	report := e.cfg.BootTrust()
	posture := report.Status
	switch posture {
	case "VERIFIED", "OBSERVE", "NOT_SUPPORTED":
	default:
		posture = "OBSERVE"
	}
	return posture, BootPostureDigest(report)
}

// sensorState maps the XDR sensor label onto the checkpoint enum. The sensor
// label itself is never exported.
func (e *WitnessEngine) sensorState() string {
	if e.cfg.SensorState == nil {
		return "disabled"
	}
	label := strings.ToLower(strings.TrimSpace(e.cfg.SensorState()))
	switch {
	case label == "" || label == "initializing":
		return "offline"
	case strings.HasPrefix(label, "disabled"):
		return "disabled"
	case strings.Contains(label, "degraded"):
		return "degraded"
	default:
		return "online"
	}
}

// witnessChallengeCache enforces single use and a client-side TTL for witness
// nonces. It is bounded, so a hostile witness cannot grow it without limit.
type witnessChallengeCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	issued  map[string]time.Time
	claimed map[string]struct{}
	order   []string
}

func newWitnessChallengeCache(ttl time.Duration) *witnessChallengeCache {
	if ttl <= 0 {
		ttl = 120 * time.Second
	}
	return &witnessChallengeCache{ttl: ttl, issued: make(map[string]time.Time), claimed: make(map[string]struct{})}
}

func validWitnessChallengeFormat(challenge string) error {
	if challenge == "" {
		return errors.New("witness challenge is empty")
	}
	if len(challenge)%2 != 0 || len(challenge)/2 > witnessChallengeMaxHexBytes {
		return errors.New("witness challenge is not bounded hex")
	}
	if !validWitnessLowerHex(challenge) {
		return errors.New("witness challenge is not lowercase hex")
	}
	return nil
}

// issue records a freshly received nonce. A nonce already in the cache is a
// replay from the witness and is refused.
func (c *witnessChallengeCache) issue(challenge string, now time.Time) error {
	if err := validWitnessChallengeFormat(challenge); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	if _, seen := c.issued[challenge]; seen {
		return errors.New("witness returned a nonce it already issued")
	}
	c.issued[challenge] = now
	c.order = append(c.order, challenge)
	if len(c.order) > witnessChallengeCacheSize {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.issued, oldest)
		delete(c.claimed, oldest)
	}
	return nil
}

// claim consumes a nonce for exactly one checkpoint push. An unknown, expired or
// already used nonce is refused.
func (c *witnessChallengeCache) claim(challenge string, now time.Time) error {
	if err := validWitnessChallengeFormat(challenge); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	issuedAt, ok := c.issued[challenge]
	if !ok {
		return errors.New("checkpoint challenge was not requested through this client")
	}
	if now.Sub(issuedAt) > c.ttl {
		delete(c.issued, challenge)
		return errors.New("checkpoint challenge has expired")
	}
	if _, used := c.claimed[challenge]; used {
		return errors.New("checkpoint challenge was already used")
	}
	c.claimed[challenge] = struct{}{}
	return nil
}

func (c *witnessChallengeCache) pending(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	return len(c.issued) > 0
}

func (c *witnessChallengeCache) prune(now time.Time) {
	for challenge, issuedAt := range c.issued {
		if now.Sub(issuedAt) > c.ttl {
			delete(c.issued, challenge)
			delete(c.claimed, challenge)
		}
	}
}

// markOutboxFull flips the engine into the fail-closed degraded state: a full
// outbox refuses new checkpoints and records witness.outbox_full exactly once per
// cooldown. It never drops queued evidence.
func (e *WitnessEngine) markOutboxFull() {
	e.mu.Lock()
	e.degraded = true
	e.lastError = "witness outbox is full"
	e.mu.Unlock()
	e.recordEventOnce("outbox-full", "critical", "witness.outbox_full",
		"Witness outbox reached its configured bound; no new checkpoint is created and no evidence is dropped")
}
