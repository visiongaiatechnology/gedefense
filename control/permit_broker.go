// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-7: unified PermitV1 broker.
//
// Central trust evaluation for AUTHORIZED / TOLERATED / ANALYST_MODE permits
// (permit_id, SHA-256, inode, allowed_parents, scope, valid_from/until,
// auto_invalidate_on, Ed25519 evidence-ledger signature). The broker is
// consulted before a finding becomes actionable, so development, container and
// observability toolchains stay at zero false positives. It can only ever
// suppress or downgrade — never create or escalate — a response.
//
// The constructors stay parameterless because the seam in NewXDREngine owns
// construction: storage binding and key material are derived lazily from the
// engine configuration on the first maintenance tick. Evaluate() already works
// without a store for the built-in TOLERATED profiles.

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const permitMaintenanceInterval = 30 * time.Second

// PermitDecision is the broker's bounded decision record. It is attached to
// XDRIncident.Permit for findings a permit downgraded, and is informational
// only: the suppression itself is already applied to the decision/action.
type PermitDecision struct {
	PermitID   string `json:"permit_id,omitempty"`
	TrustLevel string `json:"trust_level"`
	Scope      string `json:"scope,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// PermitBroker is the central trust registry.
type PermitBroker struct {
	mu sync.Mutex

	// builtins are the in-memory TOLERATED profiles seeded at construction.
	builtins []permitProfile

	// permits is the validated, signature-admitted persistent set.
	permits map[string]*PermitV1

	// store binding and persistence state.
	loaded         bool
	corrupt        bool
	storeDir       string
	storePath      string
	cipher         *StorageCipher
	verifyKey      []byte
	signKey        []byte
	hmacKey        []byte
	sequence       uint64
	dropped        map[string]uint64
	expired        int
	degradedReason string
	lastLoad       time.Time
	clock          func() time.Time

	// hashCache bounds repeated executable hashing for stored permits.
	hashCache map[string]permitExecutableIdentity
}

// NewPermitBroker constructs the broker with its auditable built-in profiles.
// It performs no I/O: the persistent store is bound by the engine's maintenance
// tick, and Evaluate works from the in-memory profiles until then.
func NewPermitBroker() *PermitBroker {
	return &PermitBroker{
		builtins:  builtinPermitProfiles(),
		permits:   make(map[string]*PermitV1),
		dropped:   make(map[string]uint64),
		hashCache: make(map[string]permitExecutableIdentity),
	}
}

// now returns the broker clock (injectable for deterministic tests).
func (b *PermitBroker) now() time.Time {
	if b != nil && b.clock != nil {
		return b.clock().UTC()
	}
	return time.Now().UTC()
}

// permitStoreHealthy reports whether the persistent store is bound and intact.
func (b *PermitBroker) permitStoreHealthy() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.loaded && !b.corrupt
}

// permitStoreState returns a consistent snapshot of the load state for logging.
func (b *PermitBroker) permitStoreState() (loaded, corrupt bool, reason string) {
	if b == nil {
		return false, false, "permit broker unavailable"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.loaded, b.corrupt, b.degradedReason
}

// firstNonEmptyPath returns the first non-empty path candidate.
func firstNonEmptyPath(paths ...string) string {
	for _, path := range paths {
		if strings.TrimSpace(path) != "" {
			return path
		}
	}
	return ""
}

// loadPermitBrokerPublicKey reads the existing Ed25519 verification key. The
// policy store writes the raw 32-byte public key; a single trailing newline is
// tolerated. Anything else is refused rather than guessed.
func loadPermitBrokerPublicKey(path string) []byte {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 128 {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil
	}
	return append([]byte(nil), raw...)
}

// loadPermitBrokerSigningKey reads the existing Ed25519 private key. The policy
// store writes either the raw 64-byte private key (or 32-byte seed) or - on an
// installation with a storage master key - an AES-GCM envelope under the
// "policy-signing-key" purpose. Both forms are accepted only from a regular,
// non-symlink, non-group/world-accessible file; anything else yields no signer
// and permits stay analyst-only instead of being signed with a guessed key.
func loadPermitBrokerSigningKey(path string, cipher *StorageCipher) []byte {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 32<<10 {
		return nil
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if cipher != nil {
		decrypted, _, decryptErr := cipher.DecryptForMigration(path, "policy-signing-key", raw, nil)
		if decryptErr != nil {
			return nil
		}
		raw = decrypted
	}
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return append([]byte(nil), raw...)
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(append([]byte(nil), raw...))
	default:
		return nil
	}
}

// permitBrokerBinding derives the store location, cipher and signing material
// from the engine configuration. It never creates a key file and never fails
// the engine: an absent key is reported honestly and yields analyst-only
// permits.
func (e *XDREngine) permitBrokerBinding() permitBrokerBinding {
	binding := permitBrokerBinding{}
	if e == nil {
		return binding
	}
	storageDir := filepath.Dir(strings.TrimSpace(e.cfg.XDR.IncidentLog))
	if storageDir == "." || storageDir == "" {
		storageDir = "/var/lib/vgt/gedefense"
	}
	binding.StorageDir = storageDir
	storageKeyPath := firstNonEmptyPath(e.cfg.XDR.StorageKeyFile, e.cfg.Runtime.StorageKeyFile, e.cfg.Policy.StorageKeyFile)
	if storageKeyPath != "" {
		if cipher, err := NewStorageCipher(storageKeyPath, e.cfg.Node.Name); err == nil && cipher != nil {
			binding.Cipher = cipher
		}
	}
	if e.policy != nil {
		if publicKey := e.policy.TrustedPublicKey(); len(publicKey) == ed25519.PublicKeySize {
			binding.VerifyKey = append([]byte(nil), publicKey...)
		}
	}
	if len(binding.VerifyKey) == 0 {
		binding.VerifyKey = loadPermitBrokerPublicKey(e.cfg.Policy.PublicKeyFile)
	}
	binding.SignKey = loadPermitBrokerSigningKey(e.cfg.Policy.SigningKeyFile, binding.Cipher)
	if len(binding.VerifyKey) == 0 {
		binding.SignKey = nil
	}
	// Never accept a signing key that does not belong to the verification
	// identity: that would mint objects the broker immediately rejects.
	if len(binding.SignKey) == ed25519.PrivateKeySize && len(binding.VerifyKey) == ed25519.PublicKeySize {
		privateKey := ed25519.PrivateKey(binding.SignKey)
		publicKey, ok := privateKey.Public().(ed25519.PublicKey)
		if !ok || !publicKey.Equal(ed25519.PublicKey(binding.VerifyKey)) {
			binding.SignKey = nil
		}
	}
	return binding
}

// permitStoreCauseSet reports whether a permit-store degradation is already
// recorded, so repeated maintenance ticks cannot flood the event stream.
func (e *XDREngine) permitStoreCauseSet() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.degradeCauses["permit_store"]
	return ok
}

// notePermitStoreDegraded records the permit-store cause once per transition.
func (e *XDREngine) notePermitStoreDegraded(reason string) {
	if e == nil {
		return
	}
	if e.permitStoreCauseSet() {
		e.markDegradedCause("permit_store", reason)
		return
	}
	e.markDegradedCause("permit_store", reason)
	if e.state != nil {
		e.state.AddEvent(Event{
			Severity: "warning", Kind: "xdr.permit_store_degraded", Source: "permit-broker",
			Message: "PermitV1 store unavailable or corrupt; no AUTHORIZED permit is active: " + boundedPermitText(reason, 320),
		})
	}
}

// clearPermitStoreDegraded clears the cause and reports the recovery once.
func (e *XDREngine) clearPermitStoreDegraded() {
	if e == nil || !e.permitStoreCauseSet() {
		return
	}
	e.clearDegradedCause("permit_store")
	if e.state != nil {
		e.state.AddEvent(Event{
			Severity: "info", Kind: "xdr.permit_store_recovered", Source: "permit-broker",
			Message: "PermitV1 store verified; permit evaluation restored",
		})
	}
}

// pollPermits loads/revalidates the store on start, expires TTLs, applies
// auto-invalidation, persists changes atomically, drives the persistent review
// queue flush and returns the next due maintenance time.
func (e *XDREngine) pollPermits(runtime RuntimeSettings, now time.Time, retryAfter time.Time) time.Time {
	if e == nil || e.permits == nil {
		return retryAfter
	}
	if !retryAfter.IsZero() && now.Before(retryAfter) {
		return retryAfter
	}
	next := now.Add(permitMaintenanceInterval)
	if !e.permits.permitStoreHealthy() {
		binding := e.permitBrokerBinding()
		if err := e.permits.bindPermitStore(binding); err != nil {
			e.notePermitStoreDegraded(err.Error())
		} else {
			e.clearPermitStoreDegraded()
			if e.state != nil {
				report := e.permits.PermitReport()
				e.state.AddEvent(Event{
					Severity: "info", Kind: "xdr.permit_broker_online", Source: "permit-broker",
					Message: eventPermitBrokerOnlineMessage(report),
				})
			}
		}
	}
	if e.permits.permitStoreHealthy() {
		if invalidated, err := e.permits.invalidateBinaryChanges(now); err != nil {
			e.notePermitStoreDegraded("permit binary re-validation failed: " + err.Error())
		} else if invalidated > 0 && e.state != nil {
			e.state.AddEvent(Event{
				Severity: "warning", Kind: "xdr.permit_auto_invalidated", Source: "permit-broker",
				Message: "PermitV1 objects invalidated after executable identity change",
			})
		}
		if expired, changed, err := e.permits.maintainPermitStore(now, nil); err != nil {
			e.notePermitStoreDegraded("permit maintenance persist failed: " + err.Error())
		} else if changed && e.state != nil {
			e.state.AddEvent(Event{
				Severity: "info", Kind: "xdr.permit_expired", Source: "permit-broker",
				Message: "Expired PermitV1 objects removed from the store",
			})
			_ = expired
		}
		if report := e.permits.PermitReport(); report.NextExpiry != nil && report.NextExpiry.Before(next) {
			next = *report.NextExpiry
		}
	}
	// The review queue flush rides the same bounded maintenance cadence so a
	// burst of incidents never forces a per-incident disk fsync.
	if due := e.maintainReviewQueue(now); due.Before(next) {
		next = due
	}
	_ = runtime
	return next
}

// eventPermitBrokerOnlineMessage renders a bounded online event.
func eventPermitBrokerOnlineMessage(report PermitReport) string {
	message := "PermitV1 broker online: stored=" + strconv.Itoa(report.Stored) +
		" builtin_profiles=" + strconv.Itoa(report.BuiltinProfiles) +
		" signature=" + report.SignatureStatus
	if report.Authorized > 0 || report.Tolerated > 0 || report.AnalystOnly > 0 {
		message += " authorized=" + strconv.Itoa(report.Authorized) +
			" tolerated=" + strconv.Itoa(report.Tolerated) +
			" analyst_only=" + strconv.Itoa(report.AnalystOnly)
	}
	return message
}

// PermitReport returns the bounded broker projection for operators and tests.
func (e *XDREngine) PermitReport() PermitReport {
	if e == nil || e.permits == nil {
		return PermitReport{SignatureStatus: permitSignatureAbsent}
	}
	return e.permits.PermitReport()
}

func (e *XDREngine) ensurePermitStoreBound() {
	if e == nil || e.permits == nil || e.permits.permitStoreHealthy() {
		return
	}
	if err := e.permits.bindPermitStore(e.permitBrokerBinding()); err != nil {
		e.notePermitStoreDegraded(err.Error())
		return
	}
	e.clearPermitStoreDegraded()
}

// ListPermits returns the bounded sorted slice of stored PermitV1 entries.
func (e *XDREngine) ListPermits() []PermitV1 {
	if e == nil || e.permits == nil {
		return []PermitV1{}
	}
	e.ensurePermitStoreBound()
	return e.permits.ListPermits()
}

// UpsertPermit binds the store if needed and persists one PermitV1 object.
func (e *XDREngine) UpsertPermit(permit *PermitV1) error {
	if e == nil || e.permits == nil {
		return errors.New("permit broker is unavailable")
	}
	e.ensurePermitStoreBound()
	return e.permits.UpsertPermit(permit)
}

// RemovePermit binds the store if needed and deletes one PermitV1 object.
func (e *XDREngine) RemovePermit(permitID string) error {
	if e == nil || e.permits == nil {
		return errors.New("permit broker is unavailable")
	}
	e.ensurePermitStoreBound()
	return e.permits.RemovePermit(permitID)
}

// InvalidatePermits is the engine-level invalidation hook for callers that
// observe a trust-relevant event (baseline_rebaseline, policy_update,
// rule_update). It never touches permits whose auto_invalidate_on does not name
// the kind.
func (e *XDREngine) InvalidatePermits(kind string) (int, error) {
	if e == nil || e.permits == nil {
		return 0, errors.New("permit broker is unavailable")
	}
	return e.permits.InvalidatePermits(kind)
}

// RevalidatePermitBinaries re-hashes every permit that requested
// auto_invalidate_on=binary_changed and removes the ones whose executable identity
// changed. The maintenance tick calls the same logic.
func (e *XDREngine) RevalidatePermitBinaries(now time.Time) (int, error) {
	if e == nil || e.permits == nil {
		return 0, errors.New("permit broker is unavailable")
	}
	return e.permits.invalidateBinaryChanges(now)
}
