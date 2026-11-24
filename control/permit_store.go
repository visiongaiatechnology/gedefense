// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// V6.3.0 AP-7: persistent PermitV1 store.
//
// Storage contract:
//   - location: <control state dir>/permits.json (the same state root as the
//     incident log, never a world-writable directory);
//   - mode 0600, regular non-symlink file, owned by the control uid (or root),
//     bounded read (4 MiB) and bounded object count (512);
//   - encrypted with the existing StorageCipher (AES-256-GCM, per-purpose key)
//     when the configured storage master key is reachable; otherwise
//     HMAC-SHA256 authenticated with a 0600 local broker key created next to
//     the store. The HMAC fallback is integrity-only by design and documented:
//     permit objects carry no secrets (public executable paths, hashes, inode
//     numbers and scopes), so confidentiality is not claimed when no storage
//     cipher exists. A signature is never faked either way;
//   - atomic replace: temp file in the same directory, fsync, rename, fsync the
//     directory. A failed write leaves the previous store intact;
//   - fail closed: a corrupt/unreadable/oversized store activates no permit,
//     refuses every overwrite (forensics) and reports the condition. There is
//     no silent reset.

// permitBrokerBinding is everything the broker needs to open its store. It is
// derived from the engine configuration by XDREngine.permitBrokerBinding.
type permitBrokerBinding struct {
	StorageDir string
	Cipher     *StorageCipher
	VerifyKey  []byte
	SignKey    []byte
}

// ensurePrivateStoreDir validates (and, for a first run, creates) the state
// directory that holds the broker stores.
func ensurePrivateStoreDir(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return errors.New("permit store directory is invalid")
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("permit store directory: %w", err)
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return fmt.Errorf("permit store directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("permit store directory must be a non-symlink directory")
	}
	if info.Mode().Perm()&0o002 != 0 {
		return errors.New("permit store directory must not be world-writable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("permit store directory ownership is unavailable")
	}
	if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return errors.New("permit store directory is owned by an unrelated account")
	}
	return nil
}

// writePrivateFileAtomic writes data to path with mode 0600, fsyncing the file
// and the containing directory. The previous file is replaced only by the
// final rename, so a crash can never expose a half-written store.
func writePrivateFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := ensurePrivateStoreDir(dir); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("permit store temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("permit store mode: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("permit store write: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("permit store fsync: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryName)
		return fmt.Errorf("permit store close: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		_ = os.Remove(temporaryName)
		return fmt.Errorf("permit store replace: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("permit store directory fsync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("permit store directory fsync: %w", err)
	}
	return nil
}

// bindPermitStore binds the broker to its store and loads the current document.
func (b *PermitBroker) bindPermitStore(binding permitBrokerBinding) error {
	if b == nil {
		return errors.New("permit broker is unavailable")
	}
	if err := ensurePrivateStoreDir(binding.StorageDir); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.storeDir = binding.StorageDir
	b.storePath = filepath.Join(binding.StorageDir, permitStoreFileName)
	b.cipher = binding.Cipher
	if len(binding.VerifyKey) != 0 && len(binding.VerifyKey) != 32 {
		return errors.New("permit verification key is invalid")
	}
	b.verifyKey = append([]byte(nil), binding.VerifyKey...)
	if len(binding.SignKey) != 0 && len(binding.SignKey) != 64 {
		return errors.New("permit signing key is invalid")
	}
	b.signKey = append([]byte(nil), binding.SignKey...)
	if b.cipher == nil {
		keyPath := filepath.Join(binding.StorageDir, permitStoreKeyFileName)
		key, err := loadOrCreatePrivateKey(keyPath, permitStoreKeyBytes)
		if err != nil {
			b.corrupt = true
			b.degradedReason = "permit store HMAC key unavailable: " + err.Error()
			return err
		}
		b.hmacKey = key
	}
	return b.loadPermitStoreLocked()
}

func (b *PermitBroker) permitStoreBound() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.loaded || b.corrupt
}

// loadPermitStoreLocked opens and re-validates every persisted permit. Invalid
// objects are dropped with a counted reason; a corrupt document activates no
// permit at all and refuses later overwrites so the evidence is preserved.
func (b *PermitBroker) loadPermitStoreLocked() error {
	b.loaded = false
	b.corrupt = false
	b.degradedReason = ""
	b.permits = make(map[string]*PermitV1)
	b.dropped = make(map[string]uint64)
	b.expired = 0
	now := b.now()
	if b.storePath == "" {
		b.corrupt = true
		b.degradedReason = "permit store path is unavailable"
		return errors.New(b.degradedReason)
	}
	if err := checkPrivateStoreFile(b.storePath, permitMaxStoreFileBytes); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// First run: an empty store is not a corruption.
			b.loaded = true
			return nil
		}
		b.corrupt = true
		b.degradedReason = "permit store integrity check failed: " + err.Error()
		return errors.New(b.degradedReason)
	}
	data, err := os.ReadFile(b.storePath)
	if err != nil {
		b.corrupt = true
		b.degradedReason = "permit store read failed: " + err.Error()
		return errors.New(b.degradedReason)
	}
	var transport permitStoreTransport
	if b.cipher != nil {
		plaintext, _, openErr := b.cipher.Decrypt(b.storePath, permitStorePurpose, data, nil)
		if openErr != nil {
			b.corrupt = true
			b.degradedReason = "permit store authentication failed: " + openErr.Error()
			return errors.New(b.degradedReason)
		}
		transport, err = decodePermitStoreTransport(plaintext)
		if err != nil {
			b.corrupt = true
			b.degradedReason = err.Error()
			return err
		}
	} else {
		transport, err = permitStoreOpenHMAC(b.hmacKey, data)
		if err != nil {
			b.corrupt = true
			b.degradedReason = err.Error()
			return err
		}
	}
	if transport.Sequence > b.sequence {
		b.sequence = transport.Sequence
	}
	for _, raw := range transport.Permits {
		if len(raw) > permitMaxObjectBytes {
			b.notePermitDropLocked("oversized")
			continue
		}
		permit, decodeErr := decodePermitObject(raw, now)
		if decodeErr != nil {
			b.notePermitDropLocked("invalid")
			continue
		}
		if _, duplicate := b.permits[permit.PermitID]; duplicate {
			b.notePermitDropLocked("duplicate")
			continue
		}
		if len(b.permits) >= permitMaxStorePermits {
			b.notePermitDropLocked("capacity")
			continue
		}
		if !now.Before(permit.ValidUntil) {
			// Normal TTL maintenance, counted separately from corruption.
			b.expired++
			continue
		}
		if err := b.admitPermitTrustLocked(permit); err != nil {
			b.notePermitDropLocked(err.Error())
			continue
		}
		b.permits[permit.PermitID] = permit
	}
	b.loaded = true
	b.lastLoad = now
	return nil
}

// admitPermitTrustLocked applies the honest signature policy. A permit whose
// signature cannot be verified is never treated as AUTHORIZED: an unsigned
// object is demoted to ANALYST_MODE (review only), and an object whose
// signature does not verify against the bound key is dropped.
func (b *PermitBroker) admitPermitTrustLocked(permit *PermitV1) error {
	if permit.Signature == permitSignatureAbsent {
		if permit.TrustLevel != permitTrustAnalyst {
			permit.TrustLevel = permitTrustAnalyst
			b.notePermitDropLocked("unsigned_demoted_to_analyst")
		}
		return nil
	}
	if len(b.verifyKey) == 0 {
		permit.TrustLevel = permitTrustAnalyst
		b.notePermitDropLocked("signature_unverifiable_demoted_to_analyst")
		return nil
	}
	if err := verifyPermitObject(permit, b.verifyKey); err != nil {
		return errors.New("signature_invalid")
	}
	return nil
}

func (b *PermitBroker) notePermitDropLocked(reason string) {
	if b.dropped == nil {
		b.dropped = make(map[string]uint64)
	}
	b.dropped[reason]++
}

// persistPermitStoreLocked atomically replaces the store with the given permit
// set. The sequence number is committed only after a successful rename.
func (b *PermitBroker) persistPermitStoreLocked(permits map[string]*PermitV1) error {
	if b.corrupt {
		return errors.New("permit store is corrupt; refusing to overwrite forensic evidence")
	}
	if b.storePath == "" {
		return errors.New("permit store path is unavailable")
	}
	ids := make([]string, 0, len(permits))
	for id := range permits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rawPermits := make([]json.RawMessage, 0, len(ids))
	for _, id := range ids {
		encoded, err := json.Marshal(permits[id])
		if err != nil {
			return fmt.Errorf("permit serialization: %w", err)
		}
		if len(encoded) > permitMaxObjectBytes {
			return errors.New("permit object exceeds its serialized bound")
		}
		rawPermits = append(rawPermits, encoded)
	}
	sequence := b.sequence + 1
	if sequence == 0 {
		sequence = 1
	}
	transport := permitStoreTransport{Schema: permitStoreSchema, Sequence: sequence, Permits: rawPermits}
	plaintext, err := json.Marshal(transport)
	if err != nil {
		return fmt.Errorf("permit store serialization: %w", err)
	}
	if len(plaintext) > permitMaxStorePlaintextBytes {
		// Refuse before writing: an over-bound document could be written but
		// never read back, which would turn the next startup into a fail-closed
		// corruption event rather than a clear capacity rejection.
		return errors.New("permit store exceeds its plaintext size bound")
	}
	var document []byte
	if b.cipher != nil {
		document, err = b.cipher.Encrypt(b.storePath, permitStorePurpose, sequence, plaintext)
		if err != nil {
			return fmt.Errorf("permit store encryption: %w", err)
		}
	} else {
		document, err = permitStoreSealHMAC(b.hmacKey, sequence, plaintext)
		if err != nil {
			return err
		}
	}
	if err := writePrivateFileAtomic(b.storePath, document); err != nil {
		return err
	}
	b.sequence = sequence
	return nil
}

// PermitReport returns the bounded store projection.
func (b *PermitBroker) PermitReport() PermitReport {
	report := PermitReport{SignatureStatus: permitSignatureAbsent}
	if b == nil {
		return report
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	report.Loaded = b.loaded
	report.StorePath = b.storePath
	report.Corrupt = b.corrupt
	report.Degraded = b.corrupt || b.degradedReason != ""
	report.DegradedReason = b.degradedReason
	report.Stored = len(b.permits)
	report.BuiltinProfiles = len(b.builtins)
	report.Expired = b.expired
	report.SignatureStatus = permitSignatureAbsent
	if len(b.verifyKey) != 0 {
		report.SignatureStatus = "attached"
	}
	if len(b.dropped) > 0 {
		report.Dropped = make(map[string]uint64, len(b.dropped))
		for reason, count := range b.dropped {
			report.Dropped[reason] = count
		}
	}
	var next *time.Time
	for _, permit := range b.permits {
		validUntil := permit.ValidUntil
		if next == nil || validUntil.Before(*next) {
			candidate := validUntil
			next = &candidate
		}
		switch permit.TrustLevel {
		case permitTrustAuthorized:
			report.Authorized++
		case permitTrustTolerated:
			report.Tolerated++
		default:
			report.AnalystOnly++
		}
	}
	report.NextExpiry = next
	return report
}

// boundPermitPaths returns the executable paths of permits that asked for
// binary re-validation; used by the maintenance pass.
func (b *PermitBroker) boundPermitPaths() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.permits))
	for _, permit := range b.permits {
		if permit.Path != "" && containsPermitKind(permit.AutoInvalidateOn, "binary_changed") {
			out = append(out, permit.Path)
		}
	}
	sort.Strings(out)
	return out
}

// stringListSummary renders a bounded rule/scope list for decision metadata.
func stringListSummary(values []string, max int) string {
	if len(values) == 0 {
		return ""
	}
	if len(values) > max {
		values = values[:max]
	}
	joined := strings.Join(values, ",")
	if len(joined) > 200 {
		joined = joined[:200] + "…"
	}
	return joined
}
