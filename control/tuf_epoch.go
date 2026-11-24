// AP-9 / S09 — persistent anti-rollback high-water register and the
// Last-Known-Good shadow that a rejected update must never replace.
//
// The register lives below the existing control-plane state root
// (/var/lib/vgt/gedefense/ by default) as a bounded plain JSON document:
//
//	tuf-high-water.json   the register (0600, owner-only, canonical JSON)
//	tuf-high-water.key    32 random bytes, HMAC-SHA256 key (0600, owner-only)
//
// The register is authenticated with HMAC-SHA256 over its canonical bytes with
// a domain-separated tag, so a process that can edit the JSON but cannot read
// the key file cannot raise/lower the epoch, rewrite the content digests or
// fake a Last-Known-Good activation. That is the strongest binding available
// without adding a configuration field for a dedicated key: a compromise of the
// whole state root (key file and register together) is equivalent to a
// compromise of the control-plane service account and is documented as such.
//
// Fail-closed semantics:
//   - register and key must exist as a pair; one without the other is corrupt;
//   - the register must be a regular non-symlink file, owner-only (0600),
//     owned by the running service uid, bounded (64 KiB) and canonical;
//   - the HMAC must verify in constant time; any failure is a
//     tuf.state_corrupt rejection, so feeds fail closed instead of silently
//     restarting the epoch at zero.
//
// Activation contract: only a sync that accepted the threshold envelope *and*
// promoted every enabled source advances the epoch and writes a new
// Last-Known-Good hash. A rejected sync leaves the previous register untouched
// (the previous Last-Known-Good keeps being served) and only increments the
// bounded rejection counters.

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	// tufHighWaterSchema is the canonical register schema token.
	tufHighWaterSchema = "vgt-gedefense-tuf-high-water-v1"
	// tufHighWaterFile / tufHighWaterKeyFile are the two state-root files.
	tufHighWaterFile    = "tuf-high-water.json"
	tufHighWaterKeyFile = "tuf-high-water.key"
	// tufHighWaterMACTag domain-separates the register MAC from every other use
	// of the same key material.
	tufHighWaterMACTag = "vgt-gedefense/tuf-high-water/v1\x00"
	// tufMaxHighWaterBytes bounds the register before any JSON decoding.
	tufMaxHighWaterBytes = 64 << 10
	// tufHighWaterKeyBytes is the fixed HMAC key size.
	tufHighWaterKeyBytes = 32
	// tufBlockedEventLimit bounds the in-memory rejection ring.
	tufBlockedEventLimit = 8
)

// TUFHighWaterRegister is the persisted epoch register. All fields are inside
// the MAC except MAC itself.
type TUFHighWaterRegister struct {
	Schema              string `json:"schema"`
	Epoch               uint64 `json:"epoch"`
	SnapshotSHA256      string `json:"snapshot_sha256"`
	ContentSHA256       string `json:"content_sha256"`
	LastKnownGoodSHA256 string `json:"last_known_good_sha256"`
	ActivatedAt         string `json:"activated_at"`
	Reason              string `json:"reason"`
	MAC                 string `json:"mac"`
}

// canonicalBytesWithoutMAC serialises the register exactly as it is MAC'd.
func (r TUFHighWaterRegister) canonicalBytesWithoutMAC() ([]byte, error) {
	r.MAC = ""
	return json.Marshal(r)
}

// TUFHighWaterStore is the file-backed register below one state root.
type TUFHighWaterStore struct {
	dir string
}

func newTUFHighWaterStore(stateDir string) TUFHighWaterStore {
	return TUFHighWaterStore{dir: stateDir}
}

func (s TUFHighWaterStore) registerPath() string {
	return filepath.Join(s.dir, tufHighWaterFile)
}

func (s TUFHighWaterStore) keyPath() string {
	return filepath.Join(s.dir, tufHighWaterKeyFile)
}

// validateTUFHighWaterRegister enforces the register invariants independent of
// the MAC. Every digest is canonical lowercase hex, so the same activation can
// only ever have one persisted representation.
func validateTUFHighWaterRegister(register TUFHighWaterRegister) error {
	if register.Schema != tufHighWaterSchema {
		return newTUFError(TUFReasonStateCorrupt, "high-water register schema rejected")
	}
	if register.Epoch == 0 {
		return newTUFError(TUFReasonStateCorrupt, "high-water register epoch must be positive")
	}
	for field, value := range map[string]string{
		"snapshot_sha256": register.SnapshotSHA256,
		"content_sha256":  register.ContentSHA256,
		"lkg_sha256":      register.LastKnownGoodSHA256,
	} {
		if len(value) != 64 {
			return newTUFError(TUFReasonStateCorrupt, "high-water register "+field+" rejected")
		}
		decoded, err := hex.DecodeString(value)
		if err != nil || hex.EncodeToString(decoded) != value {
			return newTUFError(TUFReasonStateCorrupt, "high-water register "+field+" is not canonical hex")
		}
	}
	activatedAt, err := parseTUFCanonicalTime("activated_at", register.ActivatedAt)
	if err != nil || activatedAt.IsZero() {
		return newTUFError(TUFReasonStateCorrupt, "high-water register activation time rejected")
	}
	reason := strings.TrimSpace(register.Reason)
	if reason == "" || len(reason) > 160 {
		return newTUFError(TUFReasonStateCorrupt, "high-water register reason rejected")
	}
	for index := 0; index < len(reason); index++ {
		if c := reason[index]; c < 0x20 || c == 0x7f {
			return newTUFError(TUFReasonStateCorrupt, "high-water register reason contains a control character")
		}
	}
	return nil
}

// readTUFHighWaterFile reads one owner-only regular state file with an owner
// check. The returned bytes are bounded by maxBytes.
func readTUFHighWaterFile(filePath string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return nil, newTUFError(TUFReasonStateCorrupt, "high-water state file is missing or unreadable")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, newTUFError(TUFReasonStateCorrupt, "high-water state file must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, newTUFError(TUFReasonStateCorrupt, "high-water state file must be owner-only (0600)")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return nil, newTUFError(TUFReasonStateCorrupt, "high-water state file owner does not match the service uid")
	}
	if info.Size() <= 0 || info.Size() > maxBytes {
		return nil, newTUFError(TUFReasonStateCorrupt, "high-water state file size rejected")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, newTUFError(TUFReasonStateCorrupt, "high-water state file could not be opened")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, newTUFError(TUFReasonStateCorrupt, "high-water state file could not be read")
	}
	if int64(len(raw)) > maxBytes {
		return nil, newTUFError(TUFReasonStateCorrupt, "high-water state file exceeds the bounded size")
	}
	return raw, nil
}

// Load reads and authenticates the register. (zero, false, nil) is returned only
// when neither the register nor its key exists: that is the documented
// first-activation bootstrap state, where the high-water epoch is zero. Every
// partial or corrupt state is an error, never a silent reset.
func (s TUFHighWaterStore) Load() (TUFHighWaterRegister, bool, error) {
	_, registerErr := os.Lstat(s.registerPath())
	_, keyErr := os.Lstat(s.keyPath())
	registerExists := registerErr == nil
	keyExists := keyErr == nil
	if !registerExists && !keyExists {
		if registerErr != nil && !errors.Is(registerErr, os.ErrNotExist) {
			return TUFHighWaterRegister{}, false, newTUFError(TUFReasonStateCorrupt, "high-water register cannot be inspected")
		}
		if keyErr != nil && !errors.Is(keyErr, os.ErrNotExist) {
			return TUFHighWaterRegister{}, false, newTUFError(TUFReasonStateCorrupt, "high-water key cannot be inspected")
		}
		return TUFHighWaterRegister{}, false, nil
	}
	if !registerExists || !keyExists {
		return TUFHighWaterRegister{}, false, newTUFError(TUFReasonStateCorrupt,
			"high-water register and key must exist as a pair; refusing a partial register")
	}
	keyRaw, err := readTUFHighWaterFile(s.keyPath(), tufHighWaterKeyBytes)
	if err != nil {
		return TUFHighWaterRegister{}, false, err
	}
	if len(keyRaw) != tufHighWaterKeyBytes {
		return TUFHighWaterRegister{}, false, newTUFError(TUFReasonStateCorrupt, "high-water key has the wrong length")
	}
	raw, err := readTUFHighWaterFile(s.registerPath(), tufMaxHighWaterBytes)
	if err != nil {
		return TUFHighWaterRegister{}, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var register TUFHighWaterRegister
	if err := decoder.Decode(&register); err != nil {
		return TUFHighWaterRegister{}, false, newTUFError(TUFReasonStateCorrupt, "high-water register JSON rejected")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return TUFHighWaterRegister{}, false, newTUFError(TUFReasonStateCorrupt, "high-water register trailing data rejected")
	}
	canonical, err := json.Marshal(register)
	if err != nil || !bytes.Equal(canonical, raw) {
		return TUFHighWaterRegister{}, false, newTUFError(TUFReasonStateCorrupt, "high-water register is not canonical JSON")
	}
	if err := validateTUFHighWaterRegister(register); err != nil {
		return TUFHighWaterRegister{}, false, err
	}
	providedMAC, err := hex.DecodeString(register.MAC)
	if err != nil || len(providedMAC) != sha256.Size || hex.EncodeToString(providedMAC) != register.MAC {
		return TUFHighWaterRegister{}, false, newTUFError(TUFReasonStateCorrupt, "high-water register MAC encoding rejected")
	}
	payload, err := register.canonicalBytesWithoutMAC()
	if err != nil {
		return TUFHighWaterRegister{}, false, newTUFError(TUFReasonStateCorrupt, "high-water register payload rejected")
	}
	expectedMAC := tufHighWaterMAC(keyRaw, payload)
	if !hmac.Equal(providedMAC, expectedMAC) {
		return TUFHighWaterRegister{}, false, newTUFError(TUFReasonStateCorrupt, "high-water register MAC does not verify")
	}
	return register, true, nil
}

func tufHighWaterMAC(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(tufHighWaterMACTag))
	mac.Write(payload)
	return mac.Sum(nil)
}

// ensureKey loads the HMAC key, generating it exactly once with O_EXCL. A key
// that already exists is never overwritten: rolling the register MAC key would
// make the previous register unverifiable and is not a recovery path.
func (s TUFHighWaterStore) ensureKey() ([]byte, error) {
	if _, err := os.Lstat(s.keyPath()); err == nil {
		key, readErr := readTUFHighWaterFile(s.keyPath(), tufHighWaterKeyBytes)
		if readErr != nil {
			return nil, readErr
		}
		if len(key) != tufHighWaterKeyBytes {
			return nil, newTUFError(TUFReasonStateCorrupt, "high-water key has the wrong length")
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, newTUFError(TUFReasonStateCorrupt, "high-water key cannot be inspected")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, newTUFError(TUFReasonStateCorrupt, "high-water state root could not be created")
	}
	key := make([]byte, tufHighWaterKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, newTUFError(TUFReasonStateCorrupt, "high-water key generation failed")
	}
	if err := atomicWriteFile(s.keyPath(), key, 0o600); err != nil {
		// A concurrent creator (single-instance lock should prevent this) wins;
		// re-read instead of overwriting existing key material.
		if existing, readErr := readTUFHighWaterFile(s.keyPath(), tufHighWaterKeyBytes); readErr == nil && len(existing) == tufHighWaterKeyBytes {
			return existing, nil
		}
		return nil, newTUFError(TUFReasonStateCorrupt, "high-water key could not be persisted")
	}
	return key, nil
}

// Commit authenticates and atomically persists one register. The write is
// tmp+fsync+rename (atomicWriteFile), 0600, and the persisted mode is verified
// after the rename so a umask or filesystem surprise cannot silently loosen it.
func (s TUFHighWaterStore) Commit(register TUFHighWaterRegister) error {
	if err := validateTUFHighWaterRegister(register); err != nil {
		return err
	}
	key, err := s.ensureKey()
	if err != nil {
		return err
	}
	payload, err := register.canonicalBytesWithoutMAC()
	if err != nil {
		return newTUFError(TUFReasonStateCorrupt, "high-water register payload could not be encoded")
	}
	register.MAC = hex.EncodeToString(tufHighWaterMAC(key, payload))
	encoded, err := json.Marshal(register)
	if err != nil || len(encoded) > tufMaxHighWaterBytes {
		return newTUFError(TUFReasonStateCorrupt, "high-water register could not be encoded within bounds")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return newTUFError(TUFReasonStateCorrupt, "high-water state root could not be created")
	}
	if err := atomicWriteFile(s.registerPath(), encoded, 0o600); err != nil {
		return newTUFError(TUFReasonStateCorrupt, "high-water register could not be persisted atomically")
	}
	info, err := os.Lstat(s.registerPath())
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return newTUFError(TUFReasonStateCorrupt, "persisted high-water register is not a 0600 regular file")
	}
	return nil
}

// cloneFeedGenerationStateForRollback copies the mutable last-known-good
// projection so a failed high-water commit can restore exactly the previous
// generation instead of publishing an unauthenticated advancement.
func cloneFeedGenerationStateForRollback(state *FeedGenerationState) *FeedGenerationState {
	if state == nil {
		return nil
	}
	cloned := *state
	cloned.LastGoodItems = append([]string(nil), state.LastGoodItems...)
	return &cloned
}

// snapshotLastKnownGoodLocked deep-copies every feed's mutable LKG fields. The
// caller holds m.mu.
func (m *FeedManager) snapshotLastKnownGoodLocked() map[string]*FeedGenerationState {
	snapshot := make(map[string]*FeedGenerationState, len(m.feedStates))
	for id, state := range m.feedStates {
		snapshot[id] = cloneFeedGenerationStateForRollback(state)
	}
	return snapshot
}

// restoreLastKnownGoodLocked restores the pre-sync LKG projection. The caller
// holds m.mu. A feed that did not exist before the sync is reset to its empty
// generation instead of keeping a promotion that was part of the failed commit.
func (m *FeedManager) restoreLastKnownGoodLocked(snapshot map[string]*FeedGenerationState) {
	if snapshot == nil {
		return
	}
	for id, state := range m.feedStates {
		previous, known := snapshot[id]
		if !known || previous == nil {
			state.LastGoodItems = nil
			state.LastGoodCount = 0
			state.LastGoodGen = 0
			state.LastGoodAt = time.Time{}
			state.LastError = ""
			state.ConsecutiveFails = 0
			state.Status = ""
			state.LastGoodFingerprint = ""
			state.ManifestVersion = 0
			state.ManifestValidUntil = time.Time{}
			state.ManifestVerified = false
			state.ManifestAuthenticity = ""
			continue
		}
		state.LastGoodItems = append([]string(nil), previous.LastGoodItems...)
		state.LastGoodCount = previous.LastGoodCount
		state.LastGoodGen = previous.LastGoodGen
		state.LastGoodAt = previous.LastGoodAt
		state.LastError = previous.LastError
		state.ConsecutiveFails = previous.ConsecutiveFails
		state.Status = previous.Status
		state.LastGoodFingerprint = previous.LastGoodFingerprint
		state.ManifestVersion = previous.ManifestVersion
		state.ManifestValidUntil = previous.ManifestValidUntil
		state.ManifestVerified = previous.ManifestVerified
		state.ManifestAuthenticity = previous.ManifestAuthenticity
	}
}
