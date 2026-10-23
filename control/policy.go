package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const policyDocumentVersion = 1

// bootstrapPolicyGenerationFloor is the non-zero floor every node starts with. A
// generation-0 document is the in-memory "no state yet" value and is never accepted from
// disk; the first persisted document starts at generation 1. From then on the floor rises
// automatically whenever a document is persisted (F-07 / CHAIN-003).
const bootstrapPolicyGenerationFloor uint64 = 1

const policyFloorSchema = 1

// policyFloorDocument is the separate, authenticated anti-rollback anchor. It has to live
// outside the signed policy document: a replayed document carries its own (old) generation
// and could not prove that a newer one existed.
type policyFloorDocument struct {
	Schema            int       `json:"schema"`
	MinimumGeneration uint64    `json:"minimum_generation"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type PolicyEnvelope struct {
	Version     int          `json:"version"`
	Generation  uint64       `json:"generation"`
	NodeName    string       `json:"node_name"`
	Enforcement string       `json:"enforcement"`
	XDRMode     string       `json:"xdr_mode"`
	UpdatedAt   time.Time    `json:"updated_at"`
	Blocks      []BlockEntry `json:"blocks"`
}

type PolicyDocument struct {
	Envelope  PolicyEnvelope `json:"envelope"`
	Signature string         `json:"signature"`
}

type PolicyStatus struct {
	Verified   bool       `json:"verified"`
	Generation uint64     `json:"generation"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
	Signer     string     `json:"signer,omitempty"`
	Error      string     `json:"error,omitempty"`
	// MinimumGeneration is the active anti-rollback floor. It is raised automatically on
	// every persist and is exposed so an operator can see which generations are pinned.
	MinimumGeneration uint64 `json:"minimum_generation"`
}

type PolicyStore struct {
	mu         sync.Mutex
	cfg        PolicyConfig
	crypto     *StorageCipher
	nodeName   string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	generation uint64
	// floor is the monotonic anti-rollback generation floor. It is persisted next to the
	// policy state, raised on every successful persist and never lowered by settings.
	floor     uint64
	recovered bool
	status    PolicyStatus
	trust     PolicyTrustFabricSettings
}

func NewPolicyStore(cfg PolicyConfig, nodeNames ...string) (*PolicyStore, error) {
	for label, path := range map[string]string{
		"policy state":       cfg.StateFile,
		"policy private key": cfg.SigningKeyFile,
		"policy public key":  cfg.PublicKeyFile,
	} {
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("%s path must be absolute", label)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := rejectSymlink(path); err != nil {
			return nil, err
		}
	}
	nodeName := "unnamed-node"
	if len(nodeNames) > 0 && nodeNames[0] != "" {
		nodeName = nodeNames[0]
	}
	storage, err := NewStorageCipher(cfg.StorageKeyFile, nodeName)
	if err != nil {
		return nil, fmt.Errorf("policy encryption: %w", err)
	}
	pub, priv, err := loadOrCreatePolicyKey(cfg.SigningKeyFile, cfg.PublicKeyFile, storage)
	if err != nil {
		return nil, err
	}
	finger := fmt.Sprintf("ed25519:%x", pub[:8])
	// The compiled-in bootstrap value seeds the first Fabric revision; the Policy
	// Trust namespace is authoritative for every revision after it.
	trust := defaultPolicyTrustFabricSettings()
	trust.RequireSigned = cfg.RequireSigned
	return &PolicyStore{
		cfg: cfg, crypto: storage, nodeName: nodeName, privateKey: priv, publicKey: pub,
		floor:  bootstrapPolicyGenerationFloor,
		status: PolicyStatus{Verified: true, Signer: finger, MinimumGeneration: bootstrapPolicyGenerationFloor},
		trust:  trust,
	}, nil
}

func loadOrCreatePolicyKey(privatePath, publicPath string, storage *StorageCipher) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	privRaw, err := readBoundedPrivateFile(privatePath, 16<<10)
	if err == nil {
		legacy := false
		if storage != nil {
			privRaw, legacy, err = storage.Decrypt(privatePath, "policy-signing-key", privRaw, nil)
			if err != nil {
				return nil, nil, fmt.Errorf("policy private key decrypt: %w", err)
			}
		}
		if len(privRaw) != ed25519.PrivateKeySize {
			return nil, nil, errors.New("policy private key has invalid length")
		}
		priv := ed25519.PrivateKey(append([]byte(nil), privRaw...))
		pub := append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...)
		if err := verifyOrWritePublicKey(publicPath, pub); err != nil {
			return nil, nil, err
		}
		if legacy && storage != nil {
			encoded, encErr := storage.Encrypt(privatePath, "policy-signing-key", 0, priv)
			if encErr != nil {
				return nil, nil, encErr
			}
			if err := atomicWriteFile(privatePath, append(encoded, '\n'), 0o600); err != nil {
				return nil, nil, err
			}
		}
		return pub, priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privateData := []byte(priv)
	if storage != nil {
		privateData, err = storage.Encrypt(privatePath, "policy-signing-key", 0, privateData)
		if err != nil {
			return nil, nil, err
		}
		privateData = append(privateData, '\n')
	}
	if err := atomicWriteFile(privatePath, privateData, 0o600); err != nil {
		return nil, nil, err
	}
	if err := atomicWriteFile(publicPath, pub, 0o644); err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func verifyOrWritePublicKey(path string, expected ed25519.PublicKey) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return atomicWriteFile(path, expected, 0o644)
	}
	if err != nil {
		return err
	}
	if len(b) != ed25519.PublicKeySize || !ed25519.PublicKey(b).Equal(expected) {
		return errors.New("policy public key does not match the private key")
	}
	return nil
}

// atomicWriteFile writes a file through a staging file and an atomic replace.
//
// Scope of the symlink guarantee: the final component is protected. rejectSymlink
// refuses a link at the target name and O_EXCL refuses one at the staging name, so
// neither can be redirected. Directories above the target are resolved by the
// kernel at open time and are NOT covered here. That is acceptable for the stores
// this serves, whose paths are operator configuration inside directories the
// service owns, and it is not acceptable for a path a request can influence -
// those go through openBeneath, which resolves every component relative to an
// already-open descriptor.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func canonicalPolicy(envelope PolicyEnvelope) ([]byte, error) {
	envelope.Blocks = append([]BlockEntry(nil), envelope.Blocks...)
	sort.Slice(envelope.Blocks, func(i, j int) bool {
		if envelope.Blocks[i].Target == envelope.Blocks[j].Target {
			return envelope.Blocks[i].ID < envelope.Blocks[j].ID
		}
		return envelope.Blocks[i].Target < envelope.Blocks[j].Target
	})
	return json.Marshal(envelope)
}

func decodePolicyDocument(data []byte) (PolicyDocument, error) {
	var doc PolicyDocument
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return PolicyDocument{}, fmt.Errorf("policy document: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PolicyDocument{}, errors.New("policy document contains trailing data")
	}
	if doc.Envelope.Version != policyDocumentVersion {
		return PolicyDocument{}, errors.New("unsupported policy document version")
	}
	return doc, nil
}

// Load reads and verifies the signed policy state.
//
// Failure handling is fail-closed: an unreadable, corrupt or replayed document is reported as
// unverified instead of being silently replaced by an empty observe intent. If a verified
// last-known-good document exists it is used to recover the previous intent, so an attacker
// who can damage the current file cannot disarm the host on the next restart (F-07 /
// CHAIN-003). The generation floor is read from its own authenticated anchor and raised from
// the document that is actually loaded; a document below the floor is a replay and is
// refused.
func (p *PolicyStore) Load() (envelope PolicyEnvelope, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.recovered = false
	fail := func(message string) {
		p.status = PolicyStatus{Verified: false, Signer: p.status.Signer, Error: message, MinimumGeneration: p.floor}
	}
	persistedFloor, floorPresent, floorErr := p.readPersistedFloor()
	if floorErr != nil {
		fail("policy generation floor state is unreadable")
		return PolicyEnvelope{}, fmt.Errorf("policy generation floor: %w", floorErr)
	}
	p.raiseFloorLocked(persistedFloor)
	p.raiseFloorLocked(p.trust.MinimumGeneration)

	statePath := p.cfg.StateFile
	b, readErr := readBoundedPrivateFile(statePath, p.maxStateBytes())
	if errors.Is(readErr, os.ErrNotExist) {
		if recovered, ok := p.recoverFromLastKnownGoodLocked(); ok {
			return recovered, nil
		}
		// A persisted floor anchor proves that a policy existed on this node before. Its
		// absence is not a fresh install: treating it as one would clear the kernel on a
		// targeted state deletion (F-07 / CHAIN-003).
		if floorPresent || p.floor > bootstrapPolicyGenerationFloor {
			fail("policy state is missing above the persisted generation floor")
			return PolicyEnvelope{}, errors.New("policy state is missing but a generation floor is persisted")
		}
		// Genuinely fresh node: no policy has ever been persisted here.
		p.status = PolicyStatus{Verified: true, Generation: 0, Signer: p.status.Signer, MinimumGeneration: p.floor}
		return PolicyEnvelope{Version: policyDocumentVersion}, nil
	}
	if readErr != nil {
		if recovered, ok := p.recoverFromLastKnownGoodLocked(); ok {
			return recovered, nil
		}
		fail("policy state is unreadable")
		return PolicyEnvelope{}, readErr
	}
	doc, wasLegacy, decodeErr := p.decodeDocumentFrom(statePath, "policy-state", b)
	if decodeErr != nil {
		// A document that parses incorrectly is tamper evidence, not an availability
		// problem: it is reported as unverified and the startup retains the kernel state.
		// Only a missing or unreadable file is recovered from the last-known-good copy.
		fail("policy state could not be decoded")
		return PolicyEnvelope{}, decodeErr
	}
	payload, payloadErr := canonicalPolicy(doc.Envelope)
	if payloadErr != nil {
		fail("policy state could not be canonicalised")
		return PolicyEnvelope{}, payloadErr
	}
	sig, sigErr := base64.RawURLEncoding.DecodeString(doc.Signature)
	if sigErr != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(p.publicKey, payload, sig) {
		// A wrong signature is tamper evidence. It is never replaced by silently trusting a
		// recovery copy; the load fails closed and the startup retains enforcement.
		fail("signature verification failed")
		if p.requireSigned() {
			return PolicyEnvelope{}, errors.New("policy signature verification failed")
		}
		return PolicyEnvelope{Version: policyDocumentVersion}, nil
	}
	if doc.Envelope.Generation < p.floor {
		fail(fmt.Sprintf("policy generation %d is below the pinned minimum %d", doc.Envelope.Generation, p.floor))
		return PolicyEnvelope{}, fmt.Errorf("policy rollback detected: generation %d is below the pinned minimum %d", doc.Envelope.Generation, p.floor)
	}
	p.generation = doc.Envelope.Generation
	p.raiseFloorLocked(doc.Envelope.Generation)
	if raiseErr := p.persistFloorLocked(p.floor); raiseErr != nil {
		return PolicyEnvelope{}, fmt.Errorf("policy generation floor persistence: %w", raiseErr)
	}
	u := doc.Envelope.UpdatedAt.UTC()
	p.status = PolicyStatus{Verified: true, Generation: p.generation, UpdatedAt: &u, Signer: p.status.Signer, MinimumGeneration: p.floor}
	if wasLegacy {
		if err := p.writeDocument(doc); err != nil {
			return PolicyEnvelope{}, fmt.Errorf("policy encryption migration: %w", err)
		}
	}
	if err := p.writeLastKnownGoodLocked(doc); err != nil {
		// The current document is still authoritative; only the recovery copy could not be
		// refreshed. Keep going and let the next persist retry.
		log.Printf("policy last-known-good refresh failed: %v", err)
	}
	return doc.Envelope, nil
}

// LastLoadRecovered reports whether the most recent Load used the last-known-good document
// because the current file was missing or unverifiable.
func (p *PolicyStore) LastLoadRecovered() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.recovered
}

// recoverFromLastKnownGoodLocked falls back to the signed last-known-good copy and heals the
// current state file from it. The caller holds p.mu.
func (p *PolicyStore) recoverFromLastKnownGoodLocked() (PolicyEnvelope, bool) {
	doc, ok := p.loadLastKnownGoodLocked()
	if !ok || doc.Envelope.Generation < p.floor {
		return PolicyEnvelope{}, false
	}
	p.recovered = true
	p.generation = doc.Envelope.Generation
	p.raiseFloorLocked(doc.Envelope.Generation)
	if err := p.persistFloorLocked(p.floor); err != nil {
		log.Printf("policy generation floor persistence during recovery: %v", err)
	}
	u := doc.Envelope.UpdatedAt.UTC()
	p.status = PolicyStatus{Verified: true, Generation: p.generation, UpdatedAt: &u, Signer: p.status.Signer, MinimumGeneration: p.floor}
	if err := p.writeDocument(doc); err != nil {
		log.Printf("policy state healing from last-known-good failed: %v", err)
	}
	_ = p.writeLastKnownGoodLocked(doc)
	return doc.Envelope, true
}

// SignBytes signs an arbitrary canonical payload with the policy signing key. It
// exists so the settings export can be authenticated by the same trust anchor the
// policy document already uses instead of introducing a second key to manage.
func (p *PolicyStore) SignBytes(payload []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("settings signer unavailable")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("settings signer unavailable")
	}
	return ed25519.Sign(p.privateKey, payload), nil
}

// TrustedPublicKey returns a copy of the verification key.
func (p *PolicyStore) TrustedPublicKey() ed25519.PublicKey {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.publicKey) != ed25519.PublicKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), p.publicKey...)
}

// policyFloorPath and lastGoodPath are the two auxiliary anchors next to the signed
// document: the authenticated generation floor and the signed last-known-good copy.
func (p *PolicyStore) policyFloorPath() string { return p.cfg.StateFile + ".floor" }
func (p *PolicyStore) lastGoodPath() string    { return p.cfg.StateFile + ".lastgood" }

func (p *PolicyStore) raiseFloorLocked(floor uint64) {
	if floor > p.floor {
		p.floor = floor
	}
}

// readPersistedFloor reads the authenticated generation floor. The boolean reports whether
// an anchor exists at all: its presence proves that a policy was persisted on this node
// before, even when the generation is still 1. A corrupt anchor is an error, not a zero:
// silently ignoring it would let a replayed document through.
func (p *PolicyStore) readPersistedFloor() (uint64, bool, error) {
	path := p.policyFloorPath()
	data, err := readBoundedPrivateFile(path, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if p.crypto != nil {
		plain, _, decryptErr := p.crypto.Decrypt(path, "policy-generation-floor", data, nil)
		if decryptErr != nil {
			return 0, true, decryptErr
		}
		data = plain
	}
	var document policyFloorDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return 0, true, fmt.Errorf("policy generation floor: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return 0, true, errors.New("policy generation floor contains trailing data")
	}
	if document.Schema != policyFloorSchema {
		return 0, true, errors.New("unsupported policy generation floor schema")
	}
	return document.MinimumGeneration, true, nil
}

func (p *PolicyStore) persistFloorLocked(floor uint64) error {
	if floor < bootstrapPolicyGenerationFloor {
		floor = bootstrapPolicyGenerationFloor
	}
	data, err := json.Marshal(policyFloorDocument{
		Schema: policyFloorSchema, MinimumGeneration: floor, UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	path := p.policyFloorPath()
	if p.crypto != nil {
		data, err = p.crypto.Encrypt(path, "policy-generation-floor", 0, data)
		if err != nil {
			return err
		}
	}
	return atomicWriteFile(path, append(data, '\n'), 0o600)
}

// encodeDocumentFor renders a signed document for one store path. The encryption AAD binds
// the purpose and the path, so the last-known-good copy is encrypted under its own path.
func (p *PolicyStore) encodeDocumentFor(path, purpose string, doc PolicyDocument) ([]byte, error) {
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if p.crypto != nil {
		encoded, err = p.crypto.Encrypt(path, purpose, 0, encoded)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, '\n')
	}
	return encoded, nil
}

func (p *PolicyStore) decodeDocumentFrom(path, purpose string, data []byte) (PolicyDocument, bool, error) {
	legacy := false
	if p.crypto != nil {
		plain, wasLegacy, err := p.crypto.Decrypt(path, purpose, data, nil)
		if err != nil {
			return PolicyDocument{}, false, err
		}
		data = plain
		legacy = wasLegacy
	}
	doc, err := decodePolicyDocument(data)
	return doc, legacy, err
}

func (p *PolicyStore) writeDocument(doc PolicyDocument) error {
	encoded, err := p.encodeDocumentFor(p.cfg.StateFile, "policy-state", doc)
	if err != nil {
		return err
	}
	return atomicWriteFile(p.cfg.StateFile, encoded, 0o600)
}

func (p *PolicyStore) writeLastKnownGoodLocked(doc PolicyDocument) error {
	encoded, err := p.encodeDocumentFor(p.lastGoodPath(), "policy-state-lastgood", doc)
	if err != nil {
		return err
	}
	return atomicWriteFile(p.lastGoodPath(), encoded, 0o600)
}

func (p *PolicyStore) loadLastKnownGoodLocked() (PolicyDocument, bool) {
	path := p.lastGoodPath()
	data, err := readBoundedPrivateFile(path, p.maxStateBytes())
	if err != nil {
		return PolicyDocument{}, false
	}
	doc, _, err := p.decodeDocumentFrom(path, "policy-state-lastgood", data)
	if err != nil {
		return PolicyDocument{}, false
	}
	payload, err := canonicalPolicy(doc.Envelope)
	if err != nil {
		return PolicyDocument{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(doc.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(p.publicKey, payload, sig) {
		return PolicyDocument{}, false
	}
	return doc, true
}

func (p *PolicyStore) Persist(nodeName, enforcement, xdrMode string, blocks []BlockEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().UTC()
	active := make([]BlockEntry, 0, len(blocks))
	for _, block := range blocks {
		if block.ExpiresAt.After(now) {
			active = append(active, block)
		}
	}
	nextGeneration := p.generation + 1
	if nextGeneration < p.floor {
		// A persisted document is the authority on the generation; it may never be older
		// than the pinned floor, even if an in-memory state was restored from a backup.
		nextGeneration = p.floor + 1
	}
	envelope := PolicyEnvelope{
		Version: policyDocumentVersion, Generation: nextGeneration, NodeName: nodeName,
		Enforcement: enforcement, XDRMode: xdrMode, UpdatedAt: now, Blocks: active,
	}
	payload, err := canonicalPolicy(envelope)
	if err != nil {
		return err
	}
	doc := PolicyDocument{Envelope: envelope, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(p.privateKey, payload))}
	if err := p.writeDocument(doc); err != nil {
		return err
	}
	p.generation = envelope.Generation
	p.raiseFloorLocked(envelope.Generation)
	if err := p.persistFloorLocked(p.floor); err != nil {
		return fmt.Errorf("signed policy persisted but the generation floor could not be raised: %w", err)
	}
	if err := p.writeLastKnownGoodLocked(doc); err != nil {
		log.Printf("policy last-known-good persistence failed: %v", err)
	}
	u := now
	p.status = PolicyStatus{Verified: true, Generation: p.generation, UpdatedAt: &u, Signer: p.status.Signer, MinimumGeneration: p.floor}
	return nil
}

func (p *PolicyStore) Status() PolicyStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	status := p.status
	// The floor is always at least the compiled-in bootstrap value, even before the first
	// load has run.
	if status.MinimumGeneration < p.floor {
		status.MinimumGeneration = p.floor
	}
	if status.MinimumGeneration < bootstrapPolicyGenerationFloor {
		status.MinimumGeneration = bootstrapPolicyGenerationFloor
	}
	return status
}
