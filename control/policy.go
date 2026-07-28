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
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const policyDocumentVersion = 1

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
}

type PolicyStore struct {
	mu         sync.Mutex
	cfg        PolicyConfig
	crypto     *StorageCipher
	nodeName   string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	generation uint64
	status     PolicyStatus
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
	return &PolicyStore{cfg: cfg, crypto: storage, nodeName: nodeName, privateKey: priv, publicKey: pub, status: PolicyStatus{Verified: true, Signer: finger}}, nil
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

func (p *PolicyStore) Load() (envelope PolicyEnvelope, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	defer func() {
		if err != nil {
			p.status = PolicyStatus{
				Verified: false,
				Signer:   p.status.Signer,
				Error:    "policy load failed",
			}
		}
	}()
	b, err := readBoundedPrivateFile(p.cfg.StateFile, 64<<20)
	if errors.Is(err, os.ErrNotExist) {
		p.status = PolicyStatus{Verified: true, Generation: 0, Signer: p.status.Signer}
		return PolicyEnvelope{Version: policyDocumentVersion}, nil
	}
	if err != nil {
		return PolicyEnvelope{}, err
	}
	legacy := false
	if p.crypto != nil {
		b, legacy, err = p.crypto.Decrypt(p.cfg.StateFile, "policy-state", b, nil)
		if err != nil {
			return PolicyEnvelope{}, fmt.Errorf("policy decrypt: %w", err)
		}
	}
	doc, err := decodePolicyDocument(b)
	if err != nil {
		return PolicyEnvelope{}, err
	}
	payload, err := canonicalPolicy(doc.Envelope)
	if err != nil {
		return PolicyEnvelope{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(doc.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(p.publicKey, payload, sig) {
		p.status = PolicyStatus{Verified: false, Error: "signature verification failed", Signer: p.status.Signer}
		if p.cfg.RequireSigned {
			return PolicyEnvelope{}, errors.New("policy signature verification failed")
		}
		return PolicyEnvelope{Version: policyDocumentVersion}, nil
	}
	p.generation = doc.Envelope.Generation
	u := doc.Envelope.UpdatedAt.UTC()
	p.status = PolicyStatus{Verified: true, Generation: p.generation, UpdatedAt: &u, Signer: p.status.Signer}
	if legacy && p.crypto != nil {
		if err := p.writeDocument(doc); err != nil {
			return PolicyEnvelope{}, fmt.Errorf("policy encryption migration: %w", err)
		}
	}
	return doc.Envelope, nil
}

func (p *PolicyStore) writeDocument(doc PolicyDocument) error {
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if p.crypto != nil {
		encoded, err = p.crypto.Encrypt(p.cfg.StateFile, "policy-state", 0, encoded)
		if err != nil {
			return err
		}
		encoded = append(encoded, '\n')
	}
	return atomicWriteFile(p.cfg.StateFile, encoded, 0o600)
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
	envelope := PolicyEnvelope{
		Version: policyDocumentVersion, Generation: p.generation + 1, NodeName: nodeName,
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
	u := now
	p.status = PolicyStatus{Verified: true, Generation: p.generation, UpdatedAt: &u, Signer: p.status.Signer}
	return nil
}

func (p *PolicyStore) Status() PolicyStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}
