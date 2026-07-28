package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const forensicsDocumentVersion = 1
const forensicsDomain = "VGT-GEDEFENSE-FORENSICS-V1\x00"

type ForensicsEnvelope struct {
	Version         int           `json:"version"`
	ExportedAt      time.Time     `json:"exported_at"`
	SoftwareVersion string        `json:"software_version"`
	NodeName        string        `json:"node_name"`
	NodeMode        string        `json:"node_mode"`
	Enforcement     string        `json:"enforcement"`
	Policy          PolicyStatus  `json:"policy"`
	XDR             XDRStatus     `json:"xdr"`
	Incidents       []XDRIncident `json:"incidents"`
	Events          []Event       `json:"events"`
	Blocks          []BlockEntry  `json:"blocks"`
}

type SignedForensicsDocument struct {
	Envelope  ForensicsEnvelope `json:"envelope"`
	Signer    string            `json:"signer"`
	PublicKey string            `json:"public_key"`
	Signature string            `json:"signature"`
}

func forensicsPayload(envelope ForensicsEnvelope) ([]byte, error) {
	if envelope.Version != forensicsDocumentVersion {
		return nil, errors.New("unsupported forensics document version")
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return append([]byte(forensicsDomain), payload...), nil
}

func (p *PolicyStore) SignForensics(snapshot Snapshot) (SignedForensicsDocument, error) {
	if p == nil {
		return SignedForensicsDocument{}, errors.New("forensics signer unavailable")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.privateKey) != ed25519.PrivateKeySize || len(p.publicKey) != ed25519.PublicKeySize {
		return SignedForensicsDocument{}, errors.New("forensics signer unavailable")
	}
	envelope := ForensicsEnvelope{
		Version: forensicsDocumentVersion, ExportedAt: time.Now().UTC(), SoftwareVersion: snapshot.Version,
		NodeName: snapshot.NodeName, NodeMode: snapshot.NodeMode, Enforcement: snapshot.Enforcement,
		Policy: snapshot.Policy, XDR: snapshot.XDR, Incidents: snapshot.Incidents, Events: snapshot.Events, Blocks: snapshot.Blocks,
	}
	payload, err := forensicsPayload(envelope)
	if err != nil {
		return SignedForensicsDocument{}, err
	}
	return SignedForensicsDocument{
		Envelope: envelope, Signer: p.status.Signer,
		PublicKey: base64.RawURLEncoding.EncodeToString(p.publicKey),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(p.privateKey, payload)),
	}, nil
}

func VerifyForensicsBytes(data []byte, trustedPublicKey []byte) (SignedForensicsDocument, error) {
	if len(trustedPublicKey) != ed25519.PublicKeySize {
		return SignedForensicsDocument{}, errors.New("trusted Ed25519 public key has invalid length")
	}
	var document SignedForensicsDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return SignedForensicsDocument{}, fmt.Errorf("forensics document: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return SignedForensicsDocument{}, errors.New("forensics document contains trailing JSON")
	}
	embedded, err := base64.RawURLEncoding.DecodeString(document.PublicKey)
	if err != nil || len(embedded) != ed25519.PublicKeySize {
		return SignedForensicsDocument{}, errors.New("embedded forensics public key is malformed")
	}
	if !bytes.Equal(embedded, trustedPublicKey) {
		return SignedForensicsDocument{}, errors.New("forensics signer does not match the trusted public key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(document.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return SignedForensicsDocument{}, errors.New("forensics signature is malformed")
	}
	payload, err := forensicsPayload(document.Envelope)
	if err != nil {
		return SignedForensicsDocument{}, err
	}
	if !ed25519.Verify(ed25519.PublicKey(trustedPublicKey), payload, signature) {
		return SignedForensicsDocument{}, errors.New("forensics signature verification failed")
	}
	return document, nil
}

func VerifyForensicsFile(documentPath, publicKeyPath string) (SignedForensicsDocument, error) {
	documentInfo, err := os.Lstat(documentPath)
	if err != nil {
		return SignedForensicsDocument{}, err
	}
	if !documentInfo.Mode().IsRegular() || documentInfo.Mode()&os.ModeSymlink != 0 || documentInfo.Size() <= 0 || documentInfo.Size() > 128<<20 {
		return SignedForensicsDocument{}, errors.New("forensics document must be a bounded regular non-symlink file")
	}
	publicInfo, err := os.Lstat(publicKeyPath)
	if err != nil {
		return SignedForensicsDocument{}, err
	}
	if !publicInfo.Mode().IsRegular() || publicInfo.Mode()&os.ModeSymlink != 0 || publicInfo.Mode().Perm()&0o022 != 0 {
		return SignedForensicsDocument{}, errors.New("trusted forensics public key must be a non-writable regular non-symlink file")
	}
	document, err := os.ReadFile(documentPath)
	if err != nil {
		return SignedForensicsDocument{}, err
	}
	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return SignedForensicsDocument{}, err
	}
	return VerifyForensicsBytes(document, publicKey)
}
