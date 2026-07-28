package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const releaseManifestDomain = "VGT-GEDEFENSE-RELEASE-MANIFEST-V1\n"

type ReleaseArtifact struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type ReleaseManifestEnvelope struct {
	Schema     string                     `json:"schema"`
	Product    string                     `json:"product"`
	Version    string                     `json:"version"`
	Channel    string                     `json:"channel"`
	CreatedAt  time.Time                  `json:"created_at"`
	Toolchains map[string]string          `json:"toolchains"`
	Artifacts  map[string]ReleaseArtifact `json:"artifacts"`
}

type SignedReleaseManifest struct {
	Envelope  ReleaseManifestEnvelope `json:"envelope"`
	Signer    string                  `json:"signer"`
	Signature string                  `json:"signature"`
}

func canonicalReleaseManifest(envelope ReleaseManifestEnvelope) ([]byte, error) {
	return json.Marshal(envelope)
}

func releaseBuildTime() (time.Time, error) {
	raw := strings.TrimSpace(os.Getenv("SOURCE_DATE_EPOCH"))
	if raw == "" {
		return time.Time{}, errors.New("SOURCE_DATE_EPOCH is required for a reproducible signed release")
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}, errors.New("SOURCE_DATE_EPOCH must be a positive Unix timestamp")
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func fileSHA256(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", 0, errors.New("artifact must be a regular non-symlink file")
	}
	if info.Size() > 1<<30 {
		return "", 0, errors.New("artifact exceeds the one-gibibyte release boundary")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), info.Size(), nil
}

func buildReleaseEnvelope(dir string) (ReleaseManifestEnvelope, error) {
	created, err := releaseBuildTime()
	if err != nil {
		return ReleaseManifestEnvelope{}, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ReleaseManifestEnvelope{}, err
	}
	artifacts := make(map[string]ReleaseArtifact)
	for _, entry := range entries {
		name := entry.Name()
		if name == "release-manifest.signed.json" || name == "SHA256SUMS" || entry.IsDir() {
			continue
		}
		lowerName := strings.ToLower(name)
		if strings.HasSuffix(lowerName, ".key") || strings.Contains(lowerName, "private") || strings.Contains(lowerName, "ed25519") {
			return ReleaseManifestEnvelope{}, fmt.Errorf("secret-like file is forbidden in release artifacts: %s", name)
		}
		if filepath.Base(name) != name {
			return ReleaseManifestEnvelope{}, errors.New("invalid artifact name")
		}
		digest, size, err := fileSHA256(filepath.Join(dir, name))
		if err != nil {
			return ReleaseManifestEnvelope{}, fmt.Errorf("artifact %s: %w", name, err)
		}
		artifacts[name] = ReleaseArtifact{SHA256: digest, Size: size}
	}
	for _, required := range []string{"gedefense-control", "gedefense-core", "gedefense-ebpf", "sbom.spdx.json", "build-provenance.json"} {
		if _, ok := artifacts[required]; !ok {
			return ReleaseManifestEnvelope{}, fmt.Errorf("required release artifact missing: %s", required)
		}
	}
	return ReleaseManifestEnvelope{
		Schema: "vgt.gedefense.release.v1", Product: "VGT GeDefense", Version: version, Channel: "beta", CreatedAt: created,
		Toolchains: expectedReleaseToolchains(), Artifacts: artifacts,
	}, nil
}

func loadReleaseKeyPair(privatePath, publicPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privateRaw, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, nil, err
	}
	privateInfo, err := os.Lstat(privatePath)
	if err != nil || !privateInfo.Mode().IsRegular() || privateInfo.Mode()&os.ModeSymlink != 0 || privateInfo.Mode().Perm()&0o077 != 0 {
		return nil, nil, errors.New("release private key must be a non-symlink 0600 regular file")
	}
	publicInfo, err := os.Lstat(publicPath)
	if err != nil || !publicInfo.Mode().IsRegular() || publicInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("release public key must be a non-symlink regular file")
	}
	publicRaw, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, nil, err
	}
	if len(privateRaw) != ed25519.PrivateKeySize || len(publicRaw) != ed25519.PublicKeySize {
		return nil, nil, errors.New("invalid Ed25519 release key length")
	}
	privateKey := ed25519.PrivateKey(append([]byte(nil), privateRaw...))
	publicKey := ed25519.PublicKey(append([]byte(nil), publicRaw...))
	if !privateKey.Public().(ed25519.PublicKey).Equal(publicKey) {
		return nil, nil, errors.New("release private and public keys do not match")
	}
	return privateKey, publicKey, nil
}

func SignReleaseDirectory(dir, privatePath, publicPath, output string) error {
	envelope, err := buildReleaseEnvelope(dir)
	if err != nil {
		return err
	}
	privateKey, publicKey, err := loadReleaseKeyPair(privatePath, publicPath)
	if err != nil {
		return err
	}
	payload, err := canonicalReleaseManifest(envelope)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(privateKey, append([]byte(releaseManifestDomain), payload...))
	document := SignedReleaseManifest{
		Envelope: envelope, Signer: fmt.Sprintf("ed25519:%x", publicKey[:8]), Signature: base64.RawURLEncoding.EncodeToString(signature),
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(output, append(encoded, '\n'), 0o644)
}

func strictPublicReleaseKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("trusted release public key must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("trusted release public key must not be group/world writable")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid trusted release public key length")
	}
	return raw, nil
}

func strictManifestBytes(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("release manifest must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > 8<<20 {
		return nil, errors.New("release manifest size is outside the accepted boundary")
	}
	return os.ReadFile(path)
}

func expectedReleaseToolchains() map[string]string {
	return map[string]string{
		"go": "go1.23.2", "node": "v22.16.0", "rust": "1.97.1",
		"rust-ebpf": "nightly-2026-07-16", "bpf-linker": "0.10.3",
	}
}

func validateReleaseEnvelope(envelope ReleaseManifestEnvelope) error {
	if envelope.Schema != "vgt.gedefense.release.v1" || envelope.Product != "VGT GeDefense" || envelope.Channel != "beta" {
		return errors.New("unsupported release manifest")
	}
	if envelope.Version != version {
		return errors.New("release manifest version does not match this verifier")
	}
	if envelope.CreatedAt.IsZero() {
		return errors.New("release manifest timestamp is missing")
	}
	expectedToolchains := expectedReleaseToolchains()
	if len(envelope.Toolchains) != len(expectedToolchains) {
		return errors.New("release manifest toolchain set is incomplete")
	}
	for name, expected := range expectedToolchains {
		if envelope.Toolchains[name] != expected {
			return fmt.Errorf("release manifest toolchain mismatch: %s", name)
		}
	}
	for _, required := range []string{"gedefense-control", "gedefense-core", "gedefense-ebpf", "sbom.spdx.json", "build-provenance.json"} {
		if _, ok := envelope.Artifacts[required]; !ok {
			return fmt.Errorf("required release artifact missing: %s", required)
		}
	}
	return nil
}

func VerifyReleaseManifest(manifestPath, publicPath, artifactDir string) (SignedReleaseManifest, error) {
	manifestRaw, err := strictManifestBytes(manifestPath)
	if err != nil {
		return SignedReleaseManifest{}, err
	}
	publicRaw, err := strictPublicReleaseKey(publicPath)
	if err != nil {
		return SignedReleaseManifest{}, err
	}
	var document SignedReleaseManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return SignedReleaseManifest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return SignedReleaseManifest{}, errors.New("release manifest contains trailing data")
	}
	if err := validateReleaseEnvelope(document.Envelope); err != nil {
		return SignedReleaseManifest{}, err
	}
	expectedSigner := fmt.Sprintf("ed25519:%x", publicRaw[:8])
	if document.Signer != expectedSigner {
		return SignedReleaseManifest{}, errors.New("release manifest signer fingerprint mismatch")
	}
	payload, err := canonicalReleaseManifest(document.Envelope)
	if err != nil {
		return SignedReleaseManifest{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(document.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(publicRaw), append([]byte(releaseManifestDomain), payload...), signature) {
		return SignedReleaseManifest{}, errors.New("release manifest signature verification failed")
	}
	if artifactDir != "" {
		if err := verifyReleaseArtifacts(document.Envelope, artifactDir); err != nil {
			return SignedReleaseManifest{}, err
		}
	}
	return document, nil
}

func verifyReleaseArtifacts(envelope ReleaseManifestEnvelope, artifactDir string) error {
	names := make([]string, 0, len(envelope.Artifacts))
	for name := range envelope.Artifacts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if filepath.Base(name) != name {
			return errors.New("manifest contains an invalid artifact path")
		}
		digest, size, err := fileSHA256(filepath.Join(artifactDir, name))
		if err != nil {
			return fmt.Errorf("artifact %s: %w", name, err)
		}
		expected := envelope.Artifacts[name]
		if digest != expected.SHA256 || size != expected.Size {
			return fmt.Errorf("artifact integrity mismatch: %s", name)
		}
	}
	return nil
}
