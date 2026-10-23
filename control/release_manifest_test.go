package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestSignedReleaseManifestDetectsArtifactTampering(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dist")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gedefense-control", "gedefense-core", "gedefense-ebpf", "sbom.spdx.json", "build-provenance.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("artifact:"+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "release.key")
	publicPath := filepath.Join(root, "release.pub")
	if err := os.WriteFile(privatePath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, publicKey, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOURCE_DATE_EPOCH", "1784246400")
	manifest := filepath.Join(dir, "release-manifest.signed.json")
	if err := SignReleaseDirectory(dir, privatePath, publicPath, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReleaseManifest(manifest, publicPath, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gedefense-core"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReleaseManifest(manifest, publicPath, dir); err == nil {
		t.Fatal("tampered release artifact unexpectedly verified")
	}
}

func TestReleaseManifestRejectsTrailingDataAndWritableTrustKey(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dist")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gedefense-control", "gedefense-core", "gedefense-ebpf", "sbom.spdx.json", "build-provenance.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("artifact:"+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "release.key")
	publicPath := filepath.Join(root, "release.pub")
	if err := os.WriteFile(privatePath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, publicKey, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOURCE_DATE_EPOCH", "1784246400")
	manifest := filepath.Join(dir, "release-manifest.signed.json")
	if err := SignReleaseDirectory(dir, privatePath, publicPath, manifest); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(manifest, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReleaseManifest(manifest, publicPath, dir); err == nil {
		t.Fatal("release manifest with trailing JSON was accepted")
	}
	if err := os.Chmod(publicPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReleaseManifest(manifest, publicPath, dir); err == nil {
		t.Fatal("group/world-writable trusted public key was accepted")
	}
}
