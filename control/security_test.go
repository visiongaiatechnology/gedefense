package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestDashboardTokenIsStrictPrivate256BitMaterial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dashboard.token")
	token, err := loadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		t.Fatalf("generated token is not 256-bit base64url: bytes=%d err=%v", len(raw), err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("token mode=%#o want=0600", st.Mode().Perm())
	}
	loaded, err := loadOrCreateToken(path)
	if err != nil || loaded != token {
		t.Fatalf("token reload failed: equal=%v err=%v", loaded == token, err)
	}
}

func TestSecretFilesRejectSymlinkAndPermissiveModes(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real.key")
	if err := os.WriteFile(realPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "link.key")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateBinaryKey(linkPath); err == nil {
		t.Fatal("binary key symlink was accepted")
	}
	if _, err := loadOrCreateToken(linkPath); err == nil {
		t.Fatal("dashboard token symlink was accepted")
	}

	permissiveKey := filepath.Join(dir, "permissive.key")
	if err := os.WriteFile(permissiveKey, make([]byte, 32), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateBinaryKey(permissiveKey); err == nil {
		t.Fatal("group-readable binary key was accepted")
	}

	permissiveToken := filepath.Join(dir, "permissive.token")
	encoded := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if err := os.WriteFile(permissiveToken, []byte(encoded+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateToken(permissiveToken); err == nil {
		t.Fatal("world-readable dashboard token was accepted")
	}
}

func TestTokenComparisonUsesFixedLengthDigests(t *testing.T) {
	if !tokenEqual("operator-secret", "operator-secret") {
		t.Fatal("equal tokens were rejected")
	}
	if tokenEqual("operator-secret", "operator-secret-x") || tokenEqual("", "operator-secret") {
		t.Fatal("different tokens were accepted")
	}
}
