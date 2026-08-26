// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSelfSignedCreatesServerLeafCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "access.crt")
	keyPath := filepath.Join(dir, "access.key")
	if err := generateSelfSigned("127.0.0.1:9843", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("generated certificate is not PEM encoded")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.IsCA {
		t.Fatal("server leaf certificate must not be a certificate authority")
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P384() {
		t.Fatal("server leaf certificate must use ECDSA P-384")
	}
	if certificate.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Fatalf("server leaf certificate uses unexpected signature algorithm: %s", certificate.SignatureAlgorithm)
	}
	if err := certificate.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("server leaf certificate is not valid for loopback: %v", err)
	}
	if len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatal("server leaf certificate lacks exclusive server authentication usage")
	}
}

func TestGenerateSelfSignedBindsPublicAndLocalApplicationIdentities(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "access.crt")
	keyPath := filepath.Join(dir, "access.key")
	if err := generateSelfSigned("security.example.test:9843", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("generated certificate is not PEM encoded")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range []string{"security.example.test", "localhost", "127.0.0.1", "::1"} {
		if err := certificate.VerifyHostname(identity); err != nil {
			t.Fatalf("server leaf certificate is not valid for %s: %v", identity, err)
		}
	}
}

func TestValidateTLSFilesAcceptsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "access.crt")
	keyPath := filepath.Join(dir, "access.key")
	writeTLSFixture(t, certPath, 0o644)
	writeTLSFixture(t, keyPath, 0o600)
	if err := validateTLSFiles(certPath, keyPath); err != nil {
		t.Fatalf("private TLS key rejected: %v", err)
	}
}

func TestValidateTLSFilesRejectsOrdinaryGroupReadableKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "access.crt")
	keyPath := filepath.Join(dir, "access.key")
	writeTLSFixture(t, certPath, 0o644)
	writeTLSFixture(t, keyPath, 0o640)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if err := validateTLSFiles(certPath, keyPath); err == nil {
		t.Fatal("ordinary group-readable TLS key accepted")
	}
}

func TestSecureTLSKeyModeRejectsSpoofedCredentialDirectory(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tls-key")
	writeTLSFixture(t, keyPath, 0o440)
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	keyInfo, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if secureTLSKeyMode(keyPath, keyInfo) {
		t.Fatal("user-owned credential directory accepted")
	}
}

func TestSecureTLSKeyModeAcceptsRootOwnedSystemdCredential(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership fixture requires root")
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tls-key")
	writeTLSFixture(t, keyPath, 0o440)
	keyInfo, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if !secureTLSKeyMode(keyPath, keyInfo) {
		t.Fatal("root-owned systemd credential rejected")
	}
}

func writeTLSFixture(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("fixture"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
