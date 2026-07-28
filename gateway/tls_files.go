package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func validateTLSFiles(certPath, keyPath string) error {
	certInfo, err := os.Lstat(certPath)
	if err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	}
	keyInfo, err := os.Lstat(keyPath)
	if err != nil {
		return fmt.Errorf("TLS key: %w", err)
	}
	if !certInfo.Mode().IsRegular() || certInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("TLS certificate must be regular and non-symlink")
	}
	if !keyInfo.Mode().IsRegular() || keyInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("TLS key must be regular and non-symlink")
	}
	if certInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("TLS certificate must not be group/world writable")
	}
	if keyInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("TLS key must be 0600 or stricter")
	}
	return nil
}

func generateSelfSigned(publicHost, certPath, keyPath string) error {
	host, _, _ := net.SplitHostPort(publicHost)
	if host == "" {
		host = publicHost
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}
	templateCert := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"VisionGaia Technology"}},
		NotBefore:    time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		templateCert.IPAddresses = []net.IP{ip}
	} else {
		templateCert.DNSNames = []string{host}
	}
	pub, priv, err := generateEd25519()
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificate(rand.Reader, &templateCert, &templateCert, pub, priv)
	if err != nil {
		return err
	}
	certPEM := pemEncode("CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	keyPEM := pemEncode("PRIVATE KEY", keyDER)
	if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		return err
	}
	if err := writeAtomic(certPath, certPEM, 0o644); err != nil {
		return err
	}
	return writeAtomic(keyPath, keyPEM, 0o600)
}

func generateEd25519() (any, any, error) {
	pub, priv, err := ed25519GenerateKey(rand.Reader)
	return pub, priv, err
}

func pemEncode(kind string, der []byte) []byte { return pemEncodeBlock(kind, der) }

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".gedefense-atomic-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
