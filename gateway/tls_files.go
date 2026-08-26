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
	"syscall"
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
	if !secureTLSKeyMode(keyPath, keyInfo) {
		return errors.New("TLS key must be private or a root-owned systemd credential")
	}
	return nil
}

func secureTLSKeyMode(keyPath string, keyInfo os.FileInfo) bool {
	if keyInfo.Mode().Perm()&0o077 == 0 {
		return true
	}
	credentialDir := filepath.Clean(os.Getenv("CREDENTIALS_DIRECTORY"))
	if credentialDir == "." || !filepath.IsAbs(credentialDir) ||
		filepath.Clean(keyPath) != filepath.Join(credentialDir, "tls-key") ||
		keyInfo.Mode().Perm() != 0o440 {
		return false
	}
	keyStat, keyOK := keyInfo.Sys().(*syscall.Stat_t)
	if !keyOK || keyStat.Uid != 0 || keyStat.Gid != 0 {
		return false
	}
	dirInfo, err := os.Lstat(credentialDir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 ||
		dirInfo.Mode().Perm()&0o022 != 0 {
		return false
	}
	dirStat, dirOK := dirInfo.Sys().(*syscall.Stat_t)
	return dirOK && dirStat.Uid == 0 && dirStat.Gid == 0
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
		IsCA:                  false,
	}
	// The universal desktop application terminates exclusively at loopback,
	// while remote operators use the configured public identity. Both names
	// therefore belong to the same local leaf certificate.
	templateCert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	templateCert.DNSNames = []string{"localhost"}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			templateCert.IPAddresses = append(templateCert.IPAddresses, ip)
		}
	} else if host != "localhost" {
		templateCert.DNSNames = append(templateCert.DNSNames, host)
	}
	priv, err := ecdsaP384GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificate(
		rand.Reader, &templateCert, &templateCert, &priv.PublicKey, priv,
	)
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
