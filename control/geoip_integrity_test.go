// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// F-24 / CHAIN-009: the GeoIP sidecar must be verified at load and a signed
// update gate must fail closed when keys are pinned.
func TestGeoIPLoadVerifiesSidecarAndFailsClosed(t *testing.T) {
	body := "network,country_code,country_name,latitude,longitude\n8.8.8.0/24,US,United States,37.751,-97.822\n"
	path := writeGeoFixture(t, body)
	resolver := NewGeoResolver(path)
	if !resolver.Status().Loaded || !resolver.Status().SidecarVerified {
		t.Fatalf("valid sidecar was not accepted: %+v", resolver.Status())
	}

	// A tampered dataset behind a stale sidecar must be unavailable.
	tampered := path + ".tampered"
	if err := os.WriteFile(tampered, []byte(body+"1.1.1.1,US,United States,0,0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tampered+".sha256", []byte(strings.Repeat("a", 64)+"  geoip.csv\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := NewGeoResolver(tampered); r.Status().Loaded {
		t.Fatalf("tampered GeoIP dataset was loaded despite a mismatching sidecar: %+v", r.Status())
	}

	// A missing sidecar is fail-closed, not silently tolerated.
	missing := path + ".missing"
	if err := os.WriteFile(missing, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := NewGeoResolver(missing); r.Status().Loaded || !strings.Contains(r.Status().LastError, "sidecar") {
		t.Fatalf("missing GeoIP sidecar did not fail closed: %+v", r.Status())
	}
}

func TestGeoIPSignedUpdateGate(t *testing.T) {
	body := "network,country_code,country_name,latitude,longitude\n8.8.8.0/24,US,United States,37.751,-97.822\n"
	path := writeGeoFixture(t, body)
	sidecar, err := os.ReadFile(path + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinned := []string{base64.StdEncoding.EncodeToString(publicKey)}
	signature := ed25519.Sign(privateKey, sidecar)
	if err := os.WriteFile(path+".sig", []byte(base64.StdEncoding.EncodeToString(signature)), 0o600); err != nil {
		t.Fatal(err)
	}
	if resolver := NewGeoResolverWithTrust(path, pinned); !resolver.Status().Loaded || !resolver.Status().UpdateSigned {
		t.Fatalf("valid signed GeoIP update was rejected: %+v", resolver.Status())
	}

	// A signature without a pinned key fails closed (never silently ignored).
	if resolver := NewGeoResolver(path); resolver.Status().Loaded {
		t.Fatalf("unpinned GeoIP update signature was silently ignored: %+v", resolver.Status())
	}

	// A pinned key without a signature fails closed.
	unsignedPath := writeGeoFixture(t, body)
	if resolver := NewGeoResolverWithTrust(unsignedPath, pinned); resolver.Status().Loaded {
		t.Fatalf("missing GeoIP update signature was accepted with pinned keys: %+v", resolver.Status())
	}

	// A corrupted signature fails closed.
	if err := os.WriteFile(path+".sig", []byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))), 0o600); err != nil {
		t.Fatal(err)
	}
	if resolver := NewGeoResolverWithTrust(path, pinned); resolver.Status().Loaded {
		t.Fatalf("invalid GeoIP update signature was accepted: %+v", resolver.Status())
	}
}

func TestGeoIPSidecarUsesParsedBytesOnly(t *testing.T) {
	body := "network,country_code,country_name,latitude,longitude\n8.8.8.0/24,US,United States,37.751,-97.822\n"
	path := writeGeoFixture(t, body)
	// Replace only the sidecar: the dataset must not be trusted.
	digest := sha256.Sum256([]byte("other dataset"))
	if err := os.WriteFile(path+".sha256", []byte(hex.EncodeToString(digest[:])+"  geoip.csv\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if resolver := NewGeoResolver(path); resolver.Status().Loaded {
		t.Fatal("dataset was loaded with a sidecar for different bytes")
	}
}
