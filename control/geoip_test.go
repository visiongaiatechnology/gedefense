package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeGeoFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geoip.csv")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(body))
	if err := os.WriteFile(path+".sha256", []byte(hex.EncodeToString(digest[:])+"  geoip.csv\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGeoResolverLocalLookupCacheAndStatus(t *testing.T) {
	path := writeGeoFixture(t, "network,country_code,country_name,latitude,longitude,asn,as_name\n8.8.8.0/24,US,United States,37.751,-97.822,AS15169,Google LLC\n2001:4860::/32,US,United States,37.751,-97.822,AS15169,Google LLC\n")
	r := NewGeoResolver(path)
	status := r.Status()
	if !status.Loaded || status.Entries != 2 || status.SourceModifiedAt == nil || status.CacheCapacity != geoCacheCapacity {
		t.Fatalf("unexpected initial geo status: %#v", status)
	}
	geo, ok := r.Lookup(net.ParseIP("8.8.8.8"))
	if !ok || geo.CountryCode != "US" || geo.ASN != "AS15169" {
		t.Fatalf("unexpected geo lookup: ok=%v geo=%#v", ok, geo)
	}
	if _, ok := r.Lookup(net.ParseIP("8.8.8.8")); !ok {
		t.Fatal("cached lookup unexpectedly failed")
	}
	status = r.Status()
	if status.CacheEntries != 1 {
		t.Fatalf("cache entries=%d want=1", status.CacheEntries)
	}
}

func TestGeoResolverRejectsNonPublicAddressesBeforeLookup(t *testing.T) {
	path := writeGeoFixture(t, "network,country_code,country_name,latitude,longitude\n0.0.0.0/0,US,United States,37.751,-97.822\n::/0,US,United States,37.751,-97.822\n")
	r := NewGeoResolver(path)
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "::1", "fe80::1", "ff02::1", "::"} {
		if geo, ok := r.Lookup(net.ParseIP(ip)); ok {
			t.Fatalf("non-public address %s was geolocated: %#v", ip, geo)
		}
	}
	if got := r.Status().CacheEntries; got != 0 {
		t.Fatalf("non-public lookups should not poison cache, got %d entries", got)
	}
}

func TestGeoResolverCacheIsStrictlyBounded(t *testing.T) {
	path := writeGeoFixture(t, "network,country_code,country_name,latitude,longitude\n8.0.0.0/8,US,United States,37.751,-97.822\n")
	r := NewGeoResolver(path)
	for i := 0; i < geoCacheCapacity+900; i++ {
		a := 1 + (i/(254*254))%253
		b := 1 + (i/254)%253
		c := 1 + i%253
		ip := net.ParseIP(fmt.Sprintf("8.%d.%d.%d", a, b, c))
		if _, ok := r.Lookup(ip); !ok {
			t.Fatalf("fixture lookup unexpectedly failed for %s", ip)
		}
	}
	status := r.Status()
	if status.CacheEntries > geoCacheCapacity {
		t.Fatalf("cache exceeded bound: %d > %d", status.CacheEntries, geoCacheCapacity)
	}
}

func TestGeoResolverSuccessfulReloadClearsCache(t *testing.T) {
	path := writeGeoFixture(t, "network,country_code,country_name,latitude,longitude\n8.8.8.0/24,US,United States,37.751,-97.822\n")
	r := NewGeoResolver(path)
	if _, ok := r.Lookup(net.ParseIP("8.8.8.8")); !ok {
		t.Fatal("initial lookup failed")
	}
	if r.Status().CacheEntries != 1 {
		t.Fatal("expected populated cache before reload")
	}
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	if got := r.Status().CacheEntries; got != 0 {
		t.Fatalf("cache not cleared after successful reload: %d", got)
	}
}

func TestGeoResolverRejectsSpecialUseDocumentationAndCGNAT(t *testing.T) {
	path := writeGeoFixture(t, "network,country_code,country_name,latitude,longitude\n0.0.0.0/0,US,United States,37.751,-97.822\n::/0,US,United States,37.751,-97.822\n")
	r := NewGeoResolver(path)
	for _, ip := range []string{
		"100.64.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "240.0.0.1",
		"2001:db8::1", "2001:2::1", "fc00::1",
	} {
		if geo, ok := r.Lookup(net.ParseIP(ip)); ok {
			t.Fatalf("special-use address %s was geolocated: %#v", ip, geo)
		}
	}
	if got := r.Status().CacheEntries; got != 0 {
		t.Fatalf("special-use lookups should not poison cache, got %d entries", got)
	}
}

func TestGeoResolverLongestPrefixWins(t *testing.T) {
	path := writeGeoFixture(t, "network,country_code,country_name,latitude,longitude,asn,as_name\n8.0.0.0/8,US,United States,37.751,-97.822,AS1,Broad\n8.8.8.0/24,DE,Germany,50.1109,8.6821,AS2,Specific\n")
	r := NewGeoResolver(path)
	geo, ok := r.Lookup(net.ParseIP("8.8.8.8"))
	if !ok || geo.CountryCode != "DE" || geo.ASN != "AS2" {
		t.Fatalf("longest-prefix lookup failed: ok=%v geo=%#v", ok, geo)
	}
	geo, ok = r.Lookup(net.ParseIP("8.1.1.1"))
	if !ok || geo.CountryCode != "US" || geo.ASN != "AS1" {
		t.Fatalf("broad-prefix fallback failed: ok=%v geo=%#v", ok, geo)
	}
}

func TestGeoResolverRejectsSymlinkDatabase(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real.csv")
	if err := os.WriteFile(realPath, []byte("network,country_code,country_name,latitude,longitude\n8.8.8.0/24,US,United States,37.751,-97.822\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "geoip.csv")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}
	r := NewGeoResolver(linkPath)
	status := r.Status()
	if status.Loaded || status.LastError == "" {
		t.Fatalf("symlink GeoIP database must fail closed: %#v", status)
	}
}

func TestGeoResolverRejectsOversizedDatabaseBeforeParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geoip.csv")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxGeoIPCSVBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r := NewGeoResolver(path)
	status := r.Status()
	if status.Loaded || status.LastError == "" {
		t.Fatalf("oversized GeoIP database must fail before parsing: %#v", status)
	}
}

// geoIPIntegrityInteropVector is the shared Python -> Go test vector for the
// canonical signed sidecar contract (FIND-006). The same file is consumed by
// scripts/tests/test_geoip_update_contract.py, so producer and consumer cannot
// drift apart silently.
type geoIPIntegrityInteropVector struct {
	CSV              string `json:"csv"`
	CSVName          string `json:"csv_name"`
	CSVSHA256        string `json:"csv_sha256"`
	CSVSize          int64  `json:"csv_size"`
	SidecarCanonical string `json:"sidecar_canonical"`
	PublicKeyBase64  string `json:"public_key_base64"`
	SignatureBase64  string `json:"signature_base64"`
}

func readGeoIPIntegrityInteropVector(t *testing.T) geoIPIntegrityInteropVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "scripts", "tests", "geoip_integrity_vector.json"))
	if err != nil {
		t.Fatalf("read shared GeoIP interop vector: %v", err)
	}
	var vector geoIPIntegrityInteropVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("parse shared GeoIP interop vector: %v", err)
	}
	if vector.CSV == "" || vector.CSVName != "geoip.csv" || vector.SidecarCanonical == "" ||
		vector.PublicKeyBase64 == "" || vector.SignatureBase64 == "" || vector.CSVSize <= 0 {
		t.Fatal("shared GeoIP interop vector is incomplete")
	}
	return vector
}

// geoIPCanonicalSidecar serialises the canonical sidecar document exactly like
// the Python producer (sorted keys, compact ASCII, no trailing newline).
func geoIPCanonicalSidecar(t *testing.T, csvName, sha256Hex string, size int64) string {
	t.Helper()
	canonical, err := json.Marshal(geoIPIntegrityDocument{File: csvName, Schema: geoIPIntegritySchema, SHA256: sha256Hex, Size: size})
	if err != nil {
		t.Fatalf("marshal canonical sidecar: %v", err)
	}
	return string(canonical)
}

func writeGeoIPVectorFixture(t *testing.T, directory, csvBody, sidecar, signatureBase64 string) string {
	t.Helper()
	path := filepath.Join(directory, "geoip.csv")
	if err := os.WriteFile(path, []byte(csvBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sha256", []byte(sidecar), 0o600); err != nil {
		t.Fatal(err)
	}
	if signatureBase64 != "" {
		if err := os.WriteFile(path+".sig", []byte(signatureBase64+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// TestGeoIPCanonicalSidecarInteropVector proves that the Python producer's
// vector is accepted byte-for-byte by the Go consumer: canonical sidecar bytes,
// Base64 Ed25519 signature over those bytes, and the SHA-256/size binding.
func TestGeoIPCanonicalSidecarInteropVector(t *testing.T) {
	vector := readGeoIPIntegrityInteropVector(t)
	digest := sha256.Sum256([]byte(vector.CSV))
	if hex.EncodeToString(digest[:]) != vector.CSVSHA256 || int64(len(vector.CSV)) != vector.CSVSize {
		t.Fatal("shared interop vector CSV does not match its recorded SHA-256/size")
	}
	signature, err := base64.StdEncoding.DecodeString(vector.SignatureBase64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("shared interop vector signature is not valid Base64 Ed25519: %v", err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(vector.PublicKeyBase64)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("shared interop vector public key is invalid: %v", err)
	}
	// Independent interop proof: Go's crypto verifies the Python-produced bytes.
	if !ed25519.Verify(publicKey, []byte(vector.SidecarCanonical), signature) {
		t.Fatal("Python-produced signature does not verify over the canonical sidecar bytes in Go")
	}
	expected, declared, err := parseGeoIPIntegritySidecar([]byte(vector.SidecarCanonical), vector.CSVName)
	if err != nil || hex.EncodeToString(expected) != vector.CSVSHA256 || declared != vector.CSVSize {
		t.Fatalf("Go parser rejected the shared canonical sidecar: expected=%x declared=%d err=%v", expected, declared, err)
	}
	if geoIPCanonicalSidecar(t, vector.CSVName, vector.CSVSHA256, vector.CSVSize) != vector.SidecarCanonical {
		t.Fatal("Go canonical sidecar serialization differs from the Python producer bytes")
	}

	directory := t.TempDir()
	pinned := []string{vector.PublicKeyBase64}
	signedPath := writeGeoIPVectorFixture(t, directory, vector.CSV, vector.SidecarCanonical, vector.SignatureBase64)
	resolver := NewGeoResolverWithTrust(signedPath, pinned)
	status := resolver.Status()
	if !status.Loaded || !status.SidecarVerified || !status.UpdateSigned {
		t.Fatalf("signed canonical sidecar dataset was rejected: %+v", status)
	}
	if geo, ok := resolver.Lookup(net.ParseIP("8.8.8.8")); !ok || geo.CountryCode != "US" {
		t.Fatalf("signed canonical sidecar dataset lookup failed: ok=%v geo=%#v", ok, geo)
	}

	// The JSON sidecar is still an integrity sidecar, not automatically a signed
	// update: without pinned keys and without a .sig it loads as before.
	directory = t.TempDir()
	unsignedPath := writeGeoIPVectorFixture(t, directory, vector.CSV, vector.SidecarCanonical, "")
	if r := NewGeoResolver(unsignedPath); !r.Status().Loaded || !r.Status().SidecarVerified || r.Status().UpdateSigned {
		t.Fatalf("unsigned canonical sidecar dataset was rejected: %+v", r.Status())
	}
}

// TestGeoIPCanonicalSidecarTamperReplayRejected covers the negative cases: a
// modified dataset, a replayed signature/sidecar pair, a non-canonical sidecar
// and a wrong byte-size binding must all fail closed.
func TestGeoIPCanonicalSidecarTamperReplayRejected(t *testing.T) {
	vector := readGeoIPIntegrityInteropVector(t)
	pinned := []string{vector.PublicKeyBase64}

	// Tampered dataset behind the authentic sidecar/signature pair.
	directory := t.TempDir()
	tamperedPath := writeGeoIPVectorFixture(t, directory, vector.CSV+"1.1.1.1/32,US,United States,0.000,0.000,,\n", vector.SidecarCanonical, vector.SignatureBase64)
	if r := NewGeoResolverWithTrust(tamperedPath, pinned); r.Status().Loaded {
		t.Fatalf("tampered dataset was loaded with a stale signature: %+v", r.Status())
	}

	// Replay: an authentic sidecar/signature pair for dataset A must not
	// authenticate dataset B even when both are otherwise valid CSV.
	replayDirectory := t.TempDir()
	replayBody := "network,country_code,country_name,latitude,longitude\n9.9.9.0/24,DE,Germany,50.110,8.682\n"
	replayPath := writeGeoIPVectorFixture(t, replayDirectory, replayBody, vector.SidecarCanonical, vector.SignatureBase64)
	if r := NewGeoResolverWithTrust(replayPath, pinned); r.Status().Loaded {
		t.Fatalf("replayed sidecar/signature authenticated a different dataset: %+v", r.Status())
	}

	// Old Python contract bug: a signature over the raw CSV (not over the
	// canonical sidecar JSON) must never authenticate a signed deployment.
	directory = t.TempDir()
	rawCSVPath := writeGeoIPVectorFixture(t, directory, vector.CSV, vector.SidecarCanonical, "")
	rawCSVSignature := ed25519.Sign(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), []byte(vector.CSV))
	rawCSVPublic := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if err := os.WriteFile(rawCSVPath+".sig", []byte(base64.StdEncoding.EncodeToString(rawCSVSignature)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := NewGeoResolverWithTrust(rawCSVPath, []string{base64.StdEncoding.EncodeToString(rawCSVPublic)}); r.Status().Loaded {
		t.Fatalf("signature over the raw CSV was accepted instead of the canonical sidecar signature: %+v", r.Status())
	}

	// Non-canonical JSON sidecar (pretty printed) is rejected even with a
	// matching dataset, because the signature covers the canonical bytes only.
	directory = t.TempDir()
	pretty, err := json.MarshalIndent(geoIPIntegrityDocument{File: vector.CSVName, Schema: geoIPIntegritySchema, SHA256: vector.CSVSHA256, Size: vector.CSVSize}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	prettyPath := writeGeoIPVectorFixture(t, directory, vector.CSV, string(pretty), vector.SignatureBase64)
	if r := NewGeoResolverWithTrust(prettyPath, pinned); r.Status().Loaded || !strings.Contains(strings.ToLower(r.Status().LastError), "canonical") {
		t.Fatalf("non-canonical JSON sidecar was not rejected as non-canonical: %+v", r.Status())
	}

	// Declared size must match the dataset bytes.
	directory = t.TempDir()
	sizePath := writeGeoIPVectorFixture(t, directory, vector.CSV, geoIPCanonicalSidecar(t, vector.CSVName, vector.CSVSHA256, vector.CSVSize+1), "")
	if r := NewGeoResolver(sizePath); r.Status().Loaded || !strings.Contains(r.Status().LastError, "bytes") {
		t.Fatalf("sidecar byte-size mismatch was not rejected: %+v", r.Status())
	}

	// The sidecar must bind the dataset file name, not another file.
	directory = t.TempDir()
	filePath := writeGeoIPVectorFixture(t, directory, vector.CSV, geoIPCanonicalSidecar(t, "elsewhere.csv", vector.CSVSHA256, vector.CSVSize), "")
	if r := NewGeoResolver(filePath); r.Status().Loaded || !strings.Contains(r.Status().LastError, "file") {
		t.Fatalf("sidecar binding a different file name was not rejected: %+v", r.Status())
	}

	// The legacy sha256sum sidecar format stays readable for installed data.
	directory = t.TempDir()
	legacyPath := writeGeoIPVectorFixture(t, directory, vector.CSV, vector.CSVSHA256+"  geoip.csv\n", "")
	if r := NewGeoResolver(legacyPath); !r.Status().Loaded {
		t.Fatalf("legacy sha256sum sidecar was rejected: %+v", r.Status())
	}
}
