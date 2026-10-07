package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func writeGeoFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geoip.csv")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
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
