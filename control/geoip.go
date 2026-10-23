package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	maxGeoIPCSVBytes       = 128 << 20
	maxGeoIPEntries        = 1_000_000
	geoCacheCapacity       = 4096
	maxGeoIPSidecarBytes   = 512
	maxGeoIPSignatureBytes = 8 << 10
)

var geoSpecialUsePrefixes = mustGeoPrefixes(
	// IPv4 special-use / non-public source space. Keep this deliberately
	// conservative: operator geography must prefer "unknown" over a false pin.
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
	// IPv6 unspecified/loopback/link-local/ULA/documentation/multicast and
	// IPv4 translation/documentation ranges that are not useful as attacker
	// geography.
	"::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001:2::/48",
	"2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
)

func mustGeoPrefixes(raw ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic("invalid built-in GeoIP exclusion prefix: " + value)
		}
		out = append(out, prefix.Masked())
	}
	return out
}

func isPublicGeoAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range geoSpecialUsePrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// GeoRecord is intentionally coarse. GeDefense displays approximate network
// origin for operator context, not a claim about a person's physical location.
type GeoRecord struct {
	CountryCode string  `json:"country_code,omitempty"`
	Country     string  `json:"country,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	ASN         string  `json:"asn,omitempty"`
	ASName      string  `json:"as_name,omitempty"`
}

type GeoStatus struct {
	Loaded           bool       `json:"loaded"`
	Path             string     `json:"path,omitempty"`
	Entries          int        `json:"entries"`
	LoadedAt         *time.Time `json:"loaded_at,omitempty"`
	SourceModifiedAt *time.Time `json:"source_modified_at,omitempty"`
	CacheEntries     int        `json:"cache_entries"`
	CacheCapacity    int        `json:"cache_capacity"`
	LastError        string     `json:"last_error,omitempty"`
	// Integrity projection (F-24): the loader only reports Loaded=true when the
	// shipped SHA-256 sidecar verified against the exact bytes that were parsed.
	SidecarVerified bool `json:"sidecar_verified"`
	UpdateSigned    bool `json:"update_signed"`
}

type geoCacheEntry struct {
	Record     GeoRecord
	Found      bool
	Generation uint64
}

type GeoResolver struct {
	updateKeys  []ed25519.PublicKey
	mu          sync.RWMutex
	v4          map[int]map[netip.Addr]GeoRecord
	v6          map[int]map[netip.Addr]GeoRecord
	v4Lens      []int
	v6Lens      []int
	status      GeoStatus
	cacheMu     sync.RWMutex
	cache       map[netip.Addr]geoCacheEntry
	cacheKeys   [geoCacheCapacity]netip.Addr
	cacheCursor int
	generation  atomic.Uint64
}

func NewGeoResolver(path string) *GeoResolver {
	return NewGeoResolverWithTrust(path, nil)
}

// NewGeoResolverWithTrust optionally pins Ed25519 keys for the signed GeoIP
// update gate. When keys are configured the loader requires a detached
// geoip.csv.sig over the sidecar bytes; when the signature file exists without
// configured keys the load fails closed instead of silently ignoring it.
func NewGeoResolverWithTrust(path string, updateSigningKeys []string) *GeoResolver {
	keys := make([]ed25519.PublicKey, 0, len(updateSigningKeys))
	for _, raw := range updateSigningKeys {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
		}
		if err == nil && len(decoded) == ed25519.PublicKeySize {
			keys = append(keys, ed25519.PublicKey(decoded))
		}
	}
	r := &GeoResolver{updateKeys: keys, status: GeoStatus{Path: path, CacheCapacity: geoCacheCapacity}, cache: make(map[netip.Addr]geoCacheEntry, geoCacheCapacity)}
	if strings.TrimSpace(path) == "" {
		r.status.LastError = "GeoIP database not configured"
		return r
	}
	if err := r.Load(path); err != nil {
		r.status.LastError = err.Error()
	}
	return r
}

// Load consumes the local compact CSV format documented in docs/kinetic/geoip.md:
// network,country_code,country_name,latitude,longitude,asn,as_name
func (r *GeoResolver) Load(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("geoip database: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("geoip database must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > maxGeoIPCSVBytes {
		return fmt.Errorf("geoip database size outside limit: %d bytes", info.Size())
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// F-24 / CHAIN-009: verify the shipped SHA-256 sidecar over the exact bytes
	// that will be parsed. A missing or mismatching sidecar leaves the resolver
	// unavailable (Loaded=false) instead of presenting unverified data.
	if err := r.verifyGeoIPCIntegrity(f, path); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("geoip database rewind: %w", err)
	}

	reader := csv.NewReader(io.LimitReader(f, maxGeoIPCSVBytes+1))
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true
	v4 := make(map[int]map[netip.Addr]GeoRecord)
	v6 := make(map[int]map[netip.Addr]GeoRecord)
	lengths4 := make(map[int]struct{})
	lengths6 := make(map[int]struct{})
	count := 0
	row := 0
	for {
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return fmt.Errorf("geoip CSV row %d: %w", row+1, readErr)
		}
		row++
		if len(record) == 0 {
			continue
		}
		if row == 1 && strings.EqualFold(strings.TrimSpace(record[0]), "network") {
			continue
		}
		if len(record) < 5 {
			return fmt.Errorf("geoip CSV row %d requires at least 5 columns", row)
		}
		if count >= maxGeoIPEntries {
			return fmt.Errorf("geoip entry limit %d exceeded", maxGeoIPEntries)
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(record[0]))
		if err != nil {
			return fmt.Errorf("geoip CSV row %d invalid network: %w", row, err)
		}
		prefix = prefix.Masked()
		code := strings.ToUpper(strings.TrimSpace(record[1]))
		country := strings.TrimSpace(record[2])
		if len(code) != 2 || len(country) > 96 {
			return fmt.Errorf("geoip CSV row %d has invalid country metadata", row)
		}
		lat, err := strconv.ParseFloat(strings.TrimSpace(record[3]), 64)
		if err != nil || lat < -90 || lat > 90 {
			return fmt.Errorf("geoip CSV row %d has invalid latitude", row)
		}
		lon, err := strconv.ParseFloat(strings.TrimSpace(record[4]), 64)
		if err != nil || lon < -180 || lon > 180 {
			return fmt.Errorf("geoip CSV row %d has invalid longitude", row)
		}
		geo := GeoRecord{CountryCode: code, Country: country, Latitude: lat, Longitude: lon}
		if len(record) > 5 {
			geo.ASN = strings.TrimSpace(record[5])
			if len(geo.ASN) > 32 {
				geo.ASN = truncateUTF8Bytes(geo.ASN, 32)
			}
		}
		if len(record) > 6 {
			geo.ASName = strings.TrimSpace(record[6])
			if len(geo.ASName) > 128 {
				geo.ASName = truncateUTF8Bytes(geo.ASName, 128)
			}
		}
		bits := prefix.Bits()
		addr := prefix.Addr()
		if addr.Is4() {
			if v4[bits] == nil {
				v4[bits] = make(map[netip.Addr]GeoRecord)
			}
			v4[bits][addr] = geo
			lengths4[bits] = struct{}{}
		} else {
			if v6[bits] == nil {
				v6[bits] = make(map[netip.Addr]GeoRecord)
			}
			v6[bits][addr] = geo
			lengths6[bits] = struct{}{}
		}
		count++
	}
	v4Lens := sortedPrefixLengths(lengths4)
	v6Lens := sortedPrefixLengths(lengths6)
	now := time.Now().UTC()

	modified := info.ModTime().UTC()
	r.mu.Lock()
	r.v4, r.v6, r.v4Lens, r.v6Lens = v4, v6, v4Lens, v6Lens
	r.status = GeoStatus{Loaded: true, Path: path, Entries: count, LoadedAt: &now, SourceModifiedAt: &modified, CacheCapacity: geoCacheCapacity,
		SidecarVerified: true, UpdateSigned: len(r.updateKeys) > 0}
	r.generation.Add(1)
	r.mu.Unlock()
	r.cacheMu.Lock()
	r.cache = make(map[netip.Addr]geoCacheEntry, geoCacheCapacity)
	r.cacheKeys = [geoCacheCapacity]netip.Addr{}
	r.cacheCursor = 0
	r.cacheMu.Unlock()
	return nil
}

// verifyGeoIPCIntegrity authenticates the dataset against its sidecar and, if a
// detached update signature is present or pinned keys are configured, verifies
// the signed update gate.
func (r *GeoResolver) verifyGeoIPCIntegrity(file *os.File, path string) (err error) {
	sidecarPath := path + ".sha256"
	info, statErr := os.Lstat(sidecarPath)
	if statErr != nil {
		return fmt.Errorf("geoip integrity sidecar missing: %w", statErr)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxGeoIPSidecarBytes {
		return errors.New("geoip integrity sidecar must be a small regular non-symlink file")
	}
	sidecar, err := os.ReadFile(sidecarPath)
	if err != nil {
		return fmt.Errorf("geoip integrity sidecar read: %w", err)
	}
	fields := strings.Fields(string(sidecar))
	if len(fields) == 0 || len(fields[0]) != 64 {
		return errors.New("invalid geoip SHA-256 sidecar")
	}
	expected, err := hex.DecodeString(fields[0])
	if err != nil || len(expected) != sha256.Size {
		return errors.New("invalid geoip SHA-256 sidecar")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(file, maxGeoIPCSVBytes+1)); err != nil {
		return fmt.Errorf("geoip integrity hash: %w", err)
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), expected) != 1 {
		return errors.New("geoip SHA-256 sidecar mismatch: dataset rejected")
	}

	signaturePath := path + ".sig"
	signatureInfo, signatureErr := os.Lstat(signaturePath)
	signaturePresent := signatureErr == nil
	if signatureErr != nil && !errors.Is(signatureErr, os.ErrNotExist) {
		return fmt.Errorf("geoip update signature: %w", signatureErr)
	}
	if signaturePresent {
		if !signatureInfo.Mode().IsRegular() || signatureInfo.Mode()&os.ModeSymlink != 0 || signatureInfo.Size() <= 0 || signatureInfo.Size() > maxGeoIPSignatureBytes {
			return errors.New("geoip update signature must be a small regular non-symlink file")
		}
		if len(r.updateKeys) == 0 {
			return errors.New("geoip update signature is present but no pinned update key is configured")
		}
		rawSignature, readErr := os.ReadFile(signaturePath)
		if readErr != nil {
			return readErr
		}
		signature, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawSignature)))
		if decodeErr != nil {
			signature, decodeErr = base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(rawSignature)))
		}
		if decodeErr != nil || len(signature) != ed25519.SignatureSize {
			return errors.New("geoip update signature encoding rejected")
		}
		for _, key := range r.updateKeys {
			if ed25519.Verify(key, sidecar, signature) {
				return nil
			}
		}
		return errors.New("geoip update signature verification failed")
	}
	if len(r.updateKeys) > 0 {
		return errors.New("geoip pinned update keys are configured but geoip.csv.sig is missing")
	}
	return nil
}

func sortedPrefixLengths(in map[int]struct{}) []int {
	out := make([]int, 0, len(in))
	for bits := range in {
		out = append(out, bits)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

func (r *GeoResolver) Lookup(ip net.IP) (GeoRecord, bool) {
	if r == nil || ip == nil {
		return GeoRecord{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return GeoRecord{}, false
	}
	addr = addr.Unmap()
	if !isPublicGeoAddr(addr) {
		return GeoRecord{}, false
	}

	currentGeneration := r.generation.Load()
	r.cacheMu.RLock()
	cached, cachedOK := r.cache[addr]
	r.cacheMu.RUnlock()
	if cachedOK && cached.Generation == currentGeneration {
		return cached.Record, cached.Found
	}

	r.mu.RLock()
	var table map[int]map[netip.Addr]GeoRecord
	var lengths []int
	if addr.Is4() {
		table, lengths = r.v4, r.v4Lens
	} else {
		table, lengths = r.v6, r.v6Lens
	}
	var result GeoRecord
	found := false
	for _, bits := range lengths {
		key := netip.PrefixFrom(addr, bits).Masked().Addr()
		if geo, exists := table[bits][key]; exists {
			result, found = geo, true
			break
		}
	}
	lookupGeneration := r.generation.Load()
	r.mu.RUnlock()
	r.cacheStore(addr, geoCacheEntry{Record: result, Found: found, Generation: lookupGeneration})
	return result, found
}

func (r *GeoResolver) cacheStore(addr netip.Addr, entry geoCacheEntry) {
	if r == nil || !addr.IsValid() {
		return
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if r.cache == nil {
		r.cache = make(map[netip.Addr]geoCacheEntry, geoCacheCapacity)
	}
	if _, exists := r.cache[addr]; exists {
		r.cache[addr] = entry
		return
	}
	if len(r.cache) >= geoCacheCapacity {
		old := r.cacheKeys[r.cacheCursor]
		if old.IsValid() {
			delete(r.cache, old)
		}
	}
	r.cache[addr] = entry
	r.cacheKeys[r.cacheCursor] = addr
	r.cacheCursor = (r.cacheCursor + 1) % geoCacheCapacity
}

func (r *GeoResolver) Status() GeoStatus {
	if r == nil {
		return GeoStatus{CacheCapacity: geoCacheCapacity, LastError: "GeoIP resolver unavailable"}
	}
	r.mu.RLock()
	status := r.status
	r.mu.RUnlock()
	r.cacheMu.RLock()
	status.CacheEntries = len(r.cache)
	r.cacheMu.RUnlock()
	status.CacheCapacity = geoCacheCapacity
	return status
}

func truncateUTF8Bytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	b := []byte(s[:maxBytes])
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return strings.TrimSpace(string(b))
}
