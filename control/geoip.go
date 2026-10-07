package main

import (
	"encoding/csv"
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
)

const (
	maxGeoIPCSVBytes = 128 << 20
	maxGeoIPEntries  = 1_000_000
	geoCacheCapacity = 4096
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
}

type geoCacheEntry struct {
	Record     GeoRecord
	Found      bool
	Generation uint64
}

type GeoResolver struct {
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
	r := &GeoResolver{status: GeoStatus{Path: path, CacheCapacity: geoCacheCapacity}, cache: make(map[netip.Addr]geoCacheEntry, geoCacheCapacity)}
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
				return fmt.Errorf("geoip CSV row %d ASN too long", row)
			}
		}
		if len(record) > 6 {
			geo.ASName = strings.TrimSpace(record[6])
			if len(geo.ASName) > 128 {
				return fmt.Errorf("geoip CSV row %d AS name too long", row)
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
	r.status = GeoStatus{Loaded: true, Path: path, Entries: count, LoadedAt: &now, SourceModifiedAt: &modified, CacheCapacity: geoCacheCapacity}
	r.generation.Add(1)
	r.mu.Unlock()
	r.cacheMu.Lock()
	r.cache = make(map[netip.Addr]geoCacheEntry, geoCacheCapacity)
	r.cacheKeys = [geoCacheCapacity]netip.Addr{}
	r.cacheCursor = 0
	r.cacheMu.Unlock()
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
