package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
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

	// geoIPIntegritySchema is the canonical signed sidecar contract shared with
	// scripts/update-geoip-db.py: canonical compact JSON, sorted keys, ASCII,
	// no trailing newline. geoip.csv.sig is the Base64 Ed25519 signature over
	// the exact bytes of that sidecar document.
	geoIPIntegritySchema = "vgt.gedefense.geoip-integrity.v1"
)

// geoIPIntegrityDocument mirrors the producer's canonical JSON sidecar. The
// field order below is the sorted key order the producer emits, so
// encoding/json reproduces exactly the bytes the Ed25519 signature covers.
type geoIPIntegrityDocument struct {
	File   string `json:"file"`
	Schema string `json:"schema"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

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

type geoV4Entry struct {
	addr    uint32
	metaIdx uint32
}

type geoV6Entry struct {
	addr    [16]byte
	metaIdx uint32
}

type GeoResolver struct {
	updateKeys  []ed25519.PublicKey
	mu          sync.RWMutex
	meta        []GeoRecord
	v4          [33][]geoV4Entry
	v6          [129][]geoV6Entry
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
// geoip.csv.sig: Base64 Ed25519 over the exact bytes of the canonical
// geoip.csv.sha256 JSON sidecar (which binds the dataset by SHA-256 and size).
// When the signature file exists without configured keys the load fails closed
// instead of silently ignoring it.
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
	if err := r.verifyGeoIPCIntegrity(f, path, info.Size()); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("geoip database rewind: %w", err)
	}

	reader := csv.NewReader(io.LimitReader(f, maxGeoIPCSVBytes+1))
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true
	var v4 [33][]geoV4Entry
	var v6 [129][]geoV6Entry
	lengths4 := make(map[int]struct{})
	lengths6 := make(map[int]struct{})
	strIntern := make(map[string]string, 16384)
	intern := func(s string) string {
		if s == "" {
			return ""
		}
		if cached, ok := strIntern[s]; ok {
			return cached
		}
		cloned := strings.Clone(s)
		strIntern[cloned] = cloned
		return cloned
	}
	metaMap := make(map[GeoRecord]uint32, 65536)
	var meta []GeoRecord
	addMeta := func(g GeoRecord) uint32 {
		if idx, ok := metaMap[g]; ok {
			return idx
		}
		idx := uint32(len(meta))
		metaMap[g] = idx
		meta = append(meta, g)
		return idx
	}
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
		geo := GeoRecord{
			CountryCode: intern(code),
			Country:     intern(country),
			Latitude:    lat,
			Longitude:   lon,
		}
		if len(record) > 5 {
			asn := strings.TrimSpace(record[5])
			if len(asn) > 32 {
				asn = truncateUTF8Bytes(asn, 32)
			}
			geo.ASN = intern(asn)
		}
		if len(record) > 6 {
			asName := strings.TrimSpace(record[6])
			if len(asName) > 128 {
				asName = truncateUTF8Bytes(asName, 128)
			}
			geo.ASName = intern(asName)
		}
		metaIdx := addMeta(geo)
		bits := prefix.Bits()
		addr := prefix.Addr()
		if addr.Is4() && bits >= 0 && bits <= 32 {
			b4 := addr.As4()
			v4[bits] = append(v4[bits], geoV4Entry{
				addr:    binary.BigEndian.Uint32(b4[:]),
				metaIdx: metaIdx,
			})
			lengths4[bits] = struct{}{}
		} else if bits >= 0 && bits <= 128 {
			v6[bits] = append(v6[bits], geoV6Entry{
				addr:    addr.As16(),
				metaIdx: metaIdx,
			})
			lengths6[bits] = struct{}{}
		}
		count++
	}
	v4Lens := sortedPrefixLengths(lengths4)
	v6Lens := sortedPrefixLengths(lengths6)
	for _, bits := range v4Lens {
		v4[bits] = sortAndDedupeGeoV4(v4[bits])
	}
	for _, bits := range v6Lens {
		v6[bits] = sortAndDedupeGeoV6(v6[bits])
	}
	compactMeta := make([]GeoRecord, len(meta))
	copy(compactMeta, meta)
	now := time.Now().UTC()

	modified := info.ModTime().UTC()
	r.mu.Lock()
	r.meta, r.v4, r.v6, r.v4Lens, r.v6Lens = compactMeta, v4, v6, v4Lens, v6Lens
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
func (r *GeoResolver) verifyGeoIPCIntegrity(file *os.File, path string, datasetSize int64) (err error) {
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
	expected, declaredSize, err := parseGeoIPIntegritySidecar(sidecar, path)
	if err != nil {
		return err
	}
	if declaredSize != 0 && declaredSize != datasetSize {
		return fmt.Errorf("geoip integrity sidecar declares %d bytes but the dataset has %d", declaredSize, datasetSize)
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

// parseGeoIPIntegritySidecar returns the expected SHA-256 of the dataset and,
// for the canonical JSON form, the declared dataset size (0 for the legacy
// form). Two formats are accepted:
//
//   - canonical JSON document (geoIPIntegritySchema) that binds `file`, the
//     SHA-256 and the exact byte size. The bytes must be byte-identical to
//     their own canonical serialization, because the Ed25519 signature covers
//     exactly these bytes. This is the contract implemented by
//     scripts/update-geoip-db.py;
//   - legacy sha256sum line (`<64-hex>  geoip.csv`), kept readable so already
//     installed datasets and unsigned deployments keep loading. New signed
//     updates always use the canonical JSON form.
func parseGeoIPIntegritySidecar(sidecar []byte, csvPath string) ([]byte, int64, error) {
	if len(bytes.TrimSpace(sidecar)) == 0 {
		return nil, 0, errors.New("invalid geoip SHA-256 sidecar")
	}
	if bytes.HasPrefix(bytes.TrimSpace(sidecar), []byte("{")) {
		var document geoIPIntegrityDocument
		decoder := json.NewDecoder(bytes.NewReader(sidecar))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&document); err != nil {
			return nil, 0, fmt.Errorf("invalid canonical geoip integrity sidecar: %w", err)
		}
		if document.Schema != geoIPIntegritySchema {
			return nil, 0, errors.New("geoip integrity sidecar schema mismatch")
		}
		if document.File != filepath.Base(csvPath) {
			return nil, 0, errors.New("geoip integrity sidecar binds a different dataset file")
		}
		expected, err := hex.DecodeString(document.SHA256)
		if err != nil || len(expected) != sha256.Size {
			return nil, 0, errors.New("invalid geoip SHA-256 sidecar")
		}
		if document.Size <= 0 || document.Size > maxGeoIPCSVBytes {
			return nil, 0, fmt.Errorf("geoip integrity sidecar size outside limit: %d", document.Size)
		}
		canonical, err := json.Marshal(document)
		if err != nil {
			return nil, 0, fmt.Errorf("geoip integrity sidecar canonicalization: %w", err)
		}
		if !bytes.Equal(canonical, sidecar) {
			return nil, 0, errors.New("geoip integrity sidecar is not canonical JSON: dataset rejected")
		}
		return expected, document.Size, nil
	}
	fields := strings.Fields(string(sidecar))
	if len(fields) == 0 || len(fields[0]) != 64 {
		return nil, 0, errors.New("invalid geoip SHA-256 sidecar")
	}
	expected, err := hex.DecodeString(fields[0])
	if err != nil || len(expected) != sha256.Size {
		return nil, 0, errors.New("invalid geoip SHA-256 sidecar")
	}
	return expected, 0, nil
}

func sortedPrefixLengths(in map[int]struct{}) []int {
	out := make([]int, 0, len(in))
	for bits := range in {
		out = append(out, bits)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

func sortAndDedupeGeoV4(entries []geoV4Entry) []geoV4Entry {
	if len(entries) <= 1 {
		return entries
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].addr < entries[j].addr
	})
	write := 0
	for i := 0; i < len(entries); i++ {
		if i+1 < len(entries) && entries[i+1].addr == entries[i].addr {
			continue
		}
		entries[write] = entries[i]
		write++
	}
	out := make([]geoV4Entry, write)
	copy(out, entries[:write])
	return out
}

func sortAndDedupeGeoV6(entries []geoV6Entry) []geoV6Entry {
	if len(entries) <= 1 {
		return entries
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].addr[:], entries[j].addr[:]) < 0
	})
	write := 0
	for i := 0; i < len(entries); i++ {
		if i+1 < len(entries) && entries[i+1].addr == entries[i].addr {
			continue
		}
		entries[write] = entries[i]
		write++
	}
	out := make([]geoV6Entry, write)
	copy(out, entries[:write])
	return out
}

func maskGeoV4(addr uint32, bits int) uint32 {
	if bits <= 0 {
		return 0
	}
	if bits >= 32 {
		return addr
	}
	return addr & (^uint32(0) << (32 - bits))
}

func maskGeoV6(addr [16]byte, bits int) [16]byte {
	if bits <= 0 {
		return [16]byte{}
	}
	if bits >= 128 {
		return addr
	}
	full := bits / 8
	rem := bits % 8
	for i := full + 1; i < 16; i++ {
		addr[i] = 0
	}
	if rem == 0 {
		addr[full] = 0
	} else {
		addr[full] &= ^byte(0xff >> rem)
	}
	return addr
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
	var result GeoRecord
	found := false
	if addr.Is4() {
		b4 := addr.As4()
		raw := binary.BigEndian.Uint32(b4[:])
		for _, bits := range r.v4Lens {
			if bits < 0 || bits > 32 {
				continue
			}
			key := maskGeoV4(raw, bits)
			table := r.v4[bits]
			idx := sort.Search(len(table), func(i int) bool {
				return table[i].addr >= key
			})
			if idx < len(table) && table[idx].addr == key {
				metaIdx := int(table[idx].metaIdx)
				if metaIdx >= 0 && metaIdx < len(r.meta) {
					result, found = r.meta[metaIdx], true
					break
				}
			}
		}
	} else {
		raw := addr.As16()
		for _, bits := range r.v6Lens {
			if bits < 0 || bits > 128 {
				continue
			}
			key := maskGeoV6(raw, bits)
			table := r.v6[bits]
			idx := sort.Search(len(table), func(i int) bool {
				return bytes.Compare(table[i].addr[:], key[:]) >= 0
			})
			if idx < len(table) && table[idx].addr == key {
				metaIdx := int(table[idx].metaIdx)
				if metaIdx >= 0 && metaIdx < len(r.meta) {
					result, found = r.meta[metaIdx], true
					break
				}
			}
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
