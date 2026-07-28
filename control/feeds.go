package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type ThreatIndex struct {
	mu        sync.RWMutex
	v4        map[int]map[[4]byte]struct{}
	v6        map[int]map[[16]byte]struct{}
	v4Lengths []int
	v6Lengths []int
	count     int
}

func NewThreatIndex() *ThreatIndex {
	return &ThreatIndex{v4: make(map[int]map[[4]byte]struct{}), v6: make(map[int]map[[16]byte]struct{})}
}

func maskIPv4(ip [4]byte, prefix int) [4]byte {
	for bit := prefix; bit < 32; bit++ {
		byteIndex := bit / 8
		bitIndex := uint(7 - bit%8)
		ip[byteIndex] &^= 1 << bitIndex
	}
	return ip
}

func maskIPv6(ip [16]byte, prefix int) [16]byte {
	for bit := prefix; bit < 128; bit++ {
		byteIndex := bit / 8
		bitIndex := uint(7 - bit%8)
		ip[byteIndex] &^= 1 << bitIndex
	}
	return ip
}

func (t *ThreatIndex) Replace(items []string) {
	v4 := make(map[int]map[[4]byte]struct{})
	v6 := make(map[int]map[[16]byte]struct{})
	for _, raw := range items {
		ip, network, err := net.ParseCIDR(raw)
		if err != nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if ones < 0 {
			continue
		}
		if bits == 32 {
			four := ip.To4()
			if four == nil {
				continue
			}
			var key [4]byte
			copy(key[:], four)
			key = maskIPv4(key, ones)
			if v4[ones] == nil {
				v4[ones] = make(map[[4]byte]struct{})
			}
			v4[ones][key] = struct{}{}
			continue
		}
		if bits == 128 {
			sixteen := ip.To16()
			if sixteen == nil {
				continue
			}
			var key [16]byte
			copy(key[:], sixteen)
			key = maskIPv6(key, ones)
			if v6[ones] == nil {
				v6[ones] = make(map[[16]byte]struct{})
			}
			v6[ones][key] = struct{}{}
		}
	}
	v4Lengths := make([]int, 0, len(v4))
	v6Lengths := make([]int, 0, len(v6))
	count := 0
	for prefix, entries := range v4 {
		v4Lengths = append(v4Lengths, prefix)
		count += len(entries)
	}
	for prefix, entries := range v6 {
		v6Lengths = append(v6Lengths, prefix)
		count += len(entries)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(v4Lengths)))
	sort.Sort(sort.Reverse(sort.IntSlice(v6Lengths)))
	t.mu.Lock()
	t.v4, t.v6 = v4, v6
	t.v4Lengths, t.v6Lengths = v4Lengths, v6Lengths
	t.count = count
	t.mu.Unlock()
}

func (t *ThreatIndex) ContainsString(raw string) bool {
	ip := net.ParseIP(raw)
	if ip == nil {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if four := ip.To4(); four != nil {
		var address [4]byte
		copy(address[:], four)
		for _, prefix := range t.v4Lengths {
			if _, ok := t.v4[prefix][maskIPv4(address, prefix)]; ok {
				return true
			}
		}
		return false
	}
	sixteen := ip.To16()
	if sixteen == nil {
		return false
	}
	var address [16]byte
	copy(address[:], sixteen)
	for _, prefix := range t.v6Lengths {
		if _, ok := t.v6[prefix][maskIPv6(address, prefix)]; ok {
			return true
		}
	}
	return false
}

func (t *ThreatIndex) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.count
}

type FeedManager struct {
	cfg    FeedConfig
	client *http.Client
	index  *ThreatIndex
}

func NewFeedManager(cfg FeedConfig) *FeedManager {
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid feed dial address")
		}
		if port != "443" {
			return nil, errors.New("feed destination port refused")
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addresses) == 0 {
			return nil, errors.New("feed host resolution failed")
		}
		for _, resolved := range addresses {
			if forbiddenFeedIP(resolved.IP) {
				return nil, errors.New("feed host resolved to a forbidden network")
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
	}, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second, ForceAttemptHTTP2: true}
	return &FeedManager{cfg: cfg, index: NewThreatIndex(), client: &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 2 {
			return errors.New("too many redirects")
		}
		if len(via) > 0 && req.URL.Hostname() != via[0].URL.Hostname() {
			return errors.New("cross-host redirect refused")
		}
		if req.URL.Scheme != "https" {
			return errors.New("non-HTTPS redirect refused")
		}
		return nil
	}}}
}
func (m *FeedManager) Sync(ctx context.Context) ([]string, map[string]error) {
	type result struct {
		items []string
		url   string
		err   error
	}
	sem := make(chan struct{}, 3)
	out := make(chan result, len(m.cfg.Sources))
	var wg sync.WaitGroup
	for _, source := range m.cfg.Sources {
		source := source
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			items, err := m.fetch(ctx, source)
			out <- result{items: items, url: source, err: err}
		}()
	}
	wg.Wait()
	close(out)
	set := make(map[string]struct{})
	errs := make(map[string]error)
	for r := range out {
		if r.err != nil {
			errs[r.url] = r.err
			continue
		}
		for _, x := range r.items {
			if len(set) >= m.cfg.MaxEntries {
				break
			}
			set[x] = struct{}{}
		}
	}
	items := make([]string, 0, len(set))
	for x := range set {
		items = append(items, x)
	}
	m.index.Replace(items)
	return items, errs
}
func forbiddenFeedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func validateFeedSourceURL(source string) (*url.URL, error) {
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid HTTPS feed URL")
	}
	port := u.Port()
	if port != "" && port != "443" {
		return nil, errors.New("feed destination port refused")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return nil, errors.New("feed hostname is not public")
	}
	if ip := net.ParseIP(host); ip != nil && forbiddenFeedIP(ip) {
		return nil, errors.New("feed IP is not public")
	}
	return u, nil
}

func (m *FeedManager) fetch(ctx context.Context, source string) ([]string, error) {
	u, err := validateFeedSourceURL(source)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VGT-GeDefense/0.5 feed-fetcher")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	lr := io.LimitReader(resp.Body, m.cfg.MaxDownloadBytes+1)
	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 4096), 256*1024)
	set := make(map[string]struct{})
	var read int64
	for sc.Scan() {
		read += int64(len(sc.Bytes()) + 1)
		if read > m.cfg.MaxDownloadBytes {
			return nil, errors.New("feed exceeds size limit")
		}
		if x, ok := parseThreatLine(sc.Text()); ok {
			set[x] = struct{}{}
			if len(set) >= m.cfg.MaxEntries {
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	items := make([]string, 0, len(set))
	for x := range set {
		items = append(items, x)
	}
	return items, nil
}
func parseThreatLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return "", false
	}
	tok := strings.Fields(line)[0]
	tok = strings.TrimRight(tok, ";, ")
	ip, network, err := net.ParseCIDR(tok)
	if err != nil {
		ip = net.ParseIP(tok)
		if ip == nil {
			return "", false
		}
		if ip.To4() != nil {
			tok = ip.String() + "/32"
		} else {
			tok = ip.String() + "/128"
		}
		_, network, _ = net.ParseCIDR(tok)
	}
	if ip == nil {
		ip = network.IP
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
		return "", false
	}
	return network.String(), true
}
