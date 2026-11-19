// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/flowguard"
	"github.com/visiongaiatechnology/gedefense/control/internal/webposture"
)

const (
	overviewConnectionsDefaultPageSize = 10
	overviewConnectionsMaxPageSize     = 50
)

// OverviewConnectionItem is one correlated active local-app / website -> remote-peer connection.
type OverviewConnectionItem struct {
	ID          string `json:"id"`
	App         string `json:"app"`
	ServiceType string `json:"service_type"` // web | app
	Direction   string `json:"direction"`    // inbound | outbound | peer
	Protocol    string `json:"protocol"`
	LocalIP     string `json:"local_ip,omitempty"`
	LocalPort   uint16 `json:"local_port,omitempty"`
	RemoteIP    string `json:"remote_ip"`
	RemotePort  uint16 `json:"remote_port,omitempty"`
	Host        string `json:"host,omitempty"` // SNI / vhost
	ALPN        string `json:"alpn,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Country     string `json:"country,omitempty"`
	ASN         string `json:"asn,omitempty"`
	ASName      string `json:"as_name,omitempty"`
	RxBytes     uint64 `json:"rx_bytes"`
	TxBytes     uint64 `json:"tx_bytes"`
	Packets     uint64 `json:"packets"`
	State       string `json:"state"`
	Verdict     string `json:"verdict"` // active | blocked | throttled | flagged
	External    bool   `json:"external"`
	PID         int    `json:"pid,omitempty"`
	User        string `json:"user,omitempty"`
	Source      string `json:"source"` // kernel+geoip | tls-sensor | styx
}

// OverviewConnectionsSummary totals across all currently tracked connections before pagination.
type OverviewConnectionsSummary struct {
	Total     int `json:"total"`
	External  int `json:"external"`
	Web       int `json:"web"`
	Apps      int `json:"apps"`
	Blocked   int `json:"blocked"`
	Countries int `json:"countries"`
}

// OverviewConnectionsResponse backs GET /api/v1/overview/connections.
type OverviewConnectionsResponse struct {
	GeneratedAt time.Time                  `json:"generated_at"`
	Page        int                        `json:"page"`
	PageSize    int                        `json:"page_size"`
	Total       int                        `json:"total"`
	TotalPages  int                        `json:"total_pages"`
	Filter      string                     `json:"filter"`
	GeoLoaded   bool                       `json:"geo_loaded"`
	Summary     OverviewConnectionsSummary `json:"summary"`
	Items       []OverviewConnectionItem   `json:"items"`
}

type systemSocketRow struct {
	Proto      string
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	State      string
	UID        uint32
	User       string
	Inode      string
	PID        int
	Comm       string
}

type connectionsInput struct {
	Now        time.Time
	Page       int
	PageSize   int
	Filter     string
	Query      string
	Sockets    []systemSocketRow
	Servers    []webposture.Server
	TLSFlows   []flowguard.FlowEntry
	Handshakes []tlsSensorHandshakeView
	StyxFlows  []StyxBeaconFlowSnapshot
	BlockedIPs map[string]struct{}
	Geo        *GeoResolver
}

func (s *APIServer) overviewConnections(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := clampQueryInt(q.Get("page"), 1, 1, 10000)
	limit := clampQueryInt(q.Get("limit"), overviewConnectionsDefaultPageSize, 1, overviewConnectionsMaxPageSize)
	filter := strings.ToLower(strings.TrimSpace(q.Get("filter")))
	switch filter {
	case "web", "apps", "external", "all":
	default:
		filter = "all"
	}
	search := strings.ToLower(strings.TrimSpace(q.Get("q")))
	if len(search) > 120 {
		search = search[:120]
	}

	in := connectionsInput{
		Now:        time.Now().UTC(),
		Page:       page,
		PageSize:   limit,
		Filter:     filter,
		Query:      search,
		Sockets:    readSystemSockets(),
		BlockedIPs: make(map[string]struct{}),
		Geo:        s.geo,
	}
	if s.state != nil {
		for _, blk := range s.state.Snapshot().Blocks {
			target := strings.TrimSpace(blk.Target)
			if target != "" {
				in.BlockedIPs[target] = struct{}{}
			}
		}
	}
	if s.v61 != nil {
		if we := s.v61.webExposure; we != nil {
			in.Servers = we.Snapshot().Servers
		}
		if ts := s.v61.tlsSensor; ts != nil {
			ts.mu.Lock()
			table := ts.flows
			in.Handshakes = append([]tlsSensorHandshakeView(nil), ts.handshakes...)
			ts.mu.Unlock()
			if table != nil {
				in.TLSFlows, _ = table.Snapshot(flowguard.FlowListLimit)
			}
		}
	}
	if s.xdr != nil {
		in.StyxFlows = s.xdr.StyxBeaconSnapshot().Top
	}
	writeJSON(w, http.StatusOK, buildOverviewConnections(in))
}

func buildOverviewConnections(in connectionsInput) OverviewConnectionsResponse {
	if in.Page < 1 {
		in.Page = 1
	}
	if in.PageSize <= 0 || in.PageSize > overviewConnectionsMaxPageSize {
		in.PageSize = overviewConnectionsDefaultPageSize
	}

	portApp := buildPortServiceMap(in.Servers)
	peerSNI := make(map[string]tlsSensorHandshakeView)
	for i := len(in.Handshakes) - 1; i >= 0; i-- {
		hs := in.Handshakes[i]
		peer := normalizeHostIP(hs.Peer)
		if peer == "" {
			continue
		}
		if _, exists := peerSNI[peer]; !exists {
			peerSNI[peer] = hs
		}
	}

	type connEntry struct {
		item *OverviewConnectionItem
	}
	merged := make(map[string]*OverviewConnectionItem)
	order := make([]string, 0, 64)

	upsert := func(key string, candidate OverviewConnectionItem) {
		if cur, ok := merged[key]; ok {
			if candidate.RxBytes > cur.RxBytes {
				cur.RxBytes = candidate.RxBytes
			}
			if candidate.TxBytes > cur.TxBytes {
				cur.TxBytes = candidate.TxBytes
			}
			if candidate.Packets > cur.Packets {
				cur.Packets = candidate.Packets
			}
			if cur.Host == "" && candidate.Host != "" {
				cur.Host = candidate.Host
			}
			if cur.ALPN == "" && candidate.ALPN != "" {
				cur.ALPN = candidate.ALPN
			}
			if cur.PID == 0 && candidate.PID > 0 {
				cur.PID = candidate.PID
			}
			if cur.App == "" || cur.App == "system" {
				if candidate.App != "" {
					cur.App = candidate.App
				}
			}
			if cur.Verdict == "active" && candidate.Verdict != "" && candidate.Verdict != "active" {
				cur.Verdict = candidate.Verdict
			}
			return
		}
		copied := candidate
		merged[key] = &copied
		order = append(order, key)
	}

	// 1. Live kernel active sockets (/proc/net/* + WebExposure port mapping + UID).
	for _, sock := range in.Sockets {
		remoteIP := normalizeHostIP(sock.RemoteIP)
		if remoteIP == "" {
			continue
		}
		appName, svcType, dir := inferServiceIdentity(sock, portApp)
		hs := peerSNI[remoteIP]
		verdict := "active"
		if _, blk := in.BlockedIPs[remoteIP]; blk {
			verdict = "blocked"
		}
		proto := strings.ToUpper(sock.Proto)
		key := appName + "|" + proto + "|" + remoteIP + "|" + strconv.Itoa(int(sock.RemotePort)) + "|" + strconv.Itoa(int(sock.LocalPort))
		upsert(key, OverviewConnectionItem{
			ID:          key,
			App:         appName,
			ServiceType: svcType,
			Direction:   dir,
			Protocol:    proto,
			LocalIP:     sock.LocalIP,
			LocalPort:   sock.LocalPort,
			RemoteIP:    remoteIP,
			RemotePort:  sock.RemotePort,
			Host:        hs.SNI,
			ALPN:        strings.Join(hs.ALPN, ","),
			State:       sock.State,
			Verdict:     verdict,
			PID:         sock.PID,
			User:        sock.User,
			Source:      "kernel",
		})
	}

	// 2. TLS/ALPN tracked socket flows (adds real RX/TX bytes & packets + verdicts + SNI).
	for _, flow := range in.TLSFlows {
		remoteIP := normalizeHostIP(flow.Sample.Peer)
		if remoteIP == "" {
			continue
		}
		hs := peerSNI[remoteIP]
		appName := portApp[flow.Sample.Port]
		if appName == "" {
			appName = inferPortName(flow.Sample.Port)
		}
		verdict := flow.Verdict
		if verdict == "" || verdict == "normal" {
			verdict = "active"
		}
		if _, blk := in.BlockedIPs[remoteIP]; blk {
			verdict = "blocked"
		}
		key := appName + "|TCP|" + remoteIP + "|" + strconv.Itoa(int(flow.Sample.Port))
		// Try matching existing kernel inbound socket on same local port + remote IP.
		matched := false
		for k, existing := range merged {
			if existing.RemoteIP == remoteIP && existing.LocalPort == flow.Sample.Port {
				key = k
				matched = true
				break
			}
		}
		_ = matched
		upsert(key, OverviewConnectionItem{
			ID:          key,
			App:         appName,
			ServiceType: "web",
			Direction:   "inbound",
			Protocol:    "TCP/TLS",
			LocalPort:   flow.Sample.Port,
			RemoteIP:    remoteIP,
			Host:        hs.SNI,
			ALPN:        strings.Join(hs.ALPN, ","),
			RxBytes:     flow.Sample.RxBytes,
			TxBytes:     flow.Sample.TxBytes,
			Packets:     flow.Sample.SegsIn + flow.Sample.SegsOut,
			State:       "ESTABLISHED",
			Verdict:     verdict,
			Source:      "tls-sensor",
		})
	}

	// 3. StyX eBPF outbound process flows (process PID/comm -> remote IP:port + RX/TX).
	for _, sf := range in.StyxFlows {
		ip, port := splitRemoteAddr(sf.Remote)
		if ip == "" {
			continue
		}
		appName := strings.TrimSpace(sf.Comm)
		if appName == "" {
			appName = "process"
		}
		svcType := "app"
		if isWebComm(appName) {
			svcType = "web"
		}
		verdict := "active"
		if sf.Score >= 50 || len(sf.Signals) > 0 {
			verdict = "flagged"
		}
		if _, blk := in.BlockedIPs[ip]; blk {
			verdict = "blocked"
		}
		key := appName + "|OUT|" + ip + "|" + strconv.Itoa(int(port))
		upsert(key, OverviewConnectionItem{
			ID:          key,
			App:         appName,
			ServiceType: svcType,
			Direction:   "outbound",
			Protocol:    "TCP",
			RemoteIP:    ip,
			RemotePort:  port,
			RxBytes:     sf.RxBytes,
			TxBytes:     sf.TxBytes,
			State:       "ACTIVE",
			Verdict:     verdict,
			PID:         sf.PID,
			Source:      "styx",
		})
	}

	geoLoaded := in.Geo != nil && in.Geo.Status().Loaded
	countriesSeen := make(map[string]struct{})
	summary := OverviewConnectionsSummary{}
	all := make([]OverviewConnectionItem, 0, len(order))

	for _, key := range order {
		item := merged[key]
		ip := net.ParseIP(item.RemoteIP)
		if ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
			item.External = true
			if in.Geo != nil {
				if g, ok := in.Geo.Lookup(ip); ok {
					item.CountryCode = g.CountryCode
					item.Country = g.Country
					item.ASN = g.ASN
					item.ASName = g.ASName
					if g.CountryCode != "" {
						countriesSeen[g.CountryCode] = struct{}{}
					}
				}
			}
		} else {
			item.Country = "Lokal / Intern"
			item.CountryCode = "LO"
		}
		summary.Total++
		if item.External {
			summary.External++
		}
		if item.ServiceType == "web" {
			summary.Web++
		} else {
			summary.Apps++
		}
		if item.Verdict == "blocked" {
			summary.Blocked++
		}
		all = append(all, *item)
	}
	summary.Countries = len(countriesSeen)

	// Filter before sorting & paginating.
	filtered := make([]OverviewConnectionItem, 0, len(all))
	for _, item := range all {
		switch in.Filter {
		case "web":
			if item.ServiceType != "web" {
				continue
			}
		case "apps":
			if item.ServiceType != "app" {
				continue
			}
		case "external":
			if !item.External {
				continue
			}
		}
		if in.Query != "" {
			haystack := strings.ToLower(item.App + " " + item.Host + " " + item.RemoteIP + " " + item.Country + " " + item.ASName + " " + item.ASN + " " + item.User)
			if !strings.Contains(haystack, in.Query) {
				continue
			}
		}
		filtered = append(filtered, item)
	}

	sort.Slice(filtered, func(i, j int) bool {
		a, b := filtered[i], filtered[j]
		volA, volB := a.RxBytes+a.TxBytes, b.RxBytes+b.TxBytes
		if volA != volB {
			return volA > volB
		}
		if a.External != b.External {
			return a.External
		}
		actA := a.State == "ESTABLISHED" || a.State == "ACTIVE"
		actB := b.State == "ESTABLISHED" || b.State == "ACTIVE"
		if actA != actB {
			return actA
		}
		if a.ServiceType != b.ServiceType {
			return a.ServiceType == "web"
		}
		if a.RemoteIP != b.RemoteIP {
			return a.RemoteIP < b.RemoteIP
		}
		return a.RemotePort < b.RemotePort
	})

	total := len(filtered)
	totalPages := 1
	if total > 0 {
		totalPages = (total + in.PageSize - 1) / in.PageSize
	}
	page := in.Page
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * in.PageSize
	end := start + in.PageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	pageItems := filtered[start:end]

	return OverviewConnectionsResponse{
		GeneratedAt: in.Now,
		Page:        page,
		PageSize:    in.PageSize,
		Total:       total,
		TotalPages:  totalPages,
		Filter:      in.Filter,
		GeoLoaded:   geoLoaded,
		Summary:     summary,
		Items:       pageItems,
	}
}

func buildPortServiceMap(servers []webposture.Server) map[uint16]string {
	m := map[uint16]string{
		80:   "http-web",
		443:  "https-web",
		8080: "web-upstream",
		8188: "openlitespeed",
		8289: "apache-httpd",
		8290: "apache-https",
		8443: "tls-edge",
		9843: "gedefense-access",
		53:   "dns-resolver",
		22:   "sshd",
		25:   "smtp",
		587:  "submission",
		3306: "mysql",
	}
	for _, srv := range servers {
		name := strings.TrimSpace(srv.Comm)
		if name == "" {
			continue
		}
		for _, ep := range srv.Listen {
			_, portStr, err := net.SplitHostPort(strings.TrimSpace(ep))
			if err != nil {
				continue
			}
			if p, err := strconv.ParseUint(portStr, 10, 16); err == nil && p > 0 {
				m[uint16(p)] = name
			}
		}
	}
	return m
}

func inferPortName(port uint16) string {
	switch port {
	case 80, 443, 8443:
		return "nginx/web"
	case 22:
		return "sshd"
	case 53:
		return "dns"
	case 25, 465, 587:
		return "mail"
	default:
		return "port-" + strconv.Itoa(int(port))
	}
}

func inferServiceIdentity(sock systemSocketRow, portApp map[uint16]string) (app, svcType, direction string) {
	comm := strings.TrimSpace(sock.Comm)
	if comm != "" {
		app = comm
		if isWebComm(comm) || isWebPort(sock.LocalPort) {
			svcType = "web"
		} else {
			svcType = "app"
		}
	} else if known, ok := portApp[sock.LocalPort]; ok && sock.LocalPort > 0 && sock.LocalPort < 32768 {
		app = known
		if isWebPort(sock.LocalPort) || isWebComm(known) {
			svcType = "web"
		} else {
			svcType = "app"
		}
	} else if known, ok := portApp[sock.RemotePort]; ok {
		app = sock.User
		if app == "" {
			app = "client -> " + known
		} else {
			app = app + " -> " + known
		}
		svcType = "app"
		direction = "outbound"
		return app, svcType, direction
	} else {
		if sock.User != "" {
			app = sock.User + "-app"
		} else {
			app = "system-socket"
		}
		svcType = "app"
	}

	if direction == "" {
		if isWebPort(sock.LocalPort) || (sock.LocalPort > 0 && sock.LocalPort < 32768 && sock.RemotePort >= 1024) {
			direction = "inbound"
		} else {
			direction = "outbound"
		}
	}
	return app, svcType, direction
}

func isWebPort(p uint16) bool {
	switch p {
	case 80, 443, 8080, 8188, 8190, 8289, 8290, 8443, 888, 9843:
		return true
	default:
		return false
	}
}

func isWebComm(comm string) bool {
	l := strings.ToLower(strings.TrimSpace(comm))
	for _, needle := range []string{"nginx", "httpd", "apache", "litespeed", "openlitespeed", "php-fpm", "caddy", "haproxy", "webserver", "gedefense"} {
		if strings.Contains(l, needle) {
			return true
		}
	}
	return false
}

func splitRemoteAddr(raw string) (string, uint16) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0
	}
	if host, portStr, err := net.SplitHostPort(raw); err == nil {
		if ip := normalizeHostIP(host); ip != "" {
			p, _ := strconv.ParseUint(portStr, 10, 16)
			return ip, uint16(p)
		}
	}
	if ip := normalizeHostIP(raw); ip != "" {
		return ip, 0
	}
	return "", 0
}
