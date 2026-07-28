package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type BaselineProfile struct {
	Executable         string   `json:"executable"`
	SHA256             string   `json:"sha256,omitempty"`
	AllowedUIDs        []uint32 `json:"allowed_uids,omitempty"`
	AllowedParents     []string `json:"allowed_parents,omitempty"`
	AllowExternal      bool     `json:"allow_external_network"`
	AllowedRemotePorts []uint16 `json:"allowed_remote_ports,omitempty"`
	AllowedRemoteCIDRs []string `json:"allowed_remote_cidrs,omitempty"`
}

type XDRBaseline struct {
	Version  int               `json:"version"`
	Profiles []BaselineProfile `json:"profiles"`
	compiled map[string]compiledBaseline
}

func resolveBaselinePath(path string) string {
	clean := filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(clean)
	if err == nil && filepath.IsAbs(resolved) {
		return filepath.Clean(resolved)
	}
	return clean
}

type compiledBaseline struct {
	profile BaselineProfile
	parents map[string]struct{}
	ports   map[uint16]struct{}
	nets    []*net.IPNet
}

func LoadXDRBaseline(path string) (*XDRBaseline, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("baseline exceeds 1 MiB")
	}
	var bl XDRBaseline
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bl); err != nil {
		return nil, err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("baseline contains trailing data")
	}
	if bl.Version != 1 {
		return nil, errors.New("unsupported baseline version")
	}
	bl.compiled = make(map[string]compiledBaseline)
	for _, p := range bl.Profiles {
		exe := resolveBaselinePath(p.Executable)
		if !filepath.IsAbs(exe) {
			return nil, errors.New("baseline executable paths must be absolute")
		}
		c := compiledBaseline{profile: p, parents: map[string]struct{}{}, ports: map[uint16]struct{}{}}
		for _, parent := range p.AllowedParents {
			c.parents[resolveBaselinePath(parent)] = struct{}{}
		}
		for _, port := range p.AllowedRemotePorts {
			c.ports[port] = struct{}{}
		}
		for _, raw := range p.AllowedRemoteCIDRs {
			_, n, err := net.ParseCIDR(raw)
			if err != nil {
				return nil, errors.New("invalid allowed_remote_cidrs entry")
			}
			c.nets = append(c.nets, n)
		}
		bl.compiled[exe] = c
	}
	return &bl, nil
}

func (b *XDRBaseline) Evaluate(p ProcessSample, conns []NetConnection) []RuleMatch {
	if b == nil {
		return nil
	}
	exe := resolveBaselinePath(strings.TrimSuffix(p.Exe, " (deleted)"))
	c, ok := b.compiled[exe]
	if !ok {
		return nil
	}
	var out []RuleMatch
	if c.profile.SHA256 != "" {
		h, err := hashFile(exe)
		if err != nil || !strings.EqualFold(h, c.profile.SHA256) {
			out = append(out, RuleMatch{ID: "BASELINE.HASH_MISMATCH", Category: "integrity", Score: 120, Summary: "Executable digest differs from the approved baseline", KillEligible: true})
		}
	}
	if len(c.profile.AllowedUIDs) > 0 {
		allowed := false
		for _, uid := range c.profile.AllowedUIDs {
			allowed = allowed || uid == p.UID
		}
		if !allowed {
			out = append(out, RuleMatch{ID: "BASELINE.UID_MISMATCH", Category: "identity", Score: 55, Summary: "Process UID is outside its approved baseline"})
		}
	}
	if len(c.parents) > 0 {
		if _, ok := c.parents[resolveBaselinePath(strings.TrimSuffix(p.ParentExe, " (deleted)"))]; !ok {
			out = append(out, RuleMatch{ID: "BASELINE.PARENT_MISMATCH", Category: "lineage", Score: 50, Summary: "Parent executable is outside the approved baseline", KillEligible: true})
		}
	}
	if len(conns) > 0 && !c.profile.AllowExternal {
		out = append(out, RuleMatch{ID: "BASELINE.NETWORK_FORBIDDEN", Category: "network", Score: 80, Summary: "Process opened external network traffic although its baseline forbids it", KillEligible: true})
	}
	if c.profile.AllowExternal && (len(c.ports) > 0 || len(c.nets) > 0) {
		for _, conn := range conns {
			portOK := len(c.ports) == 0
			if !portOK {
				_, portOK = c.ports[conn.RemotePort]
			}
			netOK := len(c.nets) == 0
			ip := net.ParseIP(conn.RemoteIP)
			for _, n := range c.nets {
				if ip != nil && n.Contains(ip) {
					netOK = true
				}
			}
			if !portOK || !netOK {
				out = append(out, RuleMatch{ID: "BASELINE.NETWORK_DEVIATION", Category: "network", Score: 55, Summary: "Remote endpoint differs from the approved baseline", Remote: conn.RemoteIP})
				break
			}
		}
	}
	return out
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 64*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func baselineExecutables(b *XDRBaseline) []string {
	if b == nil {
		return nil
	}
	out := make([]string, 0, len(b.compiled))
	for p := range b.compiled {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
