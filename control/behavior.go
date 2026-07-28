package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const behaviorDocumentVersion = 2

type runningStat struct {
	Samples uint64  `json:"samples"`
	Mean    float64 `json:"mean"`
	M2      float64 `json:"m2"`
}

func (s *runningStat) update(v float64) {
	s.Samples++
	delta := v - s.Mean
	s.Mean += delta / float64(s.Samples)
	s.M2 += delta * (v - s.Mean)
}

func (s runningStat) stddev() float64 {
	if s.Samples < 2 {
		return 0
	}
	return math.Sqrt(s.M2 / float64(s.Samples-1))
}

type behaviorProfile struct {
	Executable      string            `json:"executable"`
	ConnectionCount runningStat       `json:"connection_count"`
	UniqueRemotes   runningStat       `json:"unique_remotes"`
	RemotePorts     map[uint16]uint64 `json:"remote_ports"`
	LastSeen        time.Time         `json:"last_seen"`
	ExecTimestamps  []time.Time       `json:"-"`
}

type behaviorPayload struct {
	Version   int               `json:"version"`
	UpdatedAt time.Time         `json:"updated_at"`
	Profiles  []behaviorProfile `json:"profiles"`
}

type behaviorDocument struct {
	Payload behaviorPayload `json:"payload"`
	MAC     string          `json:"mac"`
}

type BehaviorSummary struct {
	Profiles            int        `json:"profiles"`
	WarmProfiles        int        `json:"warm_profiles"`
	MaxProfiles         int        `json:"max_profiles"`
	Saturated           bool       `json:"saturated"`
	DroppedObservations uint64     `json:"dropped_observations"`
	LastSaved           *time.Time `json:"last_saved,omitempty"`
	IntegrityOK         bool       `json:"integrity_ok"`
	Error               string     `json:"error,omitempty"`
}

type BehaviorModel struct {
	mu             sync.Mutex
	enabled        bool
	warmup         uint64
	zscore         float64
	minConnections int
	maxProfiles    int
	maxPorts       int
	dropped        uint64
	path           string
	key            []byte
	crypto         *StorageCipher
	profiles       map[string]*behaviorProfile
	lastSaved      *time.Time
	integrityErr   error
}

func NewBehaviorModel(cfg XDRConfig, nodeNames ...string) (*BehaviorModel, error) {
	m := &BehaviorModel{
		// The model stays initialized so the dashboard can enable or disable
		// learning live. RuntimeSettings is the authoritative activation gate.
		enabled: true, warmup: uint64(cfg.BehaviorWarmupSamples),
		zscore: float64(cfg.BehaviorZScoreMilli) / 1000.0, minConnections: cfg.BehaviorMinConnections,
		maxProfiles: cfg.BehaviorMaxProfiles, maxPorts: cfg.BehaviorMaxPorts,
		path: cfg.BehaviorProfileFile, profiles: make(map[string]*behaviorProfile),
	}
	if !m.enabled {
		return m, nil
	}
	if !filepath.IsAbs(m.path) {
		return nil, errors.New("behavior profile path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return nil, err
	}
	if err := rejectSymlink(m.path); err != nil {
		return nil, err
	}
	key, err := loadOrCreateBinaryKey(cfg.LogKeyFile)
	if err != nil {
		return nil, err
	}
	m.key = deriveHMACSubkey(key, "behavior-profiles-v2")
	nodeName := "unnamed-node"
	if len(nodeNames) > 0 && nodeNames[0] != "" {
		nodeName = nodeNames[0]
	}
	m.crypto, err = NewStorageCipher(cfg.StorageKeyFile, nodeName)
	if err != nil {
		return nil, err
	}
	if err := m.load(); err != nil {
		m.integrityErr = err
	}
	return m, nil
}

func behaviorKey(p ProcessSample) string {
	exe := filepath.Clean(strings.TrimSuffix(p.Exe, " (deleted)"))
	if exe == "." || exe == "" {
		exe = "comm:" + p.Comm
	}
	return exe
}

func (m *BehaviorModel) ObserveExec(p ProcessSample, now time.Time) []RuleMatch {
	if !m.enabled {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	profile := m.profileLocked(behaviorKey(p))
	if profile == nil {
		m.dropped++
		return nil
	}
	cutoff := now.Add(-time.Minute)
	kept := profile.ExecTimestamps[:0]
	for _, stamp := range profile.ExecTimestamps {
		if stamp.After(cutoff) {
			kept = append(kept, stamp)
		}
	}
	profile.ExecTimestamps = append(kept, now)
	if len(profile.ExecTimestamps) > 256 {
		profile.ExecTimestamps = append([]time.Time(nil), profile.ExecTimestamps[len(profile.ExecTimestamps)-256:]...)
	}
	profile.LastSeen = now.UTC()
	if len(profile.ExecTimestamps) >= 12 {
		return []RuleMatch{{ID: "XDR.ANOMALY.EXEC_BURST", Category: "behavior", Score: 45, Summary: "Executable start rate deviates sharply from its normal cadence"}}
	}
	return nil
}

func (m *BehaviorModel) ObserveNetwork(p ProcessSample, conns []NetConnection, now time.Time) []RuleMatch {
	if !m.enabled {
		return nil
	}
	unique := make(map[string]struct{}, len(conns))
	ports := make(map[uint16]struct{}, len(conns))
	for _, conn := range conns {
		unique[conn.RemoteIP] = struct{}{}
		ports[conn.RemotePort] = struct{}{}
	}
	count, uniqueCount := float64(len(conns)), float64(len(unique))
	m.mu.Lock()
	defer m.mu.Unlock()
	profile := m.profileLocked(behaviorKey(p))
	if profile == nil {
		m.dropped++
		return nil
	}
	var matches []RuleMatch
	if profile.ConnectionCount.Samples >= m.warmup {
		connStd := math.Max(profile.ConnectionCount.stddev(), 1.0)
		remoteStd := math.Max(profile.UniqueRemotes.stddev(), 1.0)
		connZ := (count - profile.ConnectionCount.Mean) / connStd
		remoteZ := (uniqueCount - profile.UniqueRemotes.Mean) / remoteStd
		if len(conns) >= m.minConnections && connZ >= m.zscore {
			matches = append(matches, RuleMatch{ID: "XDR.ANOMALY.CONNECTION_FANOUT", Category: "behavior", Score: 55, Summary: "External connection fan-out exceeds the learned process profile"})
		}
		if len(unique) >= m.minConnections/2 && remoteZ >= m.zscore {
			matches = append(matches, RuleMatch{ID: "XDR.ANOMALY.REMOTE_DIVERSITY", Category: "behavior", Score: 50, Summary: "Unique remote destination count exceeds the learned process profile"})
		}
		unseen := 0
		for port := range ports {
			if profile.RemotePorts[port] == 0 {
				unseen++
			}
		}
		if unseen >= 4 && len(ports) >= 6 {
			matches = append(matches, RuleMatch{ID: "XDR.ANOMALY.PORT_DIVERSITY", Category: "behavior", Score: 35, Summary: "Process contacted an unusual number of previously unseen remote ports"})
		}
	}
	profile.ConnectionCount.update(count)
	profile.UniqueRemotes.update(uniqueCount)
	for port := range ports {
		if _, exists := profile.RemotePorts[port]; !exists && len(profile.RemotePorts) >= m.maxPorts {
			m.dropped++
			continue
		}
		profile.RemotePorts[port]++
	}
	profile.LastSeen = now.UTC()
	return matches
}

func (m *BehaviorModel) profileLocked(key string) *behaviorProfile {
	if p := m.profiles[key]; p != nil {
		return p
	}
	if len(m.profiles) >= m.maxProfiles {
		return nil
	}
	p := &behaviorProfile{Executable: key, RemotePorts: make(map[uint16]uint64)}
	m.profiles[key] = p
	return p
}

func (m *BehaviorModel) Summary() BehaviorSummary {
	m.mu.Lock()
	defer m.mu.Unlock()
	warm := 0
	for _, p := range m.profiles {
		if p.ConnectionCount.Samples >= m.warmup {
			warm++
		}
	}
	s := BehaviorSummary{
		Profiles: len(m.profiles), WarmProfiles: warm, MaxProfiles: m.maxProfiles,
		Saturated: len(m.profiles) >= m.maxProfiles, DroppedObservations: m.dropped,
		LastSaved: m.lastSaved, IntegrityOK: m.integrityErr == nil,
	}
	if m.integrityErr != nil {
		s.Error = m.integrityErr.Error()
	}
	return s
}

func (m *BehaviorModel) Snapshot(limit int) []behaviorProfile {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]behaviorProfile, 0, len(m.profiles))
	for _, p := range m.profiles {
		copyProfile := *p
		copyProfile.ExecTimestamps = nil
		copyProfile.RemotePorts = make(map[uint16]uint64, len(p.RemotePorts))
		for port, n := range p.RemotePorts {
			copyProfile.RemotePorts[port] = n
		}
		out = append(out, copyProfile)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (m *BehaviorModel) Persist() error {
	if !m.enabled {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.persistLocked()
}

func (m *BehaviorModel) persistLocked() error {
	profiles := make([]behaviorProfile, 0, len(m.profiles))
	for _, p := range m.profiles {
		copyProfile := *p
		copyProfile.ExecTimestamps = nil
		profiles = append(profiles, copyProfile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Executable < profiles[j].Executable })
	payload := behaviorPayload{Version: behaviorDocumentVersion, UpdatedAt: time.Now().UTC(), Profiles: profiles}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte("VGT-GEDEFENSE-BEHAVIOR-V1\x00"))
	_, _ = mac.Write(canonical)
	doc := behaviorDocument{Payload: payload, MAC: base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if m.crypto != nil {
		encoded, err = m.crypto.Encrypt(m.path, "behavior-profiles", 0, encoded)
		if err != nil {
			return err
		}
		encoded = append(encoded, '\n')
	}
	if err := atomicWriteFile(m.path, encoded, 0o600); err != nil {
		return err
	}
	u := payload.UpdatedAt
	m.lastSaved = &u
	m.integrityErr = nil
	return nil
}

func (m *BehaviorModel) load() error {
	b, err := readBoundedPrivateFile(m.path, 64<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	legacy := false
	if m.crypto != nil {
		b, legacy, err = m.crypto.Decrypt(m.path, "behavior-profiles", b, nil)
		if err != nil {
			return err
		}
	}
	var doc behaviorDocument
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("behavior profile contains trailing data")
	}
	if doc.Payload.Version != behaviorDocumentVersion {
		return errors.New("unsupported behavior profile version")
	}
	canonical, err := json.Marshal(doc.Payload)
	if err != nil {
		return err
	}
	got, err := base64.RawURLEncoding.DecodeString(doc.MAC)
	if err != nil {
		return errors.New("behavior profile MAC is malformed")
	}
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte("VGT-GEDEFENSE-BEHAVIOR-V1\x00"))
	_, _ = mac.Write(canonical)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return errors.New("behavior profile authentication failed")
	}
	if len(doc.Payload.Profiles) > m.maxProfiles {
		return errors.New("behavior profile count exceeds configured capacity")
	}
	for i := range doc.Payload.Profiles {
		p := doc.Payload.Profiles[i]
		if p.Executable == "" || len(p.Executable) > 4096 ||
			p.ConnectionCount.Samples > 1_000_000_000 || p.UniqueRemotes.Samples > 1_000_000_000 ||
			p.ConnectionCount.M2 < 0 || p.UniqueRemotes.M2 < 0 {
			return errors.New("behavior profile contains invalid bounds")
		}
		if len(p.RemotePorts) > m.maxPorts {
			return errors.New("behavior profile remote-port set exceeds configured capacity")
		}
		if p.RemotePorts == nil {
			p.RemotePorts = make(map[uint16]uint64)
		}
		m.profiles[p.Executable] = &p
	}
	u := doc.Payload.UpdatedAt.UTC()
	m.lastSaved = &u
	if legacy && m.crypto != nil {
		if err := m.persistLocked(); err != nil {
			return err
		}
	}
	return nil
}
