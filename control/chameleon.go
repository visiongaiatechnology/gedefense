// V6.3.0 AP-8: opt-in Chameleon Identity Mode (control-plane half).
//
// Chameleon is an installation property, not a runtime mutation: when the
// installer created a signed manifest, the control plane reads it once at
// startup and applies the neutral socket paths/ports/state roots before any
// listener or client is constructed. With no manifest (the default) the public
// GeDefense identity is used unchanged. The manifest is a bounded strict
// key=value document; invalid manifests are fatal at startup (an operator who
// opted in must never silently get the public identity).
//
// Manifest schema token: "vgt-gedefense-chameleon-v1". The format and every
// validator mirror `rust/gedefense-core/src/chameleon.rs`; a manifest that one
// side accepts and the other refuses is an installation defect, so both sides
// are deliberately strict about the same rules.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	// chameleonDefaultCoreSocket / ScanSocket / BpfPinRoot are the documented
	// public identity. They are only used while the profile is inactive.
	chameleonDefaultCoreSocket = "/run/vgt-gedefense/core.sock"
	chameleonDefaultScanSocket = "/run/gedefense-scan/scan.sock"
	chameleonDefaultBpfPinRoot = "/sys/fs/bpf/gedefense"
	// chameleonAuditCommitmentDomain separates the mapping commitment hash from
	// every other SHA-256 use in the control plane.
	chameleonAuditCommitmentDomain = "vgt-gedefense-chameleon-mapping-v1"
)

// ChameleonManifest is the strict, bounded install profile.
type ChameleonManifest struct {
	InstallID      string
	CoreSocket     string
	ScanSocket     string
	BpfPinRoot     string
	StateDir       string
	ConfigDir      string
	PublicPort     string
	BackendPort    string
	BPFNameSalt    string
	NeutralPrefix  string
	AdminAuditPath string
}

// ChameleonProfile applies the opt-in installation identity to the config.
type ChameleonProfile struct {
	enabled  bool
	manifest ChameleonManifest
}

// ChameleonAuditMapping is the non-secret commitment the evidence ledger records
// for an active Chameleon installation. It carries no salt and no mapping: the
// signed install manifest remains the administrator's source of truth and the
// privileged core writes the full public=neutral mapping to its root-only audit
// file.
type ChameleonAuditMapping struct {
	InstallID       string
	SaltFingerprint string
	MappingHash     string
}

// activeChameleon is the process-wide profile installed by the startup seam so the
// scan/BPF-root helpers resolve without threading the profile through every call
// site. It is written once at startup and read-only afterwards.
var (
	activeChameleonMu sync.RWMutex
	activeChameleon   *ChameleonProfile
)

func installChameleonProfile(profile *ChameleonProfile) {
	activeChameleonMu.Lock()
	activeChameleon = profile
	activeChameleonMu.Unlock()
}

func activeChameleonProfile() *ChameleonProfile {
	activeChameleonMu.RLock()
	defer activeChameleonMu.RUnlock()
	return activeChameleon
}

// NewChameleonProfile loads the profile from `path` (empty disables it). An
// absolute path that cannot be parsed or validated is an error.
func NewChameleonProfile(path string) (*ChameleonProfile, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &ChameleonProfile{}, nil
	}
	if !strings.HasPrefix(path, "/") {
		return nil, errors.New("chameleon manifest path must be absolute")
	}
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return nil, errors.New("chameleon manifest path contains control characters")
		}
	}
	raw, err := readChameleonManifestFile(path)
	if err != nil {
		return nil, err
	}
	manifest, err := parseChameleonManifest(raw)
	if err != nil {
		return nil, err
	}
	return &ChameleonProfile{enabled: true, manifest: manifest}, nil
}

// Active reports whether the installation opted into Chameleon.
func (p *ChameleonProfile) Active() bool {
	return p != nil && p.enabled
}

// Manifest returns a copy-safe view of the parsed manifest. It is only valid for
// an active profile.
func (p *ChameleonProfile) Manifest() (ChameleonManifest, bool) {
	if !p.Active() {
		return ChameleonManifest{}, false
	}
	return p.manifest, true
}

// AuditMapping returns the non-secret evidence commitment for this profile. It
// reports false when the profile is inactive.
func (p *ChameleonProfile) AuditMapping() (ChameleonAuditMapping, bool) {
	if !p.Active() {
		return ChameleonAuditMapping{}, false
	}
	salt, err := hex.DecodeString(p.manifest.BPFNameSalt)
	if err != nil || len(salt) != 32 {
		return ChameleonAuditMapping{}, false
	}
	saltFingerprint := sha256.Sum256(salt)
	// The mapping itself is derived by the privileged core from the salt and the
	// object's symbol set. The control plane can only commit to the inputs it
	// validates; the core's root-only audit file carries the resolved mapping.
	commitment := fmt.Sprintf("%s\ninstall_id=%s\nsalt_fingerprint=%x\nname_schema=ap8-neutral-name-v1\n",
		chameleonAuditCommitmentDomain, p.manifest.InstallID, saltFingerprint)
	digest := sha256.Sum256([]byte(commitment))
	return ChameleonAuditMapping{
		InstallID:       p.manifest.InstallID,
		SaltFingerprint: hex.EncodeToString(saltFingerprint[:]),
		MappingHash:     hex.EncodeToString(digest[:]),
	}, true
}

// Apply rewrites the neutral paths/ports into the configuration. It is a no-op
// when the profile is inactive and never adds capabilities, weakens auth/TLS or
// moves a secret/key file: only daemon-owned state paths, the loopback listen
// address and the core socket are installation-specific.
func (p *ChameleonProfile) Apply(cfg Config) Config {
	if !p.Active() {
		return cfg
	}
	manifest := p.manifest
	cfg.Core.Socket = manifest.CoreSocket
	// The dashboard stays loopback-only; only the port is installation-specific.
	cfg.Dashboard.Listen = net.JoinHostPort("127.0.0.1", manifest.BackendPort)
	// Daemon-owned state and log files move under the neutral state root. Keys,
	// trust anchors, certificates and the gateway/dashboard credential remain at
	// their provisioned paths: the gateway owns the token file and moving it in
	// the control plane alone would break dashboard authentication.
	stateDir := manifest.StateDir
	cfg.Policy.StateFile = path.Join(stateDir, "policy.json")
	cfg.XDR.IncidentLog = path.Join(stateDir, "incidents.jsonl")
	cfg.XDR.BehaviorProfileFile = path.Join(stateDir, "behavior-profiles.json")
	cfg.Runtime.SettingsFile = path.Join(stateDir, "runtime-settings.json")
	cfg.Release.EmergencyStopFile = path.Join(stateDir, "EMERGENCY_STOP")
	cfg.Feeds.ManifestPath = path.Join(stateDir, "threat-feed-manifest.json")
	cfg.Feeds.SnapshotDir = path.Join(stateDir, "feed-snapshots")
	return cfg
}

// chameleonScanSocket returns the peer-bound user malware scan socket path of
// this installation (identity when the profile is inactive).
func chameleonScanSocket() string {
	if profile := activeChameleonProfile(); profile.Active() {
		return profile.manifest.ScanSocket
	}
	return chameleonDefaultScanSocket
}

// chameleonBpfPinRoot returns the bpffs pin root of this installation (identity
// when the profile is inactive). The authoritative binding for the privileged
// core is its unit drop-in (`--bpf-pin-root=`); this helper exists for
// diagnostics and for future control-plane call sites.
func chameleonBpfPinRoot() string {
	if profile := activeChameleonProfile(); profile.Active() {
		return profile.manifest.BpfPinRoot
	}
	return chameleonDefaultBpfPinRoot
}

// chameleonUserMalwareScan scans one browser-quarantine file through the
// peer-bound user malware socket. The packaged public socket still goes through
// `UserMalwareScan` (which pins the documented path); an opted-in installation
// may have a different, manifest-owned socket path, so that path is validated
// here (absolute /run/ runtime socket, bounded timeout) and the same bounded
// VGTSCAN1 protocol is spoken. The authentication decision stays on the
// privileged core side (SO_PEERCRED); the client adds no new trust.
func chameleonUserMalwareScan(filePath string, timeout time.Duration) (MalwareScanResult, error) {
	socketPath := chameleonScanSocket()
	if socketPath == chameleonDefaultScanSocket {
		return UserMalwareScan(socketPath, filePath, timeout)
	}
	if !strings.HasPrefix(socketPath, "/run/") || strings.Contains(socketPath, "..") ||
		strings.Contains(socketPath, "//") || len(socketPath) > 200 ||
		timeout < time.Second || timeout > time.Minute {
		return MalwareScanResult{}, errors.New("user malware scan endpoint rejected")
	}
	if err := validateQuarantinePathBuiltin(filePath); err != nil {
		return MalwareScanResult{}, errors.New("user malware scan path rejected")
	}
	token, err := quarantinePathToken(filePath)
	if err != nil {
		return MalwareScanResult{}, err
	}
	connection, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return MalwareScanResult{}, err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return MalwareScanResult{}, err
	}
	if _, err := io.WriteString(connection, "VGTSCAN1 "+token+"\n"); err != nil {
		return MalwareScanResult{}, err
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		if err := unixConnection.CloseWrite(); err != nil {
			return MalwareScanResult{}, err
		}
	}
	reader := bufio.NewReaderSize(io.LimitReader(connection, maxCoreResponseBytes+1), maxCoreResponseBytes+1)
	response, err := reader.ReadString('\n')
	if err != nil || len(response) > maxCoreResponseBytes {
		return MalwareScanResult{}, errors.New("user malware scan response rejected")
	}
	encoded, ok := strings.CutPrefix(strings.TrimSpace(response), "OK ")
	if !ok {
		return MalwareScanResult{}, errors.New("user malware scan was rejected")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) > 2048 {
		return MalwareScanResult{}, errors.New("user malware scan response encoding rejected")
	}
	return parseMalwareScanResult(string(decoded))
}
