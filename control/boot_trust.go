// STATUS: DIAMANT VGT SUPREME

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	bootStateObserved     = "OBSERVED"
	bootStateEnabled      = "ENABLED"
	bootStateDisabled     = "DISABLED"
	bootStateWarning      = "WARNING"
	bootStateUnknown      = "UNKNOWN"
	bootStateNotAvailable = "NOT_AVAILABLE"

	maxBootTextBytes = 64 << 10
	maxKernelBytes   = 256 << 20
)

type BootTrustEvidence struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	Summary  string `json:"summary"`
	Source   string `json:"source"`
	Evidence string `json:"evidence,omitempty"`
	Digest   string `json:"digest,omitempty"`
}

type BootTrustReport struct {
	GeneratedAt time.Time           `json:"generated_at"`
	ClaimLevel  string              `json:"claim_level"`
	Platform    string              `json:"platform"`
	DistroID    string              `json:"distro_id,omitempty"`
	DistroName  string              `json:"distro_name,omitempty"`
	VersionID   string              `json:"version_id,omitempty"`
	GaiaOS      bool                `json:"gaiaos"`
	Summary     string              `json:"summary"`
	Items       []BootTrustEvidence `json:"items"`
}

type bootTrustProbe struct {
	root  string
	linux bool
	now   func() time.Time
}

type BootTrustCollector struct {
	mu      sync.Mutex
	probe   bootTrustProbe
	ttl     time.Duration
	expires time.Time
	cached  BootTrustReport
}

func NewBootTrustCollector(ttl time.Duration) *BootTrustCollector {
	if ttl < time.Second {
		ttl = 5 * time.Minute
	}
	return &BootTrustCollector{
		probe: bootTrustProbe{linux: runtime.GOOS == "linux", now: time.Now},
		ttl:   ttl,
	}
}

func newBootTrustCollectorForTest(root string, linux bool, now func() time.Time) *BootTrustCollector {
	return &BootTrustCollector{
		probe: bootTrustProbe{root: root, linux: linux, now: now},
		ttl:   5 * time.Minute,
	}
}

func (c *BootTrustCollector) Collect() BootTrustReport {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.probe.now().UTC()
	if !c.expires.IsZero() && now.Before(c.expires) {
		return cloneBootTrustReport(c.cached)
	}
	report := c.probe.collect(now)
	c.cached = cloneBootTrustReport(report)
	c.expires = now.Add(c.ttl)
	return report
}

func cloneBootTrustReport(in BootTrustReport) BootTrustReport {
	out := in
	out.Items = append([]BootTrustEvidence(nil), in.Items...)
	return out
}

func (p bootTrustProbe) collect(now time.Time) BootTrustReport {
	report := BootTrustReport{
		GeneratedAt: now,
		ClaimLevel:  "evidence-only",
		Platform:    runtime.GOOS,
		Items:       make([]BootTrustEvidence, 0, 12),
	}
	if !p.linux {
		report.Items = append(report.Items, BootTrustEvidence{
			ID: "platform", State: bootStateNotAvailable,
			Summary: "Linux boot evidence is unavailable on this platform.",
			Source:  "runtime",
		})
		report.Summary = "Boot evidence unavailable"
		return report
	}
	report.Platform = "linux"

	osRelease := p.readOSRelease()
	report.DistroID = osRelease["ID"]
	report.DistroName = osRelease["NAME"]
	report.VersionID = osRelease["VERSION_ID"]
	report.GaiaOS = strings.EqualFold(report.DistroID, "gaiaos")
	report.Items = append(report.Items, distroEvidence(report))
	report.Items = append(report.Items, p.secureBootEvidence())
	report.Items = append(report.Items, p.lockdownEvidence())
	report.Items = append(report.Items, p.cmdlineEvidence())
	report.Items = append(report.Items, p.tpmEvidence())
	report.Items = append(report.Items, p.cgroupEvidence())
	report.Items = append(report.Items, p.gaiaCellsEvidence())
	report.Items = append(report.Items, p.kernelImageEvidence())
	report.Summary = summarizeBootEvidence(report.Items)
	return report
}

func distroEvidence(report BootTrustReport) BootTrustEvidence {
	if report.DistroID == "" {
		return BootTrustEvidence{
			ID: "distribution", State: bootStateUnknown,
			Summary: "Distribution identity could not be observed.",
			Source:  "/etc/os-release",
		}
	}
	summary := "Linux distribution identity observed."
	if report.GaiaOS {
		summary = "GaiaOS distribution identity observed."
	}
	return BootTrustEvidence{
		ID: "distribution", State: bootStateObserved, Summary: summary,
		Source: "/etc/os-release", Evidence: report.DistroID,
	}
}

func (p bootTrustProbe) readOSRelease() map[string]string {
	data, err := p.readBounded("/etc/os-release", maxBootTextBytes)
	if err != nil {
		return map[string]string{}
	}
	allowed := map[string]bool{"ID": true, "NAME": true, "VERSION_ID": true}
	values := make(map[string]string, len(allowed))
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !allowed[key] {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = strings.ReplaceAll(value[1:len(value)-1], `\"`, `"`)
		}
		if len(value) <= 256 && !strings.ContainsRune(value, '\x00') {
			values[key] = value
		}
	}
	return values
}

func (p bootTrustProbe) secureBootEvidence() BootTrustEvidence {
	candidates := []string{
		"/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
		"/sys/firmware/efi/vars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c/data",
	}
	for _, candidate := range candidates {
		data, err := p.readBounded(candidate, 4096)
		if err != nil {
			continue
		}
		var value byte
		switch {
		case strings.Contains(candidate, "/efivars/") && len(data) >= 5:
			value = data[4]
		case len(data) >= 1:
			value = data[0]
		default:
			continue
		}
		state := bootStateDisabled
		summary := "UEFI Secure Boot reports disabled."
		if value == 1 {
			state = bootStateEnabled
			summary = "UEFI Secure Boot variable reports enabled; signature-chain measurement is separate evidence."
		}
		return BootTrustEvidence{
			ID: "secure-boot", State: state, Summary: summary,
			Source: candidate, Evidence: fmt.Sprintf("value=%d", value),
		}
	}
	if p.exists("/sys/firmware/efi") {
		return BootTrustEvidence{
			ID: "secure-boot", State: bootStateUnknown,
			Summary: "UEFI is present, but its Secure Boot variable is unreadable.",
			Source:  "efivarfs",
		}
	}
	return BootTrustEvidence{
		ID: "secure-boot", State: bootStateNotAvailable,
		Summary: "No UEFI firmware evidence is exposed.",
		Source:  "/sys/firmware/efi",
	}
}

func (p bootTrustProbe) lockdownEvidence() BootTrustEvidence {
	data, err := p.readBounded("/sys/kernel/security/lockdown", 4096)
	if err != nil {
		return BootTrustEvidence{
			ID: "kernel-lockdown", State: bootStateUnknown,
			Summary: "Kernel lockdown state is unavailable.",
			Source:  "/sys/kernel/security/lockdown",
		}
	}
	value := strings.TrimSpace(string(data))
	state := bootStateWarning
	if strings.Contains(value, "[integrity]") || strings.Contains(value, "[confidentiality]") {
		state = bootStateEnabled
	}
	return BootTrustEvidence{
		ID: "kernel-lockdown", State: state,
		Summary: "Kernel lockdown runtime state observed.",
		Source:  "/sys/kernel/security/lockdown", Evidence: truncateBootEvidence(value, 128),
	}
}

func (p bootTrustProbe) cmdlineEvidence() BootTrustEvidence {
	data, err := p.readBounded("/proc/cmdline", maxBootTextBytes)
	if err != nil {
		return BootTrustEvidence{
			ID: "kernel-cmdline", State: bootStateUnknown,
			Summary: "Kernel command line is unavailable.",
			Source:  "/proc/cmdline",
		}
	}
	sum := sha256.Sum256(data)
	required := map[string]bool{
		"init_on_alloc=1":            false,
		"init_on_free=1":             false,
		"randomize_kstack_offset=on": false,
		"module.sig_enforce=1":       false,
	}
	for _, token := range strings.Fields(string(data)) {
		if _, ok := required[token]; ok {
			required[token] = true
		}
	}
	present := make([]string, 0, len(required))
	for token, found := range required {
		if found {
			present = append(present, token)
		}
	}
	sort.Strings(present)
	state := bootStateWarning
	if len(present) == len(required) {
		state = bootStateEnabled
	}
	return BootTrustEvidence{
		ID: "kernel-cmdline", State: state,
		Summary: "Security-relevant boot parameters observed; raw command line is intentionally redacted.",
		Source:  "/proc/cmdline", Evidence: strings.Join(present, ","),
		Digest: hex.EncodeToString(sum[:]),
	}
}

func (p bootTrustProbe) tpmEvidence() BootTrustEvidence {
	for _, candidate := range []string{"/sys/class/tpm/tpm0", "/sys/class/tpmrm/tpmrm0", "/dev/tpmrm0", "/dev/tpm0"} {
		if p.exists(candidate) {
			return BootTrustEvidence{
				ID: "tpm", State: bootStateObserved,
				Summary: "A TPM interface is present; measured-boot verification has not been claimed.",
				Source:  candidate,
			}
		}
	}
	return BootTrustEvidence{
		ID: "tpm", State: bootStateNotAvailable,
		Summary: "No TPM interface was observed.",
		Source:  "sysfs/devfs",
	}
}

func (p bootTrustProbe) cgroupEvidence() BootTrustEvidence {
	data, err := p.readBounded("/sys/fs/cgroup/cgroup.controllers", 4096)
	if err != nil {
		return BootTrustEvidence{
			ID: "cgroup-v2", State: bootStateNotAvailable,
			Summary: "A unified cgroup v2 hierarchy was not observed.",
			Source:  "/sys/fs/cgroup/cgroup.controllers",
		}
	}
	controllers := strings.Fields(string(data))
	sort.Strings(controllers)
	return BootTrustEvidence{
		ID: "cgroup-v2", State: bootStateObserved,
		Summary:  "Unified cgroup v2 isolation substrate observed.",
		Source:   "/sys/fs/cgroup/cgroup.controllers",
		Evidence: strings.Join(controllers, ","),
	}
}

func (p bootTrustProbe) gaiaCellsEvidence() BootTrustEvidence {
	path := p.resolve("/run/gaia-cells/control.sock")
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSocket != 0 {
		return BootTrustEvidence{
			ID: "gaia-cells", State: bootStateObserved,
			Summary: "Gaia Cells runtime socket observed; protocol authentication remains required.",
			Source:  "/run/gaia-cells/control.sock",
		}
	}
	return BootTrustEvidence{
		ID: "gaia-cells", State: bootStateNotAvailable,
		Summary: "Gaia Cells runtime is not installed or has not exposed its versioned control socket.",
		Source:  "/run/gaia-cells/control.sock",
	}
}

func (p bootTrustProbe) kernelImageEvidence() BootTrustEvidence {
	releaseData, _ := p.readBounded("/proc/sys/kernel/osrelease", 4096)
	release := strings.TrimSpace(string(releaseData))
	candidates := []string{"/boot/vmlinuz-linux-hardened", "/boot/vmlinuz-linux"}
	if release != "" && !strings.ContainsAny(release, `/\`+"\x00") {
		candidates = append(candidates, "/usr/lib/modules/"+release+"/vmlinuz")
	}
	for _, candidate := range candidates {
		digest, size, err := p.hashRegular(candidate, maxKernelBytes)
		if err != nil {
			continue
		}
		return BootTrustEvidence{
			ID: "kernel-image", State: bootStateObserved,
			Summary: "Kernel image digest observed; trust requires comparison with a signed release manifest.",
			Source:  candidate, Evidence: fmt.Sprintf("size=%d", size), Digest: digest,
		}
	}
	return BootTrustEvidence{
		ID: "kernel-image", State: bootStateUnknown,
		Summary: "No bounded regular kernel image could be read.",
		Source:  "/boot or /usr/lib/modules",
	}
}

func (p bootTrustProbe) readBounded(path string, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, errors.New("invalid read limit")
	}
	resolved := p.resolve(path)
	info, err := os.Lstat(resolved)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("evidence source is not a regular non-symlink file")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("evidence source exceeds limit")
	}
	return data, nil
}

func (p bootTrustProbe) hashRegular(path string, max int64) (string, int64, error) {
	resolved := p.resolve(path)
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > max {
		return "", 0, errors.New("kernel image is outside the regular-file boundary")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", 0, errors.New("kernel image identity changed")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, max+1))
	if err != nil {
		return "", 0, err
	}
	if written != info.Size() || written > max {
		return "", 0, errors.New("kernel image changed while hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), written, nil
}

func (p bootTrustProbe) exists(path string) bool {
	_, err := os.Lstat(p.resolve(path))
	return err == nil
}

func (p bootTrustProbe) resolve(path string) string {
	clean := filepath.Clean(filepath.FromSlash(path))
	if p.root == "" {
		return clean
	}
	volume := filepath.VolumeName(clean)
	clean = strings.TrimPrefix(clean, volume)
	clean = strings.TrimLeft(clean, `/\`)
	return filepath.Join(p.root, clean)
}

func truncateBootEvidence(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func summarizeBootEvidence(items []BootTrustEvidence) string {
	observed, warnings, unavailable := 0, 0, 0
	for _, item := range items {
		switch item.State {
		case bootStateEnabled, bootStateObserved:
			observed++
		case bootStateWarning, bootStateDisabled:
			warnings++
		default:
			unavailable++
		}
	}
	return fmt.Sprintf("%d observed/enabled, %d disabled/warning, %d unknown/unavailable; evidence-only", observed, warnings, unavailable)
}
