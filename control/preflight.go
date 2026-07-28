package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type PreflightCheck struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Required bool   `json:"required"`
	Detail   string `json:"detail"`
}

type PreflightReport struct {
	Version   string           `json:"version"`
	Timestamp time.Time        `json:"timestamp"`
	Passed    bool             `json:"passed"`
	Interface string           `json:"interface,omitempty"`
	Kernel    string           `json:"kernel,omitempty"`
	Checks    []PreflightCheck `json:"checks"`
}

func rootOwnedNotWritable(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode().Perm()&0o022 == 0
}

func runPreflight(cfg Config, configPath string, requireEmergencyClear bool) PreflightReport {
	report := PreflightReport{Version: version, Timestamp: time.Now().UTC(), Passed: true}
	add := func(name string, passed, required bool, detail string) {
		report.Checks = append(report.Checks, PreflightCheck{Name: name, Passed: passed, Required: required, Detail: detail})
		if required && !passed {
			report.Passed = false
		}
	}
	if info, err := os.Lstat(configPath); err != nil {
		add("configuration-file", false, true, err.Error())
	} else {
		regular := info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && rootOwnedNotWritable(info)
		add("configuration-file", regular, true, fmt.Sprintf("mode=%s root_owned=%t", info.Mode(), rootOwnedNotWritable(info)))
	}
	if iface, err := detectInterface(cfg.Node.Interface); err != nil {
		add("network-interface", false, true, err.Error())
	} else {
		report.Interface = iface
		add("network-interface", true, true, iface)
	}
	if raw, err := os.ReadFile("/proc/sys/kernel/osrelease"); err != nil {
		add("linux-kernel", false, true, err.Error())
	} else {
		report.Kernel = strings.TrimSpace(string(raw))
		add("linux-kernel", report.Kernel != "", true, report.Kernel)
	}
	mounted := bpfFSMounted()
	add("bpffs-mounted", mounted, true, "/sys/fs/bpf")
	allowlistConfigured := len(cfg.Defense.Allowlist) > 0
	add("management-allowlist", allowlistConfigured, requireEmergencyClear, fmt.Sprintf("%d normalized CIDR entries", len(cfg.Defense.Allowlist)))
	artifactRoot := strings.TrimSpace(os.Getenv("VGT_RELEASE_ROOT"))
	if artifactRoot == "" {
		artifactRoot = "/opt/vgt/gedefense/current"
	}
	for _, path := range []string{filepath.Join(artifactRoot, "bin/gedefense-control"), filepath.Join(artifactRoot, "libexec/gedefense-core"), filepath.Join(artifactRoot, "lib/gedefense/gedefense-ebpf")} {
		info, err := os.Lstat(path)
		ok := err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && rootOwnedNotWritable(info)
		detail := path
		if err != nil {
			detail += ": " + err.Error()
		}
		add("artifact:"+filepath.Base(path), ok, true, detail)
	}
	keyInfo, keyErr := os.Lstat(cfg.Core.AuthKeyFile)
	keyOK := false
	keyDetail := cfg.Core.AuthKeyFile
	if keyErr == nil {
		if stat, ok := keyInfo.Sys().(*syscall.Stat_t); ok {
			mode := keyInfo.Mode().Perm()
			productionProfile := keyInfo.Mode().IsRegular() && keyInfo.Mode()&os.ModeSymlink == 0 && stat.Uid == 0 && stat.Gid == uint32(os.Getegid()) && mode == 0o640
			localProfile := keyInfo.Mode().IsRegular() && keyInfo.Mode()&os.ModeSymlink == 0 && stat.Uid == uint32(os.Geteuid()) && mode == 0o600
			keyOK = productionProfile || localProfile
			keyDetail += fmt.Sprintf(" uid=%d gid=%d mode=%#o", stat.Uid, stat.Gid, mode)
		}
	} else {
		keyDetail += ": " + keyErr.Error()
	}
	add("core-ipc-key", keyOK, true, keyDetail)
	runtimeKeyInfo, runtimeKeyErr := os.Lstat(cfg.Runtime.KeyFile)
	runtimeKeyOK := runtimeKeyErr == nil && runtimeKeyInfo.Mode().IsRegular() && runtimeKeyInfo.Mode().Perm()&0o077 == 0
	runtimeKeyDetail := cfg.Runtime.KeyFile
	if runtimeKeyErr != nil {
		runtimeKeyDetail += ": " + runtimeKeyErr.Error()
	}
	add("runtime-settings-key", runtimeKeyOK, true, runtimeKeyDetail)
	_, stopErr := os.Lstat(cfg.Release.EmergencyStopFile)
	stopClear := errors.Is(stopErr, os.ErrNotExist)
	if stopErr != nil && !errors.Is(stopErr, os.ErrNotExist) {
		stopClear = false
	}
	add("emergency-stop-clear", stopClear, requireEmergencyClear, cfg.Release.EmergencyStopFile)
	add("startup-observe", cfg.Defense.Enforcement == "observe" && cfg.XDR.Mode == "observe", true, "runtime promotion is release-gated")
	return report
}

func bpfFSMounted() bool {
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[1] == "/sys/fs/bpf" && fields[2] == "bpf" {
			return true
		}
	}
	return false
}

func writePreflightJSON(report PreflightReport) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func probeLoopback(endpoint, expectedPath, label string, timeout time.Duration) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Path != expectedPath || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s probe URL must be a loopback http:// host ending in %s", label, expectedPath)
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("%s probe is restricted to loopback", label)
	}
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	var last string
	for time.Now().Before(deadline) {
		response, requestErr := client.Get(endpoint)
		if requestErr == nil {
			last = response.Status
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		} else {
			last = requestErr.Error()
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("%s probe timed out: %s", label, last)
}

func probeReady(endpoint string, timeout time.Duration) error {
	return probeLoopback(endpoint, "/readyz", "readiness", timeout)
}

func probeLive(endpoint string, timeout time.Duration) error {
	return probeLoopback(endpoint, "/livez", "liveness", timeout)
}
