// STATUS: DIAMANT VGT SUPREME
package main

// M5.1 / M5.2 / M1.3 regression tests: the extended CIS/Lynis sysctl catalogue
// with preview/apply/verify/reverse, the userland posture checks, the
// kinetic-to-XDR context correlator and the raw request-body malware inspection.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------------- M5.1 sysctl

func TestM51SysctlCatalogueAndDefaultProfiles(t *testing.T) {
	required := map[string]string{
		"network.rp-filter":              "net.ipv4.conf.all.rp_filter",
		"network.log-martians":           "net.ipv4.conf.all.log_martians",
		"network.icmp-hardening":         "net.ipv4.icmp_echo_ignore_broadcasts",
		"filesystem.protected-hardlinks": "fs.protected_hardlinks",
		"filesystem.protected-symlinks":  "fs.protected_symlinks",
		"kernel.sysrq":                   "kernel.sysrq",
		"kernel.perf-event":              "kernel.perf_event_paranoid",
		"kernel.tty-ldisc":               "dev.tty.ldisc_autoload",
		"memory.swappiness":              "vm.swappiness",
		"network.syn-cookies":            "net.ipv4.tcp_syncookies",
		"kernel.dmesg":                   "kernel.dmesg_restrict",
		"kernel.kptr":                    "kernel.kptr_restrict",
		"kernel.ptrace":                  "kernel.yama.ptrace_scope",
	}
	seenMasks := map[uint32]string{}
	for id, definition := range sysctlControlDefinitions {
		if definition.Mask == 0 {
			t.Fatalf("control %q has a zero identity mask", id)
		}
		if other, duplicate := seenMasks[definition.Mask]; duplicate {
			t.Fatalf("controls %q and %q share mask %#x", id, other, definition.Mask)
		}
		seenMasks[definition.Mask] = id
		for key, value := range definition.Values {
			if !validSysctlKey(key) || !validSysctlToken(value) {
				t.Fatalf("control %q carries an invalid sysctl %q=%q", id, key, value)
			}
		}
	}
	for id, key := range required {
		definition, exists := sysctlControlDefinitions[id]
		if !exists {
			t.Fatalf("required M5.1 control %q is missing", id)
		}
		if _, exists := definition.Values[key]; !exists {
			t.Fatalf("control %q does not manage %q", id, key)
		}
	}
	// The extended catalogue needs more than the old 10-bit mask space.
	for id := range map[string]struct{}{"network.ipv6-disable": {}, "memory.swappiness": {}} {
		if definition := sysctlControlDefinitions[id]; definition.Mask <= 0x03ff {
			t.Fatalf("control %q still fits in the old 10-bit mask space: %#x", id, definition.Mask)
		}
	}
	defaults := defaultHardeningFabricSettings(Config{}, "").Sysctl
	profiles := map[string][]string{}
	for _, profile := range defaults.Profiles {
		profiles[profile.Name] = profile.Controls
		for _, control := range profile.Controls {
			if _, exists := sysctlControlDefinitions[control]; !exists {
				t.Fatalf("profile %q references unknown control %q", profile.Name, control)
			}
		}
	}
	for _, name := range []string{"linux-server-balanced", "astraeaos-workstation-strict", "astraeaos-cis-l1"} {
		if _, exists := profiles[name]; !exists {
			t.Fatalf("M5.1 profile %q is missing", name)
		}
	}
	for _, requiredControl := range []string{"network.rp-filter", "network.log-martians", "network.icmp-hardening", "filesystem.protected-hardlinks", "filesystem.protected-symlinks", "kernel.sysrq", "kernel.perf-event"} {
		if !containsString(profiles["linux-server-balanced"], requiredControl) {
			t.Fatalf("balanced profile does not manage %q", requiredControl)
		}
	}
	// IPv6 disable is context-dependent and must never be applied implicitly.
	for name, controls := range profiles {
		if containsString(controls, "network.ipv6-disable") {
			t.Fatalf("profile %q silently disables IPv6", name)
		}
	}
	if !validHardeningState("astraeaos-cis-l1") {
		t.Fatal("the CIS L1 profile name is not a valid persistent hardening state")
	}
	if !validHardeningState("astraeaos-custom-1fffff") {
		t.Fatal("a custom mask built from the extended catalogue is rejected")
	}
	if validHardeningState("astraeaos-custom-200000") {
		t.Fatal("a custom mask outside the catalogue was accepted")
	}
}

func TestM51CISProfilePreviewApplyVerifyReverse(t *testing.T) {
	core := &memorySysctlCore{values: map[string]string{}, persistent: "absent"}
	settings := defaultHardeningFabricSettings(Config{}, "").Sysctl
	profileCount := 0
	for _, profile := range settings.Profiles {
		if profile.Name != "astraeaos-cis-l1" {
			continue
		}
		profileCount++
		for _, control := range profile.Controls {
			for key := range sysctlControlDefinitions[control].Values {
				if _, exists := core.values[key]; !exists {
					core.values[key] = "0"
				}
			}
		}
	}
	if profileCount != 1 {
		t.Fatalf("CIS L1 profile defined %d times", profileCount)
	}
	applier := NewSysctlTransactionApplier(core)
	plan, before, err := applier.Preview([]byte(`{"profile":"astraeaos-cis-l1"}`))
	if err != nil {
		t.Fatalf("preview failed: %v", err)
	}
	after, err := applier.Apply(plan, before)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if err := applier.Verify(plan, after); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if core.values["net.ipv4.conf.all.rp_filter"] != "1" || core.values["fs.protected_hardlinks"] != "1" ||
		core.values["kernel.perf_event_paranoid"] != "3" {
		t.Fatalf("CIS values were not applied: %v", core.values)
	}
	if core.persistent != "astraeaos-cis-l1" {
		t.Fatalf("persistent profile is %q", core.persistent)
	}
	if err := applier.Reverse(before, after); err != nil {
		t.Fatalf("reverse failed: %v", err)
	}
	if core.values["net.ipv4.conf.all.rp_filter"] != "0" || core.values["kernel.perf_event_paranoid"] != "0" {
		t.Fatalf("reverse did not restore the previous values: %v", core.values)
	}
	if core.persistent != "absent" {
		t.Fatalf("reverse left persistent state %q", core.persistent)
	}

	// Ad-hoc / legacy profile names with empty afterRaw must still recover via
	// the built-in sysctl catalogue when every key in `before` is known.
	if _, _, err := applier.Preview([]byte(`{"controls":["network.rp-filter","kernel.aslr"]}`)); err != nil {
		t.Fatalf("ad-hoc preview failed: %v", err)
	}
	if err := core.SysctlCompareSet("net.ipv4.conf.all.rp_filter", "0", "1"); err != nil {
		t.Fatal(err)
	}
	if err := core.SysctlCompareSet("net.ipv4.conf.default.rp_filter", "0", "1"); err != nil {
		t.Fatal(err)
	}
	if err := core.SysctlCompareSet("kernel.randomize_va_space", "0", "2"); err != nil {
		t.Fatal(err)
	}
	adHocBefore := []byte(`{"profile":"ad-hoc","values":{"kernel.randomize_va_space":"0","net.ipv4.conf.all.rp_filter":"0","net.ipv4.conf.default.rp_filter":"0"},"persistent":"absent"}`)
	if err := applier.Reverse(adHocBefore, nil); err != nil {
		t.Fatalf("ad-hoc recovery reverse failed: %v", err)
	}
	if core.values["net.ipv4.conf.all.rp_filter"] != "0" || core.values["kernel.randomize_va_space"] != "0" {
		t.Fatalf("ad-hoc recovery did not restore previous values: %v", core.values)
	}
}

func writeHardeningFixture(t *testing.T, root string, values map[string]string) {
	t.Helper()
	for relative, value := range values {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestM51CISPostureChecksAreMeasurableAndHonest(t *testing.T) {
	root := t.TempDir()
	writeHardeningFixture(t, root, map[string]string{
		"proc/sys/net/ipv4/conf/all/rp_filter":                "1\n",
		"proc/sys/net/ipv4/conf/default/rp_filter":            "1\n",
		"proc/sys/net/ipv4/conf/all/log_martians":             "1\n",
		"proc/sys/net/ipv4/conf/default/log_martians":         "1\n",
		"proc/sys/net/ipv4/icmp_echo_ignore_broadcasts":       "1\n",
		"proc/sys/net/ipv4/icmp_ignore_bogus_error_responses": "1\n",
		"proc/sys/fs/protected_hardlinks":                     "1\n",
		"proc/sys/fs/protected_symlinks":                      "1\n",
		"proc/sys/kernel/sysrq":                               "0\n",
		"proc/sys/kernel/perf_event_paranoid":                 "3\n",
		"proc/sys/dev/tty/ldisc_autoload":                     "0\n",
		"proc/sys/vm/swappiness":                              "10\n",
		"proc/sys/net/ipv6/conf/all/disable_ipv6":             "0\n",
		"proc/sys/net/ipv6/conf/default/disable_ipv6":         "0\n",
		"etc/ssh/sshd_config":                                 "PermitRootLogin prohibit-password\n",
		"etc/ssh/sshd_config.d/99-gedefense.conf":             "MaxAuthTries 3\nAllowTcpForwarding no\nX11Forwarding no\nClientAliveCountMax 2\nLogLevel VERBOSE\n",
		"etc/login.defs":                                      "UMASK 027\nPASS_MAX_DAYS 365\n",
		"etc/issue":                                           "Authorized access only. All activity is monitored.\n",
		"etc/issue.net":                                       "Authorized access only. All activity is monitored.\n",
		"etc/audit/rules.d/gedefense.rules":                   "-w /etc/sudoers -p wa -k sudoers\n-w /etc/ssh/sshd_config -p wa -k sshd\n-e 1\n",
		"etc/modprobe.d/gedefense-blacklist.conf":             "install dccp /bin/true\ninstall sctp /bin/true\ninstall rds /bin/true\ninstall tipc /bin/true\ninstall cramfs /bin/true\ninstall usb-storage /bin/true\n",
	})
	collector := newHardeningCollectorForTest(root, time.Now)
	posture := collector.Collect(Snapshot{}, BootTrustReport{})
	for _, id := range []string{
		"network.rp-filter", "network.log-martians", "network.icmp-hardening",
		"filesystem.protected-hardlinks", "filesystem.protected-symlinks",
		"kernel.sysrq", "kernel.perf-event", "kernel.tty-ldisc", "memory.swappiness",
		"web.sshd-baseline", "web.login-umask", "web.legal-banner",
		"integrity.audit-baseline", "kernel.module-blacklist",
	} {
		if check := postureCheck(t, posture, id); check.State != hardeningStateProtected {
			t.Fatalf("check %q reported %s (%s)", id, check.State, check.Evidence)
		}
	}
	// IPv6 is enabled: the context-dependent switch must be partial, not blocked.
	if check := postureCheck(t, posture, "network.ipv6-disable"); check.State != hardeningStatePartial {
		t.Fatalf("IPv6-enabled host reported %s", check.State)
	}
}

// ------------------------------------------------------------- M5.2 kinetic

func procNetLine(localIP string, localPort uint16, remoteIP string, remotePort uint16, state string) string {
	address := func(ip string) string {
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			return "00000000"
		}
		values := make([]int, 4)
		for index := range parts {
			parsed, err := strconv.Atoi(parts[index])
			if err != nil {
				return "00000000"
			}
			values[index] = parsed
		}
		return fmt.Sprintf("%02X%02X%02X%02X", values[3], values[2], values[1], values[0])
	}
	return fmt.Sprintf("  0: %s:%04X %s:%04X %s 00000000:00000000 00:00000000 00000000 0 0 0 0 0 0 0 0",
		address(localIP), localPort, address(remoteIP), remotePort, state)
}

func kineticContextFixture(t *testing.T, tcpRows []string) (*APIServer, *XDREngine) {
	t.Helper()
	previousRoot := kineticProcNetRoot
	kineticProcNetRoot = t.TempDir()
	t.Cleanup(func() { kineticProcNetRoot = previousRoot })
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	content += strings.Join(tcpRows, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(kineticProcNetRoot, "tcp"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	engine := &XDREngine{
		state: NewState("test", defaultConfig()), correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
	}
	return &APIServer{xdr: engine}, engine
}

func TestM52KineticBlockContextResolvesServiceAndMITRE(t *testing.T) {
	server, engine := kineticContextFixture(t, []string{
		procNetLine("127.0.0.1", 22, "203.0.113.7", 40000, "01"),
	})
	now := time.Now().UTC()
	event := KineticEvent{
		ID: "kinetic-event-1", Time: now, RuleID: "NET.INGRESS.PORT_SCAN",
		SourceIP: "203.0.113.7", Score: 95, Confidence: 0.9,
		Decision: "block", Action: "block",
	}
	server.recordKineticBlockContext(event, BlockEntry{Target: "203.0.113.7"}, now)

	snapshot := engine.state.Snapshot()
	if len(snapshot.Incidents) != 1 {
		t.Fatalf("expected one correlated incident, got %d", len(snapshot.Incidents))
	}
	incident := snapshot.Incidents[0]
	if incident.Remote != "203.0.113.7" || incident.Decision != "block" {
		t.Fatalf("incident is wrong: %+v", incident)
	}
	if len(incident.AttackStory) == 0 {
		t.Fatal("incident carries no attack-story node")
	}
	node := incident.AttackStory[0]
	if node.Metadata["mitre_technique"] != "T1046" || node.Metadata["has_lineage_or_chain"] != "true" {
		t.Fatalf("attack-story node lacks MITRE lineage metadata: %+v", node.Metadata)
	}
	if !strings.Contains(node.Metadata["local_services"], "sshd:22") {
		t.Fatalf("local service was not resolved: %q", node.Metadata["local_services"])
	}
	if incident.ExecutionChainID == "" || incident.EvidenceRoot == "" {
		t.Fatalf("incident has no chain/evidence identity: %+v", incident)
	}
	stories := engine.Correlator().GetAllStories()
	if len(stories) == 0 || len(stories[0].Nodes) == 0 {
		t.Fatal("attack story was not registered in the correlator")
	}
	// Dedupe: the same block must not create a second incident.
	server.recordKineticBlockContext(event, BlockEntry{Target: "203.0.113.7"}, now)
	if got := len(engine.state.Snapshot().Incidents); got != 1 {
		t.Fatalf("duplicate kinetic block created %d incidents", got)
	}
}

func TestM52KineticSynFloodUsesDoSAndFallsBackToListeningServices(t *testing.T) {
	server, engine := kineticContextFixture(t, []string{
		procNetLine("0.0.0.0", 22, "0.0.0.0", 0, "0A"),
		procNetLine("0.0.0.0", 5432, "0.0.0.0", 0, "0A"),
	})
	now := time.Now().UTC()
	server.recordKineticBlockContext(KineticEvent{
		ID: "kinetic-event-2", Time: now, RuleID: "NET.INGRESS.SYN_FLOOD", SourceIP: "198.51.100.9", Score: 90,
	}, BlockEntry{Target: "198.51.100.9"}, now)
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 1 {
		t.Fatalf("expected one incident, got %d", len(incidents))
	}
	node := incidents[0].AttackStory[0]
	if node.Metadata["mitre_technique"] != "T1499.002" {
		t.Fatalf("SYN flood mapped to %q", node.Metadata["mitre_technique"])
	}
	if !strings.Contains(node.Metadata["local_services"], "sshd:22") || !strings.Contains(node.Metadata["local_services"], "postgresql:5432") {
		t.Fatalf("listening-service fallback failed: %q", node.Metadata["local_services"])
	}
}

// ---------------------------------------------------------- M1.3 raw body

func TestM13AirlockInspectsRawRequestBodyMarkers(t *testing.T) {
	inspector, err := NewAirlockInspector(t.TempDir(), 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	eicar := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	result, err := inspector.InspectRequestBody("application/octet-stream", eicar)
	if err == nil || result == nil || result.ThreatType != "MALWARE_MARKER" {
		t.Fatalf("EICAR body was not rejected: %+v (err %v)", result, err)
	}
	if result.RiskScore < 110 {
		t.Fatalf("EICAR body risk score %d is below the required 110", result.RiskScore)
	}
	webshell := []byte("<?php system($_GET['cmd']); ?>")
	if _, err := inspector.InspectRequestBody("", webshell); err == nil {
		t.Fatal("webshell body was not rejected")
	}
	if _, err := inspector.InspectRequestBody("application/octet-stream", []byte("harmless binary payload")); err != nil {
		t.Fatalf("benign raw body was rejected: %v", err)
	}
}

func TestM13L7BlocksEicarOnRawPost(t *testing.T) {
	cfg := l7TestConfig()
	cfg.Mode = "block"
	inspector, err := NewAirlockInspector(t.TempDir(), 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.airlock = inspector
	engine.canBlock = func() bool { return true }
	eicar := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	request := L7InspectionRequest{
		Version: l7ProtocolVersion, RequestID: "0123456789abcdef", Method: "POST", Scheme: "https",
		Host: "example.test", URI: "/api/upload", RemoteIP: "198.51.100.10",
		Headers: []L7Header{{Name: "Content-Type", Value: "application/octet-stream"}},
	}
	response, _, err := engine.InspectRaw(context.Background(), request, eicar)
	if err != nil {
		t.Fatalf("raw EICAR POST was rejected by the parser instead of inspected: %v", err)
	}
	found := false
	for _, finding := range response.Findings {
		if strings.HasPrefix(finding.RuleID, "L7.UPLOAD.") {
			found = true
		}
	}
	if !found || response.Decision != "block" || !response.Enforced {
		t.Fatalf("raw EICAR POST was not blocked: %+v", response)
	}
	// A benign opaque body stays clean.
	benign := L7InspectionRequest{
		Version: l7ProtocolVersion, RequestID: "0123456789abcdea", Method: "POST", Scheme: "https",
		Host: "example.test", URI: "/api/upload", RemoteIP: "198.51.100.10",
		Headers: []L7Header{{Name: "Content-Type", Value: "application/octet-stream"}},
	}
	benignResponse, _, err := engine.InspectRaw(context.Background(), benign, []byte("benign opaque payload"))
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range benignResponse.Findings {
		if strings.HasPrefix(finding.RuleID, "L7.UPLOAD.") {
			t.Fatalf("benign raw body produced an upload finding: %+v", finding)
		}
	}
}

// --------------------------------------------------- M5.1 provisioning script

func TestM51ProvisionScriptCISBaselineIsSyntacticallyValidAndOptIn(t *testing.T) {
	provision := filepath.Join("..", "packaging", "scripts", "gedefense-provision")
	script := filepath.Join("..", "packaging", "scripts", "gedefense-cis-baseline")
	raw, err := os.ReadFile(provision)
	if err != nil {
		t.Fatalf("provisioning script missing: %v", err)
	}
	if !strings.Contains(string(raw), "--cis-baseline") || !strings.Contains(string(raw), "gedefense-cis-baseline") {
		t.Fatal("provisioning script does not pass through the opt-in CIS baseline flag")
	}
	raw, err = os.ReadFile(script)
	if err != nil {
		t.Fatalf("CIS baseline helper missing: %v", err)
	}
	text := string(raw)
	for _, anchor := range []string{
		"--apply", "--remove", "--check", "99-gedefense.conf",
		"UMASK 027", "PASS_MAX_DAYS 365", "Authorized access only",
		"gedefense-blacklist.conf", "gedefense.rules",
		"install dccp /bin/true", "install usb-storage /bin/true",
	} {
		if !strings.Contains(text, anchor) {
			t.Fatalf("CIS baseline helper lacks %q", anchor)
		}
	}
	if strings.Contains(text, "systemctl reload sshd") || strings.Contains(text, "systemctl restart sshd") {
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, "systemctl reload sshd") || strings.Contains(trimmed, "systemctl restart sshd") {
				t.Fatalf("CIS baseline helper reloads/restarts sshd on its own: %q", trimmed)
			}
		}
	}
	for _, target := range []string{provision, script} {
		if out, err := exec.Command("bash", "-n", target).CombinedOutput(); err != nil {
			t.Fatalf("script %q has a syntax error: %v\n%s", target, err, out)
		}
	}
	// Stage a real CIS apply into a temporary tree.
	root := t.TempDir()
	cmd := exec.Command("bash", script, "--apply")
	cmd.Env = append(os.Environ(), "GEDEFENSE_PROVISION_ROOT="+root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("staged CIS baseline failed: %v\n%s", err, out)
	}
	for _, relative := range []string{
		"etc/ssh/sshd_config.d/99-gedefense.conf",
		"etc/modprobe.d/gedefense-blacklist.conf",
		"etc/audit/rules.d/gedefense.rules",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("staged CIS baseline artifact %q missing: %v", relative, err)
		}
	}
	loginDefs, err := os.ReadFile(filepath.Join(root, "etc", "login.defs"))
	if err != nil || !strings.Contains(string(loginDefs), "UMASK 027") {
		t.Fatalf("staged login.defs has no managed UMASK block: %v", err)
	}
	// Idempotent, reversible and never touching unmanaged files.
	if out, err := exec.Command("bash", script, "--apply").CombinedOutput(); err != nil {
		t.Logf("second apply output: %s", out)
	}
	check := exec.Command("bash", script, "--check")
	check.Env = append(os.Environ(), "GEDEFENSE_PROVISION_ROOT="+root)
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("CIS --check failed after apply: %v\n%s", err, out)
	}
	remove := exec.Command("bash", script, "--remove")
	remove.Env = append(os.Environ(), "GEDEFENSE_PROVISION_ROOT="+root)
	if out, err := remove.CombinedOutput(); err != nil {
		t.Fatalf("CIS --remove failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "ssh", "sshd_config.d", "99-gedefense.conf")); !os.IsNotExist(err) {
		t.Fatalf("CIS --remove left the SSHD drop-in behind: %v", err)
	}
}
