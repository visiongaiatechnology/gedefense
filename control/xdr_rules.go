package main

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

type commandRule struct {
	id, category, summary string
	score                 int
	killEligible          bool
	re                    *regexp.Regexp
}

type XDRRuleEngine struct {
	mu           sync.RWMutex
	commandRules []commandRule
	redactors    []*regexp.Regexp
	revision     uint64
	modules      map[string]bool
	customRules  []commandRule
}

func NewXDRRuleEngine() *XDRRuleEngine {
	// Go's standard regexp engine uses RE2 semantics and linear-time matching.
	defs := []struct {
		id, category, summary, pattern string
		score                          int
		killEligible                   bool
	}{
		{"KD.LINUX.PIPE_SHELL", "execution", "Download or generated content piped into a shell", `(?i)\b(?:curl|wget|fetch)\b[^\n|]{0,900}\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b`, 85, true},
		{"KD.LINUX.ENCODED_EXEC", "execution", "Encoded payload decoded into an interpreter", `(?i)(?:base64\s+(?:-d|--decode)|openssl\s+enc\s+-d|b64decode\s*\(|frombase64string\s*\().{0,900}(?:\|\s*(?:ba|da|z|k)?sh\b|\beval\b|\bexec\s*\()`, 75, true},
		{"KD.LINUX.REVERSE_SHELL", "network", "Reverse-shell construction detected", `(?i)(?:/dev/(?:tcp|udp)/|\bnc(?:at)?\b[^\n]{0,500}(?:-e|--exec)\b|\bsocat\b[^\n]{0,500}\bexec:|\b(?:bash|sh)\s+-i\b)`, 105, true},
		{"KD.LINUX.LD_PRELOAD", "injection", "Dynamic-loader injection variable used", `(?i)\b(?:LD_PRELOAD|LD_AUDIT)\s*=`, 70, true},
		{"KD.LINUX.CREDENTIAL_ACCESS", "credential", "Direct access to sensitive credential material", `(?i)(?:\bcat\s+/(?:etc/shadow|root/\.ssh/)|\b(?:grep|strings)\b[^\n]{0,300}/proc/[0-9*]+/(?:environ|mem)|\bssh-keygen\b[^\n]{0,300}-y\s+-f\s+/root/)`, 65, true},
		{"KD.LINUX.DESTRUCTIVE", "impact", "Destructive system command detected", `(?i)(?:\brm\s+-rf\s+/(?:\s|$)|\bmkfs\.[a-z0-9]+\s+/dev/|\bdd\s+[^\n]{0,300}\bof=/dev/(?:sd|nvme|vd)|:\(\)\s*\{\s*:\|:&\s*;\s*\}\s*;)`, 140, true},
		{"KD.LINUX.PERSISTENCE", "persistence", "Persistence-oriented command sequence", `(?i)(?:\bcrontab\b[^\n]{0,400}(?:-e|-)|/etc/(?:cron\.|systemd/system)|\bsystemctl\s+enable\b|\bchattr\s+\+i\b)`, 35, false},
		{"KD.LINUX.BPF_LOAD", "kernel", "Unexpected BPF program loading command", `(?i)\bbpftool\s+prog\s+(?:load|loadall)|\b(?:bpf|libbpf)\b[^\n]{0,300}\bprog_load\b`, 45, false},
	}
	out := &XDRRuleEngine{}
	for _, d := range defs {
		out.commandRules = append(out.commandRules, commandRule{d.id, d.category, d.summary, d.score, d.killEligible, regexp.MustCompile(d.pattern)})
	}
	out.redactors = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(--?(?:password|passwd|token|secret|api[-_]?key|authorization)(?:=|\s+))([^\s]+)`),
		regexp.MustCompile(`(?i)(https?://[^:/\s]+:)([^@/\s]+)(@)`),
		regexp.MustCompile(`(?i)(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})`),
	}
	return out
}

func (e *XDRRuleEngine) Configure(settings RuntimeSettings) error {
	e.mu.RLock()
	if e.revision == settings.Revision {
		e.mu.RUnlock()
		return nil
	}
	e.mu.RUnlock()

	custom := make([]commandRule, 0, len(settings.CustomRules))
	for _, rule := range settings.CustomRules {
		if !rule.Enabled {
			continue
		}
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return err
		}
		// Operator rules are deliberately alert-only evidence. They may add
		// score, but never create an independent kill-authorizing category.
		custom = append(custom, commandRule{
			id: rule.ID, category: rule.Category, summary: rule.Summary,
			score: rule.Score, killEligible: false, re: compiled,
		})
	}
	e.mu.Lock()
	e.revision = settings.Revision
	e.modules = effectiveRuleModules(settings)
	e.customRules = custom
	e.mu.Unlock()
	return nil
}

func (e *XDRRuleEngine) RedactCommand(s string, max int) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, re := range e.redactors {
		if re.NumSubexp() == 3 {
			s = re.ReplaceAllString(s, `${1}[REDACTED]${3}`)
		} else {
			s = re.ReplaceAllString(s, `${1}[REDACTED]`)
		}
	}
	if max > 0 && len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

func commandDigest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (e *XDRRuleEngine) EvaluateProcess(p ProcessSample, connections []NetConnection, feeds *ThreatIndex, baseline *XDRBaseline, extra ...RuleMatch) XDRDecision {
	e.mu.RLock()
	defer e.mu.RUnlock()
	matches := make([]RuleMatch, 0, 8+len(extra))
	matches = append(matches, extra...)
	cmd := p.Cmdline
	if e.moduleEnabled("command") {
		for _, r := range e.commandRules {
			if r.re.MatchString(cmd) {
				matches = append(matches, RuleMatch{ID: r.id, Category: r.category, Score: r.score, Summary: r.summary, KillEligible: r.killEligible})
			}
		}
	}
	for _, r := range e.customRules {
		if r.re.MatchString(cmd) {
			matches = append(matches, RuleMatch{ID: r.id, Category: r.category, Score: r.score, Summary: r.summary, OperatorDefined: true})
		}
	}
	cleanExe := strings.TrimSuffix(p.Exe, " (deleted)")
	if e.moduleEnabled("origin") {
		if strings.Contains(p.Exe, " (deleted)") {
			matches = append(matches, RuleMatch{ID: "XDR.EXE_DELETED", Category: "integrity", Score: 65, Summary: "Running executable was deleted from disk", KillEligible: true})
		}
		if strings.Contains(cleanExe, "/memfd:") || strings.HasPrefix(cleanExe, "memfd:") {
			matches = append(matches, RuleMatch{ID: "XDR.MEMFD_EXEC", Category: "origin", Score: 110, Summary: "Process executes from anonymous memfd storage", KillEligible: true})
		}
		if pathUnderTemp(cleanExe) {
			matches = append(matches, RuleMatch{ID: "XDR.TEMP_EXEC", Category: "origin", Score: 55, Summary: "Executable launched from a temporary writable path", KillEligible: true})
		}
	}
	if e.moduleEnabled("lineage") && suspiciousLineage(p.ParentExe, cleanExe) {
		matches = append(matches, RuleMatch{ID: "XDR.WEB_SHELL_LINEAGE", Category: "lineage", Score: 95, Summary: "Network-facing service spawned a shell or interpreter", KillEligible: true})
	}
	if e.moduleEnabled("masquerading") && p.Comm != "" && cleanExe != "" {
		base := strings.TrimSuffix(filepath.Base(cleanExe), " (deleted)")
		if !strings.EqualFold(base, p.Comm) && !strings.HasPrefix(p.Comm, "(") {
			matches = append(matches, RuleMatch{ID: "XDR.NAME_PATH_MISMATCH", Category: "masquerading", Score: 15, Summary: "Process name differs from executable name"})
		}
	}
	if e.moduleEnabled("threat-intel") {
		for _, c := range connections {
			if feeds != nil && feeds.ContainsString(c.RemoteIP) {
				matches = append(matches, RuleMatch{ID: "XDR.THREAT_INTEL_C2", Category: "c2", Score: 100, Summary: "Process connected to a staged threat-intelligence prefix", KillEligible: true, Remote: c.RemoteIP})
			}
		}
	}
	if e.moduleEnabled("baseline") && baseline != nil {
		matches = append(matches, baseline.Evaluate(p, connections)...)
	}
	return combineMatches(matches)
}

func (e *XDRRuleEngine) moduleEnabled(name string) bool {
	return e.modules == nil || e.modules[name]
}

func pathUnderTemp(path string) bool {
	path = filepath.Clean(path)
	return path == "/tmp" || strings.HasPrefix(path, "/tmp/") || path == "/var/tmp" || strings.HasPrefix(path, "/var/tmp/") || path == "/dev/shm" || strings.HasPrefix(path, "/dev/shm/")
}

func suspiciousLineage(parent, exe string) bool {
	p := strings.ToLower(filepath.Base(strings.TrimSuffix(parent, " (deleted)")))
	c := strings.ToLower(filepath.Base(strings.TrimSuffix(exe, " (deleted)")))
	parents := map[string]bool{"nginx": true, "apache2": true, "httpd": true, "php-fpm": true, "php-fpm8.2": true, "php-fpm8.3": true, "caddy": true, "traefik": true}
	children := map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "python": true, "python3": true, "perl": true, "ruby": true, "node": true, "nc": true, "ncat": true, "socat": true}
	return parents[p] && children[c]
}

func combineMatches(matches []RuleMatch) XDRDecision {
	if len(matches) == 0 {
		return XDRDecision{Decision: "none"}
	}
	ids := make([]string, 0, len(matches))
	catsSet := make(map[string]struct{})
	summaries := make([]string, 0, len(matches))
	score := 0
	responseScore := 0
	killCategories := make(map[string]struct{})
	remote := ""
	seen := make(map[string]struct{})
	for _, m := range matches {
		if _, ok := seen[m.ID]; ok {
			continue
		}
		seen[m.ID] = struct{}{}
		ids = append(ids, m.ID)
		catsSet[m.Category] = struct{}{}
		score += m.Score
		if !m.OperatorDefined {
			responseScore += m.Score
		}
		summaries = append(summaries, m.Summary)
		if m.KillEligible {
			killCategories[m.Category] = struct{}{}
		}
		if remote == "" {
			remote = m.Remote
		}
	}
	if score > 250 {
		score = 250
	}
	if responseScore > 250 {
		responseScore = 250
	}
	cats := make([]string, 0, len(catsSet))
	for c := range catsSet {
		cats = append(cats, c)
	}
	sort.Strings(ids)
	sort.Strings(cats)
	decision := "alert"
	if responseScore >= 120 && len(killCategories) >= 2 {
		decision = "kill"
	} else if responseScore >= 80 {
		decision = "contain"
	}
	return XDRDecision{
		Score: score, ResponseScore: responseScore, RuleIDs: ids, Categories: cats,
		Summary: strings.Join(summaries, "; "), Decision: decision,
		KillSignals: len(killCategories), Remote: remote,
	}
}
