package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// crossViewToleratedPathPrefixes are installation-managed executable roots.
var crossViewToleratedPathPrefixes = []string{
	"/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/",
	"/opt/", "/usr/libexec/",
}

// crossViewSuspiciousExecRoots are the writable drop roots a raw tap must not
// execute from (BPFDoor class).
var crossViewSuspiciousExecRoots = []string{
	"/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/user/", "/var/run/user/",
}

// crossViewCore is the subset of the privileged client the AP-3 contract needs.
type crossViewCore interface {
	CrossViewStatus() (CoreCrossViewStatus, error)
	CrossViewReport() (string, error)
	CrossViewEvents() ([]CoreCrossViewEvent, uint64, error)
}

// crossViewProcessPath resolves the executable behind a pid, keeping the kernel's
// " (deleted)" marker because it is part of the evidence. Failures are bounded
// and become "unknown" (never a guess).
func crossViewProcessPath(pid uint32) string {
	if pid == 0 || pid > 4_194_304 {
		return "unknown"
	}
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "unknown"
	}
	if target == "" || len(target) > crossViewPathMaxBytes || !filepath.IsAbs(target) ||
		strings.ContainsAny(target, "\x00\r\n\t") {
		return "unknown"
	}
	return target
}

func crossViewPathUnderAny(path string, prefixes []string) bool {
	if path == "" || path == "unknown" {
		return false
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// crossViewTapOwnerPath resolves the executable behind a tap record. The kernel
// hook fires in the calling thread, so a short-lived thread id can already be
// gone by the time the control plane drains; tap records therefore carry the
// emitting tgid in the wire `ino` field as a fallback identity.
func crossViewTapOwnerPath(event CoreCrossViewEvent) string {
	if path := crossViewProcessPath(uint32(event.PID)); path != "unknown" {
		return path
	}
	if event.Ino > 0 && event.Ino <= 0xffffffff {
		if path := crossViewProcessPath(uint32(event.Ino)); path != "unknown" {
			return path
		}
	}
	return "unknown"
}

// claimCrossViewRecord dedupes by the mandated (ts,domain,kind,pid,ino) key.
func (e *XDREngine) claimCrossViewRecord(event CoreCrossViewEvent, now time.Time) bool {
	key := fmt.Sprintf("event:%d|%d|%d|%d|%d", event.TsNS, event.Domain, event.Kind, event.PID, event.Ino)
	return e.claimCrossViewSeen(key, now, crossViewDedupeTTL)
}

// claimCrossViewSeen is the bounded dedupe/bookkeeping primitive.
func (e *XDREngine) claimCrossViewSeen(key string, now time.Time, ttl time.Duration) bool {
	e.crossViewMu.Lock()
	defer e.crossViewMu.Unlock()
	if e.crossViewSeen == nil {
		e.crossViewSeen = make(map[string]time.Time)
	}
	if until, exists := e.crossViewSeen[key]; exists && now.Before(until) {
		return false
	}
	e.crossViewSeen[key] = now.Add(ttl)
	if len(e.crossViewSeen) > crossViewSeenLimit {
		for seenKey, until := range e.crossViewSeen {
			if !until.After(now) {
				delete(e.crossViewSeen, seenKey)
			}
		}
	}
	return true
}

func crossViewTarget(event CoreCrossViewEvent) string {
	target := fmt.Sprintf("cross-view:ts:%d:pid:%d:uid:%d:dev:%d:ino:%d",
		event.TsNS, event.PID, event.UID, event.Dev, event.Ino)
	return crossViewBounded(target, crossViewEvidenceTargetBytes)
}

func crossViewBounded(text string, max int) string {
	text = strings.TrimSpace(strings.Join(strings.Fields(text), " "))
	if max > 0 && len(text) > max {
		text = text[:max]
	}
	return text
}
