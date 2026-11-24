package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// StyxSessionSummary is the bounded logind session projection and the honest
// idle statement derived from it. IdleHint is `unavailable`, `inactive`
// (no ACTIVE=1 session; a temporal statement, never a lock claim) or `active`.
type StyxSessionSummary struct {
	Total      int    `json:"total"`
	Active     int    `json:"active"`
	Inactive   int    `json:"inactive"`
	Unreadable int    `json:"unreadable"`
	IdleHint   string `json:"idlehint"`
}

// ---------------------------------------------------------------------------
// IdleHint / logind session projection
// ---------------------------------------------------------------------------

// refreshSessions reads the bounded logind session directory and stores the
// honest idle statement. A missing directory or unreadable file is reported as
// `idlehint=unavailable`; it never fails the poll.
func (p *StyxPhase2Engine) refreshSessions(now time.Time) {
	if p == nil {
		return
	}
	root := p.sessionsRoot
	if root == "" {
		root = styxPhase2SessionsRoot
	}
	summary, err := readStyxSessions(root)
	var errText string
	if err != nil {
		summary = StyxSessionSummary{IdleHint: "unavailable"}
		errText = boundedStyxText(err)
	}
	p.mu.Lock()
	p.sessions = summary
	p.sessionsAt = now
	p.sessionsErr = errText
	p.mu.Unlock()
}

// readStyxSessions parses at most styxPhase2MaxSessions regular session files of
// at most styxPhase2MaxSessionBytes each. Non-regular files (systemd keeps a
// `.ref` FIFO next to each session) are skipped; a malformed session file is
// counted as unreadable, never silently treated as active.
func readStyxSessions(root string) (StyxSessionSummary, error) {
	summary := StyxSessionSummary{IdleHint: "unavailable"}
	entries, err := os.ReadDir(root)
	if err != nil {
		return summary, err
	}
	parsed := 0
	for _, entry := range entries {
		if parsed >= styxPhase2MaxSessions {
			break
		}
		name := entry.Name()
		if name == "" || strings.HasPrefix(name, ".") || !styxPhase2DecimalName(name) {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil || !info.Mode().IsRegular() {
			// The `.ref` FIFO and any other special file are not session records.
			continue
		}
		parsed++
		if info.Size() > styxPhase2MaxSessionBytes {
			summary.Unreadable++
			continue
		}
		data, readErr := styxPhase2ReadBounded(filepath.Join(root, name), styxPhase2MaxSessionBytes)
		if readErr != nil {
			summary.Unreadable++
			continue
		}
		session, ok := parseStyxSessionFile(data)
		if !ok {
			summary.Unreadable++
			continue
		}
		summary.Total++
		if session.active {
			summary.Active++
		} else {
			summary.Inactive++
		}
	}
	switch {
	case summary.Total == 0:
		summary.IdleHint = "unavailable"
	case summary.Active == 0:
		// No ACTIVE=1 logind session: a session-inactive timing statement is
		// supported by the file content. It is NOT a locked-screen claim.
		summary.IdleHint = "inactive"
	default:
		summary.IdleHint = "active"
	}
	return summary, nil
}

// styxPhase2Session is the strict projection of one session file.
type styxPhase2Session struct {
	uid      uint32
	active   bool
	state    string
	class    string
	typeName string
}

// parseStyxSessionFile strictly parses the documented fields of a logind session
// file. Unknown keys are tolerated (systemd owns that format and adds fields),
// but known fields must be valid, single-occurrence and bounded. A missing
// `SEAT=` is explicitly tolerated.
func parseStyxSessionFile(data []byte) (styxPhase2Session, bool) {
	var session styxPhase2Session
	seenUID, seenActive := false, false
	seenKeys := make(map[string]struct{}, 8)
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(rawLine, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || len(key) > 64 || len(value) > 512 {
			return styxPhase2Session{}, false
		}
		if !styxPhase2SessionKey(key) {
			return styxPhase2Session{}, false
		}
		if _, duplicate := seenKeys[key]; duplicate {
			return styxPhase2Session{}, false
		}
		seenKeys[key] = struct{}{}
		if strings.IndexFunc(value, func(character rune) bool {
			return character < 0x20 || character == 0x7f
		}) >= 0 {
			return styxPhase2Session{}, false
		}
		switch key {
		case "UID":
			uid, uidErr := parseStyxUint(value, 32)
			if uidErr != nil {
				return styxPhase2Session{}, false
			}
			session.uid = uint32(uid)
			seenUID = true
		case "ACTIVE":
			active, activeErr := parseStyxUint(value, 1)
			if activeErr != nil {
				return styxPhase2Session{}, false
			}
			session.active = active == 1
			seenActive = true
		case "STATE":
			if !styxPhase2SessionToken(value) {
				return styxPhase2Session{}, false
			}
			session.state = value
		case "CLASS":
			if !styxPhase2SessionToken(value) {
				return styxPhase2Session{}, false
			}
			session.class = value
		case "TYPE":
			if !styxPhase2SessionToken(value) {
				return styxPhase2Session{}, false
			}
			session.typeName = value
		}
	}
	if !seenUID || !seenActive {
		return styxPhase2Session{}, false
	}
	switch session.state {
	case "", "online", "active", "closing":
	default:
		return styxPhase2Session{}, false
	}
	return session, true
}

// styxPhase2SessionKey accepts an upper-case systemd field name.
func styxPhase2SessionKey(key string) bool {
	for i := 0; i < len(key); i++ {
		character := key[i]
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

// styxPhase2SessionToken accepts the bounded lower-case token vocabulary used by
// STATE/CLASS/TYPE.
func styxPhase2SessionToken(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for i := 0; i < len(value); i++ {
		character := value[i]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

// styxPhase2DecimalName accepts a session id file name (decimal digits only).
func styxPhase2DecimalName(name string) bool {
	if name == "" || len(name) > 20 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

// styxPhase2ReadBounded reads at most limit+1 bytes so an oversized file is
// detected instead of read into memory.
func styxPhase2ReadBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data := make([]byte, 0, 1024)
	buffer := make([]byte, 4096)
	for int64(len(data)) <= limit {
		read, readErr := file.Read(buffer)
		if read > 0 {
			data = append(data, buffer[:read]...)
			if int64(len(data)) > limit {
				return nil, errors.New("logind session file exceeds the bounded reader limit")
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return nil, readErr
		}
	}
	return data, nil
}
