// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PHP upload-progress mitigation audit.
//
// The disclosed PHP vulnerability class is suspected to live in the session upload-progress
// handler, which PHP executes before the application script. A web application firewall loaded
// through auto_prepend_file therefore cannot protect that path, and an L7 edge only helps while a
// request can still be refused before PHP. The durable in-host mitigation is the PHP runtime
// setting itself: session.upload_progress.enabled must be Off in every web SAPI, and no pool or
// per-directory override may turn it back on.
//
// This check reads the effective setting from the host instead of trusting a deployment note. It is
// bounded: at most phpWebIniFileLimit web SAPIs, each file capped at phpIniByteLimit, and the
// per-directory overrides are found by a depth- and count-limited walk below the usual document
// roots. CLI-only PHP installations are deliberately not counted as exposure - a CLI SAPI cannot
// receive an upload - but they are also not counted as protection.

const (
	phpUploadProgressDirective = "session.upload_progress.enabled"
	phpUploadProgressCheckID   = "web.php-upload-progress"
	phpWebIniFileLimit         = 64
	phpIniByteLimit            = 1 << 20
	phpOverrideLineLimit       = 200000
	phpScanDirFileLimit        = 64
	phpUserIniDepth            = 3
	phpUserIniFileLimit        = 2048
)

// phpWebIniPatterns are the web SAPIs whose effective configuration decides whether an HTTP
// upload can reach the upload-progress handler.
var phpWebIniPatterns = []string{
	"etc/php/*/fpm/php.ini",
	"etc/php/*/apache2/php.ini",
	"www/server/php/*/etc/php.ini",
	"usr/local/lsws/lsphp*/etc/php/*/litespeed/php.ini",
}

// phpPoolOverridePatterns are the pool files that can pin the directive with php_admin_value or
// php_value. An admin value cannot be overridden per directory, so it decides the effective state
// for that pool.
var phpPoolOverridePatterns = []string{
	"etc/php/*/fpm/pool.d/*.conf",
	"etc/php/*/fpm/php-fpm.conf",
	"www/server/php/*/etc/php-fpm.conf",
	"www/server/php/*/etc/php-fpm.d/*.conf",
	"usr/local/lsws/lsphp*/etc/php/*/litespeed/php-fpm.conf",
}

// phpUserIniRoots are the common document-root parents. The walk finds only files named
// .user.ini, so it observes the per-directory override mechanism without reading site content.
var phpUserIniRoots = []string{"www/wwwroot", "var/www", "home", "srv/www"}

type phpUploadProgressAudit struct {
	WebIniFiles  int
	ProtectedIni int
	ExposedIni   []string
	OverrideOn   []string
	Unreadable   []string
}

func (a phpUploadProgressAudit) exposed() bool {
	return len(a.ExposedIni) > 0 || len(a.OverrideOn) > 0
}

func (a phpUploadProgressAudit) evidence() string {
	parts := []string{
		fmt.Sprintf("web sapi ini=%d", a.WebIniFiles),
		fmt.Sprintf("explicit off=%d", a.ProtectedIni),
	}
	if len(a.ExposedIni) > 0 {
		parts = append(parts, "effective on="+boundedPHPPaths(a.ExposedIni))
	}
	if len(a.OverrideOn) > 0 {
		parts = append(parts, "override on="+boundedPHPPaths(a.OverrideOn))
	}
	if len(a.Unreadable) > 0 {
		parts = append(parts, "unreadable="+boundedPHPPaths(a.Unreadable))
	}
	return strings.Join(parts, ", ")
}

func boundedPHPPaths(paths []string) string {
	const max = 3
	if len(paths) <= max {
		return strings.Join(paths, ",")
	}
	return strings.Join(paths[:max], ",") + fmt.Sprintf(" (+%d more)", len(paths)-max)
}

// phpUploadProgressCheck reports whether the host would still route an upload through PHP's
// session upload-progress handler. The PHP default is On, so an ini file that never names the
// directive is exposure, not an unknown.
func (c *HardeningCollector) phpUploadProgressCheck() HardeningCheck {
	check := baseHardeningCheck(phpUploadProgressCheckID, "web", "PHP upload-progress handler disabled", 10, false)
	audit := inspectPHPUploadProgress(c.root)
	check.Evidence = audit.evidence()
	switch {
	case audit.exposed():
		check.State = hardeningStateUnprotected
		check.Recommendation = "Set session.upload_progress.enabled = Off in every web SAPI php.ini and remove pool or per-directory overrides that re-enable it; keep it off until the official PHP update is installed."
	case audit.WebIniFiles == 0:
		// No PHP web runtime exists on this host: there is no handler to protect, and claiming a
		// posture for it would be an invented result.
		return unavailableHardening(check)
	case len(audit.Unreadable) > 0:
		check.State = hardeningStatePartial
		check.Recommendation = "Make the PHP SAPI configuration readable so the effective upload-progress setting can be verified."
	default:
		check.State = hardeningStateProtected
	}
	return check
}

func inspectPHPUploadProgress(root string) phpUploadProgressAudit {
	if strings.TrimSpace(root) == "" {
		root = string(filepath.Separator)
	}
	audit := phpUploadProgressAudit{}
	seen := make(map[string]struct{})
	for _, pattern := range phpWebIniPatterns {
		matches, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		sort.Strings(matches)
		for _, ini := range matches {
			if audit.WebIniFiles >= phpWebIniFileLimit {
				break
			}
			if _, exists := seen[ini]; exists {
				continue
			}
			seen[ini] = struct{}{}
			audit.WebIniFiles++
			files := []string{ini}
			if scanDir := phpScanDirFor(ini); scanDir != "" {
				extra, _ := filepath.Glob(filepath.Join(scanDir, "*.ini"))
				sort.Strings(extra)
				if len(extra) > phpScanDirFileLimit {
					extra = extra[:phpScanDirFileLimit]
				}
				files = append(files, extra...)
			}
			effective, _, unreadable := phpUploadProgressEffective(files)
			audit.Unreadable = append(audit.Unreadable, unreadable...)
			if len(unreadable) == len(files) {
				continue
			}
			if effective {
				audit.ExposedIni = append(audit.ExposedIni, ini)
				continue
			}
			audit.ProtectedIni++
		}
	}
	audit.OverrideOn = append(audit.OverrideOn, phpPoolOverridesOn(root)...)
	audit.OverrideOn = append(audit.OverrideOn, phpUserIniOverridesOn(root)...)
	audit.OverrideOn = uniqueSortedPHP(audit.OverrideOn, phpWebIniFileLimit)
	audit.Unreadable = uniqueSortedPHP(audit.Unreadable, phpWebIniFileLimit)
	return audit
}

// phpScanDirFor returns the additional-ini directory PHP reads after the main php.ini, when the
// SAPI layout is known.
func phpScanDirFor(ini string) string {
	dir := filepath.Dir(ini)
	switch filepath.Base(dir) {
	case "fpm", "apache2":
		return filepath.Join(dir, "conf.d")
	case "litespeed":
		return filepath.Join(filepath.Dir(dir), "mods-available")
	case "etc":
		if info, err := os.Stat(filepath.Join(dir, "php.d")); err == nil && info.IsDir() {
			return filepath.Join(dir, "php.d")
		}
	}
	return ""
}

// phpUploadProgressEffective applies the files in PHP's load order. The default is On, so an
// absent directive leaves the handler enabled.
func phpUploadProgressEffective(files []string) (bool, bool, []string) {
	effective := true
	explicit := false
	unreadable := make([]string, 0, 1)
	for _, file := range files {
		value, found, err := phpReadUploadProgressDirective(file)
		if err != nil {
			unreadable = append(unreadable, file)
			continue
		}
		if found {
			effective = value
			explicit = true
		}
	}
	return effective, explicit, unreadable
}

func phpReadUploadProgressDirective(path string) (bool, bool, error) {
	value, found, err := scanPHPDirective(path, phpUploadProgressDirective)
	return value, found, err
}

// scanPHPDirective reads one bounded configuration file and returns the last assignment of the
// named boolean directive. Both the plain php.ini form and the php_admin_value[...] /
// php_value[...] pool form are accepted.
func scanPHPDirective(path, directive string) (bool, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, false, err
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, phpIniByteLimit))
	value, found := false, false
	for lines := 0; lines < phpOverrideLineLimit; lines++ {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			if parsed, ok := phpDirectiveLine(line, directive); ok {
				value, found = parsed, true
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return value, found, nil
			}
			return value, found, readErr
		}
	}
	return value, found, nil
}

func phpDirectiveLine(raw, directive string) (bool, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
		return false, false
	}
	equals := strings.IndexByte(line, '=')
	if equals <= 0 {
		return false, false
	}
	key := phpDirectiveKey(strings.TrimSpace(line[:equals]))
	if !strings.EqualFold(key, directive) {
		return false, false
	}
	return phpBooleanValue(strings.TrimSpace(line[equals+1:]))
}

func phpDirectiveKey(key string) string {
	if open := strings.IndexByte(key, '['); open >= 0 {
		if close := strings.LastIndexByte(key, ']'); close > open {
			return strings.TrimSpace(key[open+1 : close])
		}
	}
	return key
}

func phpBooleanValue(raw string) (bool, bool) {
	value := strings.TrimSpace(raw)
	if len(value) > 0 && (value[0] == '"' || value[0] == 0x27) {
		if close := strings.IndexByte(value[1:], value[0]); close >= 0 {
			value = value[1 : 1+close]
		}
	} else if comment := strings.IndexByte(value, ';'); comment >= 0 {
		value = value[:comment]
	}
	value = strings.TrimSpace(strings.Trim(value, "\"'"))
	switch strings.ToLower(value) {
	case "on", "1", "true", "yes":
		return true, true
	case "off", "0", "false", "no", "":
		return false, true
	default:
		// PHP treats an unrecognised boolean as false. It is not a verifiable On, so it cannot be
		// reported as exposure; the recommendation still covers it because the value is not Off.
		return false, true
	}
}

func phpPoolOverridesOn(root string) []string {
	out := make([]string, 0, 2)
	seen := make(map[string]struct{})
	for _, pattern := range phpPoolOverridePatterns {
		matches, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		sort.Strings(matches)
		for _, path := range matches {
			if len(out) >= phpWebIniFileLimit {
				return out
			}
			if _, exists := seen[path]; exists {
				continue
			}
			seen[path] = struct{}{}
			if value, found, err := scanPHPDirective(path, phpUploadProgressDirective); err == nil && found && value {
				out = append(out, path)
			}
		}
	}
	return out
}

func phpUserIniOverridesOn(root string) []string {
	out := make([]string, 0, 2)
	for _, base := range phpUserIniRoots {
		start := filepath.Join(root, filepath.FromSlash(base))
		info, err := os.Stat(start)
		if err != nil || !info.IsDir() {
			continue
		}
		phpWalkUserInis(start, 0, &out)
	}
	return out
}

func phpWalkUserInis(dir string, depth int, out *[]string) {
	if depth > phpUserIniDepth || len(*out) >= phpUserIniFileLimit {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if len(*out) >= phpUserIniFileLimit {
			return
		}
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "vendor", ".cache", "plugins", "themes", "uploads", "languages":
				continue
			}
			phpWalkUserInis(path, depth+1, out)
			continue
		}
		if entry.Name() != ".user.ini" {
			continue
		}
		if value, found, err := scanPHPDirective(path, phpUploadProgressDirective); err == nil && found && value {
			*out = append(*out, path)
		}
	}
}

func uniqueSortedPHP(values []string, limit int) []string {
	if len(values) == 0 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
