//go:build linux

package webposture

import (
	"context"
	"debug/elf"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// maxProcEntries bounds the /proc pid directory walk.
const (
	maxProcEntries = 65536
	maxFDPerPID    = 256
)

var (
	nginxVersionPattern = regexp.MustCompile(`nginx/([0-9]+\.[0-9]+\.[0-9]+[a-z0-9]*)`)
	opensslPattern      = regexp.MustCompile(`OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]*)`)
	withModulePattern   = regexp.MustCompile(`--with-([a-z0-9_]+)`)
)

// webCommNames are the comm values a web server process may carry. The master
// and the workers both match; the report keeps one row per process.
var webCommNames = []string{"nginx", "apache2", "httpd", "php-fpm", "caddy", "haproxy", "lighttpd", "openresty"}

// discoverServers walks /proc without exec and without network access. It reads
// /proc/<pid>/exe, comm, status and fd, plus the ELF .rodata section of the
// binary for build flags and version strings.
func discoverServers(ctx context.Context, maxServers int) ([]Server, []string, string) {
	evidence := make([]string, 0, 8)
	if maxServers <= 0 {
		maxServers = DefaultMaxServers
	}
	listeners, listenerErr := readListenerInodes()
	if listenerErr != nil {
		evidence = append(evidence, "socket table unavailable: "+listenerErr.Error())
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, evidence, "/proc is not readable"
	}
	if len(entries) > maxProcEntries {
		entries = entries[:maxProcEntries]
	}
	servers := make([]Server, 0, 4)
	seen := make(map[int]struct{}, 4)
	resolvedByPID := make(map[int]string, 8)
	elfCache := make(map[string]elfScanResult, 4)
	for _, entry := range entries {
		if len(servers) >= maxServers {
			evidence = append(evidence, "server bound reached ("+strconv.Itoa(maxServers)+")")
			break
		}
		if ctx != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				break
			}
		}
		if !entry.IsDir() {
			continue
		}
		pid, pidErr := strconv.Atoi(entry.Name())
		if pidErr != nil || pid <= 0 {
			continue
		}
		if _, dup := seen[pid]; dup {
			continue
		}
		seen[pid] = struct{}{}
		comm, readErr := readProcText("/proc/"+strconv.Itoa(pid)+"/comm", 64)
		if readErr != nil || !isWebComm(comm) {
			continue
		}
		server, scanEvidence := inspectProcess(pid, comm, listeners, resolvedByPID, elfCache)
		if server == nil {
			continue
		}
		servers = append(servers, *server)
		evidence = append(evidence, scanEvidence...)
		if len(evidence) > 24 {
			evidence = evidence[:24]
		}
	}
	return servers, evidence, ""
}

// isWebComm classifies a process name using the bounded web-server name list.
func isWebComm(comm string) bool {
	lower := strings.ToLower(comm)
	for _, name := range webCommNames {
		if strings.Contains(lower, name) {
			return true
		}
	}
	return false
}

func isWebBinaryPath(path string) bool {
	lowerExe := strings.ToLower(path)
	for _, name := range []string{"nginx", "apache2", "httpd", "caddy", "haproxy", "lighttpd", "openresty"} {
		if strings.Contains(lowerExe, name) {
			return true
		}
	}
	return false
}

// resolveProcessBinary determines the executable path for a web process.
// An unprivileged control plane receives EACCES on /proc/<root-pid>/exe, so we
// fall back cleanly to /proc/<pid>/cmdline (e.g. `nginx: master process /path/sbin/nginx`)
// and parent-PID lookup for worker children.
func resolveProcessBinary(pid int, resolvedByPID map[int]string) (string, string) {
	if cached, ok := resolvedByPID[pid]; ok {
		return cached, "/proc/" + strconv.Itoa(pid) + "/exe -> " + cached
	}
	pidStr := strconv.Itoa(pid)
	if target, err := os.Readlink("/proc/" + pidStr + "/exe"); err == nil {
		exe := strings.TrimSuffix(target, " (deleted)")
		if isWebBinaryPath(exe) {
			resolvedByPID[pid] = exe
			return exe, "/proc/" + pidStr + "/exe -> " + exe
		}
		return "", ""
	}
	if rawCmd, err := readProcText("/proc/"+pidStr+"/cmdline", 4096); err == nil {
		if exe := binaryPathFromCmdline(rawCmd); exe != "" {
			resolvedByPID[pid] = exe
			return exe, "/proc/" + pidStr + "/cmdline -> " + exe
		}
	}
	if ppid := readParentPID(pid); ppid > 1 && ppid != pid {
		if parentExe, ok := resolvedByPID[ppid]; ok && parentExe != "" {
			return parentExe, "/proc/" + pidStr + " (ppid=" + strconv.Itoa(ppid) + ") -> " + parentExe
		}
		if rawParentCmd, err := readProcText("/proc/"+strconv.Itoa(ppid)+"/cmdline", 4096); err == nil {
			if exe := binaryPathFromCmdline(rawParentCmd); exe != "" {
				resolvedByPID[ppid] = exe
				return exe, "/proc/" + pidStr + " (ppid=" + strconv.Itoa(ppid) + ") -> " + exe
			}
		}
	}
	return "", ""
}

func readParentPID(pid int) int {
	raw, err := readProcText("/proc/"+strconv.Itoa(pid)+"/status", 4096)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "PPid:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			ppid, convErr := strconv.Atoi(value)
			if convErr == nil {
				return ppid
			}
			return 0
		}
	}
	return 0
}

type elfScanResult struct {
	version   string
	openssl   string
	modules   []string
	tlsStatic bool
	evidence  []string
}

// inspectProcess collects the bounded facts about one candidate process.
func inspectProcess(pid int, comm string, listeners map[string][]string, resolvedByPID map[int]string, elfCache map[string]elfScanResult) (*Server, []string) {
	exe, originEvidence := resolveProcessBinary(pid, resolvedByPID)
	if exe == "" || !isWebBinaryPath(exe) {
		return nil, nil
	}
	server := &Server{PID: pid, Comm: comm, Binary: exe, Modules: []string{}, Configs: []ConfigHit{}, Listen: []string{}, Affected: []AdvisoryHit{}}
	evidence := []string{originEvidence}
	cached, ok := elfCache[exe]
	if !ok {
		v, o, m, t, ev := scanELF(exe)
		cached = elfScanResult{version: v, openssl: o, modules: m, tlsStatic: t, evidence: ev}
		elfCache[exe] = cached
	}
	server.Version = cached.version
	server.OpenSSL = cached.openssl
	server.Modules = append([]string{}, cached.modules...)
	server.TLSStatic = cached.tlsStatic
	evidence = append(evidence, cached.evidence...)
	if inodes, err := readSocketInodes(pid); err == nil && len(inodes) > 0 {
		for _, inode := range inodes {
			for _, endpoint := range listeners[inode] {
				server.Listen = appendUniqueListen(server.Listen, endpoint)
			}
		}
	} else if err != nil && os.IsPermission(err) {
		server.fdInaccessible = true
		evidence = append(evidence, "/proc/"+strconv.Itoa(pid)+"/fd EACCES (unprivileged scan); using /proc/net listener fallback")
	}
	return server, evidence
}

// scanELF reads the build evidence from the binary's .rodata section with a
// hard size cap. An unreadable binary is reported as unknown, not guessed at.
func scanELF(path string) (version, openssl string, modules []string, tlsStatic bool, evidence []string) {
	file, err := elf.Open(path)
	if err != nil {
		return "", "", []string{}, false, []string{"ELF unreadable: " + path}
	}
	defer file.Close()
	modules = []string{}
	section := file.Section(".rodata")
	if section == nil {
		// Stripped or different layout: fall back to the whole file's string
		// table bounded to the same read budget.
		return "", "", []string{}, false, []string{"binary has no .rodata section: " + path}
	}
	reader, err := section.Data()
	if err != nil {
		return "", "", []string{}, false, []string{"ELF .rodata unreadable: " + path}
	}
	if len(reader) > maxELFBytes {
		reader = reader[:maxELFBytes]
	}
	data := reader
	evidence = append(evidence, "ELF .rodata scanned: "+strconv.Itoa(len(data))+" bytes")
	text := string(data)
	if match := nginxVersionPattern.FindStringSubmatch(text); len(match) == 2 {
		version = match[1]
	}
	if match := opensslPattern.FindStringSubmatch(text); len(match) == 2 {
		openssl = "OpenSSL " + match[1]
	}
	seen := make(map[string]struct{}, 8)
	for _, match := range withModulePattern.FindAllStringSubmatch(text, 64) {
		name := strings.TrimSuffix(match[1], "_module")
		if name == "" || len(name) > 32 {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		modules = append(modules, name)
	}
	hasTLS := false
	for _, name := range modules {
		if name == "ssl" || name == "http_ssl" {
			hasTLS = true
		}
	}
	tlsStatic = hasTLS && openssl == ""
	return version, openssl, modules, tlsStatic, evidence
}

// readSocketInodes maps one process's open socket inodes (bounded fd walk).
func readSocketInodes(pid int) ([]string, error) {
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > 4096 {
		entries = entries[:4096]
	}
	inodes := make([]string, 0, 8)
	for index, entry := range entries {
		if index >= maxFDPerPID {
			break
		}
		target, err := os.Readlink(dir + "/" + entry.Name())
		if err != nil {
			continue
		}
		if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		inode := target[len("socket:[") : len(target)-1]
		if inode == "" || len(inode) > 20 {
			continue
		}
		inodes = append(inodes, inode)
	}
	return inodes, nil
}

// readListenerInodes parses /proc/net/tcp and /proc/net/tcp6 into a map of
// socket inode -> rendered local endpoints for LISTEN sockets.
func readListenerInodes() (map[string][]string, error) {
	out := make(map[string][]string, 16)
	var firstErr error
	for _, family := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := readProcText(family, 1<<20)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		lines := strings.Split(data, "\n")
		if len(lines) > 65536 {
			lines = lines[:65536]
		}
		for index, line := range lines {
			if index == 0 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			if fields[3] != "0A" { // TCP_LISTEN
				continue
			}
			endpoint, renderErr := renderLocalEndpoint(fields[1])
			if renderErr != nil {
				continue
			}
			inode := fields[9]
			if len(inode) > 20 {
				continue
			}
			out[inode] = appendUniqueListen(out[inode], endpoint)
		}
	}
	return out, nil
}

// renderLocalEndpoint converts the /proc hex address into host:port form.
func renderLocalEndpoint(raw string) (string, error) {
	addressHex, portHex, ok := strings.Cut(raw, ":")
	if !ok || len(portHex) != 4 {
		return "", errors.New("malformed /proc socket address")
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil || port == 0 {
		return "", errors.New("malformed /proc socket port")
	}
	ip, err := decodeProcAddress(addressHex)
	if err != nil {
		return "", err
	}
	if ip.To4() != nil {
		return ip.String() + ":" + strconv.FormatUint(port, 10), nil
	}
	return "[" + ip.String() + "]:" + strconv.FormatUint(port, 10), nil
}

// decodeProcAddress decodes the native-endian hex address form used by
// /proc/net/tcp (4 bytes) and /proc/net/tcp6 (4 little-endian words).
func decodeProcAddress(raw string) (net.IP, error) {
	switch len(raw) {
	case 8:
		bytes := make([]byte, 4)
		for index := 0; index < 4; index++ {
			value, err := strconv.ParseUint(raw[index*2:index*2+2], 16, 8)
			if err != nil {
				return nil, err
			}
			bytes[3-index] = byte(value)
		}
		return net.IP(bytes), nil
	case 32:
		bytes := make([]byte, 16)
		for word := 0; word < 4; word++ {
			chunk := raw[word*8 : word*8+8]
			for index := 0; index < 4; index++ {
				value, err := strconv.ParseUint(chunk[index*2:index*2+2], 16, 8)
				if err != nil {
					return nil, err
				}
				bytes[word*4+3-index] = byte(value)
			}
		}
		return net.IP(bytes), nil
	default:
		return nil, errors.New("unsupported /proc address width")
	}
}

// readProcText reads a bounded /proc text file.
func readProcText(path string, limit int) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)))
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(data), "\x00"), nil
}

// appendUniqueListen adds one rendered endpoint if it is new, bounded to 16.
func appendUniqueListen(dst []string, endpoint string) []string {
	if len(dst) >= 16 || endpoint == "" {
		return dst
	}
	for _, existing := range dst {
		if existing == endpoint {
			return dst
		}
	}
	return append(dst, endpoint)
}

func binaryPathFromCmdline(raw string) string {
	fields := strings.Fields(strings.ReplaceAll(raw, "\x00", " "))
	for _, token := range fields {
		token = strings.TrimSpace(token)
		if !strings.HasPrefix(token, "/") || strings.HasPrefix(token, "-") || len(token) > 512 {
			continue
		}
		base := strings.ToLower(filepath.Base(token))
		for _, name := range []string{"nginx", "apache2", "httpd", "caddy", "haproxy", "lighttpd", "openresty"} {
			if base == name || strings.HasPrefix(base, name) {
				clean := filepath.Clean(token)
				if info, err := os.Lstat(clean); err == nil && info.Mode().IsRegular() {
					return clean
				}
			}
		}
	}
	return ""
}

func fillListenersFromProcNet(server *Server, files []ConfigFile) {
	if server == nil || len(server.Listen) > 0 || !server.fdInaccessible {
		return
	}
	listeners, err := readListenerInodes()
	if err != nil {
		return
	}
	wantPorts := make(map[string]struct{})
	for _, file := range files {
		for _, p := range file.ListenPorts {
			wantPorts[strconv.Itoa(p)] = struct{}{}
		}
	}
	if strings.Contains(strings.ToLower(server.Comm+" "+server.Binary), "nginx") {
		for _, p := range []string{"80", "443", "8443"} {
			wantPorts[p] = struct{}{}
		}
	}
	for _, endpoints := range listeners {
		for _, ep := range endpoints {
			idx := strings.LastIndex(ep, ":")
			if idx < 0 {
				continue
			}
			if _, ok := wantPorts[ep[idx+1:]]; ok {
				server.Listen = appendUniqueListen(server.Listen, ep)
			}
		}
	}
}
