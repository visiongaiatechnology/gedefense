//go:build linux

// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var tcpStateNames = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

func readSystemSockets() []systemSocketRow {
	uidNames := readPasswdUIDs()
	inodeProcs := scanReadableSocketInodes()

	out := make([]systemSocketRow, 0, 128)
	specs := []struct {
		path  string
		proto string
		ipv6  bool
	}{
		{"/proc/net/tcp", "tcp", false},
		{"/proc/net/tcp6", "tcp6", true},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/udp6", "udp6", true},
	}
	for _, spec := range specs {
		f, err := os.Open(spec.path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 {
				continue
			}
			stHex := strings.ToUpper(fields[3])
			// Skip passive listening sockets; only active/established/half-open connections belong here.
			if stHex == "0A" || stHex == "07" {
				continue
			}
			remIP, remPort, ok := decodeProcAddrHex(fields[2], spec.ipv6)
			if !ok || remPort == 0 || remIP == "" || remIP == "0.0.0.0" || remIP == "::" {
				continue
			}
			locIP, locPort, _ := decodeProcAddrHex(fields[1], spec.ipv6)
			uid64, _ := strconv.ParseUint(fields[7], 10, 32)
			uid := uint32(uid64)
			inode := fields[9]
			state := tcpStateNames[stHex]
			if state == "" {
				if strings.HasPrefix(spec.proto, "udp") {
					state = "ACTIVE"
				} else {
					state = stHex
				}
			}
			proc := inodeProcs[inode]
			out = append(out, systemSocketRow{
				Proto:      spec.proto,
				LocalIP:    locIP,
				LocalPort:  locPort,
				RemoteIP:   remIP,
				RemotePort: remPort,
				State:      state,
				UID:        uid,
				User:       uidNames[uid],
				Inode:      inode,
				PID:        proc.pid,
				Comm:       proc.comm,
			})
			if len(out) >= 2048 {
				break
			}
		}
		f.Close()
	}
	return out
}

type inodeProcInfo struct {
	pid  int
	comm string
}

func scanReadableSocketInodes() map[string]inodeProcInfo {
	result := make(map[string]inodeProcInfo, 128)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // gracefully skip processes belonging to other UIDs when unprivileged
		}
		commRaw, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		comm := strings.TrimSpace(string(commRaw))
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if inode != "" {
				result[inode] = inodeProcInfo{pid: pid, comm: comm}
			}
		}
	}
	return result
}

func readPasswdUIDs() map[uint32]string {
	out := make(map[uint32]string, 32)
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 3 {
			continue
		}
		uid, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			continue
		}
		out[uint32(uid)] = parts[0]
	}
	return out
}

func decodeProcAddrHex(v string, ipv6 bool) (string, uint16, bool) {
	host, portHex, ok := strings.Cut(v, ":")
	if !ok {
		return "", 0, false
	}
	p, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, false
	}
	b, err := hex.DecodeString(host)
	if err != nil {
		return "", 0, false
	}
	if !ipv6 && len(b) == 4 {
		b[0], b[3] = b[3], b[0]
		b[1], b[2] = b[2], b[1]
		return net.IP(b).String(), uint16(p), true
	}
	if ipv6 && len(b) == 16 {
		for i := 0; i < 16; i += 4 {
			b[i], b[i+3] = b[i+3], b[i]
			b[i+1], b[i+2] = b[i+2], b[i+1]
		}
		ip := net.IP(b)
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), uint16(p), true
		}
		return ip.String(), uint16(p), true
	}
	return "", 0, false
}
