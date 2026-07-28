//go:build linux

package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func scanLinuxProcesses(maxCmdBytes int) (map[string]ProcessSample, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make(map[string]ProcessSample, len(entries)/2)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		p, err := readLinuxProcess(pid, maxCmdBytes)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%d:%d", p.PID, p.StartTicks)
		out[key] = p
	}
	return out, nil
}

func readLinuxProcess(pid, maxCmdBytes int) (ProcessSample, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	stat, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return ProcessSample{}, err
	}
	ppid, start, comm, err := parseProcStat(string(stat))
	if err != nil {
		return ProcessSample{}, err
	}
	uid, gid := readProcIDs(filepath.Join(base, "status"))
	exe, _ := os.Readlink(filepath.Join(base, "exe"))
	parentExe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", ppid))
	cmd, _ := readBounded(filepath.Join(base, "cmdline"), maxCmdBytes)
	cmd = strings.TrimSpace(strings.ReplaceAll(cmd, "\x00", " "))
	if cmd == "" {
		cmd = comm
	}
	cg, _ := readBounded(filepath.Join(base, "cgroup"), 16*1024)
	return ProcessSample{PID: pid, PPID: ppid, StartTicks: start, UID: uid, GID: gid, Comm: comm, Exe: exe, ParentExe: parentExe, Cmdline: cmd, CmdSHA256: commandDigest(cmd), Cgroup: strings.TrimSpace(cg)}, nil
}

func parseProcStat(s string) (ppid int, startTicks uint64, comm string, err error) {
	open := strings.IndexByte(s, '(')
	close := strings.LastIndexByte(s, ')')
	if open < 0 || close <= open || close+2 > len(s) {
		return 0, 0, "", errors.New("malformed proc stat")
	}
	comm = s[open+1 : close]
	fields := strings.Fields(s[close+2:]) // starts at field 3 (state)
	if len(fields) <= 19 {
		return 0, 0, "", errors.New("short proc stat")
	}
	ppid64, err := strconv.ParseInt(fields[1], 10, 32) // field 4
	if err != nil {
		return 0, 0, "", err
	}
	start, err := strconv.ParseUint(fields[19], 10, 64) // field 22
	if err != nil {
		return 0, 0, "", err
	}
	return int(ppid64), start, comm, nil
}

func readProcIDs(path string) (uint32, uint32) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	var uid, gid uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			uid, _ = strconv.ParseUint(strings.Fields(line)[1], 10, 32)
		}
		if strings.HasPrefix(line, "Gid:") {
			gid, _ = strconv.ParseUint(strings.Fields(line)[1], 10, 32)
		}
	}
	return uint32(uid), uint32(gid)
}

func readBounded(path string, max int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return "", err
	}
	if len(b) > max {
		b = b[:max]
	}
	return string(b), nil
}

func correlateLinuxConnections(processes map[string]ProcessSample) (map[string][]NetConnection, int) {
	sockets := make(map[string]NetConnection)
	for _, spec := range []struct{ path, proto string }{{"/proc/net/tcp", "tcp4"}, {"/proc/net/tcp6", "tcp6"}, {"/proc/net/udp", "udp4"}, {"/proc/net/udp6", "udp6"}} {
		parseProcNet(spec.path, spec.proto, sockets)
	}
	out := make(map[string][]NetConnection)
	total := 0
	for key, p := range processes {
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", p.PID))
		if err != nil {
			continue
		}
		seen := map[string]struct{}{}
		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", p.PID, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			conn, ok := sockets[inode]
			if !ok || !isPublicIP(conn.RemoteIP) {
				continue
			}
			finger := conn.Protocol + "|" + conn.RemoteIP + "|" + strconv.Itoa(int(conn.RemotePort))
			if _, ok := seen[finger]; ok {
				continue
			}
			seen[finger] = struct{}{}
			out[key] = append(out[key], conn)
			total++
		}
	}
	return out, total
}

func parseProcNet(path, proto string, out map[string]NetConnection) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
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
		remoteIP, remotePort, ok := decodeProcAddr(fields[2], strings.HasSuffix(proto, "6"))
		if !ok || remotePort == 0 || remoteIP == "" {
			continue
		}
		inode := fields[9]
		out[inode] = NetConnection{Protocol: proto, RemoteIP: remoteIP, RemotePort: remotePort, State: fields[3], Inode: inode}
	}
}

func decodeProcAddr(v string, ipv6 bool) (string, uint16, bool) {
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
		// /proc/net/tcp6 prints each 32-bit word in host byte order.
		for i := 0; i < 16; i += 4 {
			b[i], b[i+3] = b[i+3], b[i]
			b[i+1], b[i+2] = b[i+2], b[i+1]
		}
		return net.IP(b).String(), uint16(p), true
	}
	return "", 0, false
}

func isPublicIP(raw string) bool {
	ip := net.ParseIP(raw)
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast() && !ip.IsUnspecified()
}
