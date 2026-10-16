// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DesktopStatusServer serves the read-only status telegram on a local Unix socket.
//
// Hardening, in the order the connection passes it:
//  1. peer credentials are read before the first byte and are the identity for every limit,
//  2. a per-identity connection cap keeps one local user from occupying every slot,
//  3. a per-identity token bucket bounds the request rate,
//  4. read and write deadlines bound the time,
//  5. the request is size-limited, strictly parsed and allowlisted to one operation,
//  6. the reply is size-limited and contains no path, hash, token or configuration value.
//
// A refusal is logged; a success is not, because the tray polls every few seconds and would turn
// the journal into noise.
type DesktopStatusServer struct {
	cfg         DesktopConfig
	state       *State
	alertWindow time.Duration

	mu       sync.Mutex
	listener *net.UnixListener
	clients  map[int]*desktopClient
	stopped  bool
	wg       sync.WaitGroup
}

type desktopClient struct {
	connections int
	tokens      float64
	last        time.Time
	lastRefusal time.Time
}

func NewDesktopStatusServer(cfg DesktopConfig, state *State) *DesktopStatusServer {
	window := time.Duration(cfg.AlertWindowSeconds) * time.Second
	if window <= 0 {
		window = time.Duration(defaultDesktopAlertWindowSeconds) * time.Second
	}
	return &DesktopStatusServer{
		cfg:         cfg,
		state:       state,
		alertWindow: window,
		clients:     make(map[int]*desktopClient, 8),
	}
}

// Start binds the socket and serves until the context is cancelled.
func (s *DesktopStatusServer) Start(ctx context.Context) error {
	if s == nil || s.state == nil {
		return errors.New("desktop status server requires state")
	}
	if !s.cfg.Enabled {
		return nil
	}
	path := strings.TrimSpace(s.cfg.SocketPath)
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("desktop status socket path must be absolute")
	}
	mode, err := parseDesktopSocketMode(s.cfg.SocketMode)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	// The directory belongs to the service user and carries the desktop group with the set-group-id
	// bit, so the socket inherits that group without the service needing root or CAP_CHOWN.
	//
	// The set-group-id bit is set by packaging/tmpfiles and not here: the unit runs with
	// RestrictSUIDSGID=true, which forbids this process from setting it at all. What this code owes
	// the operator is a complaint that names the expected ownership instead of an EPERM.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("desktop status directory: %w", err)
	}
	if err := verifyDesktopDirectory(dir); err != nil {
		return err
	}
	if err := prepareDesktopSocketPath(path); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fmt.Errorf("desktop status listen: %w", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return fmt.Errorf("desktop status permissions: %w", err)
	}
	if group := strings.TrimSpace(s.cfg.SocketGroup); group != "" {
		// With the set-group-id directory the socket already carries the group; a chown attempt is
		// only a fallback for a host whose directory has no set-group-id bit, and it legitimately
		// fails for an unprivileged service. What matters is the group that ended up on the socket,
		// so that is what gets verified and reported.
		if err := chownDesktopSocket(path, group); err != nil {
			if verifyErr := verifyDesktopSocketGroup(path, group); verifyErr != nil {
				log.Printf("desktop status socket is not readable by group %q: %v (directory mode must be 2750 %s:%s, see packaging/tmpfiles)", group, verifyErr, "gedefense", group)
			}
		}
	}
	s.mu.Lock()
	s.listener = listener
	s.stopped = false
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		s.stop()
	}()
	log.Printf("desktop status socket ready: %s mode=%s", path, s.cfg.SocketMode)

	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if s.isStopped() || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			if temporary, ok := err.(interface{ Temporary() bool }); ok && temporary.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return fmt.Errorf("desktop status accept: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(conn)
		}()
	}
}

func (s *DesktopStatusServer) stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	listener := s.listener
	path := s.cfg.SocketPath
	s.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	if strings.TrimSpace(path) != "" {
		_ = os.Remove(path)
	}
}

func (s *DesktopStatusServer) isStopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped
}

func (s *DesktopStatusServer) serve(conn *net.UnixConn) {
	defer conn.Close()

	uid, gid, pid, err := desktopPeerIdentity(conn)
	if err != nil {
		s.logRefusal(-1, "peer credentials unavailable: "+err.Error())
		return
	}
	if !s.admit(uid) {
		s.logRefusal(uid, "connection or rate limit reached")
		_ = writeDesktopError(conn, "busy")
		return
	}
	defer s.release(uid)

	if err := conn.SetDeadline(time.Now().Add(desktopRequestTimeout)); err != nil {
		return
	}
	line, err := readDesktopRequest(conn)
	if err != nil {
		s.logRefusal(uid, "request rejected: "+err.Error())
		return
	}
	if err := validateDesktopRequest(line); err != nil {
		s.logRefusal(uid, "request rejected: "+err.Error())
		_ = writeDesktopError(conn, "invalid request")
		return
	}
	payload, err := encodeDesktopPayload(buildDesktopStatus(s.state.Snapshot(), time.Now().UTC(), s.alertWindow))
	if err != nil {
		s.logRefusal(uid, "telegram unavailable: "+err.Error())
		_ = writeDesktopError(conn, "unavailable")
		return
	}
	if err := conn.SetWriteDeadline(time.Now().Add(desktopWriteTimeout)); err != nil {
		return
	}
	if _, err := conn.Write(payload); err != nil {
		s.logRefusal(uid, "write failed: "+err.Error())
	}
	_ = gid
	_ = pid
}

// admit applies the per-identity connection cap and token bucket.
func (s *DesktopStatusServer) admit(uid int) bool {
	now := time.Now()
	burst := float64(s.cfg.RateLimitBurst)
	if burst < 1 {
		burst = float64(defaultDesktopRateLimitBurst)
	}
	rate := float64(s.cfg.RateLimitPerMinute) / 60.0
	if rate <= 0 {
		rate = float64(defaultDesktopRateLimitPerMinute) / 60.0
	}
	maxConnections := s.cfg.MaxConnectionsPerUser
	if maxConnections < 1 {
		maxConnections = defaultDesktopMaxConnectionsPerUser
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	client := s.clients[uid]
	if client == nil {
		if len(s.clients) >= desktopMaxTrackedClients {
			s.evictStaleClientsLocked(now)
		}
		if len(s.clients) >= desktopMaxTrackedClients {
			return false
		}
		client = &desktopClient{tokens: burst, last: now}
		s.clients[uid] = client
	}
	if client.connections >= maxConnections {
		return false
	}
	elapsed := now.Sub(client.last).Seconds()
	if elapsed > 0 {
		client.tokens = minFloat(burst, client.tokens+elapsed*rate)
		client.last = now
	}
	if client.tokens < 1 {
		return false
	}
	client.tokens--
	client.connections++
	return true
}

func (s *DesktopStatusServer) release(uid int) {
	s.mu.Lock()
	if client := s.clients[uid]; client != nil {
		if client.connections > 0 {
			client.connections--
		}
	}
	s.mu.Unlock()
}

func (s *DesktopStatusServer) evictStaleClientsLocked(now time.Time) {
	for uid, client := range s.clients {
		if client.connections == 0 && now.Sub(client.last) > time.Hour {
			delete(s.clients, uid)
		}
	}
}

func (s *DesktopStatusServer) logRefusal(uid int, reason string) {
	now := time.Now()
	key := uid
	s.mu.Lock()
	client := s.clients[key]
	if client == nil && key >= 0 {
		if len(s.clients) < desktopMaxTrackedClients {
			client = &desktopClient{last: now}
			s.clients[key] = client
		}
	}
	if client != nil {
		if now.Sub(client.lastRefusal) < time.Minute {
			s.mu.Unlock()
			return
		}
		client.lastRefusal = now
	}
	s.mu.Unlock()
	log.Printf("desktop status refused uid=%d: %s", uid, reason)
}

func readDesktopRequest(conn *net.UnixConn) ([]byte, error) {
	reader := bufio.NewReaderSize(io.LimitReader(conn, desktopRequestLimit+1), desktopRequestLimit+1)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil, errors.New("empty request")
		}
		if len(line) > desktopRequestLimit {
			return nil, errors.New("request too large")
		}
		return nil, err
	}
	if len(line) > desktopRequestLimit {
		return nil, errors.New("request too large")
	}
	return line, nil
}

func validateDesktopRequest(line []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var request desktopStatusRequest
	if err := decoder.Decode(&request); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after request")
	}
	if request.Version != desktopStatusProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d", request.Version)
	}
	if strings.TrimSpace(strings.ToLower(request.Op)) != "status" {
		return fmt.Errorf("unsupported operation %q", request.Op)
	}
	return nil
}

func writeDesktopError(conn *net.UnixConn, code string) error {
	payload, err := json.Marshal(struct {
		Version int    `json:"v"`
		Error   string `json:"error"`
	}{Version: desktopStatusProtocolVersion, Error: code})
	if err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(desktopWriteTimeout)); err != nil {
		return err
	}
	_, err = conn.Write(append(payload, '\n'))
	return err
}

// desktopPeerIdentity resolves the kernel-provided identity of the client. The identity never comes
// from the payload, and the credential helper is the one the L7 edge already uses - one audited
// implementation instead of two.
func desktopPeerIdentity(conn *net.UnixConn) (int, int, int, error) {
	credentials, err := l7PeerCredentialsFromConn(conn)
	if err != nil {
		return 0, 0, 0, err
	}
	return int(credentials.UID), int(credentials.GID), int(credentials.PID), nil
}

// prepareDesktopSocketPath refuses an unclean path outright, refuses to replace a live socket, and
// removes a leftover one from a previous process.
func prepareDesktopSocketPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return errors.New("desktop status socket path must be a clean absolute path of at most 100 bytes")
	}
	parent := filepath.Dir(path)
	if parent == "/" {
		return errors.New("desktop status socket must not live in the filesystem root")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("desktop status path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("desktop status path %s exists and is not a socket", path)
	}
	probe, dialErr := net.DialTimeout("unix", path, 500*time.Millisecond)
	if dialErr == nil {
		_ = probe.Close()
		return fmt.Errorf("desktop status socket %s is already served", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("desktop status stale socket: %w", err)
	}
	return nil
}

func parseDesktopSocketMode(value string) (os.FileMode, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		trimmed = defaultDesktopSocketMode
	}
	parsed, err := strconv.ParseUint(trimmed, 8, 32)
	if err != nil || parsed == 0 || parsed > 0o777 {
		return 0, fmt.Errorf("desktop socket mode %q is not a valid permission mask", value)
	}
	return os.FileMode(parsed), nil
}

// verifyDesktopDirectory reports why the socket directory cannot serve its purpose, naming the
// expected ownership. The service must own it: it creates the socket there, and with
// ProtectSystem=strict the path has to be listed in ReadWritePaths as well.
func verifyDesktopDirectory(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("desktop status directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("desktop status path %s is not a directory", dir)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("desktop status directory %s is owned by uid %d, expected the service uid %d (see packaging/tmpfiles)", dir, stat.Uid, os.Getuid())
	}
	if info.Mode().Perm()&0o200 == 0 {
		return fmt.Errorf("desktop status directory %s is not writable by its owner (mode %04o)", dir, info.Mode().Perm())
	}
	return nil
}

func chownDesktopSocket(path, groupName string) error {
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return fmt.Errorf("resolve desktop socket group: %w", err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid < 0 {
		return errors.New("resolved desktop socket group has an invalid gid")
	}
	return os.Chown(path, -1, gid)
}

// verifyDesktopSocketGroup checks the group that actually landed on the socket. The service cannot
// always chown its own socket, so the group inherited from the directory is the normal case - and a
// mismatch means the indicator will be refused, which the operator has to see.
func verifyDesktopSocketGroup(path, groupName string) error {
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return fmt.Errorf("resolve desktop socket group: %w", err)
	}
	want, err := strconv.Atoi(group.Gid)
	if err != nil || want < 0 {
		return errors.New("resolved desktop socket group has an invalid gid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("socket ownership is unavailable")
	}
	if int(stat.Gid) != want {
		return fmt.Errorf("socket group is %d, expected %d", stat.Gid, want)
	}
	return nil
}

func minFloat(left, right float64) float64 {
	if left < right {
		return left
	}
	return right
}
