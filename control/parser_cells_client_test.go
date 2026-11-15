package main

// POINT 2 / P2-T3 client tests: a real Unix listener speaking the VGTGC2 text
// protocol (HMAC, timestamp window, replay cache, SCM_RIGHTS export descriptor) so
// the client is tested against bytes, not against a mock method set.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type parserCellFakeHelper struct {
	t            *testing.T
	cfg          ParserCellsConfig
	key          []byte
	listener     net.Listener
	mu           sync.Mutex
	closed       bool
	requests     int
	calls        []string
	onCall       func(command string)
	corrupt      func(line string) string
	profiles     []string
	sandbox      bool
	bpfLSM       string
	createErr    string
	burnErr      string
	healthState  string
	startedAt    int64
	export       []byte
	exportFDMode string
	seq          int
	// wayland is empty (feature not advertised), "false" or "true": exercises the
	// additive capability negotiation of the phase-1/future helper.
	wayland string
	cells   map[string]*ParserCellRemote
}

func newParserCellFakeHelper(t *testing.T) *parserCellFakeHelper {
	t.Helper()
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x42}, 32)
	keyPath := filepath.Join(dir, "cell-helper.key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "helper.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("fake helper listen: %v", err)
	}
	helper := &parserCellFakeHelper{t: t, key: key, listener: listener,
		cfg: ParserCellsConfig{Socket: socket, AuthKeyFile: keyPath,
			InputDir: filepath.Join(dir, "inputs"), ImportsDir: filepath.Join(dir, "exports"),
			RequestTimeoutMillis: 2000, PeerUID: os.Getuid()},
		profiles: []string{"pdf-viewer"}, sandbox: true, bpfLSM: "inactive",
		healthState: "ok", startedAt: time.Now().Unix() - 5, cells: map[string]*ParserCellRemote{}}
	if err := os.MkdirAll(helper.cfg.ImportsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(helper.cfg.InputDir, 0o750); err != nil {
		t.Fatal(err)
	}
	go helper.serve()
	t.Cleanup(func() {
		helper.mu.Lock()
		helper.closed = true
		helper.mu.Unlock()
		_ = listener.Close()
	})
	return helper
}
func (h *parserCellFakeHelper) set(mutate func(*parserCellFakeHelper)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	mutate(h)
}
func (h *parserCellFakeHelper) serve() {
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			return
		}
		go h.handle(conn.(*net.UnixConn))
	}
}
func (h *parserCellFakeHelper) handle(conn *net.UnixConn) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 16<<10)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	h.mu.Lock()
	h.requests++
	h.mu.Unlock()
	data, fds := h.dispatch(line)
	var oob []byte
	for _, fd := range fds {
		oob = append(oob, syscall.UnixRights(fd)...)
	}
	if len(oob) > 0 {
		_, _, _ = conn.WriteMsgUnix(data, oob, nil)
	} else {
		_, _ = conn.Write(data)
	}
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}
func (h *parserCellFakeHelper) dispatch(rawLine string) ([]byte, []int) {
	line := strings.TrimSuffix(rawLine, "\n")
	fields := strings.Split(line, parserCellSep)
	if len(fields) != 6 || fields[0] != parserCellFrameTag {
		return []byte(h.responseLine("", "ERR", "code=bad-request") + "\n"), nil
	}
	id := fields[1]
	expectedMAC := hex.EncodeToString(parserCellMAC(h.key, strings.Join(fields[:5], parserCellSep)))
	if fields[5] != expectedMAC {
		return []byte(h.responseLine(id, "ERR", "code=bad-mac") + "\n"), nil
	}
	ts, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || time.Since(time.Unix(ts, 0)).Abs() > 30*time.Second {
		return []byte(h.responseLine(id, "ERR", "code=stale") + "\n"), nil
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(fields[4])
	if err != nil {
		return []byte(h.responseLine(id, "ERR", "code=bad-request") + "\n"), nil
	}
	status, payload, fds := h.commandResponse(fields[3], string(payloadBytes))
	response := h.responseLine(id, status, payload)
	h.mu.Lock()
	corrupt := h.corrupt
	h.mu.Unlock()
	if corrupt != nil {
		response = corrupt(response)
	}
	return []byte(response + "\n"), fds
}
func (h *parserCellFakeHelper) responseLine(id, status, payload string) string {
	b64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hex.EncodeToString(parserCellMAC(h.key, strings.Join([]string{parserCellResponseTag, id, status, b64}, parserCellSep)))
	return strings.Join([]string{parserCellResponseTag, id, status, b64, mac}, parserCellSep)
}
func parserCellFakeFields(payload string) map[string]string {
	fields := map[string]string{}
	if payload == "" {
		return fields
	}
	for _, part := range strings.Split(payload, parserCellSep) {
		key, value, ok := strings.Cut(part, "=")
		if ok {
			fields[key] = value
		}
	}
	return fields
}
func (h *parserCellFakeHelper) commandResponse(command, payload string) (string, string, []int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, command)
	if h.onCall != nil {
		h.onCall(command)
	}
	switch command {
	case "CELL_CAPABILITIES":
		payload := fmt.Sprintf("abi=cell-runtime-v1\x1fsandbox=%t\x1fprofiles=%s\x1fmax_concurrent=16\x1finput_bytes=8388608\x1fexport_bytes=2097152\x1fttl_max=3600\x1fbpf_lsm=%s",
			h.sandbox, strings.Join(h.profiles, ","), h.bpfLSM)
		if h.wayland != "" {
			payload += "\x1fwayland=" + h.wayland
		}
		return "OK", payload, nil
	case "CELL_CREATE":
		if h.createErr != "" {
			return "ERR", "code=" + h.createErr, nil
		}
		fields := parserCellFakeFields(payload)
		ttl, _ := strconv.Atoi(fields["ttl_seconds"])
		if ttl <= 0 {
			ttl = 120
		}
		h.seq++
		remote := &ParserCellRemote{UUID: fmt.Sprintf("%032x", 0xabc000+h.seq), Generation: uint64(h.seq),
			CgroupID: uint64(4200 + h.seq), Profile: fields["profile"], State: "isolated",
			ExpiresAt: time.Now().Unix() + int64(ttl), PID: 200 + h.seq}
		h.cells[remote.UUID] = remote
		return "OK", fmt.Sprintf("uuid=%s\x1fgeneration=%d\x1fcgroup_id=%d\x1fcgroup_path=/sys/fs/cgroup/vgt-cells/parser-%s\x1fpid=%d\x1fexpires_at=%d\x1fsandbox=true\x1fnetns=true",
			remote.UUID, remote.Generation, remote.CgroupID, remote.UUID, remote.PID, remote.ExpiresAt), nil
	case "CELL_LIST":
		rows := make([]string, 0, len(h.cells))
		for _, cell := range h.cells {
			rows = append(rows, fmt.Sprintf("uuid=%s\x1fgeneration=%d\x1fcgroup_id=%d\x1fprofile=%s\x1fstate=%s\x1fexpires_at=%d\x1fpid=%d\x1fexport_size=0",
				cell.UUID, cell.Generation, cell.CgroupID, cell.Profile, cell.State, cell.ExpiresAt, cell.PID))
		}
		payload := fmt.Sprintf("count=%d\n", len(rows))
		if len(rows) > 0 {
			payload += strings.Join(rows, "\n") + "\n"
		}
		return "OK", payload, nil
	case "CELL_FREEZE", "CELL_UNFREEZE":
		state := "applied"
		if command == "CELL_UNFREEZE" {
			state = "deleted"
		}
		return "OK", "state=" + state, nil
	case "CELL_BURN":
		if h.burnErr != "" {
			return "ERR", "code=" + h.burnErr, nil
		}
		fields := parserCellFakeFields(payload)
		delete(h.cells, fields["uuid"])
		sha := "-"
		if len(h.export) > 0 {
			sum := sha256.Sum256(h.export)
			sha = hex.EncodeToString(sum[:])
		}
		return "OK", fmt.Sprintf("burned=true\x1fexport_size=%d\x1fexport_sha256=%s", len(h.export), sha), nil
	case "CELL_EXPORT_READ":
		if len(h.export) == 0 {
			return "ERR", "code=export-missing", nil
		}
		sum := sha256.Sum256(h.export)
		payload := fmt.Sprintf("size=%d\x1fsha256=%s\x1ftype=file", len(h.export), hex.EncodeToString(sum[:]))
		fdCount := 1
		if h.exportFDMode == "zero" {
			fdCount = 0
		}
		if h.exportFDMode == "two" {
			fdCount = 2
		}
		fds := make([]int, 0, fdCount)
		for index := 0; index < fdCount; index++ {
			file, err := os.CreateTemp("", "gd-parser-export-")
			if err != nil {
				return "ERR", "code=internal", nil
			}
			_, _ = file.Write(h.export)
			path := file.Name()
			_ = file.Close()
			// A raw descriptor is deliberate: the fake must not hold an *os.File
			// whose finalizer could close the descriptor before it is sent.
			fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
			if err != nil {
				return "ERR", "code=internal", nil
			}
			fds = append(fds, fd)
		}
		return "OK", payload, fds
	case "CELL_HEALTH":
		return "OK", fmt.Sprintf("state=%s\x1factive_cells=%d\x1fburned_total=0\x1flast_error=-\x1fstarted_at=%d\x1fabi=cell-runtime-v1",
			h.healthState, len(h.cells), h.startedAt), nil
	}
	return "ERR", "code=unknown-command", nil
}
func (h *parserCellFakeHelper) client(t *testing.T) *parserCellClient {
	t.Helper()
	client, err := newParserCellClient(h.cfg)
	if err != nil {
		t.Fatalf("parser cell test client: %v", err)
	}
	return client
}
func (h *parserCellFakeHelper) requestCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.requests
}
func (h *parserCellFakeHelper) commands() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...)
}

func TestParserCellsClientRoundTrip(t *testing.T) {
	helper := newParserCellFakeHelper(t)
	helper.set(func(h *parserCellFakeHelper) { h.export = []byte("parser export bytes") })
	client := helper.client(t)

	caps, err := client.Capabilities()
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if !caps.Sandbox || caps.ABI != parserCellsABI || len(caps.Profiles) != 1 || caps.Profiles[0] != "pdf-viewer" ||
		caps.MaxConcurrent != 16 || caps.InputBytes != 8<<20 || caps.TTLMax != 3600 || caps.BPFLSM {
		t.Fatalf("capability negotiation is wrong: %+v", caps)
	}
	created, err := client.Create(ParserCellCreateRequest{Profile: "pdf-viewer", InputToken: strings.Repeat("ab", 16),
		InputSHA256: strings.Repeat("cd", 32), InputSize: 42, TTLSeconds: 60})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(created.UUID) != 32 || created.Generation == 0 || created.CgroupID == 0 || created.PID == 0 || !created.Sandbox || !created.NetNS {
		t.Fatalf("create answer is incomplete: %+v", created)
	}
	rows, err := client.List()
	if err != nil || len(rows) != 1 || rows[0].UUID != created.UUID || rows[0].State != "isolated" {
		t.Fatalf("list: rows=%+v err=%v", rows, err)
	}
	if err := client.Freeze(created.UUID, created.Generation, created.CgroupID); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if err := client.Unfreeze(created.UUID, created.Generation, created.CgroupID); err != nil {
		t.Fatalf("unfreeze: %v", err)
	}
	file, meta, err := client.ExportRead(created.UUID, created.Generation, 2<<20)
	if err != nil {
		t.Fatalf("export read: %v", err)
	}
	data := make([]byte, 64)
	n, _ := file.Read(data)
	_ = file.Close()
	exportText := "parser export bytes"
	if string(data[:n]) != exportText || meta.Size != int64(len(exportText)) || len(meta.SHA256) != 64 || meta.Kind != "file" {
		t.Fatalf("export read returned wrong data: %q %+v", data[:n], meta)
	}
	burned, err := client.Burn(created.UUID, created.Generation, created.CgroupID, "PC-test", "operator")
	if err != nil || !burned.Burned || burned.ExportSize != int64(len(exportText)) || burned.ExportSHA == "-" {
		t.Fatalf("burn: %+v err=%v", burned, err)
	}
	health, err := client.Health()
	if err != nil || health.ABI != parserCellsABI || health.State != "ok" {
		t.Fatalf("health: %+v err=%v", health, err)
	}
}
func TestParserCellsClientHostileAnswers(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*parserCellFakeHelper)
		client func(*parserCellFakeHelper) *parserCellClient
	}{
		{"bad-mac", func(h *parserCellFakeHelper) {
			h.corrupt = func(line string) string {
				last := line[len(line)-1]
				replacement := byte('0')
				if last == '0' {
					replacement = '1'
				}
				return line[:len(line)-1] + string(replacement)
			}
		}, nil},
		{"wrong-id", func(h *parserCellFakeHelper) {
			h.corrupt = func(line string) string {
				fields := strings.Split(line, parserCellSep)
				fields[1] = strings.Repeat("0", 16)
				return strings.Join(fields, parserCellSep)
			}
		}, nil},
		{"oversize", func(h *parserCellFakeHelper) {
			h.corrupt = func(string) string { return strings.Repeat("A", parserCellResponseMaxBytes+1) }
		}, nil},
		{"trailing-frame", func(h *parserCellFakeHelper) {
			h.corrupt = func(line string) string { return line + "\n" + line }
		}, nil},
		{"unknown-err-code", func(h *parserCellFakeHelper) {
			h.createErr = "made-up-code"
		}, nil},
		{"stale", func(h *parserCellFakeHelper) {}, func(h *parserCellFakeHelper) *parserCellClient {
			client := h.client(t)
			client.now = func() time.Time { return time.Now().Add(-2 * time.Minute) }
			return client
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			helper := newParserCellFakeHelper(t)
			helper.set(testCase.mutate)
			client := helper.client(t)
			if testCase.client != nil {
				client = testCase.client(helper)
			}
			_, err := client.Create(ParserCellCreateRequest{Profile: "pdf-viewer", InputToken: strings.Repeat("ab", 16),
				InputSHA256: strings.Repeat("cd", 32), InputSize: 1, TTLSeconds: 30})
			if err == nil {
				t.Fatalf("hostile %q answer was accepted", testCase.name)
			}
			if testCase.name == "stale" {
				var helperErr *ParserCellError
				if !errors.As(err, &helperErr) || helperErr.Code != "stale" {
					t.Fatalf("stale answer was not surfaced as a closed helper code: %v", err)
				}
			}
		})
	}
}
func TestParserCellsClientExportDescriptorBounds(t *testing.T) {
	for _, mode := range []string{"zero", "two"} {
		t.Run(mode, func(t *testing.T) {
			helper := newParserCellFakeHelper(t)
			helper.set(func(h *parserCellFakeHelper) {
				h.export = []byte("bounded export")
				h.exportFDMode = mode
			})
			client := helper.client(t)
			if _, _, err := client.ExportRead(strings.Repeat("a", 32), 1, 2<<20); err == nil {
				t.Fatalf("export answer with %s descriptors was accepted", mode)
			}
		})
	}
}
func TestParserCellsClientUnavailableAndPeerRejection(t *testing.T) {
	helper := newParserCellFakeHelper(t)
	missing := helper.cfg
	missing.Socket = filepath.Join(t.TempDir(), "missing.sock")
	client, err := newParserCellClient(missing)
	if err != nil {
		t.Fatalf("missing-socket client construction: %v", err)
	}
	if _, err := client.Capabilities(); !errors.Is(err, ErrParserCellsRuntimeUnavailable) {
		t.Fatalf("missing helper was not reported as capability-missing: %v", err)
	}
	wrongPeer := helper.cfg
	wrongPeer.PeerUID = os.Getuid() + 1
	peerClient, err := newParserCellClient(wrongPeer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peerClient.Capabilities(); !errors.Is(err, ErrParserCellsPeer) {
		t.Fatalf("impostor peer was not rejected: %v", err)
	}
}
func TestParserCellsKeyLoaderBounds(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	// Explicit chmod keeps this test meaningful under a strict umask (0077), where
	// the create mode would otherwise already be 0600.
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadParserCellKey(keyPath); !errors.Is(err, ErrParserCellsProtocol) {
		t.Fatalf("world-readable key was accepted: %v", err)
	}
	if err := os.WriteFile(keyPath, make([]byte, 31), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadParserCellKey(keyPath); err == nil {
		t.Fatal("short key was accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(keyPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadParserCellKey(link); err == nil {
		t.Fatal("symlink key was accepted")
	}
	if _, err := loadParserCellKey(filepath.Join(dir, "absent")); !errors.Is(err, ErrParserCellsRuntimeUnavailable) {
		t.Fatalf("missing key was not reported as runtime-unavailable: %v", err)
	}
}
func TestParserCellsPayloadParserIsAllOrNothing(t *testing.T) {
	keys := []string{"abi", "sandbox"}
	if values, err := parseParserCellPayload([]byte("abi=x\x1fsandbox=true"), keys...); err != nil || values[0] != "x" || values[1] != "true" {
		t.Fatalf("valid payload rejected: %v %v", values, err)
	}
	for _, hostile := range []string{
		"abi=x",                          // missing sandbox
		"abi=x\x1fsandbox=true\x1fnew=1", // unknown field
		"abi=x\x1fabi=y",                 // duplicate field
		"abi=x y\x1fsandbox=true",        // whitespace value
		"abi=\x00\x1fsandbox=true",       // NUL value
	} {
		if _, err := parseParserCellPayload([]byte(hostile), keys...); err == nil {
			t.Fatalf("hostile payload %q was accepted", hostile)
		}
	}
	if _, err := parseParserCellPayload([]byte("abi=x\x1fsandbox=true"), keys...); err != nil {
		t.Fatalf("structural payload rejected: %v", err)
	}
	if _, err := parseParserCellPayload(bytes.Repeat([]byte("A"), parserCellResponseMaxBytes+1), keys...); err == nil {
		t.Fatal("oversized payload accepted")
	}
	if _, err := parseParserCellList([]byte("count=2\nuuid=" + strings.Repeat("a", 32) + "\n")); err == nil {
		t.Fatal("list count mismatch accepted")
	}
	if _, err := parseParserCellList([]byte("count=0\n\n")); err == nil {
		t.Fatal("list with empty row accepted")
	}
	if _, err := buildParserCellPayload([]string{"profile=bad value"}); err == nil {
		t.Fatal("unsafe request field accepted")
	}
	if _, err := parseParserCellResponse("garbage", "id", []byte("0123456789abcdef0123456789abcdef")); err == nil {
		t.Fatal("garbage response frame accepted")
	}
}
