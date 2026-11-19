//go:build linux

package workerguard

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Netlink / proc-connector ABI constants (linux/cn_proc.h, linux/netlink.h).
const (
	netlinkConnector  = 11 // NETLINK_CONNECTOR
	cnIdxProc         = 1  // CN_IDX_PROC
	cnValProc         = 1  // CN_VAL_PROC
	procCnMcastListen = 1  // PROC_CN_MCAST_LISTEN
	procEventExit     = 0x00000100
	nlmsgDone         = 3
	nlmFRequest       = 0x1
	soRecvBuf         = 8
	soRecvTimeout     = 20
	cnMsgHeaderLen    = 20
	procEventHeader   = 16 // what(4) + cpu(4) + timestamp_ns(8)
	maxNetlinkBatch   = 64 << 10
	maxProcEntries    = 65536
)

// ExitRecord is one kernel-reported process exit from the proc connector.
type ExitRecord struct {
	PID      int
	Signal   int
	ExitCode int
	At       time.Time
}

// ErrProcConnectorUnsupported reports a host without the proc connector
// netlink controller (kernel config or capability).
var ErrProcConnectorUnsupported = errors.New("proc connector netlink source is unavailable")

// ScanProcesses classifies the live web workers from /proc in two passes:
//
//  1. collect the cgroup ids that also host an excluded master/control process
//     (systemd puts `nginx: master process` and its workers into the same
//     cgroup inode, so excluding only the master PID is not enough), then
//  2. classify the remaining tracked workers, skipping every cgroup from pass 1
//     and surfacing each skip with its concrete reason.
//
// The returned second value is a hard scan failure ("/proc is not readable"),
// never a silent empty result.
func ScanProcesses(registry Registry, strict bool, max int) (ScanResult, string) {
	result := ScanResult{Workers: []Worker{}, Skipped: []SkippedCgroup{}}
	if max <= 0 || max > maxProcEntries {
		max = maxProcEntries
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return result, "/proc is not readable"
	}
	if len(entries) > maxProcEntries {
		entries = entries[:maxProcEntries]
	}
	excluded := ExcludedControlCgroups(collectControlUnitObservations(entries, registry), registry.ExcludeUnits)
	workers := result.Workers
	seenCgroups := make(map[uint64]struct{}, 8)
	seenSkips := make(map[uint64]struct{}, len(excluded))
	for _, entry := range entries {
		if len(workers) >= max {
			break
		}
		if !entry.IsDir() {
			continue
		}
		pid, pidErr := strconv.Atoi(entry.Name())
		if pidErr != nil || pid <= 0 {
			continue
		}
		dir := "/proc/" + entry.Name()
		comm, readErr := readSmallFile(dir+"/comm", 64)
		if readErr != nil {
			continue
		}
		comm = strings.TrimRight(comm, "\n\x00")
		if !IsTrackedComm(comm, registry) {
			continue
		}
		if IsControlUnit(comm, registry.ExcludeUnits) {
			continue
		}
		cmdline, _ := readSmallFile(dir+"/cmdline", 4096)
		if MatchesExcludedUnit(cmdline, registry.ExcludeUnits) {
			// The nginx/apache master shares the worker's comm; only the command
			// line distinguishes it, and a master in the strict scope would take
			// the whole service down with it.
			continue
		}
		uid, uidErr := readProcessUID(dir + "/status")
		if uidErr != nil {
			continue
		}
		cgroupPath, cgroupErr := readCgroupPath(dir + "/cgroup")
		if cgroupErr != nil {
			continue
		}
		cgroupID := cgroupIDForPath(cgroupPath)
		if cgroupID == 0 {
			continue
		}
		if exclusion, skipped := excluded[cgroupID]; skipped {
			if _, dup := seenSkips[cgroupID]; !dup {
				seenSkips[cgroupID] = struct{}{}
				result.Skipped = append(result.Skipped, exclusion)
			}
			continue
		}
		if _, dup := seenCgroups[cgroupID]; dup {
			// One scope per cgroup: workers of the same unit are protected by the
			// same rule.
			continue
		}
		worker, ok := ClassifyWorker(pid, comm, uid, cgroupPath, cgroupID, registry, strict)
		if !ok {
			continue
		}
		seenCgroups[cgroupID] = struct{}{}
		workers = append(workers, worker)
	}
	result.Workers = workers
	sort.Slice(result.Skipped, func(left, right int) bool {
		return result.Skipped[left].CgroupID < result.Skipped[right].CgroupID
	})
	return result, ""
}

// collectControlUnitObservations is the bounded first /proc pass. Only
// processes that could be a tracked worker or a known control unit are
// inspected further, so the pass stays cheap while still finding a master whose
// comm is a registered worker name.
func collectControlUnitObservations(entries []os.DirEntry, registry Registry) []ProcessObservation {
	observations := make([]ProcessObservation, 0, 8)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, pidErr := strconv.Atoi(entry.Name())
		if pidErr != nil || pid <= 0 {
			continue
		}
		dir := "/proc/" + entry.Name()
		comm, readErr := readSmallFile(dir+"/comm", 64)
		if readErr != nil {
			continue
		}
		comm = strings.TrimRight(comm, "\n\x00")
		if !IsTrackedComm(comm, registry) && !IsControlUnit(comm, registry.ExcludeUnits) {
			continue
		}
		cmdline, _ := readSmallFile(dir+"/cmdline", 4096)
		if !IsControlUnit(comm, registry.ExcludeUnits) && !MatchesExcludedUnit(cmdline, registry.ExcludeUnits) {
			continue
		}
		cgroupPath, cgroupErr := readCgroupPath(dir + "/cgroup")
		if cgroupErr != nil {
			continue
		}
		observations = append(observations, ProcessObservation{
			PID: pid, Comm: comm, Cmdline: cmdline,
			CgroupPath: cgroupPath, CgroupID: cgroupIDForPath(cgroupPath),
		})
	}
	return observations
}

// readProcessUID parses the Uid line of /proc/<pid>/status.
func readProcessUID(path string) (uint32, error) {
	data, err := readSmallFile(path, 8192)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		uid, parseErr := strconv.ParseUint(fields[1], 10, 32)
		if parseErr != nil {
			break
		}
		return uint32(uid), nil
	}
	return 0, errors.New("process uid unreadable")
}

// readCgroupPath parses the unified-hierarchy entry of /proc/<pid>/cgroup.
func readCgroupPath(path string) (string, error) {
	data, err := readSmallFile(path, 8192)
	if err != nil {
		return "", err
	}
	return ParseCgroupPath(data)
}

// cgroupIDForPath resolves the kernel cgroup id of a unified cgroup path. For
// cgroup v2 the kernfs node id (and therefore bpf_get_current_cgroup_id) is the
// inode number of the cgroup directory.
func cgroupIDForPath(path string) uint64 {
	if path == "" || path == "/" {
		return 0
	}
	info, err := os.Stat("/sys/fs/cgroup" + path)
	if err != nil {
		return 0
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return 0
	}
	return uint64(stat.Ino)
}

// readSmallFile reads at most limit bytes from a /proc text file.
func readSmallFile(path string, limit int) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// RunProcConnector subscribes to PROC_EVENT_EXIT/PROC_EVENT_COREDUMP and calls
// emit for every exit until the context is cancelled. onReady runs exactly once,
// after the kernel accepted the subscription and before the first record, so the
// caller can report the capability honestly. It returns
// ErrProcConnectorUnsupported when the kernel or the capability is missing, so
// the caller can report `source: none` honestly.
func RunProcConnector(ctx context.Context, onReady func(), emit func(ExitRecord)) error {
	if ctx == nil {
		ctx = context.Background()
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, netlinkConnector)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProcConnectorUnsupported, err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		return fmt.Errorf("%w: bind: %v", ErrProcConnectorUnsupported, err)
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soRecvBuf, 1<<20)
	timeout := syscall.Timeval{Usec: 500000}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, soRecvTimeout, &timeout)
	if err := subscribeProcConnector(fd); err != nil {
		return fmt.Errorf("%w: subscribe: %v", ErrProcConnectorUnsupported, err)
	}
	if onReady != nil {
		onReady()
	}
	buffer := make([]byte, maxNetlinkBatch)
	for {
		select {
		case <-ctx.Done():
			unsubscribeProcConnector(fd)
			return ctx.Err()
		default:
		}
		read, _, recvErr := syscall.Recvfrom(fd, buffer, 0)
		if recvErr != nil {
			if errors.Is(recvErr, syscall.EAGAIN) || errors.Is(recvErr, syscall.EINTR) || errors.Is(recvErr, syscall.EWOULDBLOCK) {
				continue
			}
			return fmt.Errorf("proc connector receive: %w", recvErr)
		}
		if read <= 0 {
			continue
		}
		records, parseErr := parseConnectorMessages(buffer[:read])
		if parseErr != nil {
			// A malformed message is dropped; the sensor never guesses.
			continue
		}
		for _, record := range records {
			emit(record)
		}
	}
}

// subscribeProcConnector sends the PROC_CN_MCAST_LISTEN op to the kernel.
func subscribeProcConnector(fd int) error {
	message := make([]byte, 16+cnMsgHeaderLen+4)
	binary.LittleEndian.PutUint32(message[0:], uint32(len(message)))
	binary.LittleEndian.PutUint16(message[4:], nlmsgDone)
	binary.LittleEndian.PutUint16(message[6:], nlmFRequest)
	binary.LittleEndian.PutUint32(message[8:], 1) // seq
	binary.LittleEndian.PutUint32(message[12:], uint32(os.Getpid()))
	binary.LittleEndian.PutUint32(message[16:], cnIdxProc)
	binary.LittleEndian.PutUint32(message[20:], cnValProc)
	binary.LittleEndian.PutUint32(message[24:], 1) // cn_msg.seq
	binary.LittleEndian.PutUint16(message[32:], 4) // cn_msg.len = payload size
	op := message[16+cnMsgHeaderLen:]
	binary.LittleEndian.PutUint32(op, procCnMcastListen)
	return syscall.Sendto(fd, message, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}

// unsubscribeProcConnector sends PROC_CN_MCAST_IGNORE (best effort on shutdown).
func unsubscribeProcConnector(fd int) {
	message := make([]byte, 16+cnMsgHeaderLen+4)
	binary.LittleEndian.PutUint32(message[0:], uint32(len(message)))
	binary.LittleEndian.PutUint16(message[4:], nlmsgDone)
	binary.LittleEndian.PutUint16(message[6:], nlmFRequest)
	binary.LittleEndian.PutUint32(message[8:], 2)
	binary.LittleEndian.PutUint32(message[12:], uint32(os.Getpid()))
	binary.LittleEndian.PutUint32(message[16:], cnIdxProc)
	binary.LittleEndian.PutUint32(message[20:], cnValProc)
	binary.LittleEndian.PutUint32(message[24:], 1)
	binary.LittleEndian.PutUint16(message[32:], 4)
	binary.LittleEndian.PutUint32(message[16+cnMsgHeaderLen:], 2) // PROC_CN_MCAST_IGNORE
	_ = syscall.Sendto(fd, message, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}

// parseConnectorMessages walks one netlink datagram and returns the exit records.
func parseConnectorMessages(data []byte) ([]ExitRecord, error) {
	if len(data) < 16 {
		return nil, errors.New("short netlink datagram")
	}
	records := make([]ExitRecord, 0, 4)
	offset := 0
	for offset+16 <= len(data) {
		length := int(binary.LittleEndian.Uint32(data[offset:]))
		if length < 16 || offset+length > len(data) {
			return nil, errors.New("malformed netlink message length")
		}
		payloadEnd := offset + length
		headerEnd := offset + 16
		// Skip the netlink header and the cn_msg header.
		cursor := headerEnd + cnMsgHeaderLen
		if cursor+procEventHeader > payloadEnd {
			offset += align4(length)
			continue
		}
		what := binary.LittleEndian.Uint32(data[cursor:])
		cursor += procEventHeader
		if what == procEventExit {
			if cursor+16 > payloadEnd {
				offset += align4(length)
				continue
			}
			pid := int(int32(binary.LittleEndian.Uint32(data[cursor:])))
			exitCode := int(int32(binary.LittleEndian.Uint32(data[cursor+8:])))
			exitSignal := int(int32(binary.LittleEndian.Uint32(data[cursor+12:])))
			signal := exitSignal
			if !IsFatalSignal(signal) {
				if derived, ok := WaitStatusSignal(exitCode); ok {
					signal = derived
				}
			}
			if pid > 0 {
				records = append(records, ExitRecord{
					PID: pid, Signal: signal, ExitCode: exitCode, At: time.Now().UTC(),
				})
			}
		}
		offset += align4(length)
	}
	return records, nil
}

// align4 rounds a netlink message length up to the 4-byte alignment.
func align4(value int) int { return (value + 3) &^ 3 }

// CgroupScanner is a small helper the engine uses to refresh the live PID map
// without holding a lock while walking /proc.
type CgroupScanner struct {
	mu      sync.Mutex
	workers map[int]Worker
	config  Registry
	strict  bool
}

// NewCgroupScanner constructs the process classifier state.
func NewCgroupScanner(registry Registry, strict bool) *CgroupScanner {
	return &CgroupScanner{workers: make(map[int]Worker), config: registry, strict: strict}
}

// Refresh walks /proc and replaces the live PID map.
func (s *CgroupScanner) Refresh() []Worker {
	if s == nil {
		return nil
	}
	result, _ := ScanProcesses(s.config, s.strict, 1024)
	workers := result.Workers
	next := make(map[int]Worker, len(workers))
	for _, worker := range workers {
		next[worker.PID] = worker
	}
	s.mu.Lock()
	s.workers = next
	s.mu.Unlock()
	return workers
}

// Lookup resolves a crash PID against the last live scan.
func (s *CgroupScanner) Lookup(pid int) (Worker, bool) {
	if s == nil {
		return Worker{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	worker, ok := s.workers[pid]
	return worker, ok
}
