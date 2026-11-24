// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

type CoreExecEvent struct {
	PID  int
	UID  uint32
	GID  uint32
	Comm string
}

type CoreCellLSMDenyEvent struct {
	CgroupID uint64
	PID      int
	UID      uint32
	Family   int32
}

func (c *CoreClient) Stop(pid int, startTicks uint64, rule string) error {
	_, err := c.command("XDR_STOP", strconv.Itoa(pid), strconv.FormatUint(startTicks, 10), rule)
	return err
}
func (c *CoreClient) Resume(pid int, startTicks uint64, rule string) error {
	_, err := c.command("XDR_CONT", strconv.Itoa(pid), strconv.FormatUint(startTicks, 10), rule)
	return err
}
func (c *CoreClient) Kill(pid int, startTicks uint64, rule string) error {
	_, err := c.command("XDR_KILL", strconv.Itoa(pid), strconv.FormatUint(startTicks, 10), rule)
	return err
}

func (c *CoreClient) FreezeProcess(pid int, startTicks uint64, reason string) error {
	return c.Stop(pid, startTicks, reason)
}

func (c *CoreClient) UnfreezeProcess(pid int, startTicks uint64) error {
	return c.Resume(pid, startTicks, "RESPONSE_TTL_ROLLBACK")
}

func (c *CoreClient) SetCellPolicy(cgroupID uint64, flags uint8) error {
	return c.CellPolicySet(cgroupID, flags)
}

func (c *CoreClient) DeleteCellPolicy(cgroupID uint64) error {
	return c.CellPolicyDelete(cgroupID)
}

func parseCoreExecEvents(response string) ([]CoreExecEvent, error) {
	if response == "empty" {
		return nil, nil
	}
	records := strings.Split(response, ",")
	if len(records) > 24 {
		return nil, errors.New("core returned too many exec events")
	}
	events := make([]CoreExecEvent, 0, len(records))
	for _, record := range records {
		fields := strings.Split(record, ":")
		if len(fields) != 4 {
			return nil, errors.New("core returned malformed exec event")
		}
		pid64, pidErr := strconv.ParseInt(fields[0], 10, 32)
		uid64, uidErr := strconv.ParseUint(fields[1], 10, 32)
		gid64, gidErr := strconv.ParseUint(fields[2], 10, 32)
		comm, commErr := hex.DecodeString(fields[3])
		if pidErr != nil || uidErr != nil || gidErr != nil || commErr != nil ||
			pid64 <= 0 || len(comm) > 16 || strings.ContainsRune(string(comm), '\x00') {
			return nil, errors.New("core returned invalid exec event fields")
		}
		events = append(events, CoreExecEvent{
			PID:  int(pid64),
			UID:  uint32(uid64),
			GID:  uint32(gid64),
			Comm: string(comm),
		})
	}
	return events, nil
}

func parseCoreCellLSMDenyEvents(response string) ([]CoreCellLSMDenyEvent, error) {
	if response == "empty" {
		return nil, nil
	}
	records := strings.Split(response, ",")
	if len(records) > 24 {
		return nil, errors.New("core returned too many Cell LSM events")
	}
	events := make([]CoreCellLSMDenyEvent, 0, len(records))
	for _, record := range records {
		fields := strings.Split(record, ":")
		if len(fields) != 4 {
			return nil, errors.New("core returned a malformed Cell LSM event")
		}
		cgroupID, cgroupErr := strconv.ParseUint(fields[0], 10, 64)
		pid64, pidErr := strconv.ParseInt(fields[1], 10, 32)
		uid64, uidErr := strconv.ParseUint(fields[2], 10, 32)
		family64, familyErr := strconv.ParseInt(fields[3], 10, 32)
		if cgroupErr != nil || pidErr != nil || uidErr != nil || familyErr != nil ||
			cgroupID == 0 || pid64 <= 0 || family64 <= 0 || family64 > 255 || family64 == syscall.AF_UNIX {
			return nil, errors.New("core returned invalid Cell LSM event fields")
		}
		events = append(events, CoreCellLSMDenyEvent{
			CgroupID: cgroupID,
			PID:      int(pid64),
			UID:      uint32(uid64),
			Family:   int32(family64),
		})
	}
	return events, nil
}

const (
	// Allowed batch shape (§5): the core decodes at most 256 newline-separated
	// paths and at most 2048 bytes; the control plane refuses anything larger
	// before dialling, so a policy can never fail halfway through a batch.
	titanExecMaxBatchPaths = 200
	titanExecMaxBatchBytes = 2048

	titanExecMaxStatusPayloadBytes = 512
	titanExecMaxHealthPayloadBytes = 160
	titanExecMaxVersionBytes       = 32
)

// TitanExecAllowIdentity is the parsed ALLOW_ADD answer: the core-resolved kernel
// identity of one allowlisted path. Go never derives this identity itself.
type TitanExecAllowIdentity struct {
	// State is "added" or "exists" (idempotent re-add on a retry).
	State string
	Dev   uint32
	Ino   uint64
}

// TitanExecBatchResult is the parsed ALLOW_ADD_BATCH answer. Error is the core's
// closed error token ("none" on success, a specific reason when Rejected>0); a
// non-zero Rejected count means the sync failed even if some paths were accepted (§5).
type TitanExecBatchResult struct {
	Added    int
	Rejected int
	Error    string
}

// TitanExecCoreStatus is the parsed TITAN_EXEC_STATUS answer (§5). State/Path/LSM/
// Offsets are the kernel-side facts; they are reported verbatim, never inferred.
type TitanExecCoreStatus struct {
	State   string
	Mode    uint8
	Flags   uint8
	Path    string
	LSM     string
	Offsets string
	Entries int
	Scopes  int
	Epoch   string
}

// CoreTitanExecHealth mirrors the fixed six-counter TITAN_EXEC_HEALTH payload.
type CoreTitanExecHealth struct {
	Emitted      uint64
	RingDrops    uint64
	ReadFailures uint64
	Denies       uint64
	Audits       uint64
	CtimeRejects uint64
}

// titanExecCommand issues one TITAN_EXEC_* command and classifies the
// backwards-compatible "unknown command" rejection as ErrTitanExecUnavailable.
func (c *CoreClient) titanExecCommand(parts ...string) (string, error) {
	response, err := c.command(parts...)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "unknown command") || strings.Contains(message, "unsupported command") {
			return "", fmt.Errorf("%w: %v", ErrTitanExecUnavailable, err)
		}
		return "", err
	}
	return response, nil
}

// titanExecExpect issues a command and requires one exact OK payload.
func (c *CoreClient) titanExecExpect(expected string, parts ...string) error {
	response, err := c.titanExecCommand(parts...)
	if err != nil {
		return err
	}
	if response != expected {
		return fmt.Errorf("core returned unexpected titan exec state %q", response)
	}
	return nil
}

func titanExecParseUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized titan exec counter")
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, errors.New("core returned a non-decimal titan exec counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range titan exec counter")
	}
	return value, nil
}

func titanExecValidEpoch(field string) bool {
	if len(field) != 16 {
		return false
	}
	for index := 0; index < len(field); index++ {
		character := field[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

// TitanExecVersion negotiates the TitanExec ABI. A pre-TitanExec core yields
// ErrTitanExecUnavailable.
func (c *CoreClient) TitanExecVersion() (string, error) {
	version, err := c.titanExecCommand("TITAN_EXEC_VERSION")
	if err != nil {
		return "", err
	}
	if len(version) > titanExecMaxVersionBytes || version != titanExecSupportedVersion {
		return "", fmt.Errorf("core returned unsupported titan exec version %q", version)
	}
	return version, nil
}

// TitanExecEpoch returns the 16-hex-character epoch that changes on every core
// start; a changed epoch means the maps were lost and a full re-sync is required.
func (c *CoreClient) TitanExecEpoch() (string, error) {
	epoch, err := c.titanExecCommand("TITAN_EXEC_EPOCH")
	if err != nil {
		return "", err
	}
	if !titanExecValidEpoch(epoch) {
		return "", errors.New("core returned an invalid titan exec epoch")
	}
	return strings.ToLower(epoch), nil
}

// TitanExecSetGlobal applies the host-wide mode and the REQUIRE_CTIME flag. The
// global mode range is 0..4: V6.2 adds TITAN_EXEC_MODE_UNTRUSTED (4) as a global
// default-deny mode for untrusted exec paths. Per-scope overrides stay 0..3.
// The core answers with Err "enforcement-unavailable" when mode>0 and the BPF-LSM
// hook is not attached; the caller reports that as inactive, never as applied.
func (c *CoreClient) TitanExecSetGlobal(mode, flags uint8) error {
	if mode > 4 {
		return errors.New("titan exec global mode is out of range")
	}
	if flags&^uint8(titanExecGlobalFlagRequireCtime) != 0 {
		return errors.New("titan exec global flags are out of range")
	}
	return c.titanExecExpect("applied", "TITAN_EXEC_SET_GLOBAL",
		strconv.FormatUint(uint64(mode), 10), strconv.FormatUint(uint64(flags), 10))
}

// TitanExecAllowAdd allowlists one canonical absolute path. The core resolves and
// returns the kernel identity (dev, ino); a symlink, non-regular file, non
// executable file or read failure is an error, not a silent skip.
func (c *CoreClient) TitanExecAllowAdd(path string) (TitanExecAllowIdentity, error) {
	canonical, err := titanExecCanonicalPath(path)
	if err != nil {
		return TitanExecAllowIdentity{}, err
	}
	response, err := c.titanExecCommand("TITAN_EXEC_ALLOW_ADD", canonical)
	if err != nil {
		return TitanExecAllowIdentity{}, err
	}
	return parseTitanExecAllowIdentity(response)
}

// TitanExecAllowAddBatch adds a bounded set of canonical paths in one command. The
// decoded wire form is the newline-separated path list, base64url encoded (§5).
func (c *CoreClient) TitanExecAllowAddBatch(paths []string) (TitanExecBatchResult, error) {
	if len(paths) == 0 || len(paths) > titanExecMaxBatchPaths {
		return TitanExecBatchResult{}, fmt.Errorf("titan exec batch must carry 1..%d paths", titanExecMaxBatchPaths)
	}
	canonical := make([]string, 0, len(paths))
	decodedBytes := 0
	for _, path := range paths {
		value, err := titanExecCanonicalPath(path)
		if err != nil {
			return TitanExecBatchResult{}, err
		}
		decodedBytes += len(value) + 1
		if decodedBytes-1 > titanExecMaxBatchBytes {
			return TitanExecBatchResult{}, fmt.Errorf("titan exec batch exceeds %d decoded bytes", titanExecMaxBatchBytes)
		}
		canonical = append(canonical, value)
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(strings.Join(canonical, "\n")))
	response, err := c.titanExecCommand("TITAN_EXEC_ALLOW_ADD_BATCH", payload)
	if err != nil {
		return TitanExecBatchResult{}, err
	}
	result, err := parseTitanExecBatchResult(response)
	if err != nil {
		return TitanExecBatchResult{}, err
	}
	if result.Added+result.Rejected > len(canonical) {
		return TitanExecBatchResult{}, errors.New("core reported more batch results than submitted paths")
	}
	return result, nil
}

// TitanExecAllowDel removes one allowlisted kernel identity. Deletion is idempotent
// on the core (KeyNotFound still answers "deleted").
func (c *CoreClient) TitanExecAllowDel(dev uint32, ino uint64) error {
	if dev == 0 || ino == 0 {
		return errors.New("titan exec delete requires a non-zero dev and ino")
	}
	return c.titanExecExpect("deleted", "TITAN_EXEC_ALLOW_DEL",
		strconv.FormatUint(uint64(dev), 10), strconv.FormatUint(ino, 10))
}

// TitanExecClear removes every allowlist entry. It is only issued while the global
// mode is off (fail-safe ordering), because an empty map denies in STRICT mode.
func (c *CoreClient) TitanExecClear() error {
	return c.titanExecExpect("cleared", "TITAN_EXEC_CLEAR")
}

// TitanExecScopeSet applies one per-cgroup mode/flags override.
func (c *CoreClient) TitanExecScopeSet(cgroupID uint64, mode, flags uint8) error {
	if cgroupID == 0 {
		return errors.New("titan exec scope cgroup id is invalid")
	}
	if mode > 3 {
		return errors.New("titan exec scope mode is out of range")
	}
	if flags&^uint8(titanExecScopeFlagJitAllow) != 0 {
		return errors.New("titan exec scope flags are out of range")
	}
	return c.titanExecExpect("applied", "TITAN_EXEC_SCOPE_SET", strconv.FormatUint(cgroupID, 10),
		strconv.FormatUint(uint64(mode), 10), strconv.FormatUint(uint64(flags), 10))
}

// TitanExecScopeDel removes one per-cgroup override (idempotent on the core).
func (c *CoreClient) TitanExecScopeDel(cgroupID uint64) error {
	if cgroupID == 0 {
		return errors.New("titan exec scope cgroup id is invalid")
	}
	return c.titanExecExpect("deleted", "TITAN_EXEC_SCOPE_DEL", strconv.FormatUint(cgroupID, 10))
}

// TitanExecHealth reports the six kernel-side exec-gate counters.
func (c *CoreClient) TitanExecHealth() (CoreTitanExecHealth, error) {
	response, err := c.titanExecCommand("TITAN_EXEC_HEALTH")
	if err != nil {
		return CoreTitanExecHealth{}, err
	}
	return parseCoreTitanExecHealth(response)
}

// parseTitanExecAllowIdentity decodes "added:<dev>:<ino>" / "exists:<dev>:<ino>".
func parseTitanExecAllowIdentity(payload string) (TitanExecAllowIdentity, error) {
	if len(payload) > 64 || strings.TrimSpace(payload) != payload {
		return TitanExecAllowIdentity{}, errors.New("core returned a malformed titan exec allow identity")
	}
	fields := strings.Split(payload, ":")
	if len(fields) != 3 || (fields[0] != "added" && fields[0] != "exists") {
		return TitanExecAllowIdentity{}, errors.New("core returned a malformed titan exec allow identity")
	}
	dev, devErr := titanExecParseUint(fields[1], 32)
	ino, inoErr := titanExecParseUint(fields[2], 64)
	if devErr != nil || inoErr != nil || dev == 0 || ino == 0 {
		return TitanExecAllowIdentity{}, errors.New("core returned an invalid titan exec allow identity")
	}
	return TitanExecAllowIdentity{State: fields[0], Dev: uint32(dev), Ino: ino}, nil
}

// titanExecBatchErrorTokens is the closed reason vocabulary of the Rust core's
// ALLOW_ADD_BATCH answer (P1-T3). "none" is the success token; a rejection always
// carries its specific reason instead.
var titanExecBatchErrorTokens = map[string]bool{
	"none": true, "empty": true, "too-long": true, "nul": true,
	"not-absolute": true, "not-canonical": true, "open-failed": true,
	"symlink": true, "not-regular": true, "not-executable": true,
	"device-out-of-range": true, "clock-out-of-range": true,
	"cap-reached": true, "map-write-failed": true, "store-write-failed": true,
}

// parseTitanExecBatchResult decodes "added:<n>;rejected:<n>;error=<token>". The
// token is a closed core vocabulary: "none" without a rejection, a specific reason
// with one. Anything else is a protocol violation and never a successful sync.
func parseTitanExecBatchResult(payload string) (TitanExecBatchResult, error) {
	if len(payload) > 256 || strings.ContainsAny(payload, "\x00\r\n") {
		return TitanExecBatchResult{}, errors.New("core returned a malformed titan exec batch result")
	}
	fields := strings.Split(payload, ";")
	if len(fields) != 3 ||
		!strings.HasPrefix(fields[0], "added:") ||
		!strings.HasPrefix(fields[1], "rejected:") ||
		!strings.HasPrefix(fields[2], "error=") {
		return TitanExecBatchResult{}, errors.New("core returned a malformed titan exec batch result")
	}
	added, addedErr := titanExecParseUint(strings.TrimPrefix(fields[0], "added:"), 16)
	rejected, rejectedErr := titanExecParseUint(strings.TrimPrefix(fields[1], "rejected:"), 16)
	if addedErr != nil || rejectedErr != nil || added > titanExecMaxBatchPaths || rejected > titanExecMaxBatchPaths {
		return TitanExecBatchResult{}, errors.New("core returned invalid titan exec batch counters")
	}
	token := strings.TrimPrefix(fields[2], "error=")
	if !titanExecBatchErrorTokens[token] {
		return TitanExecBatchResult{}, errors.New("core returned an unknown titan exec batch error token")
	}
	// "none" and "empty" describe the absence of a rejection; a rejection must name
	// its specific reason, otherwise the sync would fail without saying why.
	if rejected == 0 && token != "none" {
		return TitanExecBatchResult{}, errors.New("core returned an inconsistent titan exec batch result")
	}
	if rejected > 0 && (token == "none" || token == "empty") {
		return TitanExecBatchResult{}, errors.New("core returned an inconsistent titan exec batch result")
	}
	return TitanExecBatchResult{Added: int(added), Rejected: int(rejected), Error: token}, nil
}

// parseCoreTitanExecHealth decodes the fixed six-counter payload
// "emitted:ring_drops:read_failures:denies:audits:ctime_rejects".
func parseCoreTitanExecHealth(payload string) (CoreTitanExecHealth, error) {
	if len(payload) == 0 || len(payload) > titanExecMaxHealthPayloadBytes {
		return CoreTitanExecHealth{}, errors.New("core returned an oversized titan exec health payload")
	}
	fields := strings.Split(payload, ":")
	if len(fields) != 6 {
		return CoreTitanExecHealth{}, errors.New("core returned malformed titan exec health")
	}
	values := make([]uint64, len(fields))
	for index, field := range fields {
		value, err := titanExecParseUint(field, 64)
		if err != nil {
			return CoreTitanExecHealth{}, errors.New("core returned invalid titan exec health counters")
		}
		values[index] = value
	}
	return CoreTitanExecHealth{
		Emitted: values[0], RingDrops: values[1], ReadFailures: values[2],
		Denies: values[3], Audits: values[4], CtimeRejects: values[5],
	}, nil
}
