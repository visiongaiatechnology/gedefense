// STATUS: DIAMANT VGT SUPREME
package main

// POINT 2 / P2-T3: VGTGC2 command codec - bounded, all-or-nothing payload parsing.
import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func (c *parserCellClient) Capabilities() (ParserCellCapabilities, error) {
	raw, fd, err := c.request("CELL_CAPABILITIES", nil)
	if err != nil {
		return ParserCellCapabilities{}, err
	}
	if fd >= 0 {
		_ = syscall.Close(fd)
		return ParserCellCapabilities{}, parserCellProtocol("unexpected descriptor on a capabilities answer")
	}
	fields, wayland, err := parseParserCellCapabilitiesPayload(raw)
	if err != nil {
		return ParserCellCapabilities{}, err
	}
	if fields[0] != parserCellsABI {
		return ParserCellCapabilities{}, fmt.Errorf("%w: unsupported helper abi", ErrParserCellsRuntimeUnavailable)
	}
	sandbox, err := parserCellBoolField(fields, 1)
	if err != nil {
		return ParserCellCapabilities{}, err
	}
	profiles, err := parserCellProfileList(fields[2])
	if err != nil {
		return ParserCellCapabilities{}, err
	}
	concurrent, err := parserCellIntField(fields, 3, parserCellsMaxConcurrentCap)
	if err != nil {
		return ParserCellCapabilities{}, err
	}
	inputBytes, err := parserCellIntField(fields, 4, parserCellsMaxInputBytesCap)
	if err != nil {
		return ParserCellCapabilities{}, err
	}
	exportBytes, err := parserCellIntField(fields, 5, parserCellsMaxExportBytesCap)
	if err != nil {
		return ParserCellCapabilities{}, err
	}
	ttlMax, err := parserCellIntField(fields, 6, parserCellsMaxTTLSeconds)
	if err != nil {
		return ParserCellCapabilities{}, err
	}
	if fields[7] != "active" && fields[7] != "inactive" {
		return ParserCellCapabilities{}, parserCellProtocol("invalid bpf_lsm capability value")
	}
	return ParserCellCapabilities{ABI: parserCellsABI, Sandbox: sandbox, Profiles: profiles,
		MaxConcurrent: concurrent, InputBytes: int64(inputBytes), ExportBytes: int64(exportBytes),
		TTLMax: ttlMax, BPFLSM: fields[7] == "active", Wayland: wayland}, nil
}

// parseParserCellCapabilitiesPayload accepts the documented eight fields plus an
// optional additive `wayland` capability, so a future helper can advertise display
// support without breaking this client. A missing field is the phase-1 fact false.
func parseParserCellCapabilitiesPayload(raw []byte) ([]string, bool, error) {
	fields, err := parseParserCellPayload(raw, "abi", "sandbox", "profiles", "max_concurrent", "input_bytes", "export_bytes", "ttl_max", "bpf_lsm")
	if err == nil {
		return fields, false, nil
	}
	extended, extendedErr := parseParserCellPayload(raw, "abi", "sandbox", "profiles", "max_concurrent", "input_bytes", "export_bytes", "ttl_max", "bpf_lsm", "wayland")
	if extendedErr != nil {
		return nil, false, err
	}
	switch extended[8] {
	case "false":
		return extended[:8], false, nil
	case "true":
		return extended[:8], true, nil
	}
	return nil, false, parserCellProtocol("invalid wayland capability value")
}
func (c *parserCellClient) Create(req ParserCellCreateRequest) (ParserCellCreateResult, error) {
	maxRSS, maxPIDs := req.MaxRSSBytes, req.MaxPIDs
	if maxRSS <= 0 {
		maxRSS = parserCellCreateMaxRSSBytes
	}
	if maxPIDs <= 0 {
		maxPIDs = parserCellCreateMaxPIDs
	}
	raw, fd, err := c.request(parserCellCommandCreate, []string{
		"profile=" + req.Profile, "input_token=" + req.InputToken, "input_sha256=" + req.InputSHA256,
		"input_size=" + strconv.FormatInt(req.InputSize, 10), "ttl_seconds=" + strconv.Itoa(req.TTLSeconds),
		"max_rss_bytes=" + strconv.FormatInt(maxRSS, 10), "max_pids=" + strconv.Itoa(maxPIDs),
	})
	if err != nil {
		return ParserCellCreateResult{}, err
	}
	if fd >= 0 {
		_ = syscall.Close(fd)
		return ParserCellCreateResult{}, parserCellProtocol("unexpected descriptor on a create answer")
	}
	fields, err := parseParserCellPayload(raw, "uuid", "generation", "cgroup_id", "cgroup_path", "pid", "expires_at", "sandbox", "netns")
	if err != nil {
		return ParserCellCreateResult{}, err
	}
	result := ParserCellCreateResult{CgroupPath: fields[3]}
	if result.UUID, err = parserCellHexField(fields, 0, 32); err != nil {
		return ParserCellCreateResult{}, err
	}
	var generation uint64
	if generation, err = parserCellUintField(fields, 1, 1<<32); err != nil || generation == 0 {
		return ParserCellCreateResult{}, parserCellProtocol("invalid cell generation")
	}
	result.Generation = generation
	var cgroupID uint64
	if cgroupID, err = parserCellUintField(fields, 2, 1<<63); err != nil || cgroupID == 0 {
		return ParserCellCreateResult{}, parserCellProtocol("invalid cgroup id")
	}
	result.CgroupID = cgroupID
	if len(result.CgroupPath) > 256 || !strings.HasPrefix(result.CgroupPath, "/") {
		return ParserCellCreateResult{}, parserCellProtocol("invalid cgroup path")
	}
	pid, err := parserCellIntField(fields, 4, 1<<22)
	if err != nil || pid <= 0 {
		return ParserCellCreateResult{}, parserCellProtocol("invalid cell pid")
	}
	result.PID = pid
	expiresAt, err := parserCellIntField(fields, 5, 1<<62)
	if err != nil || expiresAt <= 0 {
		return ParserCellCreateResult{}, parserCellProtocol("invalid cell expiry")
	}
	result.ExpiresAt = int64(expiresAt)
	if result.Sandbox, err = parserCellBoolField(fields, 6); err != nil {
		return ParserCellCreateResult{}, err
	}
	if result.NetNS, err = parserCellBoolField(fields, 7); err != nil {
		return ParserCellCreateResult{}, err
	}
	return result, nil
}
func (c *parserCellClient) List() ([]ParserCellRemote, error) {
	raw, fd, err := c.request("CELL_LIST", nil)
	if err != nil {
		return nil, err
	}
	if fd >= 0 {
		_ = syscall.Close(fd)
		return nil, parserCellProtocol("unexpected descriptor on a list answer")
	}
	return parseParserCellList(raw)
}
func (c *parserCellClient) Freeze(uuid string, generation, cgroupID uint64) error {
	return c.cellStateCommand("CELL_FREEZE", "applied", uuid, generation, cgroupID)
}
func (c *parserCellClient) Unfreeze(uuid string, generation, cgroupID uint64) error {
	return c.cellStateCommand("CELL_UNFREEZE", "deleted", uuid, generation, cgroupID)
}

func (c *parserCellClient) cellStateCommand(command, expected, uuid string, generation, cgroupID uint64) error {
	raw, fd, err := c.request(command, []string{"uuid=" + uuid, "generation=" + strconv.FormatUint(generation, 10), "cgroup_id=" + strconv.FormatUint(cgroupID, 10)})
	if err != nil {
		return err
	}
	if fd >= 0 {
		_ = syscall.Close(fd)
		return parserCellProtocol("unexpected descriptor on a state answer")
	}
	fields, err := parseParserCellPayload(raw, "state")
	if err != nil {
		return err
	}
	if fields[0] != expected {
		return parserCellProtocol("unexpected idempotent state answer")
	}
	return nil
}

func (c *parserCellClient) Burn(uuid string, generation, cgroupID uint64, evidenceID, reason string) (ParserCellBurnResult, error) {
	raw, fd, err := c.request("CELL_BURN", []string{
		"uuid=" + uuid, "generation=" + strconv.FormatUint(generation, 10),
		"cgroup_id=" + strconv.FormatUint(cgroupID, 10),
		"evidence_id=" + parserCellToken(evidenceID), "reason=" + parserCellToken(reason),
	})
	if err != nil {
		return ParserCellBurnResult{}, err
	}
	if fd >= 0 {
		_ = syscall.Close(fd)
		return ParserCellBurnResult{}, parserCellProtocol("unexpected descriptor on a burn answer")
	}
	fields, err := parseParserCellPayload(raw, "burned", "export_size", "export_sha256")
	if err != nil {
		return ParserCellBurnResult{}, err
	}
	burned, err := parserCellBoolField(fields, 0)
	if err != nil || !burned {
		return ParserCellBurnResult{}, &ParserCellError{Code: "burn-failed"}
	}
	size, err := parserCellIntField(fields, 1, parserCellsMaxExportBytesCap)
	if err != nil {
		return ParserCellBurnResult{}, err
	}
	sha := fields[2]
	if size > 0 {
		if sha, err = parserCellHexField(fields, 2, 64); err != nil {
			return ParserCellBurnResult{}, err
		}
	} else if sha != "-" && len(sha) != 64 {
		return ParserCellBurnResult{}, parserCellProtocol("invalid export digest")
	}
	return ParserCellBurnResult{Burned: true, ExportSize: int64(size), ExportSHA: sha}, nil
}

func (c *parserCellClient) ExportRead(uuid string, generation uint64, maxBytes int64) (*os.File, ParserCellExportMeta, error) {
	raw, fd, err := c.request(parserCellCommandExportRead, []string{"uuid=" + uuid, "generation=" + strconv.FormatUint(generation, 10)})
	fail := func(meta ParserCellExportMeta, failure error) (*os.File, ParserCellExportMeta, error) {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
		return nil, meta, failure
	}
	if err != nil {
		return nil, ParserCellExportMeta{}, err
	}
	if fd < 0 {
		return fail(ParserCellExportMeta{}, parserCellProtocol("export answer carries no descriptor"))
	}
	fields, err := parseParserCellPayload(raw, "size", "sha256", "type")
	if err != nil {
		return fail(ParserCellExportMeta{}, err)
	}
	size, err := parserCellIntField(fields, 0, parserCellsMaxExportBytesCap)
	if err != nil {
		return fail(ParserCellExportMeta{}, err)
	}
	if maxBytes > 0 && int64(size) > maxBytes {
		return fail(ParserCellExportMeta{}, parserCellProtocol("export exceeds the configured export bound"))
	}
	sha, err := parserCellHexField(fields, 1, 64)
	if err != nil {
		return fail(ParserCellExportMeta{}, err)
	}
	if fields[2] != "file" && fields[2] != "memfd" {
		return fail(ParserCellExportMeta{}, parserCellProtocol("unsupported export type"))
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fail(ParserCellExportMeta{}, parserCellProtocol("export descriptor is not a regular file"))
	}
	if stat.Size < 0 || stat.Size != int64(size) {
		return fail(ParserCellExportMeta{}, parserCellProtocol("export size does not match the descriptor"))
	}
	return os.NewFile(uintptr(fd), "parser-cell-export"), ParserCellExportMeta{Size: int64(size), SHA256: sha, Kind: fields[2]}, nil
}

func (c *parserCellClient) Health() (ParserCellHealth, error) {
	raw, fd, err := c.request("CELL_HEALTH", nil)
	if err != nil {
		return ParserCellHealth{}, err
	}
	if fd >= 0 {
		_ = syscall.Close(fd)
		return ParserCellHealth{}, parserCellProtocol("unexpected descriptor on a health answer")
	}
	fields, err := parseParserCellPayload(raw, "state", "active_cells", "burned_total", "last_error", "started_at", "abi")
	if err != nil {
		return ParserCellHealth{}, err
	}
	if fields[5] != parserCellsABI {
		return ParserCellHealth{}, fmt.Errorf("%w: unsupported helper abi", ErrParserCellsRuntimeUnavailable)
	}
	if !parserCellStateValid(fields[0]) {
		return ParserCellHealth{}, parserCellProtocol("invalid helper state")
	}
	active, err := parserCellIntField(fields, 1, parserCellMaxListCells)
	if err != nil {
		return ParserCellHealth{}, err
	}
	burned, err := parserCellUintField(fields, 2, 1<<62)
	if err != nil {
		return ParserCellHealth{}, err
	}
	started, err := parserCellIntField(fields, 4, 1<<62)
	if err != nil {
		return ParserCellHealth{}, err
	}
	return ParserCellHealth{State: fields[0], ActiveCells: active, BurnedTotal: burned, LastError: fields[3], StartedAt: int64(started), ABI: fields[5]}, nil
}
