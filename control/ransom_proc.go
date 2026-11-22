// STATUS: DIAMANT VGT SUPREME
package main

// M2.2: resolve the kernel start-time identity of a frozen TGID before asking
// the core for a tree kill. RANSOM_EVENTS carries pid/pgid but deliberately no
// start_ticks, so the control plane must read the same `/proc/<pid>/stat` field
// the core will verify. A wrong or unavailable identity is reported instead of
// sending a zero/forged value: the core's `XDR_KILL_TREE` parser rejects
// start_ticks == 0, and a PID-reuse race must never reach an unrelated process.

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const ransomProcStartField = 19 // stat field 22 after the closing comm ')'.
const ransomProcStatMaxBytes = 4096

// ransomProcStartTicks returns the kernel starttime (field 22) of one live TGID.
func ransomProcStartTicks(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("ransom pid must be positive")
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("read proc stat: %w", err)
	}
	if len(raw) == 0 || len(raw) > ransomProcStatMaxBytes {
		return 0, fmt.Errorf("proc stat size is outside the bound")
	}
	text := string(raw)
	closeParenthesis := strings.LastIndexByte(text, ')')
	if closeParenthesis < 0 || closeParenthesis+2 >= len(text) {
		return 0, fmt.Errorf("proc stat is malformed")
	}
	fields := strings.Fields(text[closeParenthesis+2:])
	if len(fields) <= ransomProcStartField {
		return 0, fmt.Errorf("proc stat has too few fields")
	}
	startTicks, err := strconv.ParseUint(fields[ransomProcStartField], 10, 64)
	if err != nil || startTicks == 0 {
		return 0, fmt.Errorf("proc stat start time is invalid")
	}
	return startTicks, nil
}
