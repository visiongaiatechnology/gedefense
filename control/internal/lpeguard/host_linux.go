//go:build linux

package lpeguard

import (
	"errors"
	"io"
	"os"
	"strings"
)

// maxModprobeBytes bounds the concatenated /etc/modprobe.d content.
const maxModprobeBytes = 1 << 20

// ReadHostFacts collects the read-only hardening baseline. It never writes and
// never invokes a helper; missing sources are reported as empty facts.
func ReadHostFacts() HostFacts {
	facts := HostFacts{Modules: make(map[string]bool, 16)}
	if data, err := readBounded("/proc/sys/kernel/randomize_va_space", 64); err == nil {
		facts.ASLR = strings.TrimSpace(data)
	}
	if data, err := readBounded("/proc/modules", maxModprobeBytes); err == nil {
		for _, line := range strings.Split(data, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			name := strings.TrimSuffix(fields[0], ":")
			if name != "" && len(name) <= 64 {
				facts.Modules[name] = true
			}
			if len(facts.Modules) > 65536 {
				break
			}
		}
	}
	facts.Modprobe = readModprobeDropIns()
	return facts
}

// readModprobeDropIns concatenates the bounded content of /etc/modprobe.d.
func readModprobeDropIns() string {
	entries, err := os.ReadDir("/etc/modprobe.d")
	if err != nil {
		return ""
	}
	var builder strings.Builder
	read := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		if read >= 256 {
			break
		}
		data, err := readBounded("/etc/modprobe.d/"+entry.Name(), 64<<10)
		if err != nil {
			continue
		}
		if builder.Len()+len(data) > maxModprobeBytes {
			break
		}
		builder.WriteString(data)
		builder.WriteByte('\n')
		read++
	}
	return builder.String()
}

// readBounded reads at most limit bytes from a file.
func readBounded(path string, limit int) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)))
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", errors.New("empty source")
	}
	return string(data), nil
}
