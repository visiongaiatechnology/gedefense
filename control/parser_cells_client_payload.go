// STATUS: DIAMANT VGT SUPREME
package main

// POINT 2 / P2-T3: the all-or-nothing VGTGC2 wire payload codec of the parser-cell
// client (field lists, CELL_LIST row framing, field/state validators). Unknown,
// duplicate or missing fields and out-of-charset values are refused, never repaired.

import (
	"strconv"
	"strings"
)

func buildParserCellPayload(fields []string) (string, error) {
	if len(fields) == 0 {
		return "", nil
	}
	if len(fields) > parserCellMaxFields {
		return "", parserCellProtocol("payload carries too many fields")
	}
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok || !parserCellPayloadKeyValid(key) || !parserCellPayloadValueValid(value) {
			return "", parserCellProtocol("payload field is not wire-safe")
		}
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, parserCellSep), nil
}

func parseParserCellPayload(raw []byte, keys ...string) ([]string, error) {
	if len(raw) > parserCellResponseMaxBytes {
		return nil, parserCellProtocol("payload exceeds the response bound")
	}
	if len(raw) == 0 {
		if len(keys) != 0 {
			return nil, parserCellProtocol("empty payload for a command that requires fields")
		}
		return nil, nil
	}
	allowed := make(map[string]int, len(keys))
	for index, key := range keys {
		allowed[key] = index
	}
	parts := strings.Split(string(raw), parserCellSep)
	if len(parts) > parserCellMaxFields {
		return nil, parserCellProtocol("payload carries too many fields")
	}
	values := make([]string, len(keys))
	seen := make([]bool, len(keys))
	for _, part := range parts {
		key, value, ok := strings.Cut(part, "=")
		if !ok || !parserCellPayloadKeyValid(key) || !parserCellPayloadValueValid(value) {
			return nil, parserCellProtocol("malformed payload field")
		}
		index, allowedKey := allowed[key]
		if !allowedKey {
			return nil, parserCellProtocol("unknown payload field")
		}
		if seen[index] {
			return nil, parserCellProtocol("duplicate payload field")
		}
		seen[index] = true
		values[index] = value
	}
	for _, present := range seen {
		if !present {
			return nil, parserCellProtocol("missing payload field")
		}
	}
	return values, nil
}

func parseParserCellList(raw []byte) ([]ParserCellRemote, error) {
	text := strings.TrimSuffix(string(raw), "\n")
	if text == "" || strings.Contains(text, "\n\n") || len(text) > parserCellResponseMaxBytes {
		return nil, parserCellProtocol("malformed list framing")
	}
	lines := strings.Split(text, "\n")
	countFields, err := parseParserCellPayload([]byte(lines[0]), "count")
	if err != nil {
		return nil, err
	}
	count, err := parserCellUintField(countFields, 0, parserCellMaxListCells)
	if err != nil || int(count) != len(lines)-1 {
		return nil, parserCellProtocol("list count does not match the delivered rows")
	}
	out := make([]ParserCellRemote, 0, count)
	for _, line := range lines[1:] {
		fields, err := parseParserCellPayload([]byte(line), "uuid", "generation", "cgroup_id", "profile", "state", "expires_at", "pid", "export_size")
		if err != nil {
			return nil, err
		}
		var row ParserCellRemote
		if row.UUID, err = parserCellHexField(fields, 0, 32); err != nil {
			return nil, err
		}
		if row.Generation, err = parserCellUintField(fields, 1, 1<<32); err != nil || row.Generation == 0 {
			return nil, parserCellProtocol("invalid generation in list row")
		}
		if row.CgroupID, err = parserCellUintField(fields, 2, 1<<63); err != nil || row.CgroupID == 0 {
			return nil, parserCellProtocol("invalid cgroup id in list row")
		}
		row.Profile = fields[3]
		if row.Profile != "" && !parserCellProfileValid(row.Profile) {
			return nil, parserCellProtocol("invalid profile in list row")
		}
		row.State = fields[4]
		if !parserCellStateValid(row.State) {
			return nil, parserCellProtocol("invalid state in list row")
		}
		expiresAt, err := parserCellIntField(fields, 5, 1<<62)
		if err != nil {
			return nil, err
		}
		pid, err := parserCellIntField(fields, 6, 1<<22)
		if err != nil {
			return nil, err
		}
		exportSize, err := parserCellIntField(fields, 7, parserCellsMaxExportBytesCap)
		if err != nil {
			return nil, err
		}
		row.ExpiresAt, row.PID, row.ExportSize = int64(expiresAt), pid, int64(exportSize)
		out = append(out, row)
	}
	return out, nil
}

func parserCellPayloadKeyValid(key string) bool {
	if key == "" || len(key) > 32 {
		return false
	}
	for index, character := range key {
		allowed := character == '_' || (character >= 'a' && character <= 'z')
		if index > 0 {
			allowed = allowed || (character >= '0' && character <= '9')
		}
		if !allowed {
			return false
		}
	}
	return true
}

func parserCellPayloadValueValid(value string) bool {
	if len(value) > parserCellMaxValueBytes {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '.', character == '_', character == ':', character == '/', character == '+', character == '-':
		// The documented `profiles=<csv-ids>` capability field is the one payload
		// value that contains commas; every other field is range-checked by its own
		// typed validator after parsing, so allowing the comma here cannot inject a
		// field (the field separator is 0x1f, never a comma).
		case character == ',':
		default:
			return false
		}
	}
	return true
}

// parserCellToken sanitises an operator-supplied correlation string (burn reason,
// evidence id) into the payload charset. It is correlation only: no path, no argv.
func parserCellToken(value string) string {
	if value == "" {
		return "-"
	}
	converted := make([]byte, 0, len(value))
	for index := 0; index < len(value) && len(converted) < parserCellsErrorMaxBytes; index++ {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9', character == '.', character == '_',
			character == ':', character == '/', character == '+', character == '-':
			converted = append(converted, character)
		default:
			converted = append(converted, '-')
		}
	}
	if len(converted) == 0 {
		return "-"
	}
	return string(converted)
}

func parserCellStateValid(state string) bool {
	switch state {
	case "ok", "degraded", "requested", "spawned", "isolated", "expiring", "burning", "burned", "failed":
		return true
	}
	return false
}

func parserCellProfileList(csv string) ([]string, error) {
	if csv == "" {
		return []string{}, nil
	}
	profiles := strings.Split(csv, ",")
	if len(profiles) > parserCellsMaxProfiles {
		return nil, parserCellProtocol("helper advertises too many profiles")
	}
	for _, profile := range profiles {
		if !parserCellProfileValid(profile) {
			return nil, parserCellProtocol("helper advertises an invalid profile id")
		}
	}
	return profiles, nil
}

func parserCellUintField(fields []string, index int, max uint64) (uint64, error) {
	value, err := strconv.ParseUint(fields[index], 10, 64)
	if err != nil || value > max {
		return 0, parserCellProtocol("invalid numeric field")
	}
	return value, nil
}

func parserCellIntField(fields []string, index, max int) (int, error) {
	value, err := parserCellUintField(fields, index, uint64(max))
	return int(value), err
}

func parserCellBoolField(fields []string, index int) (bool, error) {
	switch fields[index] {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, parserCellProtocol("invalid boolean field")
}

func parserCellHexField(fields []string, index, length int) (string, error) {
	value := fields[index]
	if len(value) != length || strings.ToLower(value) != value {
		return "", parserCellProtocol("invalid hex field")
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return "", parserCellProtocol("invalid lowercase hex field")
		}
	}
	return value, nil
}
