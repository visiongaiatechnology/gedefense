package main

import (
	"errors"
	"strconv"
	"strings"
)

func parseCrossViewUint(field string, bits int) (uint64, error) {
	if field == "" || len(field) > 20 {
		return 0, errors.New("core returned an empty or oversized cross-view counter")
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, errors.New("core returned a non-decimal cross-view counter")
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, errors.New("core returned an out-of-range cross-view counter")
	}
	return value, nil
}

func parseCrossViewBool(field string) (bool, error) {
	switch field {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, errors.New("core returned an invalid cross-view flag")
	}
}

func crossViewPackageDBValid(token string) bool {
	switch token {
	case CrossViewPkgDBDebian, CrossViewPkgDBArch, CrossViewPkgDBUnsupported, CrossViewPkgDBDegraded:
		return true
	default:
		return false
	}
}

// parseCoreCrossViewStatus decodes the exactly-thirteen ordered `key=value`
// status fields.
func parseCoreCrossViewStatus(response string) (CoreCrossViewStatus, error) {
	if len(response) > maxCrossViewStatusBytes || response == "" ||
		strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return CoreCrossViewStatus{}, errors.New("core returned a malformed cross-view status")
	}
	expected := []string{
		"enabled", "scans", "contradictions", "events", "drops", "domains",
		"age_ms", "tap", "mods", "procs", "bpf", "pkgdb", "trace",
	}
	fields := strings.Split(response, ":")
	if len(fields) != len(expected) {
		return CoreCrossViewStatus{}, errors.New("core returned a malformed cross-view status")
	}
	values := make([]string, len(expected))
	for index, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key != expected[index] || value == "" {
			return CoreCrossViewStatus{}, errors.New("core returned an unknown cross-view status field")
		}
		values[index] = value
	}
	counter := func(index int) (uint64, error) {
		return parseCrossViewUint(values[index], 64)
	}
	enabled, err := parseCrossViewBool(values[0])
	if err != nil {
		return CoreCrossViewStatus{}, err
	}
	flag := func(index int) (bool, error) { return parseCrossViewBool(values[index]) }
	var parsed CoreCrossViewStatus
	parsed.Enabled = enabled
	if parsed.Scans, err = counter(1); err != nil {
		return CoreCrossViewStatus{}, err
	}
	if parsed.Contradictions, err = counter(2); err != nil {
		return CoreCrossViewStatus{}, err
	}
	if parsed.Events, err = counter(3); err != nil {
		return CoreCrossViewStatus{}, err
	}
	if parsed.Drops, err = counter(4); err != nil {
		return CoreCrossViewStatus{}, err
	}
	if parsed.Domains, err = counter(5); err != nil {
		return CoreCrossViewStatus{}, err
	}
	if parsed.Domains > uint64(CrossViewDomainMax) {
		return CoreCrossViewStatus{}, errors.New("core returned an out-of-range cross-view domain count")
	}
	if parsed.LastScanAgeMS, err = counter(6); err != nil {
		return CoreCrossViewStatus{}, err
	}
	if parsed.Tap, err = flag(7); err != nil {
		return CoreCrossViewStatus{}, err
	}
	if parsed.Mods, err = flag(8); err != nil {
		return CoreCrossViewStatus{}, err
	}
	if parsed.Procs, err = flag(9); err != nil {
		return CoreCrossViewStatus{}, err
	}
	if parsed.BPF, err = flag(10); err != nil {
		return CoreCrossViewStatus{}, err
	}
	if !crossViewPackageDBValid(values[11]) {
		return CoreCrossViewStatus{}, errors.New("core returned an unknown cross-view package-DB state")
	}
	parsed.PkgDB = values[11]
	if parsed.Trace, err = flag(12); err != nil {
		return CoreCrossViewStatus{}, err
	}
	return parsed, nil
}

// parseCoreCrossViewReport decodes the bounded `bounds=…:key=value` report. The
// first token is mandatory; the remaining keys are a closed set.
func parseCoreCrossViewReport(response string) (CoreCrossViewReport, error) {
	if len(response) > maxCrossViewReportBytes || response == "" ||
		strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return CoreCrossViewReport{}, errors.New("core returned a malformed cross-view report")
	}
	tokens := strings.Split(response, ":")
	var report CoreCrossViewReport
	switch tokens[0] {
	case "bounds=ok":
		report.BoundsOK = true
	case "bounds=degraded":
		report.BoundsOK = false
	default:
		return CoreCrossViewReport{}, errors.New("core returned an unknown cross-view bounds token")
	}
	seen := map[string]bool{}
	for _, token := range tokens[1:] {
		key, value, ok := strings.Cut(token, "=")
		if !ok || value == "" || seen[key] {
			return CoreCrossViewReport{}, errors.New("core returned a malformed cross-view report field")
		}
		seen[key] = true
		switch key {
		case "domains":
			parsed, err := parseCrossViewUint(value, 8)
			if err != nil || parsed > uint64(CrossViewDomainMax) {
				return CoreCrossViewReport{}, errors.New("core returned an out-of-range cross-view domain count")
			}
			report.Domains = parsed
		case "contradictions":
			parsed, err := parseCrossViewUint(value, 64)
			if err != nil {
				return CoreCrossViewReport{}, err
			}
			report.Contradictions = parsed
		case "events":
			parsed, err := parseCrossViewUint(value, 64)
			if err != nil {
				return CoreCrossViewReport{}, err
			}
			report.Events = parsed
		case "scans":
			parsed, err := parseCrossViewUint(value, 64)
			if err != nil {
				return CoreCrossViewReport{}, err
			}
			report.Scans = parsed
		case "drops":
			parsed, err := parseCrossViewUint(value, 64)
			if err != nil {
				return CoreCrossViewReport{}, err
			}
			report.Drops = parsed
		case "age_ms":
			parsed, err := parseCrossViewUint(value, 64)
			if err != nil {
				return CoreCrossViewReport{}, err
			}
			report.LastScanAgeMS = parsed
		case "tap":
			flag, err := parseCrossViewBool(value)
			if err != nil {
				return CoreCrossViewReport{}, err
			}
			report.Tap = flag
		case "mods":
			flag, err := parseCrossViewBool(value)
			if err != nil {
				return CoreCrossViewReport{}, err
			}
			report.Mods = flag
		case "procs":
			flag, err := parseCrossViewBool(value)
			if err != nil {
				return CoreCrossViewReport{}, err
			}
			report.Procs = flag
		case "bpf":
			flag, err := parseCrossViewBool(value)
			if err != nil {
				return CoreCrossViewReport{}, err
			}
			report.BPF = flag
		case "trace":
			flag, err := parseCrossViewBool(value)
			if err != nil {
				return CoreCrossViewReport{}, err
			}
			report.Trace = flag
		case "pkgdb":
			if !crossViewPackageDBValid(value) && value != crossViewStatusPackageDBUnknown {
				return CoreCrossViewReport{}, errors.New("core returned an unknown cross-view package-DB state")
			}
			report.PkgDB = value
		case "pins":
			parsed, err := parseCrossViewUint(value, 64)
			if err != nil {
				return CoreCrossViewReport{}, err
			}
			report.Pins = parsed
		case "reason":
			reasons := strings.Split(value, ",")
			if len(reasons) > crossViewReportReasonTokens {
				return CoreCrossViewReport{}, errors.New("core returned too many cross-view report reasons")
			}
			for _, reason := range reasons {
				if reason == "" || len(reason) > 48 || !crossViewReasonToken(reason) {
					return CoreCrossViewReport{}, errors.New("core returned a malformed cross-view report reason")
				}
			}
			report.Reasons = reasons
		default:
			return CoreCrossViewReport{}, errors.New("core returned an unknown cross-view report field")
		}
	}
	if !seen["domains"] {
		return CoreCrossViewReport{}, errors.New("core returned a cross-view report without domains")
	}
	return report, nil
}

// crossViewReasonToken only accepts the bounded lowercase/underscore vocabulary
// the core document declares (no paths, no spaces, no control bytes).
func crossViewReasonToken(reason string) bool {
	for index := 0; index < len(reason); index++ {
		character := reason[index]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return false
	}
	return true
}

func parseCoreCrossViewEvent(record string) (CoreCrossViewEvent, error) {
	fields := strings.Split(record, ":")
	if len(fields) != 10 {
		return CoreCrossViewEvent{}, errors.New("core returned a malformed cross-view event")
	}
	tsNS, tsErr := parseCrossViewUint(fields[0], 64)
	pid, pidErr := parseCrossViewUint(fields[1], 31)
	uid, uidErr := parseCrossViewUint(fields[2], 32)
	dev, devErr := parseCrossViewUint(fields[3], 32)
	ino, inoErr := parseCrossViewUint(fields[4], 64)
	domain, domainErr := parseCrossViewUint(fields[5], 8)
	kind, kindErr := parseCrossViewUint(fields[6], 8)
	severity, severityErr := parseCrossViewUint(fields[7], 8)
	detail, detailErr := parseCrossViewUint(fields[8], 32)
	if tsErr != nil || pidErr != nil || uidErr != nil || devErr != nil || inoErr != nil ||
		domainErr != nil || kindErr != nil || severityErr != nil || detailErr != nil || tsNS == 0 {
		return CoreCrossViewEvent{}, errors.New("core returned invalid cross-view event fields")
	}
	if domain < uint64(CrossViewDomainEBPFIDGap) || domain > uint64(CrossViewDomainMax) {
		return CoreCrossViewEvent{}, errors.New("core returned an unknown cross-view domain")
	}
	if kind < uint64(CrossViewKindHiddenProg) || kind > uint64(CrossViewKindMax) {
		return CoreCrossViewEvent{}, errors.New("core returned an unknown cross-view kind")
	}
	if !CrossViewKindDomainValid(uint8(domain), uint8(kind)) {
		return CoreCrossViewEvent{}, errors.New("core returned a cross-view kind outside its domain")
	}
	if severity < uint64(CrossViewSeverityInfo) || severity > uint64(CrossViewSeverityCritical) {
		return CoreCrossViewEvent{}, errors.New("core returned an unknown cross-view severity")
	}
	if detail > uint64(^uint32(0)) {
		return CoreCrossViewEvent{}, errors.New("core returned an out-of-range cross-view detail code")
	}
	if len(fields[9]) == 0 || len(fields[9]) > 30 || len(fields[9])%2 != 0 {
		return CoreCrossViewEvent{}, errors.New("core returned a malformed cross-view comm")
	}
	comm, err := decodeStyxHex(fields[9], 16)
	if err != nil || len(comm) == 0 || len(comm) > 15 {
		return CoreCrossViewEvent{}, errors.New("core returned a malformed cross-view comm")
	}
	for _, character := range comm {
		if character < 0x20 || character > 0x7e {
			return CoreCrossViewEvent{}, errors.New("core returned a cross-view comm with rejected characters")
		}
	}
	return CoreCrossViewEvent{
		TsNS:       tsNS,
		Domain:     uint8(domain),
		Kind:       uint8(kind),
		Severity:   uint8(severity),
		PID:        int(pid),
		UID:        uint32(uid),
		Dev:        uint32(dev),
		Ino:        ino,
		DetailCode: uint32(detail),
		Detail:     CrossViewKindName(uint8(kind)),
		Comm:       string(comm),
	}, nil
}
