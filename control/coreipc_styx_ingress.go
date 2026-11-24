// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-6: authenticated transport for the StyX phase-2 ingress RX
// observer (`STYX_INGRESS_STATUS`, served by
// `rust/gedefense-core/src/styx_ingress.rs`). The kernel probe only observes;
// this parser treats an absent capability as a fact (`RxObservationAvailable`
// stays false), never as a fake RX claim and never as platform degradation.
//
// Wire contract (both sides must change together):
//
//	attached=0|1:rx_events=<u64>:read_failures=<u64>
//
// exactly three `:`-separated `key=value` fields in that order, bounded ASCII,
// no whitespace. The parser is all-or-nothing: one malformed token rejects the
// whole status response so the control plane never projects a partially parsed
// capability.

import (
	"errors"
	"fmt"
	"strings"
)

// ErrStyxIngressUnavailable marks the capability fact "this core has no ingress
// RX observer command/object" (pre-AP-6 core, rejected command, or an object
// without the AP-6 program). It is not an XDR degradation and must not degrade
// the platform: the phase-2 engine reports it as an explicit limitation and
// never claims RX observation.
var ErrStyxIngressUnavailable = errors.New("styx ingress RX capability unavailable")

// CoreStyxIngressStatus is the strict projection of STYX_INGRESS_STATUS.
type CoreStyxIngressStatus struct {
	// Attached is true only when the core loaded and attached the
	// `gedefense_ingress_flow` cgroup_skb/ingress program.
	Attached bool
	// RxEvents counts ingress FlowEvent records that observer queued into the
	// shared FLOW_EVENTS ring since core start. Nonzero proves the attached hook
	// is really producing RX flow records.
	RxEvents uint64
	// ReadFailures counts packets the bounded ingress parser rejected (the
	// packet itself still passed; only one aggregate update was lost).
	ReadFailures uint64
}

const (
	// maxStyxIngressStatusBytes bounds the status payload well above the worst
	// case (two u64 counters: ~76 bytes) and far below the IPC response budget.
	maxStyxIngressStatusBytes = 128
	styxIngressStatusFields   = 3
)

// StyxIngressStatus queries the ingress RX observer health.
//
// A core without the command family is reported as
// `ErrStyxIngressUnavailable` (capability fact); any other transport or parse
// error is returned as-is so the caller can tell a missing capability from a
// transient IPC failure.
func (c *CoreClient) StyxIngressStatus() (CoreStyxIngressStatus, error) {
	if c == nil {
		return CoreStyxIngressStatus{}, ErrStyxIngressUnavailable
	}
	response, err := c.styxCommand("STYX_INGRESS_STATUS")
	if err != nil {
		if errors.Is(err, ErrStyxUnavailable) {
			return CoreStyxIngressStatus{}, fmt.Errorf("%w: %v", ErrStyxIngressUnavailable, err)
		}
		return CoreStyxIngressStatus{}, err
	}
	return parseCoreStyxIngressStatus(response)
}

// parseCoreStyxIngressStatus decodes the exact three-field status wire. It never
// panics and rejects every shape the core cannot have produced.
func parseCoreStyxIngressStatus(response string) (CoreStyxIngressStatus, error) {
	if len(response) == 0 || len(response) > maxStyxIngressStatusBytes {
		return CoreStyxIngressStatus{}, errors.New("core returned an empty or oversized styx ingress status")
	}
	if strings.TrimSpace(response) != response || strings.IndexByte(response, 0) >= 0 {
		return CoreStyxIngressStatus{}, errors.New("core returned a malformed styx ingress status")
	}
	for i := 0; i < len(response); i++ {
		if response[i] < 0x20 || response[i] > 0x7e {
			return CoreStyxIngressStatus{}, errors.New("core returned a non-printable styx ingress status")
		}
	}
	fields := strings.Split(response, ":")
	if len(fields) != styxIngressStatusFields {
		return CoreStyxIngressStatus{}, errors.New("core returned a malformed styx ingress status")
	}
	if !strings.HasPrefix(fields[0], "attached=") ||
		!strings.HasPrefix(fields[1], "rx_events=") ||
		!strings.HasPrefix(fields[2], "read_failures=") {
		return CoreStyxIngressStatus{}, errors.New("core returned unknown styx ingress status fields")
	}
	attached, err := parseStyxUint(strings.TrimPrefix(fields[0], "attached="), 1)
	if err != nil {
		return CoreStyxIngressStatus{}, errors.New("core returned an invalid styx ingress attached flag")
	}
	rxEvents, err := parseStyxUint(strings.TrimPrefix(fields[1], "rx_events="), 64)
	if err != nil {
		return CoreStyxIngressStatus{}, errors.New("core returned an invalid styx ingress event counter")
	}
	readFailures, err := parseStyxUint(strings.TrimPrefix(fields[2], "read_failures="), 64)
	if err != nil {
		return CoreStyxIngressStatus{}, errors.New("core returned an invalid styx ingress read-failure counter")
	}
	return CoreStyxIngressStatus{
		Attached:     attached == 1,
		RxEvents:     rxEvents,
		ReadFailures: readFailures,
	}, nil
}
