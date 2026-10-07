// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Internal restart.
//
// Several administrable values are RESTART-class: they are persisted and shown as
// restart_required, and they are deliberately never activated behind the operator's back.
// That design was correct but incomplete - there was no way to perform the restart from
// the product. The operator had to drop to a shell and restart the unit by hand, which is
// why a persisted TLS or L7 change could sit inactive indefinitely, reported as
// "TLS not in path", with no route forward inside the interface.
//
// This closes that gap without weakening the rule that a restart is never silent.
//
// The mechanism is a clean self-exit. The unit carries Restart=always, so systemd brings
// the process back with the persisted revision active. A restart is therefore only
// offered when something will actually perform it: if the process cannot prove it is
// supervised, the request is refused rather than obeyed, because exiting there would stop
// the control plane and leave it stopped. Refusing is the fail-closed answer, and it is
// the honest one - an operator who is told "restarting" and then finds the dashboard gone
// has been misled at the moment they most needed the product to be truthful.

const (
	// systemRestartPerMinute bounds how often a restart may be requested. The limiter is
	// a per-minute bucket, so the value is named for what it is: an earlier name claimed
	// an hourly bound the limiter cannot express. A restart is disruptive and leaves the
	// control plane unauthenticated while it comes back, so the sustained rate is one per
	// minute rather than a burst - the state gate and the evidence requirement are the
	// real guards, and this only stops the endpoint being used to hold the product down.
	systemRestartPerMinute = 1
	// systemRestartBurst is the bucket size for the restart limiter.
	systemRestartBurst = 1
	// systemRestartRequestMaxBytes bounds the request body.
	systemRestartRequestMaxBytes = 4 << 10
	// systemRestartDelay is how long the handler waits before exiting, so the response
	// reaches the operator before the socket closes. The dashboard shows the pending
	// state and reconnects on its own.
	systemRestartDelay = 1200 * time.Millisecond
	// systemRestartMinReason is the shortest accepted justification. A restart is an
	// audited operator action and "x" is not a justification.
	systemRestartMinReason = 8
	// systemRestartMaxReason bounds the recorded text.
	systemRestartMaxReason = 240
)

var (
	systemRestartLimiterOnce sync.Once
	systemRestartLimiter     *RateLimiter
	// systemRestartExit is the seam the tests use to observe a restart without ending
	// the test process. Production always points at os.Exit.
	systemRestartExit = os.Exit
)

func (s *APIServer) systemRestartLimiter() *RateLimiter {
	systemRestartLimiterOnce.Do(func() {
		systemRestartLimiter = NewRateLimiter(systemRestartPerMinute, systemRestartBurst)
	})
	return systemRestartLimiter
}

// supervisedBySystemd reports whether a supervisor will bring this process back.
//
// systemd sets INVOCATION_ID for every unit it starts, and the shipped unit is the only
// supported way to run the control plane. The check is deliberately about the supervisor
// rather than about the binary: restarting is only meaningful when something restarts.
func supervisedBySystemd() bool {
	return strings.TrimSpace(os.Getenv("INVOCATION_ID")) != ""
}

// SystemRestartRequest is the operator's justification for the restart.
type SystemRestartRequest struct {
	Reason string `json:"reason"`
}

// SystemRestartResult is returned before the process exits, so the dashboard can show a
// pending state instead of reporting a failed request against a socket that is closing.
type SystemRestartResult struct {
	Accepted bool   `json:"accepted"`
	Detail   string `json:"detail"`
	// PendingMilliseconds tells the operator how long they have before the dashboard
	// drops. It is a real value read from the same constant the handler uses, not a
	// decorative estimate.
	PendingMilliseconds int `json:"pending_milliseconds"`
}

// systemRestart performs an audited, state-gated self-restart.
func (s *APIServer) systemRestart(w http.ResponseWriter, r *http.Request) {
	var request SystemRestartRequest
	if r.Body != nil {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, systemRestartRequestMaxBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil && !errors.Is(err, os.ErrClosed) {
			// An empty body is not accepted either: the justification is required.
			apiError(w, http.StatusBadRequest, "system restart rejected", fmt.Errorf("decoding restart request: %w", err))
			return
		}
	}
	reason := strings.TrimSpace(request.Reason)
	if len([]rune(reason)) < systemRestartMinReason || len([]rune(reason)) > systemRestartMaxReason {
		apiError(w, http.StatusBadRequest, "system restart rejected", fmt.Errorf("restart reason must contain %d to %d characters", systemRestartMinReason, systemRestartMaxReason))
		return
	}
	if !isPrintableText(reason) {
		apiError(w, http.StatusBadRequest, "system restart rejected", errors.New("restart reason must be printable text"))
		return
	}

	// The control plane may only be restarted when no protection phase would be
	// interrupted. The same rule the restart-class settings already obey.
	if s.state != nil {
		snapshot := s.state.Snapshot()
		phase := strings.ToLower(strings.TrimSpace(snapshot.Release.Phase))
		if phase == "enforce" || phase == "canary" {
			apiError(w, http.StatusConflict, "system restart rejected",
				fmt.Errorf("restart is only permitted in observe or degraded, not %s", phase))
			return
		}
	}

	// The decisive check. Without a supervisor the exit would stop the product and leave
	// it stopped, so the request is refused instead of obeyed.
	if !supervisedBySystemd() {
		apiError(w, http.StatusServiceUnavailable, "system restart unavailable",
			errors.New("no supervisor would restart this process (INVOCATION_ID is unset)"))
		return
	}

	// The allowance is consumed here rather than on entry. A request that fails
	// validation, arrives during an active protection phase or has no supervisor never
	// becomes a restart, so it must not spend the operator's only allowance for the
	// minute - a typo in the justification would otherwise lock the action out.
	if !s.systemRestartLimiter().Allow(remoteIdentity(r.RemoteAddr), time.Now()) {
		w.Header().Set("Retry-After", "60")
		apiError(w, http.StatusTooManyRequests, "system restart rate limit reached", nil)
		return
	}

	// Recorded before the exit, so the intent is attributable even though the process
	// will not be alive to record the outcome.
	if s.state != nil {
		if err := s.state.RecordEvidence(EvidenceRecord{
			Severity: "high", Kind: "system.restart.requested", Source: "operator",
			Message: "Operator requested an internal control-plane restart",
			Target:  "reason=" + reason, RequestID: r.Header.Get("X-VGT-Request-ID"),
		}); err != nil {
			// The evidence gate already refused the request upstream when the ledger is
			// unavailable; reaching here means the commit itself failed. A restart that
			// cannot be recorded does not happen.
			apiError(w, http.StatusServiceUnavailable, "mandatory evidence commit failed", err)
			return
		}
	}

	writeJSON(w, http.StatusAccepted, SystemRestartResult{
		Accepted: true, PendingMilliseconds: int(systemRestartDelay / time.Millisecond),
		Detail: "The control plane is exiting so the supervisor restarts it with the persisted revision active. The dashboard reconnects on its own.",
	})

	// Flush before exiting, otherwise the operator sees a dropped connection instead of
	// the acknowledgement that explains it.
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	if s.restartHook != nil {
		s.restartHook()
	}
	go func() {
		time.Sleep(systemRestartDelay)
		systemRestartExit(0)
	}()
}

// isPrintableText rejects control characters so the reason cannot corrupt the ledger.
func isPrintableText(value string) bool {
	for _, r := range value {
		if r == '\n' || r == '\t' || r == '\r' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
