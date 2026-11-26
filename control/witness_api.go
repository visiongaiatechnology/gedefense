package main

// POINT 4 / P4-T2: the operator API of the Out-of-Band Witness
// (docs/POINT4-WITNESS.md §7).
//
// Every route is registered through s.auth, so authentication, the
// X-VGT-Request-ID replay guard and the evidence gate apply exactly as they do to
// every other operator mutation. The read-only surfaces (status, export) expose a
// bounded projection without a path, endpoint, token or key. The push route adds
// a typed confirmation phrase and a dedicated rate budget on top of the shared
// budget, so intent and restraint are both proven before a checkpoint leaves the
// host.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// witnessPushConfirmation proves operator intent for the one route that sends
	// evidence off the host.
	witnessPushConfirmation = "PUSH WITNESS"
	// witnessMutationMaxBytes bounds a witness request body.
	witnessMutationMaxBytes = 8 << 10
	// witnessImportMaxBytes bounds an imported receipt document.
	witnessImportMaxBytes = 16 << 10
)

// AttachWitness wires the witness engine into this server. The engine is
// optional: without it the status endpoint reports an honest unavailable state
// and every mutation is refused instead of dereferencing nil.
func (s *APIServer) AttachWitness(engine *WitnessEngine) {
	s.witness = engine
	if s.witnessLimiter == nil {
		// One operator click is fine; a loop of pushes is not.
		s.witnessLimiter = NewRateLimiter(12, 4)
	}
}

// witnessUnavailableStatus is the honest projection when no engine is wired.
func witnessUnavailableStatus() WitnessStatus {
	return WitnessStatus{
		Enabled: false, Mode: witnessModeOff, Wired: false, Healthy: false,
		QuoteKind: witnessQuoteKindNone, KeyBinding: witnessKeyBinding,
	}
}

// witnessStatus serves GET /api/v1/witness/status: read-only and bounded.
func (s *APIServer) witnessStatus(w http.ResponseWriter, _ *http.Request) {
	if s.witness == nil {
		writeJSON(w, http.StatusOK, witnessUnavailableStatus())
		return
	}
	writeJSON(w, http.StatusOK, s.witness.StatusView())
}

// witnessExport serves GET /api/v1/witness/export: the deterministic JSON export
// plus its compact vgtw1 form. It is read-only for the host; creating the signed
// checkpoint is the only write and it is recorded as witness.export_created.
func (s *APIServer) witnessExport(w http.ResponseWriter, r *http.Request) {
	if s.witness == nil {
		writeWitnessRefusal(w, http.StatusConflict, "witness is not wired into this control plane")
		return
	}
	document, err := s.witness.ExportDocument(r.Context())
	if err != nil {
		s.writeWitnessFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

// witnessCheckpoint serves POST /api/v1/witness/checkpoint: an operator-requested
// checkpoint. The authenticated mutation intent, the replay guard and the evidence
// gate already ran before this handler; the engine records the creation evidence.
func (s *APIServer) witnessCheckpoint(w http.ResponseWriter, r *http.Request) {
	if s.witness == nil {
		writeWitnessRefusal(w, http.StatusConflict, "witness is not wired into this control plane")
		return
	}
	if r.ContentLength > 0 {
		var in struct {
			Reason string `json:"reason"`
		}
		if err := decodeStrictJSON(w, r, witnessMutationMaxBytes, &in); err != nil {
			writeWitnessRefusal(w, http.StatusBadRequest, "invalid witness checkpoint request")
			return
		}
	}
	checkpoint, err := s.witness.CheckpointNow(r.Context())
	if err != nil {
		s.writeWitnessFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"checkpoint": checkpoint, "status": s.witness.StatusView()})
}

// witnessPush serves POST /api/v1/witness/push. It requires the typed
// confirmation phrase, a fresh replay identifier (enforced by auth) and the
// dedicated push budget.
func (s *APIServer) witnessPush(w http.ResponseWriter, r *http.Request) {
	if s.witness == nil {
		writeWitnessRefusal(w, http.StatusConflict, "witness is not wired into this control plane")
		return
	}
	var in struct {
		Confirmation string `json:"confirmation"`
	}
	if err := decodeStrictJSON(w, r, witnessMutationMaxBytes, &in); err != nil {
		writeWitnessRefusal(w, http.StatusBadRequest, "invalid witness push request")
		return
	}
	if strings.TrimSpace(in.Confirmation) != witnessPushConfirmation {
		writeWitnessRefusal(w, http.StatusForbidden, "confirmation required: "+witnessPushConfirmation)
		return
	}
	if s.witnessLimiter == nil {
		s.witnessLimiter = NewRateLimiter(12, 4)
	}
	identity := "witness:" + remoteIdentity(r.RemoteAddr)
	if !s.witnessLimiter.Allow(identity, time.Now()) {
		w.Header().Set("Retry-After", "5")
		writeWitnessRefusal(w, http.StatusTooManyRequests, "witness push rate limit exceeded")
		return
	}
	receipt, err := s.witness.PushNow(r.Context())
	if err != nil {
		s.writeWitnessFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"receipt": receipt, "status": s.witness.StatusView()})
}

// witnessChallenge serves POST /api/v1/witness/challenge: it fetches one fresh,
// bounded, single-use nonce from the configured witness. It is operator-only and
// never returns a transport detail.
func (s *APIServer) witnessChallenge(w http.ResponseWriter, r *http.Request) {
	if s.witness == nil {
		writeWitnessRefusal(w, http.StatusConflict, "witness is not wired into this control plane")
		return
	}
	challenge, err := s.witness.Challenge(r.Context())
	if err != nil {
		s.writeWitnessFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": challenge, "ttl_seconds": s.witness.NonceTTLSeconds()})
}

// witnessImport serves POST /api/v1/witness/import: only a signed witness
// receipt (or a {receipt: ...} envelope) is accepted. A rejection names a
// bounded reason and is recorded as witness.import_rejected.
func (s *APIServer) witnessImport(w http.ResponseWriter, r *http.Request) {
	if s.witness == nil {
		writeWitnessRefusal(w, http.StatusConflict, "witness is not wired into this control plane")
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		writeWitnessRefusal(w, http.StatusBadRequest, "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, witnessImportMaxBytes)
	raw, err := io.ReadAll(io.LimitReader(r.Body, witnessImportMaxBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > witnessImportMaxBytes {
		writeWitnessRefusal(w, http.StatusBadRequest, "witness import body is empty or oversized")
		return
	}
	receipt, err := s.witness.ImportReceipt(r.Context(), raw)
	if err != nil {
		if errors.Is(err, errWitnessDisabled) {
			writeWitnessRefusal(w, http.StatusConflict, "witness is disabled")
			return
		}
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) {
			writeWitnessRefusal(w, http.StatusBadRequest, "witness import body is not valid JSON")
			return
		}
		writeWitnessRefusal(w, http.StatusConflict, "witness import rejected")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "receipt": receipt, "status": s.witness.StatusView()})
}

// writeWitnessFailure maps an engine error onto a stable status without ever
// publishing internal detail.
func (s *APIServer) writeWitnessFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errWitnessDisabled):
		writeWitnessRefusal(w, http.StatusConflict, "witness is disabled")
	case errors.Is(err, errWitnessOutboxFull):
		writeWitnessRefusal(w, http.StatusConflict, "witness outbox is full; no new checkpoint is created")
	case errors.Is(err, errWitnessBusy):
		writeWitnessRefusal(w, http.StatusConflict, "a witness cycle is already running")
	default:
		writeWitnessRefusal(w, http.StatusServiceUnavailable, "witness operation could not be completed")
	}
}

// writeWitnessRefusal answers with a bounded, actionable reason.
func writeWitnessRefusal(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, map[string]string{"error": witnessBoundText(reason, witnessMaxReasonBytes)})
}

// WitnessCheckpointStatus is the bounded checkpoint projection of the status API.
type WitnessCheckpointStatus struct {
	Epoch     uint64 `json:"epoch"`
	Sequence  uint64 `json:"sequence"`
	HeadHash  string `json:"head_hash,omitempty"`
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
}

// WitnessAckStatus is the bounded last-ack projection of the status API.
type WitnessAckStatus struct {
	WitnessSeq   uint64 `json:"witness_seq"`
	CheckpointID string `json:"checkpoint_id"`
	At           string `json:"at"`
}

// WitnessOutboxStatus is the bounded outbox projection of the status API.
type WitnessOutboxStatus struct {
	Depth    int        `json:"depth"`
	Bytes    int64      `json:"bytes"`
	Full     bool       `json:"full"`
	OldestAt *time.Time `json:"oldest_at,omitempty"`
}

// WitnessStatus is the §7 status object. It never carries a path, endpoint,
// token or key: only enums, hashes, fingerprints and counters.
type WitnessStatus struct {
	Enabled          bool                     `json:"enabled"`
	Mode             string                   `json:"mode"`
	Wired            bool                     `json:"wired"`
	Healthy          bool                     `json:"healthy"`
	Degraded         bool                     `json:"degraded"`
	DegradedReason   string                   `json:"degraded_reason,omitempty"`
	LastError        string                   `json:"last_error,omitempty"`
	Checkpoint       *WitnessCheckpointStatus `json:"checkpoint,omitempty"`
	LastAck          *WitnessAckStatus        `json:"last_ack,omitempty"`
	Outbox           WitnessOutboxStatus      `json:"outbox"`
	ChallengePending bool                     `json:"challenge_pending"`
	Equivocation     bool                     `json:"equivocation"`
	EquivocationAt   *time.Time               `json:"equivocation_at,omitempty"`
	EquivocationKind string                   `json:"equivocation_kind,omitempty"`
	QuoteKind        string                   `json:"quote_kind"`
	KeyBinding       string                   `json:"key_binding"`
}

// StatusView is the read-only, bounded §7 projection.
func (e *WitnessEngine) StatusView() WitnessStatus {
	e.mu.Lock()
	settings := e.settings
	status := WitnessStatus{
		Enabled: settings.Enabled, Mode: settings.Mode,
		QuoteKind: witnessQuoteKindNone, KeyBinding: witnessKeyBinding,
		Degraded: e.degraded, LastError: witnessBoundText(e.lastError, witnessMaxReasonBytes),
		Equivocation: e.equivocation, EquivocationKind: witnessBoundText(e.equivocationKind, 32),
	}
	if e.equivocationAt != nil {
		at := *e.equivocationAt
		status.EquivocationAt = &at
	}
	if e.lastCheckpoint != nil {
		status.Checkpoint = &WitnessCheckpointStatus{
			Epoch: e.lastCheckpoint.LedgerEpoch, Sequence: e.lastCheckpoint.Sequence,
			HeadHash: e.lastCheckpoint.HeadHash, ID: e.lastCheckpoint.CheckpointID,
			CreatedAt: e.lastCheckpoint.CreatedAt,
		}
	}
	if e.ack.LastWitnessSeq > 0 {
		status.LastAck = &WitnessAckStatus{WitnessSeq: e.ack.LastWitnessSeq, CheckpointID: e.ack.LastCheckpointID, At: e.ack.LastAcceptedAt}
	}
	if e.failClosed != "" {
		status.Degraded = true
		status.DegradedReason = witnessBoundText(e.failClosed, witnessMaxReasonBytes)
	}
	status.Wired = witnessModeActive(settings) && e.failClosed == "" && (settings.Mode != witnessModeHTTP || e.transport != nil)
	outbox := e.outbox
	transport := e.transport
	e.mu.Unlock()
	if outbox != nil {
		status.Outbox = WitnessOutboxStatus{Depth: outbox.depth(), Bytes: outbox.storedBytes(), Full: outbox.full()}
		if oldest := outbox.oldestAt(); !oldest.IsZero() {
			status.Outbox.OldestAt = &oldest
		}
	}
	if transport != nil {
		status.ChallengePending = transport.ChallengePending()
	}
	status.Healthy = status.Enabled && status.Wired && !status.Degraded
	return status
}

func (e *WitnessEngine) setLastError(reason string) {
	e.mu.Lock()
	e.lastError = witnessBoundText(reason, witnessMaxReasonBytes)
	e.mu.Unlock()
}

// recordEvent writes one event through the existing (ledger-backed) event path.
func (e *WitnessEngine) recordEvent(severity, kind, message string) {
	if e.cfg.State == nil {
		return
	}
	e.cfg.State.AddEvent(Event{Severity: severity, Kind: kind, Source: "witness", Message: message})
}

// recordEventOnce writes one event at most once per cooldown, so a recurring
// condition cannot flood the signed chain.
func (e *WitnessEngine) recordEventOnce(key, severity, kind, message string) {
	state := e.cfg.State
	if state == nil {
		return
	}
	now := e.now()
	e.mu.Lock()
	if last, seen := e.eventSeen[key]; seen && now.Sub(last) < witnessEventCooldown {
		e.mu.Unlock()
		return
	}
	e.eventSeen[key] = now
	e.mu.Unlock()
	state.AddEvent(Event{Severity: severity, Kind: kind, Source: "witness", Message: message})
}

// witnessBoundText truncates one operator-visible detail string. The status API
// is read-only and bounded; it is never a place for unbounded output.
func witnessBoundText(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	if max <= 1 {
		return value[:max]
	}
	return value[:max-1] + "…"
}

// witnessNodeID turns the configured node name into the bounded checkpoint token
// §3 accepts, without ever borrowing content from the host.
func witnessNodeID(raw string) string {
	var builder strings.Builder
	for i := 0; i < len(raw) && builder.Len() < witnessCheckpointMaxNodeIDBytes; i++ {
		c := raw[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if alnum || c == '.' || c == '-' || c == '_' || c == ':' {
			builder.WriteByte(c)
		} else {
			builder.WriteByte('-')
		}
	}
	if builder.Len() == 0 {
		return "gedefense"
	}
	return builder.String()
}
