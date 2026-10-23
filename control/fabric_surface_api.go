// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

// HTTP surface for the Fabric control plane: search, export, two-stage import and
// drift. Plan reference sections 36 to 39.

const (
	importPreviewTTL      = 10 * time.Minute
	importPreviewCapacity = 8
	driftWatchFloor       = 60
)

// pendingImport is a reviewed but not yet applied import. Holding the decoded
// revision server-side means apply can never install a revision other than the
// one that was previewed, even if the client resends different bytes.
type pendingImport struct {
	token      string
	revision   uint64
	candidate  RuntimeSettings
	diff       []FabricSettingDiff
	expires    time.Time
	moduleList []string
}

type importPreviewStore struct {
	mu      sync.Mutex
	secret  []byte
	pending map[string]pendingImport
}

func newImportPreviewStore() (*importPreviewStore, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("import preview secret: %w", err)
	}
	return &importPreviewStore{secret: secret, pending: make(map[string]pendingImport)}, nil
}

// remember stores a reviewed import and returns its token. Expired entries are
// dropped on every call, and the store is bounded, so a client cannot grow it by
// previewing repeatedly.
//
// The token is derived from the reviewed revision's exact content. Binding it to
// a descriptor instead would let two previews that happen to share a revision and
// a change count collide on one token, and the apply would then install the other
// review's configuration.
func (s *importPreviewStore) remember(candidate RuntimeSettings, diff []FabricSettingDiff, revision uint64, now time.Time) (pendingImport, error) {
	entry := pendingImport{
		revision: revision, candidate: candidate, diff: diff,
		expires: now.Add(importPreviewTTL),
	}
	content, err := json.Marshal(candidate)
	if err != nil {
		return pendingImport{}, err
	}
	entry.token = importNonce(s.secret, content, revision, entry.expires)
	entry.moduleList = changedModuleList(diff)

	s.mu.Lock()
	defer s.mu.Unlock()
	for token, existing := range s.pending {
		if now.After(existing.expires) {
			delete(s.pending, token)
		}
	}
	for len(s.pending) >= importPreviewCapacity {
		oldest := ""
		var oldestExpiry time.Time
		for token, existing := range s.pending {
			if oldest == "" || existing.expires.Before(oldestExpiry) {
				oldest, oldestExpiry = token, existing.expires
			}
		}
		delete(s.pending, oldest)
	}
	s.pending[entry.token] = entry
	return entry, nil
}

// claim consumes a reviewed import. A token is single-use: the entry is removed
// whether or not the apply succeeds, so a failed apply must be previewed again.
func (s *importPreviewStore) claim(token string, revision uint64, now time.Time) (pendingImport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.pending[token]
	if !exists {
		return pendingImport{}, errors.New("import preview is unknown or already used")
	}
	delete(s.pending, token)
	if now.After(entry.expires) {
		return pendingImport{}, errors.New("import preview expired; preview the bundle again")
	}
	if entry.revision != revision {
		return pendingImport{}, fmt.Errorf("runtime settings changed since the preview (reviewed revision %d, current %d)", entry.revision, revision)
	}
	return entry, nil
}

// changedModuleList names the modules a diff touches. The keys are prefixed with
// the module name by the diff builder, so they are recovered from the key.
func changedModuleList(diff []FabricSettingDiff) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 8)
	for _, change := range diff {
		module, _, found := cutFabricKey(change.Key)
		if !found || seen[module] {
			continue
		}
		seen[module] = true
		out = append(out, module)
	}
	sort.Strings(out)
	return out
}

func cutFabricKey(key string) (string, string, bool) {
	for index := 0; index < len(key); index++ {
		if key[index] == '.' {
			return key[:index], key[index+1:], true
		}
	}
	return "", "", false
}

// -------------------------------------------------------------- handlers

type fabricSearchResponse struct {
	Query     string            `json:"query"`
	Hits      []FabricSearchHit `json:"hits"`
	Truncated bool              `json:"truncated"`
}

func (s *APIServer) fabricSettingsSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	needle := []rune(query)
	if len(needle) < settingsSearchMinChars {
		apiError(w, http.StatusBadRequest, "search query must contain at least two characters", nil)
		return
	}
	if len(needle) > 64 {
		apiError(w, http.StatusBadRequest, "search query is too long", nil)
		return
	}
	settings := s.settings.Get()
	values := make(map[string]map[string]any, len(fabricModuleSnapshotOrder))
	for _, module := range fabricModuleSnapshotOrder {
		snapshot, err := fabricModuleSnapshot(settings, module)
		if err != nil {
			continue
		}
		raw, err := json.Marshal(snapshot)
		if err != nil {
			continue
		}
		flat := map[string]any{}
		if err := json.Unmarshal(raw, &flat); err != nil {
			continue
		}
		values[module] = map[string]any{}
		flattenSettingsValue("", flat, values[module])
	}
	hits := searchFabricSettings(query, values)
	truncated := len(hits) >= settingsSearchLimit
	writeJSON(w, http.StatusOK, fabricSearchResponse{Query: query, Hits: hits, Truncated: truncated})
}

func (s *APIServer) fabricSettingsExport(w http.ResponseWriter, r *http.Request) {
	if err := drainRequestBody(r); err != nil {
		apiError(w, http.StatusBadRequest, "unexpected request body", err)
		return
	}
	bundle, err := buildSettingsBundle(s.cfg.Node.Name, s.settings.Get(), s.policy, time.Now().UTC())
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, "settings export could not be produced", err)
		return
	}
	if bundle.Signature == "" {
		apiError(w, http.StatusServiceUnavailable, "settings export could not be signed", nil)
		return
	}
	if s.state != nil {
		s.state.AddEvent(Event{Severity: "info", Kind: "settings.exported", Source: "settings",
			Message: fmt.Sprintf("Fabric settings revision %d was exported and signed by %s", bundle.Revision, bundle.Signer)})
	}
	writeJSON(w, http.StatusOK, bundle)
}

type fabricImportPreviewResponse struct {
	Valid        bool                `json:"valid"`
	Token        string              `json:"token"`
	ExpiresAt    time.Time           `json:"expires_at"`
	SourceNode   string              `json:"source_node"`
	SourceRev    uint64              `json:"source_revision"`
	CurrentRev   uint64              `json:"current_revision"`
	Signer       string              `json:"signer"`
	Modules      []string            `json:"modules"`
	Diff         []FabricSettingDiff `json:"diff"`
	DiffComplete bool                `json:"diff_complete"`
}

func (s *APIServer) fabricSettingsImportPreview(w http.ResponseWriter, r *http.Request) {
	if s.imports == nil {
		apiFault(w, http.StatusServiceUnavailable, errors.New("import preview store unavailable"))
		return
	}
	raw, err := readBoundedRequestBody(r, settingsImportMaxBytes)
	if err != nil {
		apiError(w, http.StatusBadRequest, "bundle could not be read", err)
		return
	}
	bundle, err := verifySettingsBundle(raw, s.policy.TrustedPublicKey())
	if err != nil {
		apiError(w, http.StatusBadRequest, "bundle rejected", err)
		return
	}
	current := s.settings.Get()
	candidate, diff, err := decodeSettingsBundle(bundle, current)
	if err != nil {
		apiError(w, http.StatusBadRequest, "bundle rejected", err)
		return
	}
	pending, err := s.imports.remember(candidate, diff, current.Revision, time.Now().UTC())
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, "import preview could not be registered", err)
		return
	}
	modules := make([]string, 0, len(bundle.Modules))
	for module := range bundle.Modules {
		modules = append(modules, module)
	}
	sort.Strings(modules)
	writeJSON(w, http.StatusOK, fabricImportPreviewResponse{
		Valid: true, Token: pending.token, ExpiresAt: pending.expires,
		SourceNode: bundle.Node, SourceRev: bundle.Revision, CurrentRev: current.Revision,
		Signer: bundle.Signer, Modules: modules, Diff: diff, DiffComplete: true,
	})
}

type fabricImportApplyRequest struct {
	Token            string `json:"token"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

func (s *APIServer) fabricSettingsImportApply(w http.ResponseWriter, r *http.Request) {
	if s.imports == nil {
		apiFault(w, http.StatusServiceUnavailable, errors.New("import preview store unavailable"))
		return
	}
	var request fabricImportApplyRequest
	if err := decodeSingleJSONValue(r, 1<<16, &request); err != nil {
		apiError(w, http.StatusBadRequest, "invalid import apply request", err)
		return
	}
	if request.Token == "" || len(request.Token) > 128 {
		apiError(w, http.StatusBadRequest, "an import token from a completed preview is required", nil)
		return
	}
	if request.Token == "" {
		apiError(w, http.StatusBadRequest, "an import token from a completed preview is required", nil)
		return
	}
	current := s.settings.Get()
	if request.ExpectedRevision != current.Revision {
		apiError(w, http.StatusConflict, "runtime settings revision changed", nil)
		return
	}
	pending, err := s.imports.claim(request.Token, request.ExpectedRevision, time.Now().UTC())
	if err != nil {
		apiError(w, http.StatusConflict, "import cannot be applied", err)
		return
	}
	// An import is a configuration change and passes the same guards a dashboard
	// edit passes. Reusing the guard functions rather than restating the rules is
	// what keeps the two paths from diverging.
	if err := s.importGuards(current, pending.candidate); err != nil {
		apiError(w, http.StatusConflict, "import rejected by a release-phase guard", err)
		return
	}
	var allowlistTxn *managementAllowlistKernelTxn
	if !reflect.DeepEqual(current.ManagementAllowlist, pending.candidate.ManagementAllowlist) {
		allowlistTxn, err = s.stageManagementAllowlistChange(current.ManagementAllowlist, pending.candidate.ManagementAllowlist)
		if err != nil {
			apiError(w, http.StatusConflict, "management allowlist pre-apply failed", err)
			return
		}
	}
	// The store commit comes first, exactly as it does for a dashboard edit: a
	// revision that reaches the engines but never reaches disk is drift by
	// construction.
	updated, err := s.settings.Update(pending.candidate)
	if err != nil {
		_ = s.rollbackManagementAllowlistChange(allowlistTxn)
		apiError(w, http.StatusBadRequest, "import rejected by settings validation", err)
		return
	}
	label := "bundle"
	if len(pending.moduleList) > 0 {
		label = strings.Join(pending.moduleList, "+")
	}
	if err := s.applyRuntimeSettings(current, updated, label); err != nil {
		rolledBack, rbErr := s.settings.Rollback(current.Revision)
		if rbErr == nil {
			_ = s.applyRuntimeSettings(updated, rolledBack, label)
		}
		kernelRollbackErr := s.rollbackManagementAllowlistChange(allowlistTxn)
		apiError(w, http.StatusServiceUnavailable, "import apply failed and was rolled back", errors.Join(err, rbErr, kernelRollbackErr))
		return
	}
	if s.state != nil {
		s.state.SetAllowlistReady(s.state.Snapshot().CoreConnected)
	}
	if s.state != nil {
		s.state.AddEvent(Event{Severity: "warning", Kind: "settings.imported", Source: "settings",
			Message: fmt.Sprintf("Fabric settings bundle applied as revision %d across %d module(s)", updated.Revision, len(pending.moduleList))})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"revision": updated.Revision, "modules": pending.moduleList, "diff": pending.diff,
	})
}

type fabricDriftResponse struct {
	Status   string               `json:"status"`
	Revision uint64               `json:"revision"`
	Findings []FabricDriftFinding `json:"findings"`
	Checked  time.Time            `json:"checked_at"`
}

func (s *APIServer) fabricSettingsDrift(w http.ResponseWriter, _ *http.Request) {
	settings := s.settings.Get()
	status, findings := s.driftReport(settings)
	writeJSON(w, http.StatusOK, fabricDriftResponse{
		Status: status, Revision: settings.Revision, Findings: findings, Checked: time.Now().UTC(),
	})
}

// importGuards applies the release-phase restrictions that protect rule wiring
// and restart-class settings. An imported bundle must not be able to install in
// Enforce what the dashboard is forbidden from editing there.
func (s *APIServer) importGuards(current, candidate RuntimeSettings) error {
	phase := s.release.Status().Phase
	if phase == ReleasePhaseObserve || phase == ReleasePhaseDegraded {
		return nil
	}
	if current.XDREnabled && !candidate.XDREnabled {
		return errors.New("XDR can only be disabled in Observe/Degraded")
	}
	if xdrRuleWiringChanged(current, candidate) {
		return errors.New("XDR rule wiring can only be changed in Observe/Degraded")
	}
	if xdrRestartSettingsChanged(current, candidate) {
		return errors.New("restart-required XDR settings can only be changed in Observe/Degraded")
	}
	if l7RuleWiringChanged(effectiveL7Settings(current, s.cfg.L7), effectiveL7Settings(candidate, s.cfg.L7)) {
		return errors.New("L7 rule registry can only be changed in Observe/Degraded")
	}
	if l7RestartClassChanged(effectiveL7Settings(current, s.cfg.L7), effectiveL7Settings(candidate, s.cfg.L7)) {
		return errors.New("restart-required L7 settings can only be changed in Observe/Degraded")
	}
	return nil
}

// -------------------------------------------------------------- drift watch

// startDriftWatch reports configuration drift as an event instead of leaving it
// to whichever operator happens to open the settings page.
func (s *APIServer) startDriftWatch() {
	s.trustMu.Lock()
	if s.driftCancel != nil {
		s.trustMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.driftCancel = cancel
	s.trustMu.Unlock()

	go func() {
		lastStatus := ""
		for {
			interval := 5 * time.Minute
			if s.settings != nil {
				if configured := effectivePolicyTrustSettings(s.settings.Get()).VerifyIntervalSeconds; configured >= driftWatchFloor {
					interval = time.Duration(configured) * time.Second
				}
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if s.state == nil || s.settings == nil {
				continue
			}
			status, findings := s.driftReport(s.settings.Get())
			if status == lastStatus {
				continue
			}
			if status == "CONFIG_DRIFT" {
				s.state.AddEvent(Event{Severity: "warning", Kind: "settings.config_drift", Source: "settings",
					Message: "CONFIG DRIFT: " + driftSummary(findings)})
			} else if lastStatus == "CONFIG_DRIFT" {
				s.state.AddEvent(Event{Severity: "info", Kind: "settings.config_nominal", Source: "settings",
					Message: "Configuration drift resolved; every stored revision is effective"})
			}
			lastStatus = status
		}
	}()
}

func (s *APIServer) stopDriftWatch() {
	s.trustMu.Lock()
	cancel := s.driftCancel
	s.driftCancel = nil
	s.trustMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// ------------------------------------------------------------- body helpers

// readBoundedRequestBody reads at most max bytes and refuses a larger body rather
// than truncating it.
func readBoundedRequestBody(r *http.Request, max int64) ([]byte, error) {
	if r.Body == nil {
		return nil, errors.New("request body is empty")
	}
	limited := io.LimitReader(r.Body, max+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("request body exceeds %d bytes", max)
	}
	if len(raw) == 0 {
		return nil, errors.New("request body is empty")
	}
	var probe any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("request body is not valid JSON: %w", err)
	}
	return raw, nil
}

// drainRequestBody enforces that a request carries exactly one empty JSON value.
func drainRequestBody(r *http.Request) error {
	if r.Body == nil {
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<12))
	var extra any
	if err := decoder.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	if extra != nil {
		return errors.New("request body must be empty")
	}
	return nil
}

// decodeSingleJSONValue rejects a body that carries trailing content after the
// first JSON value. The strict media-type check lives in decodeStrictJSON.
func decodeSingleJSONValue(r *http.Request, max int64, target any) error {
	if r.Body == nil {
		return errors.New("request body is empty")
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, max))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}
