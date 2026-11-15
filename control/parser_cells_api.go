// STATUS: DIAMANT VGT SUPREME
package main

// POINT 2 / P2-T3: HTTP surface of the ephemeral parser cells (§6).
//
// Every route is registered through s.auth, so authentication, the X-VGT-Request-ID
// replay guard and the evidence gate already apply to every mutating call. The
// handlers add what is specific to this feature: strict bounded JSON, base64 input
// size limits, an explicit confirm phrase for the destructive burn, and an export
// download that is served as an untrusted attachment - never rendered, never
// executed. Disabled means no helper contact at all: status/list answer locally.

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

const (
	parserCellOpenBodyMax    = 8 << 10
	parserCellBurnBodyMax    = 4 << 10
	parserCellListLimit      = 64
	parserCellDownloadQuery  = "download"
	parserCellExportFilename = "export.bin"
	// parserCellInputBodyLimit is the explicit, route-scoped body ceiling of
	// POST /api/v1/parser-cells/inputs: 8 MiB decoded documents base64-encode to
	// ~10.7 MiB, plus JSON overhead. It is deliberately larger than the global
	// administrative mutation ceiling (1 MiB default) and the ONLY such exemption;
	// the decoded size is still hard-checked against MaxInputBytes (<= 8 MiB).
	parserCellInputBodyLimit int64 = 12 << 20
)

// isParserCellInputRequest identifies the one route that carries a document body.
// The security middleware uses it to apply the dedicated parser-input bound while
// every other mutating route keeps the administrable global ceiling unchanged.
func isParserCellInputRequest(r *http.Request) bool {
	return r != nil && r.Method == http.MethodPost && r.URL.Path == "/api/v1/parser-cells/inputs"
}

func (s *APIServer) parserCellsManager() *ParserCellManager {
	if s == nil || s.state == nil {
		return nil
	}
	return s.state.ParserCells()
}

// parserCellPublicMessage is the closed operator-visible error vocabulary of this
// feature. Internal text (helper payloads, paths) never crosses this boundary.
var parserCellPublicMessages = map[string]string{
	"disabled":             "parser cells are disabled",
	"capability-missing":   "parser cell runtime is unavailable",
	"evidence-gate":        "mandatory evidence ledger unavailable",
	"profile-unknown":      "parser profile is unknown or not allowed",
	"profile-invalid":      "parser profile identifier is invalid",
	"input-invalid":        "parser cell input is invalid",
	"input-missing":        "parser cell input token is unknown or expired",
	"cell-limit":           "parser cell concurrency limit reached",
	"sandbox-unavailable":  "the helper could not attest the sandbox",
	"host-layers-required": "required host isolation layers are not applied",
	"unknown-cell":         "parser cell is unknown",
	"export-missing":       "no parser cell export is available",
	"burn-failed":          "parser cell burn failed",
	"conflict":             "parser cell is already in a terminal state",
	"internal":             "parser cell operation failed",
}

func parserCellAPIError(w http.ResponseWriter, err error) {
	code := "internal"
	var helperErr *ParserCellError
	if errors.As(err, &helperErr) {
		code = helperErr.Code
	}
	if errors.Is(err, ErrParserCellsRuntimeUnavailable) && code == "internal" {
		code = "capability-missing"
	}
	message, known := parserCellPublicMessages[code]
	if !known {
		code, message = "internal", parserCellPublicMessages["internal"]
	}
	status := http.StatusInternalServerError
	switch code {
	case "disabled", "capability-missing", "evidence-gate", "sandbox-unavailable", "host-layers-required":
		status = http.StatusServiceUnavailable
	case "profile-unknown", "profile-invalid", "input-invalid", "input-missing":
		status = http.StatusBadRequest
	case "cell-limit":
		status = http.StatusTooManyRequests
	case "unknown-cell", "export-missing":
		status = http.StatusNotFound
	case "burn-failed", "conflict":
		status = http.StatusConflict
	}
	writeJSON(w, status, map[string]string{"error": message, "code": code})
}

// parserCellsStatus reports the bounded runtime projection. Disabled/absent is a
// 200 with an honest status, not an error: the namespace is off by default.
func (s *APIServer) parserCellsStatus(w http.ResponseWriter, _ *http.Request) {
	manager := s.parserCellsManager()
	if manager == nil {
		writeJSON(w, http.StatusOK, ParserCellsStatus{Enabled: false, Available: false, Helper: "disabled",
			LayerCellLSM: parserCellLayerUnavailable + ":unwired", LayerStyxEgress: parserCellLayerUnavailable + ":unwired",
			LayerTitanExec: parserCellLayerUnavailable + ":unwired"})
		return
	}
	writeJSON(w, http.StatusOK, manager.Status())
}

// parserCellsList is the bounded cell list (≤64 rows, independent of the page).
func (s *APIServer) parserCellsList(w http.ResponseWriter, r *http.Request) {
	limit := parserCellListLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > parserCellListLimit {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid parser cell list limit", "code": "input-invalid"})
			return
		}
		limit = parsed
	}
	manager := s.parserCellsManager()
	payload := struct {
		Enabled bool                `json:"enabled"`
		Limit   int                 `json:"limit"`
		Cells   []ParserCellRuntime `json:"cells"`
	}{Limit: limit, Cells: []ParserCellRuntime{}}
	if manager == nil {
		writeJSON(w, http.StatusOK, payload)
		return
	}
	status := manager.Status()
	payload.Enabled = status.Enabled
	if len(status.Cells) > limit {
		payload.Cells = status.Cells[:limit]
	} else if status.Cells != nil {
		payload.Cells = status.Cells
	}
	writeJSON(w, http.StatusOK, payload)
}

// parserCellCurrentMaxInput resolves the administrable input bound without a
// helper request (the namespace is local data).
func (s *APIServer) parserCellCurrentMaxInput() int {
	if s != nil && s.settings != nil {
		return effectiveParserCellsSettings(s.settings.Get()).MaxInputBytes
	}
	return defaultParserCellsFabricSettings().MaxInputBytes
}

// parserCellsInput stages one bounded base64 document and returns the manager
// token/hash/size that /open consumes. The token is minted here, never supplied.
func (s *APIServer) parserCellsInput(w http.ResponseWriter, r *http.Request) {
	manager := s.parserCellsManager()
	if manager == nil {
		parserCellAPIError(w, &ParserCellError{Code: "capability-missing"})
		return
	}
	maxInput := s.parserCellCurrentMaxInput()
	var request struct {
		DataBase64 string `json:"data_base64"`
	}
	if err := decodeStrictJSON(w, r, parserCellInputBodyLimit, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
				"error": "parser cell input exceeds the 12 MiB base64 request bound", "code": "input-invalid"})
			return
		}
		parserCellAPIError(w, &ParserCellError{Code: "input-invalid"})
		return
	}
	data, err := parserCellDecodeBase64(request.DataBase64, maxInput)
	if err != nil {
		parserCellAPIError(w, err)
		return
	}
	input, err := manager.StageInput(data)
	if err != nil {
		parserCellAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, input)
}

func parserCellDecodeBase64(raw string, maxBytes int) ([]byte, error) {
	if raw == "" {
		return nil, &ParserCellError{Code: "input-invalid"}
	}
	if int64(len(raw)) > int64(maxBytes)/3*4+8 {
		return nil, &ParserCellError{Code: "input-invalid"}
	}
	var (
		data []byte
		err  error
	)
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if data, err = encoding.DecodeString(raw); err == nil {
			break
		}
	}
	if err != nil || len(data) == 0 {
		return nil, &ParserCellError{Code: "input-invalid"}
	}
	if len(data) > maxBytes {
		return nil, &ParserCellError{Code: "input-invalid"}
	}
	return data, nil
}

// parserCellsOpen requests one cell. Input, digest and size are exactly what the
// staging step minted; the profile must be allowed by settings and the helper.
func (s *APIServer) parserCellsOpen(w http.ResponseWriter, r *http.Request) {
	manager := s.parserCellsManager()
	if manager == nil {
		parserCellAPIError(w, &ParserCellError{Code: "capability-missing"})
		return
	}
	var request struct {
		Profile    string `json:"profile"`
		InputToken string `json:"input_token"`
		SHA256     string `json:"sha256"`
		Size       int64  `json:"size"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := decodeStrictJSON(w, r, parserCellOpenBodyMax, &request); err != nil {
		parserCellAPIError(w, &ParserCellError{Code: "input-invalid"})
		return
	}
	runtime, err := manager.Create(strings.TrimSpace(request.Profile), strings.TrimSpace(request.InputToken), request.SHA256, request.Size, request.TTLSeconds)
	if err != nil {
		parserCellAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, runtime)
}

func parserCellUUIDValid(uuid string) bool {
	if len(uuid) != 32 {
		return false
	}
	for _, character := range uuid {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// parserCellsBurn is the confirm-gated operator burn. Idempotent: a burned cell
// answers 200 with its terminal state instead of a second destructive call.
func (s *APIServer) parserCellsBurn(w http.ResponseWriter, r *http.Request) {
	manager := s.parserCellsManager()
	if manager == nil {
		parserCellAPIError(w, &ParserCellError{Code: "capability-missing"})
		return
	}
	uuid := strings.TrimSpace(r.PathValue("uuid"))
	if !parserCellUUIDValid(uuid) {
		parserCellAPIError(w, &ParserCellError{Code: "unknown-cell"})
		return
	}
	var request struct {
		Confirm string `json:"confirm"`
	}
	if err := decodeStrictJSON(w, r, parserCellBurnBodyMax, &request); err != nil {
		parserCellAPIError(w, &ParserCellError{Code: "input-invalid"})
		return
	}
	if request.Confirm != "BURN "+uuid {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "confirmation phrase does not match this cell", "code": "input-invalid"})
		return
	}
	runtime, err := manager.Burn(uuid, "operator burn confirmed via dashboard")
	if err != nil {
		parserCellAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, runtime)
}

func (s *APIServer) parserCellsFreeze(w http.ResponseWriter, r *http.Request) {
	s.parserCellStateCommand(w, r, true)
}

func (s *APIServer) parserCellsUnfreeze(w http.ResponseWriter, r *http.Request) {
	s.parserCellStateCommand(w, r, false)
}

func (s *APIServer) parserCellStateCommand(w http.ResponseWriter, r *http.Request, freeze bool) {
	manager := s.parserCellsManager()
	if manager == nil {
		parserCellAPIError(w, &ParserCellError{Code: "capability-missing"})
		return
	}
	uuid := strings.TrimSpace(r.PathValue("uuid"))
	if !parserCellUUIDValid(uuid) {
		parserCellAPIError(w, &ParserCellError{Code: "unknown-cell"})
		return
	}
	var request struct{}
	if err := decodeStrictJSON(w, r, parserCellBurnBodyMax, &request); err != nil {
		parserCellAPIError(w, &ParserCellError{Code: "input-invalid"})
		return
	}
	var (
		runtime ParserCellRuntime
		err     error
	)
	if freeze {
		runtime, err = manager.Freeze(uuid)
	} else {
		runtime, err = manager.Unfreeze(uuid)
	}
	if err != nil {
		parserCellAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, runtime)
}

// parserCellsExport serves the export metadata and - on ?download=1 - the bounded,
// hash-verified bytes as an attachment. The response is untrusted evidence and is
// never rendered or executed by the control plane.
func (s *APIServer) parserCellsExport(w http.ResponseWriter, r *http.Request) {
	manager := s.parserCellsManager()
	if manager == nil {
		parserCellAPIError(w, &ParserCellError{Code: "capability-missing"})
		return
	}
	uuid := strings.TrimSpace(r.PathValue("uuid"))
	if !parserCellUUIDValid(uuid) {
		parserCellAPIError(w, &ParserCellError{Code: "unknown-cell"})
		return
	}
	cell, ok := manager.Cell(uuid)
	if !ok {
		parserCellAPIError(w, &ParserCellError{Code: "unknown-cell"})
		return
	}
	if cell.Export == nil {
		parserCellAPIError(w, &ParserCellError{Code: "export-missing"})
		return
	}
	download := false
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(parserCellDownloadQuery))) {
	case "1", "true", "yes":
		download = true
	}
	if !download {
		writeJSON(w, http.StatusOK, struct {
			UUID   string                `json:"uuid"`
			Export *ParserCellExportMeta `json:"export"`
		}{UUID: uuid, Export: cell.Export})
		return
	}
	data, _, err := manager.ExportDownload(uuid)
	if err != nil {
		parserCellAPIError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="parser-cell-`+uuid+`-`+parserCellExportFilename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		_ = err
	}
}
