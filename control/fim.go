// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	fimBaselineSchema = "vgt-gedefense-fim-v1"
	fimPurpose        = "fim-baseline"
	fimMaxFiles       = 8192
	fimMaxFileBytes   = int64(64 << 20)
	fimMaxTotalBytes  = int64(512 << 20)
	fimMaxBaseline    = int64(16 << 20)
	fimMaxFindings    = 500
)

type FIMRecord struct {
	SHA256 string      `json:"sha256"`
	Size   int64       `json:"size"`
	Mode   os.FileMode `json:"mode"`
}

type FIMBaseline struct {
	Schema     string               `json:"schema"`
	Generation uint64               `json:"generation"`
	CreatedAt  time.Time            `json:"created_at"`
	Roots      []string             `json:"roots"`
	Files      map[string]FIMRecord `json:"files"`
}

type FIMFinding struct {
	Path    string `json:"path"`
	Status  string `json:"status"`
	Size    int64  `json:"size,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Message string `json:"message,omitempty"`
}

type FIMScanSummary struct {
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at"`
	Total      int          `json:"total"`
	Verified   int          `json:"verified"`
	Tampered   int          `json:"tampered"`
	Missing    int          `json:"missing"`
	New        int          `json:"new"`
	Errors     int          `json:"errors"`
	Findings   []FIMFinding `json:"findings"`
}

type FIMStatus struct {
	Enabled       bool            `json:"enabled"`
	Health        string          `json:"health"`
	BaselineCount int             `json:"baseline_count"`
	Generation    uint64          `json:"generation"`
	Roots         []string        `json:"roots"`
	LastScan      *FIMScanSummary `json:"last_scan,omitempty"`
	Error         string          `json:"error,omitempty"`
}

type FIMEngine struct {
	mu           sync.RWMutex
	roots        []string
	baselinePath string
	storage      *StorageCipher
	baseline     FIMBaseline
	lastScan     *FIMScanSummary
	integrityErr error
	scanning     bool
}

func NewFIMEngine(paths []string, baselinePath string, storage *StorageCipher) (*FIMEngine, error) {
	if storage == nil {
		return nil, errors.New("FIM requires encrypted storage")
	}
	if !filepath.IsAbs(baselinePath) {
		return nil, errors.New("FIM baseline path must be absolute")
	}
	roots, err := normalizeFIMRoots(paths)
	if err != nil {
		return nil, err
	}
	engine := &FIMEngine{
		roots: roots, baselinePath: baselinePath, storage: storage,
		baseline: FIMBaseline{Schema: fimBaselineSchema, Roots: roots, Files: make(map[string]FIMRecord)},
	}
	if err := engine.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		engine.integrityErr = err
	}
	return engine, nil
}

func normalizeFIMRoots(paths []string) ([]string, error) {
	if len(paths) == 0 || len(paths) > 256 {
		return nil, errors.New("FIM requires 1-256 protected roots")
	}
	unique := make(map[string]struct{}, len(paths))
	for _, raw := range paths {
		if strings.ContainsRune(raw, '\x00') || !filepath.IsAbs(raw) {
			return nil, errors.New("FIM roots must be absolute paths without NUL")
		}
		cleaned := filepath.Clean(raw)
		if cleaned == string(filepath.Separator) {
			return nil, errors.New("FIM refuses an unbounded filesystem-root target")
		}
		unique[cleaned] = struct{}{}
	}
	roots := make([]string, 0, len(unique))
	for root := range unique {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	return roots, nil
}

func (e *FIMEngine) load() error {
	raw, err := readBoundedPrivateFile(e.baselinePath, fimMaxBaseline)
	if err != nil {
		return err
	}
	plaintext, legacy, err := e.storage.Decrypt(e.baselinePath, fimPurpose, raw, nil)
	if err != nil {
		return fmt.Errorf("FIM baseline authentication failed: %w", err)
	}
	if legacy {
		return errors.New("unencrypted FIM baseline is rejected")
	}
	baseline, err := decodeFIMBaseline(plaintext)
	if err != nil {
		return err
	}
	if !equalStrings(baseline.Roots, e.roots) {
		return errors.New("FIM baseline roots differ from configured protected roots")
	}
	e.baseline = baseline
	return nil
}

func decodeFIMBaseline(raw []byte) (FIMBaseline, error) {
	var baseline FIMBaseline
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&baseline); err != nil {
		return FIMBaseline{}, fmt.Errorf("FIM baseline decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return FIMBaseline{}, errors.New("FIM baseline contains trailing data")
	}
	if baseline.Schema != fimBaselineSchema || baseline.Generation == 0 || baseline.CreatedAt.IsZero() {
		return FIMBaseline{}, errors.New("FIM baseline metadata is invalid")
	}
	if len(baseline.Files) == 0 || len(baseline.Files) > fimMaxFiles {
		return FIMBaseline{}, errors.New("FIM baseline file count is outside bounds")
	}
	roots, err := normalizeFIMRoots(baseline.Roots)
	if err != nil || !equalStrings(roots, baseline.Roots) {
		return FIMBaseline{}, errors.New("FIM baseline roots are not canonical")
	}
	for path, record := range baseline.Files {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(record.SHA256) != 64 ||
			record.Size < 0 || record.Size > fimMaxFileBytes {
			return FIMBaseline{}, errors.New("FIM baseline contains an invalid record")
		}
		if _, err := hex.DecodeString(record.SHA256); err != nil {
			return FIMBaseline{}, errors.New("FIM baseline contains an invalid digest")
		}
	}
	return baseline, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (e *FIMEngine) CreateBaseline() (FIMStatus, error) {
	if err := e.beginScan(); err != nil {
		return e.Status(), err
	}
	defer e.endScan()

	files, err := e.collect()
	if err != nil {
		return e.setFault(err), err
	}
	records := make(map[string]FIMRecord, len(files))
	for _, path := range files {
		record, err := hashFIMFile(path)
		if err != nil {
			fault := fmt.Errorf("FIM refused to trust %s: %w", path, err)
			return e.setFault(fault), fault
		}
		records[path] = record
	}
	if len(records) == 0 {
		err := errors.New("FIM baseline cannot be empty")
		return e.setFault(err), err
	}

	e.mu.RLock()
	generation := e.baseline.Generation + 1
	e.mu.RUnlock()
	baseline := FIMBaseline{
		Schema: fimBaselineSchema, Generation: generation, CreatedAt: time.Now().UTC(),
		Roots: append([]string(nil), e.roots...), Files: records,
	}
	plaintext, err := json.Marshal(baseline)
	if err != nil {
		return e.setFault(err), err
	}
	sealed, err := e.storage.Encrypt(e.baselinePath, fimPurpose, generation, plaintext)
	if err != nil {
		return e.setFault(err), err
	}
	if err := os.MkdirAll(filepath.Dir(e.baselinePath), 0o700); err != nil {
		return e.setFault(err), err
	}
	if err := atomicWriteFile(e.baselinePath, sealed, 0o600); err != nil {
		return e.setFault(err), err
	}

	e.mu.Lock()
	e.baseline = baseline
	e.integrityErr = nil
	e.lastScan = nil
	e.mu.Unlock()
	return e.Status(), nil
}

func (e *FIMEngine) Scan() (FIMScanSummary, error) {
	if err := e.beginScan(); err != nil {
		return FIMScanSummary{}, err
	}
	defer e.endScan()

	e.mu.RLock()
	baseline := cloneFIMBaseline(e.baseline)
	loadErr := e.integrityErr
	e.mu.RUnlock()
	if loadErr != nil {
		return FIMScanSummary{}, loadErr
	}
	if baseline.Generation == 0 {
		return FIMScanSummary{}, errors.New("FIM baseline has not been created")
	}
	files, err := e.collect()
	if err != nil {
		e.setFault(err)
		return FIMScanSummary{}, err
	}

	started := time.Now().UTC()
	summary := FIMScanSummary{StartedAt: started, Findings: make([]FIMFinding, 0)}
	seen := make(map[string]struct{}, len(files))
	for _, path := range files {
		seen[path] = struct{}{}
		summary.Total++
		current, hashErr := hashFIMFile(path)
		if hashErr != nil {
			summary.Errors++
			appendFIMFinding(&summary, FIMFinding{Path: path, Status: "ERROR", Message: "file could not be verified"})
			continue
		}
		expected, exists := baseline.Files[path]
		if !exists {
			summary.New++
			appendFIMFinding(&summary, FIMFinding{Path: path, Status: "NEW", Size: current.Size, Mode: current.Mode.String()})
			continue
		}
		if current.SHA256 != expected.SHA256 || current.Size != expected.Size || current.Mode != expected.Mode {
			summary.Tampered++
			appendFIMFinding(&summary, FIMFinding{Path: path, Status: "TAMPERED", Size: current.Size, Mode: current.Mode.String()})
			continue
		}
		summary.Verified++
	}
	for path := range baseline.Files {
		if _, exists := seen[path]; exists {
			continue
		}
		summary.Total++
		summary.Missing++
		appendFIMFinding(&summary, FIMFinding{Path: path, Status: "MISSING"})
	}
	sort.Slice(summary.Findings, func(i, j int) bool {
		return summary.Findings[i].Path < summary.Findings[j].Path
	})
	summary.FinishedAt = time.Now().UTC()

	e.mu.Lock()
	e.lastScan = cloneFIMSummary(&summary)
	e.mu.Unlock()
	return summary, nil
}

func appendFIMFinding(summary *FIMScanSummary, finding FIMFinding) {
	if len(summary.Findings) < fimMaxFindings {
		summary.Findings = append(summary.Findings, finding)
	}
}

func (e *FIMEngine) beginScan() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.scanning {
		return errors.New("FIM operation already in progress")
	}
	e.scanning = true
	return nil
}

func (e *FIMEngine) endScan() {
	e.mu.Lock()
	e.scanning = false
	e.mu.Unlock()
}

func (e *FIMEngine) collect() ([]string, error) {
	unique := make(map[string]struct{})
	totalBytes := int64(0)
	for _, root := range e.roots {
		info, err := os.Lstat(root)
		if err != nil {
			return nil, fmt.Errorf("protected root unavailable: %s", root)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("protected root is a symlink: %s", root)
		}
		if info.Mode().IsRegular() {
			if err := addFIMCandidate(unique, root, info, &totalBytes); err != nil {
				return nil, err
			}
			continue
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("protected root has unsupported type: %s", root)
		}
		if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			return addFIMCandidate(unique, filepath.Clean(path), info, &totalBytes)
		}); err != nil {
			return nil, fmt.Errorf("protected root traversal failed: %s", root)
		}
	}
	files := make([]string, 0, len(unique))
	for path := range unique {
		files = append(files, path)
	}
	sort.Strings(files)
	return files, nil
}

func addFIMCandidate(files map[string]struct{}, path string, info os.FileInfo, totalBytes *int64) error {
	if info.Size() < 0 || info.Size() > fimMaxFileBytes {
		return fmt.Errorf("protected file exceeds size boundary: %s", path)
	}
	if _, exists := files[path]; exists {
		return nil
	}
	if len(files) >= fimMaxFiles || *totalBytes > fimMaxTotalBytes-info.Size() {
		return errors.New("FIM traversal budget exhausted")
	}
	files[path] = struct{}{}
	*totalBytes += info.Size()
	return nil
}

func hashFIMFile(path string) (FIMRecord, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return FIMRecord{}, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return FIMRecord{}, errors.New("file is not a regular non-symlink object")
	}
	if before.Size() < 0 || before.Size() > fimMaxFileBytes {
		return FIMRecord{}, errors.New("file exceeds size boundary")
	}
	file, err := os.Open(path)
	if err != nil {
		return FIMRecord{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return FIMRecord{}, errors.New("file identity changed before hashing")
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, fimMaxFileBytes+1))
	if err != nil || written != before.Size() {
		return FIMRecord{}, errors.New("file changed while hashing")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || after.ModTime() != before.ModTime() {
		return FIMRecord{}, errors.New("file identity changed while hashing")
	}
	return FIMRecord{
		SHA256: hex.EncodeToString(digest.Sum(nil)), Size: after.Size(), Mode: after.Mode().Perm(),
	}, nil
}

func cloneFIMBaseline(source FIMBaseline) FIMBaseline {
	clone := source
	clone.Roots = append([]string(nil), source.Roots...)
	clone.Files = make(map[string]FIMRecord, len(source.Files))
	for path, record := range source.Files {
		clone.Files[path] = record
	}
	return clone
}

func cloneFIMSummary(source *FIMScanSummary) *FIMScanSummary {
	if source == nil {
		return nil
	}
	clone := *source
	clone.Findings = append([]FIMFinding(nil), source.Findings...)
	return &clone
}

func (e *FIMEngine) setFault(err error) FIMStatus {
	e.mu.Lock()
	e.integrityErr = err
	e.mu.Unlock()
	return e.Status()
}

func (e *FIMEngine) Status() FIMStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	status := FIMStatus{
		Enabled: true, Health: "NO_BASELINE", BaselineCount: len(e.baseline.Files),
		Generation: e.baseline.Generation, Roots: append([]string(nil), e.roots...),
		LastScan: cloneFIMSummary(e.lastScan),
	}
	if e.integrityErr != nil {
		status.Health = "QUARANTINED"
		status.Error = "FIM baseline integrity unavailable"
		return status
	}
	if e.baseline.Generation == 0 {
		return status
	}
	status.Health = "PENDING"
	if e.lastScan == nil {
		return status
	}
	switch {
	case e.lastScan.Errors > 0:
		status.Health = "DEGRADED"
	case e.lastScan.Tampered > 0 || e.lastScan.Missing > 0 || e.lastScan.New > 0:
		status.Health = "TAMPERED"
	default:
		status.Health = "VERIFIED"
	}
	return status
}

func runFIM(ctx context.Context, state *State, engine *FIMEngine, interval time.Duration) {
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastOutcome := ""
	scan := func() {
		if engine.Status().Generation == 0 {
			return
		}
		summary, err := engine.Scan()
		outcome := fmt.Sprintf(
			"verified=%d tampered=%d missing=%d new=%d errors=%d",
			summary.Verified, summary.Tampered, summary.Missing, summary.New, summary.Errors,
		)
		if err != nil {
			outcome = "scan-error"
		}
		if outcome == lastOutcome {
			return
		}
		lastOutcome = outcome
		switch {
		case err != nil:
			state.AddEvent(Event{
				Severity: "critical", Kind: "fim.scan_failed", Source: "integrity",
				Message: "Protected-path verification failed safely",
			})
		case summary.Tampered > 0 || summary.Missing > 0 || summary.New > 0 || summary.Errors > 0:
			state.AddEvent(Event{
				Severity: "critical", Kind: "fim.deviation", Source: "integrity",
				Message: "Protected-path deviation detected: " + outcome,
			})
		default:
			state.AddEvent(Event{
				Severity: "info", Kind: "fim.verified", Source: "integrity",
				Message: "Encrypted integrity baseline verified: " + outcome,
			})
		}
	}
	scan()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan()
		}
	}
}
