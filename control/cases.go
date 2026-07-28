// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
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
	caseSchema       = "vgt-gedefense-cases-v1"
	casePurpose      = "security-cases"
	caseMaxBytes     = int64(16 << 20)
	caseMaxRecords   = 4096
	caseMaxEvidence  = 256
	caseMaxObserved  = 256
	caseListMaxLimit = 500
)

type CaseObservation struct {
	At      time.Time `json:"at"`
	Source  string    `json:"source"`
	Message string    `json:"message"`
	Target  string    `json:"target,omitempty"`
}

type SecurityCase struct {
	ID              string            `json:"id"`
	Fingerprint     string            `json:"fingerprint"`
	Title           string            `json:"title"`
	Status          string            `json:"status"`
	Severity        string            `json:"severity"`
	Confidence      string            `json:"confidence"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	Observations    []CaseObservation `json:"observations"`
	EvidenceIDs     []string          `json:"evidence_ids"`
	RuleIDs         []string          `json:"rule_ids"`
	Categories      []string          `json:"categories"`
	Recommended     []string          `json:"recommended_actions"`
	Resolution      string            `json:"resolution,omitempty"`
	OccurrenceCount uint64            `json:"occurrence_count"`
}

type CaseStatus struct {
	Healthy  bool           `json:"healthy"`
	Revision uint64         `json:"revision"`
	Count    int            `json:"count"`
	Open     int            `json:"open"`
	Cases    []SecurityCase `json:"cases"`
	Error    string         `json:"error,omitempty"`
}

type caseStore struct {
	Schema   string         `json:"schema"`
	Revision uint64         `json:"revision"`
	Cases    []SecurityCase `json:"cases"`
}

type CaseEngine struct {
	mu        sync.Mutex
	path      string
	storage   *StorageCipher
	evidence  func(EvidenceRecord) error
	revision  uint64
	cases     map[string]SecurityCase
	byFinger  map[string]string
	integrity error
	now       func() time.Time
}

func NewCaseEngine(
	path string,
	storage *StorageCipher,
	evidence func(EvidenceRecord) error,
) (*CaseEngine, error) {
	if storage == nil || evidence == nil {
		return nil, errors.New("case engine requires encrypted storage and evidence sink")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("case store path must be absolute")
	}
	engine := &CaseEngine{
		path: path, storage: storage, evidence: evidence,
		cases: make(map[string]SecurityCase), byFinger: make(map[string]string),
		now: func() time.Time { return time.Now().UTC() },
	}
	if err := engine.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		engine.integrity = err
	}
	return engine, nil
}

func (e *CaseEngine) load() error {
	raw, err := readBoundedPrivateFile(e.path, caseMaxBytes)
	if err != nil {
		return err
	}
	envelope, err := decodeEncryptedStorageEnvelope(bytes.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("case store envelope: %w", err)
	}
	expected := envelope.Sequence
	plaintext, legacy, err := e.storage.Decrypt(e.path, casePurpose, raw, &expected)
	if err != nil {
		return fmt.Errorf("case store authentication failed: %w", err)
	}
	if legacy {
		return errors.New("unencrypted case history is rejected")
	}
	store, err := decodeCaseStore(plaintext)
	if err != nil {
		return err
	}
	if store.Revision != expected {
		return errors.New("case store revision binding mismatch")
	}
	for _, record := range store.Cases {
		e.cases[record.ID] = cloneSecurityCase(record)
		e.byFinger[record.Fingerprint] = record.ID
	}
	e.revision = store.Revision
	return nil
}

func decodeCaseStore(raw []byte) (caseStore, error) {
	var store caseStore
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&store); err != nil {
		return caseStore{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return caseStore{}, errors.New("case store contains trailing data")
	}
	if store.Schema != caseSchema || store.Revision == 0 || len(store.Cases) > caseMaxRecords {
		return caseStore{}, errors.New("case store metadata is invalid")
	}
	ids := make(map[string]struct{}, len(store.Cases))
	fingerprints := make(map[string]struct{}, len(store.Cases))
	for _, record := range store.Cases {
		if err := validateSecurityCase(record); err != nil {
			return caseStore{}, err
		}
		if _, exists := ids[record.ID]; exists {
			return caseStore{}, errors.New("case store contains duplicate IDs")
		}
		if _, exists := fingerprints[record.Fingerprint]; exists {
			return caseStore{}, errors.New("case store contains duplicate fingerprints")
		}
		ids[record.ID] = struct{}{}
		fingerprints[record.Fingerprint] = struct{}{}
	}
	return store, nil
}

func validateSecurityCase(record SecurityCase) error {
	if !validCaseID(record.ID) || len(record.Fingerprint) != 64 ||
		len(record.Title) < 3 || len(record.Title) > 160 ||
		record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() ||
		record.UpdatedAt.Before(record.CreatedAt) || record.OccurrenceCount == 0 ||
		len(record.Observations) == 0 || len(record.Observations) > caseMaxObserved ||
		len(record.EvidenceIDs) > caseMaxEvidence || len(record.RuleIDs) > 128 ||
		len(record.Categories) > 64 || len(record.Recommended) > 32 ||
		len(record.Resolution) > 512 {
		return errors.New("case record violates structural bounds")
	}
	if _, err := hex.DecodeString(record.Fingerprint); err != nil {
		return errors.New("case fingerprint is invalid")
	}
	switch record.Status {
	case "open", "investigating", "resolved", "dismissed":
	default:
		return errors.New("case status is invalid")
	}
	switch record.Severity {
	case "warning", "high", "critical":
	default:
		return errors.New("case severity is invalid")
	}
	switch record.Confidence {
	case "low", "medium", "high":
	default:
		return errors.New("case confidence is invalid")
	}
	for _, observation := range record.Observations {
		if observation.At.IsZero() || len(observation.Source) < 1 ||
			len(observation.Source) > 64 || len(observation.Message) < 1 ||
			len(observation.Message) > 512 || len(observation.Target) > 512 {
			return errors.New("case observation violates structural bounds")
		}
	}
	return nil
}

func validCaseID(id string) bool {
	if len(id) != 19 || !strings.HasPrefix(id, "CS-") {
		return false
	}
	for _, character := range id[3:] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func (e *CaseEngine) persistLocked() error {
	records := make([]SecurityCase, 0, len(e.cases))
	for _, record := range e.cases {
		records = append(records, cloneSecurityCase(record))
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	nextRevision := e.revision + 1
	plaintext, err := json.Marshal(caseStore{
		Schema: caseSchema, Revision: nextRevision, Cases: records,
	})
	if err != nil {
		return err
	}
	if int64(len(plaintext)) > caseMaxBytes {
		return errors.New("case store size budget exhausted")
	}
	sealed, err := e.storage.Encrypt(e.path, casePurpose, nextRevision, plaintext)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.path), 0o700); err != nil {
		return err
	}
	if err := atomicWriteFile(e.path, sealed, 0o600); err != nil {
		return err
	}
	e.revision = nextRevision
	return nil
}

func (e *CaseEngine) IngestIncident(incident XDRIncident) error {
	if incident.Severity != "warning" && incident.Severity != "high" &&
		incident.Severity != "critical" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.integrity != nil {
		return e.integrity
	}
	fingerprint := caseFingerprint(incident)
	now := e.now()
	if id, exists := e.byFinger[fingerprint]; exists {
		record := e.cases[id]
		before := cloneSecurityCase(record)
		if record.Status == "resolved" || record.Status == "dismissed" {
			record.Status = "open"
			record.Resolution = ""
		}
		record.UpdatedAt = now
		record.OccurrenceCount++
		record.Severity = maximumCaseSeverity(record.Severity, incident.Severity)
		record.Observations = boundedObservations(record.Observations, incidentObservation(incident))
		record.EvidenceIDs = appendUniqueBounded(record.EvidenceIDs, caseMaxEvidence, incident.ID)
		record.RuleIDs = appendUniqueBounded(record.RuleIDs, 128, incident.RuleIDs...)
		record.Categories = appendUniqueBounded(record.Categories, 64, incident.Categories...)
		e.cases[id] = record
		if err := e.persistLocked(); err != nil {
			e.cases[id] = before
			e.integrity = err
			return err
		}
		return nil
	}
	if len(e.cases) >= caseMaxRecords {
		return errors.New("case capacity exhausted")
	}
	id := "CS-" + randomID()
	if !validCaseID(id) {
		return errors.New("secure case ID generation failed")
	}
	record := SecurityCase{
		ID: id, Fingerprint: fingerprint, Title: caseTitle(incident),
		Status: "open", Severity: incident.Severity,
		Confidence: caseConfidence(incident), CreatedAt: now, UpdatedAt: now,
		Observations: []CaseObservation{incidentObservation(incident)},
		EvidenceIDs:  appendUniqueBounded(nil, caseMaxEvidence, incident.ID),
		RuleIDs:      appendUniqueBounded(nil, 128, incident.RuleIDs...),
		Categories:   appendUniqueBounded(nil, 64, incident.Categories...),
		Recommended:  caseRecommendations(incident), OccurrenceCount: 1,
	}
	if err := validateSecurityCase(record); err != nil {
		return err
	}
	e.cases[id] = record
	e.byFinger[fingerprint] = id
	if err := e.persistLocked(); err != nil {
		delete(e.cases, id)
		delete(e.byFinger, fingerprint)
		e.integrity = err
		return err
	}
	return nil
}

func (e *CaseEngine) SetStatus(id, status, resolution string) (SecurityCase, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.integrity != nil {
		return SecurityCase{}, e.integrity
	}
	record, exists := e.cases[id]
	if !exists {
		return SecurityCase{}, errors.New("case not found")
	}
	switch status {
	case "open", "investigating":
		if resolution != "" {
			return SecurityCase{}, errors.New("active case may not contain a resolution")
		}
	case "resolved", "dismissed":
		if len(resolution) < 3 || len(resolution) > 512 {
			return SecurityCase{}, errors.New("case resolution is outside bounds")
		}
	default:
		return SecurityCase{}, errors.New("case status is invalid")
	}
	if err := e.evidence(EvidenceRecord{
		Severity: "high", Kind: "case.status.intent", Source: "case-engine",
		Message: "Authenticated case status mutation authorized",
		Target:  id + " " + status,
	}); err != nil {
		return SecurityCase{}, err
	}
	before := cloneSecurityCase(record)
	record.Status = status
	record.Resolution = resolution
	record.UpdatedAt = e.now()
	e.cases[id] = record
	if err := e.persistLocked(); err != nil {
		e.cases[id] = before
		e.integrity = err
		return SecurityCase{}, err
	}
	return cloneSecurityCase(record), nil
}

func (e *CaseEngine) Status(limit int) CaseStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit < 1 || limit > caseListMaxLimit {
		limit = 100
	}
	records := make([]SecurityCase, 0, len(e.cases))
	open := 0
	for _, record := range e.cases {
		if record.Status == "open" || record.Status == "investigating" {
			open++
		}
		records = append(records, cloneSecurityCase(record))
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].UpdatedAt.Equal(records[j].UpdatedAt) {
			return records[i].ID > records[j].ID
		}
		return records[i].UpdatedAt.After(records[j].UpdatedAt)
	})
	if len(records) > limit {
		records = records[:limit]
	}
	status := CaseStatus{
		Healthy: e.integrity == nil, Revision: e.revision,
		Count: len(e.cases), Open: open, Cases: records,
	}
	if e.integrity != nil {
		status.Error = "case history integrity unavailable"
	}
	return status
}

func caseFingerprint(incident XDRIncident) string {
	rules := append([]string(nil), incident.RuleIDs...)
	categories := append([]string(nil), incident.Categories...)
	sort.Strings(rules)
	sort.Strings(categories)
	digest := sha256.New()
	digest.Write([]byte("VGT-GEDEFENSE-CASE-FINGERPRINT-V1\x00"))
	for _, value := range []string{
		strings.Join(rules, ","), strings.Join(categories, ","),
		incident.Executable, incident.Remote, incident.Decision,
	} {
		digest.Write([]byte(value))
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func incidentObservation(incident XDRIncident) CaseObservation {
	source := "xdr"
	if len(incident.Categories) > 0 {
		source = strings.Join(incident.Categories, ",")
	}
	target := incident.Executable
	if target == "" && incident.PID > 0 {
		target = fmt.Sprintf("pid:%d:start:%d", incident.PID, incident.StartTicks)
	}
	return CaseObservation{
		At: incident.Time.UTC(), Source: truncateCaseText(source, 64),
		Message: truncateCaseText(incident.Summary, 512),
		Target:  truncateCaseText(target, 512),
	}
}

func caseTitle(incident XDRIncident) string {
	if len(incident.Categories) > 0 {
		return truncateCaseText(strings.Title(strings.ReplaceAll(incident.Categories[0], "-", " "))+" security incident", 160)
	}
	return "Correlated XDR security incident"
}

func caseConfidence(incident XDRIncident) string {
	if incident.Severity == "critical" || incident.KillSignals >= 2 {
		return "high"
	}
	if incident.Severity == "high" || incident.ResponseScore >= 80 {
		return "medium"
	}
	return "low"
}

func caseRecommendations(incident XDRIncident) []string {
	recommendations := []string{
		"Review the authenticated incident evidence and process lineage",
		"Verify executable origin and package ownership",
	}
	for _, category := range incident.Categories {
		switch category {
		case "integrity":
			recommendations = append(recommendations, "Compare the affected file with the trusted FIM baseline")
		case "network", "threat-intel":
			recommendations = append(recommendations, "Review the owning process and remote network target")
		case "origin":
			recommendations = append(recommendations, "Quarantine related artifacts before resolving the case")
		}
	}
	return appendUniqueBounded(nil, 32, recommendations...)
}

func maximumCaseSeverity(left, right string) string {
	rank := map[string]int{"warning": 1, "high": 2, "critical": 3}
	if rank[right] > rank[left] {
		return right
	}
	return left
}

func boundedObservations(
	existing []CaseObservation,
	next CaseObservation,
) []CaseObservation {
	result := append(append([]CaseObservation(nil), existing...), next)
	if len(result) > caseMaxObserved {
		result = append([]CaseObservation(nil), result[len(result)-caseMaxObserved:]...)
	}
	return result
}

func appendUniqueBounded(existing []string, limit int, values ...string) []string {
	if limit < 1 {
		return append([]string(nil), existing...)
	}
	result := append([]string(nil), existing...)
	seen := make(map[string]struct{}, len(result))
	for _, value := range result {
		seen[value] = struct{}{}
	}
	for _, value := range values {
		if value == "" {
			continue
		}
		value = truncateCaseText(value, 160)
		if _, exists := seen[value]; !exists && len(result) < limit {
			result = append(result, value)
			seen[value] = struct{}{}
		}
	}
	return result
}

func truncateCaseText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func cloneSecurityCase(record SecurityCase) SecurityCase {
	record.Observations = append([]CaseObservation(nil), record.Observations...)
	record.EvidenceIDs = append([]string(nil), record.EvidenceIDs...)
	record.RuleIDs = append([]string(nil), record.RuleIDs...)
	record.Categories = append([]string(nil), record.Categories...)
	record.Recommended = append([]string(nil), record.Recommended...)
	return record
}
