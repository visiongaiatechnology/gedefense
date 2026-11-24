// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

// Titan synchronization/refresh layer split out of titan.go (refactoring wave
// 1b, structure-only): bounded policy/journal load and atomic journal persistence,
// the sensor run/watch loop with its restart backoff, evidence/event emission
// helpers, journal counters and the bounded event/quarantine read views. The
// engine types, construction and observation pipeline stay in titan.go; policy
// compilation and validation stay in titan_policy_compile.go.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (e *TitanEngine) loadPolicy() error {
	raw, err := readBoundedPrivateFile(e.policyPath, titanMaxPolicyBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document titanPolicyDocument
	if err := decoder.Decode(&document); err != nil {
		return errors.New("Titan policy document is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Titan policy document contains trailing data")
	}
	if document.Schema != titanPolicySchema || document.Version != 1 {
		return errors.New("Titan policy schema is unsupported")
	}
	policy := document.Policy
	if err := normalizeTitanPolicy(&policy); err != nil {
		return err
	}
	e.policy = policy
	return nil
}

func (e *TitanEngine) loadJournal() error {
	raw, err := readBoundedPrivateFile(e.journalPath, titanMaxJournalReadBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document titanJournalDocument
	if err := decoder.Decode(&document); err != nil {
		return errors.New("Titan journal document is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Titan journal document contains trailing data")
	}
	if document.Schema != titanJournalSchema || document.Version != titanJournalVersion {
		return errors.New("Titan journal schema is unsupported")
	}
	if len(document.Events) > titanMaxJournalEvents || len(document.Quarantine) > titanMaxQuarantine {
		return errors.New("Titan journal exceeds its bounds")
	}
	for index := range document.Events {
		if err := validateTitanEvent(document.Events[index]); err != nil {
			return err
		}
	}
	e.events = append([]TitanEvent(nil), document.Events...)
	e.quarantine = append([]titanQuarantineItem(nil), document.Quarantine...)
	e.totalEvents = document.TotalEvents
	if len(e.events) > 0 {
		e.sequence = e.events[len(e.events)-1].JournalSequence
	}
	return nil
}

// titanSensorRestartDelay returns the wait before the next sensor restart. It is
// exponential in the number of consecutive failed restarts, capped and jittered.
// FIND-031: the retry path gets a mandatory pause instead of spinning.
func titanSensorRestartDelay(attempt uint, jitter time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := titanSensorRestartBackoffBase
	for step := uint(1); step < attempt && delay < titanSensorRestartBackoffMax; step++ {
		delay *= 2
	}
	if delay > titanSensorRestartBackoffMax {
		delay = titanSensorRestartBackoffMax
	}
	if jitter < 0 {
		jitter = 0
	}
	if jitter > delay/2 {
		jitter = delay / 2
	}
	return delay + jitter
}

// titanSensorRestartJitter returns one bounded positive jitter value.
func titanSensorRestartJitter() time.Duration {
	return time.Duration(rand.Int63n(int64(titanSensorRestartBackoffBase)))
}

// Run starts the bounded sensor loop and the policy-driven observation pipeline.
// A sensor failure degrades the Titan status and is recorded as evidence instead
// of being hidden.
func (e *TitanEngine) Run(ctx context.Context) {
	if e == nil || !e.enabled {
		return
	}
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()
	observer := e.deps.Observer
	if observer == nil {
		observer = newTitanPlatformObserver()
	}
	restartAttempt := uint(0)
	for {
		if ctx.Err() != nil {
			return
		}
		roots := e.currentRoots()
		observations := make(chan titanObservation, titanMaxSensorEvents)
		sensorCtx, cancel := context.WithCancel(ctx)
		sensorErr := make(chan error, 1)
		go func() {
			sensorErr <- observer.Run(sensorCtx, roots, observations)
		}()
		e.setSensor("healthy", "")
		e.recordEvidence(EvidenceRecord{
			Severity: "info", Kind: "titan.sensor.started", Source: "titan",
			Message: fmt.Sprintf("Titan sensor observing %d configured roots", len(roots)),
		})
		startedAt := time.Now()
		restart, runErr := e.watchLoop(sensorCtx, observations, sensorErr)
		cancel()
		if !restart {
			<-sensorErr
			return
		}
		if runErr == nil {
			runErr = <-sensorErr
		}
		if ctx.Err() != nil {
			return
		}
		if runErr != nil {
			e.setSensor("degraded", boundedTitanText(runErr.Error(), 240))
			e.recordEvidence(EvidenceRecord{
				Severity: "high", Kind: "titan.sensor.failed", Source: "titan",
				Message: "Titan integrity sensor stopped: " + boundedTitanText(runErr.Error(), 240),
			})
			e.emitEvent(Event{
				Severity: "critical", Kind: "titan.sensor.degraded", Source: "titan",
				Message: "Titan integrity sensor is degraded: " + boundedTitanText(runErr.Error(), 240),
			})
			restartAttempt++
			// A run that was healthy for a while resets the growth: the restart is then
			// a new incident, not a continuation of the failure streak.
			if time.Since(startedAt) >= titanSensorHealthyResetAfter {
				restartAttempt = 1
			}
		} else {
			e.setSensor("degraded", "sensor stopped without an error")
			restartAttempt = 0
		}
		// Mandatory backoff before the retry (FIND-031). The vulnerable build fell
		// through to the next iteration immediately, so a sensor that kept failing
		// turned the loop into a tight CPU spin.
		delay := titanSensorRestartDelay(restartAttempt, titanSensorRestartJitter())
		e.recordEvidence(EvidenceRecord{
			Severity: "info", Kind: "titan.sensor.restart_backoff", Source: "titan",
			Message: fmt.Sprintf("Titan sensor restart in %s after %d consecutive restart attempt(s)", delay, restartAttempt),
		})
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (e *TitanEngine) watchLoop(ctx context.Context, observations <-chan titanObservation, sensorErr <-chan error) (bool, error) {
	for {
		select {
		case <-ctx.Done():
			return false, nil
		case <-e.rootsChanged:
			return true, nil
		case err := <-sensorErr:
			return true, err
		case observation, ok := <-observations:
			if !ok {
				return true, nil
			}
			e.observe(observation)
		}
	}
}

func (e *TitanEngine) currentRoots() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]string(nil), e.policy.Roots...)
}

func (e *TitanEngine) setSensor(state, message string) {
	e.mu.Lock()
	e.sensor.State = state
	e.sensor.Error = message
	e.mu.Unlock()
}

func (e *TitanEngine) setSensorObservation(at time.Time) {
	e.mu.Lock()
	e.sensor.State = "healthy"
	e.sensor.Error = ""
	value := at.UTC()
	e.sensor.LastObservationUTC = &value
	e.mu.Unlock()
}

func (e *TitanEngine) recordEvidence(record EvidenceRecord) {
	if e == nil || e.deps.Evidence == nil {
		return
	}
	if record.Time.IsZero() {
		record.Time = e.now()
	}
	if record.Source == "" {
		record.Source = "titan"
	}
	_ = e.deps.Evidence(record)
}

func (e *TitanEngine) emitEvent(event Event) {
	if e == nil || e.deps.Events == nil {
		return
	}
	e.deps.Events(event)
}

func (e *TitanEngine) now() time.Time {
	if e == nil || e.deps.Now == nil {
		return time.Now().UTC()
	}
	return e.deps.Now().UTC()
}

func (e *TitanEngine) appendEvent(event TitanEvent) {
	e.mu.Lock()
	e.sequence++
	event.JournalSequence = e.sequence
	e.events = append(e.events, event)
	maxEvents := e.policy.MaxEvents
	if len(e.events) > maxEvents {
		e.events = append([]TitanEvent(nil), e.events[len(e.events)-maxEvents:]...)
	}
	e.totalEvents++
	if event.Containment == TitanResponseContained && event.QuarantineID != "" {
		e.quarantine = append(e.quarantine, titanQuarantineItem{
			ID: event.QuarantineID, EventID: event.ID, Path: event.Path,
			SampleSHA256: event.SHA256, CreatedUTC: event.ObservedUTC, State: "APPLIED",
		})
		if len(e.quarantine) > titanMaxQuarantine {
			e.quarantine = append([]titanQuarantineItem(nil), e.quarantine[len(e.quarantine)-titanMaxQuarantine:]...)
		}
	}
	e.recountLocked()
	document := e.journalDocumentLocked()
	e.mu.Unlock()
	if err := e.persistJournal(document); err != nil {
		e.recordEvidence(EvidenceRecord{
			Severity: "high", Kind: "titan.journal.persist_failed", Source: "titan",
			Message: "Titan journal could not be persisted: " + boundedTitanText(err.Error(), 240),
		})
	}
}

func (e *TitanEngine) recountLocked() {
	e.trustCounts = TitanTrustCounts{}
	e.corrCounts = TitanCorrelationCounts{}
	e.openFindings = 0
	for _, event := range e.events {
		switch event.TrustState {
		case TitanTrustAuthorized:
			e.trustCounts.Authorized++
		case TitanTrustTolerated:
			e.trustCounts.Tolerated++
		case TitanTrustUnexpected:
			e.trustCounts.Unexpected++
			if event.Review == "" || event.Review == "PENDING" {
				e.openFindings++
			}
		case TitanTrustCompromised:
			e.trustCounts.Compromised++
			if event.Review == "" || event.Review == "PENDING" {
				e.openFindings++
			}
		}
		switch event.CorrelationQuality {
		case TitanCorrelationObserved:
			e.corrCounts.Observed++
		case TitanCorrelationTemporal:
			e.corrCounts.Temporal++
		default:
			e.corrCounts.None++
		}
	}
}

func (e *TitanEngine) journalDocumentLocked() titanJournalDocument {
	events := append([]TitanEvent(nil), e.events...)
	quarantine := append([]titanQuarantineItem(nil), e.quarantine...)
	return titanJournalDocument{
		Schema: titanJournalSchema, Version: titanJournalVersion, SavedUTC: e.now(),
		TotalEvents: e.totalEvents, Events: events, Quarantine: quarantine,
	}
}

func (e *TitanEngine) persistJournal(document titanJournalDocument) error {
	maxBytes := e.currentPolicy().JournalMaxBytes
	payload, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if int64(len(payload)+1) > maxBytes {
		e.mu.Lock()
		for len(e.events) > titanMinJournalEvents {
			e.events = append([]TitanEvent(nil), e.events[1:]...)
			document.Events = append([]TitanEvent(nil), e.events...)
			payload, err = json.Marshal(document)
			if err != nil {
				break
			}
			if int64(len(payload)+1) <= maxBytes {
				break
			}
		}
		document.Events = append([]TitanEvent(nil), e.events...)
		e.recountLocked()
		e.mu.Unlock()
		if err != nil {
			return err
		}
		payload, err = json.Marshal(document)
		if err != nil {
			return err
		}
		if int64(len(payload)+1) > maxBytes {
			return errors.New("Titan journal exceeds its bounded byte budget")
		}
	}
	return atomicWriteFile(e.journalPath, append(payload, '\n'), 0o600)
}

// Events returns newest-first events older than the opaque cursor.
func (e *TitanEngine) Events(limit int, before string) ([]TitanEvent, string, error) {
	if e == nil {
		return nil, "", errors.New("Titan engine unavailable")
	}
	if limit <= 0 {
		limit = titanDefaultLimit
	}
	if limit > titanMaxLimit {
		limit = titanMaxLimit
	}
	var beforeSequence uint64
	if strings.TrimSpace(before) != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(before)
		if err != nil {
			return nil, "", errors.New("Titan event cursor is malformed")
		}
		beforeSequence, err = strconv.ParseUint(string(decoded), 10, 64)
		if err != nil {
			return nil, "", errors.New("Titan event cursor is malformed")
		}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]TitanEvent, 0, limit)
	for index := len(e.events) - 1; index >= 0; index-- {
		event := e.events[index]
		if beforeSequence != 0 && event.JournalSequence >= beforeSequence {
			continue
		}
		result = append(result, cloneTitanEvent(event))
		if len(result) >= limit {
			break
		}
	}
	next := ""
	if len(result) > 0 {
		oldest := result[len(result)-1].JournalSequence
		for index := len(e.events) - 1; index >= 0; index-- {
			if e.events[index].JournalSequence < oldest {
				next = titanEventCursor(oldest)
				break
			}
		}
	}
	return result, next, nil
}

func titanEventCursor(sequence uint64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(sequence, 10)))
}

func cloneTitanEvent(event TitanEvent) TitanEvent {
	clone := event
	if event.ReviewUTC != nil {
		value := *event.ReviewUTC
		clone.ReviewUTC = &value
	}
	return clone
}

func (e *TitanEngine) signalRootsChanged() {
	select {
	case e.rootsChanged <- struct{}{}:
	default:
	}
}

// Quarantine returns the bounded Titan-side quarantine view, refreshed from the
// transaction engine when it is available.
func (e *TitanEngine) Quarantine() TitanQuarantineStatus {
	if e == nil {
		return TitanQuarantineStatus{Items: []titanQuarantineItem{}}
	}
	var items titanContainment
	e.mu.RLock()
	items = e.deps.Containment
	e.mu.RUnlock()
	statuses := map[string]string{}
	if items != nil {
		for _, item := range items.Items() {
			statuses[item.ID] = item.State
		}
	}
	e.mu.RLock()
	result := make([]titanQuarantineItem, 0, len(e.quarantine))
	for _, item := range e.quarantine {
		if state, exists := statuses[item.ID]; exists && state != "" {
			item.State = state
		}
		result = append(result, item)
	}
	e.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedUTC.After(result[j].CreatedUTC) })
	return TitanQuarantineStatus{Items: result, Count: len(result)}
}
