// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestTitanStatusAndEventJSONContract(t *testing.T) {
	rig := newTitanTestRig(t, nil)
	event := rig.observe(rig.write("contract.bin", "x"), TitanChangeCreated)
	statusJSON, err := json.Marshal(rig.engine.Status())
	if err != nil {
		t.Fatalf("status marshal: %v", err)
	}
	var status map[string]json.RawMessage
	if err := json.Unmarshal(statusJSON, &status); err != nil {
		t.Fatalf("status unmarshal: %v", err)
	}
	for _, key := range []string{"version", "mode", "armed", "auto_contain", "trust", "correlation", "events_total", "open_findings", "quarantine_count", "sensor", "updated_utc"} {
		if _, exists := status[key]; !exists {
			t.Fatalf("status JSON missing %q: %s", key, statusJSON)
		}
	}
	var trust map[string]json.RawMessage
	if err := json.Unmarshal(status["trust"], &trust); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"AUTHORIZED", "TOLERATED", "UNEXPECTED", "COMPROMISED"} {
		if _, exists := trust[key]; !exists {
			t.Fatalf("trust JSON missing %q", key)
		}
	}
	var correlation map[string]json.RawMessage
	if err := json.Unmarshal(status["correlation"], &correlation); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"OBSERVED", "TEMPORAL", "NONE"} {
		if _, exists := correlation[key]; !exists {
			t.Fatalf("correlation JSON missing %q", key)
		}
	}
	var sensor map[string]json.RawMessage
	if err := json.Unmarshal(status["sensor"], &sensor); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"state", "last_observation_utc", "error"} {
		if _, exists := sensor[key]; !exists {
			t.Fatalf("sensor JSON missing %q", key)
		}
	}
	if string(sensor["last_observation_utc"]) != "null" {
		// After the observation above the timestamp must be present and RFC3339.
		var timestamp time.Time
		if err := json.Unmarshal(sensor["last_observation_utc"], &timestamp); err != nil || timestamp.IsZero() {
			t.Fatalf("sensor last_observation_utc is not a RFC3339 timestamp: %s", sensor["last_observation_utc"])
		}
	}
	eventJSON, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("event marshal: %v", err)
	}
	var eventMap map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &eventMap); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "observed_utc", "path", "change_type", "trust_state", "authorization_reason", "response", "correlation_quality", "severity", "sensor", "sha256", "size"} {
		if _, exists := eventMap[key]; !exists {
			t.Fatalf("event JSON missing %q: %s", key, eventJSON)
		}
	}
	quarantineJSON, err := json.Marshal(rig.engine.Quarantine())
	if err != nil {
		t.Fatal(err)
	}
	var quarantine map[string]json.RawMessage
	if err := json.Unmarshal(quarantineJSON, &quarantine); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"items", "count"} {
		if _, exists := quarantine[key]; !exists {
			t.Fatalf("quarantine JSON missing %q", key)
		}
	}
}

func TestTitanSensorHealthAndDisabledStates(t *testing.T) {
	t.Run("sensor failure degrades status and is evidenced", func(t *testing.T) {
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			rig.cfg.Roots = []string{rig.root}
		})
		engine, err := NewTitanEngine(rig.cfg, TitanDeps{
			Version: titanTestVersion, DataRoot: rig.stateDir,
			Observer: failingTitanObserver{err: errors.New("injected inotify failure")},
			Evidence: rig.evidence.Record, Events: func(Event) {},
			Now: func() time.Time { return rig.now },
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { engine.Run(ctx); close(done) }()
		deadline := time.Now().Add(4 * time.Second)
		status := engine.Status()
		for time.Now().Before(deadline) {
			status = engine.Status()
			if status.Sensor.State == "degraded" && status.Sensor.Error != "" && rig.evidence.hasKind("titan.sensor.failed") {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if status.Sensor.State != "degraded" || status.Sensor.Error == "" {
			t.Fatalf("sensor failure did not degrade status: %+v", status.Sensor)
		}
		if !rig.evidence.hasKind("titan.sensor.failed") {
			t.Fatal("sensor failure was not evidenced")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Titan Run did not stop after cancellation")
		}
	})

	t.Run("disabled module reports an explicit disabled sensor", func(t *testing.T) {
		rig := newTitanTestRig(t, func(rig *titanTestRig) { rig.cfg.Enabled = false })
		status := rig.engine.Status()
		if status.Sensor.State != "disabled" {
			t.Fatalf("disabled Titan sensor = %q", status.Sensor.State)
		}
		rig.engine.Run(context.Background())
	})
}

type failingTitanObserver struct {
	err error
}

func (o failingTitanObserver) Run(context.Context, []string, chan<- titanObservation) error {
	return o.err
}

func TestTitanNilSafety(t *testing.T) {
	var engine *TitanEngine
	if status := engine.Status(); status.Sensor.State != "disabled" {
		t.Fatalf("nil engine status = %+v", status)
	}
	if engine.Enabled() {
		t.Fatal("nil engine reported enabled")
	}
	if _, _, err := engine.Events(10, ""); err == nil {
		t.Fatal("nil engine accepted an events query")
	}
	if _, err := engine.ApplyPolicy(TitanModeObserve, false, false, "operator calls a nil Titan engine"); err == nil {
		t.Fatal("nil engine accepted a policy update")
	}
	if _, err := engine.Review("deadbeefdeadbeef", "REVIEWED", "operator calls a nil Titan engine"); err == nil {
		t.Fatal("nil engine accepted a review")
	}
	if _, err := engine.Contain(context.Background(), "deadbeefdeadbeef", "operator calls a nil Titan engine"); err == nil {
		t.Fatal("nil engine accepted containment")
	}
	if quarantine := engine.Quarantine(); quarantine.Count != 0 {
		t.Fatalf("nil engine quarantine = %+v", quarantine)
	}
	if policy := engine.Policy(); policy.Mode != "" {
		t.Fatalf("nil engine policy = %+v", policy)
	}
}

// recordingTitanObserver fails a fixed number of times, then blocks until the
// context is cancelled. It records when each sensor run started so a test can
// measure the mandatory restart backoff (FIND-031).
type recordingTitanObserver struct {
	mu     sync.Mutex
	starts []time.Time
}

func (o *recordingTitanObserver) Run(ctx context.Context, _ []string, _ chan<- titanObservation) error {
	o.mu.Lock()
	o.starts = append(o.starts, time.Now())
	attempt := len(o.starts)
	o.mu.Unlock()
	if attempt >= 3 {
		<-ctx.Done()
		return ctx.Err()
	}
	return errors.New("injected recoverable sensor failure")
}

func (o *recordingTitanObserver) started() []time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]time.Time(nil), o.starts...)
}

// TestTitanSensorRestartBackoff is the FIND-031 regression: a recoverable sensor
// failure must not make the Run loop spin. The retry delay is mandatory, above
// 100ms on the first failure, growing for consecutive failures and capped.
func TestTitanSensorRestartBackoff(t *testing.T) {
	first := titanSensorRestartDelay(1, 0)
	if first <= 100*time.Millisecond || first != titanSensorRestartBackoffBase {
		t.Fatalf("first restart delay = %s, want the base delay above 100ms", first)
	}
	second := titanSensorRestartDelay(2, 0)
	if second <= first {
		t.Fatalf("restart delay does not grow: %s then %s", first, second)
	}
	if capped := titanSensorRestartDelay(64, 0); capped != titanSensorRestartBackoffMax {
		t.Fatalf("restart delay is not capped: %s (cap %s)", capped, titanSensorRestartBackoffMax)
	}
	if jittered := titanSensorRestartDelay(1, titanSensorRestartBackoffBase); jittered <= titanSensorRestartBackoffBase ||
		jittered > titanSensorRestartBackoffMax {
		t.Fatalf("jitter moved the delay outside its bounds: %s", jittered)
	}

	rig := newTitanTestRig(t, nil)
	observer := &recordingTitanObserver{}
	engine, err := NewTitanEngine(rig.cfg, TitanDeps{
		Version: titanTestVersion, DataRoot: rig.stateDir,
		Observer: observer,
		Evidence: rig.evidence.Record, Events: func(Event) {},
		Now: func() time.Time { return rig.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { engine.Run(ctx); close(done) }()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && len(observer.started()) < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	starts := observer.started()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Titan Run did not stop after cancellation")
	}
	if len(starts) < 3 {
		t.Fatalf("the sensor was restarted %d times, want at least 3 retries", len(starts))
	}
	firstGap := starts[1].Sub(starts[0])
	secondGap := starts[2].Sub(starts[1])
	if firstGap <= 100*time.Millisecond {
		t.Fatalf("the first sensor retry was not backed off: %s", firstGap)
	}
	if secondGap <= firstGap {
		t.Fatalf("the backoff did not grow for the second retry: %s then %s", firstGap, secondGap)
	}
	if !rig.evidence.hasKind("titan.sensor.restart_backoff") {
		t.Fatal("the restart backoff was not evidenced")
	}
}
