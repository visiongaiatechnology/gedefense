// STATUS: DIAMANT VGT SUPREME
package main

// POINT 3 / P3-T5 API tests: the read-only styx status/beacons endpoints, the
// bounded /api/v1/status field and the settings module/validation surface.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ------------------------------------------------------------------- API

func styxAPIFixture(t *testing.T) (*APIServer, *styxPolicyFakeCore, *XDREngine) {
	t.Helper()
	server, store, _ := settingsAPIFixture(t)
	if _, err := store.Update(styxPolicyTestSettings()); err != nil {
		t.Fatalf("could not persist StyX settings: %v", err)
	}
	settings := store.Get()
	core := newStyxPolicyFakeCore()
	engine := &XDREngine{
		state: server.state, correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
	}
	beaconClock := newBeaconTestClock()
	engine.styxBeacon = NewStyxBeaconEngine(StyxBeaconConfig{
		Enabled: true, Mode: StyxModeMonitor, FlowCapabilityKnown: true, Now: beaconClock.Now,
	}, engine.correlator, engine.emitStyxBeaconIncident)
	engine.styxPolicy = NewStyxPolicySyncer(core, server.state, settings)
	engine.setStyxBeaconCapability(true)
	if got := engine.styxPolicy.Sync(context.Background()); got.State != StyxSyncStateApplied {
		t.Fatalf("API fixture sync failed: %+v", got)
	}
	engine.recordStyxFlowBatch(periodicBeaconEvents(30*time.Second, 13, 128, 0), 0, beaconClock.Now())
	engine.recordStyxFlowHealth(CoreStyxFlowHealth{Emitted: 42, RingDrops: 1, DropsTotal: 1}, beaconClock.Now())
	server.xdr = engine
	return server, core, engine
}

func TestStyxAPIStatusEndpointsAreReadOnlyAndBounded(t *testing.T) {
	server, _, _ := styxAPIFixture(t)

	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/styx/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("styX status returned %d: %s", rec.Code, rec.Body.String())
	}
	var status StyxStatusView
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("styX status payload: %v", err)
	}
	if status.State != StyxSyncStateApplied || status.Capability != styxWireVersion {
		t.Fatalf("styX status does not describe the applied policy: %+v", status)
	}
	if status.Sync.Mode != StyxModeMonitor || status.Sync.Cells != 2 || status.Sync.AllowRules != 2 || status.Sync.Resolvers != 2 {
		t.Fatalf("styX status sync projection is wrong: %+v", status.Sync)
	}
	if status.SensorState != "active" {
		t.Fatalf("styX status does not reflect the detector state: %q", status.SensorState)
	}
	if status.Beacon.Events == 0 || status.Beacon.Incidents != 1 || len(status.Beacon.Top) > 10 {
		t.Fatalf("styX status beacon counters/top are wrong: %+v", status.Beacon)
	}
	if status.KernelHealth.Emitted != 42 || status.KernelHealthAt == nil {
		t.Fatalf("styX status does not carry the kernel flow health: %+v", status.KernelHealth)
	}
	if status.KernelHealthError != "" {
		t.Fatalf("healthy kernel health carries an error: %q", status.KernelHealthError)
	}

	beacons := fabricRequest(t, server, http.MethodGet, "/api/v1/styx/beacons", nil)
	if beacons.Code != http.StatusOK {
		t.Fatalf("styX beacons returned %d: %s", beacons.Code, beacons.Body.String())
	}
	var beaconView StyxBeaconsView
	if err := json.Unmarshal(beacons.Body.Bytes(), &beaconView); err != nil {
		t.Fatalf("styX beacons payload: %v", err)
	}
	if beaconView.SensorState != "active" || beaconView.SyncState != StyxSyncStateApplied {
		t.Fatalf("styX beacons view is wrong: %+v", beaconView)
	}
	if len(beaconView.Beacon.Top) > 10 {
		t.Fatalf("beacons view is not bounded: %d entries", len(beaconView.Beacon.Top))
	}
	for _, flow := range beaconView.Beacon.Top {
		if flow.Remote == "" && flow.CgroupID == 0 {
			t.Fatalf("flow snapshot is empty: %+v", flow)
		}
	}

	// The existing /api/v1/status keeps its payload and gains only the bounded field.
	snapshot := fabricRequest(t, server, http.MethodGet, "/api/v1/status", nil)
	if snapshot.Code != http.StatusOK {
		t.Fatalf("status returned %d", snapshot.Code)
	}
	var payload struct {
		Version string       `json:"version"`
		XDR     *XDRStatus   `json:"xdr"`
		Styx    *StyxStatus  `json:"styx"`
		Events  []Event      `json:"events"`
		Blocks  []BlockEntry `json:"blocks"`
	}
	if err := json.Unmarshal(snapshot.Body.Bytes(), &payload); err != nil {
		t.Fatalf("status payload: %v", err)
	}
	if payload.Styx == nil {
		t.Fatal("status snapshot does not carry the bounded styx field")
	}
	if payload.Styx.SyncState != StyxSyncStateApplied || payload.Styx.Mode != StyxModeMonitor || payload.Styx.Capability != styxWireVersion {
		t.Fatalf("bounded styx status field is wrong: %+v", payload.Styx)
	}
	if payload.XDR == nil {
		t.Fatal("status snapshot lost its xdr field")
	}
	if payload.Styx.IncidentTotal != 1 {
		t.Fatalf("bounded styx status does not carry the detector counters: %+v", payload.Styx)
	}

	unauthenticated := fabricRequestWithoutAuth(t, server, "/api/v1/styx/status")
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated styX status returned %d", unauthenticated.Code)
	}
}

// TestStyxAPIStatusWithoutEngineIsHonest proves the endpoint never invents a
// running sensor: a server built with no XDR engine reports unavailable, not OK.
func TestStyxAPIStatusWithoutEngineIsHonest(t *testing.T) {
	server, _, _ := settingsAPIFixture(t)
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/styx/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("styX status without engine returned %d", rec.Code)
	}
	var view StyxStatusView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.State != StyxSyncStateUnavailable || view.SensorState != "unavailable" || view.Capability != styxCapabilityUnknown {
		t.Fatalf("status without engine claims more than it can prove: %+v", view)
	}
	beacons := fabricRequest(t, server, http.MethodGet, "/api/v1/styx/beacons", nil)
	if beacons.Code != http.StatusOK {
		t.Fatalf("beacons without engine returned %d", beacons.Code)
	}
}

func TestStyxFabricSettingsModuleAPI(t *testing.T) {
	server, store, _ := settingsAPIFixture(t)

	view := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/styx", nil)
	if view.Code != http.StatusOK {
		t.Fatalf("styX settings view returned %d: %s", view.Code, view.Body.String())
	}
	var module FabricModuleView
	if err := json.Unmarshal(view.Body.Bytes(), &module); err != nil {
		t.Fatal(err)
	}
	if module.Module != "styx" {
		t.Fatalf("wrong module view: %+v", module)
	}
	snapshot, err := fabricModuleSnapshot(store.Get(), "styx")
	if err != nil {
		t.Fatalf("styX namespace has no snapshot: %v", err)
	}
	if _, ok := snapshot.(StyxFabricSettings); !ok {
		t.Fatalf("styX snapshot has the wrong type: %T", snapshot)
	}

	current := store.Get()
	invalid := cloneStyxFabricSettings(*current.Styx)
	invalid.Mode = "blocked"
	payload, _ := json.Marshal(map[string]any{"expected_revision": current.Revision, "settings": invalid})
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/styx/preview", payload); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid mode accepted: %d %s", rec.Code, rec.Body.String())
	}
	unknownField := map[string]any{"enabled": false, "mode": "off", "invented": true}
	payload, _ = json.Marshal(map[string]any{"expected_revision": current.Revision, "settings": unknownField})
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/styx/preview", payload); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown styX field accepted: %d %s", rec.Code, rec.Body.String())
	}

	valid := StyxFabricSettings{
		Enabled: true, Mode: StyxModeMonitor, LogFlows: true,
		PerCell:   []StyxCellMode{{CgroupID: 42, Mode: StyxModeEnforce}},
		Allowlist: []StyxAllowRule{{CgroupID: 42, CIDR: "203.0.113.0/24"}},
	}
	payload, _ = json.Marshal(map[string]any{"expected_revision": current.Revision, "settings": valid})
	preview := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/styx/preview", payload)
	if preview.Code != http.StatusOK {
		t.Fatalf("valid styX preview returned %d: %s", preview.Code, preview.Body.String())
	}
	var previewPayload FabricSettingsPreview
	if err := json.Unmarshal(preview.Body.Bytes(), &previewPayload); err != nil {
		t.Fatal(err)
	}
	if !previewPayload.Valid || len(previewPayload.Diff) == 0 {
		t.Fatalf("preview did not describe a change: %+v", previewPayload)
	}
	apply := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/styx", payload)
	if apply.Code != http.StatusOK {
		t.Fatalf("valid styX apply returned %d: %s", apply.Code, apply.Body.String())
	}
	updated := store.Get()
	if updated.Styx == nil || !updated.Styx.Enabled || updated.Styx.Mode != StyxModeMonitor {
		t.Fatalf("styX settings were not persisted: %+v", updated.Styx)
	}
	if len(updated.Styx.PerCell) != 1 || updated.Styx.PerCell[0].CgroupID != 42 {
		t.Fatalf("styX per-cell settings were not persisted: %+v", updated.Styx.PerCell)
	}

	schema := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/schema", nil)
	if schema.Code != http.StatusOK {
		t.Fatalf("schema endpoint returned %d", schema.Code)
	}
	var schemaPayload struct {
		Modules  []string                `json:"modules"`
		Settings []FabricSettingMetadata `json:"settings"`
	}
	if err := json.Unmarshal(schema.Body.Bytes(), &schemaPayload); err != nil {
		t.Fatal(err)
	}
	advertised := false
	for _, module := range schemaPayload.Modules {
		if module == "styx" {
			advertised = true
		}
	}
	if !advertised {
		t.Fatal("the schema endpoint does not publish the styX module")
	}
	keys := map[string]bool{}
	for _, meta := range schemaPayload.Settings {
		if meta.Module != "styx" {
			continue
		}
		if meta.Risk == "" || meta.ApplyClass == "" || meta.Description == "" || meta.Type == "" {
			t.Fatalf("styX setting %q has incomplete metadata: %+v", meta.Key, meta)
		}
		keys[meta.Key] = true
	}
	for _, want := range []string{"enabled", "mode", "log_flows", "dns_resolvers", "per_cell", "allowlist"} {
		if !keys[want] {
			t.Fatalf("styX schema is missing %q", want)
		}
	}
}
func fabricRequestWithoutAuth(t *testing.T, server *APIServer, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	return rec
}
