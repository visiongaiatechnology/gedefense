// STATUS: DIAMANT VGT SUPREME
package main

// Regression tests for the GeDefense 5.2 security update, audit
// VGT-AUDIT-20261114-GD51:
//
//	FIND-018 - allowlist removal decoded the request body twice
//	FIND-019 - ReplayGuard global lockout and the trust-fabric data race
//	FIND-022 - silent TLS hostname-policy deactivation and the static self-test header
//
// FIND-020 (inline admission slot) is covered by the Linux end-to-end test in
// l7_edge_e2e_test.go and FIND-021 (rate-limit exemptions) by l7_rate_limit_test.go.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- FIND-018

func allowlistAPICall(t *testing.T, server *APIServer, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+path, bytes.NewBufferString(body))
	request.Host = "127.0.0.1"
	request.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-VGT-Request-ID", randomID()+randomID())
	recorder := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(recorder, request)
	return recorder
}

func allowlistContains(server *APIServer, target string) bool {
	for _, entry := range server.settings.Get().ManagementAllowlist {
		if entry == target {
			return true
		}
	}
	return false
}

// TestAllowlistAddRemoveRoundtripDecodesBodyOnce is the FIND-018 acceptance
// test: a management allowlist entry must be addable and then removable with the
// target-derived confirmation in the same request body. Before the fix the
// removal handler decoded the body twice, so the second decoder always saw EOF
// and removal failed with HTTP 400 forever.
func TestAllowlistAddRemoveRoundtripDecodesBodyOnce(t *testing.T) {
	server, _, release := settingsAPIFixture(t)
	if phase := release.Status().Phase; phase != ReleasePhaseObserve && phase != ReleasePhaseDegraded {
		t.Fatalf("fixture is not in an allowlist-removable phase: %s", phase)
	}
	// The fixture has no kernel core attached: report the kernel as disconnected
	// so the handler takes its documented core-unavailable path instead of
	// calling a nil core.
	server.state.SetCore(false, "")

	const target = "198.51.100.7/32"
	if rec := allowlistAPICall(t, server, "/api/v1/allowlist", `{"target":"`+target+`"}`); rec.Code != http.StatusCreated {
		t.Fatalf("allowlist add status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !allowlistContains(server, target) {
		t.Fatal("added allowlist entry is not in the settings store")
	}

	removeBody := `{"target":"` + target + `","confirmation":"REMOVE ALLOWLIST ` + target + `","reason":"remediate test fixture"}`
	rec := allowlistAPICall(t, server, "/api/v1/allowlist/remove", removeBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowlist removal failed with the confirmation in the same body: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if allowlistContains(server, target) {
		t.Fatal("removed allowlist entry is still present in the settings store")
	}
	if got := len(server.settings.Get().ManagementAllowlist); got != 1 {
		t.Fatalf("allowlist length after the add/remove roundtrip=%d want=1", got)
	}
}

// TestAllowlistRemovalRequiresConfirmationFromTheSameBody keeps the protection
// that motivated the typed confirmation: removal still needs the exact phrase
// and a plausible reason, decoded from the same single body read.
func TestAllowlistRemovalRequiresConfirmationFromTheSameBody(t *testing.T) {
	server, _, _ := settingsAPIFixture(t)
	server.state.SetCore(false, "")
	const target = "198.51.100.7/32"
	if rec := allowlistAPICall(t, server, "/api/v1/allowlist", `{"target":"`+target+`"}`); rec.Code != http.StatusCreated {
		t.Fatalf("allowlist add status=%d body=%s", rec.Code, rec.Body.String())
	}

	cases := []struct {
		name string
		body string
	}{
		{"missing confirmation", `{"target":"` + target + `","reason":"remediate test fixture"}`},
		{"wrong confirmation phrase", `{"target":"` + target + `","confirmation":"REMOVE ALLOWLIST 203.0.113.1/32","reason":"remediate test fixture"}`},
		{"reason too short", `{"target":"` + target + `","confirmation":"REMOVE ALLOWLIST ` + target + `","reason":"short"}`},
		{"unknown field", `{"target":"` + target + `","confirmation":"REMOVE ALLOWLIST ` + target + `","reason":"remediate test fixture","surprise":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := allowlistAPICall(t, server, "/api/v1/allowlist/remove", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("unsafe removal accepted: status=%d body=%s", rec.Code, rec.Body.String())
			}
			if !allowlistContains(server, target) {
				t.Fatal("the rejection still removed the allowlist entry")
			}
		})
	}
}

// ---------------------------------------------------------------- FIND-019

func replayTestID(index int) string {
	return fmt.Sprintf("request_%015d", index)
}

// TestReplayGuardStaysAvailableButNeverForgetsReplay is the FIND-019
// acceptance test: filling the cache beyond its capacity must neither lock out
// all further mutations nor allow an identifier that was displaced inside its
// replay window to be claimed twice.
func TestReplayGuardStaysAvailableButNeverForgetsReplay(t *testing.T) {
	const capacity = 256
	guard := NewReplayGuard(10 * time.Minute)
	guard.maxEntries = capacity
	guard.maxRetained = capacity
	now := time.Now()

	firstID := replayTestID(1)
	if !guard.Claim(firstID, now) {
		t.Fatal("fresh identifier was refused")
	}
	for index := 2; index <= capacity; index++ {
		if !guard.Claim(replayTestID(index), now) {
			t.Fatalf("identifier %d below capacity was refused", index)
		}
	}
	// Historical behaviour answered false here, which locked every mutation out
	// until the whole window expired.
	if !guard.Claim(replayTestID(capacity+1), now) {
		t.Fatal("a full replay cache still causes a global mutation lockout")
	}
	// Displacement must not equal forgetting: the oldest identifier is inside its
	// replay window and a second claim must be refused.
	if guard.Claim(firstID, now) {
		t.Fatal("a replay of the displaced identifier was accepted inside the window")
	}
	// After the window the identifier is released for legitimate reuse.
	later := now.Add(11 * time.Minute)
	if !guard.Claim(firstID, later) {
		t.Fatal("an expired replay identifier was not released after the window")
	}
	// Malformed identifiers keep failing closed.
	if guard.Claim("short", later) {
		t.Fatal("malformed request id was accepted")
	}
}

// TestReplayGuardPerScopeQuotaBoundsOneCredential proves the per-scope quota:
// one claiming identity cannot fill (and thereby displace) the bounded cache,
// while another identity keeps its own budget.
func TestReplayGuardPerScopeQuotaBoundsOneCredential(t *testing.T) {
	guard := NewReplayGuard(time.Hour)
	guard.maxPerScope = 4
	now := time.Now()
	for index := 0; index < 4; index++ {
		if !guard.ClaimFor("operator:a", replayTestID(index), now) {
			t.Fatalf("scope quota rejected identifier %d below the limit", index)
		}
	}
	if guard.ClaimFor("operator:a", replayTestID(4), now) {
		t.Fatal("one scope exceeded its replay-cache quota")
	}
	if !guard.ClaimFor("operator:b", replayTestID(5), now) {
		t.Fatal("an unrelated scope was locked out by another scope's quota")
	}
	// The quota never weakens replay rejection inside the same scope.
	if guard.ClaimFor("operator:a", replayTestID(0), now) {
		t.Fatal("a scoped replay was accepted")
	}
	// Expiry releases the quota again.
	later := now.Add(2 * time.Hour)
	if !guard.ClaimFor("operator:a", replayTestID(6), later) {
		t.Fatal("expired scoped entries did not release the quota")
	}
}

// TestTrustFabricPolicyStoreTrustSettingsAreRaceFree exercises the FIND-019 data
// race: ApplyPolicy writes the administrable trust namespace while Load (which
// holds the store lock and calls the same getters) and lock-free readers observe
// it. Run with -race; before the snapshot publishing this tripped the race
// detector on p.trust.
func TestTrustFabricPolicyStoreTrustSettingsAreRaceFree(t *testing.T) {
	dir := t.TempDir()
	store, err := NewPolicyStore(PolicyConfig{
		StateFile:      filepath.Join(dir, "policy.json"),
		SigningKeyFile: filepath.Join(dir, "policy.key"),
		PublicKeyFile:  filepath.Join(dir, "policy.pub"),
		RequireSigned:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		index := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			index++
			settings := defaultPolicyTrustFabricSettings()
			settings.RequireSigned = index%2 == 0
			settings.MaxStateBytes = int64(64<<10) << (index % 3)
			if err := store.ApplyPolicy(settings); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = store.requireSigned()
			_ = store.maxStateBytes()
			_ = store.Policy()
			_ = store.Status()
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = store.Load()
		}
	}()
	time.Sleep(75 * time.Millisecond)
	close(stop)
	wg.Wait()

	// The published snapshot must still be live, not frozen at construction.
	unsigned := defaultPolicyTrustFabricSettings()
	unsigned.RequireSigned = false
	if err := store.ApplyPolicy(unsigned); err != nil {
		t.Fatal(err)
	}
	if store.requireSigned() {
		t.Fatal("requireSigned did not observe the applied administrable revision")
	}
	if store.maxStateBytes() != unsigned.MaxStateBytes {
		t.Fatalf("maxStateBytes=%d want=%d", store.maxStateBytes(), unsigned.MaxStateBytes)
	}
	if err := store.ApplyPolicy(defaultPolicyTrustFabricSettings()); err != nil {
		t.Fatal(err)
	}
	if !store.requireSigned() {
		t.Fatal("requireSigned did not observe the restored requirement")
	}
}

// ---------------------------------------------------------------- FIND-022 (TLS)

// TestTLSAllowlistUnconfiguredIsVisibleNotSilent pins the TLS half of FIND-022:
// an empty allowed-domain list must not silently authorise every SNI. The
// hostname helper fails closed, ClientHello inspection reports an explicit
// configuration finding instead of a false "foreign" accusation, and the
// degraded policy state is published in the L7 status.
func TestTLSAllowlistUnconfiguredIsVisibleNotSilent(t *testing.T) {
	if allowedTLSHostname(nil, "example.com") {
		t.Fatal("an empty allowlist must not match every hostname")
	}
	if allowedTLSHostname(map[string]struct{}{}, "example.com") {
		t.Fatal("an empty allowlist must not match every hostname")
	}

	engine := NewTLSSecurityEngine(nil, 15, 10, true)
	packet := buildSyntheticClientHello("attacker-controlled.example", []uint16{0x002f}, nil, false)
	findings := engine.InspectHandshake("203.0.113.90", packet, time.Now().UTC())
	var unconfigured, foreign bool
	for _, finding := range findings {
		switch finding.RuleID {
		case "TLS.SNI.ALLOWLIST_UNCONFIGURED":
			unconfigured = true
		case "TLS.SNI.FOREIGN":
			foreign = true
		}
	}
	if !unconfigured {
		t.Fatalf("unconfigured TLS policy is not visible in the findings: %+v", findings)
	}
	if foreign {
		t.Fatalf("a policy that was never configured must not accuse a hostname as foreign: %+v", findings)
	}
	// Host/SNI correlation cannot classify either; it must not invent a mismatch.
	if mismatch := engine.RecordHTTPRequestForHost("203.0.113.90", "different.example", time.Now().UTC()); len(mismatch) != 0 {
		t.Fatalf("unclassified host correlation produced a mismatch: %+v", mismatch)
	}

	// A configured scope keeps the real enforcement and reports the foreign SNI.
	configured := NewTLSSecurityEngine([]string{"authorized.example"}, 15, 10, true)
	foreignConfigured := false
	for _, finding := range configured.InspectHandshake("203.0.113.91", packet, time.Now().UTC()) {
		if finding.RuleID == "TLS.SNI.FOREIGN" {
			foreignConfigured = true
		}
	}
	if !foreignConfigured {
		t.Fatal("a foreign SNI is no longer detected under a configured scope")
	}
}

func tlsStatusFixture(t *testing.T, cfg L7Config) *State {
	t.Helper()
	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState("test", Config{L7: cfg, XDR: defaultConfig().XDR, Release: defaultConfig().Release})
	service, err := NewL7Service(cfg, engine, state)
	if err != nil {
		t.Fatal(err)
	}
	service.publishStatus(true)
	return state
}

// TestL7StatusPublishesTLSUnconfiguredDegradedState proves the explicit
// UNCONFIGURED_DEGRADED state is operator-visible in the status instead of being
// an implicit "allow everything".
func TestL7StatusPublishesTLSUnconfiguredDegradedState(t *testing.T) {
	unconfiguredCfg := l7TestConfig()
	unconfiguredCfg.TLSEnabled = true
	unconfiguredCfg.TLSAllowedDomains = nil
	state := tlsStatusFixture(t, unconfiguredCfg)
	if status := state.L7Status(); !strings.Contains(status.TLSLastError, tlsPolicyUnconfiguredState) {
		t.Fatalf("TLS status does not publish the unconfigured policy state: %q", status.TLSLastError)
	}

	configuredCfg := l7TestConfig()
	configuredCfg.TLSEnabled = true
	configuredCfg.TLSAllowedDomains = []string{"example.test"}
	state = tlsStatusFixture(t, configuredCfg)
	if status := state.L7Status(); strings.Contains(status.TLSLastError, tlsPolicyUnconfiguredState) {
		t.Fatalf("configured TLS policy still reports the degraded state: %q", status.TLSLastError)
	}
}

// ------------------------------------------------------ FIND-022 (self-test)

// TestL7SelfTestAuthorizationRequiresEphemeralToken covers the static-header
// bypass: the reserved self-test path may only be used by this very process,
// with a random per-process token, and only on the reserved paths.
func TestL7SelfTestAuthorizationRequiresEphemeralToken(t *testing.T) {
	token := l7SelfTestHeaderValue()
	if len(token) < 32 {
		t.Fatalf("self-test token is not a long random value: %q", token)
	}
	if token == "1" {
		t.Fatal("self-test token is the historical static header value")
	}
	cred := l7PeerCredentials{PID: int32(os.Getpid()), UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	ctx := context.WithValue(context.Background(), l7PeerContextKey{}, cred)

	request := func(path, header string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "http://unix"+path, nil)
		if header != "" {
			req.Header.Set(l7SelfTestHeaderName, header)
		}
		return req
	}

	if !l7SelfTestPeerAuthorized(ctx, request(l7SelfTestPath, token)) {
		t.Fatal("the in-process self-test with the valid token was refused")
	}
	if !l7SelfTestPeerAuthorized(ctx, request("/v1/inspect", token)) {
		t.Fatal("the in-process producer self-test with the valid token was refused")
	}
	if l7SelfTestPeerAuthorized(ctx, request(l7SelfTestPath, "")) {
		t.Fatal("a self-test request without a token was accepted")
	}
	if l7SelfTestPeerAuthorized(ctx, request(l7SelfTestPath, "1")) {
		t.Fatal("the historical static header value was accepted")
	}
	if l7SelfTestPeerAuthorized(ctx, request(l7SelfTestPath, token+"x")) {
		t.Fatal("a wrong self-test token was accepted")
	}
	if l7SelfTestPeerAuthorized(ctx, request("/v1/tls/clienthello", token)) {
		t.Fatal("the self-test token authorised an unrelated path")
	}
	if l7SelfTestPeerAuthorized(context.Background(), request(l7SelfTestPath, token)) {
		t.Fatal("a self-test request without peer credentials was accepted")
	}

	foreignUID := cred
	foreignUID.UID++
	if l7SelfTestPeerAuthorized(context.WithValue(context.Background(), l7PeerContextKey{}, foreignUID), request(l7SelfTestPath, token)) {
		t.Fatal("a same-UUID-shaped but foreign peer identity was accepted")
	}
	foreignPID := cred
	foreignPID.PID = int32(os.Getpid()) + 1
	if l7SelfTestPeerAuthorized(context.WithValue(context.Background(), l7PeerContextKey{}, foreignPID), request(l7SelfTestPath, token)) {
		t.Fatal("a foreign process with the same UID was accepted by the self-test bypass")
	}
	if l7SelfTestPeerAuthorized(ctx, nil) {
		t.Fatal("a nil request was accepted")
	}
}
