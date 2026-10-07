// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- disclosure

// TestFaultResponsesNeverCarryInternalDetail proves the structural rule that
// replaced the keyword filter: a message that is literally the internal cause is
// the shape of a leak, and it can never reach the client.
func TestFaultResponsesNeverCarryInternalDetail(t *testing.T) {
	internal := errors.New("open /var/lib/vgt/gedefense/policy.key: permission denied")

	// The exact shape that leaked before the fix: the caller forwards the runtime
	// error as the operator-facing message.
	recorder := httptest.NewRecorder()
	apiError(recorder, http.StatusBadRequest, internal.Error(), nil)
	body := recorder.Body.String()
	if strings.Contains(body, "/var/lib") || strings.Contains(body, "permission denied") {
		t.Fatalf("internal path reached the client: %s", body)
	}
	if !strings.Contains(body, "error_id") {
		t.Fatalf("an opaque fault must still be correlatable: %s", body)
	}

	// A compiled-in message is published, and the cause is still not serialised.
	recorder = httptest.NewRecorder()
	apiError(recorder, http.StatusConflict, "import cannot be applied", internal)
	body = recorder.Body.String()
	if !strings.Contains(body, "import cannot be applied") {
		t.Fatalf("an operator message was dropped: %s", body)
	}
	if strings.Contains(body, "/var/lib") || strings.Contains(body, "policy.key") {
		t.Fatalf("the cause accompanied an operator message: %s", body)
	}

	// apiFault is opaque by construction.
	recorder = httptest.NewRecorder()
	apiFault(recorder, http.StatusServiceUnavailable, internal)
	body = recorder.Body.String()
	if strings.Contains(body, "/var/lib") || strings.Contains(body, "permission denied") {
		t.Fatalf("apiFault disclosed internal detail: %s", body)
	}
}

// TestNoHandlerForwardsARuntimeErrorAsOperatorText guards the class rather than
// the instance: a new call site that forwards err.Error() reintroduces the leak.
func TestNoHandlerForwardsARuntimeErrorAsOperatorText(t *testing.T) {
	for _, source := range []string{"server.go", "fabric_settings.go", "fabric_surface_api.go", "server_settings.go", "xdr_recovery_api.go"} {
		content := moduleSource(t, source)
		for _, match := range regexp.MustCompile(`apiError\([^)]*err\.Error\(\)`).FindAllString(content, -1) {
			t.Errorf("%s forwards a runtime error as operator-facing text: %s", source, match)
		}
	}
}

// TestOperatorMessagesAreNotFiltered proves the replacement does not mangle
// legitimate wording. The previous keyword filter rewrote messages that merely
// mentioned a token or a key.
func TestOperatorMessagesAreNotFiltered(t *testing.T) {
	for _, message := range []string{
		"an import token from a completed preview is required",
		"invalid key rotation request",
		"settings revision not found",
	} {
		recorder := httptest.NewRecorder()
		apiError(recorder, http.StatusBadRequest, message, nil)
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Error != message {
			t.Errorf("operator message %q was rewritten to %q", message, payload.Error)
		}
	}
}

// ---------------------------------------------------------------- identifiers

// TestEvidenceIdentifiersStayUnguessableAndWellFormed guards both properties the
// evidence format depends on: the value comes from the system random source, and
// its width still satisfies the CS-/TX-/QV- length contract.
func TestEvidenceIdentifiersStayUnguessableAndWellFormed(t *testing.T) {
	seen := make(map[string]bool, 1024)
	for attempt := 0; attempt < 1024; attempt++ {
		id := randomID()
		if len(id) != 16 {
			t.Fatalf("identifier width changed: %d characters, the 19-character prefixed format depends on 16", len(id))
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatalf("identifier is not hexadecimal: %q", id)
		}
		if seen[id] {
			t.Fatalf("identifier repeated within 1024 draws: %q", id)
		}
		seen[id] = true
	}
	// The format contracts that would break if the width changed again.
	caseID := "CS-" + randomID()
	if len(caseID) != 19 {
		t.Fatalf("case identifier length %d violates the validated 19-character format", len(caseID))
	}
}

func TestRandomBytesHexBoundsItsInput(t *testing.T) {
	if _, err := randomBytesHex(0); err == nil {
		t.Fatal("a zero-length random request was accepted")
	}
	if _, err := randomBytesHex(1024); err == nil {
		t.Fatal("an oversized random request was accepted")
	}
	value, err := randomBytesHex(8)
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != 16 {
		t.Fatalf("unexpected random token width: %d", len(value))
	}
}

// ---------------------------------------------------------------- path safety

// TestCanaryDeploymentRefusesSymlinks covers the finding that turned a decoy
// deployment into an arbitrary file write with the service identity.
func TestCanaryDeploymentRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.conf")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A canary path that is itself a link must be refused, not followed.
	linked := filepath.Join(dir, "decoy.env")
	if err := os.Symlink(victim, linked); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if err := DeployCanaryFile(linked, CanaryDotEnv); err == nil {
		t.Fatal("a symlinked canary path was accepted")
	}
	if content, err := os.ReadFile(victim); err != nil || string(content) != "original" {
		t.Fatalf("the symlink target was modified: %q %v", content, err)
	}

	// A staging path that is a link must be refused as well: the writer uses
	// O_EXCL, which refuses a link in the same step as an existing file.
	staged := filepath.Join(dir, "second.env")
	if err := os.Symlink(victim, staged+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := DeployCanaryFile(staged, CanaryDotEnv); err == nil {
		t.Fatal("a symlinked staging path was accepted")
	}
	if content, err := os.ReadFile(victim); err != nil || string(content) != "original" {
		t.Fatalf("the staging symlink target was modified: %q %v", content, err)
	}

	// The legitimate path still works and lands as a regular 0600 file.
	clean := filepath.Join(dir, "clean.env")
	if err := DeployCanaryFile(clean, CanaryDotEnv); err != nil {
		t.Fatalf("a legitimate deployment failed: %v", err)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("deployed decoy has unexpected mode %v", info.Mode())
	}
	if _, err := os.Lstat(clean + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the staging file was left behind")
	}
}

// TestAtomicWriteRefusesSymlinkedTargets covers every store that routes through
// the shared crash-safe writer.
func TestAtomicWriteRefusesSymlinkedTargets(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "state.json")
	if err := os.Symlink(victim, linked); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if err := atomicWriteFile(linked, []byte("overwritten"), 0o600); err == nil {
		t.Fatal("the atomic writer followed a symlink")
	}
	if content, err := os.ReadFile(victim); err != nil || string(content) != "original" {
		t.Fatalf("the symlink target was modified: %q %v", content, err)
	}

	// A stale staging link must not be followed either.
	stale := filepath.Join(dir, "other.json")
	if err := os.Symlink(victim, stale+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(stale, []byte("payload"), 0o600); err != nil {
		t.Fatalf("a stale staging link broke a legitimate write: %v", err)
	}
	if content, err := os.ReadFile(stale); err != nil || string(content) != "payload" {
		t.Fatalf("the legitimate write did not land: %q %v", content, err)
	}
	if content, err := os.ReadFile(victim); err != nil || string(content) != "original" {
		t.Fatalf("the staging link redirected the write: %q %v", content, err)
	}
}

// TestJailDestinationNeverTruncatesEvidence proves quarantined content cannot be
// destroyed by reusing a name.
func TestJailDestinationNeverTruncatesEvidence(t *testing.T) {
	dir := t.TempDir()
	first, handle, err := openJailDestination(dir, "payload.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handle.Write([]byte("first object")); err != nil {
		_ = handle.Close()
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}

	second, handle, err := openJailDestination(dir, "payload.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handle.Write([]byte("second object")); err != nil {
		_ = handle.Close()
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("a colliding name reused the existing object path")
	}
	if content, err := os.ReadFile(first); err != nil || string(content) != "first object" {
		t.Fatalf("the first object was destroyed: %q %v", content, err)
	}

	// A symlink in the vault must not be followed.
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "linked.bin")); err != nil {
		t.Fatal(err)
	}
	// O_EXCL refuses the link, so the allocator moves to a suffixed name and the
	// link target stays untouched.
	path, handle, err := openJailDestination(dir, "linked.bin")
	if err != nil {
		t.Fatal(err)
	}
	_ = handle.Close()
	if path == filepath.Join(dir, "linked.bin") {
		t.Fatal("the jail destination reused a symlinked path")
	}
	if content, err := os.ReadFile(victim); err != nil || string(content) != "original" {
		t.Fatalf("the jail followed a symlink: %q %v", content, err)
	}
}

// ---------------------------------------------------------------- import store

// TestImportTokensBindToReviewedContent proves two previews that share a revision
// and a change count cannot collide on one token.
func TestImportTokensBindToReviewedContent(t *testing.T) {
	store, err := newImportPreviewStore()
	if err != nil {
		t.Fatal(err)
	}
	base := defaultRuntimeSettings(defaultConfig())
	now := time.Unix(1700000000, 0).UTC()

	first := cloneRuntimeSettings(base)
	settings := effectiveIntegritySettings(first)
	settings.Chronos.MaxFiles = 1111
	first.Integrity = &settings

	second := cloneRuntimeSettings(base)
	other := effectiveIntegritySettings(second)
	other.Chronos.MaxFiles = 2222
	second.Integrity = &other

	diff := []FabricSettingDiff{{Key: "integrity.chronos.max_files"}}
	entryA, err := store.remember(first, diff, base.Revision, now)
	if err != nil {
		t.Fatal(err)
	}
	entryB, err := store.remember(second, diff, base.Revision, now)
	if err != nil {
		t.Fatal(err)
	}
	if entryA.token == entryB.token {
		t.Fatal("two different reviewed revisions produced the same import token")
	}

	// Claiming is single use and returns the reviewed revision itself.
	claimed, err := store.claim(entryA.token, base.Revision, now)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.candidate.Integrity.Chronos.MaxFiles != 1111 {
		t.Fatalf("the claim returned a different revision: %d", claimed.candidate.Integrity.Chronos.MaxFiles)
	}
	if _, err := store.claim(entryA.token, base.Revision, now); err == nil {
		t.Fatal("an import token was claimable twice")
	}
	// A claim past its expiry is refused.
	if _, err := store.claim(entryB.token, base.Revision, now.Add(importPreviewTTL+time.Minute)); err == nil {
		t.Fatal("an expired import token was accepted")
	}
}

// TestImportEndpointsFailClosedWhenTheStoreIsMissing covers the nil dereference
// that would have turned a random-source failure into a panic on two endpoints.
func TestImportEndpointsFailClosedWhenTheStoreIsMissing(t *testing.T) {
	server, _, _ := surfaceFixture(t)
	server.imports = nil

	preview := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/import/preview", []byte(`{}`))
	if preview.Code != http.StatusServiceUnavailable {
		t.Fatalf("preview without a store returned %d instead of failing closed", preview.Code)
	}
	apply := surfaceRequest(t, server, http.MethodPost, "/api/v1/settings/import/apply",
		[]byte(`{"token":"0000000000000000","expected_revision":1}`))
	if apply.Code != http.StatusServiceUnavailable {
		t.Fatalf("apply without a store returned %d instead of failing closed", apply.Code)
	}
}

// ---------------------------------------------------------------- browser policy

// TestContentSecurityPolicyGrantsNoInlineExecution locks the policy: the
// dashboard ships no inline script and no inline style, so neither needs to be
// allowed, and Trusted Types turns that into a runtime invariant.
func TestContentSecurityPolicyGrantsNoInlineExecution(t *testing.T) {
	policy := contentSecurityPolicy
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "'unsafe-hashes'", "*"} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("content security policy still grants %q: %s", forbidden, policy)
		}
	}
	for _, required := range []string{
		"default-src 'self'", "script-src 'self'", "style-src 'self'", "object-src 'none'",
		"base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'",
		"require-trusted-types-for 'script'", "connect-src 'self'", "worker-src 'none'",
	} {
		if !strings.Contains(policy, required) {
			t.Errorf("content security policy is missing %q", required)
		}
	}

	// The header the server actually emits must be the constant above, so the two
	// cannot drift apart.
	cfg, state, policyStore, release := betaReleaseFixture(t)
	server := NewAPIServer(cfg, state, nil, nil, policyStore, nil, release, nil, fabricTestToken)
	recorder := httptest.NewRecorder()
	server.secure(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).
		ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := recorder.Header().Get("Content-Security-Policy"); got != contentSecurityPolicy {
		t.Fatalf("served policy drifted from the constant: %q", got)
	}
	if recorder.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS was emitted for a plain-HTTP request")
	}
}

// TestDashboardShipsNoInlineStyleOrTrustedTypesSink proves the policy above is
// satisfiable: no inline style attribute exists, and no module assigns to a sink
// that Trusted Types governs.
func TestDashboardShipsNoInlineStyleOrTrustedTypesSink(t *testing.T) {
	document := embeddedWebFile(t, "index.html")
	if strings.Contains(document, `style="`) {
		t.Error("the document still carries an inline style attribute, which would require 'unsafe-inline'")
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(document) {
		t.Error("the document carries an inline event handler")
	}

	sinks := regexp.MustCompile(`(?i)\.(innerHTML|outerHTML)\s*=|\[['"](innerHTML|outerHTML)['"]\]\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(|createContextualFragment\s*\(|\.srcdoc\s*=|\.setHTML\(|eval\(|new Function`)
	for _, name := range embeddedWebFiles(t) {
		if !strings.HasSuffix(name, ".js") {
			continue
		}
		source := embeddedWebFile(t, name)
		if match := sinks.FindString(source); match != "" {
			t.Errorf("%s uses %q, which Trusted Types refuses at runtime", name, match)
		}
		if regexp.MustCompile(`set(Timeout|Interval)\(\s*['"]`).MatchString(source) {
			t.Errorf("%s passes a string to a timer, which Trusted Types refuses", name)
		}
		if regexp.MustCompile(`setAttribute\(\s*['"]style`).MatchString(source) {
			t.Errorf("%s sets an inline style attribute, which the policy refuses", name)
		}
	}
}

// TestDashboardCreatesNoDynamicScriptElements closes the remaining Trusted Types
// sink class: a script element whose source is assigned from data.
func TestDashboardCreatesNoDynamicScriptElements(t *testing.T) {
	pattern := regexp.MustCompile(`createElement\(\s*['"](script|iframe|object|embed)['"]`)
	for _, name := range embeddedWebFiles(t) {
		if !strings.HasSuffix(name, ".js") {
			continue
		}
		if match := pattern.FindString(embeddedWebFile(t, name)); match != "" {
			t.Errorf("%s creates a %s element dynamically", name, match)
		}
	}
}

func moduleSource(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(content)
}
