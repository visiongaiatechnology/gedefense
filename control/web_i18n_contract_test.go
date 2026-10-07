// STATUS: DIAMANT VGT SUPREME
package main

import (
	"regexp"
	"strings"
	"testing"
)

// Translation-key coverage.
//
// Twice now a view has been built with data-i18n attributes whose keys were never added
// to the catalogues. Nothing failed: the build was clean, the module loaded, and the
// operator saw the raw key rendered as literal text - which looks like a broken product
// rather than a missing string. The build cannot catch it and neither can a module
// syntax check, so it is asserted here.

var webTranslationAttributePattern = regexp.MustCompile(`data-i18n(?:-placeholder|-aria-label|-title)?="([^"]+)"`)

// TestEveryTranslationAttributeHasACatalogueEntry proves every key the document asks
// for exists in the default catalogue.
func TestEveryTranslationAttributeHasACatalogueEntry(t *testing.T) {
	document := embeddedWebFile(t, "index.html")
	catalogue := embeddedWebFile(t, "i18n.js")

	keys := webTranslationAttributePattern.FindAllStringSubmatch(document, -1)
	if len(keys) < 100 {
		t.Fatalf("only %d translation attributes were found; the scan looks wrong", len(keys))
	}
	missing := map[string]bool{}
	for _, match := range keys {
		key := match[1]
		if !strings.Contains(catalogue, `"`+key+`":`) {
			missing[key] = true
		}
	}
	for key := range missing {
		t.Errorf("index.html requests translation key %q, which no catalogue defines", key)
	}
}

// TestEveryTranslationKeyExistsInAllCatalogues proves the four languages stay in step.
// A key present in German but absent in Chinese renders as a raw identifier for that
// operator, which is the same defect one language over.
func TestEveryTranslationKeyExistsInAllCatalogues(t *testing.T) {
	catalogue := embeddedWebFile(t, "i18n.js")

	// Each catalogue is a frozen object literal; the blocks are separated by the
	// language keys the module already declares. Splitting on the top-level entries is
	// enough to compare coverage without parsing JavaScript.
	blocks := splitCatalogueBlocks(t, catalogue)
	if len(blocks) < 4 {
		t.Fatalf("expected at least four catalogues, found %d", len(blocks))
	}

	keyPattern := regexp.MustCompile(`"([A-Za-z0-9_.]+)":`)
	union := map[string]int{}
	for _, block := range blocks {
		for _, match := range keyPattern.FindAllStringSubmatch(block, -1) {
			union[match[1]]++
		}
	}
	// Only keys that appear in some catalogue are examined; shared non-translation keys
	// would show up with a lower count too, so the threshold is the catalogue count.
	want := len(blocks)
	short := 0
	for key, count := range union {
		if count == want {
			continue
		}
		// A key that appears more often than the catalogue count is a duplicate within
		// one catalogue, which is its own defect and is reported separately.
		if count > want {
			t.Errorf("translation key %q appears %d times across %d catalogues, so one catalogue defines it twice", key, count, want)
			continue
		}
		short++
		if short <= 20 {
			t.Errorf("translation key %q appears in %d of %d catalogues", key, count, want)
		}
	}
	if short > 20 {
		t.Errorf("... and %d further keys are missing from at least one catalogue", short-20)
	}
}

// splitCatalogueBlocks separates the four language objects by their opening declaration.
// The module declares them as `de: {`, `en: {`, `ru: {` and `'zh-CN': {`.
func splitCatalogueBlocks(t *testing.T, catalogue string) []string {
	t.Helper()
	marks := []string{`"de": {`, `"en": {`, `"ru": {`, `"zh-CN": {`}
	indices := make([]int, 0, len(marks))
	for _, mark := range marks {
		index := strings.Index(catalogue, mark)
		if index < 0 {
			t.Fatalf("catalogue block %q not found; the language set changed", mark)
		}
		indices = append(indices, index)
	}
	// The marks are declared in order, so each block runs to the next mark.
	for i := 1; i < len(indices); i++ {
		if indices[i] <= indices[i-1] {
			t.Fatalf("catalogue blocks are not in declaration order: %v", indices)
		}
	}
	blocks := make([]string, 0, len(indices))
	for i, start := range indices {
		end := len(catalogue)
		if i+1 < len(indices) {
			end = indices[i+1]
		}
		block := catalogue[start:end]
		// Skip the declaration itself (`"de": {`), otherwise the language name is
		// scanned as though it were a translation key and reported as missing from the
		// other three catalogues.
		if brace := strings.Index(block, "{"); brace >= 0 {
			block = block[brace+1:]
		}
		blocks = append(blocks, block)
	}
	return blocks
}

// TestAuthSurfaceIsComposedFromTwoPlanes pins the authentication composition. The split
// is not styling: one plane states what the host can attest before any credential
// exists and the other holds the single action. It is asserted because a later edit
// would naturally collapse it back into a centred card, which is the pattern this
// surface was rebuilt to leave behind.
func TestAuthSurfaceIsComposedFromTwoPlanes(t *testing.T) {
	document := embeddedWebFile(t, "index.html")

	if !strings.Contains(document, `class="auth-plane"`) {
		t.Fatal("the authentication surface is no longer composed from two planes")
	}
	for _, required := range []string{
		`id="authNode"`, `id="authChannel"`, `id="authState"`,
		`id="authForm"`, `id="tokenInput"`, `id="saveToken"`,
	} {
		if !strings.Contains(document, required) {
			t.Fatalf("the authentication surface lost %s", required)
		}
	}

	// The state line must be a live region, otherwise a rejected key is announced only
	// visually and the operator is left believing the session was authorised.
	statePattern := regexp.MustCompile(`id="authState"[^>]*aria-live="polite"`)
	if !statePattern.MatchString(document) {
		t.Fatal("the authentication state line is no longer an aria-live region")
	}

	// One primary action. A second button of equal weight splits the focus budget on a
	// surface that has exactly one job.
	if strings.Contains(document, `id="saveToken" class="button button-primary auth-submit"`) == false {
		t.Fatal("the primary authentication action changed shape")
	}
}

// TestAuthorizationIsVerifiedBeforeItIsClaimed proves the dashboard does not report an
// authorised session it has not checked. The earlier flow stored the key, closed the
// dialog and showed a success toast without contacting the control plane, so a wrong
// key produced a confirmation and a locked dashboard.
func TestAuthorizationIsVerifiedBeforeItIsClaimed(t *testing.T) {
	source := embeddedWebFile(t, "app.js")

	start := strings.Index(source, "async function authorizeSession()")
	if start < 0 {
		t.Fatal("the session authorization function is gone")
	}
	end := strings.Index(source[start:], "\n}")
	if end < 0 {
		t.Fatal("the session authorization function is unterminated")
	}
	body := source[start : start+end]

	// The provisional key must be exercised against a protected endpoint before the
	// dialog closes.
	verify := strings.Index(body, "await getStatus()")
	close := strings.Index(body, "authDialog')?.close()")
	if verify < 0 {
		t.Fatal("the authorization flow no longer verifies the key against the control plane")
	}
	if close < 0 {
		t.Fatal("the authorization flow no longer closes the dialog")
	}
	if verify > close {
		t.Fatal("the dialog closes before the key has been verified")
	}
	// A refusal must restore the previous key rather than leave the rejected one in
	// place, and must keep the dialog open with a stated reason.
	for _, required := range []string{"setToken(previous)", "'rejected'", "'unreachable'"} {
		if !strings.Contains(body, required) {
			t.Fatalf("the authorization flow no longer handles %s", required)
		}
	}
	// An empty submission must be refused locally rather than sent.
	if !strings.Contains(body, "auth.empty") {
		t.Fatal("an empty key is no longer refused before the request")
	}
}
