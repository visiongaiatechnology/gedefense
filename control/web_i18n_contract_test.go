// STATUS: DIAMANT VGT SUPREME
package main

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Translation coverage.
//
// Twice a view was built with data-i18n attributes whose keys were never added to the
// catalogues, and once every language variant of fifty-eight keys was written into the
// German catalogue alone. Nothing failed: the build was clean, the modules loaded, and an
// operator reading English, Russian or Chinese saw raw key identifiers where labels
// should be.
//
// The test that was supposed to catch the second case did not, and the reason is worth
// recording. It counted occurrences of each key across the whole file and compared that
// total with the number of catalogues. A key written four times into one catalogue
// therefore counted four, matched the expectation, and passed - the check was measuring
// the file while claiming to measure the catalogues. Coverage is a per-catalogue property
// and is now tested as one.

var (
	webTranslationAttributePattern = regexp.MustCompile(`data-i18n(?:-placeholder|-aria-label|-title)?="([^"]+)"`)
	// t('key'), t("key") and t(`key`) at a call site.
	webTranslationCallPattern = regexp.MustCompile("\\bt\\(\\s*['\"`]([A-Za-z0-9_.]+)['\"`]")
	webTranslationKeyPattern  = regexp.MustCompile(`"([A-Za-z0-9_.]+)":`)
)

// catalogueBlocks splits the module into one entry per language, preserving the declared
// order. Splitting on line positions keeps a key whose value happens to mention another
// language from being mistaken for a catalogue boundary.
func catalogueBlocks(t *testing.T) ([]string, []string) {
	t.Helper()
	source := embeddedWebFile(t, "i18n.js")
	lines := strings.Split(source, "\n")

	names := []string{"de", "en", "ru", "zh-CN"}
	starts := make([]int, len(names))
	for index, name := range names {
		marker := `"` + name + `": {`
		starts[index] = -1
		for line, content := range lines {
			if strings.TrimSpace(content) == marker {
				starts[index] = line
				break
			}
		}
		if starts[index] < 0 {
			t.Fatalf("catalogue %q was not found; the language set changed", name)
		}
	}
	for index := 1; index < len(starts); index++ {
		if starts[index] <= starts[index-1] {
			t.Fatalf("catalogues are not in declaration order: %v", starts)
		}
	}

	blocks := make([]string, 0, len(names))
	for index, start := range starts {
		end := len(lines)
		if index+1 < len(starts) {
			end = starts[index+1]
		}
		blocks = append(blocks, strings.Join(lines[start+1:end], "\n"))
	}
	return names, blocks
}

// catalogueKeys returns the keys each catalogue defines, together with any key a single
// catalogue defines more than once. Both are per-catalogue facts.
func catalogueKeys(t *testing.T) ([]string, []map[string]bool, map[string][]string) {
	t.Helper()
	names, blocks := catalogueBlocks(t)
	sets := make([]map[string]bool, len(blocks))
	duplicates := map[string][]string{}
	for index, block := range blocks {
		set := map[string]bool{}
		for _, match := range webTranslationKeyPattern.FindAllStringSubmatch(block, -1) {
			key := match[1]
			if set[key] {
				duplicates[key] = append(duplicates[key], names[index])
				continue
			}
			set[key] = true
		}
		sets[index] = set
	}
	return names, sets, duplicates
}

// TestEveryCatalogueDefinesTheSameKeys is the check that was missing. A key present in one
// catalogue and absent from another renders as a raw identifier for whoever reads that
// language, which looks like a broken product rather than a missing string.
func TestEveryCatalogueDefinesTheSameKeys(t *testing.T) {
	names, sets, duplicates := catalogueKeys(t)

	for key, in := range duplicates {
		t.Errorf("key %q is defined more than once in catalogue(s) %v", key, in)
	}

	union := map[string]bool{}
	for _, set := range sets {
		for key := range set {
			union[key] = true
		}
	}
	if len(union) < 500 {
		t.Fatalf("only %d keys were found across the catalogues; the scan looks wrong", len(union))
	}

	missing := map[string][]string{}
	for key := range union {
		for index, set := range sets {
			if !set[key] {
				missing[key] = append(missing[key], names[index])
			}
		}
	}
	keys := make([]string, 0, len(missing))
	for key := range missing {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		t.Errorf("key %q is missing from catalogue(s) %s", key, strings.Join(missing[key], ", "))
	}
	if len(keys) > 0 {
		t.Errorf("%d keys are not present in every catalogue", len(keys))
	}
}

// TestEveryReferencedTranslationKeyExists covers both ways a key is asked for: the
// data-i18n attributes in the document and the t() calls in the modules. The earlier check
// looked only at attributes, so every key requested from JavaScript was unverified.
func TestEveryReferencedTranslationKeyExists(t *testing.T) {
	_, sets, _ := catalogueKeys(t)
	defined := sets[0]

	requests := map[string]string{}

	document := embeddedWebFile(t, "index.html")
	attributes := webTranslationAttributePattern.FindAllStringSubmatch(document, -1)
	if len(attributes) < 100 {
		t.Fatalf("only %d translation attributes were found; the scan looks wrong", len(attributes))
	}
	for _, match := range attributes {
		requests[match[1]] = "index.html"
	}

	calls := 0
	for _, name := range embeddedWebFiles(t) {
		if !strings.HasSuffix(name, ".js") || strings.Contains(name, "vendor/") {
			continue
		}
		for _, match := range webTranslationCallPattern.FindAllStringSubmatch(embeddedWebFile(t, name), -1) {
			calls++
			if _, exists := requests[match[1]]; !exists {
				requests[match[1]] = name
			}
		}
	}
	if calls < 200 {
		t.Fatalf("only %d translation calls were found; the scan looks wrong", calls)
	}

	keys := make([]string, 0, len(requests))
	for key := range requests {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !defined[key] {
			t.Errorf("%s requests translation key %q, which no catalogue defines", requests[key], key)
		}
	}
}

// TestAuthSurfaceIsComposedFromTwoPlanes pins the authentication composition. The split
// is not styling: one plane states what the host can attest before any credential exists
// and the other holds the single action.
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

	statePattern := regexp.MustCompile(`id="authState"[^>]*aria-live="polite"`)
	if !statePattern.MatchString(document) {
		t.Fatal("the authentication state line is no longer an aria-live region")
	}
	if !strings.Contains(document, `id="saveToken" class="button button-primary auth-submit"`) {
		t.Fatal("the primary authentication action changed shape")
	}
}

// TestAuthorizationIsVerifiedBeforeItIsClaimed proves the dashboard does not report an
// authorised session it has not checked. The earlier flow stored the key, closed the
// dialog and showed a success toast without contacting the control plane, so a wrong key
// produced a confirmation and a locked dashboard.
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
	for _, required := range []string{"setToken(previous)", "'rejected'", "'unreachable'", "auth.empty"} {
		if !strings.Contains(body, required) {
			t.Fatalf("the authorization flow no longer handles %s", required)
		}
	}
}

// TestNavigationIconsAreDistinctAndSemantic covers the sidebar. One entry carried the
// dollar-sign glyph and two carried the same shield, so the rail could not be read by
// shape at all - the one job an icon in a navigation rail has.
func TestNavigationIconsAreDistinctAndSemantic(t *testing.T) {
	document := embeddedWebFile(t, "index.html")

	iconPattern := regexp.MustCompile(`<svg viewBox="0 0 24 24" class="nav-icon-svg">(.*?)</svg>`)
	matches := iconPattern.FindAllStringSubmatch(document, -1)
	if len(matches) < 14 {
		t.Fatalf("only %d navigation icons were found; the scan looks wrong", len(matches))
	}

	seen := map[string]int{}
	for index, match := range matches {
		if previous, exists := seen[match[1]]; exists {
			t.Errorf("navigation icons at positions %d and %d are the same shape, so two destinations look identical", previous+1, index+1)
		}
		seen[match[1]] = index
	}

	// The dollar sign that named nothing, asserted by shape rather than by comment so a
	// later edit cannot quietly reintroduce it.
	if strings.Contains(document, "M12 2v20M17 5H9.5") {
		t.Error("the dollar-sign glyph is back in the navigation rail")
	}
}
