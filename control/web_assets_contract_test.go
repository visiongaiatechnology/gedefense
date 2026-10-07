// STATUS: DIAMANT VGT SUPREME
package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The dashboard is a single ES module graph rooted at /assets/app.js. A missing
// allowlist entry therefore does not degrade one view: the root module fails to
// resolve and the entire operator console stays blank. These tests lock the
// served asset set to the actual embedded files and to the real import graph,
// so that failure mode cannot ship again.

// webModuleImportPattern matches every relative module specifier, with or without
// an extension and with either a single or a double dot. Vendored code is written
// the way a bundler expects it, so the pattern has to accept more than the
// project's own `./name.js` style, and imports that span several lines.
var webModuleImportPattern = regexp.MustCompile(`(?:from|import)\s*\(?\s*['"](\.[^'"]+)['"]`)

// webUnservedAssets are embedded for provenance but deliberately unreachable over
// the network. Any other embedded file must be served, which is what makes the
// allowlist exhaustive rather than a list somebody remembered to update.
var webUnservedAssets = map[string]bool{
	"vendor/jsvectormap/LICENSE":               true,
	"vendor/jsvectormap/README.md":             true,
	"vendor/jsvectormap/package.json.upstream": true,
	// `_variables.scss` is deliberately absent: go:embed excludes files whose name
	// begins with an underscore or a dot, so it is never in the binary and cannot be
	// declared unserved here - the test would fail trying to read it. The compiled
	// stylesheet derived from it is what ships.
	"vendor/jsvectormap/scss/jsvectormap.scss": true,
	"vendor/jsvectormap/maps/LICENSE":          true,
}

// embeddedWebFiles walks the whole embedded tree, because the dashboard now carries
// a vendored library in subdirectories.
func embeddedWebFilesRecursive(t *testing.T) []string {
	t.Helper()
	names := []string{}
	err := fs.WalkDir(webAssets, "web", func(entry string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		names = append(names, strings.TrimPrefix(strings.TrimPrefix(entry, "web/"), "/"))
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded web tree: %v", err)
	}
	sort.Strings(names)
	return names
}

func embeddedWebFiles(t *testing.T) []string {
	t.Helper()
	entries, err := fs.ReadDir(webAssets, "web")
	if err != nil {
		t.Fatalf("read embedded web directory: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

// TestEmbeddedWebAssetsAreExactlyAllowlisted makes the allowlist exhaustive in both
// directions: every embedded file is either served or explicitly declared unserved,
// and every served entry exists.
func TestEmbeddedWebAssetsAreExactlyAllowlisted(t *testing.T) {
	files := embeddedWebFilesRecursive(t)
	missing := make([]string, 0)
	for _, name := range files {
		if name == "index.html" {
			// The document itself is served by the index handler, not /assets/.
			continue
		}
		if webUnservedAssets[name] {
			if webAssetAllowlist[name] {
				t.Fatalf("%s is declared unserved but is in the serve allowlist", name)
			}
			continue
		}
		if !webAssetAllowlist[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("embedded dashboard assets are neither served nor declared unserved: %v", missing)
	}
	for name := range webAssetAllowlist {
		if _, err := webAssets.ReadFile("web/" + name); err != nil {
			t.Fatalf("allowlisted asset %s has no embedded file: %v", name, err)
		}
	}
	for name := range webUnservedAssets {
		if _, err := webAssets.ReadFile("web/" + name); err != nil {
			t.Fatalf("declared-unserved asset %s is not embedded: %v", name, err)
		}
	}
}

// TestAssetResolutionRejectsTraversalAndUnknownNames covers the resolution shim.
// The shim exists because vendored code imports extensionless specifiers, and it
// must not become a way to reach a file the allowlist does not expose.
func TestAssetResolutionRejectsTraversalAndUnknownNames(t *testing.T) {
	cfg := defaultConfig()
	server := NewAPIServer(cfg, NewState("test", cfg), nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")

	for _, name := range []string{
		"..%2fapp.js", "../app.js", "app.js/../../etc/passwd", "/etc/passwd",
		"vendor/jsvectormap/js/../../../app.js", "vendor\\jsvectormap\\js\\map.js",
		"", "app.js\x00", "vendor/jsvectormap/js/./map.js",
		"vendor/jsvectormap/js/does-not-exist.js", "vendor/jsvectormap/LICENSE",
		"vendor/jsvectormap/README.md", "vendor/jsvectormap/scss/jsvectormap.scss",
	} {
		if got, redirect := resolveWebAsset(name); got != "" || redirect != "" {
			t.Errorf("asset name %q resolved to %q", name, got)
		}
	}

	// The shim serves exactly the three documented forms.
	if got, _ := resolveWebAsset("app.js"); got != "app.js" {
		t.Fatalf("plain asset did not resolve: %q", got)
	}
	if got, _ := resolveWebAsset("vendor/jsvectormap/js/core/coordsToPoint"); got != "vendor/jsvectormap/js/core/coordsToPoint.js" {
		t.Fatalf("extensionless module did not resolve: %q", got)
	}
	if got, redirect := resolveWebAsset("vendor/jsvectormap/js/util"); got != "" || redirect != "vendor/jsvectormap/js/util/" {
		t.Fatalf("directory module did not resolve: %q", got)
	}

	// A traversal attempt must not reach the handler successfully either.
	for _, target := range []string{
		"/assets/../index.html", "/assets/vendor/jsvectormap/LICENSE",
		"/assets/vendor/jsvectormap/js/../../../../etc/hostname",
	} {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+target, nil)
		req.Host = "127.0.0.1"
		server.http.Handler.ServeHTTP(recorder, req)
		if recorder.Code == http.StatusOK {
			t.Errorf("%s was served with status 200", target)
		}
	}
}

func TestEveryDashboardModuleReachableAndServed(t *testing.T) {
	cfg := defaultConfig()
	server := NewAPIServer(cfg, NewState("test", cfg), nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")

	// Resolve the static module graph starting at the document root module. Each
	// specifier is resolved the way the browser would resolve it - relative to the
	// importing module - and then through the same shim the asset handler uses, so
	// the test cannot pass while the served graph is broken.
	resolved := map[string]bool{}
	queue := []string{"app.js"}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if resolved[current] {
			continue
		}
		resolved[current] = true
		body, err := webAssets.ReadFile("web/" + current)
		if err != nil {
			t.Fatalf("module %s is imported but not embedded: %v", current, err)
		}
		for _, match := range webModuleImportPattern.FindAllStringSubmatch(string(body), -1) {
			specifier := match[1]
			if specifier == "" {
				continue
			}
			requested := path.Join(path.Dir(current), specifier)
			target, redirect := resolveWebAsset(requested)
			if redirect != "" {
				// A directory import. The browser receives a redirect to the
				// trailing-slash URL and then resolves that module's own relative
				// imports against the directory, so the walk has to key the module as
				// <dir>/index.js and continue from there. Resolving the directory to
				// its index file without the redirect is what made the earlier version
				// of this walk pass while the browser saw 404s.
				target = redirect + "index.js"
			}
			if target == "" {
				t.Fatalf("module %s imports %s (resolved to %s) which the asset allowlist does not serve", current, specifier, requested)
			}
			queue = append(queue, target)
		}
	}
	for _, required := range []string{
		"fabric-settings.js", "fabric-surface.js", "geo-map.js",
		"vendor/jsvectormap/js/index.js", "vendor/jsvectormap/maps/world-merc.js",
	} {
		if !resolved[required] {
			t.Fatalf("the dashboard module graph no longer reaches %s", required)
		}
	}

	// Every resolved module must actually be served with a JavaScript type.
	for name := range resolved {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/assets/"+name, nil)
		req.Host = "127.0.0.1"
		server.http.Handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("module %s status=%d want=200", name, recorder.Code)
		}
		if got := recorder.Header().Get("Content-Type"); got != "text/javascript; charset=utf-8" {
			t.Fatalf("module %s content-type=%q", name, got)
		}
		if recorder.Body.Len() == 0 {
			t.Fatalf("module %s served an empty body", name)
		}
	}
}

// TestVendoredLibraryStaysLocalAndTrustedTypesClean locks the two properties that
// made this integration acceptable at all: nothing in the vendored tree reaches the
// network, and the single Trusted Types sink is unreachable in our configuration.
func TestVendoredLibraryStaysLocalAndTrustedTypesClean(t *testing.T) {
	files := embeddedWebFilesRecursive(t)
	namespaceURIs := map[string]bool{
		"http://www.w3.org/2000/svg":   true,
		"http://www.w3.org/1999/xlink": true,
	}
	networkPattern := regexp.MustCompile(`(?i)\b(fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(|\.src\s*=\s*['"]https?:|importScripts|new\s+Worker`)
	sinks := map[string]int{}
	for _, name := range files {
		if !strings.HasPrefix(name, "vendor/jsvectormap/") || !strings.HasSuffix(name, ".js") {
			continue
		}
		body, err := webAssets.ReadFile("web/" + name)
		if err != nil {
			t.Fatal(err)
		}
		source := string(body)
		if match := networkPattern.FindString(source); match != "" {
			t.Errorf("%s performs a network operation: %q", name, match)
		}
		for _, match := range regexp.MustCompile(`https?://[^"'\s)]+`).FindAllString(source, -1) {
			if namespaceURIs[match] {
				continue
			}
			// Anything else must be a comment, which is how attribution is recorded.
			for _, line := range strings.Split(source, "\n") {
				if !strings.Contains(line, match) {
					continue
				}
				if !strings.Contains(strings.TrimSpace(line), "//") {
					t.Errorf("%s references %s outside a comment", name, match)
				}
			}
		}
		// The token is counted without a leading dot on purpose: both sites in the
		// vendored tree use bracket notation (`el[html ? 'innerHTML' : 'textContent']`),
		// so an assignment-shaped pattern would count zero and quietly assert nothing.
		sinks[name] += strings.Count(source, "innerHTML")
	}

	// The sink inventory is pinned: one file, two sites, both behind `html = true`.
	totalSinks := 0
	for _, count := range sinks {
		totalSinks += count
	}
	if totalSinks != 2 {
		t.Fatalf("the vendored tree no longer contains exactly two innerHTML sites: %d", totalSinks)
	}
	if sinks["vendor/jsvectormap/js/util/index.js"] != 1 || sinks["vendor/jsvectormap/js/components/tooltip.js"] != 1 {
		t.Fatalf("the innerHTML sites moved: %v", sinks)
	}

	// The only caller that passes `html = true` is the zoom button factory, and our
	// configuration supplies both buttons, which selects the branch that does not.
	zoom, err := webAssets.ReadFile("web/vendor/jsvectormap/js/core/setupZoomButtons.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(zoom), ", true)") {
		t.Fatal("the zoom button factory no longer creates its fallback element with html=true")
	}
	adapter, err := webAssets.ReadFile("web/geo-map.js")
	if err != nil {
		t.Fatal(err)
	}
	adapterSource := string(adapter)
	for _, required := range []string{
		"zoomInButton: ZOOM_IN_SELECTOR",
		"zoomOutButton: ZOOM_OUT_SELECTOR",
		"if (!byId('kineticGeoZoomIn') || !byId('kineticGeoZoomOut')) return null",
	} {
		if !strings.Contains(adapterSource, required) {
			t.Fatalf("the map adapter no longer satisfies the Trusted Types condition: %q", required)
		}
	}
	// Our own modules must stay free of every sink, comments aside.
	ownSinkPattern := regexp.MustCompile(`\.innerHTML\s*=|\.outerHTML\s*=|document\.write\(|insertAdjacentHTML|\beval\(|new Function`)
	for _, name := range files {
		if strings.HasPrefix(name, "vendor/") || !strings.HasSuffix(name, ".js") {
			continue
		}
		body, _ := webAssets.ReadFile("web/" + name)
		if match := ownSinkPattern.FindString(string(body)); match != "" {
			t.Errorf("%s uses a DOM sink: %q", name, match)
		}
	}
}

func TestDashboardIndexEntryPointIsTheModuleGraphRoot(t *testing.T) {
	document, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(document)
	if !strings.Contains(html, `src="/assets/app.js"`) {
		t.Fatal("index.html no longer loads the dashboard module graph root")
	}
	if strings.Count(html, "<script") != 1 {
		t.Fatalf("index.html must load exactly one module entry point, found %d script tags", strings.Count(html, "<script"))
	}
}

// webElementReferencePattern matches the three ways the dashboard modules look up
// an element by a literal id. Dynamically composed ids (the settings workbench
// builds "fabric-<module>-<key>") never match a literal, so this only asserts the
// references that must resolve against the served document.
var webElementReferencePattern = regexp.MustCompile(`(?:getElementById\(|byID\(|\btext\()\s*'([A-Za-z0-9_-]+)'`)

// TestWebModuleElementReferencesResolve locks every literal element reference in
// the dashboard modules to an element that the served document actually contains.
// Restructuring a view is normal; leaving a module writing into an element that no
// longer exists is not, and it fails silently in the browser.
func TestWebModuleElementReferencesResolve(t *testing.T) {
	document := embeddedWebFile(t, "index.html")
	known := map[string]bool{}
	for _, match := range regexp.MustCompile(`id="([A-Za-z0-9_-]+)"`).FindAllStringSubmatch(document, -1) {
		known[match[1]] = true
	}
	if len(known) < 100 {
		t.Fatalf("the served document exposes only %d element ids; the fixture looks wrong", len(known))
	}

	unresolved := map[string][]string{}
	references := 0
	for _, name := range embeddedWebFiles(t) {
		if !strings.HasSuffix(name, ".js") {
			continue
		}
		source := embeddedWebFile(t, name)
		for _, match := range webElementReferencePattern.FindAllStringSubmatch(source, -1) {
			references++
			if known[match[1]] {
				continue
			}
			unresolved[match[1]] = append(unresolved[match[1]], name)
		}
	}
	if references < 100 {
		t.Fatalf("only %d element references were found; the scan looks wrong", references)
	}
	for id, modules := range unresolved {
		t.Errorf("id %q is referenced by %s but does not exist in index.html", id, strings.Join(modules, ", "))
	}
}

// TestDirectoryImportRedirectsToATrailingSlash pins the fix for a defect that only a
// real browser could surface. Module resolution is URL-based: answering a request for
// `.../js/core` with the bytes of `core/index.js` makes the browser resolve that
// module's own relative imports against `.../js/core` as if it were a file, so it
// requests `.../js/setupContainerEvents` and the whole vendored tree fails to load.
// The directory form must redirect to the trailing slash instead.
func TestDirectoryImportRedirectsToATrailingSlash(t *testing.T) {
	cfg := defaultConfig()
	server := NewAPIServer(cfg, NewState("test", cfg), nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")

	// The bare directory must redirect, and must not serve bytes.
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/assets/vendor/jsvectormap/js/core", nil)
	request.Host = "127.0.0.1"
	server.http.Handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMovedPermanently {
		t.Fatalf("a directory import answered with %d, want 301", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != "/assets/vendor/jsvectormap/js/core/" {
		t.Fatalf("redirect target %q does not preserve the directory form", location)
	}
	// http.Redirect writes a short HTML stub for GET requests; that is standard and
	// harmless. What must not happen is the module bytes being served under the
	// directory URL, which is the defect this test exists for.
	body := recorder.Body.String()
	if strings.Contains(body, "export") || strings.Contains(body, "import") || len(body) > 512 {
		t.Fatalf("the redirect response carried module content: %d bytes", len(body))
	}

	// The trailing-slash form must serve the index module as JavaScript.
	served := httptest.NewRecorder()
	indexed := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/assets/vendor/jsvectormap/js/core/", nil)
	indexed.Host = "127.0.0.1"
	server.http.Handler.ServeHTTP(served, indexed)
	if served.Code != http.StatusOK {
		t.Fatalf("the trailing-slash form answered with %d", served.Code)
	}
	if got := served.Header().Get("Content-Type"); got != "text/javascript; charset=utf-8" {
		t.Fatalf("the index module was served as %q", got)
	}
	if served.Body.Len() == 0 {
		t.Fatal("the index module was served empty")
	}

	// A file request must not redirect: only a directory index does.
	direct := httptest.NewRecorder()
	fileRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/assets/app.js", nil)
	fileRequest.Host = "127.0.0.1"
	server.http.Handler.ServeHTTP(direct, fileRequest)
	if direct.Code != http.StatusOK {
		t.Fatalf("a plain module request answered with %d", direct.Code)
	}

	// The redirect must not become a way to reach anything the allowlist hides.
	for _, target := range []string{
		"/assets/vendor/jsvectormap/scss/", "/assets/vendor/jsvectormap/",
		"/assets/vendor/", "/assets/",
	} {
		probe := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+target, nil)
		req.Host = "127.0.0.1"
		server.http.Handler.ServeHTTP(probe, req)
		if probe.Code == http.StatusOK {
			t.Errorf("%s was served with 200", target)
		}
	}
}
