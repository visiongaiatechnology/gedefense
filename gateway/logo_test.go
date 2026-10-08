// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEmbeddedMarkIsServedAndIsARealPNG covers the route the login page depends on.
//
// The mark used to be drawn in CSS - a rotated square with a green dot - which is a
// placeholder rather than the product's identity. It is now embedded in the binary and
// served from a route, and both halves of that have to hold: the bytes must actually be a
// PNG, and the handler must answer with the type a browser will render. An image the
// browser refuses to decode is a broken mark on the one page every operator sees first.
func TestEmbeddedMarkIsServedAndIsARealPNG(t *testing.T) {
	if len(productLogo) == 0 {
		t.Fatal("the mark was not embedded; the build would serve an empty image")
	}
	decoded, err := png.Decode(bytes.NewReader(productLogo))
	if err != nil {
		t.Fatalf("the embedded mark is not a decodable PNG: %v", err)
	}
	bounds := decoded.Bounds()
	if bounds.Dx() < 64 || bounds.Dy() < 64 {
		t.Fatalf("the embedded mark is %dx%d, too small to render at the size the page uses", bounds.Dx(), bounds.Dy())
	}

	server := &gateway{}
	recorder := httptest.NewRecorder()
	server.logo(recorder, httptest.NewRequest(http.MethodGet, "/gateway/logo.png", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("the mark route answered %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("the mark was served as %q", got)
	}
	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("the mark was served without nosniff: %q", got)
	}
	if !bytes.Equal(recorder.Body.Bytes(), productLogo) {
		t.Fatal("the served bytes differ from the embedded mark")
	}

	// A conditional request costs a header round trip instead of the whole image.
	conditional := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/gateway/logo.png", nil)
	request.Header.Set("If-None-Match", recorder.Header().Get("ETag"))
	server.logo(conditional, request)
	if conditional.Code != http.StatusNotModified {
		t.Fatalf("a conditional request for an unchanged mark answered %d", conditional.Code)
	}
}

// TestLoginPageReferencesTheMarkAndAllowsIt pins both halves of the wiring: the document
// asks for the embedded route, and the policy permits an image at all.
//
// The gateway's policy is `default-src 'none'`, which forbids every fetch the page did not
// name. Serving the mark without adding img-src would have produced a blocked request and
// the same broken placeholder the CSS drawing was meant to replace - a defect that no
// amount of correct Go would have surfaced, because the image would have been served
// perfectly and simply never displayed.
func TestLoginPageReferencesTheMarkAndAllowsIt(t *testing.T) {
	server := &gateway{publicHost: "203.0.113.10:9843", sessionKey: []byte(strings.Repeat("s", 32))}
	request := httptest.NewRequest(http.MethodGet, "https://203.0.113.10:9843/login?lang=en", nil)
	request.Host = "203.0.113.10:9843"
	recorder := httptest.NewRecorder()
	server.loginPage(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("the login page answered %d", recorder.Code)
	}
	document := recorder.Body.String()
	if !strings.Contains(document, `src="/gateway/logo.png"`) {
		t.Fatal("the login page does not reference the embedded mark")
	}
	// The drawn placeholder must be gone, not merely covered by the image.
	if strings.Contains(document, "transform:rotate(45deg)") {
		t.Error("the CSS-drawn placeholder mark is still in the document")
	}

	policy := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, `img-src 'self'`) {
		t.Fatalf("the content policy does not permit the page's own image, so the mark would be blocked: %q", policy)
	}
	// The two directives that were already relied upon must survive the addition.
	if !strings.Contains(policy, "default-src 'none'") || !strings.Contains(policy, "style-src 'nonce-") {
		t.Fatalf("the policy lost a directive it already relied on: %q", policy)
	}
}
