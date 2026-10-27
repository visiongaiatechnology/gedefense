package main

import (
	"bytes"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedMascotIsServedAndIsARealPNG(t *testing.T) {
	if len(mascotImage) == 0 {
		t.Fatal("the mascot was not embedded; the login page would show a broken image")
	}
	decoded, err := png.Decode(bytes.NewReader(mascotImage))
	if err != nil {
		t.Fatalf("the embedded mascot is not a decodable PNG: %v", err)
	}
	bounds := decoded.Bounds()
	if bounds.Dx() < 300 || bounds.Dy() < 300 {
		t.Fatalf("the embedded mascot is %dx%d, too small for the login composition", bounds.Dx(), bounds.Dy())
	}

	server := &gateway{}
	recorder := httptest.NewRecorder()
	server.mascot(recorder, httptest.NewRequest(http.MethodGet, "/gateway/sirdu.png", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("the mascot route answered %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("the mascot was served as %q", got)
	}
	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("the mascot was served without nosniff: %q", got)
	}
	if !bytes.Equal(recorder.Body.Bytes(), mascotImage) {
		t.Fatal("the served bytes differ from the embedded mascot")
	}

	conditional := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/gateway/sirdu.png", nil)
	request.Header.Set("If-None-Match", recorder.Header().Get("ETag"))
	server.mascot(conditional, request)
	if conditional.Code != http.StatusNotModified {
		t.Fatalf("a conditional request for the unchanged mascot answered %d", conditional.Code)
	}
}

func TestLoginPageReferencesTheMascot(t *testing.T) {
	document := renderLoginForTest(t, "en", true, false)
	if !strings.Contains(document, `src="/gateway/sirdu.png"`) {
		t.Fatal("the login page does not reference the embedded mascot")
	}
	if !strings.Contains(document, "ENTENPRISE") {
		t.Fatal("the login page lost the Entenprise signature")
	}
}
