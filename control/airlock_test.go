// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAirlock_ValidPNG(t *testing.T) {
	tempDir := t.TempDir()
	inspector, err := NewAirlockInspector(tempDir, 10<<20)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	validPNG := filepath.Join(tempDir, "sample.png")
	data := append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, bytes.Repeat([]byte{0x00}, 64)...)
	if err := os.WriteFile(validPNG, data, 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	res, err := inspector.InspectFile(validPNG)
	if err != nil {
		t.Fatalf("expected valid PNG, got error: %v", err)
	}
	if !res.IsClean {
		t.Fatalf("expected clean result")
	}
	if res.DetectedMime != "image/png" {
		t.Fatalf("expected image/png, got %s", res.DetectedMime)
	}
}

func TestAirlock_DisguisedExecutable(t *testing.T) {
	tempDir := t.TempDir()
	inspector, _ := NewAirlockInspector(tempDir, 10<<20)

	disguised := filepath.Join(tempDir, "innocent.png")
	data := append([]byte{0x7F, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x90}, 128)...)
	_ = os.WriteFile(disguised, data, 0644)

	res, err := inspector.InspectFile(disguised)
	if err == nil {
		t.Fatal("expected error on disguised executable, got nil")
	}
	if res.IsClean {
		t.Fatal("expected IsClean=false")
	}
	if res.ThreatType != "DISGUISED_EXECUTABLE_PAYLOAD" && res.ThreatType != "MIME_EXTENSION_MISMATCH" {
		t.Fatalf("unexpected threat type: %s", res.ThreatType)
	}
	var secErr *AirlockSecurityException
	if !errors.As(err, &secErr) {
		t.Fatalf("expected AirlockSecurityException, got %T", err)
	}
}

func TestAirlock_PolyglotScriptPayload(t *testing.T) {
	tempDir := t.TempDir()
	inspector, _ := NewAirlockInspector(tempDir, 10<<20)

	polyglot := filepath.Join(tempDir, "avatar.gif")
	data := []byte("GIF89a\x01\x00\x01\x00<?php system($_GET['c']); ?>")
	_ = os.WriteFile(polyglot, data, 0644)

	res, err := inspector.InspectFile(polyglot)
	if err == nil {
		t.Fatal("expected polyglot detection error, got nil")
	}
	if res.IsClean {
		t.Fatal("expected IsClean=false for polyglot")
	}
	if res.ThreatType != "POLYGLOT_SCRIPT_INJECTION" {
		t.Fatalf("expected POLYGLOT_SCRIPT_INJECTION, got %s", res.ThreatType)
	}
	var secErr *AirlockSecurityException
	if !errors.As(err, &secErr) {
		t.Fatalf("expected AirlockSecurityException, got %T", err)
	}
}

func TestAirlock_SVGSanitizationAndXXE(t *testing.T) {
	// 1. XXE detection
	tempDir := t.TempDir()
	inspector, _ := NewAirlockInspector(tempDir, 10<<20)

	xxeSVG := filepath.Join(tempDir, "vector.svg")
	xxeContent := `<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>`
	_ = os.WriteFile(xxeSVG, []byte(xxeContent), 0644)

	_, err := inspector.InspectFile(xxeSVG)
	if err == nil {
		t.Fatal("expected XXE blocked error")
	}

	// 2. SVG Sanitizer function
	maliciousSVG := []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert('pwn')"><script>evil()</script><circle r="10"/><a href="javascript:steal()"/></svg>`)
	cleaned, modified := SanitizeSVG(maliciousSVG)
	if !modified {
		t.Fatal("expected SVG to be modified during sanitization")
	}
	if bytes.Contains(cleaned, []byte("<script>")) {
		t.Fatal("script tag was not removed")
	}
	if bytes.Contains(cleaned, []byte("onload=")) {
		t.Fatal("onload attribute was not removed")
	}
	if bytes.Contains(cleaned, []byte("javascript:")) {
		t.Fatal("javascript: URI was not neutralized")
	}

	// 3. ForeignObject and iframe stripping
	svgWithForeign := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="100" height="100"><body xmlns="http://www.w3.org/1999/xhtml"><h1>Hello</h1></body></foreignObject><iframe src="https://evil.com"></iframe><rect width="50" height="50"/></svg>`)
	cleanedForeign, modForeign := SanitizeSVG(svgWithForeign)
	if !modForeign {
		t.Fatal("expected foreignObject SVG to be modified")
	}
	if bytes.Contains(cleanedForeign, []byte("foreignObject")) {
		t.Fatal("foreignObject element was not stripped")
	}
	if bytes.Contains(cleanedForeign, []byte("iframe")) {
		t.Fatal("iframe element was not stripped")
	}
	if !bytes.Contains(cleanedForeign, []byte("<rect width=\"50\" height=\"50\"/>")) {
		t.Fatal("legitimate rect element was lost")
	}
}

func TestAirlock_StageInJail(t *testing.T) {
	tempDir := t.TempDir()
	jailDir := filepath.Join(tempDir, "jail")
	_ = os.MkdirAll(jailDir, 0700)

	// Set a small max limit (100 bytes)
	inspector, _ := NewAirlockInspector(jailDir, 100)

	// 1. Safe payload within limit
	staged, err := inspector.StageInJail("upload.bin", bytes.NewReader([]byte("safe-payload")))
	if err != nil {
		t.Fatalf("stage in jail failed: %v", err)
	}

	fi, err := os.Stat(staged)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if fi.Size() != int64(len("safe-payload")) {
		t.Fatalf("unexpected size: %d", fi.Size())
	}

	// 2. Oversized payload exceeding maxFileSize boundary (Pattern 1.5.B)
	oversized := bytes.Repeat([]byte("A"), 105)
	_, err = inspector.StageInJail("oversized.bin", bytes.NewReader(oversized))
	if err == nil {
		t.Fatal("expected size boundary violation error for oversized payload, got nil")
	}
	var valErr *AirlockValidationException
	if !errors.As(err, &valErr) {
		t.Fatalf("expected AirlockValidationException, got %T", err)
	}
	if _, statErr := os.Stat(filepath.Join(jailDir, "oversized.bin")); !os.IsNotExist(statErr) {
		t.Fatal("expected oversized file to be deleted upon failure")
	}
}
