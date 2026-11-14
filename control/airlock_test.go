// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestAirlock_ActiveContentUploadsAreDetected(t *testing.T) {
	tempDir := t.TempDir()
	inspector, _ := NewAirlockInspector(tempDir, 10<<20)

	// F-11 / CHAIN-010 regression corpus: every one of these was reported clean
	// by the historical detector.
	cases := []struct {
		name     string
		content  []byte
		expected string
	}{
		{"shell.php", []byte("#!/usr/bin/env bash\nid\n"), "SCRIPT_SHEBANG_PAYLOAD"},
		{"drop.phtml", []byte("#!/usr/bin/env python3\nprint('x')\n"), "SCRIPT_SHEBANG_PAYLOAD"},
		{"avatar.html", []byte(`<html><body><img src=x onerror=alert(1)></body></html>`), "HTML_ACTIVE_CONTENT"},
		{"page.htm", []byte(`<html><body onload="alert(1)"></body></html>`), "HTML_ACTIVE_CONTENT"},
		{"logo.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><set attributeName="onload" to="alert(1)"/></svg>`), "SVG_ACTIVE_CONTENT"},
		{"icon.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><use href="data:image/svg+xml;base64,PHN2Zz4="/></svg>`), "SVG_ACTIVE_CONTENT"},
	}
	for _, testCase := range cases {
		result, err := inspector.InspectBytes(testCase.name, testCase.content)
		if err == nil || result == nil || result.IsClean {
			t.Fatalf("%s: active content reported clean (err=%v result=%+v)", testCase.name, err, result)
		}
		if result.ThreatType != testCase.expected {
			t.Fatalf("%s: threat type=%q, want %q", testCase.name, result.ThreatType, testCase.expected)
		}
	}

	// SVG XXE remains covered.
	xxeSVG := []byte("<?xml version=\"1.0\"?>\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<svg>&xxe;</svg>")
	if _, err := inspector.InspectBytes("vector.svg", xxeSVG); err == nil {
		t.Fatal("SVG XXE was not blocked")
	}

	// Benign images must stay clean.
	validPNG := make([]byte, 32)
	copy(validPNG, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	if result, err := inspector.InspectBytes("photo.png", validPNG); err != nil || result == nil || !result.IsClean {
		t.Fatalf("benign PNG rejected: %v %+v", err, result)
	}
}

func TestAirlock_MIMEActiveContentMismatch(t *testing.T) {
	inspector, _ := NewAirlockInspector(t.TempDir(), 10<<20)
	svgPayload := []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>")
	if result, err := inspector.InspectBytes("innocent.png", svgPayload); err == nil || result == nil || result.IsClean {
		t.Fatalf("SVG payload disguised as PNG reported clean: %v %+v", err, result)
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

// ---------------------------------------------------------------------------
// FIND-024: the on-disk inspection is bound to the staging root, refuses
// symbolic links and scans beyond the historical 64 KiB sample.
// ---------------------------------------------------------------------------

func TestAirlock_InspectFileRejectsPathsOutsideStagingRoot(t *testing.T) {
	root := t.TempDir()
	inspector, err := NewAirlockInspector(root, 10<<20)
	if err != nil {
		t.Fatal(err)
	}

	// Absolute host paths must never be inspected, even when they exist.
	for _, outside := range []string{"/etc/hostname", "/etc/passwd", "/etc/shadow"} {
		_, insErr := inspector.InspectFile(outside)
		var boundaryErr *AirlockBoundaryException
		if !errors.As(insErr, &boundaryErr) {
			t.Fatalf("%s: expected AirlockBoundaryException, got %v", outside, insErr)
		}
	}

	// Traversal out of the root is collapsed by filepath.Clean and rejected.
	traversal := filepath.Join(root, "..", "..", "etc", "hostname")
	if _, insErr := inspector.InspectFile(traversal); insErr == nil {
		t.Fatal("traversal path outside the staging root was inspected")
	} else {
		var boundaryErr *AirlockBoundaryException
		if !errors.As(insErr, &boundaryErr) {
			t.Fatalf("traversal: expected AirlockBoundaryException, got %T %v", insErr, insErr)
		}
	}

	// A path inside the root is accepted, both absolute and relative.
	inside := filepath.Join(root, "sample.png")
	png := append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, bytes.Repeat([]byte{0x00}, 64)...)
	if writeErr := os.WriteFile(inside, png, 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}
	if result, insErr := inspector.InspectFile(inside); insErr != nil || result == nil || !result.IsClean {
		t.Fatalf("absolute path inside root refused: %v %+v", insErr, result)
	}
	if result, insErr := inspector.InspectFile("sample.png"); insErr != nil || result == nil || !result.IsClean {
		t.Fatalf("relative path inside root refused: %v %+v", insErr, result)
	}
}

func TestAirlock_InspectFileRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	inspector, err := NewAirlockInspector(root, 10<<20)
	if err != nil {
		t.Fatal(err)
	}

	// A symlink to a host file inside the staging root must not be followed.
	link := filepath.Join(root, "passwd.png")
	if linkErr := os.Symlink("/etc/passwd", link); linkErr != nil {
		t.Fatalf("create symlink: %v", linkErr)
	}
	_, inspectErr := inspector.InspectFile(link)
	var boundaryErr *AirlockBoundaryException
	if !errors.As(inspectErr, &boundaryErr) {
		t.Fatalf("symlink target: expected AirlockBoundaryException, got %v", inspectErr)
	}

	// A symlinked parent directory is refused by the component-wise walk.
	outsideDir := t.TempDir()
	if writeErr := os.WriteFile(filepath.Join(outsideDir, "payload.png"), []byte("payload"), 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}
	parentLink := filepath.Join(root, "escape")
	if linkErr := os.Symlink(outsideDir, parentLink); linkErr != nil {
		t.Fatalf("create parent symlink: %v", linkErr)
	}
	if _, inspectErr := inspector.InspectFile(filepath.Join(parentLink, "payload.png")); inspectErr == nil {
		t.Fatal("inspection followed a symlinked parent directory")
	}
}

func TestAirlock_InspectFileScansBeyond64KiB(t *testing.T) {
	root := t.TempDir()
	inspector, err := NewAirlockInspector(root, 10<<20)
	if err != nil {
		t.Fatal(err)
	}

	const payloadOffset = 70000
	payload := []byte("<?php system($_GET['c']); ?>")
	data := make([]byte, payloadOffset+len(payload))
	copy(data, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	copy(data[payloadOffset:], payload)
	path := filepath.Join(root, "late-payload.png")
	if writeErr := os.WriteFile(path, data, 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}

	result, inspectErr := inspector.InspectFile(path)
	if inspectErr == nil {
		t.Fatal("payload after byte 65536 was reported clean")
	}
	if result == nil || result.IsClean || result.ThreatType != "POLYGLOT_SCRIPT_INJECTION" {
		t.Fatalf("payload after byte 65536 not classified: %+v", result)
	}

	// A marker that straddles a scan-chunk boundary is still observable through
	// the overlap window.
	split := make([]byte, 2*airlockScanChunkBytes+32)
	copy(split, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	marker := []byte("<?php system($_GET['c']); ?>")
	cut := airlockScanChunkBytes - 3
	copy(split[cut:], marker)
	splitPath := filepath.Join(root, "split-payload.png")
	if writeErr := os.WriteFile(splitPath, split, 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}
	if result, inspectErr := inspector.InspectFile(splitPath); inspectErr == nil || result == nil || result.IsClean {
		t.Fatalf("marker across a chunk boundary was reported clean: %v %+v", inspectErr, result)
	}
}

func TestAirlock_ScriptCapableExtensionsAreFlaggedTopLevel(t *testing.T) {
	inspector, err := NewAirlockInspector(t.TempDir(), 10<<20)
	if err != nil {
		t.Fatal(err)
	}

	// Benign bodies: only the declared extension makes these executable content.
	// They were reported clean before because the extension check lived in the
	// SVG-only branch.
	for _, filename := range []string{"shell.php", "drop.phtml", "cgi-bin.cgi", "tool.pl", "app.js", "module.mjs", "cmd.sh", "runner.py", "page.jsp", "legacy.asp", "page.aspx"} {
		result, inspectErr := inspector.InspectBytes(filename, []byte("plain benign text\n"))
		if inspectErr == nil {
			t.Fatalf("%s: script-capable upload was reported clean", filename)
		}
		if result == nil || result.ThreatType != "SCRIPT_CAPABLE_UPLOAD" {
			t.Fatalf("%s: threat type=%v, want SCRIPT_CAPABLE_UPLOAD (%+v)", filename, result, result)
		}
	}

	// Non-script extensions with harmless content stay clean.
	if result, inspectErr := inspector.InspectBytes("photo.txt", []byte("plain text\n")); inspectErr != nil || result == nil || !result.IsClean {
		t.Fatalf("benign text upload rejected: %v %+v", inspectErr, result)
	}

	// The shebang detection keeps precedence over the extension escalation.
	result, inspectErr := inspector.InspectBytes("shell.php", []byte("#!/bin/sh\nid\n"))
	if inspectErr == nil || result == nil || result.ThreatType != "SCRIPT_SHEBANG_PAYLOAD" {
		t.Fatalf("shebang precedence lost: %v %+v", inspectErr, result)
	}
}

func TestAirlock_InspectFileRejectsBeyondScanBudget(t *testing.T) {
	root := t.TempDir()
	inspector, err := NewAirlockInspector(root, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "large.bin")
	if writeErr := os.WriteFile(path, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}
	if truncErr := os.Truncate(path, airlockScanBudgetBytes+1); truncErr != nil {
		t.Fatal(truncErr)
	}
	_, inspectErr := inspector.InspectFile(path)
	if inspectErr == nil {
		t.Fatal("object beyond the deterministic scan budget was accepted")
	}
	var validationErr *AirlockValidationException
	if !errors.As(inspectErr, &validationErr) {
		t.Fatalf("expected AirlockValidationException for the scan budget, got %T %v", inspectErr, inspectErr)
	}
	if !strings.Contains(inspectErr.Error(), "content-scan budget") {
		t.Fatalf("scan budget rejection does not name its reason: %v", inspectErr)
	}
}
