// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"mime/multipart"
	"strings"
	"testing"
)

func phpProgressMultipartBody(t *testing.T, progressField string, withFile bool) (string, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if progressField != "" {
		if err := writer.WriteField(progressField, "a1b2c3"); err != nil {
			t.Fatal(err)
		}
	}
	if withFile {
		part, err := writer.CreateFormFile("file", "report.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.String(), writer.FormDataContentType()
}

func phpProgressRequest(t *testing.T, body, contentType string) L7InspectionRequest {
	t.Helper()
	req := l7Request("/upload.php")
	req.Method = "POST"
	req.Headers = []L7Header{{Name: "Content-Type", Value: contentType}}
	req.BodyBase64 = base64.StdEncoding.EncodeToString([]byte(body))
	return req
}

// The suspected exploit path of the PHP upload-progress vulnerability is the session
// upload-progress handler itself, which runs before auto_prepend_file. The L7 edge can only
// protect that path if it recognises the trigger field before PHP sees it.
func TestL7DetectsPHPSessionUploadProgressField(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, contentType := phpProgressMultipartBody(t, "PHP_SESSION_UPLOAD_PROGRESS", true)
	response, err := engine.Inspect(context.Background(), phpProgressRequest(t, body, contentType))
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(response.Findings, "L7.PHP.SESSION_UPLOAD_PROGRESS") {
		t.Fatalf("expected upload-progress finding, got %#v", response.Findings)
	}
	// The rule is administrable like every other built-in rule.
	if !l7RuleOverrideIDAllowed("L7.PHP.SESSION_UPLOAD_PROGRESS") {
		t.Fatal("the upload-progress rule is not part of the administrable rule set")
	}
}

func TestL7UploadProgressFieldIsCaseInsensitiveAndOnce(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, name := range []string{"php_session_upload_progress", "PHP_SESSION_UPLOAD_PROGRESS[]"} {
		if err := writer.WriteField(name, "x"); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	response, err := engine.Inspect(context.Background(), phpProgressRequest(t, body.String(), writer.FormDataContentType()))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, finding := range response.Findings {
		if finding.RuleID == "L7.PHP.SESSION_UPLOAD_PROGRESS" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one upload-progress finding per request, got %d", count)
	}
}

func TestL7OrdinaryUploadDoesNotRaiseUploadProgressFinding(t *testing.T) {
	engine, err := NewL7Engine(l7TestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, contentType := phpProgressMultipartBody(t, "", true)
	response, err := engine.Inspect(context.Background(), phpProgressRequest(t, body, contentType))
	if err != nil {
		t.Fatal(err)
	}
	if findingByID(response.Findings, "L7.PHP.SESSION_UPLOAD_PROGRESS") {
		t.Fatalf("ordinary upload raised a false upload-progress finding: %#v", response.Findings)
	}
}

func TestL7UploadProgressFindingIsHighSeverity(t *testing.T) {
	detector := &l7UploadDetector{}
	body, contentType := phpProgressMultipartBody(t, "PHP_SESSION_UPLOAD_PROGRESS", true)
	req := phpProgressRequest(t, body, contentType)
	cfg := l7TestConfig()
	normalized, err := NewL7Normalizer(cfg).Normalize(req)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := detector.Detect(context.Background(), normalized, buildL7RuntimeSnapshot(defaultL7FabricSettings(cfg), 0))
	if err != nil {
		t.Fatal(err)
	}
	var found *L7Finding
	for index := range findings {
		if findings[index].RuleID == "L7.PHP.SESSION_UPLOAD_PROGRESS" {
			found = &findings[index]
		}
	}
	if found == nil {
		t.Fatalf("expected upload-progress finding, got %#v", findings)
	}
	if found.Category != "php-upload-progress" || found.Severity != "critical" || found.Score < 100 {
		t.Fatalf("unexpected upload-progress severity: %#v", *found)
	}
	if !strings.Contains(found.Summary, "before application code") {
		t.Fatalf("the finding must explain why application code cannot see it: %q", found.Summary)
	}
}

// The rule must appear in the administrable catalogue with its real metadata, not as an empty
// disabled entry: an operator tunes it from the same surface as every other built-in rule.
func TestUploadProgressRuleIsDescribedInTheRuleRegistry(t *testing.T) {
	for _, entry := range describeL7RuleCatalog() {
		if entry.ID != "L7.PHP.SESSION_UPLOAD_PROGRESS" {
			continue
		}
		if !entry.Administrable || !entry.Enabled || entry.Category != "php-upload-progress" || entry.Score < 100 {
			t.Fatalf("unexpected rule catalogue entry: %#v", entry)
		}
		return
	}
	t.Fatal("the upload-progress rule is missing from the administrable rule catalogue")
}
