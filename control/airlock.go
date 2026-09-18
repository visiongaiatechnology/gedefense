// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Typed Airlock Error Hierarchy (Section 1.5.A Compliance)
type AirlockException struct {
	Message string
	Err     error
}

func (e *AirlockException) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *AirlockException) Unwrap() error { return e.Err }

type AirlockValidationException struct{ AirlockException }
type AirlockSecurityException struct{ AirlockException }
type AirlockStorageException struct{ AirlockException }

func NewAirlockValidationException(msg string, err error) *AirlockValidationException {
	return &AirlockValidationException{AirlockException{Message: msg, Err: err}}
}

func NewAirlockSecurityException(msg string, err error) *AirlockSecurityException {
	return &AirlockSecurityException{AirlockException{Message: msg, Err: err}}
}

func NewAirlockStorageException(msg string, err error) *AirlockStorageException {
	return &AirlockStorageException{AirlockException{Message: msg, Err: err}}
}

// Magic Byte Signatures
var (
	magicPNG     = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	magicJPEG    = []byte{0xFF, 0xD8, 0xFF}
	magicGIF87   = []byte("GIF87a")
	magicGIF89   = []byte("GIF89a")
	magicPDF     = []byte("%PDF-")
	magicZIP     = []byte{0x50, 0x4B, 0x03, 0x04}
	magicELF     = []byte{0x7F, 'E', 'L', 'F'}
	magicShebang = []byte("#!")
)

// Dangerous Script Pattern regexes for polyglot detection
var dangerousPolyglotPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<\?(?:php|=)?`),
	regexp.MustCompile(`(?i)<%`),
	regexp.MustCompile(`(?i)<script\b`),
	regexp.MustCompile(`(?i)\b(?:eval|exec|passthru|system|shell_exec|popen|proc_open)\s*\(`),
	regexp.MustCompile(`(?i)\bbase64_decode\s*\(`),
	regexp.MustCompile(`(?i)/bin/(?:ba|da|z|k)?sh\b`),
}

var svgDangerousAttrs = regexp.MustCompile(`(?i)\bon[a-z]+\s*=`)
var svgJavascriptURI = regexp.MustCompile(`(?i)(?:href|src)\s*=\s*["']?\s*(?:javascript|data:text/html|vbscript):`)
var svgXXEEntity = regexp.MustCompile(`(?i)<!(?:ENTITY|DOCTYPE|ELEMENT|ATTLIST)\b`)

type AirlockInspectionResult struct {
	IsClean           bool      `json:"is_clean"`
	DetectedMime      string    `json:"detected_mime"`
	DeclaredExtension string    `json:"declared_extension"`
	FileSize          int64     `json:"file_size"`
	SHA256            string    `json:"sha256"`
	RiskScore         int       `json:"risk_score"`
	ThreatType        string    `json:"threat_type,omitempty"`
	Sanitized         bool      `json:"sanitized"`
	Timestamp         time.Time `json:"timestamp"`
}

type AirlockInspector struct {
	mu            sync.RWMutex
	quarantineDir string
	maxFileSize   int64
}

func NewAirlockInspector(quarantineDir string, maxFileSize int64) (*AirlockInspector, error) {
	if maxFileSize <= 0 {
		maxFileSize = 100 << 20 // 100 MB limit
	}
	cleanDir := filepath.Clean(quarantineDir)
	return &AirlockInspector{
		quarantineDir: cleanDir,
		maxFileSize:   maxFileSize,
	}, nil
}

// DetectMagicType inspects the initial bytes to identify the true binary format.
func DetectMagicType(buf []byte) string {
	if len(buf) >= 8 && bytes.Equal(buf[:8], magicPNG) {
		return "image/png"
	}
	if len(buf) >= 3 && bytes.Equal(buf[:3], magicJPEG) {
		return "image/jpeg"
	}
	if len(buf) >= 6 && (bytes.Equal(buf[:6], magicGIF87) || bytes.Equal(buf[:6], magicGIF89)) {
		return "image/gif"
	}
	if len(buf) >= 12 && bytes.Equal(buf[:4], []byte("RIFF")) && bytes.Equal(buf[8:12], []byte("WEBP")) {
		return "image/webp"
	}
	if len(buf) >= 5 && bytes.Equal(buf[:5], magicPDF) {
		return "application/pdf"
	}
	if len(buf) >= 4 && bytes.Equal(buf[:4], magicZIP) {
		return "application/zip"
	}
	if len(buf) >= 4 && bytes.Equal(buf[:4], magicELF) {
		return "application/x-executable"
	}
	if len(buf) >= 2 && bytes.Equal(buf[:2], magicShebang) {
		return "text/x-shellscript"
	}
	trimmed := bytes.TrimSpace(buf)
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<svg")) {
		return "image/svg+xml"
	}
	return "application/octet-stream"
}

// InspectFile conducts comprehensive Magic-Byte, polyglot and cross-extension verification.
func (a *AirlockInspector) InspectFile(filePath string) (*AirlockInspectionResult, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return nil, NewAirlockValidationException("target file inaccessible", err)
	}

	// Pattern 1.5.B: File size measured on actual disk file
	fileSize := fi.Size()
	if fileSize <= 0 || fileSize > a.maxFileSize {
		return nil, NewAirlockValidationException(fmt.Sprintf("file size boundary violation: %d bytes", fileSize), nil)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, NewAirlockStorageException("failed to open inspection target", err)
	}
	defer f.Close()

	// Read header prefix (first 1024 bytes)
	prefixBuf := make([]byte, 1024)
	n, err := f.Read(prefixBuf)
	if err != nil && err != io.EOF {
		return nil, NewAirlockStorageException("failed to read file header", err)
	}
	prefix := prefixBuf[:n]

	// Compute full SHA-256
	hasher := sha256.New()
	hasher.Write(prefix)
	if _, err := io.Copy(hasher, f); err != nil {
		return nil, NewAirlockStorageException("failed to hash inspection target", err)
	}
	digest := hex.EncodeToString(hasher.Sum(nil))

	detectedMime := DetectMagicType(prefix)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, NewAirlockStorageException("failed to rewind inspection target", err)
	}
	body := make([]byte, 65536)
	bodyBytesRead, readErr := io.ReadFull(f, body)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return nil, NewAirlockStorageException("failed to read inspection sample", readErr)
	}
	body = body[:bodyBytesRead]

	return a.evaluateContent(filePath, fileSize, digest, detectedMime, body)
}

// InspectBytes inspects an in-memory object without staging attacker-controlled content on disk.
func (a *AirlockInspector) InspectBytes(filename string, data []byte) (*AirlockInspectionResult, error) {
	if len(data) == 0 || int64(len(data)) > a.maxFileSize {
		return nil, NewAirlockValidationException(fmt.Sprintf("file size boundary violation: %d bytes", len(data)), nil)
	}
	digestBytes := sha256.Sum256(data)
	digest := hex.EncodeToString(digestBytes[:])
	prefixEnd := len(data)
	if prefixEnd > 1024 {
		prefixEnd = 1024
	}
	sampleEnd := len(data)
	if sampleEnd > 65536 {
		sampleEnd = 65536
	}
	detectedMime := DetectMagicType(data[:prefixEnd])
	return a.evaluateContent(filename, int64(len(data)), digest, detectedMime, data[:sampleEnd])
}

func (a *AirlockInspector) evaluateContent(filename string, fileSize int64, digest, detectedMime string, body []byte) (*AirlockInspectionResult, error) {
	ext := strings.ToLower(filepath.Ext(filename))
	result := &AirlockInspectionResult{
		IsClean: true, DetectedMime: detectedMime, DeclaredExtension: ext, FileSize: fileSize,
		SHA256: digest, RiskScore: 0, Timestamp: time.Now().UTC(),
	}

	if detectedMime == "application/x-executable" && (ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".pdf" || ext == ".txt") {
		result.IsClean = false
		result.RiskScore = 250
		result.ThreatType = "DISGUISED_EXECUTABLE_PAYLOAD"
		return result, NewAirlockSecurityException("ELF executable disguised as user document", nil)
	}
	if ext == ".png" && detectedMime != "image/png" {
		result.IsClean = false
		result.RiskScore = 150
		result.ThreatType = "MIME_EXTENSION_MISMATCH"
		return result, NewAirlockSecurityException(fmt.Sprintf("file declared %s but magic bytes indicate %s", ext, detectedMime), nil)
	}
	if (ext == ".jpg" || ext == ".jpeg") && detectedMime != "image/jpeg" {
		result.IsClean = false
		result.RiskScore = 150
		result.ThreatType = "MIME_EXTENSION_MISMATCH"
		return result, NewAirlockSecurityException(fmt.Sprintf("file declared %s but magic bytes indicate %s", ext, detectedMime), nil)
	}
	if ext == ".pdf" && detectedMime != "application/pdf" {
		result.IsClean = false
		result.RiskScore = 150
		result.ThreatType = "MIME_EXTENSION_MISMATCH"
		return result, NewAirlockSecurityException(fmt.Sprintf("file declared %s but magic bytes indicate %s", ext, detectedMime), nil)
	}
	for _, re := range dangerousPolyglotPatterns {
		if re.Match(body) {
			result.IsClean = false
			result.RiskScore = 200
			result.ThreatType = "POLYGLOT_SCRIPT_INJECTION"
			return result, NewAirlockSecurityException("polyglot script payload embedded in binary body", nil)
		}
	}
	if ext == ".svg" || detectedMime == "image/svg+xml" {
		if svgXXEEntity.Match(body) {
			result.IsClean = false
			result.RiskScore = 250
			result.ThreatType = "SVG_XXE_INJECTION"
			return result, NewAirlockSecurityException("SVG contains forbidden XML external entity (XXE)", nil)
		}
		if svgDangerousAttrs.Match(body) || svgJavascriptURI.Match(body) {
			result.IsClean = false
			result.RiskScore = 180
			result.ThreatType = "SVG_EMBEDDED_SCRIPT"
			return result, NewAirlockSecurityException("SVG contains active scripting or inline event handlers", nil)
		}
	}
	return result, nil
}

// SanitizeSVG strips active scripting elements from SVG content before desktop presentation.
func SanitizeSVG(input []byte) ([]byte, bool) {
	modified := false
	output := input

	// Strip <script>...</script>
	scriptRegex := regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)
	if scriptRegex.Match(output) {
		output = scriptRegex.ReplaceAll(output, []byte(""))
		modified = true
	}

	// Strip <foreignObject>...</foreignObject> HTML execution embedding
	foreignObjRegex := regexp.MustCompile(`(?is)<foreignObject\b[^>]*>.*?</foreignObject>`)
	if foreignObjRegex.Match(output) {
		output = foreignObjRegex.ReplaceAll(output, []byte(""))
		modified = true
	}

	// Strip <embed>, <object>, <iframe> tags
	embedRegex := regexp.MustCompile(`(?is)<(?:iframe|embed|object)\b[^>]*>(?:.*?</(?:iframe|embed|object)>)?`)
	if embedRegex.Match(output) {
		output = embedRegex.ReplaceAll(output, []byte(""))
		modified = true
	}

	// Strip inline event attributes: onload=, onclick=, onerror=, etc.
	if svgDangerousAttrs.Match(output) {
		attrStripRegex := regexp.MustCompile(`(?i)\bon[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)`)
		output = attrStripRegex.ReplaceAll(output, []byte(""))
		modified = true
	}

	// Strip javascript: links
	if svgJavascriptURI.Match(output) {
		jsLinkRegex := regexp.MustCompile(`(?i)(?:href|src)\s*=\s*(?:"javascript:[^"]*"|'javascript:[^']*')`)
		output = jsLinkRegex.ReplaceAll(output, []byte(`href="#"`))
		modified = true
	}

	return output, modified
}

// StageInJail stages an incoming download in the quarantine vault under 0600 permissions (Pattern 1.5.E compliance).
func (a *AirlockInspector) StageInJail(filename string, r io.Reader) (string, error) {
	if a.quarantineDir == "" {
		return "", NewAirlockStorageException("quarantine directory unconfigured", nil)
	}

	cleanName := filepath.Base(filepath.Clean(filename))
	if cleanName == "." || cleanName == "/" || cleanName == "\\" || cleanName == "" {
		return "", NewAirlockValidationException("invalid staged filename", nil)
	}

	// Ensure quarantine directory exists and evaluate symlinks to eliminate TOCTOU jail escapes (Pattern 1.5.E)
	if err := os.MkdirAll(a.quarantineDir, 0o700); err != nil {
		return "", NewAirlockStorageException("failed to prepare quarantine directory", err)
	}
	resolvedDir, err := filepath.EvalSymlinks(a.quarantineDir)
	if err != nil {
		resolvedDir = filepath.Clean(a.quarantineDir)
	}

	destination := filepath.Join(resolvedDir, cleanName)
	if !strings.HasPrefix(destination, resolvedDir+string(filepath.Separator)) {
		return "", NewAirlockSecurityException("destination escaped quarantine jail", nil)
	}

	out, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", NewAirlockStorageException("failed to open jail destination", err)
	}
	defer out.Close()

	// Enforce hard size boundary pre-flight during streaming copy (Pattern 1.5.B)
	limitReader := io.LimitReader(r, a.maxFileSize+1)
	written, err := io.Copy(out, limitReader)
	if err != nil {
		_ = out.Close()
		_ = os.Remove(destination)
		return "", NewAirlockStorageException("failed to write payload into jail", err)
	}
	if written > a.maxFileSize {
		_ = out.Close()
		_ = os.Remove(destination)
		return "", NewAirlockValidationException(fmt.Sprintf("file size boundary violation: exceeds limit of %d bytes", a.maxFileSize), nil)
	}

	return destination, nil
}
