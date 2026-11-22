// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// AirlockBoundaryException marks a refusal because the inspected path left the
// configured staging root or resolved through a symbolic link. The API layer maps
// it to 403 Forbidden and records an event: this is not "the object was scanned
// and found clean", it is "the object was never looked at because the request
// tried to escape the jail".
type AirlockBoundaryException struct{ AirlockException }

func NewAirlockValidationException(msg string, err error) *AirlockValidationException {
	return &AirlockValidationException{AirlockException{Message: msg, Err: err}}
}

func NewAirlockBoundaryException(msg string, err error) *AirlockBoundaryException {
	return &AirlockBoundaryException{AirlockException{Message: msg, Err: err}}
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

// Active-content signatures required by F-11 / CHAIN-010. The historical
// polyglot set only covered server-side script openers, so an env-shebang,
// an HTML event handler or a SMIL/data-URI SVG upload was reported clean.
var (
	htmlActiveContentPattern = regexp.MustCompile(`(?i)<\s*(?:script|iframe|object|embed|svg|math)\b|\bon[a-z]+\s*=|\bjavascript\s*:|\bdata\s*:\s*(?:text/html|application/xhtml\+xml)`)
	svgActiveElementPattern  = regexp.MustCompile(`(?i)<\s*(?:animate|animateMotion|animateTransform|set|discard)\b|\battributeName\s*=|\bonbegin\s*=|\bbegin\s*=`)
	svgDataURIPattern        = regexp.MustCompile(`(?i)(?:href|xlink:href|src)\s*=\s*["']?\s*data\s*:\s*(?:image/svg\+xml|text/html|application/xhtml\+xml)`)
	svgForeignObjectPattern  = regexp.MustCompile(`(?i)<\s*foreignObject\b`)
	svgNamespacePattern      = regexp.MustCompile(`(?i)xmlns\s*=\s*["']http://www.w3.org/2000/svg["']|<svg\b`)
	// svgDataURIMarkerPattern is the ASCII case-insensitive twin of the historical
	// bytes.Contains(bytes.ToLower(...), "data:image/svg+xml") check. A regexp
	// avoids allocating a lower-cased copy of every scan window.
	svgDataURIMarkerPattern = regexp.MustCompile(`(?i)data:image/svg\+xml`)
)

// declaredMediaTypes maps a declared extension to its expected media type.
// Extensions that cannot be represented by magic bytes (text/*) are not listed
// and therefore never produce a false MIME mismatch.
var declaredMediaTypes = map[string]string{
	".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
	".webp": "image/webp", ".pdf": "application/pdf", ".zip": "application/zip",
}

// scriptCapableExtensions are file classes a web server may execute or render as
// active content. They are escalated according to the existing executable
// upload policy (reject => refused, report => visible finding).
//
// The list is enforced for every inspected object, not only inside the SVG
// branch: a control that only ran for one declared extension reported a clean
// .php/.jsp/.js upload whenever its bytes carried no obvious polyglot marker.
var scriptCapableExtensions = map[string]struct{}{
	".php": {}, ".phtml": {}, ".php3": {}, ".php4": {}, ".php5": {}, ".phar": {},
	".cgi": {}, ".pl": {}, ".py": {}, ".rb": {}, ".sh": {}, ".bash": {}, ".lua": {},
	".html": {}, ".htm": {}, ".xhtml": {}, ".shtml": {}, ".svg": {},
	".jsp": {}, ".jspx": {}, ".asp": {}, ".aspx": {}, ".cshtml": {},
	".js": {}, ".mjs": {}, ".cjs": {}, ".wasm": {},
}

// Scan bounds for the content inspection.
//
// The historical implementation read one 64 KiB sample and evaluated every
// pattern against it, so a payload after byte 65536 was invisible: a clean
// header was enough to pass. The scan now streams the object in bounded chunks
// with a one-chunk overlap, which makes a marker after any offset detectable at
// constant memory cost. A one-chunk overlap keeps a token that spans a chunk
// boundary observable as well.
//
// The budget is a hard, deterministic policy bound: an object larger than
// airlockScanBudgetBytes is refused instead of being scanned only in part. A
// silent partial inspection is worse than a rejection that names its reason,
// because it reports "clean" for bytes that were never looked at.
const (
	airlockInspectHeaderBytes = 1024
	airlockScanChunkBytes     = 64 << 10
	airlockScanOverlapBytes   = 64 << 10
	airlockScanBudgetBytes    = 64 << 20
)

// M1.3: raw HTTP request bodies (POST/PUT, octet-stream or unknown content type)
// are inspected with the same streaming scan as uploaded objects. The marker set
// covers the industry-standard AV test signature plus the generic webshell
// idiom (a superglobal passed straight into an interpreter primitive).
var airlockMalwareMarkerPattern = regexp.MustCompile(`(?i)(?:EICAR-STANDARD-ANTIVIRUS-TEST-FILE|\b(?:eval|assert|system|passthru|exec|shell_exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE))`)

// airlockContentSignals accumulates the independent content classes while the
// bytes are streamed. The evaluation order that assigns the reported threat
// type stays in evaluateInspection; this type only records what was seen.
type airlockContentSignals struct {
	htmlActiveContent bool
	svgXXE            bool
	svgActiveContent  bool
	svgDataURI        bool
	polyglotIndex     int
	malwareMarker     bool
}

func newAirlockContentSignals() airlockContentSignals {
	return airlockContentSignals{polyglotIndex: -1}
}

// complete reports whether every content class has already been observed, so
// the remaining bytes only need to be read (for the digest) and no longer
// matched.
func (s *airlockContentSignals) complete() bool {
	return s.htmlActiveContent && s.svgXXE && s.svgActiveContent && s.svgDataURI && s.malwareMarker && s.polyglotIndex >= 0
}

func (s *airlockContentSignals) consume(window []byte) {
	if len(window) == 0 {
		return
	}
	if !s.htmlActiveContent && htmlActiveContentPattern.Match(window) {
		s.htmlActiveContent = true
	}
	if !s.malwareMarker && airlockMalwareMarkerPattern.Match(window) {
		s.malwareMarker = true
	}
	if !s.svgXXE && svgXXEEntity.Match(window) {
		s.svgXXE = true
	}
	if !s.svgActiveContent && (svgActiveElementPattern.Match(window) || svgDataURIPattern.Match(window) ||
		svgForeignObjectPattern.Match(window) || svgDangerousAttrs.Match(window) || svgJavascriptURI.Match(window)) {
		s.svgActiveContent = true
	}
	if !s.svgDataURI && (svgDataURIMarkerPattern.Match(window) ||
		(svgNamespacePattern.Match(window) && svgActiveElementPattern.Match(window))) {
		s.svgDataURI = true
	}
	if s.polyglotIndex < 0 {
		for index, re := range dangerousPolyglotPatterns {
			if re.Match(window) {
				s.polyglotIndex = index
				break
			}
		}
	}
}

// scanAirlockBytes applies the streaming scan to an in-memory object.
func scanAirlockBytes(data []byte, signals *airlockContentSignals) {
	for offset := 0; offset < len(data); offset += airlockScanChunkBytes {
		end := offset + airlockScanChunkBytes + airlockScanOverlapBytes
		if end > len(data) {
			end = len(data)
		}
		signals.consume(data[offset:end])
		if signals.complete() {
			return
		}
	}
}

// scanAirlockReader applies the same bounded, overlapping scan to a stream. It
// consumes the entire reader even after every class was seen, because the
// caller computes the object digest from the same pass.
func scanAirlockReader(source io.Reader, signals *airlockContentSignals) error {
	chunk := make([]byte, airlockScanChunkBytes)
	carry := make([]byte, 0, airlockScanOverlapBytes)
	window := make([]byte, 0, airlockScanChunkBytes+airlockScanOverlapBytes)
	for {
		n, readErr := io.ReadFull(source, chunk)
		if n > 0 {
			window = window[:0]
			window = append(window, carry...)
			window = append(window, chunk[:n]...)
			if !signals.complete() {
				signals.consume(window)
			}
			if len(window) > airlockScanOverlapBytes {
				carry = append(carry[:0], window[len(window)-airlockScanOverlapBytes:]...)
			} else {
				carry = append(carry[:0], window...)
			}
		}
		if readErr != nil {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				return nil
			}
			return readErr
		}
	}
}

// airlockJailedRelativePath maps a requested inspection path onto the
// configured inspection root and proves the result stays inside it.
//
// The path is cleaned first, so absolute traversal (root/../etc/hostname) and
// dot-segments cannot name a parent directory. An absolute request must then
// live below the canonical root; a relative request is interpreted relative to
// that root. The returned name is a clean relative name that openBeneath walks
// one component at a time without ever following a symbolic link.
func airlockJailedRelativePath(root, requested string) (string, error) {
	trimmed := strings.TrimSpace(requested)
	if trimmed == "" || strings.ContainsRune(trimmed, '\x00') {
		return "", NewAirlockBoundaryException("inspection target path is empty or malformed", nil)
	}
	cleaned := filepath.Clean(trimmed)
	var relative string
	if filepath.IsAbs(cleaned) {
		rel, err := filepath.Rel(root, cleaned)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return "", NewAirlockBoundaryException("inspection target is outside the configured inspection root", nil)
		}
		relative = rel
	} else {
		relative = cleaned
	}
	if relative == "" || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) ||
		filepath.IsAbs(relative) || len(relative) > 2048 {
		return "", NewAirlockBoundaryException("inspection target is outside the configured inspection root", nil)
	}
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		if component == "" || component == "." || component == ".." {
			return "", NewAirlockBoundaryException("inspection target contains a non-canonical path component", nil)
		}
	}
	return relative, nil
}

// inspectionRoot resolves the canonical staging/quarantine root that every
// on-disk inspection is bound to. It comes from the administrable airlock
// policy (quarantine_directory) and falls back to the root the inspector was
// constructed with; an unconfigured or non-absolute root is a fail-closed
// condition, never an implicit "current directory".
func (a *AirlockInspector) inspectionRoot(policy airlockPolicy) (string, error) {
	candidate := strings.TrimSpace(policy.quarantineDir)
	if candidate == "" {
		a.mu.RLock()
		candidate = strings.TrimSpace(a.quarantineDir)
		a.mu.RUnlock()
	}
	if candidate == "" {
		return "", NewAirlockValidationException("airlock inspection root is not configured", nil)
	}
	if !filepath.IsAbs(candidate) {
		return "", NewAirlockValidationException("airlock inspection root must be an absolute path", nil)
	}
	// Resolve the root once so the jail anchor is a real directory. The walk
	// below every component still refuses a symbolic link, which keeps the
	// resolution from becoming a trust decision.
	resolved, err := filepath.EvalSymlinks(filepath.Clean(candidate))
	if err != nil {
		return "", NewAirlockStorageException("airlock inspection root is unavailable", err)
	}
	return resolved, nil
}

// activeContentMIME lists detected media types that are never benign when they
// appear under an unrelated extension.
var activeContentMIME = map[string]struct{}{
	"text/html": {}, "image/svg+xml": {}, "application/x-executable": {}, "text/x-shellscript": {},
}

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
	// QuarantinePath is set when automatic quarantine staged a refused object.
	QuarantinePath  string `json:"quarantine_path,omitempty"`
	QuarantineError string `json:"quarantine_error,omitempty"`
}

// airlockReportOnlyScore keeps a reported-only finding far below any block
// threshold while still producing evidence.
const airlockReportOnlyScore = 40

// airlockPolicy is the administrable inspection and staging posture.
type airlockPolicy struct {
	enabled bool
	// published distinguishes "no policy has been handed to this inspector yet" from
	// "an administrator deliberately switched a detector off". Both would otherwise
	// be the false zero value, and the safe reading of the two is not the same one.
	published              bool
	quarantineDir          string
	maxFileSize            int64
	mimeMismatchAction     string
	polyglotDetection      bool
	svgActiveContent       bool
	executableUploadPolicy string
	autoQuarantine         bool
}

type AirlockInspector struct {
	mu            sync.RWMutex
	quarantineDir string
	maxFileSize   int64
	policy        airlockPolicy
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
//
// The path is attacker-influenced (it arrives in an authenticated JSON request),
// so it is never passed to os.Stat/os.Open directly:
//
//   - it must live below the canonical inspection root (filepath.Clean +
//     filepath.Rel), and a symlink in any component is refused;
//   - the file is opened through openBeneath, which descends the jail one
//     descriptor at a time with openat(2)+O_NOFOLLOW, so a path component
//     replaced between check and open cannot redirect the read (no TOCTOU);
//   - the opened descriptor is what is stat'ed, hashed and scanned, so the
//     inspected bytes are exactly the opened object.
func (a *AirlockInspector) InspectFile(filePath string) (*AirlockInspectionResult, error) {
	policy := a.policySnapshot()
	root, err := a.inspectionRoot(policy)
	if err != nil {
		return nil, err
	}
	relative, err := airlockJailedRelativePath(root, filePath)
	if err != nil {
		return nil, err
	}

	// Lstat classifies the final component before the descriptor walk: a
	// symbolic link is refused explicitly instead of surfacing as a generic
	// resolve error. Enforcement does not depend on this check.
	info, err := os.Lstat(filepath.Join(root, relative))
	if err != nil {
		return nil, NewAirlockValidationException("target file inaccessible", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, NewAirlockBoundaryException("inspection target is a symbolic link; refusing to follow it", nil)
	}
	if !info.Mode().IsRegular() {
		return nil, NewAirlockBoundaryException("inspection target must be a regular file", nil)
	}
	// A symlinked parent directory would make the Lstat above resolve through
	// it while the descriptor walk below refuses it. Classifying it as a jail
	// refusal gives the API a 403 instead of a generic storage error; the
	// refusal itself is enforced by openBeneath, not by this diagnostic.
	if jailPathIsSymlinked(root, relative) {
		return nil, NewAirlockBoundaryException("inspection target resolves through a symbolic link", nil)
	}

	file, err := openBeneath(root, relative, os.O_RDONLY, 0)
	if err != nil {
		return nil, NewAirlockStorageException("failed to open inspection target", err)
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return nil, NewAirlockStorageException("failed to stat inspection target", err)
	}
	if !opened.Mode().IsRegular() {
		return nil, NewAirlockBoundaryException("inspection target is not a regular file", nil)
	}
	// Pattern 1.5.B: File size measured on the opened object, not on a path.
	fileSize := opened.Size()
	if fileSize <= 0 || fileSize > policy.maxFileSize {
		return nil, NewAirlockValidationException(fmt.Sprintf("file size boundary violation: %d bytes", fileSize), nil)
	}
	if fileSize > airlockScanBudgetBytes {
		// Deterministic rejection instead of a silent partial scan: a "clean"
		// verdict for bytes that were never inspected is the failure mode this
		// budget exists to prevent.
		return nil, NewAirlockValidationException(
			fmt.Sprintf("file exceeds the deterministic content-scan budget of %d bytes; inspection refused without a partial scan", int64(airlockScanBudgetBytes)), nil)
	}

	prefixBuf := make([]byte, airlockInspectHeaderBytes)
	n, readErr := io.ReadFull(file, prefixBuf)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return nil, NewAirlockStorageException("failed to read file header", readErr)
	}
	prefix := prefixBuf[:n]

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, NewAirlockStorageException("failed to rewind inspection target", err)
	}
	hasher := sha256.New()
	signals := newAirlockContentSignals()
	if err := scanAirlockReader(io.TeeReader(file, hasher), &signals); err != nil {
		return nil, NewAirlockStorageException("failed to scan inspection target", err)
	}
	digest := hex.EncodeToString(hasher.Sum(nil))

	return a.evaluateInspection(relative, fileSize, digest, DetectMagicType(prefix), prefix, signals)
}

// policySnapshot returns the administrable inspection posture with its safe,
// fail-closed defaults applied.
func (a *AirlockInspector) policySnapshot() airlockPolicy {
	a.mu.RLock()
	defer a.mu.RUnlock()
	policy := a.policy
	if policy.maxFileSize <= 0 {
		policy.maxFileSize = a.maxFileSize
	}
	if policy.quarantineDir == "" {
		policy.quarantineDir = a.quarantineDir
	}
	if policy.mimeMismatchAction == "" {
		policy.mimeMismatchAction = airlockMimeActionReport
	}
	if policy.executableUploadPolicy == "" {
		policy.executableUploadPolicy = airlockExecPolicyReject
	}
	if !policy.published {
		// Fail closed. An inspector that has not been configured yet must inspect:
		// returning the zero value here silently disabled magic-byte, polyglot and SVG
		// detection, so every file was reported clean until a policy arrived. A
		// security control defaults to enforcing, never to permitting.
		policy.enabled = true
		policy.polyglotDetection = true
		policy.svgActiveContent = true
	}
	return policy
}

// ApplyPolicy republishes the administrable inspection and staging posture. The
// signature set and the polyglot patterns stay fixed; only their participation
// and the escalation score are administrable.
func (a *AirlockInspector) ApplyPolicy(settings AirlockFabricSettings) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.policy = airlockPolicy{
		published:              true,
		enabled:                settings.Enabled,
		quarantineDir:          settings.QuarantineDirectory,
		maxFileSize:            settings.MaxFileSizeBytes,
		mimeMismatchAction:     settings.MimeMismatchAction,
		polyglotDetection:      settings.PolyglotDetection,
		svgActiveContent:       settings.SVGActiveContent,
		executableUploadPolicy: settings.ExecutableUploadPolicy,
		autoQuarantine:         settings.AutoQuarantine,
	}
	return nil
}

// Enabled reports whether upload inspection participates in evaluation.
func (a *AirlockInspector) Enabled() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.policy.enabled
}

// escalateScore maps a finding to its enforcement score. The administrable
// executable upload policy decides whether a disguised executable is refused
// outright or reported at a score that never crosses a block threshold on its
// own.
func (p airlockPolicy) escalateScore(rejectScore int) int {
	if p.executableUploadPolicy == airlockExecPolicyReject {
		return rejectScore
	}
	return airlockReportOnlyScore
}

// InspectBytes inspects an in-memory object without staging attacker-controlled content on disk.
func (a *AirlockInspector) InspectBytes(filename string, data []byte) (*AirlockInspectionResult, error) {
	policy := a.policySnapshot()
	if len(data) == 0 || int64(len(data)) > policy.maxFileSize {
		return nil, NewAirlockValidationException(fmt.Sprintf("file size boundary violation: %d bytes", len(data)), nil)
	}
	if int64(len(data)) > airlockScanBudgetBytes {
		return nil, NewAirlockValidationException(
			fmt.Sprintf("object exceeds the deterministic content-scan budget of %d bytes; inspection refused without a partial scan", int64(airlockScanBudgetBytes)), nil)
	}
	digestBytes := sha256.Sum256(data)
	digest := hex.EncodeToString(digestBytes[:])
	prefixEnd := len(data)
	if prefixEnd > airlockInspectHeaderBytes {
		prefixEnd = airlockInspectHeaderBytes
	}
	detectedMime := DetectMagicType(data[:prefixEnd])
	signals := newAirlockContentSignals()
	scanAirlockBytes(data, &signals)
	result, err := a.evaluateInspection(filename, int64(len(data)), digest, detectedMime, data[:prefixEnd], signals)

	// Preservation-on-reject: when the operator asked for automatic quarantine,
	// a refused object is staged so the evidence survives the request.
	if err != nil && result != nil && policy.autoQuarantine && policy.quarantineDir != "" {
		ext := filepath.Ext(filename)
		staged, stageErr := a.StageInJail(digest[:16]+ext, bytes.NewReader(data))
		if stageErr == nil {
			result.QuarantinePath = staged
		} else {
			result.QuarantineError = stageErr.Error()
		}
	}
	return result, err
}

// evaluateInspection is the single, ordered content rule set. It is fed by the
// header prefix and the accumulated streaming scan signals, so the verdict no
// longer depends on one 64 KiB sample.
func (a *AirlockInspector) evaluateInspection(filename string, fileSize int64, digest, detectedMime string, header []byte, signals airlockContentSignals) (*AirlockInspectionResult, error) {
	policy := a.policySnapshot()
	ext := strings.ToLower(filepath.Ext(filename))
	result := &AirlockInspectionResult{
		IsClean: true, DetectedMime: detectedMime, DeclaredExtension: ext, FileSize: fileSize,
		SHA256: digest, RiskScore: 0, Timestamp: time.Now().UTC(),
	}
	if !policy.enabled {
		return result, nil
	}

	if detectedMime == "application/x-executable" && (ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".pdf" || ext == ".txt") {
		result.IsClean = false
		result.RiskScore = clampScore(policy.escalateScore(250))
		result.ThreatType = "DISGUISED_EXECUTABLE_PAYLOAD"
		return result, NewAirlockSecurityException("ELF executable disguised as user document", nil)
	}
	trimmedHeader := bytes.TrimSpace(header)

	// F-11: env-shebang scripts are executable content regardless of the
	// declared extension. The shebang path was completely invisible before.
	if len(trimmedHeader) >= 2 && trimmedHeader[0] == '#' && trimmedHeader[1] == '!' {
		result.IsClean = false
		result.RiskScore = clampScore(policy.escalateScore(220))
		result.ThreatType = "SCRIPT_SHEBANG_PAYLOAD"
		return result, NewAirlockSecurityException("uploaded object starts with an executable shebang", nil)
	}

	if policy.mimeMismatchAction == airlockMimeActionReport {
		if expected, known := declaredMediaTypes[ext]; known && detectedMime != expected && detectedMime != "application/octet-stream" {
			result.IsClean = false
			result.RiskScore = clampScore(policy.escalateScore(180))
			result.ThreatType = "MIME_EXTENSION_MISMATCH"
			return result, NewAirlockSecurityException(fmt.Sprintf("file declared %s but magic bytes indicate %s", ext, detectedMime), nil)
		}
		if _, active := activeContentMIME[detectedMime]; active {
			switch ext {
			case ".html", ".htm", ".xhtml", ".shtml", ".svg":
				// The extension matches active content; the active-content rules
				// below decide.
			default:
				result.IsClean = false
				result.RiskScore = clampScore(policy.escalateScore(200))
				result.ThreatType = "MIME_EXTENSION_MISMATCH"
				return result, NewAirlockSecurityException(fmt.Sprintf("file declared %s but magic bytes indicate active content %s", ext, detectedMime), nil)
			}
		}
	}

	isHTMLDocument := ext == ".html" || ext == ".htm" || ext == ".xhtml" || ext == ".shtml" || detectedMime == "text/html"
	if isHTMLDocument && signals.htmlActiveContent {
		result.IsClean = false
		result.RiskScore = clampScore(policy.escalateScore(210))
		result.ThreatType = "HTML_ACTIVE_CONTENT"
		return result, NewAirlockSecurityException("HTML upload contains active scripting or event-handler content", nil)
	}

	// SVG keeps its own, stricter rule set (XXE, SMIL, foreignObject, data:-URI).
	// Only the content rules are SVG-specific; the extension policy below runs
	// for every object.
	isSVGDocument := policy.svgActiveContent && (ext == ".svg" || detectedMime == "image/svg+xml")
	if isSVGDocument {
		if signals.svgXXE {
			result.IsClean = false
			result.RiskScore = clampScore(policy.escalateScore(250))
			result.ThreatType = "SVG_XXE_INJECTION"
			return result, NewAirlockSecurityException("SVG contains forbidden XML external entity (XXE)", nil)
		}
		if signals.svgActiveContent {
			result.IsClean = false
			result.RiskScore = clampScore(policy.escalateScore(200))
			result.ThreatType = "SVG_ACTIVE_CONTENT"
			return result, NewAirlockSecurityException("SVG contains SMIL animation, foreignObject or data:-URI active content", nil)
		}
	}

	// F-11: script-capable extensions are escalated according to the existing
	// executable upload policy (reject => refused, report => visible finding).
	// This check is top-level: it must flag a .php/.js/.jsp upload even when the
	// file body carries no other active-content marker.
	if _, scriptable := scriptCapableExtensions[ext]; scriptable {
		result.IsClean = false
		result.RiskScore = clampScore(policy.escalateScore(160))
		result.ThreatType = "SCRIPT_CAPABLE_UPLOAD"
		if policy.executableUploadPolicy == airlockExecPolicyReject {
			return result, NewAirlockSecurityException(fmt.Sprintf("script-capable upload extension %s rejected", ext), nil)
		}
		return result, NewAirlockSecurityException(fmt.Sprintf("script-capable upload extension %s flagged", ext), nil)
	}

	if policy.svgActiveContent && !isSVGDocument && signals.svgDataURI {
		result.IsClean = false
		result.RiskScore = clampScore(policy.escalateScore(200))
		result.ThreatType = "SVG_DATA_URI_PAYLOAD"
		return result, NewAirlockSecurityException("non-SVG upload embeds an active SVG/SMIL payload", nil)
	}
	if policy.polyglotDetection && signals.polyglotIndex >= 0 {
		result.IsClean = false
		result.RiskScore = 200
		result.ThreatType = "POLYGLOT_SCRIPT_INJECTION"
		return result, NewAirlockSecurityException("polyglot script payload embedded in binary body", nil)
	}
	return result, nil
}

// openJailDestination creates the staging file for the quarantine vault.
//
// O_CREATE|O_EXCL refuses an existing path and a symbolic link in the same step,
// so a link planted inside the vault cannot redirect the write outside it and a
// race between a check and the open cannot exist. An existing object is never
// truncated either: quarantined content is evidence, so a colliding name receives
// a fresh random suffix instead of destroying what is already stored.
// openJailDestination creates the staging file for the quarantine vault.
//
// The file name comes from an upload, so the whole path is resolved one component
// at a time relative to the vault descriptor. A single Lstat on the directory plus
// O_EXCL on the final name would protect only the last component; a symlinked
// parent directory would still redirect the write while the exclusive create
// succeeded. An existing object is never truncated either: quarantined content is
// evidence, so a colliding name receives a fresh random suffix instead.
func openJailDestination(dir, name string) (string, *os.File, error) {
	for attempt := 0; attempt < 4; attempt++ {
		base := name
		if attempt > 0 {
			suffix, err := randomBytesHex(8)
			if err != nil {
				return "", nil, NewAirlockStorageException("failed to allocate a jail name", err)
			}
			base = name + "." + suffix
		}
		file, err := openBeneath(dir, base, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return filepath.Join(dir, base), file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, NewAirlockStorageException("failed to open jail destination", err)
		}
	}
	return "", nil, NewAirlockStorageException("quarantine vault could not allocate a free name", nil)
}

// StageInJail stages an incoming download in the quarantine vault under 0600 permissions (Pattern 1.5.E compliance).
func (a *AirlockInspector) StageInJail(filename string, r io.Reader) (string, error) {
	policy := a.policySnapshot()
	quarantineDir := policy.quarantineDir
	if quarantineDir == "" {
		return "", NewAirlockStorageException("quarantine directory unconfigured", nil)
	}

	cleanName := filepath.Base(filepath.Clean(filename))
	if cleanName == "." || cleanName == "/" || cleanName == "\\" || cleanName == "" {
		return "", NewAirlockValidationException("invalid staged filename", nil)
	}

	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return "", NewAirlockStorageException("failed to prepare quarantine directory", err)
	}
	// Resolving the configured root once gives a stable anchor for the walk and
	// makes the write and the cleanup agree on the same directory. The escape
	// protection is not this call: openBeneath refuses a symbolic link in every
	// component below the anchor, including the ones a caller could influence.
	resolvedDir, err := filepath.EvalSymlinks(quarantineDir)
	if err != nil {
		resolvedDir = filepath.Clean(quarantineDir)
	}

	destination, out, err := openJailDestination(resolvedDir, cleanName)
	if err != nil {
		return "", err
	}
	defer out.Close()

	// Enforce hard size boundary pre-flight during streaming copy (Pattern 1.5.B)
	limitReader := io.LimitReader(r, policy.maxFileSize+1)
	written, err := io.Copy(out, limitReader)
	if err != nil {
		_ = out.Close()
		_ = removeBeneath(resolvedDir, filepath.Base(destination))
		return "", NewAirlockStorageException("failed to write payload into jail", err)
	}
	if written > policy.maxFileSize {
		_ = out.Close()
		_ = removeBeneath(resolvedDir, filepath.Base(destination))
		return "", NewAirlockValidationException(fmt.Sprintf("file size boundary violation: exceeds limit of %d bytes", policy.maxFileSize), nil)
	}

	return destination, nil
}
