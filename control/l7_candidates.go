// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

func (n *L7Normalizer) addQueryCandidates(out *l7NormalizedRequest, raw string) error {
	if !l7RawEntryBudgetString(raw, n.cfg.MaxFormFields) {
		return fmt.Errorf("%w: query entry budget exceeded", ErrL7ResourceLimit)
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return fmt.Errorf("%w: malformed query encoding", ErrL7InvalidRequest)
	}
	if len(values) > n.cfg.MaxFormFields {
		return fmt.Errorf("%w: query field budget exceeded", ErrL7ResourceLimit)
	}
	if l7FormEntryCount(values, n.cfg.MaxFormFields) > n.cfg.MaxFormFields {
		return fmt.Errorf("%w: query entry budget exceeded", ErrL7ResourceLimit)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entries := values[key]
		n.addCandidate(out, "query.key", key)
		if len(entries) > 32 {
			return fmt.Errorf("%w: repeated query field budget exceeded", ErrL7ResourceLimit)
		}
		for _, value := range entries {
			n.addCandidate(out, "query."+safeLocationKey(key), value)
		}
	}
	return nil
}

func (n *L7Normalizer) addBodyCandidates(out *l7NormalizedRequest) error {
	switch {
	case isL7JSONMediaType(out.ContentType):
		return n.addJSONCandidates(out)
	case out.ContentType == "application/x-www-form-urlencoded":
		return n.addFormCandidates(out)
	case isL7XMLMediaType(out.ContentType):
		n.addTextChunks(out, "body.xml", out.Body)
		return nil
	case out.ContentType == "multipart/form-data":
		return n.addMultipartCandidates(out)
	default:
		if isMostlyText(out.Body) {
			n.addTextChunks(out, "body.text", out.Body)
		}
		return nil
	}
}

func (n *L7Normalizer) addMultipartCandidates(out *l7NormalizedRequest) error {
	values := out.Headers["content-type"]
	if len(values) != 1 {
		return nil
	}
	_, params, err := mime.ParseMediaType(values[0])
	if err != nil || params["boundary"] == "" || len(params["boundary"]) > 200 {
		return fmt.Errorf("%w: malformed multipart content type", ErrL7InvalidRequest)
	}
	reader := multipart.NewReader(bytes.NewReader(out.Body), params["boundary"])
	parts := 0
	for {
		part, nextErr := reader.NextPart()
		if nextErr == io.EOF {
			return nil
		}
		if nextErr != nil {
			return fmt.Errorf("%w: malformed multipart body", ErrL7InvalidRequest)
		}
		parts++
		if parts > n.cfg.MaxMultipartParts {
			_ = part.Close()
			return fmt.Errorf("%w: multipart part budget exceeded", ErrL7ResourceLimit)
		}
		if part.FileName() != "" {
			_ = part.Close()
			continue
		}
		name := safeLocationKey(part.FormName())
		value, readErr := io.ReadAll(io.LimitReader(part, int64(n.cfg.MaxBodyBytes)+1))
		_ = part.Close()
		if readErr != nil {
			return fmt.Errorf("%w: multipart field read failed", ErrL7InvalidRequest)
		}
		if len(value) > n.cfg.MaxBodyBytes {
			return fmt.Errorf("%w: multipart field budget exceeded", ErrL7ResourceLimit)
		}
		n.addCandidate(out, "body.multipart."+name, strings.ToValidUTF8(string(value), " "))
	}
}

func (n *L7Normalizer) addJSONCandidates(out *l7NormalizedRequest) error {
	decoder := json.NewDecoder(bytes.NewReader(out.Body))
	decoder.UseNumber()
	depth := 0
	values := 0
	tokens := 0
	maxTokens := maxInt(n.cfg.MaxFormFields*8, 256)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: malformed json body", ErrL7InvalidRequest)
		}
		tokens++
		if tokens > maxTokens {
			return fmt.Errorf("%w: json token budget exceeded", ErrL7ResourceLimit)
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{', '[':
				depth++
				if depth > n.cfg.MaxJSONDepth {
					return fmt.Errorf("%w: json depth budget exceeded", ErrL7ResourceLimit)
				}
			case '}', ']':
				depth--
				if depth < 0 {
					return fmt.Errorf("%w: malformed json nesting", ErrL7InvalidRequest)
				}
			}
		case string:
			values++
			if values > n.cfg.MaxFormFields {
				return fmt.Errorf("%w: json value budget exceeded", ErrL7ResourceLimit)
			}
			n.addCandidate(out, "body.json", value)
		}
	}
	if depth != 0 {
		return fmt.Errorf("%w: malformed json nesting", ErrL7InvalidRequest)
	}
	return nil
}

func (n *L7Normalizer) addFormCandidates(out *l7NormalizedRequest) error {
	if len(out.Body) > n.cfg.MaxBodyBytes {
		return fmt.Errorf("%w: form body exceeds budget", ErrL7ResourceLimit)
	}
	if !l7RawEntryBudgetBytes(out.Body, n.cfg.MaxFormFields) {
		return fmt.Errorf("%w: form entry budget exceeded", ErrL7ResourceLimit)
	}
	values, err := url.ParseQuery(string(out.Body))
	if err != nil {
		return fmt.Errorf("%w: malformed form body", ErrL7InvalidRequest)
	}
	if len(values) > n.cfg.MaxFormFields {
		return fmt.Errorf("%w: form field budget exceeded", ErrL7ResourceLimit)
	}
	if l7FormEntryCount(values, n.cfg.MaxFormFields) > n.cfg.MaxFormFields {
		return fmt.Errorf("%w: form entry budget exceeded", ErrL7ResourceLimit)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entries := values[key]
		n.addCandidate(out, "body.form.key", key)
		if len(entries) > 32 {
			return fmt.Errorf("%w: repeated form field budget exceeded", ErrL7ResourceLimit)
		}
		for _, value := range entries {
			n.addCandidate(out, "body.form."+safeLocationKey(key), value)
		}
	}
	return nil
}

func l7RawEntryBudgetString(raw string, limit int) bool {
	if raw == "" {
		return true
	}
	if limit < 1 {
		return false
	}
	entries := 1
	for i := 0; i < len(raw); i++ {
		if raw[i] != '&' {
			continue
		}
		entries++
		if entries > limit {
			return false
		}
	}
	return true
}

func l7RawEntryBudgetBytes(raw []byte, limit int) bool {
	if len(raw) == 0 {
		return true
	}
	if limit < 1 {
		return false
	}
	entries := 1
	for _, b := range raw {
		if b != '&' {
			continue
		}
		entries++
		if entries > limit {
			return false
		}
	}
	return true
}

func l7FormEntryCount(values url.Values, limit int) int {
	if limit < 1 {
		return 1
	}
	total := 0
	for _, entries := range values {
		if len(entries) > limit-total {
			return limit + 1
		}
		total += len(entries)
	}
	return total
}

func isL7JSONMediaType(contentType string) bool {
	return contentType == "application/json" || contentType == "application/problem+json" || contentType == "application/ld+json" || strings.HasSuffix(contentType, "+json")
}

func isL7XMLMediaType(contentType string) bool {
	return contentType == "application/xml" || contentType == "text/xml" || contentType == "image/svg+xml" || strings.HasSuffix(contentType, "+xml")
}

func (n *L7Normalizer) addTextChunks(out *l7NormalizedRequest, location string, body []byte) {
	const chunkSize = 16 << 10
	const overlap = 256
	for start := 0; start < len(body); {
		end := start + chunkSize
		if end > len(body) {
			end = len(body)
		}
		chunk := body[start:end]
		n.addCandidate(out, location, strings.ToValidUTF8(string(chunk), " "))
		if out.CandidateBudgetExceeded {
			return
		}
		if end == len(body) {
			break
		}
		start = end - overlap
	}
}

func (n *L7Normalizer) addCandidate(out *l7NormalizedRequest, location, value string) {
	if value == "" {
		return
	}
	if len(out.Candidates) >= n.cfg.MaxDecodedValues || out.CandidateBytes >= n.cfg.MaxInspectionBytes {
		out.CandidateBudgetExceeded = true
		return
	}
	value = strings.ToValidUTF8(value, " ")
	if len(value) <= n.cfg.MaxValueBytes {
		n.addCandidateChunk(out, location, value)
		return
	}
	const overlap = 256
	for start := 0; start < len(value); {
		if len(out.Candidates) >= n.cfg.MaxDecodedValues || out.CandidateBytes >= n.cfg.MaxInspectionBytes {
			out.CandidateBudgetExceeded = true
			return
		}
		chunk := truncateUTF8(value[start:], n.cfg.MaxValueBytes)
		if chunk == "" {
			out.CandidateBudgetExceeded = true
			return
		}
		n.addCandidateChunk(out, location, chunk)
		if out.CandidateBudgetExceeded {
			return
		}
		end := start + len(chunk)
		if end >= len(value) {
			return
		}
		next := end - minInt(overlap, len(chunk)/2)
		for next < len(value) && !utf8.RuneStart(value[next]) {
			next++
		}
		if next <= start {
			next = end
		}
		start = next
	}
}

func (n *L7Normalizer) addCandidateChunk(out *l7NormalizedRequest, location, value string) {
	if value == "" {
		return
	}
	if len(out.Candidates) >= n.cfg.MaxDecodedValues || out.CandidateBytes >= n.cfg.MaxInspectionBytes {
		out.CandidateBudgetExceeded = true
		return
	}
	value = truncateUTF8(value, n.cfg.MaxValueBytes)
	if value == "" {
		return
	}
	canonical := value
	for depth := 0; depth < n.cfg.MaxDecodeDepth; depth++ {
		decoded := canonical
		if v, err := url.PathUnescape(decoded); err == nil {
			decoded = v
		}
		decoded = html.UnescapeString(decoded)
		decoded = truncateUTF8(decoded, n.cfg.MaxValueBytes)
		if decoded == canonical {
			break
		}
		canonical = decoded
	}
	if !n.appendCandidate(out, location, canonical) {
		return
	}
	if compatible, ok := foldL7CompatibilityASCII(canonical, n.cfg.MaxValueBytes); ok {
		if !n.appendCandidate(out, location+".compat", compatible) {
			return
		}
	}
	if escaped, ok := decodeL7TextEscapes(canonical, n.cfg.MaxValueBytes); ok {
		if !n.appendCandidate(out, location+".escaped", escaped) {
			return
		}
	}
	if decoded, ok := decodeTextBase64(canonical, n.cfg.MaxValueBytes); ok {
		decoded = canonicalizeL7DecodedText(decoded, n.cfg.MaxDecodeDepth, n.cfg.MaxValueBytes)
		if !n.appendCandidate(out, location+".base64", decoded) {
			return
		}
	}
	if decoded, ok := decodeTextHex(canonical, n.cfg.MaxValueBytes); ok {
		decoded = canonicalizeL7DecodedText(decoded, n.cfg.MaxDecodeDepth, n.cfg.MaxValueBytes)
		n.appendCandidate(out, location+".hex", decoded)
	}
}

func (n *L7Normalizer) appendCandidate(out *l7NormalizedRequest, location, value string) bool {
	if value == "" {
		return false
	}
	if len(out.Candidates) >= n.cfg.MaxDecodedValues {
		out.CandidateBudgetExceeded = true
		return false
	}
	value = truncateUTF8(value, n.cfg.MaxValueBytes)
	if value == "" {
		return false
	}
	remaining := n.cfg.MaxInspectionBytes - out.CandidateBytes
	if remaining < len(value) {
		out.CandidateBudgetExceeded = true
		return false
	}
	out.Candidates = append(out.Candidates, l7Candidate{Location: location, Value: value})
	out.CandidateBytes += len(value)
	return true
}
