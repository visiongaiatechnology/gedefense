// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

type l7ResponseRule struct {
	id         string
	category   string
	summary    string
	severity   string
	score      int
	confidence int
	re         *regexp.Regexp
}

type l7ResponseDetector struct {
	rules []l7ResponseRule
}

func newL7ResponseDetector() (*l7ResponseDetector, error) {
	definitions := []l7PatternDefinition{
		{"L7.RESPONSE.SQL_ERROR", "information-disclosure", "Database error details were exposed in an HTTP response", "high", `(?i)(?:SQLSTATE\[[0-9A-Z]+\]|you have an error in your sql syntax|postgresql.*(?:error|fatal)|sqlite(?:3)?::?exception|ora-[0-9]{5})`, 80, 90},
		{"L7.RESPONSE.SOURCE_CODE", "information-disclosure", "Server-side source-code marker was exposed in an HTTP response", "critical", `(?i)(?:<\?(?:php|=)|<%@\s*page\b|<jsp:|\bimport\s+javax?\.servlet\b)`, 105, 94},
		{"L7.RESPONSE.STACK_TRACE", "information-disclosure", "Application stack trace was exposed in an HTTP response", "high", `(?m)(?:Traceback \(most recent call last\):|Exception in thread \"[^\"]+\"|\bat [A-Za-z0-9_.$]+\([^\r\n]+:[0-9]+\)|panic: [^\r\n]+)`, 75, 88},
		{"L7.RESPONSE.DIRECTORY_INDEX", "information-disclosure", "Directory index response was exposed", "medium", `(?i)<title>\s*index of /[^<]*</title>`, 55, 95},
		{"L7.RESPONSE.PRIVATE_KEY", "secret-disclosure", "Private-key material was exposed in an HTTP response", "critical", `-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`, 125, 99},
	}
	detector := &l7ResponseDetector{rules: make([]l7ResponseRule, 0, len(definitions))}
	for _, definition := range definitions {
		re, err := regexp.Compile(definition.pattern)
		if err != nil {
			return nil, fmt.Errorf("compile l7 response rule %s: %w", definition.id, err)
		}
		detector.rules = append(detector.rules, l7ResponseRule{
			id: definition.id, category: definition.category, summary: definition.summary,
			severity: definition.severity, score: definition.score, confidence: definition.confidence, re: re,
		})
	}
	return detector, nil
}

func (d *l7ResponseDetector) Detect(statusCode int, headers map[string][]string, body []byte) []L7Finding {
	if d == nil {
		return nil
	}
	findings := make([]L7Finding, 0, 4)
	contentEncoding := firstHeaderValue(headers, "content-encoding")
	contentType := strings.ToLower(firstHeaderValue(headers, "content-type"))
	if contentEncoding != "" && !strings.EqualFold(strings.TrimSpace(contentEncoding), "identity") {
		return findings
	}
	if len(body) > 0 && l7ResponseBodyInspectable(contentType, body) {
		text := string(body)
		for _, rule := range d.rules {
			if !rule.re.MatchString(text) {
				continue
			}
			findings = append(findings, newL7Finding(rule.id, rule.category, rule.severity, rule.score, rule.confidence, "response.body", text, rule.summary))
			if len(findings) >= 8 {
				break
			}
		}
	}
	if statusCode >= 500 && strings.Contains(strings.ToLower(firstHeaderValue(headers, "x-powered-by")), "php") {
		findings = append(findings, newL7Finding(
			"L7.RESPONSE.TECHNOLOGY_DISCLOSURE", "information-disclosure", "medium", 45, 90,
			"response.header.x-powered-by", firstHeaderValue(headers, "x-powered-by"), "Runtime technology disclosure accompanied a server error",
		))
	}
	return findings
}

func (e *L7Engine) InspectResponse(ctx context.Context, req l7NormalizedRequest, statusCode int, headers map[string][]string, bodyPrefix []byte) ([]L7Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e == nil || e.responseDetector == nil {
		return nil, nil
	}
	findings := e.responseDetector.Detect(statusCode, headers, bodyPrefix)
	if len(findings) == 0 {
		return nil, nil
	}
	_, _, unique := aggregateL7Findings(findings)
	if e.xdr != nil {
		e.xdr.RecordL7ResponseInspection(req, statusCode, unique)
	}
	return unique, nil
}

func l7ResponseBodyInspectable(contentType string, body []byte) bool {
	if strings.HasPrefix(contentType, "text/") || strings.Contains(contentType, "json") || strings.Contains(contentType, "xml") || strings.Contains(contentType, "javascript") {
		return true
	}
	return contentType == "" && isMostlyText(body)
}

func firstHeaderValue(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}
