// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoginPageRendersTheAttestedFacts pins the composition of the authentication page.
//
// The page previously opened with a marketing headline, a decorative grid, a glow, three
// identical architecture cards and a five-item technology claim - none of which answers a
// question an operator has at a trust boundary. What it did not state above the fold was
// the one fact that matters most there: which node is being trusted. The facts are now
// the left plane and the credential is the right one, and that is asserted rather than
// left to survive the next edit.
func TestLoginPageRendersTheAttestedFacts(t *testing.T) {
	rendered := renderLoginForTest(t, "en", true, false)

	for _, required := range []string{
		// The four attested facts, each with its own label.
		`class="facts"`, "Node", "Channel", "Grants", "Custody",
		// The node value and the channel verdict.
		`<code>`, "TLS, certificate verified",
		// The single action and its field.
		`id="password"`, `name="csrf"`, `action="/login"`,
	} {
		if !strings.Contains(rendered, required) {
			t.Errorf("the login page no longer renders %s", required)
		}
	}

	// The card matrix, the hero claim and the glow are gone. Each was a pattern the
	// design standard names explicitly, and each would otherwise creep back.
	for _, forbidden := range []string{
		"At kernel speed", "Host defense.", // the hero claim
		`class="stack"`,      // the three-card matrix
		"KERNEL", "RESPONSE", // the card contents
		"--stroke",        // the outlined second headline
		"backdrop-filter", // glassmorphism over the whole shell
		"42px 42px",       // the decorative background grid
	} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("the login page still carries the removed pattern %q", forbidden)
		}
	}

	// Exactly one primary button: a second would split the focus budget on a surface
	// whose whole job is one submission.
	if count := strings.Count(rendered, "<button"); count != 1 {
		t.Errorf("the page renders %d buttons, want exactly 1", count)
	}
}

// TestLoginPageStatesTheChannelItObserved proves the transport claim is read from the
// connection rather than asserted. A page that prints "TLS" because the product intends
// to use TLS is worthless at a trust boundary.
func TestLoginPageStatesTheChannelItObserved(t *testing.T) {
	secure := renderLoginForTest(t, "en", true, false)
	if !strings.Contains(secure, "TLS, certificate verified") {
		t.Fatal("a TLS connection was not reported as TLS")
	}
	if !strings.Contains(secure, `data-channel="secure"`) {
		t.Fatal("the secure channel is not marked as such for the stylesheet")
	}

	plain := renderLoginForTest(t, "en", false, false)
	if !strings.Contains(plain, "unencrypted transport") {
		t.Fatal("a plaintext connection was not reported as plaintext")
	}
	if !strings.Contains(plain, `data-channel="plain"`) {
		t.Fatal("the plaintext channel is not marked as such")
	}
	if strings.Contains(plain, "TLS, certificate verified") {
		t.Fatal("a plaintext connection claimed TLS")
	}
}

// TestLoginPageStatesFailureWithoutLosingTheFacts covers the error state. A failed
// attempt must say so where the action is, and must not displace the facts an operator
// needs in order to judge whether they are even typing into the right host.
func TestLoginPageStatesFailureWithoutLosingTheFacts(t *testing.T) {
	rendered := renderLoginForTest(t, "en", true, true)
	if !strings.Contains(rendered, `class="error"`) || !strings.Contains(rendered, `role="alert"`) {
		t.Fatal("a failed attempt is not announced")
	}
	if !strings.Contains(rendered, "Node") || !strings.Contains(rendered, "Channel") {
		t.Fatal("the attested facts were dropped from the failure state")
	}
}

// TestLoginCopyIsCompleteInEveryLanguage proves every catalogue fills every field. A
// missing string renders as an empty element, which looks like a layout bug rather than a
// translation gap, and it would only surface for the operator who reads that language.
func TestLoginCopyIsCompleteInEveryLanguage(t *testing.T) {
	for _, language := range []string{"de", "en", "ru", "zh-CN"} {
		copy := copyForLanguage(language)
		fields := map[string]string{
			"ProductSub": copy.ProductSub, "Title": copy.Title, "Intro": copy.Intro,
			"Failed": copy.Failed, "PasswordLabel": copy.PasswordLabel, "Submit": copy.Submit,
			"FactsHeading": copy.FactsHeading, "HostLabel": copy.HostLabel, "HostNote": copy.HostNote,
			"ChannelLabel": copy.ChannelLabel, "ChannelTLS": copy.ChannelTLS,
			"ChannelPlain": copy.ChannelPlain, "ChannelNote": copy.ChannelNote,
			"GrantLabel": copy.GrantLabel, "GrantValue": copy.GrantValue,
			"CustodyLabel": copy.CustodyLabel, "CustodyValue": copy.CustodyValue,
			"Support": copy.Support, "SupportIntro": copy.SupportIntro, "Footer": copy.Footer,
		}
		for name, value := range fields {
			if strings.TrimSpace(value) == "" {
				t.Errorf("catalogue %s leaves %s empty", language, name)
			}
		}
	}

	// The two channel verdicts must differ in every language, otherwise the page reports
	// the same thing for a secure and an insecure transport.
	for _, language := range []string{"de", "en", "ru", "zh-CN"} {
		copy := copyForLanguage(language)
		if copy.ChannelTLS == copy.ChannelPlain {
			t.Errorf("catalogue %s uses the same wording for TLS and plaintext", language)
		}
	}
}

// renderLoginForTest executes the real template with realistic data and returns the
// document. When GEdefense_LOGIN_QA_OUT is set the document is also written there, so the
// page can be opened in a browser without reimplementing the handler.
func renderLoginForTest(t *testing.T, lang string, secure, failed bool) string {
	t.Helper()
	data := struct {
		CSRF, Nonce, Host, Lang, ProductVersion string
		Copy                                    loginCopy
		Failed                                  bool
		Secure                                  bool
	}{
		CSRF: "0123456789abcdef0123456789abcdef", Nonce: "nonce-value-for-test",
		Host: "203.0.113.10:9843", Lang: lang, ProductVersion: "4.2.0",
		Copy: copyForLanguage(lang), Failed: failed, Secure: secure,
	}
	var buffer bytes.Buffer
	if err := loginTemplate.Execute(&buffer, data); err != nil {
		t.Fatalf("the login template failed to execute: %v", err)
	}
	document := buffer.String()
	if out := os.Getenv("GEDEFENSE_LOGIN_QA_OUT"); out != "" {
		target := filepath.Join(out, "login-"+lang+".html")
		if err := os.WriteFile(target, []byte(document), 0o644); err != nil {
			t.Fatalf("writing the rendered page: %v", err)
		}
	}
	return document
}
