// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"regexp"
	"strings"
	"testing"
)

func TestProtectionStatusBannerSitsOutsideStepperGrid(t *testing.T) {
	html := embeddedWebFile(t, "index.html")
	js := embeddedWebFile(t, "protection.js")
	appCSS := embeddedWebFile(t, "css/components.css")
	v4CSS := embeddedWebFile(t, "css/components.css")

	bannerIdx := strings.Index(html, `id="protectionStatusBanner"`)
	stepperIdx := strings.Index(html, `id="protectionStepperContainer"`)
	if bannerIdx < 0 || stepperIdx < 0 {
		t.Fatalf("missing protection banner (%d) or stepper container (%d) in index.html", bannerIdx, stepperIdx)
	}
	if bannerIdx > stepperIdx {
		t.Fatalf("protectionStatusBanner must precede protectionStepperContainer instead of sitting inside the 3-column grid")
	}

	stepperSectionPattern := regexp.MustCompile(`(?s)<div id="protectionStepperContainer" class="stepper-grid">(.*?)</div>\s*<div class="protection-actions-bar`)
	match := stepperSectionPattern.FindStringSubmatch(html)
	if match == nil {
		t.Fatal("could not locate protectionStepperContainer block in index.html")
	}
	if strings.Contains(match[1], "protectionStatusBanner") {
		t.Fatal("protectionStatusBanner must not be nested inside protectionStepperContainer")
	}

	if strings.Contains(js, "stepperContainer.prepend(statusBanner)") {
		t.Fatal("protection.js must not prepend protectionStatusBanner into the 3-column stepper grid")
	}
	if !strings.Contains(js, "insertBefore(statusBanner, stepperContainer)") {
		t.Fatal("protection.js must keep protectionStatusBanner positioned before stepperContainer")
	}

	for name, css := range map[string]string{"app.css": appCSS, "v4.css": v4CSS} {
		if !strings.Contains(css, ".protection-status-banner {") {
			t.Fatalf("%s does not style .protection-status-banner", name)
		}
		if !strings.Contains(css, ".protection-status-banner[hidden]") {
			t.Fatalf("%s does not preserve [hidden] behavior for .protection-status-banner", name)
		}
	}
}

func TestI18nRespectsQueryLanguageParameter(t *testing.T) {
	i18nJS := embeddedWebFile(t, "i18n.js")
	if !strings.Contains(i18nJS, "URLSearchParams") || !strings.Contains(i18nJS, ".get('lang')") {
		t.Fatal("i18n.js must honor the ?lang= URL query parameter cleanly")
	}
}
