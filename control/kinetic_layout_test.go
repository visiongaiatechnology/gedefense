// STATUS: DIAMANT VGT SUPREME
package main

import (
	"strings"
	"testing"
)

// TestKineticStreamSitsUnderTheMapInTheLeftColumn locks the composition change.
//
// The map panel and the reaction stream describe the same traffic - where it came from
// and what the engine decided about it - and the intelligence stack beside them is
// taller than the map alone. Keeping the stream at the foot of the page left a void
// under the map and separated the two halves of one story. The structural contract is
// asserted here rather than trusted, because markup order is exactly the kind of thing
// a later edit rearranges without noticing.
func TestKineticStreamSitsUnderTheMapInTheLeftColumn(t *testing.T) {
	document, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(document)

	stackStart := strings.Index(html, `<div class="kinetic-left-stack"`)
	if stackStart < 0 {
		t.Fatal("the left column wrapper is gone; the map and the stream are no longer grouped")
	}
	stackEnd := matchingDivClose(t, html, stackStart)
	stack := html[stackStart:stackEnd]

	mapPanel := strings.Index(stack, "kinetic-map-panel")
	stream := strings.Index(stack, "kineticEventsTableBody")
	if mapPanel < 0 {
		t.Fatal("the map panel is not inside the left column")
	}
	if stream < 0 {
		t.Fatal("the event stream is not inside the left column")
	}
	if mapPanel > stream {
		t.Fatal("the event stream is rendered above the map; the map must lead")
	}

	// The stream must not also remain at the foot of the page, which would render it
	// twice and defeat the move.
	lowerStart := strings.Index(html, `<div id="kineticStream"`)
	if lowerStart < 0 {
		t.Fatal("the lower grid is gone; the forensic drawer has no container")
	}
	lowerEnd := matchingDivClose(t, html, lowerStart)
	lower := html[lowerStart:lowerEnd]
	if strings.Contains(lower, "kineticEventsTableBody") {
		t.Fatal("the event stream still appears in the lower grid as well as in the left column")
	}
	if !strings.Contains(lower, "kineticDetailDrawer") {
		t.Fatal("the forensic drawer is no longer in the lower grid")
	}

	// The lower grid now holds a single panel, so it must not reserve a second column.
	if strings.Contains(html[lowerStart:lowerEnd], `class="grid-2`) {
		t.Fatal("the lower grid still declares two columns for one panel")
	}
}

// matchingDivClose returns the index just past the </div> that closes the element whose
// opening tag starts at or after start. It counts nested div elements and ignores
// self-closing content, which is precise enough for a served document with no divs in
// attribute values.
func matchingDivClose(t *testing.T, html string, start int) int {
	t.Helper()
	depth := 0
	index := start
	for index < len(html) {
		nextOpen := strings.Index(html[index:], "<div")
		nextClose := strings.Index(html[index:], "</div>")
		if nextClose < 0 {
			t.Fatal("unbalanced div in the served document")
		}
		if nextOpen >= 0 && nextOpen < nextClose {
			depth++
			index += nextOpen + len("<div")
			continue
		}
		depth--
		index += nextClose + len("</div>")
		if depth == 0 {
			return index
		}
	}
	t.Fatal("unbalanced div in the served document")
	return 0
}

// TestKineticLeftStackHasStyles proves the wrapper the markup now depends on is
// actually styled. An unstyled wrapper would stack the two panels with no gap and no
// height sharing, which is a different layout, not the intended one.
func TestKineticLeftStackHasStyles(t *testing.T) {
	stylesheet, err := webAssets.ReadFile("web/v4.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(stylesheet)
	ruleStart := strings.Index(css, ".kinetic-left-stack {")
	if ruleStart < 0 {
		t.Fatal("the left column wrapper has no style rule")
	}
	ruleEnd := strings.Index(css[ruleStart:], "}")
	if ruleEnd < 0 {
		t.Fatal("the left column rule is unterminated")
	}
	rule := css[ruleStart : ruleStart+ruleEnd]
	for _, required := range []string{"display: grid", "grid-template-rows", "gap:"} {
		if !strings.Contains(rule, required) {
			t.Fatalf("the left column rule does not declare %q", required)
		}
	}
	// The map must be the element that absorbs the spare height, otherwise the void
	// simply moves into the stream instead of closing.
	if !strings.Contains(rule, "minmax(") {
		t.Fatal("the left column rule does not let the map absorb the remaining height")
	}
}
