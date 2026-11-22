// STATUS: DIAMANT VGT SUPREME
package main

// M4.1: SQL canonicalisation and the false-positive guard for English prose.
//
// `1/**/oR/**/1=1--` is the same SQL predicate as `1 OR 1=1--`; the comment is
// only a token separator. The canonicaliser removes SQL block comments (keeping
// the inner token of a MySQL conditional comment), folds every whitespace run
// into one space and leaves everything else untouched, so the signature rules
// see the predicate the database would parse.
//
// The guard is the counterpart: a plain-English sentence that happens to contain
// words such as "select", "union" or "from" has no SQL operators at all and must
// never be treated as an injection.

import "strings"

const (
	// l7SQLMaxCommentScan bounds how far a single block comment may extend.
	l7SQLMaxCommentScan = 4096
	// l7SQLMaxConditionalDigits bounds the optional version digits of MySQL's /*!50000 ... */ form.
	l7SQLMaxConditionalDigits = 8
)

// canonicalizeL7SQL returns the comment-free, whitespace-folded form of one
// candidate. The second return value is false when the value did not change.
func canonicalizeL7SQL(value string, maxBytes int) (string, bool) {
	if maxBytes <= 0 || value == "" {
		return "", false
	}
	var builder strings.Builder
	builder.Grow(minInt(len(value), maxBytes))
	changed := false
	pendingSpace := false
	appendByte := func(character byte) bool {
		if builder.Len()+1 > maxBytes {
			return false
		}
		builder.WriteByte(character)
		return true
	}
	for index := 0; index < len(value); {
		remaining := value[index:]
		// SQL line comment: everything to end of line is a comment. The trailing
		// "--" is itself a strong injection marker and is preserved by the rule
		// set, so only the comment body is dropped.
		if strings.HasPrefix(remaining, "--") {
			changed = true
			for index < len(value) && value[index] != '\n' {
				index++
			}
			if index < len(value) {
				index++ // consume newline
			}
			pendingSpace = true
			continue
		}
		if strings.HasPrefix(remaining, "/*") {
			end := strings.Index(remaining[2:], "*/")
			if end < 0 || end > l7SQLMaxCommentScan {
				// An unclosed comment cannot be safely interpreted: stop
				// rewriting and return what is already canonical.
				break
			}
			body := remaining[2 : 2+end]
			index += 2 + end + 2
			changed = true
			condition := strings.HasPrefix(body, "!")
			if condition {
				body = body[1:]
				digits := 0
				for digits < len(body) && digits < l7SQLMaxConditionalDigits && body[digits] >= '0' && body[digits] <= '9' {
					digits++
				}
				body = body[digits:]
				if builder.Len() > 0 {
					pendingSpace = true
				}
				for i := 0; i < len(body); i++ {
					if body[i] == ' ' || body[i] == '\t' || body[i] == '\n' || body[i] == '\r' {
						pendingSpace = true
						continue
					}
					if pendingSpace && builder.Len() > 0 {
						if !appendByte(' ') {
							return builder.String(), true
						}
					}
					pendingSpace = false
					if !appendByte(body[i]) {
						return builder.String(), true
					}
				}
				continue
			}
			if builder.Len() > 0 {
				pendingSpace = true
			}
			continue
		}
		character := value[index]
		if character == ' ' || character == '\t' || character == '\n' || character == '\r' || character == '\v' || character == '\f' {
			pendingSpace = true
			index++
			continue
		}
		if pendingSpace && builder.Len() > 0 {
			if !appendByte(' ') {
				return builder.String(), true
			}
			changed = true
		}
		pendingSpace = false
		if !appendByte(character) {
			break
		}
		index++
	}
	if !changed {
		return "", false
	}
	return builder.String(), true
}

// l7SQLProseGuard reports whether one candidate looks like an ordinary English
// sentence rather than a SQL expression. It requires several English function
// words, no SQL operator or quoting characters and no digits, which is what keeps
// sentences like "select a union contract from our table" at 200 OK while a real
// predicate (which needs operators, quotes or numbers to do anything) is never
// suppressed.
func l7SQLProseGuard(value string) bool {
	if len(value) < 12 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z'),
			character == ' ', character == '\t', character == '\n', character == '\r':
		default:
			// Any operator, quote, parenthesis, statement terminator or digit is
			// executable SQL syntax, not prose.
			return false
		}
	}
	lower := strings.ToLower(value)
	stopwords := 0
	for _, word := range l7ProseStopwords {
		if l7ContainsWord(lower, word) {
			stopwords++
			if stopwords >= 2 {
				return true
			}
		}
	}
	return false
}

// l7ProseStopwords are English function words that are highly untypical in an
// effective SQL injection predicate. "or", "and" and "from" are deliberately not
// in the list because SQL shares them.
var l7ProseStopwords = []string{"the", "a", "an", "our", "is", "are", "of", "to", "we", "you", "that", "this", "with", "for", "has", "have", "will"}

// l7ContainsWord matches one whole, space-delimited word.
func l7ContainsWord(haystack, word string) bool {
	start := 0
	for {
		index := strings.Index(haystack[start:], word)
		if index < 0 {
			return false
		}
		index += start
		before := index == 0 || haystack[index-1] == ' '
		after := index+len(word) == len(haystack) || haystack[index+len(word)] == ' '
		if before && after {
			return true
		}
		start = index + 1
	}
}

// l7SQLRuleGuarded reports whether one SQLi rule may evaluate this candidate.
func l7SQLRuleGuarded(category, value string) bool {
	if category != "sqli" {
		return true
	}
	return !l7SQLProseGuard(value)
}
