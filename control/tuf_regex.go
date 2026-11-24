// AP-9 / S09 — RE2 linear-complexity budget for feed/rule regex entries.
//
// The standard library regexp package is RE2 and therefore linear, but the
// guard still bounds the *shape* of every new or changed rule: rule documents
// are consumed by several components (XDR evaluation, L7 inspection, UI
// rendering), so an absurd pattern can exhaust memory or match work outside the
// RE2 fast path even when the engine itself is safe. The estimator below is
// deterministic and documented; it never depends on wall-clock measurements.
//
// Budget (all upper bounds):
//   - pattern length                 1024 bytes
//   - group nesting depth            12
//   - bounded repetition count       1024  ({n} / {n,m})
//   - nested repetition amplification 1024 (product of quantified group factors)
//
// Compilation failure under RE2 is always rejected first.

package main

import (
	"fmt"
	"regexp"
	"strings"
)

// TUFRegexBudget is the deterministic complexity estimate of one regex.
type TUFRegexBudget struct {
	Length        int
	Nesting       int
	MaxRepeat     int
	Amplification int
}

// tufRegexQuantifierAt parses one repetition operator starting at index and
// returns its repetition factor (2 for * and +, 1 for ?, the upper bound for
// {n}/{n,m}/{n,}). Malformed or absent operators return value 0.
func tufRegexQuantifierAt(pattern string, index int) (value int, next int) {
	if index < 0 || index >= len(pattern) {
		return 0, index
	}
	switch pattern[index] {
	case '*', '+':
		return 2, index + 1
	case '?':
		return 1, index + 1
	case '{':
		end := strings.IndexByte(pattern[index:], '}')
		if end < 0 {
			return 0, index
		}
		body := pattern[index+1 : index+end]
		value = 0
		for _, part := range strings.SplitN(body, ",", 2) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			parsed := 0
			for position := 0; position < len(part); position++ {
				if part[position] < '0' || part[position] > '9' {
					return 0, index
				}
				parsed = parsed*10 + int(part[position]-'0')
				if parsed > 1<<20 {
					parsed = 1 << 20
				}
			}
			value = parsed
		}
		if value <= 0 {
			return 0, index
		}
		return value, index + end + 1
	default:
		return 0, index
	}
}

func tufRegexSkipClass(pattern string, index int) int {
	position := index + 1
	for position < len(pattern) {
		if pattern[position] == '\\' {
			position += 2
			continue
		}
		if pattern[position] == ']' {
			return position + 1
		}
		position++
	}
	return len(pattern)
}

// tufRegexSaturatingMul multiplies two repetition factors without overflowing:
// anything above the amplification ceiling collapses to ceiling+1.
func tufRegexSaturatingMul(left, right, ceiling int) int {
	if left <= 0 || right <= 0 {
		return 0
	}
	if left > (ceiling+1)/right {
		return ceiling + 1
	}
	return left * right
}

// estimateTUFRegexBudget computes the documented complexity estimate:
//
//   - Length: raw pattern bytes.
//   - Nesting: maximum number of simultaneously open groups.
//   - MaxRepeat: largest bounded repetition count in {n} / {n,m} form.
//   - Amplification: product of repetition factors of *nested quantified
//     groups*. A quantified atom alone is linear (RE2), but a quantified group
//     that itself contains a quantified group multiplies the work of every
//     consumer that expands the rule. This is deterministic and documented:
//     "(a{500}){500}" yields 250000, "(a){500}" yields 500.
func estimateTUFRegexBudget(pattern string) TUFRegexBudget {
	capValue := DefaultTUFSemanticGuardLimits().RegexMaxAmplification
	budget := TUFRegexBudget{Length: len(pattern)}
	// frames holds the largest repetition factor of any atom inside each open
	// group. Index 0 is the top-level frame.
	frames := []int{1}
	depth := 0
	position := 0
	for position < len(pattern) {
		atomEnd := position
		switch pattern[position] {
		case '\\':
			atomEnd = position + 2
		case '[':
			atomEnd = tufRegexSkipClass(pattern, position)
		case '(':
			depth++
			if depth > budget.Nesting {
				budget.Nesting = depth
			}
			frames = append(frames, 1)
			position++
			continue
		case ')':
			if len(frames) == 1 {
				position++
				continue
			}
			inner := frames[len(frames)-1]
			frames = frames[:len(frames)-1]
			if factor, next := tufRegexQuantifierAt(pattern, position+1); factor > 0 {
				if factor > budget.MaxRepeat {
					budget.MaxRepeat = factor
				}
				inner = tufRegexSaturatingMul(inner, factor, capValue)
				position = next
			} else {
				position++
			}
			if inner > budget.Amplification {
				budget.Amplification = inner
			}
			if inner > frames[len(frames)-1] {
				frames[len(frames)-1] = inner
			}
			continue
		default:
			atomEnd = position + 1
		}
		position = atomEnd
		if factor, next := tufRegexQuantifierAt(pattern, position); factor > 0 {
			if factor > budget.MaxRepeat {
				budget.MaxRepeat = factor
			}
			if factor > frames[len(frames)-1] {
				frames[len(frames)-1] = factor
			}
			if factor > budget.Amplification {
				budget.Amplification = factor
			}
			position = next
		}
	}
	if budget.Amplification > capValue {
		budget.Amplification = capValue + 1
	}
	return budget
}

// validateTUFRegexPattern compiles the pattern with stdlib RE2 and enforces the
// documented complexity budget. Compilation failure is always a hard rejection.
func validateTUFRegexPattern(pattern string, limits TUFSemanticGuardLimits) error {
	if strings.TrimSpace(pattern) == "" {
		return newTUFError(TUFReasonRegexComplexity, "regex rule has an empty pattern")
	}
	if len(pattern) > limits.RegexMaxLength {
		return newTUFError(TUFReasonRegexComplexity,
			fmt.Sprintf("regex length %d exceeds the %d byte budget", len(pattern), limits.RegexMaxLength))
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return newTUFError(TUFReasonRegexComplexity, "regex does not compile under RE2")
	}
	budget := estimateTUFRegexBudget(pattern)
	if budget.Nesting > limits.RegexMaxNesting {
		return newTUFError(TUFReasonRegexComplexity,
			fmt.Sprintf("regex group nesting %d exceeds the %d budget", budget.Nesting, limits.RegexMaxNesting))
	}
	if budget.MaxRepeat > limits.RegexMaxRepeat {
		return newTUFError(TUFReasonRegexComplexity,
			fmt.Sprintf("regex repetition bound %d exceeds the %d budget", budget.MaxRepeat, limits.RegexMaxRepeat))
	}
	if budget.Amplification > limits.RegexMaxAmplification {
		return newTUFError(TUFReasonRegexComplexity,
			fmt.Sprintf("regex nested repetition amplification %d exceeds the %d budget", budget.Amplification, limits.RegexMaxAmplification))
	}
	return nil
}
