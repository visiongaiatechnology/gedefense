// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

func truncateUTF8(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func decodeTextBase64(value string, maxBytes int) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if maxBytes <= 0 || len(trimmed) < 12 || len(trimmed) > base64.StdEncoding.EncodedLen(maxBytes)+4 || len(trimmed)%4 == 1 {
		return "", false
	}
	source := []byte(trimmed)
	decoded := make([]byte, maxBytes)
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, encoding := range encodings {
		if encoding.DecodedLen(len(source)) > len(decoded) {
			continue
		}
		n, err := encoding.Decode(decoded, source)
		if err != nil || n == 0 {
			continue
		}
		candidate := decoded[:n]
		if isMostlyText(candidate) && utf8.Valid(candidate) {
			return string(candidate), true
		}
	}
	return "", false
}

func canonicalizeL7DecodedText(value string, maxDepth, maxBytes int) string {
	value = truncateUTF8(value, maxBytes)
	for depth := 0; depth < maxDepth; depth++ {
		next := value
		if decoded, err := url.PathUnescape(next); err == nil {
			next = decoded
		}
		next = html.UnescapeString(next)
		if escaped, ok := decodeL7TextEscapes(next, maxBytes); ok {
			next = escaped
		}
		if compatible, ok := foldL7CompatibilityASCII(next, maxBytes); ok {
			next = compatible
		}
		next = truncateUTF8(next, maxBytes)
		if next == value {
			break
		}
		value = next
	}
	return value
}

func foldL7CompatibilityASCII(value string, maxBytes int) (string, bool) {
	if maxBytes <= 0 {
		return "", false
	}
	changed := false
	var builder strings.Builder
	builder.Grow(minInt(len(value), maxBytes))
	for _, r := range value {
		switch {
		case r == '\u3000':
			r = ' '
			changed = true
		case r >= '\uff01' && r <= '\uff5e':
			r -= 0xfee0
			changed = true
		}
		if builder.Len()+utf8.RuneLen(r) > maxBytes {
			break
		}
		builder.WriteRune(r)
	}
	if !changed {
		return "", false
	}
	return builder.String(), true
}

func decodeL7TextEscapes(value string, maxBytes int) (string, bool) {
	if maxBytes <= 0 || len(value) < 4 {
		return "", false
	}
	changed := false
	var builder strings.Builder
	builder.Grow(minInt(len(value), maxBytes))
	for i := 0; i < len(value); {
		var (
			runeValue rune
			consumed  int
			ok        bool
		)
		if i+4 <= len(value) && value[i] == '\\' && (value[i+1] == 'x' || value[i+1] == 'X') {
			runeValue, ok = parseL7EscapedRune(value[i+2:i+4], 8)
			consumed = 4
		} else if i+6 <= len(value) && value[i] == '\\' && (value[i+1] == 'u' || value[i+1] == 'U') {
			runeValue, ok = parseL7EscapedRune(value[i+2:i+6], 16)
			consumed = 6
		} else if i+6 <= len(value) && value[i] == '%' && (value[i+1] == 'u' || value[i+1] == 'U') {
			runeValue, ok = parseL7EscapedRune(value[i+2:i+6], 16)
			consumed = 6
		}
		if ok {
			size := utf8.RuneLen(runeValue)
			if size < 1 || builder.Len()+size > maxBytes {
				break
			}
			builder.WriteRune(runeValue)
			i += consumed
			changed = true
			continue
		}
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			return "", false
		}
		if builder.Len()+size > maxBytes {
			break
		}
		builder.WriteRune(r)
		i += size
	}
	if !changed {
		return "", false
	}
	return builder.String(), true
}

func parseL7EscapedRune(hexValue string, bits int) (rune, bool) {
	value, err := strconv.ParseUint(hexValue, 16, bits)
	if err != nil {
		return 0, false
	}
	r := rune(value)
	if r > utf8.MaxRune || (r >= 0xd800 && r <= 0xdfff) {
		return 0, false
	}
	return r, true
}

func decodeTextHex(value string, maxBytes int) (string, bool) {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "0x")
	if len(trimmed) < 16 || len(trimmed)%2 != 0 || len(trimmed) > maxBytes*2 {
		return "", false
	}
	decoded := make([]byte, hex.DecodedLen(len(trimmed)))
	if _, err := hex.Decode(decoded, []byte(trimmed)); err != nil || !isMostlyText(decoded) || !utf8.Valid(decoded) {
		return "", false
	}
	return string(decoded), true
}

func isMostlyText(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}
	printable := 0
	for _, b := range buf {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b != 0x7f) {
			printable++
		}
	}
	return printable*100/len(buf) >= 85
}
