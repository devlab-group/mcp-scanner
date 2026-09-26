// Package report holds what every output writer (json, sarif, table,
// summary) shares
package report

import (
	"fmt"
	"strings"
)

// Sanitize escapes control, bidi, zero-width, separator, tag, and backslash
// characters before untrusted text reaches terminals or delimited formats.
// SanitizeBlock is the multiline variant.
func Sanitize(s string) string {
	if !strings.ContainsFunc(s, needsEscape) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if needsEscape(r) {
			b.WriteString(escapeRune(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SanitizeBlock preserves literal newline bytes but escapes every other unsafe rune. Unicode
// line and paragraph separators receive no exception because they can alter rendered structure.
func SanitizeBlock(s string) string {
	if !strings.ContainsFunc(s, needsEscapeInBlock) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if needsEscapeInBlock(r) {
			b.WriteString(escapeRune(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// needsEscape identifies backslashes and runes that alter terminal state,
// delimited structure, or rendered appearance instead of displaying normally
func needsEscape(r rune) bool {
	switch {
	case r < 0x20 || r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		// The C1 controls. xterm and urxvt interpret a UTF-8 C1 in UTF-8 mode, so U+009B is "ESC ["
		// there and U+009D opens an OSC: a tool name carrying one can recolour, clear or retitle
		// the operator's terminal even though it cannot forge a row.
		return true
	case r == '\\':
		// Escape the marker prefix too, keeping sanitization injective: literal "\\x1b" must
		// remain distinguishable from a marker produced for a real ESC byte
		return true
	case r == 0x2028 || r == 0x2029:
		return true // LINE SEPARATOR, PARAGRAPH SEPARATOR
	case r == 0x061c:
		return true // ARABIC LETTER MARK
	case r >= 0x202a && r <= 0x202e:
		return true // LRE, RLE, PDF, LRO, RLO
	case r >= 0x2066 && r <= 0x2069:
		return true // LRI, RLI, FSI, PDI
	case r >= 0x200b && r <= 0x200f:
		return true // zero-width space, ZWNJ, ZWJ, LRM, RLM
	case r == 0xfeff:
		return true // zero-width no-break space / byte-order mark
	case r == 0x00ad:
		return true // SOFT HYPHEN
	case r == 0x034f:
		return true // COMBINING GRAPHEME JOINER
	case r == 0x180e:
		return true // MONGOLIAN VOWEL SEPARATOR
	case r >= 0xfe00 && r <= 0xfe0f:
		return true // variation selectors 1-16
	case r >= 0xe0100 && r <= 0xe01ef:
		return true // variation selectors 17-256 (supplement)
	case r == 0x3164:
		return true // HANGUL FILLER: renders as blank in most terminals
	case r == 0xffa0:
		return true // HALFWIDTH HANGUL FILLER: same, halfwidth form
	case r >= 0xe0000 && r <= 0xe007f:
		return true // tag characters: render invisibly, can carry a hidden suffix onto a visible name
	default:
		return false
	}
}

// needsEscapeInBlock is needsEscape with \n let through
func needsEscapeInBlock(r rune) bool {
	return r != '\n' && needsEscape(r)
}

// escapeRune renders r as a visible, harmless marker. Runes wider than a byte keep their full
// code point so distinct bidi or zero-width characters cannot collapse to the same escape.
func escapeRune(r rune) string {
	if r == '\\' {
		return `\\`
	}
	if r >= 0 && r <= 0xff {
		return `\x` + hexByte(byte(r))
	}
	return fmt.Sprintf(`\u%04x`, r)
}

func hexByte(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0xf]})
}
