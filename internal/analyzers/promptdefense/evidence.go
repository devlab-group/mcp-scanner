package promptdefense

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// snippetContext is how many bytes of surrounding text ride along with a
// match, on each side, so a reviewer sees enough to judge the finding
// without the whole description
const snippetContext = 40

// snippet extracts the text around [start,end) in s and escapes anything
// that is not a normal printable character. Scanned content is hostile
// input: without this, a zero-width character would render invisibly and a
// raw ANSI escape sequence in a description could rewrite the operator's
// terminal when the report is printed.
func snippet(s string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	if end < start {
		end = start
	}
	lo, hi := start-snippetContext, end+snippetContext
	if lo < 0 {
		lo = 0
	}
	if hi > len(s) {
		hi = len(s)
	}
	for lo > 0 && !utf8.RuneStart(s[lo]) {
		lo--
	}
	for hi < len(s) && !utf8.RuneStart(s[hi]) {
		hi++
	}

	out := escapeControl(s[lo:hi])
	if lo > 0 {
		out = "..." + out
	}
	if hi < len(s) {
		out += "..."
	}
	return out
}

// escapeControl renders control, format, private-use and hidden characters as a visible
// escape instead of the raw rune. It keeps plain newlines and tabs readable; everything
// else in those categories - zero-width spaces, bidi overrides, C0 control codes, a
// tag-block ASCII-smuggling payload - becomes text a terminal cannot act on.
func escapeControl(s string) string {
	var b strings.Builder
	for _, r := range s {
		_, hidden := hiddenCharNote(r)
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			b.WriteString(`\x`)
			b.WriteString(hexByte(byte(r)))
		case unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r) || unicode.Is(unicode.Cc, r) || hidden:
			b.WriteString(strconv.QuoteRune(r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hexByte(b byte) string {
	const hex = "0123456789abcdef"
	return string([]byte{hex[b>>4], hex[b&0xf]})
}
