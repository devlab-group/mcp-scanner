package promptdefense

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// normalizeForMatching folds spacing, punctuation, markup, and selected look-alike characters so
// ASCII rules can match common spelling variants. The caller adds the fold as a separate unit; a
// match found only there quotes the normalized unit as evidence.
func normalizeForMatching(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r':
			b.WriteRune(r)
		case r == '\t' || unicode.Is(unicode.Zs, r):
			b.WriteByte(' ')
		case unicode.Is(unicode.Mn, r):
			// A combining acute over an ASCII letter leaves the letter
		case r == '*' || r == '~':
			// Markdown emphasis around a word, not part of it
		default:
			b.WriteRune(foldRune(r))
		}
	}
	out := b.String()
	out = htmlTag.ReplaceAllString(out, "")
	out = underscoreEmphasis.ReplaceAllString(out, "$1")
	out = repeatedSpace.ReplaceAllString(out, " ")
	return out, out != s
}

var (
	// A short tag only: an angle bracket followed by a paragraph of text
	// is prose, not markup, and <IMPORTANT> is the shape that matters
	htmlTag = regexp.MustCompile(`</?[A-Za-z][A-Za-z0-9-]{0,30}(\s[^<>]{0,80})?/?>`)
	// _word_ is emphasis; api_key is one identifier. Only a run bounded by
	// underscores on both sides with no underscore inside is folded.
	underscoreEmphasis = regexp.MustCompile(`_([^\s_][^_]{0,80})_`)
	repeatedSpace      = regexp.MustCompile(`  +`)
)

// foldRune maps one rune onto its ASCII twin: the punctuation a word
// processor substitutes, the full-width and mathematical alphanumeric
// forms, and the Cyrillic and Greek letters findConfusables already knows
// are look-alikes. A rune with no twin is returned unchanged.
func foldRune(r rune) rune {
	if r < utf8.RuneSelf {
		return r
	}
	if a, ok := asciiPunct[r]; ok {
		return a
	}
	if a, ok := confusableToLatin[r]; ok {
		return a
	}
	// Halfwidth and Fullwidth Forms: the full-width block is the ASCII
	// printable range shifted by a constant
	if r >= 0xFF01 && r <= 0xFF5E {
		return r - 0xFEE0
	}
	// Mathematical Alphanumeric Symbols. The Latin series runs in blocks
	// of 52 - A-Z then a-z - from bold through monospace; the digit series
	// runs in blocks of 10. A few slots are holes where the character was
	// already encoded elsewhere, and mapping a hole arithmetically still
	// lands on the letter it stands for.
	switch {
	case r >= 0x1D400 && r <= 0x1D6A3:
		i := (r - 0x1D400) % 52
		if i < 26 {
			return 'A' + i
		}
		return 'a' + (i - 26)
	case r >= 0x1D7CE && r <= 0x1D7FF:
		return '0' + (r-0x1D7CE)%10
	}
	return r
}

var asciiPunct = map[rune]rune{
	'‘': '\'', '’': '\'', '‚': '\'', '‛': '\'',
	'′': '\'', 'ʼ': '\'', '＇': '\'',
	'“': '"', '”': '"', '„': '"', '‟': '"', '″': '"',
	'‐': '-', '‑': '-', '‒': '-', '–': '-',
	'—': '-', '―': '-', '−': '-',
}

// confusableToLatin maps selected Cyrillic and Greek look-alikes so rules see the word a reader
// sees. Mixed-script detection is broader and does not use this map.
var confusableToLatin = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
	'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j',
	'һ': 'h', 'ԛ': 'q', 'ԝ': 'w', 'к': 'k', 'в': 'b',
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M',
	'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T',
	'У': 'Y', 'Х': 'X', 'Ѕ': 'S', 'І': 'I', 'Ј': 'J',
	'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'υ': 'u',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H',
	'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
	'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}
