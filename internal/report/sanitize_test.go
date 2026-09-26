package report

import (
	"strings"
	"testing"
)

func TestSanitizeEscapesANSI(t *testing.T) {
	in := "tool description\x1b[2J\x1b[H(screen cleared)"
	out := Sanitize(in)
	if out == in {
		t.Fatal("ESC byte was not touched")
	}
	for _, r := range out {
		if r < 0x20 {
			t.Fatalf("output still contains a raw control byte: %q", out)
		}
	}
}

func TestSanitizePassesThroughOrdinaryText(t *testing.T) {
	in := "a normal tool description with no control characters at all"
	if Sanitize(in) != in {
		t.Fatalf("ordinary text was altered: %q", Sanitize(in))
	}
}

func TestSanitizeEscapesNewlineAndTab(t *testing.T) {
	in := "evil.go\nINFO\tfake.rule\t\"no issues found\""
	out := Sanitize(in)
	if strings.ContainsAny(out, "\n\t") {
		t.Fatalf("Sanitize left a raw newline or tab in the output, which can forge table rows: %q", out)
	}
	if !strings.Contains(out, `\x0a`) || !strings.Contains(out, `\x09`) {
		t.Fatalf("expected escaped \\x0a (newline) and \\x09 (tab) markers in output: %q", out)
	}
}

func TestSanitizeEscapesBidiOverride(t *testing.T) {
	const rlo = "‮"
	in := "gpj." + rlo + "og.evil.go"
	out := Sanitize(in)
	if strings.ContainsRune(out, '‮') {
		t.Fatalf("RLO character passed through unescaped: %q", out)
	}
	if !strings.Contains(out, `\u202e`) {
		t.Fatalf("expected an escaped \\u202e marker, got: %q", out)
	}
}

func TestSanitizeEscapesZeroWidthAndBOM(t *testing.T) {
	for _, r := range []rune{0x200b, 0x200c, 0x200d, 0xfeff} {
		in := "look" + string(r) + "safe"
		out := Sanitize(in)
		if strings.ContainsRune(out, r) {
			t.Fatalf("zero-width/BOM character U+%04X passed through unescaped: %q", r, out)
		}
	}
}

func TestSanitizeEscapesLineSeparatorsAndDirectionalMarks(t *testing.T) {
	for _, r := range []rune{0x2028, 0x2029, 0x200e, 0x200f, 0x061c} {
		in := "look" + string(r) + "safe"
		out := Sanitize(in)
		if strings.ContainsRune(out, r) {
			t.Fatalf("character U+%04X passed through unescaped: %q", r, out)
		}
	}
}

func TestSanitizeBlockEscapesLineAndParagraphSeparators(t *testing.T) {
	for _, r := range []rune{0x2028, 0x2029} {
		out := SanitizeBlock("line one" + string(r) + "line two")
		if strings.ContainsRune(out, r) {
			t.Fatalf("U+%04X passed through SanitizeBlock unescaped: %q", r, out)
		}
	}
}

// A wide rune must not collide with an unrelated byte value once escaped:
// hexByte alone truncates anything above 0xff
func TestEscapeRuneDoesNotTruncateWideRunes(t *testing.T) {
	wide := escapeRune(0x202e)
	narrow := escapeRune(0x2e) // same low byte as 0x202e
	if wide == narrow {
		t.Fatalf("a wide rune's escape collided with a narrow one: %q == %q", wide, narrow)
	}
	if !strings.Contains(wide, "202e") {
		t.Fatalf("wide rune escape does not show the full code point: %q", wide)
	}
}

func TestSanitizeBlockAlsoEscapesBidiOverride(t *testing.T) {
	const rlo = "‮"
	out := SanitizeBlock("line one\n" + rlo + "line two")
	if strings.ContainsRune(out, '‮') {
		t.Fatalf("RLO character passed through SanitizeBlock unescaped: %q", out)
	}
	if !strings.Contains(out, "\n") {
		t.Fatal("SanitizeBlock must still preserve the genuine newline")
	}
}

func TestSanitizeEscapesInvisibleFormattingAndTags(t *testing.T) {
	for _, r := range []rune{0x00ad, 0x034f, 0x180e, 0xfe00, 0xfe0f, 0xe0000, 0xe007f} {
		in := "look" + string(r) + "safe"
		out := Sanitize(in)
		if strings.ContainsRune(out, r) {
			t.Fatalf("character U+%04X passed through unescaped: %q", r, out)
		}
	}
}

func TestSanitizeEscapesVariationSelectorSupplementAndFillers(t *testing.T) {
	for _, r := range []rune{0xe0100, 0xe01ef, 0x3164, 0xffa0} {
		in := "look" + string(r) + "safe"
		out := Sanitize(in)
		if strings.ContainsRune(out, r) {
			t.Fatalf("character U+%04X passed through unescaped: %q", r, out)
		}
	}
}

func TestSanitizeBlockKeepsNewlineButNotOtherControls(t *testing.T) {
	in := "line one\nline two\x1b[2Jline three"
	out := SanitizeBlock(in)
	if !strings.Contains(out, "\n") {
		t.Fatal("SanitizeBlock must preserve a genuine newline")
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Fatal("SanitizeBlock must still escape ESC and other non-newline control bytes")
	}
	if !strings.Contains(out, "line one") || !strings.Contains(out, "line two") || !strings.Contains(out, "line three") {
		t.Fatalf("content was altered beyond escaping controls: %q", out)
	}
}

func TestSanitizeDistinguishesALiteralMarkerFromARealControl(t *testing.T) {
	forged := Sanitize(`foo\x1b[31m`)
	genuine := Sanitize("foo\x1b[31m")
	if forged == genuine {
		t.Fatalf("literal text and a real control character sanitize identically: %q", forged)
	}
	if strings.Contains(genuine, `\\`) {
		t.Fatalf("a real ESC must still produce a single-backslash marker, got %q", genuine)
	}
	if !strings.Contains(forged, `\\x1b`) {
		t.Fatalf("expected the literal backslash to be escaped, got %q", forged)
	}
}

// SanitizeBlock allows a newline through; it is no less an escape
// function for that, so the same ambiguity has to be closed there too
func TestSanitizeBlockEscapesTheBackslashToo(t *testing.T) {
	forged := SanitizeBlock(`line\x0dINFO`)
	genuine := SanitizeBlock("line\rINFO")
	if forged == genuine {
		t.Fatalf("literal text and a real control character sanitize identically: %q", forged)
	}
	if got := SanitizeBlock("a\nb"); got != "a\nb" {
		t.Fatalf("a genuine newline must still pass through SanitizeBlock, got %q", got)
	}
}

func TestSanitizeEscapesC1Controls(t *testing.T) {
	for _, r := range []rune{0x85, 0x9b, 0x9d, 0x80, 0x9f} {
		in := "tool" + string(r) + "name"
		got := Sanitize(in)
		if strings.ContainsRune(got, r) {
			t.Errorf("Sanitize(%q) left U+%04X in place: %q", in, r, got)
		}
	}
}
