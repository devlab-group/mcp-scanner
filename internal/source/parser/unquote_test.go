package parser

import "testing"

// A description written as a + chain of literals is its joined text, escapes are decoded, and a
// chain with anything but literals in it is not a fixed string
func TestUnquoteStringConcatenationAndEscapes(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{`'Fetch the page\'s HTML. ' +
          'Docs: https://help.example.com/x'`, "Fetch the page's HTML. Docs: https://help.example.com/x", true},
		{`"a" + 'b' + ` + "`c`", "abc", true},
		{`"line\nbreak \"quoted\""`, "line\nbreak \"quoted\"", true},
		{`r"C:\path\n"`, `C:\path\n`, true},
		{`'Hello ' + name`, "", false},
		{`'a' + fn('b')`, "", false},
		{`"plain"`, "plain", true},
	} {
		got, ok := UnquoteString(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("UnquoteString(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
