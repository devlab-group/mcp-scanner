package taint

import (
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

func TestContainmentRootValues(t *testing.T) {
	vacuous := []string{`"/"`, `"//"`, `""`, `'/'`, "`/`", `"\\"`, ` "/" `}
	for _, v := range vacuous {
		if !isVacuousRoot(v) {
			t.Errorf("isVacuousRoot(%s) = false, want true: a guard against it can never be taken", v)
		}
	}

	real := []string{`"/srv/notes"`, `"/srv/notes/"`, `ROOT`, `root`, `"/a/"`, `notesRoot + string(os.PathSeparator)`}
	for _, v := range real {
		if isVacuousRoot(v) {
			t.Errorf("isVacuousRoot(%s) = true, want false", v)
		}
	}

	anchored := []string{
		`"/srv/notes/"`,
		`ROOT + path.sep`,
		`notesRoot + string(os.PathSeparator)`,
		`root + string(filepath.Separator)`,
		`ROOT + File.separator`,
		`ROOT + "/"`,
	}
	for _, v := range anchored {
		if !isAnchoredValue(v) {
			t.Errorf("isAnchoredValue(%s) = false, want true: this is a correct guard and would be reported", v)
		}
	}

	unanchored := []string{`"/srv/notes"`, `ROOT`, `notesRoot`, `"/srv/notes-x"`}
	for _, v := range unanchored {
		if isAnchoredValue(v) {
			t.Errorf("isAnchoredValue(%s) = true, want false: a sibling directory passes this check", v)
		}
	}
}

func TestPropagatedTaintDropsNormalized(t *testing.T) {
	tainted := map[string]taintInfo{"clean": {confidence: 1, normalized: true}}

	joined := []string{
		`notesRoot + string(os.PathSeparator) + clean`,
		`ROOT + "/" + clean`,
		`f"{NOTES}/{clean}"`,
		`NOTES / clean`,
	}
	for _, expr := range joined {
		info, ok := propagatedTaint(expr, tainted)
		if !ok {
			t.Fatalf("propagatedTaint(%s) lost the taint entirely", expr)
		}
		if info.normalized {
			t.Errorf("propagatedTaint(%s).normalized = true: the guard would accept a prefix test on a string assembled after the last normalizing call", expr)
		}
	}

	for _, expr := range []string{`clean`, ` clean `} {
		info, ok := propagatedTaint(expr, tainted)
		if !ok {
			t.Fatalf("propagatedTaint(%q) lost the taint entirely", expr)
		}
		if !info.normalized {
			t.Errorf("propagatedTaint(%q).normalized = false: nothing was appended, so a correct containment guard on the renamed value would now be reported", expr)
		}
	}
}

func TestContainmentConjunction(t *testing.T) {
	cases := []struct {
		cond      string
		predicate string
		subject   string
		id        language.ID
		want      bool
	}{
		// Correct guards, all of which must stay honoured
		{`!strings.HasPrefix(full, notesRoot+string(os.PathSeparator))`, "HasPrefix", "full", language.Go, true},
		{`full != notesRoot && !strings.HasPrefix(full, notesRoot+string(os.PathSeparator))`, "HasPrefix", "full", language.Go, true},
		{`(resolved !== ROOT && !resolved.startsWith(ROOT + path.sep))`, "startsWith", "resolved", language.TypeScript, true},
		{`err != nil || strings.HasPrefix(rel, "..")`, "HasPrefix", "rel", language.Go, true},
		{`not full.is_relative_to(NOTES)`, "is_relative_to", "full", language.Python, true},
		// "and" inside a longer identifier is not the operator
		{`not full.is_relative_to(SANDBOX_ROOT)`, "is_relative_to", "full", language.Python, true},
		{`full != NOTES and not full.is_relative_to(NOTES)`, "is_relative_to", "full", language.Python, true},
		// A && inside an argument list or a string literal is not a
		// conjunction of the condition
		{`(!full.startsWith(ROOT + "/" + a(b && c)))`, "startsWith", "full", language.JavaScript, true},
		{`(!full.startsWith(ROOT + "/&&"))`, "startsWith", "full", language.JavaScript, true},

		// Guards whose exit is conditional on something the containment
		// check does not control
		{`(STRICT && !full.startsWith(ROOT + path.sep))`, "startsWith", "full", language.TypeScript, false},
		{`(!full.startsWith(ROOT + path.sep) && STRICT)`, "startsWith", "full", language.TypeScript, false},
		{`strict and not full.is_relative_to(NOTES)`, "is_relative_to", "full", language.Python, false},
		{`name != "" && !strings.HasPrefix(full, notesRoot+string(os.PathSeparator))`, "HasPrefix", "full", language.Go, false},
		{`audit(full) && !full.startsWith(ROOT + path.sep)`, "startsWith", "full", language.JavaScript, false},
	}
	for _, c := range cases {
		at := strings.Index(c.cond, c.predicate)
		if at < 0 {
			t.Fatalf("test case is wrong: %q does not contain %q", c.cond, c.predicate)
		}
		if got := soleDecidingConjunct(c.cond, at, c.subject, c.id); got != c.want {
			t.Errorf("soleDecidingConjunct(%q, %s) = %v, want %v", c.cond, c.subject, got, c.want)
		}
	}
}

func TestMaskLiteralText(t *testing.T) {
	hidden := []struct{ expr, name string }{
		// Mask words inside the literal without masking the adjacent (name,) argument
		{`"SELECT id FROM users WHERE name = ?", (name,)`, "users"},
		{`"SELECT id FROM users WHERE name = $1"`, "name"},
		{"`SELECT id FROM users WHERE name = $1`", "name"},
		{`'a path called name'`, "name"},
	}
	for _, c := range hidden {
		if mentionsIdent(maskLiteralText(c.expr), c.name) {
			t.Errorf("maskLiteralText(%s) still shows %q: a name inside a literal is text, not the variable", c.expr, c.name)
		}
	}

	visible := []struct{ expr, name string }{
		{`"SELECT id FROM users WHERE name = '" + name + "'"`, "name"},
		{"`SELECT id FROM users WHERE name = '${name}'`", "name"},
		{`f"SELECT id FROM users WHERE name = '{name}'"`, "name"},
		{`"SELECT id FROM users WHERE name = {}".format(name)`, "name"},
		{`fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name)`, "name"},
		{`"SELECT id FROM users WHERE name = ?", (name,)`, "name"},

		{`"a\"b" + name`, "name"},
		{`"cd C:\\" + name`, "name"},
	}
	for _, c := range visible {
		if !mentionsIdent(maskLiteralText(c.expr), c.name) {
			t.Errorf("maskLiteralText(%s) hid %q: the value reaching the sink is no longer visible", c.expr, c.name)
		}
	}
}

func TestMaskLiteralTextUnclosed(t *testing.T) {
	// Assembled from pieces because the data is backticks and backslashes,
	// which no Go string literal renders legibly
	tick, esc := "`", `\`
	unclosed := []string{
		tick + "grep -rn --color=never " + esc + tick + ` + " " + in.Pattern`,
		tick + "set -e\ncd /data\ngrep " + esc + tick + ` + in.Pattern`,
	}
	for _, expr := range unclosed {
		if !mentionsIdent(maskLiteralText(expr), "Pattern") {
			t.Errorf("maskLiteralText(%q) hid the identifier: an expression whose literal never closed has to come back unmasked, not blanked", expr)
		}
	}

	// A Rust lifetime opens a quote with no partner, and reaches the same
	// floor for the same reason
	if !mentionsIdent(maskLiteralText(`run::<'a>(name)`), "name") {
		t.Error("a lone quote blanked the rest of the expression")
	}
}

func TestEscapedAt(t *testing.T) {
	tick, esc := "`", `\`
	rawGo := tick + "a" + esc + tick
	cases := []struct {
		text  string
		idx   int
		quote byte
		id    language.ID
		want  bool
	}{
		{`"a\"b"`, 3, '"', language.JavaScript, true},
		// Two backslashes escape each other, leaving the quote itself
		// unescaped: this literal is closed
		{`"a\\"`, 4, '"', language.JavaScript, false},
		// No byte is an escape inside a Go raw string
		{rawGo, 3, '`', language.Go, false},
		// The same text in a JavaScript template literal, where the backslash does escape it
		{rawGo, 3, '`', language.JavaScript, true},
		{`"ab"`, 3, '"', language.Go, false},
	}
	for _, c := range cases {
		if got := escapedAt(c.text, c.idx, c.quote, c.id); got != c.want {
			t.Errorf("escapedAt(%q, %d, %q, %v) = %v, want %v", c.text, c.idx, c.quote, c.id, got, c.want)
		}
	}
}

func TestContainmentSubjectSurvivesEveryReceiverShape(t *testing.T) {
	conditions := []struct {
		cond string
		id   language.ID
	}{
		{`not Path(NOTES / name).resolve().is_relative_to(NOTES)`, language.Python},
		{`!path.resolve(ROOT, name).startsWith(ROOT + path.sep)`, language.JavaScript},
		{`!Paths.get(ROOT, name).normalize().startsWith(ROOT)`, language.Java},
		{`!parts[0].startsWith(ROOT + "/")`, language.JavaScript},
		{`!(full).startsWith(ROOT + "/")`, language.JavaScript},
		{`!"literal".startsWith(ROOT + "/")`, language.JavaScript},
		{`!full.startsWith(ROOT + "/")`, language.JavaScript},
		{`.startsWith(ROOT)`, language.JavaScript},
		{`!.is_relative_to(NOTES)`, language.Python},
	}
	for _, c := range conditions {
		for _, p := range containmentPredicates {
			// The point is that none of these panics; what each returns is
			// pinned by the corpus, not here
			p.subjectIn(c.id, c.cond)
		}
	}
}
