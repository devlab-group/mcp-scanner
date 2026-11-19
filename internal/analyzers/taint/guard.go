package taint

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// guardIndex finds an input check between a tool argument's source and the point where its value
// leaves the handler: a call to a validation-named function, or a pattern, prefix or allowlist test,
// followed within a few lines by an early exit (return, throw, raise). It reads source text, so it
// decides nothing: a finding behind such a check goes to needs_review, never away.
type guardIndex struct {
	root  string
	files map[string][]string
}

// guardWindow is how many lines after a check its early exit may appear
const guardWindow = 6

var (
	earlyExit  = regexp.MustCompile(`\b(return|throw|raise)\b|\bpanic\(|\babort\(`)
	assignFrom = regexp.MustCompile(`^\s*(?:const|let|var|final|val)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?:?=[^=]`)
)

func (gi guardIndex) lines(file string) []string {
	if ls, ok := gi.files[file]; ok {
		return ls
	}
	b, err := os.ReadFile(filepath.Join(gi.root, file))
	var ls []string
	if err == nil && len(b) < 4<<20 {
		ls = strings.Split(string(b), "\n")
	}
	gi.files[file] = ls
	return ls
}

// before returns the check's text and line when the path's source value is checked in the source's
// file before the next step of the path in that file
func (gi guardIndex) before(path []model.FlowStep) (string, int, bool) {
	if len(path) < 2 || path[0].Symbol == "" || !isGuardIdent(path[0].Symbol) {
		return "", 0, false
	}
	src := path[0]
	stop := 0
	for _, st := range path[1:] {
		if st.File == src.File && st.Line > src.Line {
			stop = st.Line
			break
		}
	}
	ls := gi.lines(src.File)
	if stop == 0 || stop > len(ls) || stop-src.Line > 400 {
		return "", 0, false
	}
	vars := []string{src.Symbol}
	for n := src.Line; n < stop; n++ {
		line := ls[n-1]
		// a value derived from a checked variable in one assignment: normalized = f(url)
		if m := assignFrom.FindStringSubmatch(line); m != nil && mentionsVar(line[len(m[0])-1:], vars) && !hasString(vars, m[1]) {
			vars = append(vars, m[1])
		}
		for _, v := range vars {
			if !checks(line, v) {
				continue
			}
			end := min(n+guardWindow, stop-1, len(ls))
			for k := n; k <= end; k++ {
				if earlyExit.MatchString(ls[k-1]) {
					return strings.TrimSpace(clipText(line, 100)), n, true
				}
			}
		}
	}
	return "", 0, false
}

// checks reports whether line tests v: validate(v), isSafe(v), v.match(/^https:\/\/x\//),
// /re/.test(v), re.match(p, v), v.startswith("..."), v in ALLOWED, ALLOWED.includes(v)
func checks(line, v string) bool {
	q := regexp.QuoteMeta(v)
	pats := []string{
		`(?i)\b_*(validate|sanitize|sanitise|check|ensure|verify|assert|is_?safe|is_?valid|is_?allowed|allowed)\w*\s*\(\s*` + q + `\b`,
		`\b` + q + `\s*\.\s*(match|test|startsWith|startswith|endsWith|endswith|fullmatch|matches|HasPrefix)\s*\(`,
		`\.(test|match|fullmatch|search|MatchString)\s*\(\s*(?:[^,()]+,\s*)?` + q + `\b`,
		`\bstrings\.HasPrefix\s*\(\s*` + q + `\b`,
		`\b` + q + `\s+not\s+in\s+\w+|\b` + q + `\s+in\s+[A-Z_]{3,}\b`,
		`\.(includes|has|contains)\s*\(\s*` + q + `\s*\)`,
	}
	for _, p := range pats {
		if regexp.MustCompile(p).MatchString(line) {
			return true
		}
	}
	return false
}

func isGuardIdent(s string) bool {
	return regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(s)
}

func mentionsVar(s string, vs []string) bool {
	for _, v := range vs {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(v) + `\b`).MatchString(s) {
			return true
		}
	}
	return false
}

func hasString(vs []string, v string) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}

func clipText(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func guardIfHigh(gi guardIndex, sev model.Severity, path []model.FlowStep) (string, int, bool) {
	if !sev.AtLeast(model.SeverityHigh) {
		return "", 0, false
	}
	return gi.before(path)
}
