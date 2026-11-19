package taint

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// guardIndex finds an input check between a tool argument's source and the point where its value
// leaves the handler: a call to a validation-named function, or a pattern, prefix or allowlist test,
// followed within a few lines by an early exit (return, throw, raise). It reads source text, so it
// decides nothing: a finding behind such a check goes to needs_review, never away.
type guardIndex struct {
	root  string
	files map[string][]string
	g     *graph.Graph
	// callee caches inCallee's answer per symbol: the same helpers sit on many findings' paths
	callee map[graph.SymbolID]calleeGuard
	// byName indexes symbols by name once, instead of a walk of every symbol per path step
	byName map[string][]*graph.Symbol
}

type calleeGuard struct {
	text string
	line int
	ok   bool
}

// guardWindow is how many lines after a check its early exit may appear
const guardWindow = 6

var (
	earlyExit = regexp.MustCompile(`\b(return|throw|raise)\b|\bpanic\(|\babort\(`)
	// errorExit is an exit that rejects: it throws, raises, or returns an error. A check followed
	// only by a plain return (if (src.match(/^data:/)) return decoded) picks a branch instead.
	errorExit  = regexp.MustCompile(`\b(throw|raise)\b|\bpanic\(|\babort\(|return\s+.*\b(err|error|Error|errorResponse|isError|toolError|None|null|false)\b|return\s+fmt\.Errorf|return\s*;?\s*$`)
	assignFrom = regexp.MustCompile(`^\s*(?:const|let|var|final|val)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?:?=[^=]`)
)

func (gi *guardIndex) lines(file string) []string {
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
func (gi *guardIndex) before(path []model.FlowStep) (string, int, bool) {
	if g, n, ok := gi.inSource(path); ok {
		return g, n, ok
	}
	return gi.inCallee(path)
}

// inCallee looks for the same kind of check inside an in-repo function the value passes through on
// its way to the sink - buildDocMetadata(id) that throws when id contains ".." - on that function's
// own parameter
func (gi *guardIndex) inCallee(path []model.FlowStep) (string, int, bool) {
	if gi.g == nil {
		return "", 0, false
	}
	for _, st := range path[1:] {
		if st.Kind != "transform" || (st.Detail != "result of a call that received tainted input" && st.Detail != "passes tainted input into another function") {
			continue
		}
		name := parser.LastSegment(st.Symbol)
		if gi.byName == nil {
			gi.byName = map[string][]*graph.Symbol{}
			for _, s := range gi.g.Symbols {
				gi.byName[s.Name] = append(gi.byName[s.Name], s)
			}
		}
		cands := gi.byName[name]
		if len(cands) != 1 {
			continue // absent, or ambiguous by name: not this function's check
		}
		sym := cands[0]
		if sym.EndLine <= sym.Line {
			continue
		}
		if cg, ok := gi.callee[sym.ID]; ok {
			if cg.ok {
				return cg.text, cg.line, true
			}
			continue
		}
		ls := gi.lines(sym.File)
		if len(ls) < sym.EndLine {
			continue
		}
		var params []string
		for _, p := range sym.Params {
			if isGuardIdent(p) {
				params = append(params, p)
			}
		}
		text, n, ok := scanRegion(ls, sym.Line, sym.EndLine+1, params)
		gi.callee[sym.ID] = calleeGuard{text: text + " in " + sym.Name, line: n, ok: ok}
		if ok {
			return text + " in " + sym.Name, n, true
		}
	}
	return "", 0, false
}

func (gi *guardIndex) inSource(path []model.FlowStep) (string, int, bool) {
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
	return scanRegion(ls, src.Line, stop, []string{src.Symbol})
}

// checks reports whether line tests v: validate(v), isSafe(v), v.match(/^https:\/\/x\//),
// /re/.test(v), re.match(p, v), v.startswith("..."), v in ALLOWED, ALLOWED.includes(v)
// checkPatterns are the shapes of an input check on a value; %[1]s is the value's quoted name
var checkPatterns = []string{
	`(?i)\b_*(validate|sanitize|sanitise|check|ensure|verify|assert|is_?safe|is_?valid|is_?allowed|allowed)\w*\s*\(\s*%[1]s\b`,
	`\b%[1]s\s*\.\s*(match|test|startsWith|startswith|endsWith|endswith|fullmatch|matches|HasPrefix)\s*\(`,
	`\.(test|match|fullmatch|search|MatchString)\s*\(\s*(?:[^,()]+,\s*)?%[1]s\b`,
	`\bstrings\.HasPrefix\s*\(\s*%[1]s\b`,
	`\b%[1]s\s+not\s+in\s+\w+|\b%[1]s\s+in\s+[A-Z_]{3,}\b`,
	`\.(includes|has|contains)\s*\(\s*%[1]s\s*\)`,
	// a denylist test on the value itself: id.includes(".."), ".." in name, strings.Contains(p, "..")
	`\b%[1]s\s*\.\s*(includes|contains|indexOf|match)\s*\(`,
	`['"][^'"]*['"]\s+in\s+%[1]s\b`,
	`\bstrings\.Contains\s*\(\s*%[1]s\b`,
}

// checkRegexps caches one compiled alternation of checkPatterns per value name; compiling them for
// every line of every function a finding's path crosses was most of a large tree's scan time
var (
	checkMu      sync.Mutex
	checkRegexps = map[string]*regexp.Regexp{}
	wordRegexps  = map[string]*regexp.Regexp{}
)

func checkRegexp(v string) *regexp.Regexp {
	checkMu.Lock()
	defer checkMu.Unlock()
	if re, ok := checkRegexps[v]; ok {
		return re
	}
	q := regexp.QuoteMeta(v)
	parts := make([]string, len(checkPatterns))
	for i, p := range checkPatterns {
		parts[i] = "(?:" + fmt.Sprintf(p, q) + ")"
	}
	re := regexp.MustCompile(strings.Join(parts, "|"))
	checkRegexps[v] = re
	return re
}

func wordRegexp(v string) *regexp.Regexp {
	checkMu.Lock()
	defer checkMu.Unlock()
	if re, ok := wordRegexps[v]; ok {
		return re
	}
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(v) + `\b`)
	wordRegexps[v] = re
	return re
}

// checks reports whether line tests v: validate(v), isSafe(v), v.match(/^https:\/\/x\//),
// /re/.test(v), re.match(p, v), v.startswith("..."), v in ALLOWED, ALLOWED.includes(v)
func checks(line, v string) bool {
	if !strings.Contains(line, v) {
		return false
	}
	return checkRegexp(v).MatchString(line)
}

func isGuardIdent(s string) bool {
	return regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(s)
}

func mentionsVar(s string, vs []string) bool {
	for _, v := range vs {
		if strings.Contains(s, v) && wordRegexp(v).MatchString(s) {
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

func guardIfHigh(gi *guardIndex, sev model.Severity, path []model.FlowStep) (string, int, bool) {
	if !sev.AtLeast(model.SeverityHigh) {
		return "", 0, false
	}
	return gi.before(path)
}

// scanRegion looks at lines [from, to) for a check on one of vars, or on a value derived from them
// by assignment, followed within guardWindow lines by an exit. A check whose exit rejects (throws,
// raises, returns an error) wins over one followed only by a plain return.
func scanRegion(ls []string, from, to int, vars []string) (string, int, bool) {
	vars = append([]string(nil), vars...)
	weakText, weakLine := "", 0
	for n := from; n < to && n <= len(ls); n++ {
		line := ls[n-1]
		if m := assignFrom.FindStringSubmatch(line); m != nil && mentionsVar(line[len(m[0])-1:], vars) && !hasString(vars, m[1]) {
			vars = append(vars, m[1])
		}
		for _, v := range vars {
			if !checks(line, v) {
				continue
			}
			end := min(n+guardWindow, to-1, len(ls))
			for k := n; k <= end; k++ {
				if errorExit.MatchString(ls[k-1]) {
					return strings.TrimSpace(clipText(line, 100)), n, true
				}
				if weakLine == 0 && earlyExit.MatchString(ls[k-1]) {
					weakText, weakLine = strings.TrimSpace(clipText(line, 100)), n
				}
			}
		}
	}
	if weakLine > 0 {
		return weakText, weakLine, true
	}
	return "", 0, false
}
