package taint

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/internal/source/targetfs"
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
	// refused are the manifests a triage rule needed and could not read through the scan root
	refused map[string]bool
	// callee caches inCallee's answer per symbol: the same helpers sit on many findings' paths
	callee map[graph.SymbolID]calleeGuardResult
	// byName indexes symbols by name once, instead of a walk of every symbol per path step
	byName map[string][]*graph.Symbol
	// allowed are the function names the current path may descend into at the second level
	allowed map[string]bool
	// shell is set while the finding being triaged is a command injection: a check that cannot
	// reject shell syntax (a NUL or '..' test, a prefix test) does not count then
	shell bool
	// calleeShell caches inCallee's answer per symbol for shell mode
	calleeShell map[graph.SymbolID]calleeGuardResult
	// hit is where the last check before() found sits and which value it tests, so the check's
	// own pattern can be read (regexguard.go)
	hit guardHit
	// elsewhere, manifests and dirs cache what the not-shipped rule read (notshipped.go)
	elsewhere *string
	// surfaceImports caches whether any import names MCP (mcpsurface.go)
	surfaceImports *bool
	// callIndex lists the graph's calls by file and line (locator.go)
	callIndex map[string][]graph.Call
	manifests map[string]manifestRead
	dirs      map[string]dirRead
}

// guardHit locates one check: the file and line of the test and the name of the value it tests
type guardHit struct {
	file  string
	line  int
	value string
	// fn is the first line of the function the check is in; own is set when that function is the
	// handler the path starts in, and roots are the names the search started from there (the
	// argument, or the function's parameters), as opposed to a value derived from them
	fn    int
	own   bool
	roots []string
}

type calleeGuardResult struct {
	text  string
	line  int
	ok    bool
	file  string
	value string
	fn    int
	roots []string
}

// guardWindow is how many lines after a check its early exit may appear
const guardWindow = 6

var (
	earlyExit = regexp.MustCompile(`\b(return|throw|raise)\b|\bpanic\(|\babort\(`)
	// errorExit is an exit that rejects: it throws, raises, or returns an error. A check followed
	// only by a plain return (if (src.match(/^data:/)) return decoded) picks a branch instead.
	errorExit = regexp.MustCompile(`\b(throw|raise)\b|\bpanic\(|\babort\(|return\s+.*\b(err|error|Error|errorResponse|isError|toolError|None|null|false)\b|return\s+fmt\.Errorf|return\s*;?\s*$`)
	// checkerName is a function named for checking or normalizing its argument
	checkerName = regexp.MustCompile(`(?i)^_*(normali[sz]e|validate|sanitize|sanitise|check|ensure|verify|clean|safe|parse)`)
	assignFrom  = regexp.MustCompile(`^\s*(?:const|let|var|final|val)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?:?=[^=]`)
)

func (gi *guardIndex) refuse(p string) {
	if gi.refused == nil {
		gi.refused = map[string]bool{}
	}
	gi.refused[p] = true
}

func (gi *guardIndex) lines(file string) []string {
	if ls, ok := gi.files[file]; ok {
		return ls
	}
	b, _, err := targetfs.Read(gi.root, file, targetfs.Cap(gi.g, file))
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
	gi.hit = guardHit{}
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
	var names []string
	for _, st := range path[1:] {
		switch {
		case st.Kind == "transform" && (st.Detail == "result of a call that received tainted input" || st.Detail == "passes tainted input into another function"):
			names = append(names, parser.LastSegment(st.Symbol))
		case st.Kind == "sink":
			// resolve_note(p).read_text(): the helper is the sink's receiver, not a step of its own
			for _, m := range callNames.FindAllStringSubmatch(st.Symbol, 4) {
				if n := parser.LastSegment(m[1]); n != parser.LastSegment(st.Symbol) {
					names = append(names, n)
				}
			}
		}
	}
	// The second level may only enter functions the path itself names, or that the sink's own line
	// calls (fs.readFile(jobPath(id))): a dispatcher hands its arguments to every handler, and a
	// check in a handler the path never reaches says nothing about this value
	gi.allowed = map[string]bool{}
	for _, n := range names {
		gi.allowed[n] = true
	}
	if last := path[len(path)-1]; last.Kind == "sink" {
		if ls := gi.lines(last.File); last.Line > 0 && last.Line <= len(ls) {
			for _, m := range callNames.FindAllStringSubmatch(ls[last.Line-1], 8) {
				gi.allowed[parser.LastSegment(m[1])] = true
			}
		}
	}
	for _, name := range names {
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
		if text, n, ok := gi.calleeGuard(sym, 0); ok {
			return text, n, true
		}
	}
	return "", 0, false
}

// calleeGuard looks for an input check on sym's parameters in its body, and one level further in
// a project function the body hands a parameter to - readJob(id) calling jobPath(id), which
// throws unless id matches /^[a-f0-9-]{36}$/
func (gi *guardIndex) calleeGuard(sym *graph.Symbol, depth int) (string, int, bool) {
	cache := gi.callee
	if gi.shell {
		if gi.calleeShell == nil {
			gi.calleeShell = map[graph.SymbolID]calleeGuardResult{}
		}
		cache = gi.calleeShell
	}
	own, ok := cache[sym.ID]
	if !ok {
		own = gi.ownBodyGuard(sym)
		cache[sym.ID] = own
	}
	if own.ok || depth >= 1 {
		if own.ok {
			gi.hit = guardHit{file: own.file, line: own.line, value: own.value, fn: own.fn, roots: own.roots}
		}
		return own.text, own.line, own.ok
	}
	// a project function this body hands one of its parameters to, if the path allows it
	ls := gi.lines(sym.File)
	params := guardParams(sym)
	for k := sym.Line; k <= sym.EndLine && k <= len(ls); k++ {
		if !mentionsVar(ls[k-1], params) {
			continue
		}
		targets := assignedTargets(ls[k-1])
		for _, m := range callNames.FindAllStringSubmatch(ls[k-1], 6) {
			name := parser.LastSegment(m[1])
			cands := gi.byName[name]
			// pid = normalize_id(raw): a value the body replaces with a checking function's result
			// flows through that function even when the path does not name it; so does one whose
			// result the body returns (full, err = r.resolve(ctx, p) ... return full, nil)
			through := len(targets) > 0 && (checkerName.MatchString(name) || returnedLater(ls, k+1, sym.EndLine, targets))
			if len(cands) != 1 || cands[0].ID == sym.ID || !gi.allowed[name] && !through {
				continue
			}
			if t2, n2, ok2 := gi.calleeGuard(cands[0], depth+1); ok2 {
				return t2, n2, true
			}
		}
	}
	return "", 0, false
}

// ownBodyGuard is a check on sym's parameters in sym's own body; it does not depend on the path,
// so calleeGuard caches it per symbol
func (gi *guardIndex) ownBodyGuard(sym *graph.Symbol) calleeGuardResult {
	ls := gi.lines(sym.File)
	if sym.EndLine <= sym.Line || len(ls) < sym.EndLine {
		return calleeGuardResult{}
	}
	var text, value string
	var n int
	var ok bool
	if gi.shell {
		// In shell mode the body is read for what it checks, so the declaration line
		// (function sanitizePath(input: string)) is not itself taken for a call to a checker:
		// the function's own name is masked there
		region := append([]string(nil), ls[sym.Line-1:sym.EndLine]...)
		region[0] = declName(sym.Name).ReplaceAllString(region[0], "${1}_")
		text, n, value, ok = scanRegionValue(region, 1, len(region)+1, guardParams(sym), gi.blind())
		n += sym.Line - 1
	} else {
		text, n, value, ok = scanRegionValue(ls, sym.Line, sym.EndLine+1, guardParams(sym), gi.blind())
	}
	if ok {
		text += " in " + sym.Name
	}
	return calleeGuardResult{text: text, line: n, ok: ok, file: sym.File, value: value, fn: sym.Line, roots: guardParams(sym)}
}

func guardParams(sym *graph.Symbol) []string {
	var params []string
	for _, p := range sym.Params {
		if isGuardIdent(p) {
			params = append(params, p)
		}
	}
	return params
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
	text, n, value, ok := scanRegionValue(ls, src.Line, stop, []string{src.Symbol}, gi.blind())
	if ok {
		gi.hit = guardHit{file: src.File, line: n, value: value, fn: src.Line, own: true, roots: []string{src.Symbol}}
	}
	return text, n, ok
}

// checks reports whether line tests v: validate(v), isSafe(v), v.match(/^https:\/\/x\//),
// /re/.test(v), re.match(p, v), v.startswith("..."), v in ALLOWED, ALLOWED.includes(v)
// checkPatterns are the shapes of an input check on a value; %[1]s is the value's quoted name
var checkPatterns = []string{
	`(?i)\b_*(validate|sanitize|sanitise|check|ensure|verify|assert|is_?safe|is_?valid|is_?allowed|allowed)\w*\s*\(\s*%[1]s\b`,
	// the same with the value after simple leading arguments: validateDir(ctx, p), check(root, p)
	`(?i)\b_*(validate|sanitize|sanitise|ensure|verify|is_?safe|is_?valid|is_?allowed)\w*\s*\((?:\s*[\w.]+\s*,){1,2}\s*%[1]s\s*\)`,
	`\b%[1]s\s*\.\s*(match|test|startsWith|startswith|endsWith|endswith|fullmatch|matches|HasPrefix|is_relative_to|relative_to)\s*\(`,
	// a predicate of the project named for what it tests: isSlug(v), is_hex_id(v), hasSafeName(v)
	`(?:!\s*|\bnot\s+)(?:is|has)_?[A-Za-z]\w*\s*\(\s*%[1]s\s*\)`,
	`\.(test|match|fullmatch|search|MatchString)\s*\(\s*(?:(?:r|R|b|rb|br)?(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|` + "`[^`]*`" + `|[^,()]+)\s*,\s*)?%[1]s\b`,
	`\bstrings\.HasPrefix\s*\(\s*%[1]s\b`,
	`\b%[1]s\s+not\s+in\s+\w+|\b%[1]s\s+in\s+[A-Z_]{3,}\b`,
	`\.(includes|has|contains)\s*\(\s*%[1]s\s*\)`,
	// a denylist test on the value itself: id.includes(".."), ".." in name, strings.Contains(p, "..")
	`\b%[1]s\s*\.\s*(includes|contains|indexOf|match)\s*\(`,
	`['"][^'"]*['"]\s+in\s+%[1]s\b`,
	`\bstrings\.Contains\s*\(\s*%[1]s\b`,
	// a containment or allowlist helper of the project, the value in any argument position:
	// resolveAllowedPath(filePath, dirs), isInside(base, target), toSafePath(root, p)
	`(?i)\b\w*(allowed|inside|within|subpath|safe_?path|valid_?path|under_?root|in_?root|confine)\w*\s*\([^()]*\b%[1]s\b`,
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

var guardIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func isGuardIdent(s string) bool {
	return guardIdent.MatchString(s)
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
func scanRegion(ls []string, from, to int, vars []string, blind func(line, v string) bool) (string, int, bool) {
	text, n, _, ok := scanRegionValue(ls, from, to, vars, blind)
	return text, n, ok
}

// scanRegionValue is scanRegion that also names the value the check tests
func scanRegionValue(ls []string, from, to int, vars []string, blind func(line, v string) bool) (string, int, string, bool) {
	vars = append([]string(nil), vars...)
	weakText, weakLine, weakValue := "", 0, ""
	for n := from; n < to && n <= len(ls); n++ {
		line := ls[n-1]
		if m := assignFrom.FindStringSubmatch(line); m != nil && mentionsVar(line[len(m[0])-1:], vars) && !hasString(vars, m[1]) {
			vars = append(vars, m[1])
		}
		for _, v := range vars {
			if !checks(line, v) || blind != nil && blind(line, v) {
				continue
			}
			end := min(n+guardWindow, to-1, len(ls))
			for k := n; k <= end; k++ {
				if errorExit.MatchString(ls[k-1]) {
					return strings.TrimSpace(clipText(line, 100)), n, v, true
				}
				if weakLine == 0 && earlyExit.MatchString(ls[k-1]) {
					weakText, weakLine, weakValue = strings.TrimSpace(clipText(line, 100)), n, v
				}
			}
		}
	}
	if weakLine > 0 {
		return weakText, weakLine, weakValue, true
	}
	return "", 0, "", false
}

// assignTargets matches the left side of an assignment, one name or several: p = ..., full, err := ...
var assignTargets = regexp.MustCompile(`^\s*(?:const|let|var|final|val)?\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::[^=]+)?:?=[^=]`)

// assignedTargets are the names an assignment line binds, or nil for any other line
func assignedTargets(line string) []string {
	m := assignTargets.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	var out []string
	for _, t := range strings.Split(m[1], ",") {
		if t = strings.TrimSpace(t); t != "" && t != "_" && t != "err" {
			out = append(out, t)
		}
	}
	return out
}

// returnedLater reports whether a return in lines [from, to] hands back one of names
func returnedLater(ls []string, from, to int, names []string) bool {
	for n := from; n <= to && n <= len(ls); n++ {
		if strings.Contains(ls[n-1], "return") && regexp.MustCompile(`\breturn\b`).MatchString(ls[n-1]) && mentionsVar(ls[n-1], names) {
			return true
		}
	}
	return false
}

// blind is the filter scanRegion applies in shell mode, or nil
func (gi *guardIndex) blind() func(line, v string) bool {
	if gi.shell {
		return shellBlindCheck
	}
	return nil
}

// shellMeta are the characters a POSIX shell or cmd.exe gives a meaning to in a command line,
// plus whitespace, which splits words
const shellMeta = ";|&$`<>()'\"\\\n\r\t *?[]{}!#~%^"

// literalArg is a quoted literal: "..", '\0', `x`
const literalArg = `("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|` + "`[^`$]*`" + `)`

// shellBlindPatterns are the shapes of a check that cannot reject shell syntax, whatever the rest
// of the value holds: a test for one literal that is not shell syntax (a NUL byte, ".."), and a
// prefix or suffix test, which says nothing about the middle of the value. %[1]s is the value's
// quoted name. A literal's own text is tested separately, see blindLiteral.
var shellBlindPatterns = []string{
	`\b%[1]s\s*\.\s*(?:includes|contains|indexOf)\s*\(\s*` + literalArg + `\s*\)`,
	literalArg + `\s+(?:not\s+)?in\s+%[1]s\b`,
	`\bstrings\.Contains(?:Rune)?\s*\(\s*%[1]s\s*,\s*` + literalArg + `\s*\)`,
	`\b%[1]s\s*\.\s*(?:startsWith|startswith|endsWith|endswith|is_relative_to|relative_to)\s*\(`,
	`\bstrings\.Has(?:Prefix|Suffix)\s*\(\s*%[1]s\b`,
}

var (
	blindMu      sync.Mutex
	blindRegexps = map[string][]*regexp.Regexp{}
	// nulEscape is a NUL byte written as an escape in a literal
	nulEscape = regexp.MustCompile(`\\(?:0|x00|u0000|u\{0\})`)
)

func blindRegexpsFor(v string) []*regexp.Regexp {
	blindMu.Lock()
	defer blindMu.Unlock()
	if res, ok := blindRegexps[v]; ok {
		return res
	}
	q := regexp.QuoteMeta(v)
	res := make([]*regexp.Regexp, len(shellBlindPatterns))
	for i, p := range shellBlindPatterns {
		res[i] = regexp.MustCompile(fmt.Sprintf(p, q))
	}
	blindRegexps[v] = res
	return res
}

// shellBlindCheck reports whether every check on v in line is one that cannot reject shell syntax.
// It is a fact of the code, not of names: a value that passes `p.includes("\0")` or
// `p.startsWith(ROOT)` may still hold "; id", so for a value that ends up in a shell command line
// such a check is no guard. A line with any other check on v (a pattern, an allowlist, a
// project's checker) is not blind.
func shellBlindCheck(line, v string) bool {
	all := checkRegexp(v).FindAllStringIndex(line, -1)
	if len(all) == 0 {
		return false
	}
	var blind [][]int
	for _, re := range blindRegexpsFor(v) {
		for _, m := range re.FindAllStringSubmatchIndex(line, -1) {
			if len(m) >= 4 && m[2] >= 0 {
				lit := line[m[2]:m[3]]
				body := nulEscape.ReplaceAllString(lit[1:len(lit)-1], "")
				if strings.ContainsAny(body, shellMeta) {
					continue // a test for a quote or a ';' may well be the guard
				}
			}
			blind = append(blind, m[:2])
		}
	}
	for _, a := range all {
		covered := false
		for _, b := range blind {
			if b[0] <= a[1] && a[0] <= b[1] {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

var (
	// replaceCall is a replace whose pattern is the first argument: a regex or a string literal
	replaceCall = regexp.MustCompile(`\.(?:replace|replaceAll)\s*\(\s*(/(?:[^/\\\n]|\\.)+/[a-z]*|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|\bre\.sub[n]?\(\s*r?("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')`)
	// otherRewrite is a rewrite the scanner cannot read the pattern of
	otherRewrite = regexp.MustCompile(`(?i)\bstrings\.(?:Replace|ReplaceAll|Map|NewReplacer)\b|\btranslate\s*\(|\b\w*(?:escape|quote)\w*\s*\(`)
	// shellStrip are pattern parts that can remove shell syntax: a metacharacter named in the
	// pattern, a negated class or a class shorthand that covers punctuation
	shellStrip = regexp.MustCompile("[;|&$`]|\\[\\^|\\\\[WsS]")
)

// validatorShellBlind reports whether the project validator name (a path's sanitizer step) can be
// read and cannot reject or remove shell syntax: every check its body makes on its parameters is
// shell-blind (see shellBlindCheck), there is at least one, and it rewrites the value with no
// replace that could strip shell characters and no escaping or quoting call. sanitizePath that
// tests for NUL and for the root prefix and only swaps backslashes is such a function; one that
// also tests /^[\w.-]+$/ is not.
func (gi *guardIndex) validatorShellBlind(name string) bool {
	if gi.g == nil {
		return false
	}
	if gi.byName == nil {
		gi.byName = map[string][]*graph.Symbol{}
		for _, s := range gi.g.Symbols {
			gi.byName[s.Name] = append(gi.byName[s.Name], s)
		}
	}
	cands := gi.byName[parser.LastSegment(name)]
	if len(cands) != 1 {
		return false
	}
	sym := cands[0]
	ls := gi.lines(sym.File)
	if sym.EndLine <= sym.Line || len(ls) < sym.EndLine {
		return false
	}
	vars := guardParams(sym)
	if len(vars) == 0 {
		return false
	}
	found := false
	for n := sym.Line + 1; n <= sym.EndLine; n++ {
		line := ls[n-1]
		if m := assignFrom.FindStringSubmatch(line); m != nil && mentionsVar(line[len(m[0])-1:], vars) && !hasString(vars, m[1]) {
			vars = append(vars, m[1])
		}
		if otherRewrite.MatchString(line) {
			return false
		}
		for _, m := range replaceCall.FindAllStringSubmatch(line, -1) {
			if shellStrip.MatchString(m[1] + m[2]) {
				return false
			}
		}
		for _, m := range callNames.FindAllStringSubmatch(line, 6) {
			// a check delegated to another function of the project is not read here
			if c := parser.LastSegment(m[1]); c != sym.Name && checkerName.MatchString(c) && len(gi.byName[c]) > 0 {
				return false
			}
		}
		for _, v := range vars {
			if !checks(line, v) {
				continue
			}
			if !shellBlindCheck(line, v) {
				return false
			}
			found = true
		}
	}
	return found
}

// declName matches a function's own name where its declaration line names it before "("
func declName(name string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^\w$])` + regexp.QuoteMeta(name) + `\s*\(`)
}
