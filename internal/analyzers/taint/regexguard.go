package taint

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// regexGuard is what a pattern check before a sink proves about the values it lets through.
// The guard index finds a check by its shape and decides nothing; when the check is a regular
// expression written in the code, the expression itself can be read: an anchored pattern whose
// alphabet cannot spell the sink's dangerous syntax closes the path (complete), and a pattern
// that accepts a concrete dangerous value does not limit it at all (ineffective).
type regexGuard struct {
	complete    bool
	ineffective bool
	pattern     string
	// why says what a matching value cannot carry (complete) or which dangerous value matches
	// (ineffective)
	why string
	// dashFirst is set when a matching value may begin with '-': pasted where a word of a command
	// starts, it is an option of that command
	dashFirst bool
}

// regexMode is how the language's test applies a pattern to the value
type regexMode int

const (
	modeSearch regexMode = iota // anywhere in the value: re.search, RegExp.test, Go MatchString
	modeStart                   // anchored at the start only: Python re.match
	modeFull                    // the whole value: re.fullmatch, Java String.matches
)

// a regex test found on a line: its pattern source and how it applies
type regexTest struct {
	pattern string
	mode    regexMode
	flags   string
}

var (
	pyReCall   = regexp.MustCompile(`\bre\.(fullmatch|match|search)\(\s*(r|R|b|rb|br)?("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*,\s*([^)]+)\)`)
	pyReMethod = regexp.MustCompile(`\b([A-Za-z_]\w*)\.(fullmatch|match|search)\(\s*([^),]+)`)
	pyCompile  = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*re\.compile\(\s*(r|R)?("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')`)
	jsLiteral  = regexp.MustCompile(`/((?:[^/\\\n\[]|\\.|\[(?:[^\]\\]|\\.)*\])+)/([dgimsuvy]*)\s*\.test\(\s*([^)]+)\)`)
	jsMatch    = regexp.MustCompile(`([A-Za-z_$][\w$.]*)\s*\.\s*(?:match|search)\(\s*/((?:[^/\\\n\[]|\\.|\[(?:[^\]\\]|\\.)*\])+)/([dgimsuvy]*)\s*\)`)
	jsNamed    = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\.test\(\s*([^)]+)\)`)
	jsConst    = regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*/((?:[^/\\\n\[]|\\.|\[(?:[^\]\\]|\\.)*\])+)/([dgimsuvy]*)\s*;?\s*$`)
	goMatch    = regexp.MustCompile(`\bregexp\.MatchString\(\s*(` + "`[^`]*`" + `|"(?:[^"\\]|\\.)*")\s*,\s*([^)]+)\)`)
	goNamed    = regexp.MustCompile(`\b([A-Za-z_]\w*)\.MatchString\(\s*([^)]+)\)`)
	goCompile  = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*(?::=|=)\s*regexp\.(?:MustCompile|Compile)\(\s*(` + "`[^`]*`" + `|"(?:[^"\\]|\\.)*")\s*\)`)
	javaMatch  = regexp.MustCompile(`\b([A-Za-z_]\w*)\.matches\(\s*("(?:[^"\\]|\\.)*")\s*\)|Pattern\.matches\(\s*("(?:[^"\\]|\\.)*")\s*,\s*([^)]+)\)`)
	callOnVal  = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*\(\s*([^(),]+)\s*\)`)
)

// regexVerdict reads the pattern of the check guardIndex last found and weighs it for category
func (gi *guardIndex) regexVerdict(category string) regexGuard {
	h := gi.hit
	if h.file == "" || h.line <= 0 || h.value == "" {
		return regexGuard{}
	}
	ls := gi.lines(h.file)
	if h.line > len(ls) {
		return regexGuard{}
	}
	line := ls[h.line-1]
	if t, ok := findRegexTest(line, h.value, ls); ok && rejectsOnMismatch(line, h.value) {
		return weighPattern(t, category)
	}
	// if (!isSlug(branch)) throw ...: a project function whose body returns one pattern test of its
	// parameter
	for _, m := range callOnVal.FindAllStringSubmatch(line, -1) {
		if strings.TrimSpace(m[2]) != h.value || !negatedCall(line, m[1]) {
			continue
		}
		if t, ok := gi.validatorPattern(m[1]); ok {
			return weighPattern(t, category)
		}
	}
	return regexGuard{}
}

// validatorPattern reads a function that returns a single pattern test of its first parameter
func (gi *guardIndex) validatorPattern(name string) (regexTest, bool) {
	if gi.g == nil {
		return regexTest{}, false
	}
	if gi.byName == nil {
		gi.byName = map[string][]*graph.Symbol{}
		for _, s := range gi.g.Symbols {
			gi.byName[s.Name] = append(gi.byName[s.Name], s)
		}
	}
	cands := gi.byName[name]
	if len(cands) != 1 || len(cands[0].Params) == 0 || cands[0].EndLine <= cands[0].Line || cands[0].EndLine-cands[0].Line > 8 {
		return regexTest{}, false
	}
	sym := cands[0]
	// isSlug(value: string), def is_key(v: str = ""): the name alone
	param := strings.TrimSpace(strings.FieldsFunc(sym.Params[0], func(r rune) bool { return r == ':' || r == '=' || r == ' ' })[0])
	ls := gi.lines(sym.File)
	if sym.EndLine > len(ls) {
		return regexTest{}, false
	}
	var found regexTest
	returns := 0
	for k := sym.Line; k <= sym.EndLine; k++ {
		l := ls[k-1]
		if !strings.Contains(l, "return") {
			continue
		}
		returns++
		t, ok := findRegexTest(l, param, ls)
		if !ok || strings.Contains(l, "!") || strings.Contains(l, " not ") {
			return regexTest{}, false
		}
		// return /^[a-z]+$/.test(v) || v.startsWith("refs/"): the function accepts more than the
		// pattern does
		if code := codeOnly(l); orOperator.MatchString(code) || strings.Contains(code, "?") {
			return regexTest{}, false
		}
		found = t
	}
	return found, returns == 1
}

// findRegexTest finds a pattern test of value on line, resolving a same-file pattern constant
func findRegexTest(line, value string, file []string) (regexTest, bool) {
	isVal := func(arg string) bool { return strings.TrimSpace(arg) == value }
	for _, m := range pyReCall.FindAllStringSubmatch(line, -1) {
		if isVal(m[4]) {
			return regexTest{pattern: pyString(m[2], m[3]), mode: pyMode(m[1])}, true
		}
	}
	for _, m := range pyReMethod.FindAllStringSubmatch(line, -1) {
		if m[1] == "re" || !isVal(m[3]) {
			continue
		}
		for _, l := range file {
			if c := pyCompile.FindStringSubmatch(l); c != nil && c[1] == m[1] {
				return regexTest{pattern: pyString(c[2], c[3]), mode: pyMode(m[2])}, true
			}
		}
	}
	for _, m := range jsLiteral.FindAllStringSubmatch(line, -1) {
		if isVal(m[3]) {
			return regexTest{pattern: m[1], flags: m[2]}, true
		}
	}
	for _, m := range jsMatch.FindAllStringSubmatch(line, -1) {
		if isVal(m[1]) {
			return regexTest{pattern: m[2], flags: m[3]}, true
		}
	}
	for _, m := range jsNamed.FindAllStringSubmatch(line, -1) {
		if !isVal(m[2]) {
			continue
		}
		for _, l := range file {
			if c := jsConst.FindStringSubmatch(l); c != nil && c[1] == m[1] {
				return regexTest{pattern: c[2], flags: c[3]}, true
			}
		}
	}
	for _, m := range goMatch.FindAllStringSubmatch(line, -1) {
		if isVal(m[2]) {
			return regexTest{pattern: goString(m[1])}, true
		}
	}
	for _, m := range goNamed.FindAllStringSubmatch(line, -1) {
		if !isVal(m[2]) {
			continue
		}
		for _, l := range file {
			if c := goCompile.FindStringSubmatch(l); c != nil && c[1] == m[1] {
				return regexTest{pattern: goString(c[2])}, true
			}
		}
	}
	for _, m := range javaMatch.FindAllStringSubmatch(line, -1) {
		switch {
		case m[1] != "" && isVal(m[1]):
			return regexTest{pattern: javaString(m[2]), mode: modeFull}, true
		case m[3] != "" && isVal(m[4]):
			return regexTest{pattern: javaString(m[3]), mode: modeFull}, true
		}
	}
	return regexTest{}, false
}

// rejectsOnMismatch reports whether the line's test is negated, so the exit that follows it is
// taken for values that do NOT match: if not re.fullmatch(...), if (!/.../.test(v)), x is None
func rejectsOnMismatch(line, value string) bool {
	l := strings.TrimSpace(line)
	return regexp.MustCompile(`\bnot\s+(?:re\.|[A-Za-z_]\w*\.)|!\s*\(?\s*(?:/|re\.|regexp\.|[A-Za-z_$][\w$]*\s*\.\s*(?:test|MatchString|matches|match)\(|` + regexp.QuoteMeta(value) + `\s*\.\s*match)|\)\s*(?:is\s+None|==\s*None|===?\s*null|==\s*false)\b`).MatchString(l)
}

// negatedCall reports whether a call to name on the line is negated
func negatedCall(line, name string) bool {
	return regexp.MustCompile(`(?:!\s*|\bnot\s+)` + regexp.QuoteMeta(name) + `\s*\(`).MatchString(line)
}

var (
	regexLiteral  = regexp.MustCompile(`(^|[=(,!&|?:;{}\s])/(?:[^/\\\n\[]|\\.|\[(?:[^\]\\]|\\.)*\])+/[dgimsuvy]*`)
	stringLiteral = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|` + "`(?:[^`\\\\]|\\\\.)*`")
	commentStart  = regexp.MustCompile(`(?:^|\s)(?://|#)`)
	ifWord        = regexp.MustCompile(`\bif\b`)
	andOperator   = regexp.MustCompile(`&&|\band\b`)
	orOperator    = regexp.MustCompile(`\|\||\bor\b`)
	negatedGroup  = regexp.MustCompile(`(?:!|\bnot)\s*\(`)
	// if (...) throw ..., if not ...: raise ..., if !ok { return ... }: the if's body on its own line
	sameLineExit  = regexp.MustCompile(`^if\b.*?(?:\)|:)\s*\{?\s*((?:throw|raise|return)\b.*|(?:panic|abort|process\.exit|sys\.exit|os\.Exit)\(.*)$`)
	exitStatement = regexp.MustCompile(`^(?:(?:throw|raise|return)\b|(?:panic|abort|process\.exit|sys\.exit|os\.Exit)\()`)
	// a return that hands back an error: return nil, fmt.Errorf(...), return mcp.NewToolResultError(...)
	errorValue = regexp.MustCompile(`\b(?:Errorf|New\w*Error|Error)\(|\berrors\.New\(`)
	// a block whose body runs only on some ways through the function
	branchBlock = regexp.MustCompile(`^(?:\}\s*)?(?:if|elif|else|for|foreach|while|do|except|catch|finally|switch|case|default|match|select)\b`)
	// a block whose body runs whole, but which can catch or suppress the rejection inside it
	containerBlock = regexp.MustCompile(`^(?:try|with|async\s+with)\b`)
	// a call that changes which characters a value holds: decoding, unquoting, replacing, expanding,
	// parsing
	reshaping = regexp.MustCompile(`(?i)\b\w*(?:decode|unescape|unquote|normali[sz]e|replace|fromcharcode|atob|base64|unhexlify|fromhex|expand|translate|substitute|format_map|parse)\w*\s*\(`)
)

// codeOnly is a line without its string and regex literals and its trailing comment, so the
// words and operators left are code: and in "letters and digits" is not an operator
func codeOnly(line string) string {
	s := regexLiteral.ReplaceAllString(line, "${1}/re/")
	s = stringLiteral.ReplaceAllString(s, `""`)
	if i := commentStart.FindStringIndex(s); i != nil {
		s = s[:i[0]]
	}
	return strings.TrimRight(s, " \t\r")
}

// indentWidth is the width of a line's leading whitespace, a tab counting as four
func indentWidth(line string) int {
	n := 0
	for _, r := range line {
		switch r {
		case ' ':
			n++
		case '\t':
			n += 4
		default:
			return n
		}
	}
	return n
}

// closes reports whether a complete pattern closes this path: the check stands on it, and a value
// that may begin with '-' is not pasted where a word of the command starts
func (gi *guardIndex) closes(rv regexGuard, path []model.FlowStep) bool {
	return rv.complete && gi.closesPath(path) && !(rv.dashFirst && startsAWord(path, gi.hit.value))
}

// startsAWord reports whether v may begin a word of the command a path step builds: at the start
// of the text, after whitespace or after a quote (git log '-x' is still an option). A value pasted
// after other characters (/srv/{name}, --ref={name}) cannot; when the step's text does not show
// where v goes, it may.
func startsAWord(path []model.FlowStep, v string) bool {
	q := regexp.QuoteMeta(v)
	interp := regexp.MustCompile(`\$\{\s*` + q + `\s*\}|\{\s*` + q + `\s*(?:[!:][^}]*)?\}`)
	concat := regexp.MustCompile(`((?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'))\s*\+\s*` + q + `\b`)
	seen := false
	for _, st := range path[1:] {
		if st.Kind != "transform" {
			continue
		}
		for _, m := range interp.FindAllStringIndex(st.Symbol, -1) {
			seen = true
			if m[0] == 0 || wordBoundary(st.Symbol[m[0]-1]) {
				return true
			}
		}
		for _, m := range concat.FindAllStringSubmatch(st.Symbol, -1) {
			seen = true
			lit := m[1]
			if len(lit) < 3 || wordBoundary(lit[len(lit)-2]) {
				return true
			}
		}
	}
	return !seen
}

func wordBoundary(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\'' || c == '"' || c == '`'
}

// closesPath reports whether the check gi.hit found stands between the argument and the sink on
// every way through the code, so that a complete pattern may close the path. The guard index finds
// a check by the text of one line, and that text proves the value's alphabet only when:
//   - the line is a plain if whose condition rejects every mismatch, whatever else it tests: no
//     else-if, no second if, no && or and (a flag could skip the test), and with || or or the
//     negation sits on the test itself, not on a group;
//   - the if's own body leaves, on the same line or as a statement of its block; a plain return
//     counts in the handler itself, elsewhere the exit must reject (throw, raise, an error value);
//   - the check is not inside another branch, loop or case; inside try or with, the value's next
//     step is inside the same block, so a caught rejection skips it as well;
//   - the value the sink reads is the value tested: the name the search started from, or one the
//     path goes through; nothing is assigned to it before its next step; and no call the scanner
//     cannot follow, nor a decoding or replacing step, reshapes it after the test.
//
// When any of this does not hold, the check still sends the finding to review.
func (gi *guardIndex) closesPath(path []model.FlowStep) bool {
	h := gi.hit
	ls := gi.lines(h.file)
	if len(path) < 2 || h.line <= 0 || h.line > len(ls) || h.fn <= 0 || h.fn >= h.line {
		return false
	}
	raw := ls[h.line-1]
	code := strings.TrimSpace(codeOnly(raw))
	if !strings.HasPrefix(code, "if") || len(ifWord.FindAllStringIndex(code, -1)) != 1 || andOperator.MatchString(code) {
		return false
	}
	if negatedGroup.MatchString(code) && (orOperator.MatchString(code) || strings.Contains(code, "?")) {
		return false
	}
	ind := indentWidth(raw)
	if !bodyRejects(ls, h, raw, code, ind) {
		return false
	}
	next := nextStepLine(path, h)
	return notNested(ls, h, ind, next) && testedValueFlows(ls, path, h, next)
}

// bodyRejects reports whether the if on line h.line leaves when its condition holds
func bodyRejects(ls []string, h guardHit, raw, code string, ind int) bool {
	if m := sameLineExit.FindStringSubmatch(code); m != nil {
		return rejectingExit(m[1], raw, h.own)
	}
	braceless := strings.HasSuffix(code, ")")
	if !braceless && !strings.HasSuffix(code, "{") && !strings.HasSuffix(code, ":") {
		return false
	}
	body := -1
	for k := h.line + 1; k <= len(ls) && k <= h.line+40; k++ {
		s := strings.TrimSpace(codeOnly(ls[k-1]))
		if s == "" {
			continue
		}
		li := indentWidth(ls[k-1])
		if li <= ind {
			// the block ended: its closing brace, an else or the next statement
			break
		}
		if body < 0 {
			body = li
		}
		if li == body && exitStatement.MatchString(s) && rejectingExit(s, ls[k-1], h.own) {
			return true
		}
		if braceless {
			break
		}
	}
	return false
}

func rejectingExit(stmt, raw string, own bool) bool {
	if !strings.HasPrefix(stmt, "return") {
		return true
	}
	return own || errorExit.MatchString(raw) || errorValue.MatchString(raw)
}

// nextStepLine is the line of the path's nearest step after the check in the check's file, or 0
func nextStepLine(path []model.FlowStep, h guardHit) int {
	next := 0
	for _, st := range path[1:] {
		if st.File == h.file && st.Line > h.line && (next == 0 || st.Line < next) {
			next = st.Line
		}
	}
	return next
}

// notNested reports whether every block around the check, up to its function, runs it on every
// way through the function
func notNested(ls []string, h guardHit, ind, next int) bool {
	cur := ind
	for k := h.line - 1; k > h.fn; k-- {
		s := strings.TrimSpace(codeOnly(ls[k-1]))
		if s == "" {
			continue
		}
		li := indentWidth(ls[k-1])
		if li >= cur {
			continue
		}
		// a line less indented than everything below it up to the check opens a block around it
		cur = li
		switch {
		case containerBlock.MatchString(s):
			if next == 0 || next >= blockEnd(ls, h.line, li) {
				return false
			}
		case branchBlock.MatchString(s):
			return false
		}
	}
	return true
}

// blockEnd is the first line after from that is indented no deeper than the block's opener
func blockEnd(ls []string, from, opener int) int {
	for k := from + 1; k <= len(ls); k++ {
		if strings.TrimSpace(codeOnly(ls[k-1])) != "" && indentWidth(ls[k-1]) <= opener {
			return k
		}
	}
	return len(ls) + 1
}

// testedValueFlows reports whether the value the check tests is the value that reaches the sink
func testedValueFlows(ls []string, path []model.FlowStep, h guardHit, next int) bool {
	v := h.value
	onPath := false
	for _, st := range path[1:] {
		if wordRegexp(v).MatchString(st.Symbol) {
			onPath = true
			break
		}
	}
	// name = basename(path) tested while path is opened; helper(a, b) testing a while the path
	// goes on through b
	if !onPath && (!hasString(h.roots, v) || !h.own && len(h.roots) > 1) {
		return false
	}
	// name = decodeURIComponent(name), name += suffix: a new value after the test
	compound := regexp.MustCompile(`(?:^|[^.\w$])` + regexp.QuoteMeta(v) + `\s*(?:[-+*/%|&^]|\?\?|<<|>>|\*\*|//)=`)
	end := next
	if end == 0 {
		end = h.line + 200
	}
	for k := h.line + 1; k <= end && k <= len(ls); k++ {
		l := codeOnly(ls[k-1])
		if hasString(assignedTargets(l), v) || compound.MatchString(l) {
			return false
		}
	}
	// a call the scanner cannot follow, or a decoding or replacing step, after the test: what the
	// pattern allowed is not what reaches the sink
	derived := !hasString(h.roots, v)
	for _, st := range path[1:] {
		if derived && st.File == h.file && st.Line > h.fn && st.Line < h.line {
			// before a test of a value derived on the path, which saw the step's result; a test of
			// the argument itself did not (p = decodeURIComponent(name) ... test(name) ... use p)
			continue
		}
		if st.Kind == "unknown" || st.Kind == "transform" && reshaping.MatchString(st.Symbol) {
			return false
		}
	}
	return true
}

func pyMode(fn string) regexMode {
	switch fn {
	case "fullmatch":
		return modeFull
	case "match":
		return modeStart
	}
	return modeSearch
}

func pyString(prefix, quoted string) string {
	body := quoted[1 : len(quoted)-1]
	if strings.ContainsAny(prefix, "rR") {
		return body
	}
	return strings.ReplaceAll(body, `\\`, `\`)
}

func goString(quoted string) string {
	body := quoted[1 : len(quoted)-1]
	if quoted[0] == '`' {
		return body
	}
	return strings.ReplaceAll(body, `\\`, `\`)
}

func javaString(quoted string) string { return strings.ReplaceAll(quoted[1:len(quoted)-1], `\\`, `\`) }

// the dangerous values each category's sink gives a meaning to; a pattern that accepts one of them
// does not protect the sink
var dangerousSamples = map[string][]string{
	"path_traversal":     {"../x", "x/../../y", "..\\x", "/etc/passwd", ".."},
	"command_injection":  {"a;id", "a|id", "$(id)", "`id`", "a&&id", "a\nid"},
	"argument_injection": {"-x", "--upload-pack=x"},
	"sql_injection":      {"' OR '1'='1", "1; DROP TABLE x", "a'--"},
}

// shellMetaRunes are what a POSIX shell or cmd.exe gives a meaning to, plus whitespace
const shellMetaRunes = ";|&$`<>()'\"\\\n\r\t *?[]{}!#~%^"

// sqlMetaRunes are what can end or extend an SQL literal or identifier
const sqlMetaRunes = "'\"`;-/*()=,<>|&%#\\\n\r\t "

func weighPattern(t regexTest, category string) regexGuard {
	out := regexGuard{pattern: t.pattern}
	if strings.ContainsAny(t.flags, "m") || t.pattern == "" {
		// a multiline pattern anchors at line breaks, not at the value's ends
		return out
	}
	src := t.pattern
	if strings.Contains(t.flags, "i") {
		src = "(?i)" + src
	}
	src = strings.ReplaceAll(src, `\Z`, `\z`)
	switch t.mode {
	case modeFull:
		src = `^(?:` + src + `)$`
	case modeStart:
		src = `^(?:` + src + `)`
	}
	accept, err := regexp.Compile(src)
	if err != nil {
		// lookarounds and backreferences: not something this check reads
		return out
	}
	for _, s := range dangerousSamples[category] {
		if accept.MatchString(s) {
			out.ineffective = true
			out.why = fmt.Sprintf("it accepts %q", s)
			return out
		}
	}
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return out
	}
	re = re.Simplify()
	if !anchoredStart(re) {
		return out
	}
	if category == "ssrf" {
		// the host is fixed by the start of the value; what follows the origin is a path
		if prefix := literalPrefix(re); fixedOrigin.MatchString(prefix) {
			out.complete, out.why = true, "any other host than the one its fixed prefix "+prefix+" names"
		}
		return out
	}
	if !anchoredEnd(re) {
		return out
	}
	alpha := alphabet(re)
	switch category {
	case "path_traversal":
		if !alpha.has('/') && !alpha.has('\\') && !accept.MatchString(".") && !accept.MatchString("..") && !alpha.has(0) {
			out.complete, out.why = true, "a path separator, so it stays one name inside the folder"
		}
	case "command_injection":
		if !alpha.hasAny(shellMetaRunes) && !alpha.has(0) {
			out.dashFirst = firstRunes(re).has('-')
			out.complete, out.why = true, "shell syntax or whitespace"
		}
	case "argument_injection":
		if first := firstRunes(re); !first.has('-') && !alpha.hasAny(" \t\n") {
			out.complete, out.why = true, "a leading '-', so it cannot be read as an option"
		}
	case "sql_injection":
		if !alpha.hasAny(sqlMetaRunes) {
			out.complete, out.why = true, "quotes, comment markers or statement separators"
		}
	}
	return out
}

// fixedOrigin is a literal URL prefix that ends the host part: scheme://host/ (or ? or #)
var fixedOrigin = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://[^/?#@\s]+[/?#]`)

// runeSet is a set of characters a pattern can produce, as ranges
type runeSet struct {
	ranges [][2]rune
	any    bool
}

func (s runeSet) has(r rune) bool {
	if s.any {
		return true
	}
	for _, rg := range s.ranges {
		if r >= rg[0] && r <= rg[1] {
			return true
		}
	}
	return false
}

func (s runeSet) hasAny(chars string) bool {
	for _, r := range chars {
		if s.has(r) {
			return true
		}
	}
	return false
}

func (s *runeSet) add(lo, hi rune) { s.ranges = append(s.ranges, [2]rune{lo, hi}) }

// alphabet is every character the pattern can match
func alphabet(re *syntax.Regexp) runeSet {
	var s runeSet
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		switch r.Op {
		case syntax.OpLiteral:
			for _, c := range r.Rune {
				s.add(c, c)
				if r.Flags&syntax.FoldCase != 0 {
					s.add(unicode.ToUpper(c), unicode.ToUpper(c))
					s.add(unicode.ToLower(c), unicode.ToLower(c))
				}
			}
		case syntax.OpCharClass:
			for i := 0; i+1 < len(r.Rune); i += 2 {
				s.add(r.Rune[i], r.Rune[i+1])
			}
		case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
			s.any = true
		}
		for _, sub := range r.Sub {
			walk(sub)
		}
	}
	walk(re)
	return s
}

// firstRunes are the characters a match can begin with
func firstRunes(re *syntax.Regexp) runeSet {
	var s runeSet
	var first func(*syntax.Regexp) bool // reports whether r can match the empty string
	first = func(r *syntax.Regexp) bool {
		switch r.Op {
		case syntax.OpLiteral:
			if len(r.Rune) > 0 {
				s.add(r.Rune[0], r.Rune[0])
				if r.Flags&syntax.FoldCase != 0 {
					s.add(unicode.ToUpper(r.Rune[0]), unicode.ToUpper(r.Rune[0]))
					s.add(unicode.ToLower(r.Rune[0]), unicode.ToLower(r.Rune[0]))
				}
				return false
			}
			return true
		case syntax.OpCharClass:
			for i := 0; i+1 < len(r.Rune); i += 2 {
				s.add(r.Rune[i], r.Rune[i+1])
			}
			return false
		case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
			s.any = true
			return false
		case syntax.OpConcat:
			for _, sub := range r.Sub {
				if !first(sub) {
					return false
				}
			}
			return true
		case syntax.OpAlternate:
			empty := false
			for _, sub := range r.Sub {
				if first(sub) {
					empty = true
				}
			}
			return empty
		case syntax.OpCapture, syntax.OpPlus:
			return first(r.Sub[0])
		case syntax.OpStar, syntax.OpQuest:
			first(r.Sub[0])
			return true
		case syntax.OpRepeat:
			e := first(r.Sub[0])
			return e || r.Min == 0
		}
		// anchors and empty-width assertions match the empty string
		return true
	}
	first(re)
	return s
}

func anchoredStart(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginText:
		return true
	case syntax.OpConcat:
		return len(re.Sub) > 0 && anchoredStart(re.Sub[0])
	case syntax.OpCapture:
		return anchoredStart(re.Sub[0])
	case syntax.OpAlternate:
		for _, s := range re.Sub {
			if !anchoredStart(s) {
				return false
			}
		}
		return len(re.Sub) > 0
	}
	return false
}

func anchoredEnd(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpEndText:
		return true
	case syntax.OpConcat:
		return len(re.Sub) > 0 && anchoredEnd(re.Sub[len(re.Sub)-1])
	case syntax.OpCapture:
		return anchoredEnd(re.Sub[0])
	case syntax.OpAlternate:
		for _, s := range re.Sub {
			if !anchoredEnd(s) {
				return false
			}
		}
		return len(re.Sub) > 0
	}
	return false
}

// literalPrefix is the fixed text every match starts with, after the start anchor
func literalPrefix(re *syntax.Regexp) string {
	var b strings.Builder
	var walk func(*syntax.Regexp) bool // reports whether the prefix may continue after r
	walk = func(r *syntax.Regexp) bool {
		switch r.Op {
		case syntax.OpBeginText, syntax.OpBeginLine:
			return true
		case syntax.OpLiteral:
			if r.Flags&syntax.FoldCase != 0 {
				return false
			}
			b.WriteString(string(r.Rune))
			return true
		case syntax.OpConcat:
			for _, s := range r.Sub {
				if !walk(s) {
					return false
				}
			}
			return true
		case syntax.OpCapture:
			return walk(r.Sub[0])
		}
		return false
	}
	walk(re)
	return b.String()
}
