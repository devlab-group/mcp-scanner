package behavioral

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/targetfs"
)

// A word in a description - local, workspace, project - says little on its own: "the projects in
// the workspace" is a vendor's account, not a promise to stay on this machine. What does say
// something is whether the caller's data leaves: the address of a network call, or what it sends,
// built from a tool argument or from a file the handler read. carriesCallerData looks for that
// along the handler's calls, by names rather than a traced flow: the handler's parameters, names a
// function body assigns from them or from a file read, and the parameters of a project function
// they are handed to.

var (
	identWord = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	// name = ..., const name = ..., name := ..., with open(p) as name:, for name in ...
	assignLine = regexp.MustCompile(`^\s*(?:(?:const|let|var|final|val)\s+)?([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)\s*(?::[^=]+?)?\s*:?=\s*([^=].*)$`)
	withAsLine = regexp.MustCompile(`\bwith\s+(.+?)\s+as\s+([A-Za-z_]\w*)\s*:`)
	forInLine  = regexp.MustCompile(`^\s*for\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+in\s+(.+?):\s*$|^\s*for\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+of\s+(.+?)\)`)
	// the parameter list of an arrow function or function expression on its first line:
	// async ({ query }) =>, function ({ path }, extra) {
	sigParams = regexp.MustCompile(`(?:\bfunction\s*\w*\s*|\basync\s*)?\(\s*((?:\{[^}]*\}|[^()])*)\)\s*(?::\s*[^=>{]+)?\s*(?:=>|\{)`)
	// a read of a file's content: what it returns is data the handler did not write itself
	fileRead = regexp.MustCompile(`\b(?:open|read_text|read_bytes|readFile|readFileSync|ReadFile|readAsText|load)\s*\(|\.read\s*\(`)
)

// notCallerData are parameters that carry the request's context or the object itself, not what
// the caller asked for
var notCallerData = map[string]bool{"self": true, "cls": true, "ctx": true, "context": true, "this": true}

// paramNames are the names a parameter list binds: "path: str" is path, "{ path, mirror }" is
// path and mirror
func paramNames(params []string) []string {
	var out []string
	for _, p := range params {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "{") || strings.HasPrefix(p, "[") {
			inner := p
			if i := strings.LastIndexAny(inner, "}]"); i > 0 {
				inner = inner[1:i]
			}
			for _, part := range strings.Split(inner, ",") {
				if m := identWord.FindString(strings.SplitN(part, "=", 2)[0]); m != "" {
					out = append(out, m)
				}
			}
			continue
		}
		p = strings.TrimLeft(p, "*&.")
		if m := identWord.FindString(strings.FieldsFunc(p, func(r rune) bool { return r == ':' || r == '=' || r == ' ' })[0]); m != "" {
			out = append(out, m)
		}
	}
	var keep []string
	for _, n := range out {
		if !notCallerData[n] {
			keep = append(keep, n)
		}
	}
	return keep
}

// splitParams splits a parameter list at its top-level commas: "{ a, b }, c" is "{ a, b }" and "c"
func splitParams(list string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range list {
		switch r {
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, list[start:i])
				start = i + 1
			}
		}
	}
	if strings.TrimSpace(list[start:]) != "" {
		out = append(out, list[start:])
	}
	return out
}

var (
	// a string literal with its prefix: "x", f'{y}', rb"z", `${w}`
	literalText = regexp.MustCompile(`(?:\b[rRbBuUfF]{1,2})?"(?:[^"\\]|\\.)*"|(?:\b[rRbBuUfF]{1,2})?'(?:[^'\\]|\\.)*'|` + "`(?:[^`\\\\]|\\\\.)*`")
	jsInterp    = regexp.MustCompile(`\$\{((?:[^{}]|\{[^{}]*\})*)\}`)
	pyInterp    = regexp.MustCompile(`\{((?:[^{}]|\{[^{}]*\})*)\}`)
)

// codeText is an expression with the text of its string literals left out and what f-strings and
// template literals interpolate kept: f"Sunny in {city}" is city, "token saved" is nothing
func codeText(text string) string {
	if !strings.ContainsAny(text, "\"'`") {
		return text
	}
	return literalText.ReplaceAllStringFunc(text, func(lit string) string {
		var parts []string
		q := strings.IndexAny(lit, "\"'`")
		switch {
		case lit[q] == '`':
			for _, m := range jsInterp.FindAllStringSubmatch(lit, -1) {
				parts = append(parts, m[1])
			}
		case strings.ContainsAny(lit[:q], "fF"):
			for _, m := range pyInterp.FindAllStringSubmatch(strings.NewReplacer("{{", "", "}}", "").Replace(lit), -1) {
				parts = append(parts, m[1])
			}
		}
		return ` "" ` + strings.Join(parts, " ") + " "
	})
}

// mentionsAny reports whether an expression names one of names in its code, not in the text of a
// string literal
func mentionsAny(text string, names map[string]bool) bool {
	if len(names) == 0 {
		return false
	}
	for _, w := range identWord.FindAllString(codeText(text), -1) {
		if names[w] {
			return true
		}
	}
	return false
}

// netCall is a network call reached from the handler, with the function it sits in
type netCall struct {
	sym  graph.SymbolID
	call graph.Call
}

// flow is what the names along the handler's calls say: which names in each reached function hold
// the caller's data, which hold a credential the server read, the network calls, and whether the
// handler's own result carries a credential
type flow struct {
	caller        map[graph.SymbolID]map[string]bool
	cred          map[graph.SymbolID]map[string]bool
	net           []netCall
	returnsCred   bool
	callerReaches bool // a network call is addressed or fed with the caller's data
	// names that hold the caller's data but an address starting with a fixed or configured host -
	// url = f"{API}/items/{name}", a parameter handed one - and names that hold an address the
	// caller's data may start; a name in both is not settled
	ownAddr, otherAddr map[graph.SymbolID]map[string]bool
}

// effectiveCaller is the caller's data of a function without the names that hold an address
// starting with a fixed or configured host: where such an address starts is not the caller's
func (fl *flow) effectiveCaller(id graph.SymbolID) map[string]bool {
	caller, own, other := fl.caller[id], fl.ownAddr[id], fl.otherAddr[id]
	drop := false
	for n := range own {
		if caller[n] && !other[n] {
			drop = true
			break
		}
	}
	if !drop {
		return caller
	}
	out := map[string]bool{}
	for n := range caller {
		if !(own[n] && !other[n]) {
			out[n] = true
		}
	}
	return out
}

// bindArgs names the parameters each argument of a call binds: by position, and by keyword.
// It reports false when the call or the parameter list does not settle it - a spread argument,
// a rest or keyword-collecting parameter, more arguments than parameters, an unknown keyword.
func bindArgs(args []graph.Arg, params []string) (map[int][]string, bool) {
	first := func(p string) string {
		p = strings.TrimLeft(strings.TrimSpace(p), "*&.")
		f := strings.FieldsFunc(p, func(r rune) bool { return r == ':' || r == '=' || r == ' ' || r == '?' })
		if len(f) == 0 {
			return ""
		}
		return identWord.FindString(f[0])
	}
	ps := params
	if len(ps) > 0 && (first(ps[0]) == "self" || first(ps[0]) == "cls") {
		ps = ps[1:]
	}
	for _, p := range ps {
		if t := strings.TrimSpace(p); strings.HasPrefix(t, "*") || strings.HasPrefix(t, "...") {
			return nil, false
		}
	}
	out := map[int][]string{}
	pos := 0
	for i, a := range args {
		if t := strings.TrimSpace(a.Text); strings.HasPrefix(t, "*") || strings.HasPrefix(t, "...") {
			return nil, false
		}
		if a.Keyword != "" {
			j := -1
			for k, p := range ps {
				if first(p) == a.Keyword {
					j = k
					break
				}
			}
			if j < 0 {
				return nil, false
			}
			out[i] = paramNames([]string{ps[j]})
			continue
		}
		if pos >= len(ps) {
			return nil, false
		}
		out[i] = paramNames([]string{ps[pos]})
		pos++
	}
	return out, true
}

// credentialRead is an environment read of a credential-named variable: os.environ["API_KEY"],
// os.getenv("TOKEN"), process.env.SECRET, os.Getenv("API_TOKEN")
var credentialRead = regexp.MustCompile(`(?:os\.environ(?:\.get)?\s*[\[(]\s*|\bgetenv\s*\(\s*|process\.env\.|process\.env\[\s*|os\.Getenv\s*\(\s*|System\.getenv\s*\(\s*|\bENV\[\s*|env::var\s*\(\s*)["'\x60]?([A-Za-z_][A-Za-z0-9_]*)`)

func readsCredential(text string) bool {
	for _, m := range credentialRead.FindAllStringSubmatch(text, -1) {
		if credentialLikeName(m[1]) {
			return true
		}
	}
	return false
}

var returnLine = regexp.MustCompile(`^\s*return\b(.*)$`)

// envRead is a whole environment read, so that what is left of an expression shows whether the
// value is the read itself or something built from it: os.getenv("K") is, fetch(url, os.getenv("K"))
// is not
var envRead = regexp.MustCompile(`os\.environ\[\s*["'][^"']+["']\s*\]|os\.environ\.get\(\s*["'][^"']+["'][^)]*\)|(?:os\.)?getenv\(\s*["'][^"']+["'][^)]*\)|process\.env\.[A-Za-z_]\w*|process\.env\[\s*["'][^"']+["']\s*\]|os\.Getenv\(\s*"[^"]+"\s*\)|System\.getenv\(\s*"[^"]+"\s*\)|ENV\[\s*["'][^"']+["']\s*\]|env::var\(\s*"[^"]+"\s*\)`)

var (
	callName = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*\(`)
	// calls that build a value from their argument rather than act on it
	valueBuilders = map[string]bool{"format": true, "encode": true, "decode": true, "b64encode": true, "str": true, "String": true,
		"strip": true, "trim": true, "lower": true, "upper": true, "join": true, "replace": true, "concat": true, "Sprintf": true, "toString": true}
	quoted = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`)
)

// buildsValue reports whether an expression builds a value from its parts - concatenation, an
// f-string or template, a format or encode call - rather than being the result of another call:
// "Bearer " + key carries the key, requests.get(url, headers=h) does not
func buildsValue(expr string) bool {
	for _, m := range callName.FindAllStringSubmatch(quoted.ReplaceAllString(expr, `""`), -1) {
		if !valueBuilders[m[1]] {
			return false
		}
	}
	return true
}

// walkFlow follows the caller's data and the credentials the server reads along the handler's
// calls, by names rather than a traced flow
func walkFlow(g *graph.Graph, handler graph.SymbolID, reached map[graph.SymbolID]bool) *flow {
	fl := &flow{caller: map[graph.SymbolID]map[string]bool{}, cred: map[graph.SymbolID]map[string]bool{},
		ownAddr: map[graph.SymbolID]map[string]bool{}, otherAddr: map[graph.SymbolID]map[string]bool{}}
	files := map[string][]string{}
	lines := func(file string) []string {
		if ls, ok := files[file]; ok {
			return ls
		}
		b, err := targetfs.ReadGraphFile(g, file)
		var ls []string
		if err == nil {
			ls = strings.Split(string(b), "\n")
		}
		files[file] = ls
		return ls
	}
	set := func(m map[graph.SymbolID]map[string]bool, id graph.SymbolID) map[string]bool {
		if m[id] == nil {
			m[id] = map[string]bool{}
		}
		return m[id]
	}
	if s := g.Symbols[handler]; s != nil {
		params := s.Params
		if ls := lines(s.File); len(params) == 0 && s.Line >= 1 && s.Line <= len(ls) {
			// an inline handler whose destructured parameters the graph does not list
			for _, m := range sigParams.FindAllStringSubmatch(ls[s.Line-1], -1) {
				params = append(params, splitParams(m[1])...)
			}
		}
		for _, n := range paramNames(params) {
			set(fl.caller, handler)[n] = true
		}
	}
	// every reached function is read once, and again only when a caller handed it more than it
	// was read with
	queue := []graph.SymbolID{handler}
	for id := range reached {
		if id != handler {
			queue = append(queue, id)
		}
	}
	queued := map[graph.SymbolID]bool{}
	for _, id := range queue {
		queued[id] = true
	}
	netSeen := map[string]bool{}
	for steps := 0; len(queue) > 0 && steps < 2000; steps++ {
		id := queue[0]
		queue = queue[1:]
		queued[id] = false
		s := g.Symbols[id]
		if s == nil {
			continue
		}
		caller, cred := set(fl.caller, id), set(fl.cred, id)
		// names the body assigns from the caller's data, a file read or a credential read
		ls := lines(s.File)
		for k := s.Line; k <= s.EndLine && k <= len(ls); k++ {
			l := ls[k-1]
			if m := withAsLine.FindStringSubmatch(l); m != nil {
				if mentionsAny(m[1], caller) || fileRead.MatchString(m[1]) {
					caller[m[2]] = true
				}
				if _, ok := sensitiveFragment(m[1]); ok || mentionsAny(m[1], cred) {
					cred[m[2]] = true
				}
			}
			if m := forInLine.FindStringSubmatch(l); m != nil {
				lhs, rhs := m[1], m[2]
				if lhs == "" {
					lhs, rhs = m[3], m[4]
				}
				if mentionsAny(rhs, caller) {
					for _, n := range identWord.FindAllString(lhs, -1) {
						caller[n] = true
					}
				}
			}
			if m := assignLine.FindStringSubmatch(l); m != nil {
				if mentionsAny(m[2], caller) || fileRead.MatchString(m[2]) {
					names := identWord.FindAllString(m[1], -1)
					for _, n := range names {
						caller[n] = true
					}
					// where an address built from the caller's data starts
					if len(names) == 1 {
						if addrStart(m[2], fl.effectiveCaller(id)) == "own" {
							set(fl.ownAddr, id)[names[0]] = true
						} else {
							set(fl.otherAddr, id)[names[0]] = true
						}
					}
				}
				if _, ok := sensitiveFragment(m[2]); ok || readsCredential(m[2]) && buildsValue(envRead.ReplaceAllString(m[2], "CRED")) || mentionsAny(m[2], cred) && buildsValue(m[2]) {
					for _, n := range identWord.FindAllString(m[1], -1) {
						cred[n] = true
					}
				}
			}
			if id == handler {
				// return f"key: {key}" hands the credential back; return requests.post(url,
				// headers={"Authorization": key}).text hands back the response
				if m := returnLine.FindStringSubmatch(l); m != nil && (mentionsAny(m[1], cred) && buildsValue(m[1]) || readsCredential(m[1]) && buildsValue(envRead.ReplaceAllString(m[1], "CRED"))) {
					fl.returnsCred = true
				}
			}
		}
		for _, c := range g.CallsFrom(id) {
			var args []string
			for _, a := range c.Args {
				args = append(args, a.Text)
			}
			text := strings.Join(args, ", ")
			if cat, ok := categoryOf(c.CalleeText); ok && cat == catNetwork {
				if mentionsAny(text, caller) {
					fl.callerReaches = true
				}
				if k := c.File + ":" + strconv.Itoa(c.Line) + ":" + c.CalleeText; !netSeen[k] {
					netSeen[k] = true
					fl.net = append(fl.net, netCall{sym: id, call: c})
				}
			}
			// handed to a project function: its parameters carry what was handed
			if c.Callee == "" || !reached[c.Callee] {
				continue
			}
			cs := g.Symbols[c.Callee]
			if cs == nil {
				continue
			}
			grew := false
			mark := func(m map[graph.SymbolID]map[string]bool, n string) {
				if !set(m, c.Callee)[n] {
					m[c.Callee][n], grew = true, true
				}
			}
			binds, bound := bindArgs(c.Args, cs.Params)
			for _, kind := range []struct {
				m      map[graph.SymbolID]map[string]bool
				from   map[string]bool
				isCred bool
			}{{fl.caller, caller, false}, {fl.cred, cred, true}} {
				if !mentionsAny(text, kind.from) && !(kind.isCred && readsCredential(text)) {
					continue
				}
				if !bound {
					// the arguments do not settle which parameter gets what: all of them may
					for _, n := range paramNames(cs.Params) {
						mark(kind.m, n)
					}
					continue
				}
				for i, a := range c.Args {
					if !mentionsAny(a.Text, kind.from) && !(kind.isCred && readsCredential(a.Text)) {
						continue
					}
					for _, n := range binds[i] {
						mark(kind.m, n)
						if !kind.isCred {
							// an address handed on keeps where it starts
							if addrStart(a.Text, fl.effectiveCaller(id)) == "own" {
								mark(fl.ownAddr, n)
							} else {
								mark(fl.otherAddr, n)
							}
						}
					}
				}
			}
			if grew && !queued[c.Callee] {
				queued[c.Callee] = true
				queue = append(queue, c.Callee)
			}
		}
	}
	// a network call is judged with what its function finally knows
	for _, nc := range fl.net {
		var args []string
		for _, a := range nc.call.Args {
			args = append(args, a.Text)
		}
		if mentionsAny(strings.Join(args, ", "), fl.caller[nc.sym]) {
			fl.callerReaches = true
		}
	}
	return fl
}

// carriesCallerData reports whether a network call reached from the handler is addressed or fed
// with the caller's data
func carriesCallerData(g *graph.Graph, handler graph.SymbolID, reached map[graph.SymbolID]bool) bool {
	return walkFlow(g, handler, reached).callerReaches
}
