package taint

import (
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A file's content or an HTTP response is untrusted when whoever can write it is: a page at an
// address the caller picks, a repository the server cloned for the caller. Content read from a
// location the code itself fixes - a literal path of the server's own files, a literal URL of its
// own fixed host - is the server's data, as far as the code shows. constantLocator reads that at
// the source: the location argument of the read must be made only of literals and constants the
// file assigns a literal. A location configured at run time (an environment variable) is not
// constant: what the operator points it at decides. A literal path whose folder the file mentions
// anywhere else is not constant either: the server may write there - clone, download, extract -
// for the caller.

var (
	interpPy    = regexp.MustCompile(`\{([^{}]*)\}`)
	interpJS    = regexp.MustCompile(`\$\{([^{}]*)\}`)
	anyLiteral  = regexp.MustCompile(`[fFrRbB]?"(?:[^"\\]|\\.)*"|[fFrRbB]?'(?:[^'\\]|\\.)*'|` + "`(?:[^`\\\\]|\\\\.)*`")
	identifier  = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	pathLiteral = regexp.MustCompile(`^["'` + "`" + `]([^"'` + "`" + `$]+)["'` + "`" + `]$`)
	// names a location may be built with besides literals: the join and path helpers, and the
	// server's own folder
	locatorBuiltins = map[string]bool{
		"path": true, "join": true, "resolve": true, "os": true, "filepath": true, "Join": true, "Path": true,
		"pathlib": true, "dirname": true, "abspath": true, "__dirname": true, "__file__": true,
		"fileURLToPath": true, "new": true, "URL": true, "parent": true,
	}
	// the module's own location, as one token: import.meta.url, import.meta.dirname
	moduleLocation = regexp.MustCompile(`\bimport\.meta\.(?:url|dirname|filename)\b`)
)

// worldWritable is a shared folder any local user can write: a literal path there is not the
// server's own file
var worldWritable = regexp.MustCompile(`["'` + "`" + `/](?:tmp|var/tmp|dev/shm|private/tmp)(?:/|["'` + "`" + `])|\btmpdir\b|\bgettempdir\b|\bTempDir\b`)

// literalConstants are the names a file assigns a pure literal: API = "https://x/", const BASE = "/srv"
func literalConstants(ls []string) map[string]bool {
	out := map[string]bool{}
	assign := regexp.MustCompile(`^\s*(?:export\s+)?(?:(?:const|let|var|final|static)\s+)*([A-Za-z_$][\w$]*)\s*(?::\s*[\w.\[\]]+\s*)?:?=\s*(["'` + "`" + `])([^"'` + "`" + `$\\]*)["'` + "`" + `]\s*;?\s*$`)
	for _, l := range ls {
		if m := assign.FindStringSubmatch(l); m != nil {
			out[m[1]] = true
		}
	}
	return out
}

// constantText reports whether an argument is made only of literals, constants the file assigns
// a literal, and path helpers
func constantText(text string, consts map[string]bool) bool {
	t := strings.TrimSpace(moduleLocation.ReplaceAllString(text, "__dirname"))
	if t == "" {
		return false
	}
	var names []string
	for _, lit := range anyLiteral.FindAllString(t, -1) {
		if strings.HasPrefix(lit, "`") {
			for _, m := range interpJS.FindAllStringSubmatch(lit, -1) {
				names = append(names, identifier.FindAllString(m[1], -1)...)
			}
		} else if lit[0] == 'f' || lit[0] == 'F' {
			for _, m := range interpPy.FindAllStringSubmatch(lit, -1) {
				names = append(names, identifier.FindAllString(m[1], -1)...)
			}
		}
	}
	rest := anyLiteral.ReplaceAllString(t, `""`)
	if strings.ContainsAny(rest, "[") {
		return false // an index into something: meta["path"]
	}
	names = append(names, identifier.FindAllString(rest, -1)...)
	for _, n := range names {
		if !locatorBuiltins[n] && !consts[n] {
			return false
		}
	}
	return true
}

// callsAt are the calls on a file's line whose callee names the source
func (gi *guardIndex) callsAt(file string, line int, symbol string) []graph.Call {
	if gi.g == nil {
		return nil
	}
	if gi.callIndex == nil {
		gi.callIndex = map[string][]graph.Call{}
		for _, c := range gi.g.Calls {
			k := c.File + ":" + strconv.Itoa(c.Line)
			gi.callIndex[k] = append(gi.callIndex[k], c)
		}
	}
	// the source is named by the read it starts with: (await fetch(url)).json is a fetch
	want := parser.LastSegment(symbol)
	for _, p := range sourcePatterns {
		if mentionsIdent(symbol, p.text) {
			want = parser.LastSegment(p.text)
			break
		}
	}
	var out []graph.Call
	for _, c := range gi.callIndex[file+":"+strconv.Itoa(line)] {
		if parser.LastSegment(c.CalleeText) == want {
			out = append(out, c)
		}
	}
	return out
}

// constantLocator reports whether an external-content source reads from a location the code
// fixes, and names it
func (gi *guardIndex) constantLocator(src model.FlowStep) (string, bool) {
	if src.Detail != "file contents" && src.Detail != "HTTP response body" {
		return "", false
	}
	calls := gi.callsAt(src.File, src.Line, src.Symbol)
	if len(calls) == 0 {
		return "", false
	}
	ls := gi.lines(src.File)
	consts := literalConstants(ls)
	where := ""
	for _, c := range calls {
		var loc string
		for _, a := range c.Args {
			if a.Keyword == "" || a.Keyword == "url" || a.Keyword == "path" || a.Keyword == "file" {
				loc = a.Text
				break
			}
		}
		if loc == "" || !constantText(loc, consts) || worldWritable.MatchString(loc) {
			return "", false
		}
		if src.Detail == "file contents" && gi.locationUsedElsewhere(ls, src.Line, loc, consts) {
			return "", false
		}
		where = clipText(strings.TrimSpace(loc), 80)
	}
	return where, true
}

// locationUsedElsewhere reports whether the folder of a literal path, or a constant the location
// is built with, appears on another line of the file than the read and the constant's own
// assignment: the server may write there - clone, download, extract - for the caller
func (gi *guardIndex) locationUsedElsewhere(ls []string, readLine int, loc string, consts map[string]bool) bool {
	var needles []*regexp.Regexp
	for _, lit := range anyLiteral.FindAllString(loc, -1) {
		if m := pathLiteral.FindStringSubmatch(lit); m != nil {
			if dir := path.Dir(m[1]); dir != "." && dir != "/" && dir != "" {
				needles = append(needles, regexp.MustCompile(regexp.QuoteMeta(dir)))
			}
		}
	}
	for _, n := range identifier.FindAllString(anyLiteral.ReplaceAllString(loc, `""`), -1) {
		if consts[n] {
			needles = append(needles, regexp.MustCompile(`\b`+regexp.QuoteMeta(n)+`\b`))
		}
	}
	assign := regexp.MustCompile(`^\s*(?:export\s+)?(?:(?:const|let|var|final|static)\s+)*([A-Za-z_$][\w$]*)\s*(?::\s*[\w.\[\]]+\s*)?:?=`)
	for k, l := range ls {
		if k+1 == readLine {
			continue
		}
		if m := assign.FindStringSubmatch(l); m != nil && consts[m[1]] && anyLiteral.MatchString(l) && !strings.Contains(l[len(m[0]):], "(") {
			continue // the constant's own assignment
		}
		for _, re := range needles {
			if re.MatchString(l) {
				return true
			}
		}
	}
	return false
}
