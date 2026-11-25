package transport

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/devlab-group/mcp-scanner/internal/analyzers/behavioral"
	"github.com/devlab-group/mcp-scanner/internal/analyzers/taint"
	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// reach is how much a caller of the server's tools can do, from weakest to strongest
type reach int

const (
	reachNone   reach = iota // nothing beyond what the caller could do without the server
	reachRead                // reads local data, or writes files only as a side effect
	reachCred                // acts with a credential the server holds (an API key, a service token)
	reachStrong              // runs programs or code, queries a database, changes files on request, reads sensitive paths, holds a private key
)

// power is what the tools in one server scope can do, with the evidence for the strongest level
type power struct {
	level   reach
	reasons []string
	tools   int
}

func (p *power) add(level reach, reason string) {
	if level > p.level {
		p.level, p.reasons = level, nil
	}
	if level == p.level && level > reachNone && len(p.reasons) < 4 && !containsString(p.reasons, reason) {
		p.reasons = append(p.reasons, reason)
	}
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// mutatingFileCalls are file-sink callees, by last segment, that change or remove a file.
// Creating a directory is not on the list: it is how a server makes its own cache folder.
var mutatingFileCalls = map[string]bool{
	"writeFile": true, "writeFileSync": true, "appendFile": true, "appendFileSync": true, "unlink": true, "unlinkSync": true,
	"rm": true, "rmSync": true, "rmdir": true, "rmdirSync": true, "rename": true, "renameSync": true, "copyFile": true,
	"copyFileSync": true, "cp": true, "cpSync": true, "createWriteStream": true, "chmod": true, "symlink": true,
	"write_text": true, "write_bytes": true, "WriteFile": true, "Create": true, "Remove": true, "RemoveAll": true,
	"Rename": true, "Symlink": true, "Chmod": true, "remove": true, "removedirs": true, "rmtree": true, "move": true,
	"copy": true, "copy2": true, "copyfile": true, "copytree": true, "unpack_archive": true, "extractall": true,
	"write": true, "writeString": true, "renames": true, "symlink_to": true,
}

// opensForWriting reports whether an open call's mode or flags write: Python's open(p, "w"),
// Path.open("a"), Go's os.OpenFile(p, os.O_WRONLY|os.O_CREATE, ...)
func opensForWriting(call graph.Call) bool {
	last := parser.LastSegment(call.CalleeText)
	if last != "open" && last != "OpenFile" {
		return false
	}
	for _, a := range call.Args {
		if a.Keyword == "mode" || a.Literal && len(a.Value) <= 4 {
			if strings.ContainsAny(a.Value, "wax+") {
				return true
			}
		}
		if strings.Contains(a.Text, "O_WRONLY") || strings.Contains(a.Text, "O_RDWR") || strings.Contains(a.Text, "O_CREATE") || strings.Contains(a.Text, "O_APPEND") {
			return true
		}
	}
	return false
}

// envReadText finds environment reads in source text, by the variable name, in the forms the
// three languages write them
var envReadText = regexp.MustCompile(`\bos\.environ(?:\.get)?\s*[\[(]\s*["']([A-Za-z_]\w*)["']|\b(?:os\.)?getenv\s*\(\s*["']([A-Za-z_]\w*)["']|\bprocess\.env\.([A-Za-z_]\w*)|\bprocess\.env\[\s*["'` + "`" + `]([A-Za-z_]\w*)["'` + "`" + `]\s*\]|\bos\.(?:Getenv|LookupEnv)\s*\(\s*"([A-Za-z_]\w*)"`)

// credentialWords are the name parts that make a variable a credential; matched as whole parts
// of the name, so KEYWORDS and KEYBOARD are not keys
var credentialWords = map[string]bool{
	"KEY": true, "APIKEY": true, "TOKEN": true, "SECRET": true, "PASSWORD": true, "PASSWD": true, "PWD": true,
	"CREDENTIAL": true, "CREDENTIALS": true, "PAT": true, "MNEMONIC": true,
}

// settingTails are last name parts that make a credential-looking name a setting about one
var settingTails = map[string]bool{
	"FILE": true, "PATH": true, "DIR": true, "URL": true, "URI": true, "HOST": true, "PORT": true, "HEADER": true,
	"NAME": true, "ID": true, "TYPE": true, "MODE": true, "ENABLED": true, "ENABLE": true, "DISABLED": true,
	"REQUIRED": true, "LIMIT": true, "COUNT": true, "SIZE": true, "MAX": true, "TTL": true, "TIMEOUT": true,
	"EXPIRY": true, "LENGTH": true, "PREFIX": true, "PROVIDER": true, "FIELD": true, "PARAM": true,
}

// nameParts splits SOME_API_KEY, someApiKey and some-api-key into upper-case parts
func nameParts(name string) []string {
	var parts []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, strings.ToUpper(string(cur)))
			cur = nil
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && i > 0 && unicode.IsLower(rs[i-1]):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return parts
}

// credentialName reports whether a variable name holds a credential
func credentialName(name string) bool {
	parts := nameParts(name)
	if len(parts) == 0 || settingTails[parts[len(parts)-1]] {
		return false
	}
	for _, p := range parts {
		if credentialWords[p] {
			return true
		}
	}
	return false
}

// privateKeyName reports whether a credential is a private key or wallet seed, which acts as the
// owner itself rather than as an account at a service
func privateKeyName(name string) bool {
	u := strings.ToUpper(name)
	return strings.Contains(u, "PRIVATE_KEY") || strings.Contains(u, "PRIVATEKEY") || strings.Contains(u, "MNEMONIC") || strings.Contains(u, "SEED_PHRASE")
}

// credentialEnv lists the credential-named environment variables a source text reads
func credentialEnv(src string) []string {
	var out []string
	for _, m := range envReadText.FindAllStringSubmatch(src, -1) {
		name := strings.Join(m[1:], "")
		if name != "" && credentialName(name) && !containsString(out, name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (p *power) credential(who, v string) {
	if privateKeyName(v) {
		p.add(reachStrong, fmt.Sprintf("%s acts with the private key in %s", who, v))
		return
	}
	p.add(reachCred, fmt.Sprintf("%s acts with the credential in %s", who, v))
}

// fileNouns are the words with which a tool says it works with files: the reading and writing
// verbs alone also describe data, notes and tickets
var fileNouns = regexp.MustCompile(`(?i)\b(files?|folders?|director(y|ies)|disk|paths?|filesystem|file system)\b`)

func declaresFiles(text string) bool {
	return fileNouns.MatchString(strings.NewReplacer("_", " ", "-", " ").Replace(text))
}

// configFragments are sensitive-path hits that are usually the server reading its own
// configuration (dotenv, a TLS certificate), not a caller reaching the user's secrets
var configFragments = map[string]bool{".env": true, ".pem": true}

// start is one entry point whose reach is weighed: a capability handler, or a function of a file
// that dispatches tools itself
type start struct {
	id         graph.SymbolID
	who        string
	declaresFS bool
}

// capabilityPower weighs what the capabilities in scope reach, and the code of the extra files
// when the server dispatches tools itself (no registered capability to start from)
func (a *analysis) capabilityPower(scope string, extraFiles []string) power {
	var p power
	var starts []start
	seen := map[graph.SymbolID]bool{}
	for _, c := range a.g.Capabilities {
		if c.Handler == "" || !inScope(c.File, scope) || seen[c.Handler] {
			continue
		}
		if _, ok := a.g.Symbols[c.Handler]; !ok {
			continue
		}
		seen[c.Handler] = true
		p.tools++
		starts = append(starts, start{c.Handler, fmt.Sprintf("%s %q", c.Kind, source.DisplayName(c)), declaresFiles(c.Name + " " + c.Description)})
	}
	for _, path := range extraFiles {
		for id, sym := range a.g.Symbols {
			if sym.File == path && !seen[id] {
				seen[id] = true
				starts = append(starts, start{id, "the request handler code in " + path, false})
			}
		}
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i].id < starts[j].id })
	files := map[string]bool{}
	for _, f := range extraFiles {
		files[f] = true
	}
	for _, s := range starts {
		reached := a.reachedWithNested(s.id)
		ids := make([]graph.SymbolID, 0, len(reached))
		for id := range reached {
			sym := a.g.Symbols[id]
			if sym == nil || !inScope(sym.File, scope) {
				// resolution by name reaches same-named functions of other packages in a
				// monorepo; a tool runs its own package's code
				continue
			}
			ids = append(ids, id)
			files[sym.File] = true
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			for _, call := range a.g.CallsFrom(id) {
				a.weighCall(&p, s, call)
			}
		}
		b := behavioral.Behavior(a.g, s.id)
		if b.Process {
			p.add(reachStrong, s.who+" runs programs")
		}
		var paths []string
		for _, sp := range b.SensitivePaths {
			switch {
			case strings.HasPrefix(sp, "env:"):
				// credential variables, weighed below by name
			case configFragments[sp]:
				p.add(reachRead, fmt.Sprintf("%s reads its configuration (%s)", s.who, sp))
			default:
				paths = append(paths, sp)
			}
		}
		if len(paths) > 0 {
			p.add(reachStrong, fmt.Sprintf("%s reads %s", s.who, strings.Join(paths, ", ")))
		}
		for _, v := range b.EnvVars {
			if credentialName(v) {
				p.credential(s.who, v)
			}
		}
	}
	// a credential read at module level in a file the tools run code from is used by those tools
	// without the handler itself reading the variable
	var paths []string
	for f := range files {
		if !testPath.MatchString(f) {
			paths = append(paths, f)
		}
	}
	sort.Strings(paths)
	for _, path := range paths {
		for _, v := range credentialEnv(a.source(path)) {
			p.credential("the server code in "+path, v)
		}
	}
	return p
}

// reachedWithNested is what handler reaches through the call graph, plus every function written
// inside a reached one: a callback handed to new Promise(...), setTimeout or a library runs as
// part of the handler, but the graph has no call edge to it
func (a *analysis) reachedWithNested(h graph.SymbolID) map[graph.SymbolID]bool {
	reached, _ := a.g.Reachable(h)
	reached[h] = true
	if a.byFile == nil {
		a.byFile = map[string][]*graph.Symbol{}
		for _, s := range a.g.Symbols {
			a.byFile[s.File] = append(a.byFile[s.File], s)
		}
	}
	for changed := true; changed; {
		changed = false
		for id := range reached {
			outer := a.g.Symbols[id]
			if outer == nil || outer.EndLine < outer.Line {
				continue
			}
			for _, s := range a.byFile[outer.File] {
				if !reached[s.ID] && s.Line >= outer.Line && s.EndLine <= outer.EndLine && s.EndLine >= s.Line {
					reached[s.ID] = true
					changed = true
					more, _ := a.g.Reachable(s.ID)
					for m := range more {
						reached[m] = true
					}
				}
			}
		}
	}
	return reached
}

func (a *analysis) weighCall(p *power, s start, call graph.Call) {
	gf := a.g.Files[call.File]
	if gf == nil {
		return
	}
	imports := make([]string, 0, len(gf.Imports))
	for _, imp := range gf.Imports {
		imports = append(imports, imp.Path)
	}
	cat, ok := taint.OperationCategory(language.ID(gf.Language), call.CalleeText, call.Args, call.Resolved, imports)
	if !ok {
		return
	}
	callee := strings.TrimSpace(call.CalleeText)
	if len(callee) > 60 {
		callee = callee[:60] + "..."
	}
	at := fmt.Sprintf(" (%s at %s:%d)", callee, call.File, call.Line)
	switch cat {
	case "command_injection":
		p.add(reachStrong, s.who+" runs programs"+at)
	case "eval":
		p.add(reachStrong, s.who+" evaluates code"+at)
	case "sql_injection":
		if len(call.Args) > 0 && call.Args[0].Literal {
			// fixed statements on the server's own database: data access, not arbitrary queries
			p.add(reachRead, s.who+" reads or writes its database with fixed statements"+at)
		} else {
			p.add(reachStrong, s.who+" runs database queries built at run time"+at)
		}
	case "path_traversal":
		switch {
		case !mutatingFileCalls[parser.LastSegment(call.CalleeText)] && !opensForWriting(call):
			p.add(reachRead, s.who+" reads local files"+at)
		case s.declaresFS:
			p.add(reachStrong, s.who+" writes or removes files"+at)
		default:
			// a tool that does not say it works with files writes its cache, log or output
			p.add(reachRead, s.who+" writes files as a side effect"+at)
		}
	case "deserialization", "raw_socket":
		p.add(reachRead, s.who+" handles raw data or sockets"+at)
	}
}

func inScope(path, scope string) bool {
	return scope == "" || path == scope || strings.HasPrefix(path, scope+"/")
}
