package taint

import (
	"regexp"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
)

// paramModifiers are the words that may precede a parameter's own name in its source text:
// TypeScript parameter properties (private db: Pool), Kotlin/Java finals, variadics
var paramModifiers = regexp.MustCompile(`^(?:(?:private|public|protected|readonly|override|final|const|mut|ref|out|in)\s+)*[*&.]*`)

// boundElsewhere reports whether the file binds name in a way the receiver checks
// (builtinContainerReceiver, projectInstanceMethod) do not read as an assignment: a parameter of
// any function or method in the file (including a TypeScript constructor parameter property), a
// for/with/except/catch variable, an arrow or lambda parameter, or a walrus. Inside such a scope
// the name may be any object, so what the file assigns to it elsewhere says nothing there.
func (c *ctx) boundElsewhere(file string, src []byte, name string) bool {
	for _, s := range c.g.Symbols {
		if s == nil || s.File != file {
			continue
		}
		for _, p := range s.Params {
			p = paramModifiers.ReplaceAllString(strings.TrimSpace(p), "")
			if i := strings.IndexAny(p, ":= \t?,)"); i >= 0 {
				p = p[:i]
			}
			if p == name {
				return true
			}
		}
	}
	q := regexp.QuoteMeta(name)
	other := regexp.MustCompile(
		// constructor(private db: Pool), constructor(readonly db) - also when the graph's params miss it
		`\bconstructor\s*\([^)]*\b(?:private|public|protected|readonly)\s+(?:readonly\s+)?` + q + `\b` +
			// for db in ..., for k, db in ..., for (const db of ...), with x as db, except E as db
			`|\bfor\s*\(?\s*(?:(?:const|let|var)\s+)?(?:[\w\s,\[\]{}]*[,\[{]\s*)?` + q + `\b[^\n]*\b(?:in|of)\b` +
			`|\bas\s+` + q + `\b` +
			`|\bcatch\s*\(\s*` + q + `\b` +
			// (db) => ..., db => ..., (a, db) => ..., function (db) ..., lambda db: ...
			`|\(\s*(?:[\w$]+\s*(?::[^,()]+)?,\s*)*` + q + `\s*(?::[^,()]+)?(?:,[^()]*)?\)\s*(?::[^=]+)?=>` +
			`|(?:^|[^\w$.])` + q + `\s*=>` +
			`|\blambda\b[^:\n]*\b` + q + `\b[^:\n]*:` +
			`|\b` + q + `\s*:=`)
	return other.Match(src)
}

// receiverKey caches the receiver checks per file, receiver and callee for one run: the same
// receiver is asked about at every call on it, and each answer reads the whole file
type receiverKey struct{ file, recv, callee string }

func (c *ctx) containerReceiverCached(pf *parsedFile, file, recv string) bool {
	recv = strings.TrimSpace(recv)
	if recv == "" {
		return false
	}
	k := receiverKey{file: file, recv: recv}
	if v, ok := c.containerRecv[k]; ok {
		return v
	}
	v := c.builtinContainerReceiver(pf.src, pf.adapter.ID, recv) && !c.boundElsewhere(file, pf.src, bareName(recv))
	if c.containerRecv == nil {
		c.containerRecv = map[receiverKey]bool{}
	}
	c.containerRecv[k] = v
	return v
}

func (c *ctx) instanceMethodCached(pf *parsedFile, file, recv, calleeText string) (*graph.Symbol, bool) {
	recv = strings.TrimSpace(recv)
	if recv == "" {
		return nil, false
	}
	k := receiverKey{file: file, recv: recv, callee: strings.TrimSpace(calleeText)}
	if v, ok := c.instanceRecv[k]; ok {
		return v, v != nil
	}
	m, ok := c.projectInstanceMethod(pf.src, file, recv, calleeText)
	if ok && c.boundElsewhere(file, pf.src, recv) {
		m, ok = nil, false
	}
	if c.instanceRecv == nil {
		c.instanceRecv = map[receiverKey]*graph.Symbol{}
	}
	if !ok {
		m = nil
	}
	c.instanceRecv[k] = m
	return m, ok
}

// factoryCandidatesCached is factoryCandidates, cached per file, receiver and callee, and empty
// when the file binds the receiver in a way that does not read as an assignment
func (c *ctx) factoryCandidatesCached(pf *parsedFile, file, recv, calleeText string) []*graph.Symbol {
	recv = strings.TrimSpace(recv)
	if recv == "" {
		return nil
	}
	k := receiverKey{file: file, recv: recv, callee: strings.TrimSpace(calleeText)}
	if v, ok := c.factoryRecv[k]; ok {
		return v
	}
	ms := c.factoryCandidates(pf.src, file, recv, calleeText)
	if len(ms) > 0 && c.boundElsewhere(file, pf.src, recv) {
		ms = nil
	}
	if c.factoryRecv == nil {
		c.factoryRecv = map[receiverKey][]*graph.Symbol{}
	}
	c.factoryRecv[k] = ms
	return ms
}

// bareName is the name a receiver binds: db for this.db or self.db, the name itself otherwise
func bareName(recv string) string {
	if i := strings.LastIndexByte(recv, '.'); i >= 0 {
		return recv[i+1:]
	}
	return recv
}
