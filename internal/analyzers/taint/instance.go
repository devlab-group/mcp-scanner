package taint

import (
	"regexp"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// projectInstanceMethod resolves recv.method(...) when recv is a plain name that the file binds
// only to instances of one project class, and that class itself defines method:
//
//	SESSION = TclSession()        # or: const session = new TclSession(opts)
//	SESSION.execute(command)      # TclSession.execute, not a database cursor's execute
//
// Every assignment to the name in the file must call the same class (a None placeholder or any
// other value fails), the class must be the project's own (in this file or imported by it), it
// must define the method in its own body, and nothing in the file may assign recv.method. The
// answer is a fact of the code, not of names: the object is that class's instance, so the call
// is that method, which is then followed like any resolved call.
func (c *ctx) projectInstanceMethod(src []byte, file, recv, calleeText string) (*graph.Symbol, bool) {
	recv = strings.TrimSpace(recv)
	method := parser.LastSegment(calleeText)
	if !isGuardIdent(recv) || !isGuardIdent(method) || strings.TrimSpace(calleeText) != recv+"."+method {
		return nil, false
	}
	text := string(src)
	if !strings.Contains(text, recv) {
		return nil, false
	}
	assign := regexp.MustCompile(`(?m)^[ \t]*(?:export\s+)?(?:const|let|var|final|val)?\s*` + regexp.QuoteMeta(recv) + `\s*(?::[^=\n]+)?:?=([^=].*)$`)
	ctor := regexp.MustCompile(`^\s*(?:await\s+)?(?:new\s+)?([A-Za-z_$][\w$]*)\s*\(`)
	class := ""
	for _, m := range assign.FindAllStringSubmatch(text, -1) {
		k := ctor.FindStringSubmatch(m[1])
		if k == nil || class != "" && k[1] != class {
			return nil, false
		}
		class = k[1]
	}
	if class == "" {
		return nil, false
	}
	if regexp.MustCompile(`\b` + regexp.QuoteMeta(recv) + `\s*\.\s*` + regexp.QuoteMeta(method) + `\s*=[^=]`).MatchString(text) {
		return nil, false // the method replaced on the instance
	}
	var cls *graph.Symbol
	for _, id := range c.idx[class] {
		s := c.g.Symbols[id]
		if s == nil || s.Kind != graph.KindClass || s.File != file && !c.importNames(file, s.File) {
			continue
		}
		if cls != nil {
			return nil, false
		}
		cls = s
	}
	if cls == nil {
		return nil, false
	}
	var found *graph.Symbol
	for _, id := range c.idx[method] {
		s := c.g.Symbols[id]
		if s == nil || s.Kind != graph.KindMethod && s.Kind != graph.KindFunction || s.File != cls.File ||
			s.Receiver != "" && s.Receiver != cls.Name || s.Line <= cls.Line || s.EndLine > cls.EndLine || !c.directMember(cls, s) {
			continue
		}
		if found != nil {
			return nil, false
		}
		found = s
	}
	return found, found != nil
}

// directMember reports whether m sits in cls's own body: no other function or class of the
// file encloses m inside cls (a def nested in another method is not the class's method).
// Python's graph records methods as functions by line range, with no receiver.
func (c *ctx) directMember(cls, m *graph.Symbol) bool {
	for _, s := range c.g.Symbols {
		if s == nil || s.ID == m.ID || s.ID == cls.ID || s.File != m.File {
			continue
		}
		if s.Kind != graph.KindFunction && s.Kind != graph.KindMethod && s.Kind != graph.KindClass {
			continue
		}
		if s.Line > cls.Line && s.Line < m.Line && m.EndLine <= s.EndLine {
			return false
		}
	}
	return true
}
