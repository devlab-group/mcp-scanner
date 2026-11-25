package taint

import (
	"regexp"
	"slices"
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
	return c.instanceOf(src, file, recv, calleeText)
}

var (
	returnStmt = regexp.MustCompile(`(?m)^[ \t]*return\b(.*)$`)
	yieldStmt  = regexp.MustCompile(`(?m)^[ \t]*(?:yield\b|.*=\s*yield\b)`)
	ctorCall   = regexp.MustCompile(`^\s*(?:await\s+)?(?:new\s+)?([A-Za-z_$][\w$]*)\s*\(`)
)

// factoryClasses names the classes the returns of a project function construct, or none when a
// return is anything else, there is no return, or the function is a generator
func (c *ctx) factoryClasses(fn *graph.Symbol) []string {
	pf, def := c.defNodeFor(fn)
	if pf == nil || def == nil {
		return nil
	}
	body := def.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	text := body.Utf8Text(pf.src)
	if yieldStmt.MatchString(text) {
		return nil
	}
	var out []string
	for _, m := range returnStmt.FindAllStringSubmatch(text, -1) {
		k := ctorCall.FindStringSubmatch(m[1])
		if k == nil {
			return nil
		}
		if !slices.Contains(out, k[1]) {
			out = append(out, k[1])
		}
	}
	return out
}

// instanceOf is projectInstanceMethod: the method of the one project class every assignment to
// recv in the file constructs
func (c *ctx) instanceOf(src []byte, file, recv, calleeText string) (*graph.Symbol, bool) {
	recv = strings.TrimSpace(recv)
	method := parser.LastSegment(calleeText)
	if !isGuardIdent(recv) || !isGuardIdent(method) || strings.TrimSpace(calleeText) != recv+"."+method {
		return nil, false
	}
	text := string(src)
	if !strings.Contains(text, recv) {
		return nil, false
	}
	class := ""
	for _, m := range assignsTo(recv).FindAllStringSubmatch(text, -1) {
		k := ctorCall.FindStringSubmatch(m[1])
		if k == nil || class != "" && k[1] != class {
			return nil, false
		}
		class = k[1]
	}
	if class == "" || methodReplaced(text, recv, method) {
		return nil, false
	}
	m := c.classMethod(class, file, method)
	return m, m != nil
}

// assignsTo matches the lines assigning a name, with the assigned text as the first group
func assignsTo(recv string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^[ \t]*(?:export\s+)?(?:const|let|var|final|val)?\s*` + regexp.QuoteMeta(recv) + `\s*(?::[^=\n]+)?:?=([^=].*)$`)
}

// methodReplaced reports whether the file assigns recv.method: the method replaced on the instance
func methodReplaced(text, recv, method string) bool {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(recv) + `\s*\.\s*` + regexp.QuoteMeta(method) + `\s*=[^=]`).MatchString(text)
}

// classMethod is the method of the one project class named class - defined in from or imported
// by it - that the class defines in its own body, or nil
func (c *ctx) classMethod(class, from, method string) *graph.Symbol {
	var cls *graph.Symbol
	for _, id := range c.idx[class] {
		s := c.g.Symbols[id]
		if s == nil || s.Kind != graph.KindClass || s.File != from && !c.importNames(from, s.File) {
			continue
		}
		if cls != nil {
			return nil
		}
		cls = s
	}
	if cls == nil {
		return nil
	}
	var found *graph.Symbol
	for _, id := range c.idx[method] {
		s := c.g.Symbols[id]
		if s == nil || s.Kind != graph.KindMethod && s.Kind != graph.KindFunction || s.File != cls.File ||
			s.Receiver != "" && s.Receiver != cls.Name || s.Line <= cls.Line || s.EndLine > cls.EndLine || !c.directMember(cls, s) {
			continue
		}
		if found != nil {
			return nil
		}
		found = s
	}
	return found
}

// factoryCandidates resolves recv.method(...) when recv is built by a project factory function:
//
//	def get_backend(): return LocalBackend(ROOT)
//	backend = get_backend()
//	backend.write_text(key, text)     # LocalBackend.write_text, not pathlib's
//
// It returns the methods the call may reach: every assignment to recv in recv.method(...) may call when every assignment to recv in
// the file calls a project function, and every return of those functions constructs a project
// class that defines method in its own body: one method when the functions build one class,
// one per class otherwise. Any other assignment or return, or a class without its own method,
// leaves none.
func (c *ctx) factoryCandidates(src []byte, file, recv, calleeText string) []*graph.Symbol {
	recv = strings.TrimSpace(recv)
	method := parser.LastSegment(calleeText)
	if !isGuardIdent(recv) || !isGuardIdent(method) || strings.TrimSpace(calleeText) != recv+"."+method {
		return nil
	}
	text := string(src)
	if !strings.Contains(text, recv) || methodReplaced(text, recv, method) {
		return nil
	}
	var out []*graph.Symbol
	seen := map[graph.SymbolID]bool{}
	any := false
	for _, m := range assignsTo(recv).FindAllStringSubmatch(text, -1) {
		any = true
		k := ctorCall.FindStringSubmatch(m[1])
		if k == nil {
			return nil
		}
		fn, ok := c.resolveCallee(file, k[1])
		if !ok || fn.Kind != graph.KindFunction && fn.Kind != graph.KindMethod {
			return nil
		}
		classes := c.factoryClasses(fn)
		if len(classes) == 0 {
			return nil
		}
		for _, class := range classes {
			ms := c.classMethod(class, fn.File, method)
			if ms == nil {
				return nil
			}
			if !seen[ms.ID] {
				seen[ms.ID] = true
				out = append(out, ms)
			}
		}
	}
	if !any {
		return nil
	}
	return out
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
