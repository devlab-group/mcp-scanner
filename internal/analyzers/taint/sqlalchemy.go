package taint

import (
	"regexp"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// sqlaConstructs are the SQLAlchemy (and SQLModel) statement constructors. A statement built from
// them carries Python values as bound parameters, never as SQL text: update(T).where(T.id == x)
// sends x apart from the statement.
var sqlaConstructs = map[string]bool{"select": true, "update": true, "delete": true, "insert": true}

// sqlaRawText finds what puts text into a SQLAlchemy statement as SQL, or builds a string that
// could: text(), literal_column(), f-strings, str.format, % formatting and string concatenation
var sqlaRawText = regexp.MustCompile(`\btext\s*\(|\bliteral_column\s*\(|\b[fF][rR]?["']|\.format\s*\(|["']\s*%|["']\s*\+|\+\s*["']`)

// sqlalchemyStatement reports whether a Python execute() argument is a SQLAlchemy statement built
// from select/update/delete/insert with no raw SQL text in it. The constructor is the one the file
// imports from sqlalchemy or sqlmodel - directly, through a module alias (sa.select), or through a
// same-file wrapper whose only return calls one (def select(*a): return _sa_select(*a)).
//
// A variable is followed through the enclosing function's text (scope): stmt = select(T) and
// stmt = stmt.where(...) qualify only when every assignment to it is such a statement or a method
// chained onto it, with no raw SQL text in any of them.
func (c *ctx) sqlalchemyStatement(file, arg, scope string) bool {
	t := strings.TrimSpace(arg)
	if isPlainIdent(t) && scope != "" {
		re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(t) + `\s*(?::[^=\n]+)?=[^=]`)
		locs := re.FindAllStringIndex(scope, -1)
		if len(locs) == 0 {
			return false
		}
		var rhss []string
		for _, l := range locs {
			rhss = append(rhss, assignedExpression(scope[l[1]-1:]))
		}
		built := false
		for _, rhs := range rhss {
			rhs = peelParens(withoutPyComments(rhs))
			if sqlaRawText.MatchString(rhs) {
				return false
			}
			if strings.HasPrefix(rhs, t+".") {
				continue
			}
			if !c.sqlalchemyStatement(file, rhs, "") {
				return false
			}
			built = true
		}
		return built
	}
	t = peelParens(withoutPyComments(t))
	if sqlaRawText.MatchString(t) {
		return false
	}
	i := strings.IndexByte(t, '(')
	if i <= 0 {
		return false
	}
	return c.sqlalchemyConstruct(file, strings.TrimSpace(t[:i]), true)
}

func (c *ctx) sqlalchemyConstruct(file, name string, followWrapper bool) bool {
	f := c.g.Files[file]
	if f == nil || name == "" {
		return false
	}
	fromSQLA := func(p string) bool {
		return p == "sqlalchemy" || p == "sqlmodel" || strings.HasPrefix(p, "sqlalchemy.") || strings.HasPrefix(p, "sqlmodel.")
	}
	if root, last, dotted := strings.Cut(name, "."); dotted {
		// sa.select(...) after `import sqlalchemy as sa`
		if !sqlaConstructs[last] {
			return false
		}
		for _, imp := range f.Imports {
			local := imp.Alias
			if local == "" {
				local = imp.Path
			}
			if local == root && fromSQLA(imp.Path) {
				return true
			}
		}
		return false
	}
	for _, imp := range f.Imports {
		local := imp.Alias
		if local == "" {
			local = parser.LastSegment(imp.Path)
		}
		if local == name && fromSQLA(imp.Path) && sqlaConstructs[parser.LastSegment(imp.Path)] {
			return true
		}
	}
	if !followWrapper {
		return false
	}
	// A same-file function of that name whose only return calls a SQLAlchemy constructor
	for _, id := range c.idx[name] {
		sym := c.g.Symbols[id]
		if sym == nil || sym.File != file || (sym.Kind != graph.KindFunction && sym.Kind != graph.KindMethod) {
			continue
		}
		hpf, def := c.defNodeFor(sym)
		if hpf == nil || def == nil {
			return false
		}
		ret := returnedExpression(def)
		if ret == nil || ret.Kind() != "call" {
			return false
		}
		fn := ret.ChildByFieldName("function")
		return fn != nil && c.sqlalchemyConstruct(file, fn.Utf8Text(hpf.src), false)
	}
	return false
}

// assignedExpression reads one Python expression from the start of s: to the end of its line, and
// on over the next lines while a bracket it opened is still open
func assignedExpression(s string) string {
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == '\\' {
				i++
			} else if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '#':
			// a comment runs to the end of its line and opens nothing
			for i+1 < len(s) && s[i+1] != '\n' {
				i++
			}
		case '"', '\'':
			quote = ch
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '\n':
			if depth <= 0 {
				return s[:i]
			}
		}
	}
	return s
}

// withoutPyComments drops Python # comments outside string literals
func withoutPyComments(s string) string {
	var b strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			b.WriteByte(ch)
			if ch == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '#' {
			for i+1 < len(s) && s[i+1] != '\n' {
				i++
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
		}
		b.WriteByte(ch)
	}
	return b.String()
}

// peelParens trims s and removes parentheses that wrap all of it - stmt = ( select(T) ... ) spans
// lines that way - but not the pair in (a).where(b), where the first ")" closes early
func peelParens(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' && bracketedParen(s, 0) == s[1:len(s)-1] {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}
