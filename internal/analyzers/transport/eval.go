package transport

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// valState is how much the code fixes a listen host or address
type valState int

const (
	valUnknown valState = iota // a runtime value the scanner cannot read
	valLiteral                 // a fixed string, or the default an environment read falls back to
	valAbsent                  // no value: undefined, None, or an unset environment variable with no default
)

// hostVal is the value a listen host or address expression has when the user changes nothing:
// a literal, or the default of an environment variable. env names the variable the user could
// set to change it.
type hostVal struct {
	state valState
	value string
	env   string
	// partial marks a value whose tail is a runtime expression (":" + port, fmt.Sprintf verbs):
	// only its leading text is fixed
	partial bool
}

func unknownVal() hostVal { return hostVal{state: valUnknown} }

func literalVal(v string) hostVal { return hostVal{state: valLiteral, value: v} }

const maxEvalDepth = 4

var (
	jsEnvMember    = regexp.MustCompile(`^(?:process|Bun|import\.meta)\.env\.([A-Za-z_]\w*)$`)
	jsEnvSubscript = regexp.MustCompile(`^(?:process|Bun|import\.meta)\.env\[\s*["'` + "`" + `]([A-Za-z_]\w*)["'` + "`" + `]\s*\]$`)
)

// evalJS reads a JavaScript or TypeScript host expression
func (f *file) evalJS(n *sitter.Node, depth int) hostVal {
	if n == nil {
		return hostVal{state: valAbsent}
	}
	if depth > maxEvalDepth {
		return unknownVal()
	}
	text := strings.TrimSpace(f.text(n))
	switch n.Kind() {
	case "string", "template_string":
		if v, ok := f.lit(n); ok {
			return literalVal(v)
		}
		return unknownVal()
	case "undefined", "null":
		return hostVal{state: valAbsent}
	case "identifier":
		if text == "undefined" {
			return hostVal{state: valAbsent}
		}
		if v := f.declValue(text); v != nil {
			return f.evalJS(v, depth+1)
		}
		if c, ok := f.g.Constants[text]; ok {
			return literalVal(c)
		}
		return unknownVal()
	case "member_expression", "subscript_expression":
		if m := jsEnvMember.FindStringSubmatch(text); m != nil {
			return hostVal{state: valAbsent, env: m[1]}
		}
		if m := jsEnvSubscript.FindStringSubmatch(text); m != nil {
			return hostVal{state: valAbsent, env: m[1]}
		}
		if n.Kind() == "member_expression" {
			// options.host from a command-line parser with a default
			if v, ok := f.cliDefault(f.text(n.ChildByFieldName("property"))); ok {
				return hostVal{state: valLiteral, value: v, env: "flag --" + f.text(n.ChildByFieldName("property"))}
			}
		}
		return unknownVal()
	case "binary_expression":
		op := f.text(n.ChildByFieldName("operator"))
		if op == "||" || op == "??" {
			l := f.evalJS(n.ChildByFieldName("left"), depth+1)
			if l.state == valAbsent || op == "||" && l.state == valLiteral && l.value == "" {
				r := f.evalJS(n.ChildByFieldName("right"), depth+1)
				if r.env == "" {
					r.env = l.env
				}
				return r
			}
			return l
		}
		return unknownVal()
	case "parenthesized_expression", "as_expression", "non_null_expression", "satisfies_expression", "type_assertion":
		if inner := firstNamed(n); inner != nil {
			return f.evalJS(inner, depth+1)
		}
	}
	return unknownVal()
}

// evalPy reads a Python host expression
func (f *file) evalPy(n *sitter.Node, depth int) hostVal {
	if n == nil {
		return hostVal{state: valAbsent}
	}
	if depth > maxEvalDepth {
		return unknownVal()
	}
	text := strings.TrimSpace(f.text(n))
	switch n.Kind() {
	case "string", "concatenated_string":
		if v, ok := f.lit(n); ok {
			return literalVal(v)
		}
		return unknownVal()
	case "none":
		return hostVal{state: valAbsent}
	case "identifier":
		if v := f.declValue(text); v != nil {
			return f.evalPy(v, depth+1)
		}
		if c, ok := f.g.Constants[text]; ok {
			return literalVal(c)
		}
		return unknownVal()
	case "call":
		callee := f.text(n.ChildByFieldName("function"))
		pos, kw := f.pyArgs(n)
		switch callee {
		case "os.getenv", "getenv", "os.environ.get", "environ.get":
			name := ""
			if len(pos) > 0 {
				name, _ = f.lit(pos[0])
			}
			def := kw["default"]
			if def == nil && len(pos) > 1 {
				def = pos[1]
			}
			if def == nil {
				return hostVal{state: valAbsent, env: name}
			}
			r := f.evalPy(def, depth+1)
			r.env = name
			return r
		case "str":
			if len(pos) == 1 {
				return f.evalPy(pos[0], depth+1)
			}
		}
		return unknownVal()
	case "subscript":
		if v := f.text(n.ChildByFieldName("value")); v == "os.environ" || v == "environ" {
			name, _ := f.lit(n.ChildByFieldName("subscript"))
			// a required variable: the code fixes no value of its own
			return hostVal{state: valUnknown, env: name}
		}
		return unknownVal()
	case "attribute":
		if v, ok := f.cliDefault(f.text(n.ChildByFieldName("attribute"))); ok {
			return hostVal{state: valLiteral, value: v, env: "flag --" + f.text(n.ChildByFieldName("attribute"))}
		}
		return unknownVal()
	case "boolean_operator":
		if strings.TrimSpace(f.text(n.ChildByFieldName("operator"))) == "or" {
			l := f.evalPy(n.ChildByFieldName("left"), depth+1)
			if l.state == valAbsent || l.state == valLiteral && l.value == "" {
				r := f.evalPy(n.ChildByFieldName("right"), depth+1)
				if r.env == "" {
					r.env = l.env
				}
				return r
			}
			return l
		}
		return unknownVal()
	case "parenthesized_expression":
		if inner := firstNamed(n); inner != nil {
			return f.evalPy(inner, depth+1)
		}
	}
	return unknownVal()
}

// evalGo reads a Go listen address expression (host:port)
func (f *file) evalGo(n *sitter.Node, depth int) hostVal {
	if n == nil {
		return hostVal{state: valAbsent}
	}
	if depth > maxEvalDepth {
		return unknownVal()
	}
	text := strings.TrimSpace(f.text(n))
	switch n.Kind() {
	case "interpreted_string_literal", "raw_string_literal":
		if v, ok := f.lit(n); ok {
			return literalVal(v)
		}
		return unknownVal()
	case "identifier":
		if v := f.declValue(text); v != nil {
			return f.evalGo(v, depth+1)
		}
		if c, ok := f.g.Constants[text]; ok {
			return literalVal(c)
		}
		if v, ok := f.cliDefault(text); ok {
			return hostVal{state: valLiteral, value: v, env: "flag " + text}
		}
		return unknownVal()
	case "unary_expression":
		if strings.HasPrefix(text, "*") {
			return f.evalGo(n.ChildByFieldName("operand"), depth+1)
		}
		return unknownVal()
	case "call_expression":
		callee := f.text(n.ChildByFieldName("function"))
		args := namedArgs(n.ChildByFieldName("arguments"))
		switch last := parser.LastSegment(callee); {
		case last == "String" && len(args) >= 2 && strings.Contains(callee, "lag"):
			// flag.String("addr", ":8080", "usage"), fs.String(...)
			if v, ok := f.lit(args[1]); ok {
				return hostVal{state: valLiteral, value: v, env: "flag"}
			}
		case last == "StringP" && len(args) >= 3:
			if v, ok := f.lit(args[2]); ok {
				return hostVal{state: valLiteral, value: v, env: "flag"}
			}
		}
		switch callee {
		case "os.Getenv":
			name := ""
			if len(args) > 0 {
				name, _ = f.lit(args[0])
			}
			return hostVal{state: valAbsent, env: name}
		case "fmt.Sprintf":
			if len(args) > 0 {
				if v, ok := f.lit(args[0]); ok {
					return hostVal{state: valLiteral, value: v, partial: strings.Contains(v, "%")}
				}
			}
		case "net.JoinHostPort":
			if len(args) == 2 {
				h := f.evalGo(args[0], depth+1)
				if h.state == valAbsent {
					return hostVal{state: valLiteral, value: ":", env: h.env, partial: true}
				}
				if h.state == valLiteral {
					return hostVal{state: valLiteral, value: h.value + ":", env: h.env, partial: true}
				}
			}
		}
		return unknownVal()
	case "binary_expression":
		if f.text(n.ChildByFieldName("operator")) != "+" {
			return unknownVal()
		}
		l := f.evalGo(n.ChildByFieldName("left"), depth+1)
		r := f.evalGo(n.ChildByFieldName("right"), depth+1)
		switch {
		case l.state == valLiteral && r.state == valLiteral:
			return hostVal{state: valLiteral, value: l.value + r.value, env: l.env + r.env, partial: r.partial}
		case l.state == valLiteral:
			return hostVal{state: valLiteral, value: l.value, env: l.env, partial: true}
		case l.state == valAbsent && r.state == valLiteral:
			// os.Getenv("HOST") + ":8080": an unset variable leaves ":8080"
			return hostVal{state: valLiteral, value: r.value, env: l.env, partial: r.partial}
		}
		return unknownVal()
	case "parenthesized_expression":
		if inner := firstNamed(n); inner != nil {
			return f.evalGo(inner, depth+1)
		}
	}
	return unknownVal()
}

// classifyHostName says where a listen host name puts the endpoint
func classifyHostName(h string) bind {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	switch {
	case h == "" || h == "0.0.0.0" || h == "::" || h == "0:0:0:0:0:0:0:0" || h == "*":
		return bindAll
	case h == "localhost" || h == "::1" || h == "ip6-localhost" || strings.HasPrefix(h, "127."):
		return bindLocal
	case strings.ContainsAny(h, "%{}$<>"):
		return bindUnknown
	}
	// a named or addressed interface is reachable from the network it is on
	return bindAll
}

// classifyHost classifies a host-only value (JavaScript listen's host, Python's host=). absent is
// what the API does with no host at all: Node binds every interface, uvicorn and FastMCP localhost.
func classifyHost(v hostVal, absent bind) bind {
	switch v.state {
	case valAbsent:
		return absent
	case valUnknown:
		return bindUnknown
	}
	if v.value == "" {
		return absent
	}
	return classifyHostName(v.value)
}

// classifyGoAddr classifies a Go "host:port" address: an empty host listens on every interface
func classifyGoAddr(v hostVal) bind {
	switch v.state {
	case valAbsent:
		return bindAll
	case valUnknown:
		return bindUnknown
	}
	s := v.value
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return bindUnknown
	}
	host := s[:i]
	if strings.Contains(host, "%") {
		return bindUnknown
	}
	return classifyHostName(host)
}
