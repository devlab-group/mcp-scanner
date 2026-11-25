package iac

import (
	"fmt"
	"regexp"
	"strings"
)

// bicepFile is what the line reader takes from one Bicep file
type bicepFile struct {
	path   string
	params map[string]bicepParam
	vars   map[string]bicepDecl
	props  []prop // secret-named properties: resource properties and module parameters
	names  []string
	// moduleParams are the parameter names this file passes to modules
	moduleParams map[string]bool
}

type bicepParam struct {
	secure bool
	def    string
	line   int
}

type bicepDecl struct {
	expr string
	line int
}

// prop is one `key: value` (Bicep) or `key = value` (Terraform) or "key": "value" (ARM) line
// whose key names a secret
type prop struct {
	file, key, expr string
	line            int
}

var (
	bicepParamLine = regexp.MustCompile(`^param\s+([A-Za-z_]\w*)\s+[\w.]+(?:\[\])?\??(?:\s*=\s*(.+))?$`)
	bicepVarLine   = regexp.MustCompile(`^var\s+([A-Za-z_]\w*)\s*=\s*(.+)$`)
	bicepPropLine  = regexp.MustCompile(`^([A-Za-z_]\w*)\s*:\s*(.+?),?$`)
	bicepNameLine  = regexp.MustCompile(`^name\s*:\s*(.+?),?$`)
)

// stripComment removes a // comment that is outside a quoted string
func stripComment(line string, hashToo bool) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '/' && i+1 < len(line) && line[i+1] == '/':
			return line[:i]
		case hashToo && c == '#':
			return line[:i]
		}
	}
	return line
}

func parseBicep(path, src string) *bicepFile {
	f := &bicepFile{path: path, params: map[string]bicepParam{}, vars: map[string]bicepDecl{}, moduleParams: map[string]bool{}}
	pendingSecure := false
	paramsDepth := -1 // brace depth of an open `params: {` block, -1 outside one
	depth := 0
	for i, raw := range strings.Split(src, "\n") {
		n := i + 1
		line := strings.TrimSpace(stripComment(raw, false))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "@") {
			if strings.HasPrefix(line, "@secure()") {
				pendingSecure = true
			}
			continue
		}
		if m := bicepParamLine.FindStringSubmatch(line); m != nil {
			f.params[m[1]] = bicepParam{secure: pendingSecure, def: strings.TrimSpace(m[2]), line: n}
		} else if m := bicepVarLine.FindStringSubmatch(line); m != nil {
			f.vars[m[1]] = bicepDecl{expr: strings.TrimSpace(m[2]), line: n}
		}
		pendingSecure = false
		if paramsDepth >= 0 && depth == paramsDepth+1 {
			if m := bicepPropLine.FindStringSubmatch(line); m != nil {
				f.moduleParams[m[1]] = true
			}
		}
		if m := bicepNameLine.FindStringSubmatch(line); m != nil {
			f.names = append(f.names, m[1])
		}
		// one-line objects ({ startIpAddress: '0.0.0.0', endIpAddress: '0.0.0.0' }) carry
		// properties too; read every key: value pair on the line
		for _, kv := range keyValues(line) {
			if secretKey(kv[0]) {
				f.props = append(f.props, prop{file: path, key: kv[0], expr: kv[1], line: n})
			}
		}
		if strings.HasPrefix(line, "params:") && strings.HasSuffix(line, "{") {
			paramsDepth = depth
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if paramsDepth >= 0 && depth <= paramsDepth {
			paramsDepth = -1
		}
	}
	return f
}

// keyValues splits `key: value` pairs from a line, including those inside a one-line object
func keyValues(line string) [][2]string {
	s := strings.TrimSpace(line)
	s = strings.TrimPrefix(strings.TrimSuffix(s, "}"), "{")
	s = strings.TrimSuffix(strings.TrimSpace(s), ",")
	var out [][2]string
	for _, part := range splitTopLevel(s) {
		m := bicepPropLine.FindStringSubmatch(strings.TrimSpace(part))
		if m == nil {
			continue
		}
		v := strings.TrimSpace(m[2])
		if v == "{" || v == "[" {
			continue
		}
		out = append(out, [2]string{m[1], v})
	}
	return out
}

// bicepValue classifies a Bicep expression in the context of its file
func (s *set) bicepValue(f *bicepFile, expr string, depth int) val {
	expr = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(expr), ","))
	if depth > 6 || expr == "" {
		return val{kind: kindUnknown}
	}
	switch {
	case strings.HasPrefix(expr, "'") && strings.HasSuffix(expr, "'") && len(expr) >= 2:
		return s.bicepString(f, expr[1:len(expr)-1], depth)
	case identOnly.MatchString(expr):
		if p, ok := f.params[expr]; ok {
			if p.def == "" || s.provided[expr] {
				return val{kind: kindExternal, detail: "parameter " + expr + " supplied at deployment"}
			}
			v := s.bicepValue(f, p.def, depth+1)
			if v.kind == kindLiteral {
				v.via, v.viaFile, v.viaLine = "the default of parameter "+expr, f.path, p.line
			}
			return v
		}
		if d, ok := f.vars[expr]; ok {
			v := s.bicepValue(f, d.expr, depth+1)
			if v.detail == "" {
				v.detail = "variable " + expr
			}
			return v
		}
		return val{kind: kindUnknown}
	case strings.Contains(expr, ".getSecret(") || strings.Contains(expr, "listKeys(") || strings.Contains(expr, "listCredentials(") ||
		strings.Contains(expr, ".properties.") || strings.HasPrefix(expr, "reference("):
		return val{kind: kindExternal, detail: "read from a resource or vault"}
	}
	name, args, ok := outerCall(expr)
	if !ok {
		return val{kind: kindUnknown}
	}
	switch name {
	case "uniqueString", "guid":
		return val{kind: kindPredictable, detail: fmt.Sprintf("%s(%s)", name, args), inputs: s.bicepInputs(f, args, depth)}
	case "newGuid":
		return val{kind: kindRandom, detail: "newGuid()"}
	case "toLower", "toUpper", "take", "substring", "trim", "string", "concat", "format", "replace", "skip", "padLeft", "base64":
		var parts []val
		for i, a := range splitTopLevel(args) {
			if (name == "take" || name == "substring" || name == "skip" || name == "padLeft") && i > 0 {
				continue
			}
			parts = append(parts, s.bicepValue(f, a, depth+1))
		}
		return combine(parts)
	}
	return val{kind: kindUnknown}
}

var identOnly = regexp.MustCompile(`^[A-Za-z_]\w*$`)

// bicepString classifies a quoted Bicep string, reading each ${...} it interpolates
func (s *set) bicepString(f *bicepFile, body string, depth int) val {
	if !strings.Contains(body, "${") {
		if body == "" {
			return val{kind: kindUnknown}
		}
		return val{kind: kindLiteral, detail: "the literal '" + mask(body) + "'"}
	}
	var parts []val
	rest := body
	for {
		i := strings.Index(rest, "${")
		if i < 0 {
			if rest != "" {
				parts = append(parts, val{kind: kindLiteral})
			}
			break
		}
		if i > 0 {
			parts = append(parts, val{kind: kindLiteral})
		}
		j := matchBrace(rest, i+1)
		if j < 0 {
			return val{kind: kindUnknown}
		}
		parts = append(parts, s.bicepValue(f, rest[i+2:j], depth+1))
		rest = rest[j+1:]
	}
	return combine(parts)
}

// matchBrace finds the } that closes the { at open
func matchBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// bicepInputs are the names a hash is computed from, following variables to the names they are
// built from so a password hashed from a variable that names public resources is traced to it
func (s *set) bicepInputs(f *bicepFile, args string, depth int) []string {
	var out []string
	for _, id := range identifiers(args) {
		out = append(out, id)
	}
	return uniq(out)
}

// mask shows only the shape of a literal secret, never the secret itself
func mask(s string) string {
	if len(s) <= 2 {
		return strings.Repeat("*", len(s))
	}
	return s[:1] + strings.Repeat("*", len(s)-2) + s[len(s)-1:]
}
