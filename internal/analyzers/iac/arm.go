package iac

import (
	"encoding/json"
	"regexp"
	"strings"
)

// armFile is one ARM deployment template
type armFile struct {
	path   string
	src    string
	params map[string]armParam
	vars   map[string]string
	props  []prop
	names  []string
}

type armParam struct {
	secure bool
	def    string
	hasDef bool
}

// isARM reports whether a JSON file is an ARM deployment template
func isARM(src string) bool {
	return strings.Contains(src, "schema.management.azure.com/schemas/") && strings.Contains(src, "deploymentTemplate.json")
}

func parseARM(path, src string) *armFile {
	var doc map[string]any
	if json.Unmarshal([]byte(src), &doc) != nil {
		return nil
	}
	f := &armFile{path: path, src: src, params: map[string]armParam{}, vars: map[string]string{}}
	if ps, ok := doc["parameters"].(map[string]any); ok {
		for name, raw := range ps {
			p, _ := raw.(map[string]any)
			typ, _ := p["type"].(string)
			ap := armParam{secure: strings.HasPrefix(strings.ToLower(typ), "secure")}
			if d, ok := p["defaultValue"].(string); ok {
				ap.def, ap.hasDef = d, true
			}
			f.params[name] = ap
		}
	}
	if vs, ok := doc["variables"].(map[string]any); ok {
		for name, raw := range vs {
			if s, ok := raw.(string); ok {
				f.vars[name] = s
			}
		}
	}
	var walk func(any)
	walk = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			for k, v := range x {
				if s, ok := v.(string); ok {
					if secretKey(k) {
						f.props = append(f.props, prop{file: path, key: k, expr: s, line: f.lineOf(k, s)})
					}
					if k == "name" {
						f.names = append(f.names, s)
					}
					continue
				}
				if k == "parameters" || k == "variables" || k == "outputs" {
					// declarations, not resource properties
					if _, top := x["$schema"]; top {
						continue
					}
				}
				walk(v)
			}
		case []any:
			for _, v := range x {
				walk(v)
			}
		}
	}
	walk(doc)
	return f
}

// lineOf finds the line of "key": "value" in the template text
func (f *armFile) lineOf(key, value string) int {
	enc, _ := json.Marshal(value)
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(key) + `"\s*:\s*` + regexp.QuoteMeta(string(enc)))
	if loc := re.FindStringIndex(f.src); loc != nil {
		return strings.Count(f.src[:loc[0]], "\n") + 1
	}
	return 1
}

var (
	armParamRef = regexp.MustCompile(`parameters\(\s*'([^']+)'\s*\)`)
	armVarRef   = regexp.MustCompile(`variables\(\s*'([^']+)'\s*\)`)
	armHashCall = regexp.MustCompile(`(uniqueString|guid)\(`)
)

// armValue classifies an ARM property string: a literal, or a "[...]" template expression
func (s *set) armValue(f *armFile, v string, depth int) val {
	if depth > 6 {
		return val{kind: kindUnknown}
	}
	if !strings.HasPrefix(v, "[") || strings.HasPrefix(v, "[[") {
		if v == "" {
			return val{kind: kindUnknown}
		}
		return val{kind: kindLiteral, detail: "the literal \"" + mask(v) + "\""}
	}
	expr := strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
	switch {
	case strings.Contains(expr, "newGuid("):
		return val{kind: kindRandom, detail: "newGuid()"}
	case strings.Contains(expr, "reference(") || strings.Contains(expr, "listKeys(") || strings.Contains(expr, "listSecrets("):
		return val{kind: kindExternal, detail: "read from a resource"}
	}
	var parts []val
	for _, m := range armParamRef.FindAllStringSubmatch(expr, -1) {
		p, ok := f.params[m[1]]
		switch {
		case !ok:
			parts = append(parts, val{kind: kindUnknown})
		case !p.hasDef || s.provided[m[1]]:
			parts = append(parts, val{kind: kindExternal, detail: "parameter " + m[1] + " supplied at deployment"})
		default:
			pv := s.armValue(f, p.def, depth+1)
			if pv.kind == kindLiteral {
				pv.via, pv.viaFile, pv.viaLine = "the default of parameter "+m[1], f.path, f.lineOf("defaultValue", p.def)
			}
			parts = append(parts, pv)
		}
	}
	for _, m := range armVarRef.FindAllStringSubmatch(expr, -1) {
		if vv, ok := f.vars[m[1]]; ok {
			parts = append(parts, s.armValue(f, vv, depth+1))
		} else {
			parts = append(parts, val{kind: kindUnknown})
		}
	}
	if loc := armHashCall.FindStringSubmatchIndex(expr); loc != nil {
		name := expr[loc[2]:loc[3]]
		open := loc[1] - 1
		closeAt := matchParen(expr, open)
		args := ""
		if closeAt > open {
			args = expr[open+1 : closeAt]
		}
		var inputs []string
		for _, m := range armVarRef.FindAllStringSubmatch(args, -1) {
			inputs = append(inputs, m[1])
		}
		for _, m := range armParamRef.FindAllStringSubmatch(args, -1) {
			inputs = append(inputs, m[1])
		}
		parts = append(parts, val{kind: kindPredictable, detail: name + "(" + args + ")", inputs: inputs})
	}
	if len(parts) == 0 {
		if !strings.ContainsAny(stripQuoted(expr), "()") {
			return val{kind: kindUnknown}
		}
		if onlyLiterals(expr) {
			return val{kind: kindLiteral, detail: "a fixed expression"}
		}
		return val{kind: kindUnknown}
	}
	return combine(parts)
}

func matchParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func stripQuoted(s string) string { return quoted.ReplaceAllString(s, "''") }

// onlyLiterals reports whether an expression is concat/format over string literals alone
func onlyLiterals(expr string) bool {
	rest := stripQuoted(expr)
	rest = strings.NewReplacer("concat(", "", "format(", "", "''", "", ",", "", ")", "", " ", "").Replace(rest)
	return rest == ""
}
