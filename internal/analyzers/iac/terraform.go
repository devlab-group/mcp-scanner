package iac

import (
	"regexp"
	"strings"
)

// tfVariable is one `variable "name" { ... }` block
type tfVariable struct {
	def       string
	sensitive bool
	file      string
	line      int
}

// tfFile is what the line reader takes from one .tf or .tfvars file
type tfFile struct {
	path   string
	vars   map[string]tfVariable
	locals map[string]bicepDecl
	props  []prop
	names  []string
	// assigned are the variables a .tfvars file sets, with literal values
	assigned map[string]bicepDecl
}

var (
	tfVariableOpen = regexp.MustCompile(`^variable\s+"([A-Za-z_][\w-]*)"\s*\{`)
	tfAttr         = regexp.MustCompile(`^([A-Za-z_][\w-]*)\s*=\s*(.+)$`)
	tfLocalsOpen   = regexp.MustCompile(`^locals\s*\{`)
)

func parseTerraform(path, src string, tfvars bool) *tfFile {
	f := &tfFile{path: path, vars: map[string]tfVariable{}, locals: map[string]bicepDecl{}, assigned: map[string]bicepDecl{}}
	depth := 0
	inVar, inLocals := "", false
	for i, raw := range strings.Split(src, "\n") {
		n := i + 1
		line := strings.TrimSpace(stripComment(raw, true))
		if line == "" {
			continue
		}
		if depth == 0 {
			if m := tfVariableOpen.FindStringSubmatch(line); m != nil {
				inVar = m[1]
				f.vars[inVar] = tfVariable{file: path, line: n}
			} else if tfLocalsOpen.MatchString(line) {
				inLocals = true
			}
		}
		if m := tfAttr.FindStringSubmatch(line); m != nil {
			key, expr := m[1], strings.TrimSpace(m[2])
			switch {
			case tfvars:
				f.assigned[key] = bicepDecl{expr: expr, line: n}
			case inVar != "" && depth == 1 && key == "default":
				v := f.vars[inVar]
				v.def, v.line = expr, n
				f.vars[inVar] = v
			case inVar != "" && depth == 1 && key == "sensitive":
				v := f.vars[inVar]
				v.sensitive = expr == "true"
				f.vars[inVar] = v
			case inLocals && depth == 1:
				f.locals[key] = bicepDecl{expr: expr, line: n}
			case inVar == "" && secretKey(key):
				f.props = append(f.props, prop{file: path, key: key, expr: expr, line: n})
			case key == "name":
				f.names = append(f.names, expr)
			}
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			depth, inVar, inLocals = 0, "", false
		}
	}
	return f
}

// tfValue classifies a Terraform expression
func (s *set) tfValue(f *tfFile, expr string, depth int) val {
	expr = strings.TrimSpace(expr)
	if depth > 6 || expr == "" {
		return val{kind: kindUnknown}
	}
	switch {
	case strings.HasPrefix(expr, `"`) && strings.HasSuffix(expr, `"`) && len(expr) >= 2:
		body := expr[1 : len(expr)-1]
		if !strings.Contains(body, "${") {
			if body == "" {
				return val{kind: kindUnknown}
			}
			return val{kind: kindLiteral, detail: "the literal \"" + mask(body) + "\""}
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
			parts = append(parts, s.tfValue(f, rest[i+2:j], depth+1))
			rest = rest[j+1:]
		}
		return combine(parts)
	case strings.HasPrefix(expr, "var."):
		name := strings.TrimPrefix(expr, "var.")
		if !identOnly.MatchString(strings.ReplaceAll(name, "-", "_")) {
			return val{kind: kindUnknown}
		}
		if a, ok := s.tfAssigned[name]; ok {
			v := s.tfValue(f, a.expr, depth+1)
			if v.kind == kindLiteral {
				v.via, v.viaFile, v.viaLine = "variable "+name+" set in "+a.file, a.file, a.line
			}
			return v
		}
		decl, ok := s.tfVars[name]
		if !ok || decl.def == "" || decl.def == "null" {
			return val{kind: kindExternal, detail: "variable " + name + " supplied at apply time"}
		}
		v := s.tfValue(f, decl.def, depth+1)
		if v.kind == kindLiteral {
			v.via, v.viaFile, v.viaLine = "the default of variable "+name, decl.file, decl.line
		}
		return v
	case strings.HasPrefix(expr, "local."):
		if d, ok := s.tfLocals[strings.TrimPrefix(expr, "local.")]; ok {
			return s.tfValue(f, d.expr, depth+1)
		}
		return val{kind: kindUnknown}
	case strings.HasPrefix(expr, "random_password.") || strings.HasPrefix(expr, "random_string.") || strings.HasPrefix(expr, "random_id.") || strings.HasPrefix(expr, "random_uuid."):
		return val{kind: kindRandom, detail: expr}
	case strings.HasPrefix(expr, "data.") || strings.Contains(expr, "key_vault_secret") || strings.Contains(expr, "secretsmanager") || strings.Contains(expr, "ssm_parameter"):
		return val{kind: kindExternal, detail: "read from " + expr}
	}
	return val{kind: kindUnknown}
}

// tfvarsSecrets reports literal values a committed .tfvars file assigns to secret-named variables
func tfvarsSecretName(name string) bool {
	l := strings.ToLower(name)
	return strings.Contains(l, "password") || strings.HasSuffix(l, "_secret")
}
