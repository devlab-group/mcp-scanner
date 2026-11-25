package iac

import (
	"regexp"
	"sort"
	"strings"
)

// kind is where a secret's value comes from
type kind int

const (
	kindUnknown     kind = iota // a value the scanner cannot place
	kindLiteral                 // a fixed string written in the repository
	kindPredictable             // a deterministic hash (uniqueString, guid) of deployment values
	kindRandom                  // generated at deployment time (newGuid, random_password)
	kindExternal                // supplied from outside the repository: a secure parameter, a vault, a service key
)

// val is the classified value of a secret expression
type val struct {
	kind   kind
	detail string
	// inputs are the names a predictable value is computed from
	inputs []string
	// via names the parameter or variable whose default supplies a literal, with its location
	via, viaFile string
	viaLine      int
}

// combine joins the parts of an interpolation or concatenation: any part supplied from outside or
// generated makes the whole strong, an unknown part makes it unknown, and a hash among fixed text
// makes it predictable
func combine(parts []val) val {
	if len(parts) == 0 {
		return val{kind: kindUnknown}
	}
	out := val{kind: kindLiteral}
	var details []string
	for _, p := range parts {
		switch p.kind {
		case kindExternal, kindRandom:
			return p
		case kindUnknown:
			out.kind = kindUnknown
		case kindPredictable:
			if out.kind != kindUnknown {
				out.kind = kindPredictable
			}
			out.inputs = append(out.inputs, p.inputs...)
		}
		if p.via != "" && out.via == "" {
			out.via, out.viaFile, out.viaLine = p.via, p.viaFile, p.viaLine
		}
		if p.detail != "" {
			details = append(details, p.detail)
		}
	}
	out.inputs = uniq(out.inputs)
	out.detail = strings.Join(details, " + ")
	return out
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// splitTopLevel splits a function's argument text at commas outside brackets and quotes
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if rest := strings.TrimSpace(s[start:]); rest != "" {
		out = append(out, rest)
	}
	return out
}

// outerCall splits name(args) when the whole expression is one call
func outerCall(expr string) (string, string, bool) {
	m := callShape.FindStringSubmatch(expr)
	if m == nil {
		return "", "", false
	}
	// the closing paren must match the opening one
	depth := 0
	body := m[2]
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return "", "", false
			}
		}
	}
	return m[1], body, depth == 0
}

var callShape = regexp.MustCompile(`^([A-Za-z_][\w.]*)\((.*)\)$`)

// identifiers lists the names an expression refers to, without function names and literals
func identifiers(expr string) []string {
	noStrings := quoted.ReplaceAllString(expr, "")
	var out []string
	for _, m := range ident.FindAllStringSubmatchIndex(noStrings, -1) {
		name := noStrings[m[2]:m[3]]
		after := strings.TrimSpace(noStrings[m[1]:])
		if strings.HasPrefix(after, "(") || keywords[name] {
			continue
		}
		out = append(out, name)
	}
	return out
}

var (
	quoted   = regexp.MustCompile(`'[^']*'|"[^"]*"`)
	ident    = regexp.MustCompile(`(?:^|[^\w.])([A-Za-z_]\w*)`)
	keywords = map[string]bool{"true": true, "false": true, "null": true, "id": true}
)

// secretKeys are template property names that hold a password or a secret
var secretKeys = map[string]bool{
	"administratorloginpassword": true, "adminpassword": true, "administratorpassword": true,
	"sqladministratorloginpassword": true, "adminuserpassword": true, "adminpasswordorkey": true,
	"rootpassword": true, "masteruserpassword": true, "password": true, "dbpassword": true,
	"databasepassword": true, "postgrespassword": true, "mysqlpassword": true,
	// Terraform attribute names
	"administrator_login_password": true, "administrator_password": true, "admin_password": true,
	"master_password": true, "root_password": true, "sql_admin_password": true, "db_password": true,
}

func secretKey(name string) bool { return secretKeys[strings.ToLower(name)] }
