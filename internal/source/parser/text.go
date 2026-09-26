package parser

import "strings"

// UnquoteString strips the quote syntax off a string-literal node's raw
// source text and reports whether the result is a fixed value. A template
// or f-string with an interpolation in it is not a fixed value: ok is false
// so callers do not mistake the template for the literal name it produces.
func UnquoteString(text string) (value string, ok bool) {
	i := 0
	for i < len(text) && text[i] != '"' && text[i] != '\'' && text[i] != '`' {
		i++
	}
	if i >= len(text) {
		return "", false
	}
	quote := text[i]
	prefix := text[:i]

	// Triple-quoted Python strings
	if quote != '`' {
		tq := strings.Repeat(string(quote), 3)
		if strings.HasPrefix(text[i:], tq) && strings.HasSuffix(text, tq) && len(text)-i >= 6 {
			val := text[i+3 : len(text)-3]
			return val, !isDynamic(prefix, quote, val)
		}
	}

	if len(text) < i+2 || text[len(text)-1] != quote {
		return "", false
	}
	val := text[i+1 : len(text)-1]
	return val, !isDynamic(prefix, quote, val)
}

// isDynamic flags a string whose value is not actually fixed: a Python
// f-string or JS/TS template literal with an interpolation
func isDynamic(prefix string, quote byte, val string) bool {
	if quote == '`' && strings.Contains(val, "${") {
		return true
	}
	if strings.ContainsAny(prefix, "fF") && strings.Contains(val, "{") {
		return true
	}
	return false
}

// SplitTopLevel splits inner on commas that are not nested inside a bracket, brace, paren
// or quoted string, so a comma belonging to a nested literal never breaks up its enclosing
// element
func SplitTopLevel(inner string) []string {
	var parts []string
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case quote != 0:
			if c == quote && (i == 0 || inner[i-1] != '\\') {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '[' || c == '(' || c == '{':
			depth++
		case c == ']' || c == ')' || c == '}':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, inner[start:i])
			start = i + 1
		}
	}
	parts = append(parts, inner[start:])
	return parts
}

// stripComment removes the line/block comment syntax, for use as a leading
// doc comment
func stripComment(text string) string {
	t := strings.TrimSpace(text)
	t = strings.TrimPrefix(t, "///")
	t = strings.TrimPrefix(t, "//")
	t = strings.TrimPrefix(t, "#")
	t = strings.TrimPrefix(t, "/**")
	t = strings.TrimPrefix(t, "/*")
	t = strings.TrimSuffix(t, "*/")
	return strings.TrimSpace(t)
}

// LastSegment reduces a dotted or path-scoped callee expression to its final identifier:
// "srv.AddTool" and "mcp::server::add_tool" both become their method name. Name-based resolution,
// registration discovery and the taint catalogue all match on that name, since receiver types are
// not tracked.
func LastSegment(text string) string {
	t := strings.ReplaceAll(text, "::", ".")
	if i := strings.LastIndexByte(t, '.'); i >= 0 {
		t = t[i+1:]
	}
	return strings.TrimSpace(t)
}
