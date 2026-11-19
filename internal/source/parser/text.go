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
		if last := text[len(text)-1]; strings.ContainsRune("\"'`", rune(last)) && strings.Contains(text, "+") {
			// "a" + 'b': a chain that ends in a different quote
			return joinConcatenation(text)
		}
		return "", false
	}
	val := text[i+1 : len(text)-1]
	if hasUnescaped(val, quote) {
		// 'a' + 'b': more than one literal. Their joined value is the string, when every part
		// is a literal; anything else in between is not a fixed string
		return joinConcatenation(text)
	}
	if !strings.ContainsAny(prefix, "rR") {
		val = unescapeSimple(val, quote)
	}
	return val, !isDynamic(prefix, quote, val)
}

// hasUnescaped reports whether s contains quote not preceded by an odd run of backslashes
func hasUnescaped(s string, quote byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == quote {
			return true
		}
	}
	return false
}

// joinConcatenation joins a + chain of string literals ('a' + "b" + 'c') into one value
func joinConcatenation(text string) (string, bool) {
	var parts []string
	depth, start := 0, 0
	var q byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		if q != 0 {
			if c == '\\' {
				i++
			} else if c == q {
				q = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			q = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '+':
			if depth == 0 {
				parts = append(parts, text[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, text[start:])
	if len(parts) < 2 {
		return "", false
	}
	var b strings.Builder
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return "", false
		}
		v, ok := UnquoteString(p)
		if !ok || !strings.ContainsAny(p[:1], "\"'`rRbBuUfF") {
			return "", false
		}
		b.WriteString(v)
	}
	return b.String(), true
}

// unescapeSimple decodes the escapes a description or name literal commonly carries: an escaped
// quote, backslash, newline or tab. Anything else is left as written.
func unescapeSimple(s string, quote byte) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch n := s[i+1]; n {
		case '\'', '"', '`', '\\':
			b.WriteByte(n)
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		default:
			b.WriteByte('\\')
			b.WriteByte(n)
		}
		i++
	}
	_ = quote
	return b.String()
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
func SplitTopLevel(inner string) []string { return SplitTopLevelSep(inner, ',') }

// SplitTopLevelSep is SplitTopLevel on another separator: int | None splits on '|'
func SplitTopLevelSep(inner string, sep byte) []string {
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
		case c == sep && depth == 0:
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

// TemplateWithSubstitutions returns a JavaScript template literal's body with every ${...}
// substitution replaced by repl, or false when a substitution is not closed. Escapes are decoded
// to the character they stand for.
func TemplateWithSubstitutions(body, repl string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) {
			b.WriteByte(body[i+1])
			i++
			continue
		}
		if body[i] == '$' && i+1 < len(body) && body[i+1] == '{' {
			depth, j := 0, i+1
			for ; j < len(body); j++ {
				if body[j] == '{' {
					depth++
				} else if body[j] == '}' {
					if depth--; depth == 0 {
						break
					}
				}
			}
			if j >= len(body) {
				return "", false
			}
			b.WriteString(repl)
			i = j
			continue
		}
		b.WriteByte(body[i])
	}
	return b.String(), true
}
