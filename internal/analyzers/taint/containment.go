package taint

import (
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/language"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// ifStatementKinds is the if-statement node kind this package recognizes
// per language - "if_expression" for Rust, which has no if_statement at
// all, "if_statement" everywhere else. Kept local to this package rather
// than added to language.Grammar: nothing else here needs to recognize an
// if, so growing the shared vocabulary for one caller is not worth it.
var ifStatementKinds = map[language.ID]string{
	language.Go:         "if_statement",
	language.Python:     "if_statement",
	language.JavaScript: "if_statement",
	language.TypeScript: "if_statement",
	language.Java:       "if_statement",
	language.Rust:       "if_expression",
}

// extraExitKinds is exitKindsFor's per-language addition to
// grammar.ReturnKinds - the statement kind each grammar uses to raise an
// exception. Go's error return already goes through ReturnKinds and Rust
// has no throw-shaped statement at all (its `?` operator is not a
// statement this walk would find here), so neither needs an entry.
var extraExitKinds = map[language.ID][]string{
	language.Python:     {"raise_statement"},
	language.JavaScript: {"throw_statement"},
	language.TypeScript: {"throw_statement"},
	language.Java:       {"throw_statement"},
}

func exitKindsFor(id language.ID, grammar language.Grammar) []string {
	kinds := make([]string, 0, len(grammar.ReturnKinds)+len(extraExitKinds[id]))
	kinds = append(kinds, grammar.ReturnKinds...)
	kinds = append(kinds, extraExitKinds[id]...)
	return kinds
}

// handleContainmentGuard clears path taint after a recognized exit-on-escape guard. Prefix
// predicates require prior normalization; Go's filepath.Rel shape proves containment without it.
// Alternatives stay tainted because their safe branch cannot be proved.
func (c *ctx) handleContainmentGuard(pf *parsedFile, tainted map[string]taintInfo, n *sitter.Node) {
	if n.ChildByFieldName("alternative") != nil {
		return
	}
	if !blockExits(pf.adapter.ID, pf.adapter.Grammar, n.ChildByFieldName("consequence")) {
		return
	}
	cond := n.ChildByFieldName("condition")
	if cond == nil {
		return
	}
	condText := cond.Utf8Text(pf.src)
	subject, requireNormalized := c.containmentSubject(pf, n, condText)
	if subject == "" {
		return
	}
	info, ok := tainted[subject]
	if !ok {
		return
	}
	if requireNormalized && !info.normalized {
		return
	}
	tainted[subject] = info.clearFor("path_traversal")
}

// blockExits reports whether consequence - an if-statement's own
// "consequence" field - unconditionally leaves the enclosing function: its
// terminal statement, once any wrapping block is peeled away, is a return,
// raise or throw. A consequence that only logs, or whose exit sits behind a
// further nested condition, does not qualify.
func blockExits(id language.ID, grammar language.Grammar, consequence *sitter.Node) bool {
	stmt := terminalStatement(consequence)
	if stmt == nil {
		return false
	}
	return slices.Contains(exitKindsFor(id, grammar), stmt.Kind())
}

// terminalStatement peels through the wrapper nodes tree-sitter interposes
// between a block and its own statements - "block"/"statement_block"
// (every grammar here), "statement_list" (Go nests one level deeper than
// the others between a block and its statements) and "expression_statement"
// (Rust wraps a semicolon-terminated return_expression in one, unlike every
// other grammar here where return/raise/throw are already statement-level)
// - and returns the last statement actually inside them
func terminalStatement(n *sitter.Node) *sitter.Node {
	if n == nil {
		return nil
	}
	switch n.Kind() {
	case "block", "statement_block", "statement_list", "expression_statement":
		return terminalStatement(lastNamedChild(n))
	default:
		return n
	}
}

func lastNamedChild(n *sitter.Node) *sitter.Node {
	if n == nil {
		return nil
	}
	cursor := n.Walk()
	defer cursor.Close()
	children := n.NamedChildren(cursor)
	if len(children) == 0 {
		return nil
	}
	last := children[len(children)-1]
	return &last
}

// containmentPredicate is one way source code proves a resolved path stays under a root: a
// call whose receiver (is_relative_to, startsWith, starts_with) or first argument
// (HasPrefix) is the path being checked
type containmentPredicate struct {
	text         string
	fromReceiver bool
}

var containmentPredicates = []containmentPredicate{
	{"is_relative_to", true},
	{"startsWith", true},
	{"starts_with", true},
	{"HasPrefix", false},
}

// containmentSubject finds a recognized path guard and reports whether its
// subject must already be normalized. filepath.Rel normalizes internally;
// direct prefix and component predicates require separate normalization.
func (c *ctx) containmentSubject(pf *parsedFile, n *sitter.Node, condText string) (subject string, requireNormalized bool) {
	if subject := c.relContainmentSubject(pf, n, condText); subject != "" {
		return subject, false
	}
	for _, p := range containmentPredicates {
		if subject, ok := p.subjectIn(pf.adapter.ID, condText); ok {
			return subject, true
		}
	}
	return "", false
}

// subjectIn finds p's own call in condText and returns the subject it checks, or "" (and
// false) if p never appears with a valid subject, a negation in front of it (for the
// receiver-blind entries here), and an anchored comparison - see anchoredBy
func (p containmentPredicate) subjectIn(id language.ID, condText string) (subject string, ok bool) {
	for i := 0; i < len(condText); {
		idx := indexIdentFrom(condText, p.text, i)
		if idx < 0 {
			return "", false
		}
		open := idx + len(p.text)
		if open >= len(condText) || condText[open] != '(' {
			i = idx + len(p.text)
			continue
		}
		end := matchingParen(condText, open)
		if end < 0 {
			return "", false
		}
		i = end
		args := splitTopLevel(condText[open+1 : end])

		var sub, compared string
		var negAt int
		if p.fromReceiver {
			if idx == 0 || condText[idx-1] != '.' {
				continue
			}
			chainStart := dottedChainStart(condText, idx)
			if chainStart >= idx-1 {
				// The receiver is not a dotted chain of names at all: a call, an index or a parenthesized
				// expression, as in Path(NOTES / name).resolve().is_relative_to(NOTES). dottedChainStart
				// stops on the ")" and hands back a start at or past the "." it was scanning from, which is
				// an inverted slice.
				continue
			}
			sub = condText[chainStart : idx-1]
			negAt = chainStart
			if len(args) > 0 {
				compared = strings.TrimSpace(args[0])
			}
		} else {
			if len(args) == 0 {
				continue
			}
			sub = strings.TrimSpace(args[0])
			negAt = dottedChainStart(condText, idx)
			if len(args) > 1 {
				compared = strings.TrimSpace(args[1])
			}
		}
		if !isPlainIdent(sub) {
			continue
		}
		if !negatedAt(condText, negAt, id) {
			continue
		}
		if isVacuousRoot(compared) {
			continue
		}
		if !p.anchoredBy(id, compared) {
			continue
		}
		if !soleDecidingConjunct(condText, idx, sub, id) {
			continue
		}
		return sub, true
	}
	return "", false
}

// anchoredBy reports whether this match - p, in a file of language id, compared against the
// value compared - proves containment down to a path boundary rather than just a run of
// matching characters
func (p containmentPredicate) anchoredBy(id language.ID, compared string) bool {
	switch {
	case p.text == "is_relative_to":
		return true
	case p.text == "starts_with" && id == language.Rust:
		return true
	case p.text == "startsWith" && id == language.Java:
		return true
	default:
		return isAnchoredValue(compared)
	}
}

// isVacuousRoot reports whether text - the value a containment predicate compares its
// subject against - is a string literal holding nothing but separators. Every absolute path
// is under "/", so a guard testing containment against it is a branch that cannot be taken,
// and an empty string is a prefix of everything.
func isVacuousRoot(text string) bool {
	text = strings.TrimSpace(text)
	if len(text) < 2 {
		return false
	}
	quote := text[0]
	if quote != '"' && quote != '\'' && quote != '`' {
		return false
	}
	if text[len(text)-1] != quote {
		return false
	}
	return strings.Trim(text[1:len(text)-1], `/\`) == ""
}

// pathSeparatorIdents are whole identifiers that anchor a concatenated root
// to a path boundary. Match each separately to avoid substring mistakes.
var pathSeparatorIdents = []string{
	"PathSeparator", // Go: os.PathSeparator
	"Separator",     // Go: filepath.Separator
	"sep",           // node: path.sep; Python: os.sep
	"separator",     // Java: File.separator
}

// isAnchoredValue reports whether text - the value a character-wise containment predicate
// compares its subject against - is anchored to a path boundary: a string literal that
// itself ends in a separator ("/srv/notes/"), or a concatenation that appends one (ROOT +
// path.sep, root+string(os.PathSeparator))
func isAnchoredValue(text string) bool {
	text = strings.TrimSpace(text)
	if len(text) >= 2 {
		last := text[len(text)-1]
		if (last == '"' || last == '\'' || last == '`') &&
			(text[len(text)-2] == '/' || text[len(text)-2] == '\\') {
			return true
		}
	}
	for _, ident := range pathSeparatorIdents {
		if mentionsIdent(text, ident) {
			return true
		}
	}
	return false
}

// relContainmentSubject recognizes the two-statement Go idiom this repository's own
// resolveWithinBase and ResolveRoot both use: a filepath.Rel(root, target) computed one
// statement earlier, then tested for a leading ".." in the guard's own condition
func (c *ctx) relContainmentSubject(pf *parsedFile, n *sitter.Node, condText string) string {
	relVar := dotDotPrefixCheckSubject(condText, pf.adapter.ID)
	if relVar == "" {
		return ""
	}
	prev := n.PrevNamedSibling()
	if prev == nil || !slices.Contains(pf.adapter.Grammar.AssignKinds, prev.Kind()) {
		return ""
	}
	isTarget := slices.Contains(parser.AssignTargets(prev, pf.src), relVar)
	if !isTarget {
		return ""
	}
	rhs := parser.AssignValue(prev, pf.src)
	if rhs == nil || !slices.Contains(pf.adapter.Grammar.CallKinds, rhs.Kind()) {
		return ""
	}
	calleeText, _, args := parser.CalleeAndArgs(pf.adapter.ID, rhs, pf.src)
	if !mentionsIdent(calleeText, "filepath.Rel") || len(args) < 2 {
		return ""
	}
	subject := strings.TrimSpace(args[1].Text)
	if !isPlainIdent(subject) {
		return ""
	}
	return subject
}

// dotDotPrefixCheckSubject finds a HasPrefix(x, "..") call in condText - any whole-word
// "HasPrefix", receiver- and package-blind the same way the rest of this file matches -
// whose second argument is a ".."-prefixed string literal, and returns x
func dotDotPrefixCheckSubject(condText string, id language.ID) string {
	const name = "HasPrefix"
	for i := 0; i < len(condText); {
		idx := indexIdentFrom(condText, name, i)
		if idx < 0 {
			return ""
		}
		open := idx + len(name)
		if open >= len(condText) || condText[open] != '(' {
			i = idx + len(name)
			continue
		}
		end := matchingParen(condText, open)
		if end < 0 {
			return ""
		}
		i = end
		args := splitTopLevel(condText[open+1 : end])
		if len(args) < 2 {
			continue
		}
		first := strings.TrimSpace(args[0])
		second := strings.TrimSpace(args[1])
		if !isPlainIdent(first) || !looksLikeDotDotLiteral(second) {
			continue
		}
		if !soleDecidingConjunct(condText, idx, first, id) {
			continue
		}
		return first
	}
	return ""
}

// soleDecidingConjunct rejects AND guards controlled by unrelated conditions.
// It allows the common `subject != root && !contained(subject)` form. The
// disequality's other operand is not checked for attacker control.
func soleDecidingConjunct(cond string, at int, subject string, id language.ID) bool {
	parts := topLevelConjuncts(cond, id)
	if len(parts) < 2 {
		return true
	}
	for _, r := range parts {
		if at >= r[0] && at < r[1] {
			continue
		}
		if !subjectDisequality(cond[r[0]:r[1]], subject) {
			return false
		}
	}
	return true
}

// topLevelConjuncts splits cond on the and-operator at paren, bracket and quote depth zero
// and returns each conjunct's byte range in cond
func topLevelConjuncts(cond string, id language.ID) [][2]int {
	andOp := "&&"
	if id == language.Python {
		andOp = "and"
	}
	lo, hi := 0, len(cond)
	for lo < hi && cond[lo] == '(' && matchingParen(cond[:hi], lo) == hi-1 {
		lo++
		hi--
	}
	var out [][2]int
	depth := 0
	var quote byte
	start := lo
	for i := lo; i < hi; i++ {
		ch := cond[i]
		switch {
		case quote != 0:
			if ch == quote && !escapedAt(cond, i, quote, id) {
				quote = 0
			}
		case ch == '"' || ch == '\'' || ch == '`':
			quote = ch
		case ch == '(' || ch == '[' || ch == '{':
			depth++
		case ch == ')' || ch == ']' || ch == '}':
			depth--
		case depth == 0 && strings.HasPrefix(cond[i:hi], andOp) && identBoundaries(cond[lo:hi], i-lo, andOp):
			out = append(out, [2]int{start, i})
			i += len(andOp) - 1
			start = i + 1
		}
	}
	return append(out, [2]int{start, hi})
}

// escapedAt reports whether the quote byte at idx is escaped rather than closing its
// literal. It counts the full backslash run, and treats Go backticks as raw strings with no escapes.
func escapedAt(text string, idx int, quote byte, id language.ID) bool {
	if quote == '`' && id == language.Go {
		return false
	}
	backslashes := 0
	for j := idx - 1; j >= 0 && text[j] == '\\'; j-- {
		backslashes++
	}
	return backslashes%2 == 1
}

// identBoundaries reports whether the operator at idx is a whole token -
// only Python's word-shaped "and" can be part of a longer identifier
// ("random", "andrew"), so "&&" always passes
func identBoundaries(text string, idx int, op string) bool {
	if op != "and" {
		return true
	}
	before := idx == 0 || !isIdentByte(text[idx-1])
	end := idx + len(op)
	return before && (end >= len(text) || !isIdentByte(text[end]))
}

// subjectDisequality reports whether text is a "subject != other" term -
// Go's and Python's !=, JavaScript's !== - with subject as one of the two
// operands. See soleDecidingConjunct for why that is the one conjunct a
// containment guard may carry alongside its own predicate.
func subjectDisequality(text, subject string) bool {
	text = strings.TrimSpace(text)
	for len(text) > 1 && text[0] == '(' && matchingParen(text, 0) == len(text)-1 {
		text = strings.TrimSpace(text[1 : len(text)-1])
	}
	idx := strings.Index(text, "!=")
	if idx < 0 {
		return false
	}
	lhs := strings.TrimSpace(text[:idx])
	rhs := strings.TrimSpace(strings.TrimLeft(text[idx+len("!="):], "="))
	return lhs == subject || rhs == subject
}

// looksLikeDotDotLiteral reports whether text is a string literal starting
// with ".." - ".." itself, or a concatenation like Go's
// ".."+string(filepath.Separator) - the shape a filepath.Rel result is
// compared against to detect that it climbed above the root
func looksLikeDotDotLiteral(text string) bool {
	for _, q := range []byte{'"', '\'', '`'} {
		if strings.HasPrefix(text, string(q)+"..") {
			return true
		}
	}
	return false
}

// dottedChainStart scans left from idx - the start of some identifier token - through as
// much of a dotted chain (identifier(.identifier)*) as precedes it, and returns where that
// chain begins
func dottedChainStart(text string, idx int) int {
	i := idx
	for i > 0 {
		if isIdentByte(text[i-1]) {
			i--
			continue
		}
		if text[i-1] == '.' && i >= 2 && isIdentByte(text[i-2]) {
			i--
			continue
		}
		break
	}
	return i
}

// negatedAt reports whether text's negation token for id - the keyword
// "not" in Python, "!" everywhere else here - appears immediately before
// pos, up to intervening whitespace and any wrapping parens: "not (x)" and
// "!(x)" both still negate x
func negatedAt(text string, pos int, id language.ID) bool {
	i := pos
	for {
		trimmed := i
		for trimmed > 0 && text[trimmed-1] == ' ' {
			trimmed--
		}
		if trimmed > 0 && text[trimmed-1] == '(' {
			i = trimmed - 1
			continue
		}
		i = trimmed
		break
	}
	if id == language.Python {
		const tok = "not"
		if !strings.HasSuffix(text[:i], tok) {
			return false
		}
		before := i - len(tok)
		return before == 0 || !isIdentByte(text[before-1])
	}
	return i > 0 && text[i-1] == '!'
}

// splitTopLevel splits argText on commas that are not nested inside
// parens, brackets or a quoted string - the same nesting matchingParen
// already tracks for finding a call's own closing paren
func splitTopLevel(argText string) []string {
	var out []string
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(argText); i++ {
		ch := argText[i]
		switch {
		case quote != 0:
			if ch == quote && argText[i-1] != '\\' {
				quote = 0
			}
		case ch == '"' || ch == '\'' || ch == '`':
			quote = ch
		case ch == '(' || ch == '[' || ch == '{':
			depth++
		case ch == ')' || ch == ']' || ch == '}':
			depth--
		case ch == ',' && depth == 0:
			out = append(out, argText[start:i])
			start = i + 1
		}
	}
	out = append(out, argText[start:])
	return out
}

// isPlainIdent reports whether s is a single bare identifier - not a
// compound expression like "self.p" or "NOTES / name" - so containment
// clearing only ever applies to an actual entry in the tainted map, never
// silently does nothing because the map has no such compound key
func isPlainIdent(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentByte(s[i]) {
			return false
		}
	}
	return true
}
