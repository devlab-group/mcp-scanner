package taint

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// zodParseDetail marks a zod schema's parse: it returns the values it was given
const zodParseDetail = "parsed by a zod schema, which returns the values it was given"

// zodParseMethods are the zod schema methods that return the parsed input: parse and parseAsync
// return it, safeParse and safeParseAsync return { success, data } with it in data
var zodParseMethods = map[string]bool{"parse": true, "safeParse": true, "parseAsync": true, "safeParseAsync": true}

var (
	// zodChecks are the schema methods that may limit which characters a value holds or rewrite
	// it. Length bounds (min, max, length) and trim/toLowerCase/toUpperCase are not among them:
	// '../x' and 'a; id' keep their meaning at any length, case or outer whitespace.
	zodChecks = regexp.MustCompile(`\.\s*(regex|refine|superRefine|transform|pipe|preprocess|url|email|uuid|cuid2?|ulid|ip|cidr|datetime|date|time|duration|base64|emoji|nanoid|startsWith|endsWith|includes)\s*\(`)
	// zodAnchoredRegex is an entry's .regex(/^[class]+$/flags) with one character class, nothing else
	zodAnchoredRegex = regexp.MustCompile(`\.\s*regex\s*\(\s*/\^\[([^\]\[^]*)\](?:[+*]|\{\d+(?:,\d*)?\})\$/([a-z]*)\s*[,)]`)
	// zodEntryValue is the start of an entry's value: key: z.string() -> "z"
	zodEntryValue = regexp.MustCompile(`^\s*["']?[A-Za-z_$][\w$]*["']?\s*:\s*([A-Za-z_$][\w$]*)`)
)

type zodParseResult struct {
	ok bool
	// shellSafe: every entry that can carry text is limited to characters a shell gives no
	// meaning to, by an anchored one-class regex
	shellSafe bool
	// checks names the methods that constrain or rewrite values, for a person to read
	checks []string
}

// zodParse recognizes NAME.parse(v), NAME.safeParse(v) and their async forms where NAME is a
// z.object schema the project defines. The call is then a known pass-through, not an unknown
// library call: zod returns the same values, after the checks the schema lists.
func (c *ctx) zodParse(file, calleeText string) (zodParseResult, bool) {
	if !zodParseMethods[parser.LastSegment(calleeText)] {
		return zodParseResult{}, false
	}
	dot := strings.LastIndex(calleeText, ".")
	if dot <= 0 {
		return zodParseResult{}, false // a bare parse(v), not a schema's method
	}
	name := strings.TrimSpace(calleeText[:dot])
	if !isGuardIdent(name) {
		return zodParseResult{}, false
	}
	gf := c.g.Files[file]
	if gf == nil || (gf.Language != "typescript" && gf.Language != "javascript") {
		return zodParseResult{}, false
	}
	if c.zodNames == nil {
		c.zodNames = zodSchemaNames(c.g)
		c.zodParsed = map[string]zodParseResult{}
	}
	if !c.zodNames[name] {
		return zodParseResult{}, false // JSON.parse, url.parse: no z.object of that name in the tree
	}
	key := file + "\x00" + name
	if r, ok := c.zodParsed[key]; ok {
		return r, r.ok
	}
	r := readZodSchema(schemaDefinition(c.g, file, name))
	c.zodParsed[key] = r
	return r, r.ok
}

// readZodSchema reads a z.object's entries text (what schemaDefinition returns)
func readZodSchema(text string) zodParseResult {
	if strings.TrimSpace(text) == "" || len(text) >= 600 {
		// not found, or cut at entryAt's limit: the scanner did not read the whole schema
		return zodParseResult{}
	}
	r := zodParseResult{ok: true, shellSafe: true}
	seen := map[string]bool{}
	textEntries := 0
	for _, entry := range parser.SplitTopLevelSep(text, ',') {
		if strings.TrimSpace(entry) == "" {
			continue
		}
		if zodScalar.MatchString(entry) && !strings.Contains(entry, ".or(") && !strings.Contains(entry, "union") {
			continue // an enum, a literal, a number or a boolean carries no text
		}
		textEntries++
		if m := zodEntryValue.FindStringSubmatch(entry); m == nil || m[1] != "z" {
			// project, or entityConfig: entityConfig.optional(): another schema the scanner does
			// not read here, whose checks are unknown
			name := strings.TrimSpace(strings.SplitN(entry, ":", 2)[0])
			if !seen["nested "+name] {
				seen["nested "+name] = true
				r.checks = append(r.checks, "nested schema at "+name+", not read")
			}
			r.shellSafe = false
			continue
		}
		multiline := false
		if a := zodAnchoredRegex.FindStringSubmatch(entry); a != nil && strings.Contains(a[2], "m") {
			// /^[a-z]+$/m.test("abc\n; id") is true: one matching line is enough, so the pattern
			// limits nothing and is no check
			multiline = true
		}
		for _, m := range zodChecks.FindAllStringSubmatch(entry, -1) {
			if m[1] == "regex" && multiline {
				continue
			}
			if !seen[m[1]] {
				seen[m[1]] = true
				r.checks = append(r.checks, "."+m[1])
			}
		}
		m := zodAnchoredRegex.FindStringSubmatch(entry)
		// only i and u keep ^ and $ anchored to the whole value: with m they match at each line,
		// so a newline - a shell command separator - passes the pattern
		if m == nil || strings.Trim(m[2], "iu") != "" || !shellSafeClass(m[1]) || strings.Contains(entry, ".or(") || strings.Contains(entry, "union") || strings.Contains(entry, ".transform(") {
			r.shellSafe = false
		}
	}
	if textEntries == 0 {
		r.shellSafe = false // nothing to clear: the scalar entries are not seeded in the first place
	}
	return r
}

// classSpecials reads a regex character class (the text between [ and ]) and returns the
// characters it admits besides letters and digits. ok is false for anything it cannot read for
// certain: a negated class, a class escape other than \w and \d (\s, \W, \p{...}), a range
// that is not within one of a-z, A-Z or 0-9.
func classSpecials(class string) (specials string, ok bool) {
	if strings.HasPrefix(class, "^") {
		return "", false
	}
	r := []rune(class)
	for i := 0; i < len(r); i++ {
		ch := r[i]
		if ch == '\\' {
			if i+1 >= len(r) {
				return "", false
			}
			i++
			switch e := r[i]; {
			case e == 'w':
				specials += "_"
			case e == 'd':
			case strings.ContainsRune(`-./_:,+=@]\\[`, e):
				specials += string(e)
			default:
				return "", false
			}
			continue
		}
		if i+2 < len(r) && r[i+1] == '-' {
			lo, hi := ch, r[i+2]
			if lo > hi || !(lo >= 'a' && hi <= 'z' || lo >= 'A' && hi <= 'Z' || lo >= '0' && hi <= '9') {
				return "", false
			}
			i += 2
			continue
		}
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			continue
		}
		specials += string(ch)
	}
	return specials, true
}

// shellSafeClass reports whether a character class admits only letters, digits and characters a
// shell gives no meaning to (". _ - / : , + = @"). A value starting with "-" is argument
// injection, not a second command, and is out of its scope.
func shellSafeClass(class string) bool {
	sp, ok := classSpecials(class)
	return ok && strings.Trim(sp, "._-/:,+=@") == ""
}

// pathSafeClass reports whether a character class admits only letters, digits, "_" and "-": no
// dot, no separator, so no '..', no absolute path and no other directory
func pathSafeClass(class string) bool {
	sp, ok := classSpecials(class)
	return ok && strings.Trim(sp, "_-") == ""
}

var zodObjectDecl = regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*z\s*\.\s*(?:strict)?[oO]bject\s*\(`)

// zodSchemaNames are the names the tree's JavaScript and TypeScript files declare as a z.object,
// read once per run (cached on ctx): a parse call on any other receiver is not looked up file by
// file
func zodSchemaNames(g *graph.Graph) map[string]bool {
	names := map[string]bool{}
	for f, gf := range g.Files {
		if gf.Language != "typescript" && gf.Language != "javascript" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(g.Root, f))
		if err != nil || !strings.Contains(string(data), "object") {
			continue
		}
		for _, m := range zodObjectDecl.FindAllStringSubmatch(string(data), -1) {
			names[m[1]] = true
		}
	}
	return names
}

// zodPatternEntry is a registration schema entry whose value is a string limited by one anchored
// character class: sha: z.string().regex(/^[a-f0-9]{64}$/). Flags other than i and u are refused
// (m makes ^ and $ line anchors, so a second line would pass); so is anything that widens or
// rewrites the value after the check.
var zodPatternEntry = regexp.MustCompile(`^\s*["']?([A-Za-z_$][\w$]*)["']?\s*:\s*z\s*\.\s*string\s*\(\s*\)(?:\s*\.\s*(?:min|max|length|describe|optional|nullable|default)\s*\([^()]*\))*\s*\.\s*regex\s*\(\s*/\^\[((?:[^\]\\]|\\.)*)\](?:[+*]|\{\d+(?:,\d*)?\})\$/([a-z]*)\s*[,)]`)

// zodPatternParams are the parameters of a tool registration whose inline zod schema limits them
// by such a pattern, with the finding categories the pattern rules out. The SDK validates the
// arguments against the schema before the handler runs (the same fact zodScalarParams relies
// on), so the handler only ever sees values made of the class's characters.
func (c *ctx) zodPatternParams(capRec graph.Capability) map[string][]string {
	f := c.g.Files[capRec.File]
	if f == nil || (f.Language != "typescript" && f.Language != "javascript") {
		return nil
	}
	var out map[string][]string
	for _, call := range c.g.Calls {
		if call.File != capRec.File || call.Line != capRec.Line {
			continue
		}
		for _, a := range call.Args {
			if !strings.Contains(a.Text, "z.") || !strings.HasPrefix(strings.TrimSpace(a.Text), "{") {
				continue
			}
			entries := parser.SplitTopLevelSep(strings.TrimSpace(a.Text)[1:], ',')
			for _, entry := range entries {
				if m := zodInputSchema.FindStringSubmatch(entry); m != nil {
					entries = append(entries, parser.SplitTopLevelSep(m[1], ',')...)
				}
			}
			for _, entry := range entries {
				m := zodPatternEntry.FindStringSubmatch(entry)
				if m == nil || strings.Trim(m[3], "iu") != "" {
					continue
				}
				if len(regexp.MustCompile(`(?:^|[{,\s])["']?`+regexp.QuoteMeta(m[1])+`["']?\s*:`).FindAllStringIndex(a.Text, -1)) > 1 {
					// the same key also names a nested field ({ id: ..., opts: z.object({ id }) }):
					// which binding the handler's name is cannot be told from the key, so no clearing
					continue
				}
				if strings.Contains(entry, ".or(") || strings.Contains(entry, "union") || strings.Contains(entry, ".transform(") || strings.Contains(entry, ".pipe(") {
					continue
				}
				var cats []string
				switch {
				case pathSafeClass(m[2]):
					cats = []string{"path_traversal", "command_injection"}
				case shellSafeClass(m[2]):
					cats = []string{"command_injection"}
				default:
					continue
				}
				if out == nil {
					out = map[string][]string{}
				}
				out[m[1]] = cats
			}
		}
	}
	return out
}
