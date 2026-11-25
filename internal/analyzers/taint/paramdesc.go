package taint

import (
	"regexp"
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/targetfs"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A tool's purpose is sometimes written only on its parameter: server.tool("summarize-pdf",
// { filePath: z.string().describe("Path to the PDF file") }, ...) has no description, and a FastMCP
// tool without a docstring may still say url: Annotated[str, Field(description="The URL of the
// website to preview")]. paramDescription reads that text from the registration and the handler's
// signature, so the capability check can use it as it uses the tool's own description.

// paramWindow is how many lines around the registration and the handler's first line are read
const paramWindow = 15

var (
	// a string literal in any of the three quotes; the text is in the first non-empty group
	quotedLit      = `(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|\x60([^\x60]*)\x60)`
	describeCall   = regexp.MustCompile(`\.describe\(\s*` + quotedLit)
	descriptionKey = regexp.MustCompile(`\bdescription\s*[:=]\s*` + quotedLit)
	goDescription  = regexp.MustCompile(`(?s)\bDescription\(\s*"(.*?)"`)
	javaParamAnn   = regexp.MustCompile(`@(?:McpToolParam|ToolParam|McpArg)\s*\(([^)]*)\)\s*(?:final\s+)?[\w<>\[\],.? ]+?\s+(\w+)\s*[,)]`)
	javaBareString = regexp.MustCompile(`^\s*"(.*)"\s*$`)
)

func paramDescription(g *graph.Graph, c *graph.Capability, param string) string {
	if c == nil || param == "" || !isGuardIdent(param) {
		return ""
	}
	sym := g.Symbols[c.Handler]
	if sym != nil && sym.Doc != "" {
		if d := docstringArg(sym.Doc, param); d != "" {
			return d
		}
	}
	data, err := targetfs.ReadGraphFile(g, c.File)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	from, to := c.Line-3, c.Line+2*paramWindow
	if sym != nil && sym.File == c.File {
		from = min(from, sym.Line-3)
		to = max(to, sym.Line+paramWindow)
	}
	from, to = max(from, 1), min(to, len(lines))
	if from > to {
		return ""
	}
	text := strings.Join(lines[from-1:to], "\n")
	q := regexp.QuoteMeta(param)

	// zod or JSON-schema entry: filePath: z.string().describe("..."), "url": { type: "string", description: "..." }
	// Python: url: Annotated[str, Field(description="...")], url: str = Field(description="...")
	// mcp-go: mcp.WithString("path", mcp.Description("..."))
	starts := []struct {
		re        *regexp.Regexp
		wholeCall bool
	}{
		{regexp.MustCompile(`(?:^|[\s{,(])["']?` + q + `["']?\??\s*:\s*`), false},
		// the rest of the With...( call holds the options
		{regexp.MustCompile(`\bWith\w*\(\s*"` + q + `"`), true},
	}
	for _, st := range starts {
		for _, loc := range st.re.FindAllStringIndex(text, -1) {
			entry := entryAt(text, loc[1], st.wholeCall)
			for _, d := range []*regexp.Regexp{describeCall, descriptionKey, goDescription} {
				if m := d.FindStringSubmatch(entry); m != nil {
					return firstGroup(m)
				}
			}
		}
	}
	// Azure Functions: @app.mcp_tool_property(arg_name="url", description="...")
	for _, line := range lines[from-1 : to] {
		if regexp.MustCompile(`\barg_name\s*=\s*["']` + q + `["']`).MatchString(line) {
			if m := descriptionKey.FindStringSubmatch(line); m != nil {
				return firstGroup(m)
			}
		}
	}
	// Java: @McpToolParam(description = "...") String jarFilePath, @ToolParam("...") String path
	for _, m := range javaParamAnn.FindAllStringSubmatch(text, -1) {
		if m[2] != param {
			continue
		}
		if d := descriptionKey.FindStringSubmatch(m[1]); d != nil {
			return firstGroup(d)
		}
		if d := javaBareString.FindStringSubmatch(m[1]); d != nil {
			return d[1]
		}
	}
	// ImageParams.shape, inputSchema: ImageParams: the schema is a named z.object defined elsewhere in
	// the file or in another one
	for _, name := range schemaRefs(text) {
		if def := schemaDefinition(g, c.File, name); def != "" {
			if d := entryDescription(def, param); d != "" {
				return d
			}
		}
	}
	return ""
}

// docstringArg reads param's line from a docstring's Args section: "file_path: Path to the file",
// "file_path (str): Path to the file", ":param file_path: Path to the file"
func docstringArg(doc, param string) string {
	q := regexp.QuoteMeta(param)
	re := regexp.MustCompile(`(?m)^\s*(?::param\s+(?:\w+\s+)?)?` + q + `\s*(?:\([^)]*\))?\s*:\s*(\S.*)$`)
	if m := re.FindStringSubmatch(doc); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// entryAt returns the text from i up to the end of the entry that starts there: the next comma, or
// the bracket that closes the enclosing one, outside strings and nested brackets. With wholeCall
// only the closing bracket ends it: the remaining arguments of a call.
func entryAt(text string, i int, wholeCall bool) string {
	depth := 0
	var quote byte
	for k := i; k < len(text) && k-i < 600; k++ {
		ch := text[k]
		switch {
		case quote != 0:
			if ch == '\\' {
				k++
			} else if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'' || ch == '`':
			quote = ch
		case ch == '(' || ch == '[' || ch == '{':
			depth++
		case ch == ')' || ch == ']' || ch == '}':
			if depth == 0 {
				return text[i:k]
			}
			depth--
		case ch == ',' && depth == 0 && !wholeCall:
			return text[i:k]
		}
	}
	return text[i:min(len(text), i+600)]
}

// firstGroup is a match's first non-empty capture group
func firstGroup(m []string) string {
	for _, g := range m[1:] {
		if g != "" {
			return g
		}
	}
	return ""
}

var firstStringLit = regexp.MustCompile(`["']([A-Za-z_][\w-]*)["']`)

// argumentKey is the argument name a path reads by key right after its source: the literal in
// req.RequireString("target") or arguments.get("target"), or the member of a whole-arguments
// object the next step reads, args.url or args["url"]
func argumentKey(g *graph.Graph, path []model.FlowStep) string {
	if len(path) > 1 && isGuardIdent(path[0].Symbol) {
		member := regexp.MustCompile(`\b` + regexp.QuoteMeta(path[0].Symbol) + `\s*(?:\?\.|\.)\s*([A-Za-z_]\w*)\b(?:\s*[^\w\s(]|\s*$)|\b` + regexp.QuoteMeta(path[0].Symbol) + `\[\s*["']([A-Za-z_][\w-]*)["']\s*\]`)
		st := path[1]
		if data, err := targetfs.ReadGraphFile(g, st.File); err == nil {
			if lines := strings.Split(string(data), "\n"); st.Line >= 1 && st.Line <= len(lines) {
				if m := member.FindStringSubmatch(lines[st.Line-1]); m != nil {
					return firstGroup(m)
				}
			}
		}
	}
	for _, st := range path[1:min(len(path), 3)] {
		if st.Detail != mcpGoGetterDetail && st.Detail != mappingGetDetail {
			continue
		}
		data, err := targetfs.ReadGraphFile(g, st.File)
		if err != nil {
			return ""
		}
		lines := strings.Split(string(data), "\n")
		if st.Line < 1 || st.Line > len(lines) {
			return ""
		}
		if m := firstStringLit.FindStringSubmatch(lines[st.Line-1]); m != nil {
			return m[1]
		}
	}
	return ""
}

var (
	schemaRef = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\.shape\b|\b(?:inputSchema|paramsSchema|parameters)\s*:\s*([A-Za-z_$][\w$]*)\s*[,}\n]`)
)

// schemaRefs are the names of schema constants a registration's text passes by name
func schemaRefs(text string) []string {
	var out []string
	for _, m := range schemaRef.FindAllStringSubmatch(text, -1) {
		if n := firstGroup(m); n != "" && !hasString(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// schemaDefinition is the object text of `const NAME = z.object({...})`, looked up first in the
// registration's own file, then in the project's other JavaScript and TypeScript files
func schemaDefinition(g *graph.Graph, file, name string) string {
	def := regexp.MustCompile(`(?:const|let|var)\s+` + regexp.QuoteMeta(name) + `\s*(?::[^=\n]+)?=\s*z\s*\.\s*(?:strict)?[oO]bject\s*\(\s*\{`)
	files := []string{file}
	for f, gf := range g.Files {
		if f != file && (gf.Language == "typescript" || gf.Language == "javascript") {
			files = append(files, f)
		}
	}
	sort.Strings(files[1:])
	for _, f := range files {
		data, err := targetfs.ReadGraphFile(g, f)
		if err != nil || !strings.Contains(string(data), name) {
			continue
		}
		text := string(data)
		if loc := def.FindStringIndex(text); loc != nil {
			return entryAt(text, loc[1], true)
		}
	}
	return ""
}

// entryDescription is the description of param's entry in a zod or JSON-schema object's text
func entryDescription(text, param string) string {
	start := regexp.MustCompile(`(?:^|[\s{,(])["']?` + regexp.QuoteMeta(param) + `["']?\??\s*:\s*`)
	for _, loc := range start.FindAllStringIndex(text, -1) {
		entry := entryAt(text, loc[1], false)
		for _, d := range []*regexp.Regexp{describeCall, descriptionKey} {
			if m := d.FindStringSubmatch(entry); m != nil {
				return firstGroup(m)
			}
		}
	}
	return ""
}
