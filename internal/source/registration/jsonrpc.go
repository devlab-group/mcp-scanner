package registration

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
)

// jsonrpc.go recognizes a server written without an MCP SDK: the project reads JSON-RPC messages
// itself and branches on the method name - `case "tools/call":`, `elif method == "tools/call":`,
// `"tools/call".equals(method)` or a routing table `{"tools/call": self.call_tool}`. Every tool call
// arrives through that branch, so the function it hands the request to is the handler of every
// tool. The tools' names are not read: the server lists them however it likes.

var (
	// a branch or table entry for the tools/call method
	toolsCallBranch = regexp.MustCompile(`(?:==|===|\bcase\b|\bequals\s*\()\s*['"]tools/call['"]|['"]tools/call['"]\s*(?:==|===|->|=>|\.equals\b|\)\s*(?:\{|:|$))|['"]tools/call['"]\s*:\s*([A-Za-z_][\w.]*)?`)
	// the start of the next branch: another method literal compared or cased, or a default arm
	nextBranch = regexp.MustCompile(`(?:==|===|\bcase\b|\bequals\s*\(|\bin\s*\()\s*['"][a-z]+(?:/[A-Za-z_]+)+['"]|^\s*(?:default\b|else\b|\}\s*else\b)|^\s*elif\b`)
	// test files are not the server, and neither are web assets: a browser page that answers an
	// embedded app's tools/call message is a host, not an MCP server
	jsonrpcTestPath = regexp.MustCompile(`(?i)(^|/)(tests?|__tests__|spec|testdata|examples?|static|public|assets|www|dist|build|vendor|node_modules)/|_test\.go$|(^|/)test_[^/]*\.py$|_test\.py$|\.(test|spec)\.[jt]sx?$|Test\.java$`)
)

// branchSpan is how many lines after the tools/call branch its body may run when no next branch
// ends it sooner
const branchSpan = 20

// discoverJSONRPC adds one tool capability per tools/call branch, only for a tree where no other
// form found a tool: an SDK server that also mentions the method name (a proxy, a test client)
// has its tools already
func discoverJSONRPC(g *graph.Graph, idx index, callsByFile map[string][]int) {
	for _, c := range g.Capabilities {
		if c.Kind == graph.CapabilityTool {
			return
		}
	}
	for path := range g.Files {
		if jsonrpcTestPath.MatchString(filepath.ToSlash(path)) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(g.Root, path))
		if err != nil || !strings.Contains(string(data), "tools/call") {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			m := toolsCallBranch.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			ln := i + 1
			encl := enclosingSymbol(g, path, ln)
			handler := graph.SymbolID("")
			if m[1] != "" && !strings.Contains(line, "case") {
				// {"tools/call": self.call_tool}: the table names the handler
				if id, ok := idx.resolve(m[1]); ok {
					handler = id
				}
			}
			if handler == "" {
				handler = branchHandler(g, idx, callsByFile[path], path, ln, branchEnd(lines, i, encl))
			}
			if handler == "" && encl != nil {
				// the branch reads the request inline: the function holding it receives what the
				// client sent
				handler = encl.ID
			}
			if handler == "" {
				continue
			}
			g.Capabilities = append(g.Capabilities, graph.Capability{
				Kind: graph.CapabilityTool, Form: "jsonrpc", File: path, Line: ln, Handler: handler,
			})
		}
	}
}

// branchEnd is the last line of the tools/call branch that starts at index i: the line before the
// next branch, or the enclosing function's end, at most branchSpan lines on
func branchEnd(lines []string, i int, encl *graph.Symbol) int {
	end := i + 1 + branchSpan
	if encl != nil && encl.EndLine > 0 && encl.EndLine < end {
		end = encl.EndLine
	}
	for k := i + 1; k < len(lines) && k+1 <= end; k++ {
		if nextBranch.MatchString(lines[k]) {
			return k
		}
	}
	return end
}

// branchHandler is the first project function the branch calls with an argument that is not a
// literal: handle_tool_call(name, args), h.CallTool(req.Params), callTool(id, params)
func branchHandler(g *graph.Graph, idx index, calls []int, path string, from, to int) graph.SymbolID {
	best, bestLine := graph.SymbolID(""), 0
	for _, ci := range calls {
		c := g.Calls[ci]
		if c.Line < from || c.Line > to || c.IsDecorator {
			continue
		}
		id := c.Callee
		if !c.Resolved || id == "" {
			var ok bool
			if id, ok = idx.resolve(c.CalleeText); !ok {
				continue
			}
		}
		sym := g.Symbols[id]
		if sym == nil || len(sym.Params) == 0 || !hasNonLiteralArg(c.Args) {
			continue
		}
		if best == "" || c.Line < bestLine {
			best, bestLine = id, c.Line
		}
	}
	return best
}

func hasNonLiteralArg(args []graph.Arg) bool {
	for _, a := range args {
		if !a.Literal && strings.TrimSpace(a.Text) != "" {
			return true
		}
	}
	return false
}

// enclosingSymbol is the innermost function or method of file whose span holds line
func enclosingSymbol(g *graph.Graph, file string, line int) *graph.Symbol {
	var best *graph.Symbol
	for _, s := range g.Symbols {
		if s.File != file || s.Line > line || s.EndLine < line || s.Kind == graph.KindClass {
			continue
		}
		if best == nil || s.EndLine-s.Line < best.EndLine-best.Line {
			best = s
		}
	}
	return best
}
