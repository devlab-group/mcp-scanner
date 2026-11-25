package taint

import (
	"slices"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// OperationCategory names the sink-catalogue category one call falls in, read from its callee
// and arguments alone, with no taint: command_injection when it starts a program, path_traversal
// when it opens, lists, writes or removes a path, ssrf when it requests a URL, sql_injection,
// eval, deserialization or raw_socket. Other analyzers use it to ask what a server's code can do
// at all - the transport analyzer weighs what a network caller would reach - not whether caller
// input reaches the call.
//
// resolvedInRepo is graph.Call.Resolved: a call bound to the project's own function is not
// matched by its method name alone, and a bare name the project defines is that function, not
// the global API. imports are the calling file's imports; the get/post receiver check needs an
// HTTP client among them. The rewrites the taint walk makes from the file's tree (aliases,
// RegExp receivers, Docker imports) are approximated from the callee text: a receiver-qualified
// exec in Go or JavaScript is not a process unless the receiver is the child_process module.
func OperationCategory(id language.ID, calleeText string, args []graph.Arg, resolvedInRepo bool, imports []string) (string, bool) {
	text := sinkCallee(calleeText)
	if strings.TrimSpace(text) == "" {
		return "", false
	}
	if _, _, ok := matchArgvSink(id, text, args); ok {
		return "command_injection", true
	}
	if s, ok := matchSink(text); ok {
		bare := !strings.ContainsAny(s.text, ".:") && !strings.ContainsAny(text, ".:")
		switch {
		case dockerSinks[s.text] && !importsAny(imports, "docker", "dockerode"):
			// tagmanager.accounts.containers.create(...) is a Google API, not docker-py
		case s.text == "exec" && id == language.Python && strings.TrimSpace(text) == "exec":
			// Python's builtin exec runs Python source
			return "eval", true
		case s.text == "exec" && id == language.Go:
			// exec.LookPath, exec.ExitError: Go starts a process only through exec.Command, which
			// the argv rules above handle
		case s.text == "exec" && (id == language.JavaScript || id == language.TypeScript) && !bare && !childProcessReceiver(text):
			// pattern.exec(text) is RegExp.prototype.exec; this.sql.exec(query) runs SQL
			if sqlExecReceiver(text) {
				return "sql_injection", true
			}
		case s.category == "command_injection" && parser.LastSegment(text) == "exec" && sqlExecReceiver(text):
			return "sql_injection", true
		case s.category == "ssrf" && asyncpgQuery[parser.LastSegment(text)] && receiverLooksLikeDB(text):
			return "sql_injection", true
		case resolvedInRepo && bare:
			// fetch(path) where the project defines its own fetch: that function is followed instead
		default:
			return s.category, true
		}
	}
	if resolvedInRepo {
		return "", false
	}
	if s, ok := matchMethodSink(text); ok {
		if s.category == "sql_injection" && (len(args) == 0 || !receiverMaybeDB(text)) {
			// url.Query(), tool.execute(args): a method name alone does not make a query
			return "", false
		}
		return s.category, true
	}
	if s, ok := matchGatedMethodSink(text); ok && importsAny(imports, httpClientImports...) {
		return s.category, true
	}
	return "", false
}

// childProcessReceiver reports whether a receiver-qualified exec is child_process.exec under a
// usual module alias
func childProcessReceiver(text string) bool {
	recv := strings.TrimSpace(text)
	if i := strings.LastIndexByte(recv, '.'); i >= 0 {
		recv = recv[:i]
	}
	return slices.Contains([]string{"child_process", "childProcess", "cp", "node:child_process"}, parser.LastSegment(recv))
}

// importsAny reports whether one of the imported module paths is, or starts with, one of the names
func importsAny(imports []string, names ...string) bool {
	for _, imp := range imports {
		imp = strings.TrimPrefix(imp, "node:")
		for _, n := range names {
			if imp == n || strings.HasPrefix(imp, n+".") || strings.HasPrefix(imp, n+"/") {
				return true
			}
		}
	}
	return false
}
