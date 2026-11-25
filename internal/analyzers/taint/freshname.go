package taint

import (
	"fmt"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
)

// A path whose last component the server names itself around a value drawn fresh for this call -
// path.join(dirname(out), `.${basename(out)}.${randomUUID()}.tmp`) - cannot name a file that
// existed before the call: whatever directory the caller picked, the file there is the one the
// server creates now. Removing it removes only the server's own file; the caller still picks the
// directory the file is created in.

// freshCall matches library calls that return a new random value on every call, with no path
// separator and no dot in it: an RFC 4122 version 4 UUID, hex or base64url text of random bytes,
// nanoid's URL-safe alphabet
var freshCall = regexp.MustCompile(`\b(randomUUID|uuidv4|uuid4|uuid\.v4|uuid\.New|uuid\.NewString|nanoid|token_hex|token_urlsafe)\s*\(|\b(randomBytes)\s*\([^()]*\)\s*\.\s*toString\s*\(\s*["'](?:hex|base64url)["']\s*\)|\b(urandom)\s*\([^()]*\)\s*\.\s*hex\s*\(`)

// pathJoinCalls join path components; the result's last component is the last argument's
var pathJoinCalls = map[string]bool{
	"path.join": true, "path.posix.join": true, "path.resolve": true, "path.posix.resolve": true,
	"os.path.join": true, "posixpath.join": true, "filepath.Join": true, "path.Join": true,
}

// freshNameDetail is the flow step that marks a fresh last component
const freshNameDetail = "the last path component is the server's own name around a fresh random value; the caller's text in it has no path separator"

// freshComponent reports whether text, a path's last component, is the server's own name: it
// holds a fresh random value, has no separator of its own, and every part of the caller's value in
// it is cleared of path syntax (basename(out), a hex digest). It returns the random call.
func (c *ctx) freshComponent(text string, tainted map[string]taintInfo) (string, bool) {
	if strings.ContainsAny(text, `/\`) {
		// "sub/" + randomUUID(), `${id}/${name}`: the component is not one, or the random part
		// names a directory the caller's text can climb out of
		return "", false
	}
	m := freshCall.FindStringSubmatch(text)
	if m == nil {
		return "", false
	}
	name := m[1] + m[2] + m[3]
	if c.projectDefinesMethod(parser.LastSegment(name)) {
		// The project's own randomUUID() may return anything
		return "", false
	}
	masked, _ := maskHexEncodings(text)
	if info, ok := mentionsAny(masked, tainted, "path_traversal"); ok && !info.clearedFor["path_traversal"] {
		// `.${randomUUID()}.${format}`: the caller's text after the random part can hold "/.."
		return "", false
	}
	return name + "()", true
}

// freshJoin reports whether a call joins a path whose last argument is a fresh component
func (c *ctx) freshJoin(file, calleeText string, args []graph.Arg, tainted map[string]taintInfo) (string, bool) {
	callee := strings.TrimSpace(calleeText)
	if !pathJoinCalls[callee] {
		if alias, ok := c.rewriteModuleAlias(file, callee); !ok || !pathJoinCalls[alias] {
			return "", false
		}
	}
	if len(args) < 2 || args[len(args)-1].Keyword != "" {
		return "", false
	}
	return c.freshComponent(args[len(args)-1].Text, tainted)
}

// freshArg reports whether a sink argument is a path with a fresh last component: a variable
// assigned one, or the join written inline
func (c *ctx) freshArg(pf *parsedFile, file string, node *sitter.Node, text string, tainted map[string]taintInfo) (string, bool) {
	if t := strings.TrimSpace(text); isPlainIdent(t) {
		if info, ok := tainted[t]; ok && info.freshName != "" {
			return info.freshName, true
		}
		return "", false
	}
	if node == nil {
		return "", false
	}
	node = unwrapAwait(node)
	if !isCallKind(pf, node) {
		return "", false
	}
	callee, _, args := parser.CalleeAndArgs(pf.adapter.ID, node, pf.src)
	return c.freshJoin(file, callee, args, tainted)
}

// freshSinkPath reports whether every argument of a file sink that carries the caller's value is
// a path with a fresh last component. rename(temp, output) also names the caller's own path, so
// it does not count.
func (c *ctx) freshSinkPath(pf *parsedFile, file string, n *sitter.Node, sink sinkPattern, receiver parser.Receiver, args []graph.Arg, tainted map[string]taintInfo) (string, bool) {
	const cat = "path_traversal"
	var checked []graph.Arg
	if sink.argIndex >= 0 {
		a, ok := sinkArg(args, sink.argIndex, sink.category)
		if !ok {
			return "", false
		}
		checked = []graph.Arg{a}
	} else {
		checked = withoutNonPathOptions(withoutWrittenData(sink, args))
		for _, r := range []string{receiver.Text, receiver.CallText} {
			if info, ok := mentionsAny(r, tainted, cat); ok && !info.clearedFor[cat] {
				// tmp.unlink(), Path(tmp).unlink(): receivers are not followed here
				return "", false
			}
		}
	}
	found := ""
	for _, a := range checked {
		info, ok := mentionsAny(a.Text, tainted, cat)
		if !ok || info.clearedFor[cat] {
			continue
		}
		name, fresh := c.freshArg(pf, file, argNode(n, a, pf.src), a.Text, tainted)
		if !fresh {
			return "", false
		}
		found = name
	}
	return found, found != ""
}

// freshPathReview is why a file sink on a fresh path goes to review rather than potential
func freshPathReview(sinkText, name string) string {
	return fmt.Sprintf("%s gets a path whose last component the server names itself around a fresh random value (%s), so no file that existed before the call can be read or overwritten through it; the caller picks only the directory the server's own file is created in, and whether that matters decides between a real issue and noise", sinkText, name)
}

func isCallKind(pf *parsedFile, n *sitter.Node) bool {
	for _, k := range pf.adapter.Grammar.CallKinds {
		if n.Kind() == k {
			return true
		}
	}
	return false
}
