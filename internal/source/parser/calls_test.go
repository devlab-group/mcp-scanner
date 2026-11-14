package parser

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

type callContext struct {
	inLoop    bool
	decorator bool
}

func TestParseFile_CallsRecordLoopAndDecoratorContext(t *testing.T) {
	cases := []struct {
		name string
		lang language.ID
		file string
		src  string
		want map[string]callContext
	}{
		{
			name: "go range loop",
			lang: language.Go,
			file: "a.go",
			src:  "package p\nfunc m() {\n\tfor _, t := range ts {\n\t\tinside(t)\n\t}\n\toutside()\n}\n",
			want: map[string]callContext{
				"inside":  {inLoop: true},
				"outside": {},
			},
		},
		{
			name: "python module-level loop, including the call in its header",
			lang: language.Python,
			file: "a.py",
			src:  "for t in header():\n    inside(t)\noutside()\n",
			want: map[string]callContext{
				"header":  {inLoop: true},
				"inside":  {inLoop: true},
				"outside": {},
			},
		},
		{
			name: "python loop around a definition does not reach calls in its body",
			lang: language.Python,
			file: "a.py",
			src:  "for t in ts:\n    def h():\n        nested()\n        for u in us:\n            inner()\n",
			want: map[string]callContext{
				"nested": {},
				"inner":  {inLoop: true},
			},
		},
		{
			name: "python decorator, but not a call in its arguments",
			lang: language.Python,
			file: "a.py",
			src:  "@mcp.tool(name=named())\ndef f():\n    pass\n",
			want: map[string]callContext{
				"mcp.tool": {decorator: true},
				"named":    {},
			},
		},
		{
			name: "python decorator inside a loop",
			lang: language.Python,
			file: "a.py",
			src:  "for n in names:\n    @mcp.tool(name=n)\n    def f():\n        pass\n",
			want: map[string]callContext{
				"mcp.tool": {inLoop: true, decorator: true},
			},
		},
		{
			name: "javascript for-of and classic for",
			lang: language.JavaScript,
			file: "a.js",
			src:  "for (const t of ts) { inside(t) }\nfor (;;) { classic() }\noutside()\n",
			want: map[string]callContext{
				"inside":  {inLoop: true},
				"classic": {inLoop: true},
				"outside": {},
			},
		},
		{
			name: "java enhanced for",
			lang: language.Java,
			file: "E.java",
			src:  "class E { void m() { for (String t : ts) { inside(t); } outside(); } }\n",
			want: map[string]callContext{
				"inside":  {inLoop: true},
				"outside": {},
			},
		},
		{
			name: "rust for",
			lang: language.Rust,
			file: "a.rs",
			src:  "fn m() { for t in ts { inside(t); } outside(); }\n",
			want: map[string]callContext{
				"inside":  {inLoop: true},
				"outside": {},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := ParseFile(context.Background(), language.ByID(c.lang), c.file, []byte(c.src))
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			got := map[string]callContext{}
			for _, call := range res.Calls {
				got[call.CalleeText] = callContext{
					inLoop:    call.InLoop,
					decorator: call.IsDecorator,
				}
			}
			if len(got) != len(c.want) {
				t.Errorf("calls = %+v, want %+v", got, c.want)
			}
			for callee, want := range c.want {
				if g, ok := got[callee]; !ok || g != want {
					t.Errorf("%s: got %+v (found %v), want %+v", callee, g, ok, want)
				}
			}
		})
	}
}

// Resolve loop context in one downward walk so deeply nested calls finish
// without timing out and retain their InLoop flags
func TestParseFile_DeeplyNestedCallsDoNotStallTheParse(t *testing.T) {
	const depth = 6000
	src := []byte("function m() { for (;;) { " + strings.Repeat("f(", depth) + "0" + strings.Repeat(")", depth) + " } }\n")

	type result struct {
		res *FileResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := ParseFile(context.Background(), language.ByID(language.JavaScript), "a.js", src)
		done <- result{res, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("ParseFile: %v", r.err)
		}
		if len(r.res.Calls) != depth {
			t.Fatalf("got %d calls, want %d", len(r.res.Calls), depth)
		}
		for i, call := range r.res.Calls {
			if !call.InLoop {
				t.Fatalf("call %d of %d: InLoop = false, want true: every call sits in the loop", i, depth)
			}
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("parse of %d nested calls still running after 30s", depth)
	}
}

// Nested arguments contain earlier calls. Share their source spans to avoid
// quadratic copying and memory use.
func TestParseFile_NestedCallTextStaysNearTheFileSize(t *testing.T) {
	const depth = 12000
	src := []byte("x = " + strings.Repeat("f(", depth) + "1" + strings.Repeat(")", depth) + "\n")

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	res, err := ParseFile(context.Background(), language.ByID(language.Python), "a.py", src)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	// Allow parser overhead while rejecting the quadratic cost of copied argument text
	const limit = 64 << 20
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > limit {
		t.Errorf("parsing a %d KB file allocated %d MB, want under %d MB", len(src)>>10, alloc>>20, limit>>20)
	}
	if len(res.Calls) != depth {
		t.Fatalf("got %d calls, want %d", len(res.Calls), depth)
	}
	// The innermost call's argument is 1, and each call out wraps one more f( ... ) around it
	seen := make([]bool, depth)
	for _, call := range res.Calls {
		if len(call.Args) != 1 {
			t.Fatalf("call has %d args, want 1", len(call.Args))
		}
		text := call.Args[0].Text
		k := (len(text) - 1) / 3
		if k >= depth || seen[k] || text != strings.Repeat("f(", k)+"1"+strings.Repeat(")", k) {
			t.Fatalf("unexpected argument text %.40q (%d bytes)", text, len(text))
		}
		seen[k] = true
	}
}

// Each chained callee contains the preceding links. Parse the chain without
// recursively extracting every earlier receiver at each link.
func TestParseFile_LongCallChainsParse(t *testing.T) {
	const links = 4000
	chain := "a" + strings.Repeat(".f()", links)
	cases := []struct {
		lang language.ID
		file string
		src  string
	}{
		{language.JavaScript, "a.js", "x = " + chain + ";\n"},
		{language.TypeScript, "a.ts", "x = " + chain + ";\n"},
		{language.Python, "a.py", "x = " + chain + "\n"},
		{language.Go, "a.go", "package p\nfunc m() { " + chain + " }\n"},
		{language.Java, "A.java", "class A { void m() { " + chain + "; } }\n"},
		{language.Rust, "a.rs", "fn m() { " + chain + "; }\n"},
	}
	for _, c := range cases {
		t.Run(string(c.lang), func(t *testing.T) {
			res, err := ParseFile(context.Background(), language.ByID(c.lang), c.file, []byte(c.src))
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			var got []string
			for _, call := range res.Calls {
				got = append(got, call.CalleeText)
			}
			want := make([]string, links)
			for k := range want {
				want[k] = "a" + strings.Repeat(".f()", k) + ".f"
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("got %d callees, want the %d links of the chain", len(got), links)
			}
		})
	}
}

// CalleeAndArgs reads one receiver level for taint analysis; following the
// receiver's receiver at every link would make chain processing quadratic
func TestCalleeAndArgs_ChainReceiverIsThePreviousLink(t *testing.T) {
	const links = 4000
	src := []byte("x = a" + strings.Repeat(".f(1)", links) + ";\n")
	adapter := language.ByID(language.JavaScript)
	tree, err := ParseTree(context.Background(), adapter, src)
	if err != nil {
		t.Fatalf("ParseTree: %v", err)
	}
	defer tree.Close()

	got := map[string]Receiver{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, call := range nodesOfKind(tree.RootNode(), adapter.Grammar.CallKinds) {
			callee, recv, _ := CalleeAndArgs(adapter.ID, &call, src)
			got[callee] = recv
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("CalleeAndArgs over a chain of %d calls still running after 30s", links)
	}
	if len(got) != links {
		t.Fatalf("got %d calls, want %d", len(got), links)
	}
	if r := got["a.f"]; r.Text != "a" || r.CallText != "" {
		t.Errorf("receiver of the first link = %+v, want the identifier a", r)
	}
	for k := 1; k < links; k++ {
		prev := "a" + strings.Repeat(".f(1)", k-1) + ".f"
		r := got["a"+strings.Repeat(".f(1)", k)+".f"]
		if r.Text != "" || r.CallText != prev || len(r.CallArgs) != 1 || r.CallArgs[0].Text != "1" {
			t.Fatalf("receiver of link %d = {Text: %.20q, CallText: %.20q, %d args}, want the call to link %d",
				k, r.Text, r.CallText, len(r.CallArgs), k-1)
		}
	}
}

func nodesOfKind(root *sitter.Node, kinds []string) []sitter.Node {
	var out []sitter.Node
	c := root.Walk()
	defer c.Close()
	for {
		if n := c.Node(); slices.Contains(kinds, n.Kind()) {
			out = append(out, *n)
		}
		if c.GotoFirstChild() {
			continue
		}
		for !c.GotoNextSibling() {
			if !c.GotoParent() {
				return out
			}
		}
	}
}

func TestParseFile_JavaCalleeJoinsAroundTheDot(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want string
	}{
		{"plain dots", "a.b.f(p)", "a.b.f"},
		{"newline before the dot", "Files\n    .readAllBytes(p)", "Files.readAllBytes"},
		{"spaces around the dot", "Files . readAllBytes(p)", "Files.readAllBytes"},
		{"block comment before the dot", "Files /* c */ .readAllBytes(p)", "Files.readAllBytes"},
		{"line comment before the dot", "Files // c\n    .readAllBytes(p)", "Files.readAllBytes"},
		{"comment after the dot", "b.build()./* c */run()", "b.build().run"},
		{"type arguments after the dot", "a.<String>f()", "a.f"},
		{"comment inside the object", "a /* c */ .b.f()", "a.b.f"},
		{"non-ASCII identifier before a newline", "Ünï\n    .f()", "Ünï.f"},
		// Preserve spans after brackets: identifier patterns cannot cross them, and the
		// final segment still follows the last dot
		{"newline after a call", "b.build()\n    .run()", "b.build()\n    .run"},
		{"comment after a call", "b.build() /* c */ .run()", "b.build() /* c */ .run"},
		{"newline after an index", "a[0]\n    .f()", "a[0]\n    .f"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "class A { void m() { " + c.expr + "; } }\n"
			res, err := ParseFile(context.Background(), language.ByID(language.Java), "A.java", []byte(src))
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			var got []string
			for _, call := range res.Calls {
				got = append(got, call.CalleeText)
			}
			if !slices.Contains(got, c.want) {
				t.Errorf("callees = %q, want %q among them", got, c.want)
			}
		})
	}
}

// Joining Java callees across newlines copies each preceding chain. Reject
// the file when that quadratic text growth exceeds the budget.
func TestParseFile_CallTextPastTheLimitIsALimit(t *testing.T) {
	src := []byte("class A { void m() { a" + strings.Repeat(".x\n.f()", 2000) + "; } }\n")
	res, err := ParseFile(context.Background(), language.ByID(language.Java), "A.java", src)
	if !errors.Is(err, ErrTextLimit) {
		t.Fatalf("err = %v, want ErrTextLimit", err)
	}
	if res != nil {
		t.Errorf("got a result with %d calls alongside the error, want none", len(res.Calls))
	}
}
