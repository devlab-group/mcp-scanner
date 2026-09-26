package parser

import (
	"sort"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/revinand/mcp-scanner/internal/source/language"
)

func paramBindingsOf(t *testing.T, id language.ID, src string) []string {
	t.Helper()
	adapter := language.ByID(id)
	lang, err := adapter.Language()
	if err != nil {
		t.Fatal(err)
	}
	p := sitter.NewParser()
	defer p.Close()
	if err := p.SetLanguage(lang); err != nil {
		t.Fatal(err)
	}
	tree := p.Parse([]byte(src), nil)
	defer tree.Close()

	q, err := adapter.Query("symbols")
	if err != nil {
		t.Fatal(err)
	}
	qc := sitter.NewQueryCursor()
	defer qc.Close()
	matches := qc.Matches(q, tree.RootNode(), []byte(src))
	m := matches.Next()
	if m == nil {
		t.Fatalf("no function found in %q", src)
	}
	def := m.Captures[0].Node
	list := ParamList(&def)
	if list == nil {
		t.Fatalf("no parameter list found in %q", src)
	}
	param := list.NamedChild(0)
	if param == nil {
		t.Fatalf("no parameter found in %q", src)
	}
	names := ParamBindings(id, param, []byte(src))
	sort.Strings(names)
	return names
}

func TestParamBindings_Destructured(t *testing.T) {
	cases := []struct {
		name string
		id   language.ID
		src  string
		want []string
	}{
		{"js plain identifier", language.JavaScript, `const h = (path) => { exec(path); };`, []string{"path"}},
		{"js object shorthand", language.JavaScript, `const h = ({ path }) => { exec(path); };`, []string{"path"}},
		{"js object multiple", language.JavaScript, `const h = ({ a, b }) => { exec(a); };`, []string{"a", "b"}},
		{"js array pattern", language.JavaScript, `const h = ([a, b]) => { exec(a); };`, []string{"a", "b"}},
		{"js rest element", language.JavaScript, `const h = ({ path, ...rest }) => { exec(path); };`, []string{"path", "rest"}},
		{"ts typed destructure", language.TypeScript, `const h = ({ path }: { path: string }) => { exec(path); };`, []string{"path"}},
		{"ts function declaration multi", language.TypeScript, `async function h({ a, b }: { a: string, b: string }) { exec(a); }`, []string{"a", "b"}},
		{"ts renamed binding", language.TypeScript, `async function h({ path: p }: { path: string }) { exec(p); }`, []string{"p"}},
		{"ts nested binding", language.TypeScript, `async function h({ a: { b } }: { a: { b: string } }) { exec(b); }`, []string{"b"}},
		{"ts default value", language.TypeScript, `async function h({ path = "x" }: { path?: string }) { exec(path); }`, []string{"path"}},
		{"go compact multi-name", language.Go, `func h(a, b string) { exec(a); }`, []string{"a", "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := paramBindingsOf(t, c.id, c.src)
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}
