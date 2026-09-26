package parser

import (
	"slices"
	"sort"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/revinand/mcp-scanner/internal/source/language"
)

func assignTargetsOf(t *testing.T, id language.ID, src string) []string {
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

	node := findKind(tree.RootNode(), adapter.Grammar.AssignKinds)
	if node == nil {
		t.Fatalf("no assignment found in %q", src)
	}
	names := AssignTargets(node, []byte(src))
	sort.Strings(names)
	return names
}

// findKind does a depth-first search for the first node of any kind in
// kinds
func findKind(n *sitter.Node, kinds []string) *sitter.Node {
	if slices.Contains(kinds, n.Kind()) {
		return n
	}
	cursor := n.Walk()
	defer cursor.Close()
	for _, ch := range n.NamedChildren(cursor) {
		child := ch
		if found := findKind(&child, kinds); found != nil {
			return found
		}
	}
	return nil
}

func TestAssignTargets_ShorthandDestructuring(t *testing.T) {
	cases := []struct {
		name string
		id   language.ID
		src  string
		want []string
	}{
		{"plain assignment", language.JavaScript, `const target = opts.target;`, []string{"target"}},
		{"explicit rename pair", language.JavaScript, `const { target: target } = opts;`, []string{"target"}},
		{"shorthand", language.JavaScript, `const { target } = opts;`, []string{"target"}},
		{"shorthand and rename mixed", language.JavaScript, `const { name, arguments: args } = request.params;`, []string{"args", "name"}},
		{"nested shorthand", language.JavaScript, `const { a: { b } } = opts;`, []string{"b"}},
		{"ts shorthand", language.TypeScript, `const { target } = opts;`, []string{"target"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := assignTargetsOf(t, c.id, c.src)
			want := append([]string(nil), c.want...)
			sort.Strings(want)
			if len(got) != len(want) {
				t.Fatalf("got %v, want %v", got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("got %v, want %v", got, want)
				}
			}
		})
	}
}
