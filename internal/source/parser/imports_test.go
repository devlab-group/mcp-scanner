package parser

import (
	"context"
	"reflect"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

// A call to the bare identifier require imports each of its string-literal arguments, at the
// line of that literal
func TestParseFile_RequireImports(t *testing.T) {
	imp := func(path string, line int) graph.Import {
		return graph.Import{
			Path: path,
			File: "a.js",
			Line: line,
		}
	}
	cases := []struct {
		name string
		src  string
		want []graph.Import
	}{
		{name: "one string", src: "const a = require('a')", want: []graph.Import{imp("a", 1)}},
		{name: "every string argument", src: "require('a', 'b')", want: []graph.Import{imp("a", 1), imp("b", 1)}},
		{name: "a string after a non-string", src: "require(x, 'b')", want: []graph.Import{imp("b", 1)}},
		{name: "a comment before the string", src: "require(/* c */ 'a')", want: []graph.Import{imp("a", 1)}},
		{name: "the line of the string, not the call", src: "require\n(\n'a'\n)", want: []graph.Import{imp("a", 3)}},
		{name: "a require inside a require", src: "x = require(require('inner'))", want: []graph.Import{imp("inner", 1)}},
		{name: "template literal", src: "require(`t`)"},
		{name: "tagged template", src: "require`a`"},
		{name: "concatenation", src: "require('a' + 'b')"},
		{name: "member call", src: "foo.require('a')"},
		{name: "another function", src: "load('a')"},
		{name: "no arguments", src: "require()"},
	}
	for _, id := range []language.ID{language.JavaScript, language.TypeScript} {
		for _, c := range cases {
			t.Run(string(id)+"/"+c.name, func(t *testing.T) {
				res, err := ParseFile(context.Background(), language.ByID(id), "a.js", []byte(c.src))
				if err != nil {
					t.Fatalf("ParseFile: %v", err)
				}
				if len(res.Imports) == 0 && len(c.want) == 0 {
					return
				}
				if !reflect.DeepEqual(res.Imports, c.want) {
					t.Errorf("imports = %+v, want %+v", res.Imports, c.want)
				}
			})
		}
	}
}
