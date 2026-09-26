package parser

import (
	"context"
	"testing"

	"github.com/revinand/mcp-scanner/internal/source/language"
)

func TestParseFile_Go(t *testing.T) {
	src := []byte(`package main

import (
	"fmt"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func echoHandler(ctx context.Context, args EchoArgs) (string, error) {
	fmt.Println(args.Text)
	return args.Text, nil
}

func register(s *mcpsdk.Server) {
	s.AddTool(&mcpsdk.Tool{Name: "echo", Description: "Echoes input back"}, echoHandler)
}
`)
	res, err := ParseFile(context.Background(), language.ByID(language.Go), "main.go", src)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if res.HasSyntaxErrors {
		t.Errorf("unexpected syntax errors")
	}
	if len(res.Symbols) != 2 {
		t.Fatalf("want 2 symbols, got %d: %+v", len(res.Symbols), res.Symbols)
	}
	if len(res.Imports) != 2 {
		t.Fatalf("want 2 imports, got %d: %+v", len(res.Imports), res.Imports)
	}
	var found bool
	for _, imp := range res.Imports {
		if imp.Alias == "mcpsdk" {
			found = true
		}
	}
	if !found {
		t.Errorf("aliased import not captured: %+v", res.Imports)
	}

	var addTool *struct{}
	for _, c := range res.Calls {
		if c.CalleeText == "s.AddTool" {
			addTool = &struct{}{}
			var name, desc string
			var handler string
			for _, a := range c.Args {
				switch a.Keyword {
				case "Name":
					name = a.Value
				case "Description":
					desc = a.Value
				}
				if a.Keyword == "" && a.Text == "echoHandler" {
					handler = a.Text
				}
			}
			if name != "echo" {
				t.Errorf("want Name=echo, got %q", name)
			}
			if desc != "Echoes input back" {
				t.Errorf("want Description, got %q", desc)
			}
			if handler != "echoHandler" {
				t.Errorf("want handler arg echoHandler, got %q", handler)
			}
		}
	}
	if addTool == nil {
		t.Fatalf("AddTool call not found among: %+v", res.Calls)
	}
}

func TestParseFile_GoCompactMultiNameParams(t *testing.T) {
	src := []byte(`package main

func runIn(label, command string, retries int) {
	_ = label
	_ = command
	_ = retries
}
`)
	res, err := ParseFile(context.Background(), language.ByID(language.Go), "handler.go", src)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(res.Symbols) != 1 {
		t.Fatalf("want 1 symbol, got %d", len(res.Symbols))
	}
	sym := res.Symbols[0]
	want := []string{"label", "command", "retries"}
	if len(sym.Params) != len(want) {
		t.Fatalf("want params %v, got %v", want, sym.Params)
	}
	for i := range want {
		if sym.Params[i] != want[i] {
			t.Fatalf("want params %v, got %v", want, sym.Params)
		}
	}
}

func TestParseFile_PythonDecorator(t *testing.T) {
	src := []byte(`
@mcp.tool()
def echo(text: str) -> str:
    """Echoes input back."""
    return text
`)
	res, err := ParseFile(context.Background(), language.ByID(language.Python), "server.py", src)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(res.Symbols) != 1 {
		t.Fatalf("want 1 symbol, got %d", len(res.Symbols))
	}
	sym := res.Symbols[0]
	if sym.Name != "echo" {
		t.Errorf("want name echo, got %q", sym.Name)
	}
	if sym.Doc != "Echoes input back." {
		t.Errorf("want docstring captured, got %q", sym.Doc)
	}
	if len(sym.Decorators) != 1 || sym.Decorators[0] != "mcp.tool()" {
		t.Errorf("want decorator mcp.tool(), got %+v", sym.Decorators)
	}
	if len(sym.Params) != 1 || sym.Params[0] != "text" {
		t.Errorf("want params [text], got %+v", sym.Params)
	}
}

func TestParseFile_GoFactory(t *testing.T) {
	src := []byte(`package main

func newEchoTool() *Tool {
	return &Tool{Name: "echo", Description: "Echoes input"}
}
`)
	res, err := ParseFile(context.Background(), language.ByID(language.Go), "factory.go", src)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(res.Symbols) != 1 {
		t.Fatalf("want 1 symbol, got %d", len(res.Symbols))
	}
	rl := res.Symbols[0].ReturnLiteral
	var name, desc string
	for _, a := range rl {
		if a.Keyword == "Name" {
			name = a.Value
		}
		if a.Keyword == "Description" {
			desc = a.Value
		}
	}
	if name != "echo" || desc != "Echoes input" {
		t.Errorf("want name/description extracted from return literal, got %+v", rl)
	}
}

func TestParseFile_ConciseArrowReturnText(t *testing.T) {
	cases := []struct {
		name, src, want string
	}{
		{
			name: "parenthesized object",
			src: `const listTools = async () => ({
  tools: [{ name: "echo", description: "Echoes input" }],
});
`,
			want: `{
  tools: [{ name: "echo", description: "Echoes input" }],
}`,
		},
		{
			name: "bare array",
			src:  `const listTools = async () => [{ name: "echo", description: "Echoes input" }];`,
			want: `[{ name: "echo", description: "Echoes input" }]`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := ParseFile(context.Background(), language.ByID(language.TypeScript), "handler.ts", []byte(c.src))
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			var got string
			for _, s := range res.Symbols {
				if s.ReturnText != "" {
					got = s.ReturnText
				}
			}
			if got != c.want {
				t.Errorf("ReturnText = %q, want %q", got, c.want)
			}
		})
	}
}

// TestParseFile_BlockArrowReturnText checks the block-bodied form still
// works exactly as before: `() => { return {...}; }`
func TestParseFile_BlockArrowReturnText(t *testing.T) {
	src := `const listTools = async () => {
  return { tools: [{ name: "echo" }] };
};
`
	res, err := ParseFile(context.Background(), language.ByID(language.TypeScript), "handler.ts", []byte(src))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	var got string
	for _, s := range res.Symbols {
		if s.ReturnText != "" {
			got = s.ReturnText
		}
	}
	if got != `{ tools: [{ name: "echo" }] }` {
		t.Errorf("ReturnText = %q, want the returned object literal", got)
	}
}
