package parser

import (
	"context"
	"slices"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

// Normalize whitespace, comments and line continuations around member operators
// so dotted patterns, hint words and final-segment matching still recognize callees
func TestParseFile_CalleeTextIgnoresWhatSurroundsTheDot(t *testing.T) {
	cases := []struct {
		name string
		lang language.ID
		file string
		src  string
		want string
	}{
		{"js plain", language.JavaScript, "a.js", "a.b.c(x)\n", "a.b.c"},
		{"js comment after the dot", language.JavaScript, "a.js", "server./* c */tool(x)\n", "server.tool"},
		{"js comment before the dot", language.JavaScript, "a.js", "server /* c */ .tool(x)\n", "server.tool"},
		{"js newline before the dot", language.JavaScript, "a.js", "server\n  .tool(x)\n", "server.tool"},
		{"js optional chain", language.JavaScript, "a.js", "server ?. tool(x)\n", "server?.tool"},
		{"js bracketed callee", language.JavaScript, "a.js", "(cp.exec)(x)\n", "cp.exec"},
		{"js sequence callee", language.JavaScript, "a.js", "(0, cp.exec)(x)\n", "cp.exec"},
		// Preserve spans after brackets: identifier patterns cannot cross them, and the
		// final segment still follows the last dot
		{"js commented chain link", language.JavaScript, "a.js", "a.b(1)\n  // c\n  .c(x)\n", "a.b(1)\n  // c\n  .c"},
		{"ts compiled import call", language.TypeScript, "a.ts", "(0, child_process_1.execSync)(c);\n", "child_process_1.execSync"},
		{"python plain", language.Python, "a.py", "a.b().c(x)\n", "a.b().c"},
		{"python newline in brackets", language.Python, "a.py", "x = (subprocess\n    .check_output(c))\n", "subprocess.check_output"},
		{"python line continuation", language.Python, "a.py", "os.\\\n    system(c)\n", "os.system"},
		{"python comment in a bracketed callee", language.Python, "a.py", "(os # c\n .system)(c)\n", "os.system"},
		{"python spaces", language.Python, "a.py", "os . system(c)\n", "os.system"},
		{"go newline after the dot", language.Go, "a.go", "package p\nfunc m() { exec.\n\tCommand(c) }\n", "exec.Command"},
		{"go comment after the dot", language.Go, "a.go", "package p\nfunc m() { exec. /* c */ Command(c) }\n", "exec.Command"},
		{"go bracketed callee", language.Go, "a.go", "package p\nfunc m() { (exec.Command)(c) }\n", "exec.Command"},
		{"rust path", language.Rust, "a.rs", "fn m() { std::process:: /* c */ Command::new(c); }\n", "std::process::Command::new"},
		{"rust path from the root", language.Rust, "a.rs", "fn m() { ::std::fs::read(p); }\n", "::std::fs::read"},
		{"rust field", language.Rust, "a.rs", "fn m() { a . /* c */ f(); }\n", "a.f"},
		{"rust macro", language.Rust, "a.rs", "fn m() { std:: /* c */ println!(\"x\"); }\n", "std::println!"},
		{"java constructor", language.Java, "A.java", "class A { void m() { new java. /* c */ lang.ProcessBuilder(c); } }\n", "new java.lang.ProcessBuilder"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := ParseFile(context.Background(), language.ByID(c.lang), c.file, []byte(c.src))
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

// Taint analysis uses CalleeAndArgs for callees and receivers, including
// JavaScript constructors omitted from the source graph's call query
func TestCalleeAndArgs_CalleeAndReceiverIgnoreComments(t *testing.T) {
	cases := []struct {
		name   string
		src    string
		callee string
		recv   Receiver
	}{
		{"receiver", "x = a /* c */ .b.get(u);\n", "a.b.get", Receiver{Text: "a.b"}},
		{"constructor", "x = new vm. /* c */ Script(code);\n", "new vm.Script", Receiver{}},
	}
	adapter := language.ByID(language.JavaScript)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := []byte(c.src)
			tree, err := ParseTree(context.Background(), adapter, src)
			if err != nil {
				t.Fatalf("ParseTree: %v", err)
			}
			defer tree.Close()
			calls := nodesOfKind(tree.RootNode(), adapter.Grammar.CallKinds)
			if len(calls) != 1 {
				t.Fatalf("got %d calls, want 1", len(calls))
			}
			callee, recv, _ := CalleeAndArgs(adapter.ID, &calls[0], src)
			if callee != c.callee || recv.Text != c.recv.Text || recv.CallText != c.recv.CallText {
				t.Errorf("callee %q, receiver %+v; want %q, %+v", callee, recv, c.callee, c.recv)
			}
		})
	}
}

// Normalize decorator names so comments and parentheses do not hide registrations
// from classifyDecorator, as in @Tool /* c */ ("..."), #[ /* c */ tool ] and @(mcp.tool())
func TestParseFile_DecoratorTextIgnoresCommentsAndBrackets(t *testing.T) {
	cases := []struct {
		name   string
		lang   language.ID
		file   string
		src    string
		symbol string
		want   []string
	}{
		{"python call", language.Python, "a.py", "@mcp.tool(name='x')\ndef f():\n    pass\n", "f", []string{"mcp.tool(name='x')"}},
		{"python bare", language.Python, "a.py", "@mcp.tool\ndef f():\n    pass\n", "f", []string{"mcp.tool"}},
		{"python bracketed", language.Python, "a.py", "@(mcp.tool())\ndef f():\n    pass\n", "f", []string{"mcp.tool()"}},
		{"python spaces", language.Python, "a.py", "@mcp . tool(name='x')\ndef f():\n    pass\n", "f", []string{"mcp.tool(name='x')"}},
		{"python line continuation", language.Python, "a.py", "@mcp.\\\n    tool()\ndef f():\n    pass\n", "f", []string{"mcp.tool()"}},
		{"java comment before the arguments", language.Java, "A.java", "class A { @Tool /* c */ (\"d\") void m() {} }\n", "m", []string{"@Tool(\"d\")"}},
		{"java comments in the name", language.Java, "A.java", "class A { @ /* c */ dev.x. /* c */ Tool void m() {} }\n", "m", []string{"@dev.x.Tool"}},
		{"rust comment and spaces in the path", language.Rust, "a.rs", "#[ /* c */ rmcp :: tool ]\nfn h() {}\n", "h", []string{"#[rmcp::tool]"}},
		{"rust doc comment under the attribute", language.Rust, "a.rs", "#[tool]\n/// d\nfn g() {}\n", "g", []string{"#[tool]"}},
		{"rust comments between attributes", language.Rust, "a.rs", "/// d\n#[tool]\n// c\n#[inline]\nfn g() {}\n", "g", []string{"#[tool]", "#[inline]"}},
		{"rust value attribute", language.Rust, "a.rs", "#[doc = \"x\"]\nfn g() {}\n", "g", []string{"#[doc = \"x\"]"}},
		{"rust attribute of the previous item", language.Rust, "a.rs", "#[tool]\nfn a() {}\nfn b() {}\n", "b", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := ParseFile(context.Background(), language.ByID(c.lang), c.file, []byte(c.src))
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			for _, sym := range res.Symbols {
				if sym.Name == c.symbol {
					if !slices.Equal(sym.Decorators, c.want) {
						t.Errorf("decorators = %q, want %q", sym.Decorators, c.want)
					}
					return
				}
			}
			t.Fatalf("no symbol %q among %d", c.symbol, len(res.Symbols))
		})
	}
}

func TestParseFile_RustAttributeArgsAfterAComment(t *testing.T) {
	src := []byte("#[ /* c */ tool(description = \"Reports the uptime\")]\nfn uptime() {}\n")
	res, err := ParseFile(context.Background(), language.ByID(language.Rust), "a.rs", src)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(res.Symbols) != 1 || len(res.Symbols[0].DecoratorArgs) != 1 {
		t.Fatalf("symbols %+v, want one with one attribute", res.Symbols)
	}
	args := res.Symbols[0].DecoratorArgs[0]
	if len(args) != 1 || args[0].Keyword != "description" || args[0].Value != "Reports the uptime" || !args[0].Literal {
		t.Errorf("attribute args = %+v, want the description keyword with its literal value", args)
	}
}
