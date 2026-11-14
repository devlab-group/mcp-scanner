package registration

import (
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

const pyHeader = "from fastmcp import FastMCP\n\nmcp = FastMCP(\"calc\")\n"

// Use the description argument when present; fall back to the docstring only
// for absent, empty or None values. Unreadable arguments must stay unresolved
// to avoid analyzing fallback text the server may not serve.
func TestDiscover_DecoratorDescription(t *testing.T) {
	const doc = "\n    \"\"\"Doc.\"\"\"\n    return a\n"
	py := func(prelude, decorator string) string {
		return pyHeader + prelude + "\n" + decorator + "\ndef add(a: int) -> int:" + doc
	}
	tests := []struct {
		name         string
		lang         language.ID
		src          string
		wantResolved bool
		want         string
	}{
		// Resolve the explicit argument
		{name: "keyword literal", lang: language.Python, src: py("", `@mcp.tool(description="Adds.")`), wantResolved: true, want: "Adds."},
		{name: "triple-quoted literal", lang: language.Python, src: py("", "@mcp.tool(description=\"\"\"Adds.\nMore.\"\"\")"), wantResolved: true, want: "Adds.\nMore."},
		{name: "parenthesized implicit concatenation", lang: language.Python, src: py("", "@mcp.tool(\n    description=(\n        \"Adds. \"\n        \"More.\"\n    )\n)"), wantResolved: true, want: "Adds. More."},
		{name: "comment between concatenated parts", lang: language.Python, src: py("", "@mcp.tool(description=(\"Adds. \"  # first part\n    \"More.\"))"), wantResolved: true, want: "Adds. More."},
		{name: "module constant", lang: language.Python, src: py(`D = "Adds."`, `@mcp.tool(description=D)`), wantResolved: true, want: "Adds."},
		{name: "annotated module constant", lang: language.Python, src: py(`D: str = "Adds."`, `@mcp.tool(description=D)`), wantResolved: true, want: "Adds."},
		{name: "triple-quoted constant in parentheses", lang: language.Python, src: py(`D = ("""Adds.""")`, `@mcp.tool(description=D)`), wantResolved: true, want: "Adds."},
		{name: "decoy key inside another argument's string", lang: language.Python, src: py("", `@mcp.tool(title="Calc (description='Decoy.')", description="Real.")`), wantResolved: true, want: "Real."},
		{name: "third positional argument", lang: language.Python, src: py("", `@mcp.tool("add", "Add", "Adds.")`), wantResolved: true, want: "Adds."},
		{name: "comment before positional arguments", lang: language.Python, src: py("", "@mcp.tool(\n    # name, title, description\n    \"add\", \"Add\", \"Adds.\")"), wantResolved: true, want: "Adds."},

		// Use the docstring fallback
		{name: "no description argument", lang: language.Python, src: py("", `@mcp.tool()`), wantResolved: true, want: "Doc."},
		{name: "bare decorator", lang: language.Python, src: py("", `@mcp.tool`), wantResolved: true, want: "Doc."},
		{name: "empty description", lang: language.Python, src: py("", `@mcp.tool(description="")`), wantResolved: true, want: "Doc."},
		{name: "None description", lang: language.Python, src: py("", `@mcp.tool(description=None)`), wantResolved: true, want: "Doc."},
		{name: "constant bound to an empty string", lang: language.Python, src: py(`D = ""`, `@mcp.tool(description=D)`), wantResolved: true, want: "Doc."},
		{name: "concatenated docstring", lang: language.Python, src: pyHeader + "\n@mcp.tool\ndef add(a: int) -> int:\n    \"Doc. \" \"More.\"\n    return a\n", wantResolved: true, want: "Doc. More."},
		{name: "keyword wins over unpacked options", lang: language.Python, src: py(`OPTS = {}`, `@mcp.tool(**OPTS, description="Adds.")`), wantResolved: true, want: "Adds."},

		// Without a Python docstring, the description is known to be empty; comments do not count
		{name: "no docstring", lang: language.Python, src: pyHeader + "\n@mcp.tool()\ndef add(a: int) -> int:\n    return a\n", wantResolved: true},
		{name: "comment above the function", lang: language.Python, src: pyHeader + "\n# Adds.\n@mcp.tool()\ndef add(a: int) -> int:\n    return a\n", wantResolved: true},
		{name: "empty description and no docstring", lang: language.Python, src: pyHeader + "\n@mcp.tool(description=\"\")\ndef add(a: int) -> int:\n    return a\n", wantResolved: true},

		// Rust doc comments and Java framework fallbacks remain unresolved
		{name: "rust without a description argument", lang: language.Rust, src: "impl T {\n    /// Adds.\n    #[tool]\n    fn add(&self, a: i64) -> i64 { a }\n}\n"},
		{name: "java without a description argument", lang: language.Java, src: "class T {\n    /** Adds. */\n    @Tool(name = \"add\")\n    int add(int a) { return a; }\n}\n"},

		// Keep unreadable arguments unresolved instead of using the docstring
		{name: "conditional expression", lang: language.Python, src: py("A = \"Adds.\"\nB = \"Other.\"\nX = True", `@mcp.tool(description=A if X else B)`)},
		{name: "call", lang: language.Python, src: py("", `@mcp.tool(description=load("add"))`)},
		{name: "concatenation with an f-string part", lang: language.Python, src: py(`N = "x"`, `@mcp.tool(description=("Adds. " f"{N}"))`)},
		{name: "f-string", lang: language.Python, src: py(`N = "x"`, `@mcp.tool(description=f"Adds {N}.")`)},
		{name: "attribute", lang: language.Python, src: py("import descs", `@mcp.tool(description=descs.ADD)`)},
		{name: "unpacked options", lang: language.Python, src: py(`OPTS = {"description": "Adds."}`, `@mcp.tool(**OPTS)`)},
		{name: "constant imported from another module", lang: language.Python, src: py("from descs import D", `@mcp.tool(description=D)`)},
		{name: "name bound once to a call", lang: language.Python, src: py("D = load()", `@mcp.tool(description=D)`)},

		// Reject a constant name with another binding anywhere in the file
		{name: "constant reassigned", lang: language.Python, src: py("D = \"Adds.\"\nD = load()", `@mcp.tool(description=D)`)},
		{name: "constant augmented", lang: language.Python, src: py("D = \"Adds.\"\nD += load()", `@mcp.tool(description=D)`)},
		{name: "constant rebound through global in a function", lang: language.Python, src: py("D = \"Adds.\"\n\ndef setup():\n    global D\n    D = load()\n\nsetup()", `@mcp.tool(description=D)`)},
		{name: "constant rebound by tuple assignment", lang: language.Python, src: py("D = \"Adds.\"\nD, E = load(), 1", `@mcp.tool(description=D)`)},
		{name: "constant rebound by a for loop", lang: language.Python, src: py("D = \"Adds.\"\nfor D in load():\n    pass", `@mcp.tool(description=D)`)},
		{name: "constant rebound by an assignment expression", lang: language.Python, src: py("D = \"Adds.\"\nif (D := load()):\n    pass", `@mcp.tool(description=D)`)},
		{name: "constant rebound by with", lang: language.Python, src: py("D = \"Adds.\"\nwith load() as D:\n    pass", `@mcp.tool(description=D)`)},
		{name: "constant rebound by except", lang: language.Python, src: py("D = \"Adds.\"\ntry:\n    pass\nexcept Exception as D:\n    pass", `@mcp.tool(description=D)`)},
		{name: "constant rebound by a match capture", lang: language.Python, src: py("D = \"Adds.\"\nmatch load():\n    case D:\n        pass", `@mcp.tool(description=D)`)},
		{name: "constant rebound by an import alias", lang: language.Python, src: py("D = \"Adds.\"\nimport descs as D", `@mcp.tool(description=D)`)},
		{name: "constant deleted", lang: language.Python, src: py("D = \"Adds.\"\ndel D", `@mcp.tool(description=D)`)},
		{name: "name shadowed by an enclosing function's parameter", lang: language.Python, src: pyHeader + "D = \"Adds.\"\n\ndef register(mcp, D):\n    @mcp.tool(description=D)\n    def add(a: int) -> int:\n        \"\"\"Doc.\"\"\"\n        return a\n"},
		{name: "star import", lang: language.Python, src: py("D = \"Adds.\"\nfrom descs import *", `@mcp.tool(description=D)`)},
		{name: "globals write", lang: language.Python, src: py("D = \"Adds.\"\nglobals()[\"D\"] = load()", `@mcp.tool(description=D)`)},
		{name: "setattr on the module", lang: language.Python, src: py("import sys\nD = \"Adds.\"\nsetattr(sys.modules[__name__], \"D\", load())", `@mcp.tool(description=D)`)},
		{name: "exec", lang: language.Python, src: py("D = \"Adds.\"\nexec(\"D = load()\")", `@mcp.tool(description=D)`)},

		// Java annotations
		{name: "java string literal", lang: language.Java, src: "class T {\n    @Tool(description = \"Adds.\")\n    int add(int a) { return a; }\n}\n", wantResolved: true, want: "Adds."},
		{name: "java text block", lang: language.Java, src: "class T {\n    @Tool(description = \"\"\"\n        Adds.\n        \"\"\")\n    int add(int a) { return a; }\n}\n", wantResolved: true, want: "Adds."},
		{name: "java decoy key inside another argument's string", lang: language.Java, src: "class T {\n    @Tool(name = \"add description='Decoy.'\", description = \"Real.\")\n    int add(int a) { return a; }\n}\n", wantResolved: true, want: "Real."},
		{name: "java constant", lang: language.Java, src: "class T {\n    static final String D = \"Adds.\";\n    @Tool(description = D)\n    int add(int a) { return a; }\n}\n", wantResolved: true, want: "Adds."},
		{name: "java constant built by concatenation", lang: language.Java, src: "class T {\n    private static final String D = \"Adds. \" + (\"More.\");\n    @Tool(description = D)\n    int add(int a) { return a; }\n}\n", wantResolved: true, want: "Adds. More."},
		{name: "java interface constant", lang: language.Java, src: "interface K {\n    String D = \"Adds.\";\n}\nclass T implements K {\n    @Tool(description = D)\n    int add(int a) { return a; }\n}\n", wantResolved: true, want: "Adds."},
		{name: "java value is the description", lang: language.Java, src: "class T {\n    @Tool(\"Adds.\")\n    int add(int a) { return a; }\n}\n", wantResolved: true, want: "Adds."},
		{name: "java value keyword", lang: language.Java, src: "class T {\n    @Tool(name = \"add\", value = \"Adds.\")\n    int add(int a) { return a; }\n}\n", wantResolved: true, want: "Adds."},
		{name: "java value lines", lang: language.Java, src: "class T {\n    @Tool({\"Adds.\", \"More.\"})\n    int add(int a) { return a; }\n}\n", wantResolved: true, want: "Adds.\nMore."},
		{name: "java value lines with a name", lang: language.Java, src: "class T {\n    @Tool({\"Adds.\", MORE})\n    int add(int a) { return a; }\n}\n"},
		{name: "java field that is not final", lang: language.Java, src: "class T {\n    static String D = \"Adds.\";\n    @Tool(description = D)\n    int add(int a) { return a; }\n}\n"},
		{name: "java constant declared by two classes", lang: language.Java, src: "class U {\n    static final String D = \"Other.\";\n}\nclass T {\n    static final String D = \"Adds.\";\n    @Tool(description = D)\n    int add(int a) { return a; }\n}\n"},
		{name: "java constant from another class", lang: language.Java, src: "class T {\n    @Tool(description = Descs.ADD)\n    int add(int a) { return a; }\n}\n"},
		{name: "java concatenation", lang: language.Java, src: "class T {\n    @Tool(description = \"Adds.\" + MORE)\n    int add(int a) { return a; }\n}\n"},

		// Rust attributes
		{name: "rust string literal", lang: language.Rust, src: "impl T {\n    #[tool(description = \"Adds.\")]\n    fn add(&self, a: i64) -> i64 { a }\n}\n", wantResolved: true, want: "Adds."},
		{name: "rust raw string with hashes", lang: language.Rust, src: "impl T {\n    #[tool(description = r#\"Adds \"quoted\".\"#)]\n    fn add(&self, a: i64) -> i64 { a }\n}\n", wantResolved: true, want: `Adds "quoted".`},
		{name: "rust raw string without hashes", lang: language.Rust, src: "impl T {\n    #[tool(description = r\"Adds.\")]\n    fn add(&self, a: i64) -> i64 { a }\n}\n", wantResolved: true, want: "Adds."},
		{name: "rust decoy key inside another argument's string", lang: language.Rust, src: "impl T {\n    #[tool(name = \"description = 'Decoy.'\", description = \"Real.\")]\n    fn add(&self, a: i64) -> i64 { a }\n}\n", wantResolved: true, want: "Real."},
		{name: "rust trailing comma", lang: language.Rust, src: "impl T {\n    #[tool(\n        description = \"Adds.\",\n    )]\n    fn add(&self, a: i64) -> i64 { a }\n}\n", wantResolved: true, want: "Adds."},
		{name: "rust constant", lang: language.Rust, src: "const D: &str = \"Adds.\";\nimpl T {\n    #[tool(description = D)]\n    fn add(&self, a: i64) -> i64 { a }\n}\n", wantResolved: true, want: "Adds."},
		{name: "rust static", lang: language.Rust, src: "pub static D: &'static str = r\"Adds.\";\nimpl T {\n    #[tool(description = D)]\n    fn add(&self, a: i64) -> i64 { a }\n}\n", wantResolved: true, want: "Adds."},
		{name: "rust constant also declared in a module", lang: language.Rust, src: "const D: &str = \"Adds.\";\nmod m {\n    pub const D: &str = \"Other.\";\n}\nimpl T {\n    #[tool(description = D)]\n    fn add(&self, a: i64) -> i64 { a }\n}\n"},
		{name: "rust constant of another type", lang: language.Rust, src: "const D: &[u8] = b\"Adds.\";\nimpl T {\n    #[tool(description = D)]\n    fn add(&self, a: i64) -> i64 { a }\n}\n"},
		{name: "rust concat macro", lang: language.Rust, src: "impl T {\n    #[tool(description = concat!(\"Adds\", \".\"))]\n    fn add(&self, a: i64) -> i64 { a }\n}\n"},
	}
	files := map[language.ID]string{language.Python: "server.py", language.Java: "T.java", language.Rust: "lib.rs"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := buildGraph(t, map[language.ID]map[string]string{tt.lang: {files[tt.lang]: tt.src}})
			Discover(g)
			if len(g.Capabilities) != 1 {
				t.Fatalf("want exactly one capability, got %+v", g.Capabilities)
			}
			c := g.Capabilities[0]
			got := strings.TrimSpace(c.Description)
			if c.DescriptionResolved != tt.wantResolved || got != tt.want {
				t.Errorf("description = (%q, resolved %v), want (%q, resolved %v)", got, c.DescriptionResolved, tt.want, tt.wantResolved)
			}
		})
	}
}

// Registration calls and decorators share the lookup for same-file constants
func TestDiscover_CallArgumentConstant(t *testing.T) {
	const handler = "\ndef add(a: int) -> int:\n    return a\n\n"
	const wrapper = "def register(name, desc, fn):\n    mcp.tool(name, desc, fn)\n\n"
	tests := []struct {
		name         string
		src          string
		form         string
		wantResolved bool
		want         string
	}{
		{name: "add_tool with a constant description", src: pyHeader + "D = \"Adds.\"\n" + handler + "mcp.add_tool(add, description=D)\n", form: "direct", wantResolved: true, want: "Adds."},
		{name: "add_tool with a reassigned constant", src: pyHeader + "D = \"Adds.\"\nD = load()\n" + handler + "mcp.add_tool(add, description=D)\n", form: "direct"},
		{name: "positional name and description constants", src: pyHeader + "N = \"add\"\nD = \"Adds.\"\n" + handler + "mcp.tool(N, D, add)\n", form: "direct", wantResolved: true, want: "Adds."},
		{name: "wrapper called with a constant description", src: pyHeader + "D = \"Adds.\"\n" + handler + wrapper + "register(\"add\", D, add)\n", form: "wrapper", wantResolved: true, want: "Adds."},
		{name: "wrapper called with a reassigned constant", src: pyHeader + "D = \"Adds.\"\nD = load()\n" + handler + wrapper + "register(\"add\", D, add)\n", form: "wrapper"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := buildGraph(t, map[language.ID]map[string]string{language.Python: {"server.py": tt.src}})
			Discover(g)
			c := findCap(g.Capabilities, tt.form)
			if c == nil {
				t.Fatalf("no %s capability among %+v", tt.form, g.Capabilities)
			}
			if c.DescriptionResolved != tt.wantResolved || c.Description != tt.want {
				t.Errorf("description = (%q, resolved %v), want (%q, resolved %v)", c.Description, c.DescriptionResolved, tt.want, tt.wantResolved)
			}
		})
	}
}

// Use the function's name for absent, empty or None name arguments; leave
// unreadable name arguments unresolved
func TestDiscover_DecoratorName(t *testing.T) {
	const body = "\ndef add(a: int) -> int:\n    \"\"\"Doc.\"\"\"\n    return a\n"
	py := func(prelude, decorator string) string {
		return pyHeader + prelude + "\n" + decorator + body
	}
	tests := []struct {
		name         string
		lang         language.ID
		src          string
		wantResolved bool
		want         string
	}{
		{name: "keyword literal", lang: language.Python, src: py("", `@mcp.tool(name="sum")`), wantResolved: true, want: "sum"},
		{name: "keyword constant", lang: language.Python, src: py(`N = "sum"`, `@mcp.tool(name=N)`), wantResolved: true, want: "sum"},
		{name: "first positional", lang: language.Python, src: py("", `@mcp.tool("sum")`), wantResolved: true, want: "sum"},
		{name: "prompt first positional", lang: language.Python, src: py("", `@mcp.prompt("sum")`), wantResolved: true, want: "sum"},
		{name: "resource first positional is the URI", lang: language.Python, src: py("", `@mcp.resource("data://sum")`), wantResolved: true, want: "add"},
		{name: "no name argument", lang: language.Python, src: py("", `@mcp.tool()`), wantResolved: true, want: "add"},
		{name: "empty name", lang: language.Python, src: py("", `@mcp.tool(name="")`), wantResolved: true, want: "add"},
		{name: "None name", lang: language.Python, src: py("", `@mcp.tool(name=None)`), wantResolved: true, want: "add"},
		{name: "conditional name", lang: language.Python, src: py("X = True", `@mcp.tool(name="a" if X else "b")`)},
		{name: "name from a call", lang: language.Python, src: py("", `@mcp.tool(name=load())`)},
		{name: "reassigned constant", lang: language.Python, src: py("N = \"sum\"\nN = load()", `@mcp.tool(name=N)`)},
		{name: "unpacked options", lang: language.Python, src: py(`OPTS = {"name": "sum"}`, `@mcp.tool(**OPTS)`)},
		{name: "unpacked positional arguments", lang: language.Python, src: py(`ARGS = ("sum",)`, `@mcp.tool(*ARGS)`)},
		{name: "java constant", lang: language.Java, src: "class T {\n    static final String N = \"sum\";\n    @Tool(name = N)\n    int add(int a) { return a; }\n}\n", wantResolved: true, want: "sum"},
		{name: "java constant from another class", lang: language.Java, src: "class T {\n    @Tool(name = Names.SUM)\n    int add(int a) { return a; }\n}\n"},
		{name: "java value is not the name", lang: language.Java, src: "class T {\n    @Tool(\"Adds.\")\n    int add(int a) { return a; }\n}\n", wantResolved: true, want: "add"},
		{name: "rust constant", lang: language.Rust, src: "const N: &str = \"sum\";\nimpl T {\n    #[tool(name = N)]\n    fn add(&self, a: i64) -> i64 { a }\n}\n", wantResolved: true, want: "sum"},
	}
	files := map[language.ID]string{language.Python: "server.py", language.Java: "T.java", language.Rust: "lib.rs"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := buildGraph(t, map[language.ID]map[string]string{tt.lang: {files[tt.lang]: tt.src}})
			Discover(g)
			if len(g.Capabilities) != 1 {
				t.Fatalf("want exactly one capability, got %+v", g.Capabilities)
			}
			c := g.Capabilities[0]
			want := tt.want
			if !tt.wantResolved {
				want = ""
			}
			if c.NameResolved != tt.wantResolved || c.Name != want {
				t.Errorf("name = (%q, resolved %v), want (%q, resolved %v)", c.Name, c.NameResolved, want, tt.wantResolved)
			}
		})
	}
}
