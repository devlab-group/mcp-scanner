package parser

import (
	"context"
	"slices"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

func symbolNamed(t *testing.T, id language.ID, src, name string) []string {
	t.Helper()
	adapter := language.ByID(id)
	f, err := ParseFile(context.Background(), adapter, "server.py", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	for _, sym := range f.Symbols {
		if sym.Name == name {
			return sym.Params
		}
	}
	t.Fatalf("no symbol named %q in %q", name, src)
	return nil
}

func TestParams_PythonReceiverDropped(t *testing.T) {
	cases := []struct {
		name string
		src  string
		sym  string
		want []string
	}{
		{
			name: "instance method",
			src: `class Runner:
    def execute(self, cmd):
        return cmd
`,
			sym:  "execute",
			want: []string{"cmd"},
		},
		{
			name: "classmethod",
			src: `class Runner:
    @classmethod
    def execute(cls, cmd):
        return cmd
`,
			sym:  "execute",
			want: []string{"cmd"},
		},
		{
			name: "staticmethod declares no receiver",
			src: `class Runner:
    @staticmethod
    def execute(cmd):
        return cmd
`,
			sym:  "execute",
			want: []string{"cmd"},
		},
		{
			name: "staticmethod keeps every parameter",
			src: `class Runner:
    @staticmethod
    def execute(cwd, cmd):
        return cmd
`,
			sym:  "execute",
			want: []string{"cwd", "cmd"},
		},
		{
			name: "plain function is untouched",
			src: `def execute(cmd, cwd):
    return cmd
`,
			sym:  "execute",
			want: []string{"cmd", "cwd"},
		},
		{
			name: "function nested inside a method is not a method",
			src: `class Runner:
    def execute(self, cmd):
        def inner(text):
            return text
        return inner(cmd)
`,
			sym:  "inner",
			want: []string{"text"},
		},
		{
			name: "method that declares only a receiver takes nothing",
			src: `class Runner:
    def ping(self):
        return "pong"
`,
			sym:  "ping",
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := symbolNamed(t, language.Python, c.src, c.sym)
			if !slices.Equal(got, c.want) {
				t.Fatalf("Params = %v, want %v", got, c.want)
			}
		})
	}
}

// TestParams_OtherLanguagesKeepEveryParameter is the control: no other
// grammar here spells its receiver as an ordinary parameter, so nothing may
// be dropped for them
func TestParams_OtherLanguagesKeepEveryParameter(t *testing.T) {
	cases := []struct {
		id   language.ID
		src  string
		sym  string
		want []string
	}{
		{language.JavaScript, "class Runner { execute(self, cmd) { return cmd; } }", "execute", []string{"self", "cmd"}},
		{language.Go, "package main\n\nfunc (r *Runner) Execute(cmd string) string { return cmd }\n", "Execute", []string{"cmd"}},
		{language.Java, "class Runner { String execute(String cmd) { return cmd; } }", "execute", []string{"cmd"}},
	}
	for _, c := range cases {
		t.Run(string(c.id), func(t *testing.T) {
			adapter := language.ByID(c.id)
			f, err := ParseFile(context.Background(), adapter, "server", []byte(c.src))
			if err != nil {
				t.Fatal(err)
			}
			for _, sym := range f.Symbols {
				if sym.Name != c.sym {
					continue
				}
				if !slices.Equal(sym.Params, c.want) {
					t.Fatalf("Params = %v, want %v", sym.Params, c.want)
				}
				return
			}
			t.Fatalf("no symbol named %q", c.sym)
		})
	}
}
