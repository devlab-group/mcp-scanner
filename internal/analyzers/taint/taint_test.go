package taint

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/internal/source/language"
	"github.com/revinand/mcp-scanner/internal/testutil"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func TestMatchArgvSink_RustArgFallbackIsGatedToRust(t *testing.T) {
	for _, id := range []language.ID{language.Go, language.Python, language.JavaScript, language.TypeScript, language.Java} {
		if _, _, ok := matchArgvSink(id, "opts.args", nil); ok {
			t.Errorf("%s: want the arg/args fallback gated out of non-Rust languages, but it matched", id)
		}
	}
	if _, _, ok := matchArgvSink(language.Rust, "cmd.args", nil); !ok {
		t.Error("want the arg/args fallback to still match in Rust")
	}
}

func run(t *testing.T, dir string) model.AnalyzerResult {
	t.Helper()
	a := &Analyzer{}
	target := model.Target{Kind: model.TargetSource, Path: dir}
	ac := &analyzer.AnalysisContext{Root: dir, Artifacts: analyzer.NewArtifacts()}
	return a.Analyze(context.Background(), target, ac)
}

// requireTraced prevents an error or untraced handler from passing a negative test
func requireTraced(t *testing.T, res model.AnalyzerResult) {
	t.Helper()
	if res.Status != model.AnalyzerCompleted || res.Coverage.CapabilitiesAnalyzed == 0 {
		t.Fatalf("status = %s, coverage %+v: a clean result needs a traced handler", res.Status, res.Coverage)
	}
}

const goRegisterTmpl = `package main

func register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "run", Description: "Runs a command"}, %s)
}
`

func fmtRegister(handler string) string { return fmt.Sprintf(goRegisterTmpl, handler) }

func TestTaint_CommandInjectionVulnerable(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"handler.go": `package main

import "os/exec"

func runHandler(ctx Context, args RunArgs) (string, error) {
	cmd := exec.Command("sh", "-c", args.Command)
	out, _ := cmd.Output()
	return string(out), nil
}
`,
		"register.go": fmtRegister("runHandler"),
	})
	res := run(t, dir)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, errors: %+v", res.Status, res.Errors)
	}
	got := categoryFindings(res, "command_injection")
	if len(got) != 1 {
		t.Fatalf("want 1 command_injection finding, got %d: %+v", len(got), res.Findings)
	}
	if got[0].Confidence < 0.9 {
		t.Errorf("want high confidence for a direct flow, got %v", got[0].Confidence)
	}
	if len(got[0].Evidence) == 0 || len(got[0].Evidence[0].Path) < 2 {
		t.Fatalf("want a multi-step path, got %+v", got[0].Evidence)
	}
}

func TestTaint_CommandInjectionFixed(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		// Pass the value to a fixed program without a shell; "--" prevents option parsing
		"handler.go": `package main

import "os/exec"

func runHandler(ctx Context, args RunArgs) (string, error) {
	out, _ := exec.Command("git", "log", "--oneline", "--", args.Command).Output()
	return string(out), nil
}
`,
		"register.go": fmtRegister("runHandler"),
	})
	res := run(t, dir)
	if res.Status != model.AnalyzerCompleted || res.Coverage.CapabilitiesAnalyzed != 1 {
		t.Fatalf("status = %s, coverage %+v: a clean result needs the handler traced", res.Status, res.Coverage)
	}
	if got := categoryFindings(res, "command_injection"); len(got) != 0 {
		t.Fatalf("fixed fixture must not fire, got %+v", got)
	}
}

func TestTaint_CrossFileSink(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"handler.go": `package main

func runHandler(ctx Context, args RunArgs) (string, error) {
	return execute(args.Command)
}
`,
		"exec_helper.go": `package main

import "os/exec"

func execute(cmd string) (string, error) {
	out, _ := exec.Command("sh", "-c", cmd).Output()
	return string(out), nil
}
`,
		"register.go": fmtRegister("runHandler"),
	})
	res := run(t, dir)
	got := categoryFindings(res, "command_injection")
	if len(got) != 1 {
		t.Fatalf("want 1 cross-file command_injection finding, got %d: %+v", len(got), res.Findings)
	}
	if got[0].File != "exec_helper.go" {
		t.Errorf("want the finding at the sink's own file, got %q", got[0].File)
	}
}

func TestTaint_UnknownCallStillPropagates(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"handler.go": `package main

import "os/exec"

func runHandler(ctx Context, args RunArgs) (string, error) {
	prepared := thirdparty.Transform(args.Command)
	out, _ := exec.Command("sh", "-c", prepared).Output()
	return string(out), nil
}
`,
		"register.go": fmtRegister("runHandler"),
	})
	res := run(t, dir)
	got := categoryFindings(res, "command_injection")
	if len(got) != 1 {
		t.Fatalf("an unresolved hop must not drop the flow, got %d findings: %+v", len(got), res.Findings)
	}
	path := got[0].Evidence[0].Path
	var sawUnknown bool
	for _, step := range path {
		if step.Kind == "unknown" && !step.Resolved {
			sawUnknown = true
		}
	}
	if !sawUnknown {
		t.Errorf("want an UNKNOWN step in the path, got %+v", path)
	}
	if got[0].Confidence >= 0.9 {
		t.Errorf("an unresolved hop must reduce confidence, got %v", got[0].Confidence)
	}
}

func TestTaint_WeakSanitizerStillFlags(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"handler.go": `package main

import (
	"os/exec"
	"strings"
)

func runHandler(ctx Context, args RunArgs) (string, error) {
	cleaned := strings.Replace(args.Command, ";", "", -1)
	out, _ := exec.Command("sh", "-c", cleaned).Output()
	return string(out), nil
}
`,
		"register.go": fmtRegister("runHandler"),
	})
	res := run(t, dir)
	got := categoryFindings(res, "command_injection")
	if len(got) != 1 {
		t.Fatalf("a weak sanitizer must not clear the flow, got %d findings: %+v", len(got), res.Findings)
	}
	var sawSanitizer bool
	for _, step := range got[0].Evidence[0].Path {
		if step.Kind == "sanitizer" {
			sawSanitizer = true
		}
	}
	if !sawSanitizer {
		t.Errorf("want a sanitizer step recorded in the path, got %+v", got[0].Evidence[0].Path)
	}
	if got[0].Confidence >= 1.0 {
		t.Errorf("a weak sanitizer must reduce confidence, got %v", got[0].Confidence)
	}
}

func TestTaint_StrongSanitizerClears(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"handler.go": `package main

import "path/filepath"

func readHandler(ctx Context, args ReadArgs) (string, error) {
	safe := filepath.Base(args.Name)
	return readUnder(baseDir, safe)
}

func readUnder(base string, name string) (string, error) {
	data, _ := os.ReadFile(base + "/" + name)
	return string(data), nil
}
`,
		"register.go": `package main

func register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "read", Description: "Reads a project file"}, readHandler)
}
`,
	})
	res := run(t, dir)
	requireTraced(t, res)
	if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
		t.Fatalf("a strong sanitizer must clear the flow, got %+v", got)
	}
}

func TestTaint_PropagationAssignmentSanitizerCategoryMatters(t *testing.T) {
	src := `import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reports")


@mcp.tool()
def render(report: str) -> str:
    """Renders a report."""
    safe_path = "/reports/" + os.path.basename(report)
    return os.popen("pandoc " + safe_path).read()
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.py": src}))
	if got := categoryFindings(res, "command_injection"); len(got) != 1 {
		t.Fatalf("basename does not cover command_injection, want the flow to still reach os.popen, got %d: %+v", len(got), res.Findings)
	}
}

func TestTaint_PropagationAssignmentIntersectsDisjointSanitizers(t *testing.T) {
	src := `import os
import shlex

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reports")


@mcp.tool()
def render(report: str) -> str:
    """Renders a report."""
    combined = os.path.basename(report) + shlex.quote(report)
    return os.popen("pandoc " + combined).read()
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.py": src}))
	if got := categoryFindings(res, "command_injection"); len(got) != 1 {
		t.Fatalf("a name covered by two disjoint sanitizers at two occurrences is not safe for either category, got %d: %+v", len(got), res.Findings)
	}
}

func TestTaint_ZeroParameterHandlerIsAnalyzedNotSkipped(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"handler.js": `async function countWordsHandler() {
  return "42";
}

module.exports.register = function (server) {
  server.registerTool("count_words", { description: "Counts the words in a fixed note" }, countWordsHandler);
};
`,
	})
	res := run(t, dir)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, errors: %+v", res.Status, res.Errors)
	}
	if res.Coverage.CapabilitiesAnalyzed != 1 {
		t.Errorf("want the zero-argument handler counted as analyzed, got %+v", res.Coverage)
	}
	if res.Coverage.CapabilitiesSkipped != 0 {
		t.Errorf("want it not counted as skipped, got %+v", res.Coverage)
	}
	if gaps := res.Coverage.Gaps(); len(gaps) != 0 {
		t.Errorf("want no coverage gap for an ordinary zero-argument handler, got %v", gaps)
	}
}

func TestMaskStrongSanitizerCalls(t *testing.T) {
	cases := []struct {
		category string
		text     string
		want     string
	}{
		{"path_traversal", `"/notes/" + basename(name)`, `"/notes/" + basename(    )`},
		{"path_traversal", `"/notes/" + name + basename(other)`, `"/notes/" + name + basename(     )`},
		{"path_traversal", `path.Clean(name)`, `path.Clean(name)`}, // weak sanitizer: left alone
		{"path_traversal", `joinPath(basename(a), basename(b))`, `joinPath(basename( ), basename( ))`},
		{"path_traversal", `basename`, `basename`},                                     // not a call at all: left alone
		{"path_traversal", `filepath.Base(a + "(" + b)`, `filepath.Base(           )`}, // a paren inside a quoted string does not end the match early

		{"command_injection", `"pandoc " + basename(name)`, `"pandoc " + basename(name)`},
		{"command_injection", `os.popen("x " + shlex.quote(name))`, `os.popen("x " + shlex.quote(    ))`},
		// The mirror image: shlex.quote covers command_injection, not
		// path_traversal
		{"path_traversal", `open(shlex.quote(name))`, `open(shlex.quote(name))`},

		{"", `"/notes/" + basename(name)`, `"/notes/" + basename(    )`},
	}
	for _, c := range cases {
		if got := maskStrongSanitizerCalls(c.text, c.category); got != c.want {
			t.Errorf("maskStrongSanitizerCalls(%q, %q) = %q, want %q", c.text, c.category, got, c.want)
		}
	}
}

func TestIndexIdentFrom_SubstringBeforeWholeWord(t *testing.T) {
	text := `"/reports/" + os.path.basename(report)`
	want := strings.Index(text, "(report)") + 1 // the "report" inside the parens, not the one inside "/reports/"
	if got := indexIdentFrom(text, "report", 0); got != want {
		t.Fatalf("indexIdentFrom(%q, \"report\", 0) = %d, want %d", text, got, want)
	}
}

func TestEnclosingCoversIntersection(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []string
	}{
		{"single sanitizer", `"/reports/" + os.path.basename(report)`, []string{"path_traversal"}},

		{"overlapping catalogue entries", `os.path.basename(report)`, []string{"path_traversal"}},

		{"disjoint sanitizers at different occurrences", `os.path.basename(report) + shlex.quote(report)`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := enclosingCoversIntersection(c.text, "report")
			if len(got) != len(c.want) {
				t.Fatalf("enclosingCoversIntersection(%q, \"report\") = %v, want %v", c.text, got, c.want)
			}
			for _, w := range c.want {
				if !slices.Contains(got, w) {
					t.Errorf("enclosingCoversIntersection(%q, \"report\") = %v, want it to include %q", c.text, got, w)
				}
			}
		})
	}
}

func TestTaint_CoverageReportsUnresolvedHandler(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"register.go": `package main

func register(s *mcp.Server, dispatchName string) {
	s.AddTool(&mcp.Tool{Name: dispatchName}, dispatch)
}
`,
	})
	res := run(t, dir)
	if res.Coverage.CapabilitiesDiscovered != 1 {
		t.Fatalf("want 1 discovered capability, got %d", res.Coverage.CapabilitiesDiscovered)
	}

	gaps := res.Coverage.Gaps()
	found := false
	for _, g := range gaps {
		if strings.Contains(g, "discovered but not analyzed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want the untraced handler reported as an unanalyzed capability, got gaps %v from %+v", gaps, res.Coverage)
	}
	if len(res.Coverage.SkipReasons) == 0 {
		t.Errorf("an untraced capability must still carry a reason explaining the gap")
	}
}

func TestTaint_ReceiverCarriesTaint(t *testing.T) {
	t.Run("go", func(t *testing.T) {
		dir := testutil.WriteTree(t, map[string]string{
			"handler.go": `package main

import "os/exec"

func RunHandler(ctx Context, req Request) (string, error) {
	target := req.GetString("target", "")
	out, _ := exec.Command("sh", "-c", "make "+target).CombinedOutput()
	return string(out), nil
}
`,
			"register.go": `package main

func register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "run", Description: "Runs a make target"}, RunHandler)
}
`,
		})
		res := run(t, dir)
		if got := categoryFindings(res, "command_injection"); len(got) != 1 {
			t.Fatalf("want 1 command_injection finding via the tainted receiver, got %d: %+v", len(got), res.Findings)
		}
	})

	t.Run("python", func(t *testing.T) {
		dir := testutil.WriteTree(t, map[string]string{
			"handler.py": `import subprocess


def run_handler(args):
    target = args.get("target")
    return subprocess.check_output("make " + target, shell=True)


def register(mcp):
    mcp.add_tool(run_handler, name="run", description="Runs a make target")
`,
		})
		res := run(t, dir)
		if got := categoryFindings(res, "command_injection"); len(got) != 1 {
			t.Fatalf("want 1 command_injection finding via the tainted receiver, got %d: %+v", len(got), res.Findings)
		}
	})
}

func TestTaint_ReceiverConstructorCarriesTaint(t *testing.T) {
	for name, sink := range map[string]string{
		"bare_constructor": `Path("/srv/data", name).read_text()`,
		"joinpath_on_base": `ROOT.joinpath(name).read_text()`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := testutil.WriteTree(t, map[string]string{
				"server.py": `from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("docs")
ROOT = Path("/srv/data")


@mcp.tool()
def read_doc(name: str) -> str:
    """Read a document."""
    return ` + sink + `
`,
			})
			res := run(t, dir)
			if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
				t.Fatalf("want 1 path_traversal finding via the call-shaped receiver, got %d: %+v", len(got), res.Findings)
			}
		})
	}

	t.Run("sanitized_inline", func(t *testing.T) {
		dir := testutil.WriteTree(t, map[string]string{
			"server.py": `from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("docs")
ROOT = Path("/srv/data")


@mcp.tool()
def read_doc(name: str) -> str:
    """Read a document."""
    return (ROOT / Path(name).name).read_text()
`,
		})
		res := run(t, dir)
		if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
			t.Fatalf("want no path_traversal finding - Path(name).name already strips the traversal, got %+v", got)
		}
	})
}

func TestTaint_ChainedCallReceiverIsNotScannedForTaint(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"handler.go": `package main

func ArchiveHandler(ctx Context, args ArchiveArgs) (string, error) {
	return runArchive(args.Name)
}
`,
		"shell.go": `package main

import "os/exec"

func runArchive(name string) (string, error) {
	out, err := exec.Command("tar", "czf", "/tmp/out.tgz", "--", name).CombinedOutput()
	return string(out), err
}
`,
		"register.go": `package main

func register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "archive", Description: "Archive a project directory"}, ArchiveHandler)
}
`,
	})
	res := run(t, dir)
	requireTraced(t, res)
	if got := categoryFindings(res, "command_injection"); len(got) != 0 {
		t.Fatalf("want no command_injection finding, got %+v", got)
	}
	if got := categoryFindings(res, "argument_injection"); len(got) != 0 {
		t.Fatalf("want no argument_injection finding - the tainted name sits after a literal \"--\", and \"out\" appearing inside the unrelated literal \"/tmp/out.tgz\" must not be read as taint reaching it, got %+v", got)
	}
}

func TestTaint_PathlibMethodSinksOnTaintedReceiver(t *testing.T) {
	ops := []string{"read_text", "read_bytes", "write_text", "write_bytes", "open", "unlink", "rmdir", "touch", "mkdir"}
	for _, op := range ops {
		t.Run(op, func(t *testing.T) {
			call := op + "()"
			if op == "write_text" || op == "write_bytes" {
				call = op + "(b\"x\")"
			}
			src := `from pathlib import Path

DOCS = Path("/srv/docs")


def read_doc(name: str) -> str:
    target = DOCS / name
    return target.` + call + `


def register(mcp):
    mcp.add_tool(read_doc, name="read_doc", description="Reads a document from the docs directory")
`
			res := run(t, mustWriteDir(t, map[string]string{"handler.py": src}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
				t.Fatalf("%s: want 1 path_traversal finding via the tainted receiver, got %d: %+v", op, len(got), res.Findings)
			}
		})
	}
}

func TestTaint_PathlibNamePropertySanitizes(t *testing.T) {
	for _, ctor := range []string{"Path", "PurePath"} {
		for _, prop := range []string{"name", "stem"} {
			t.Run(ctor+"."+prop, func(t *testing.T) {
				src := `from pathlib import Path, PurePath

DOCS = Path("/srv/docs")


def read_doc(name: str) -> str:
    target = DOCS / ` + ctor + `(name).` + prop + `
    return target.read_text()


def register(mcp):
    mcp.add_tool(read_doc, name="read_doc", description="Reads a document from the docs directory")
`
				res := run(t, mustWriteDir(t, map[string]string{"handler.py": src}))
				requireTraced(t, res)
				if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
					t.Fatalf("%s(name).%s must clear the flow, got %+v", ctor, prop, got)
				}
			})
		}
	}
}

func TestTaint_ModuleLevelPathSinks(t *testing.T) {
	pyOps := []string{
		`shutil.copy(target, "/tmp/out")`,
		`shutil.move(target, "/tmp/out")`,
		`shutil.rmtree(target)`,
		`os.remove(target)`,
		`os.rename(target, "/tmp/out")`,
		`os.listdir(target)`,
		`list(os.walk(target))`,
		`glob.glob(target)`,
	}
	for _, call := range pyOps {
		t.Run(call, func(t *testing.T) {
			src := `import os
import shutil
import glob


def read_doc(name: str) -> str:
    target = "/srv/docs/" + name
    return str(` + call + `)


def register(mcp):
    mcp.add_tool(read_doc, name="read_doc", description="Reads a document from the docs directory")
`
			res := run(t, mustWriteDir(t, map[string]string{"handler.py": src}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
				t.Fatalf("want 1 path_traversal finding, got %d: %+v", len(got), res.Findings)
			}
		})
	}

	goOps := []string{"os.Remove(target)", "os.RemoveAll(target)", "os.Create(target)", "os.MkdirAll(target, 0o755)"}
	for _, call := range goOps {
		t.Run(call, func(t *testing.T) {
			src := `package main

import "os"

func ReadHandler(ctx Context, args ReadArgs) (string, error) {
	target := "/srv/docs/" + args.Name
	return "", ` + call + `
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "read", Description: "Reads a document from the docs directory"}, ReadHandler)
}
`
			res := run(t, mustWriteDir(t, map[string]string{"main.go": src}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
				t.Fatalf("want 1 path_traversal finding, got %d: %+v", len(got), res.Findings)
			}
		})
	}
}

func TestTaint_StringReplaceIsNotAPathSink(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"handler.py": `import subprocess


def run_handler(command: str) -> str:
    cleaned = command.replace(";", "")
    return subprocess.check_output("sh -c " + cleaned, shell=True)


def register(mcp):
    mcp.add_tool(run_handler, name="run", description="Runs a shell command")
`,
	})
	res := run(t, dir)
	if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
		t.Fatalf("a .replace() call must never be read as a path sink, got %+v", got)
	}
	if got := categoryFindings(res, "command_injection"); len(got) != 1 {
		t.Fatalf("want the weak sanitizer to still let the command_injection flow through at reduced confidence, got %d: %+v", len(got), res.Findings)
	}
}

// helperChain builds a Python tool handler that reaches os.popen through nested helpers
func helperChain(hops int) string {
	var b strings.Builder
	b.WriteString("import os\n\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP(\"ops\")\n\n")
	for i := range hops {
		next := fmt.Sprintf("step%d(c)", i+1)
		if i == hops-1 {
			next = "os.popen(c).read()"
		}
		fmt.Fprintf(&b, "def step%d(c):\n    return %s\n\n", i, next)
	}
	b.WriteString("@mcp.tool()\ndef run(name: str) -> str:\n    \"\"\"Run a named job.\"\"\"\n    return step0(\"make \" + name)\n")
	return b.String()
}

// A flow deeper than the recursion limit must leave a coverage gap
func TestTaint_RecursionDepthLimitIsAGap(t *testing.T) {
	const limitMsg = "nested helper calls"
	hasLimit := func(res model.AnalyzerResult) bool {
		for _, l := range res.Coverage.LimitsHit {
			if strings.Contains(l, limitMsg) {
				return true
			}
		}
		return false
	}

	shallow := run(t, testutil.WriteTree(t, map[string]string{"server.py": helperChain(3)}))
	if got := categoryFindings(shallow, "command_injection"); len(got) != 1 {
		t.Fatalf("want the 3-hop flow found, got %d: %+v", len(got), shallow.Findings)
	}
	if hasLimit(shallow) {
		t.Errorf("a 3-hop flow recorded the depth limit: %v", shallow.Coverage.LimitsHit)
	}

	deep := run(t, testutil.WriteTree(t, map[string]string{"server.py": helperChain(maxDepth + 1)}))
	if deep.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s, errors: %+v", deep.Status, deep.Errors)
	}
	if len(categoryFindings(deep, "command_injection")) == 0 && !hasLimit(deep) {
		t.Fatalf("a flow past the depth limit was dropped without a limit: %+v", deep.Coverage)
	}
	if hasLimit(deep) && len(deep.Coverage.Gaps()) == 0 {
		t.Errorf("the depth limit did not produce a coverage gap: %+v", deep.Coverage)
	}
}

// Each handler uses its own tool arguments as sources, even when another handler calls it
func TestTaint_HandlerCalledByAnotherHandlerIsSeeded(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{"server.py": `import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
def run_a(name: str) -> str:
    """Run a fixed job for a name."""
    return run_b(name, "true")


@mcp.tool()
def run_b(label: str, cmd: str) -> str:
    """Run a command with a label."""
    print(label)
    return os.popen(cmd).read()
`})
	// Go randomizes map order per range, so a few runs cover both orders
	for range 10 {
		res := run(t, dir)
		if got := categoryFindings(res, "command_injection"); len(got) != 1 {
			t.Fatalf("want run_b's cmd reaching os.popen found, got %d: %+v, skips: %v",
				len(got), res.Findings, res.Coverage.SkipReasons)
		}
		if res.Coverage.CapabilitiesAnalyzed != 2 {
			t.Fatalf("want both handlers analyzed, got %+v", res.Coverage)
		}
	}
}

// Treat new Function as an eval sink without flagging unrelated constructors
func TestTaint_NewFunctionIsAnEvalSink(t *testing.T) {
	const tmpl = `function runHandler(ctx, args) {
  %s
}

module.exports.register = function (server) {
  server.registerTool("calc", { description: "Evaluates an expression" }, runHandler);
};
`
	cases := []struct {
		name, body string
		want       int
	}{
		{"new Function", `return new Function("return " + args.expr)();`, 1},
		{"new URL", `return new URL(args.expr, "https://example.com/").pathname;`, 0},
		{"new Error", `throw new Error("bad expression: " + args.expr);`, 0},
		{"new RegExp", `return new RegExp(args.expr).test("abc");`, 0},
	}
	for _, c := range cases {
		for _, file := range []string{"handler.js", "handler.ts"} {
			t.Run(c.name+"/"+file, func(t *testing.T) {
				res := run(t, testutil.WriteTree(t, map[string]string{file: fmt.Sprintf(tmpl, c.body)}))
				if res.Status != model.AnalyzerCompleted || res.Coverage.CapabilitiesAnalyzed != 1 {
					t.Fatalf("status = %s, coverage %+v", res.Status, res.Coverage)
				}
				if got := len(res.Findings); got != c.want {
					t.Fatalf("want %d finding(s), got %d: %+v", c.want, got, res.Findings)
				}
				if c.want == 1 && res.Findings[0].Category != "eval" {
					t.Errorf("category = %s, want eval", res.Findings[0].Category)
				}
			})
		}
	}
}

// Resolve common Rust import forms to the same std::fs sink
func TestTaint_RustUseForms(t *testing.T) {
	cases := []struct {
		name, use, body, category string
	}{
		{"qualified call", "", "std::fs::read_to_string(&name).unwrap_or_default()", "path_traversal"},
		{"module import", "use std::fs;\n", "fs::read_to_string(&name).unwrap_or_default()", "path_traversal"},
		{"function import", "use std::fs::read_to_string;\n", "read_to_string(&name).unwrap_or_default()", "path_traversal"},
		{"grouped import", "use std::{fs, path::Path};\n", "fs::read_to_string(&name).unwrap_or_default()", "path_traversal"},
		{"grouped self import", "use std::fs::{self, File};\n", "fs::read_to_string(&name).unwrap_or_default()", "path_traversal"},
		{"renamed module import", "use std::fs as files;\n", "files::read_to_string(&name).unwrap_or_default()", "path_traversal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.use + "\n#[tool(name = \"read_note\", description = \"Reads a note\")]\nfn read_note(name: String) -> String {\n    " + tc.body + "\n}\n"
			res := run(t, testutil.WriteTree(t, map[string]string{"tool.rs": src}))
			if got := categoryFindings(res, tc.category); len(got) != 1 {
				t.Fatalf("want 1 %s finding, got %d: %+v (gaps %v)", tc.category, len(got), res.Findings, res.Coverage.Gaps())
			}
		})
	}
}

// Guards that do not protect the path being read must leave the flow reported
func TestTaint_ContainmentGuardEdgesStillReport(t *testing.T) {
	const pyHead = "from pathlib import Path\n\nROOT = Path(\"/srv/notes\")\n\n\n"
	const pyTail = "\n\ndef register(mcp):\n    mcp.add_tool(read_note, name=\"read\", description=\"Reads a note\")\n"
	const goHead = `package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var notesRoot = "/srv/notes"

func readNoteHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := req.GetString("name", "")
	full := filepath.Join(notesRoot, name)
`
	const goTail = `	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, errors.New("name escapes the notes directory")
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(data)), nil
}

func main() {
	s := server.NewMCPServer("notes", "1.0.0")
	s.AddTool(mcp.NewTool("read_note", mcp.WithDescription("Read a note."), mcp.WithString("name", mcp.Required())), readNoteHandler)
}
`
	cases := []struct{ name, file, src string }{
		{"guard branch only logs", "server.py", pyHead + `def read_note(name: str) -> str:
    full = (ROOT / name).resolve()
    if not full.is_relative_to(ROOT):
        print("outside root")
    return full.read_text()
` + pyTail},
		{"guard checks a different path", "server.py", pyHead + `def read_note(name: str, other: str) -> str:
    a = (ROOT / other).resolve()
    full = (ROOT / name).resolve()
    if not a.is_relative_to(ROOT):
        raise ValueError("outside root")
    return full.read_text()
` + pyTail},
		{"else branch re-taints the path", "server.py", pyHead + `def read_note(name: str, suffix: str) -> str:
    full = (ROOT / name).resolve()
    if not full.is_relative_to(ROOT):
        raise ValueError("outside root")
    else:
        full = Path(str(full) + suffix)
    return full.read_text()
` + pyTail},
		{"guard exits when the path is inside", "server.py", pyHead + `def read_note(name: str) -> str:
    full = (ROOT / name).resolve()
    if full.is_relative_to(ROOT):
        raise ValueError("inside root")
    return full.read_text()
` + pyTail},
		{"checked Rel is not the one computed for the path", "server.go", goHead + `	rel, err := filepath.Rel(notesRoot, filepath.Join(notesRoot, "index"))
	checked, _ := filepath.Rel(notesRoot, full)
` + goTail},
		{"a helper posing as Rel", "server.go", goHead + `	rel, err := relativeTo(notesRoot, full)
` + goTail + `
// relativeTo only trims the prefix, so a path outside root comes back unchanged and never
// starts with ".."
func relativeTo(root, p string) (string, error) {
	return strings.TrimPrefix(p, root), nil
}
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := run(t, testutil.WriteTree(t, map[string]string{tc.file: tc.src}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
				t.Fatalf("want 1 path_traversal finding, got %d: %+v (gaps %v)", len(got), res.Findings, res.Coverage.Gaps())
			}
		})
	}
}

// If name-based resolution cannot choose between same-named functions, record the untraced call
// as a coverage limit
func TestTaint_AmbiguousCallIsALimit(t *testing.T) {
	res := run(t, testutil.WriteTree(t, map[string]string{
		"shell/run.go": "package shell\n\nimport \"os/exec\"\n\nfunc Run(cmd string) ([]byte, error) {\n\treturn exec.Command(\"sh\", \"-c\", cmd).Output()\n}\n",
		"git/run.go":   "package git\n\nfunc Run(cmd string) ([]byte, error) {\n\treturn nil, nil\n}\n",
		"main.go": `package main

func buildHandler(ctx Context, args BuildArgs) (string, error) {
	out, err := shell.Run("make " + args.Target)
	return string(out), err
}

func register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "build", Description: "Builds a target"}, buildHandler)
}
`,
	}))
	if len(categoryFindings(res, "command_injection")) > 0 {
		return // resolved through the qualifier: the flow was followed after all
	}
	found := false
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, "more than one definition") {
			found = true
		}
	}
	if !found {
		t.Fatalf("an unfollowed ambiguous call left no limit: %+v", res.Coverage)
	}
}

// A run cut off part way did not trace every handler, so it cannot report COMPLETED
func TestTaint_CutOffPartWayIsPartial(t *testing.T) {
	dir := "../../../testdata/source/discovery/go"
	res := (&Analyzer{}).Analyze(&testutil.CancelAfter{Context: context.Background(), Limit: 10},
		model.Target{Kind: model.TargetSource, Path: dir}, &analyzer.AnalysisContext{Root: dir, Artifacts: analyzer.NewArtifacts()})
	if res.Status != model.AnalyzerPartial {
		t.Fatalf("status = %s, want PARTIAL (errors %v)", res.Status, res.Errors)
	}
}

// Record combinations beyond the per-symbol taint seed limit as a coverage gap
func TestTaint_SeedLimitIsALimit(t *testing.T) {
	src := `import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


def helper(a, b, c, d):
    return os.popen(a + b + c + d).read()


@mcp.tool()
def run(x: str) -> str:
    """Runs helpers."""
    helper(x, "", "", "")
    helper("", x, "", "")
    helper("", "", x, "")
    helper("", "", "", x)
    helper(x, x, "", "")
    helper(x, "", x, "")
    helper(x, "", "", x)
    helper("", x, x, "")
    helper("", x, "", x)
    return ""
`
	res := run(t, testutil.WriteTree(t, map[string]string{"server.py": src}))
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, "per-symbol seed limit") {
			return
		}
	}
	t.Fatalf("a helper past the seed limit left no limit: %+v", res.Coverage)
}
