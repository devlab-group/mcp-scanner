package taint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func analyze(t *testing.T, dir string) model.AnalyzerResult {
	t.Helper()
	a := &Analyzer{}
	target := model.Target{Kind: model.TargetSource, Path: dir}
	ac := &analyzer.AnalysisContext{Root: dir, Artifacts: analyzer.NewArtifacts()}
	res := a.Analyze(context.Background(), target, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("%s: status = %s, errors: %+v", dir, res.Status, res.Errors)
	}
	return res
}

func categoryFindings(res model.AnalyzerResult, category string) []model.Finding {
	var out []model.Finding
	for _, f := range res.Findings {
		if f.Category == category {
			out = append(out, f)
		}
	}
	return out
}

func TestFixtures_VulnerableAndFixedPairs(t *testing.T) {
	categories := []string{"command_injection", "path_traversal", "ssrf", "sql_injection", "eval"}
	languages := []string{"go", "python"}

	for _, lang := range languages {
		for _, cat := range categories {
			base := "../../../testdata/source/taint/" + lang + "/" + cat
			t.Run(lang+"/"+cat+"/vulnerable", func(t *testing.T) {
				res := analyze(t, base+"/vulnerable")
				if got := categoryFindings(res, cat); len(got) == 0 {
					t.Fatalf("vulnerable fixture must produce a %s finding, got none among %+v", cat, res.Findings)
				}
			})
			t.Run(lang+"/"+cat+"/fixed", func(t *testing.T) {
				res := analyze(t, base+"/fixed")
				if got := categoryFindings(res, cat); len(got) != 0 {
					t.Fatalf("fixed fixture must not produce a %s finding, got %+v", cat, got)
				}
			})
		}
	}
}

func TestFixtures_ArgvVsShell(t *testing.T) {
	for _, lang := range []string{"go", "python"} {
		base := "../../../testdata/source/taint/" + lang + "/command_injection/argv_vs_shell"

		t.Run(lang+"/safe", func(t *testing.T) {
			res := analyze(t, base+"/safe")
			if got := categoryFindings(res, "command_injection"); len(got) != 0 {
				t.Fatalf("a safe argv call must not be command injection, got %+v", got)
			}
			if got := categoryFindings(res, "argument_injection"); len(got) != 0 {
				t.Fatalf("a tainted value placed after a literal -- cannot be read as a flag either; want no argument_injection finding, got %+v", got)
			}
		})
		t.Run(lang+"/shell", func(t *testing.T) {
			res := analyze(t, base+"/shell")
			got := categoryFindings(res, "command_injection")
			if len(got) != 1 {
				t.Fatalf("the shell-based version must still fire as command injection, got %d: %+v", len(got), res.Findings)
			}
			if got[0].Severity != model.SeverityHigh {
				t.Errorf("want HIGH severity, got %s", got[0].Severity)
			}
		})
	}
}

func TestFixtures_ArgumentInjectionWithoutTerminator(t *testing.T) {
	for _, lang := range []string{"go", "python"} {
		base := "../../../testdata/source/taint/" + lang + "/command_injection/argv_vs_shell/argument_injection"
		t.Run(lang, func(t *testing.T) {
			res := analyze(t, base)
			if got := categoryFindings(res, "command_injection"); len(got) != 0 {
				t.Fatalf("a safe argv call must not be command injection, got %+v", got)
			}
			got := categoryFindings(res, "argument_injection")
			if len(got) != 1 {
				t.Fatalf("want the argument_injection finding, got %d: %+v", len(got), res.Findings)
			}
			if got[0].Severity != model.SeverityMedium {
				t.Errorf("want MEDIUM severity, got %s", got[0].Severity)
			}
		})
	}
}

func TestFixtures_OversizedFileStillFindsTheVulnerability(t *testing.T) {
	base, err := os.ReadFile("../../../testdata/source/taint/go/command_injection/vulnerable/main.go")
	if err != nil {
		t.Fatal(err)
	}
	padding := strings.Repeat("x", 5<<20) // 5 MiB, over the 512 KiB default file size limit
	padded := string(base) + "\n\n// " + padding + "\n"

	res := analyze(t, mustWriteDir(t, map[string]string{"main.go": padded}))
	got := categoryFindings(res, "command_injection")
	if len(got) != 1 {
		t.Fatalf("want the vulnerable handler still found despite the padding, got %d command_injection findings: %+v", len(got), res.Findings)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("want the size limit recorded in Coverage.LimitsHit, downgrading the scan rather than reporting full coverage")
	}
}

func TestFixtures_OversizedFileTaintRecordsItsOwnLimitsHit(t *testing.T) {
	base, err := os.ReadFile("../../../testdata/source/taint/go/command_injection/vulnerable/main.go")
	if err != nil {
		t.Fatal(err)
	}
	padding := strings.Repeat("x", 5<<20) // 5 MiB, over the 512 KiB default file size limit
	padded := string(base) + "\n\n// " + padding + "\n"

	res := analyze(t, mustWriteDir(t, map[string]string{"main.go": padded}))
	found := false
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, "reached by the taint walk") && strings.Contains(l, "byte size limit") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want taint's own size-cap entry in Coverage.LimitsHit, got %v", res.Coverage.LimitsHit)
	}
}

func mustWriteDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestFixtures_DestructuredHandlerParameter(t *testing.T) {
	for _, dir := range []string{
		"../../../testdata/source/taint/typescript/command_injection/destructured_arrow",
		"../../../testdata/source/taint/typescript/command_injection/destructured_function",
		"../../../testdata/source/taint/javascript/command_injection/destructured_arrow",
		"../../../testdata/source/taint/javascript/command_injection/destructured_function",
		"../../../testdata/source/taint/python/command_injection/decorator",
	} {
		t.Run(dir, func(t *testing.T) {
			res := analyze(t, dir)
			got := categoryFindings(res, "command_injection")
			if len(got) != 1 {
				t.Fatalf("want the destructured-parameter handler still found, got %d command_injection findings: %+v", len(got), res.Findings)
			}
			if got[0].Severity != model.SeverityHigh {
				t.Errorf("want HIGH severity, got %s", got[0].Severity)
			}
			if res.Coverage.CapabilitiesAnalyzed != 1 || res.Coverage.CapabilitiesSkipped != 0 {
				t.Fatalf("want the capability counted as analyzed, not skipped, got %+v", res.Coverage)
			}
		})
	}
}

func TestFixtures_ScanEvasionDoesNotHideTheFinding(t *testing.T) {
	for _, dir := range []string{
		"../../../testdata/source/inventory/evasion/dist_only",
		"../../../testdata/source/inventory/evasion/dot_directory",
		"../../../testdata/source/inventory/evasion/generated_header",
		"../../../testdata/source/inventory/evasion/generated_suffix",
	} {
		t.Run(dir, func(t *testing.T) {
			res := analyze(t, dir)
			got := categoryFindings(res, "command_injection")
			if len(got) != 1 {
				t.Fatalf("want the vulnerable handler still found despite the evasion attempt, got %d command_injection findings: %+v", len(got), res.Findings)
			}
			if got[0].Severity != model.SeverityHigh {
				t.Errorf("want HIGH severity, got %s", got[0].Severity)
			}
		})
	}
}

// TestFixtures_UnknownCall is the mandatory case: a taint path that
// crosses an unresolved function must not disappear
func TestFixtures_UnknownCall(t *testing.T) {
	res := analyze(t, "../../../testdata/source/taint/unknown_call")
	got := categoryFindings(res, "command_injection")
	if len(got) != 1 {
		t.Fatalf("want exactly 1 command_injection finding, got %d: %+v", len(got), res.Findings)
	}
	f := got[0]
	if len(f.Evidence) == 0 {
		t.Fatalf("want evidence with a path, got none")
	}
	var sawUnknown bool
	for _, step := range f.Evidence[0].Path {
		if step.Kind == "unknown" && !step.Resolved {
			sawUnknown = true
		}
	}
	if !sawUnknown {
		t.Errorf("want an UNKNOWN step in the path, got %+v", f.Evidence[0].Path)
	}
	if f.Confidence >= 0.9 {
		t.Errorf("an unresolved hop must reduce confidence below the direct-flow baseline, got %v", f.Confidence)
	}
}

func TestFixtures_FsPromisesMethodSinks(t *testing.T) {
	ops := []string{"readFile", "writeFile", "appendFile", "unlink", "rm", "rename", "copyFile", "createReadStream"}
	for _, op := range ops {
		t.Run(op, func(t *testing.T) {
			vulnerable := "const fs = require(\"fs/promises\");\n\n" +
				"async function readHandler(ctx, args) {\n" +
				"  return fs.promises." + op + "(\"/srv/project/\" + args.name);\n" +
				"}\n\n" +
				"module.exports.register = function (server) {\n" +
				"  server.registerTool(\"read\", { description: \"Reads a file from the project directory\" }, readHandler);\n" +
				"};\n"
			res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": vulnerable}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
				t.Fatalf("%s: want 1 path_traversal finding, got %d: %+v", op, len(got), res.Findings)
			}

			fixed := "const fs = require(\"fs/promises\");\n" +
				"const path = require(\"path\");\n\n" +
				"async function readHandler(ctx, args) {\n" +
				"  const safe = path.basename(args.name);\n" +
				"  return fs.promises." + op + "(\"/srv/project/\" + safe);\n" +
				"}\n\n" +
				"module.exports.register = function (server) {\n" +
				"  server.registerTool(\"read\", { description: \"Reads a file from the project directory\" }, readHandler);\n" +
				"};\n"
			res = analyze(t, mustWriteDir(t, map[string]string{"handler.js": fixed}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
				t.Fatalf("%s: a path.basename'd argument must not fire, got %+v", op, got)
			}
		})
	}
}

func TestFixtures_DestructuredBasenameImportSanitizes(t *testing.T) {
	vulnerable := `import { readFileSync } from "fs";

async function readHandler(ctx, args) {
  return readFileSync("/notes/" + args.name, "utf8");
}

module.exports.register = function (server) {
  server.registerTool("read", { description: "Reads a note by name" }, readHandler);
};
`
	res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": vulnerable}))
	if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
		t.Fatalf("want 1 path_traversal finding, got %d: %+v", len(got), res.Findings)
	}

	fixed := `import { readFileSync } from "fs";
import { basename } from "node:path";

async function readHandler(ctx, args) {
  const safe = basename(args.name);
  return readFileSync("/notes/" + safe, "utf8");
}

module.exports.register = function (server) {
  server.registerTool("read", { description: "Reads a note by name" }, readHandler);
};
`
	res = analyze(t, mustWriteDir(t, map[string]string{"handler.js": fixed}))
	if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
		t.Fatalf("a destructured-import basename() must clear the flow, got %+v", got)
	}
}

func TestFixtures_InlineSanitizerInsideSinkArgument(t *testing.T) {
	vulnerable := `import { readFileSync } from "fs";

async function readHandler(ctx, args) {
  return readFileSync("/notes/" + args.name, "utf8");
}

module.exports.register = function (server) {
  server.registerTool("read", { description: "Reads a note by name" }, readHandler);
};
`
	res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": vulnerable}))
	if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
		t.Fatalf("want 1 path_traversal finding, got %d: %+v", len(got), res.Findings)
	}

	fixed := `import { readFileSync } from "fs";
import { basename } from "node:path";

async function readHandler(ctx, args) {
  return readFileSync("/notes/" + basename(args.name), "utf8");
}

module.exports.register = function (server) {
  server.registerTool("read", { description: "Reads a note by name" }, readHandler);
};
`
	res = analyze(t, mustWriteDir(t, map[string]string{"handler.js": fixed}))
	if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
		t.Fatalf("basename() applied inline, right inside the sink's own argument, must clear the flow, got %+v", got)
	}
}

func TestFixtures_SQLReceiverIsNotPartOfTheSink(t *testing.T) {
	t.Run("go/conn.QueryContext", func(t *testing.T) {
		vulnerable := `package main

func LookupHandler(ctx Context, args LookupArgs) (string, error) {
	rows, err := conn.QueryContext(ctx, "SELECT * FROM users WHERE id = "+args.ID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "lookup", Description: "Looks up a user by id"}, LookupHandler)
}
`
		res := analyze(t, mustWriteDir(t, map[string]string{"main.go": vulnerable}))
		if got := categoryFindings(res, "sql_injection"); len(got) != 1 {
			t.Fatalf("want 1 sql_injection finding for conn.QueryContext, got %d: %+v", len(got), res.Findings)
		}

		fixed := `package main

func LookupHandler(ctx Context, args LookupArgs) (string, error) {
	rows, err := conn.QueryContext(ctx, "SELECT * FROM users WHERE id = ?", args.ID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "lookup", Description: "Looks up a user by id"}, LookupHandler)
}
`
		res = analyze(t, mustWriteDir(t, map[string]string{"main.go": fixed}))
		if got := categoryFindings(res, "sql_injection"); len(got) != 0 {
			t.Fatalf("a parameterized conn.QueryContext call must not fire, got %+v", got)
		}
	})

	t.Run("python/cur.execute", func(t *testing.T) {
		vulnerable := `def lookup_handler(user_id: str) -> str:
    cur.execute("SELECT * FROM users WHERE id = " + user_id)
    return cur.fetchone()


def register(mcp):
    mcp.add_tool(lookup_handler, name="lookup", description="Looks up a user by id")
`
		res := analyze(t, mustWriteDir(t, map[string]string{"handler.py": vulnerable}))
		if got := categoryFindings(res, "sql_injection"); len(got) != 1 {
			t.Fatalf("want 1 sql_injection finding for cur.execute, got %d: %+v", len(got), res.Findings)
		}

		fixed := `def lookup_handler(user_id: str) -> str:
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cur.fetchone()


def register(mcp):
    mcp.add_tool(lookup_handler, name="lookup", description="Looks up a user by id")
`
		res = analyze(t, mustWriteDir(t, map[string]string{"handler.py": fixed}))
		if got := categoryFindings(res, "sql_injection"); len(got) != 0 {
			t.Fatalf("a parameterized cur.execute call must not fire, got %+v", got)
		}
	})
}

func TestFixtures_LowLevelSDKRequestHandler(t *testing.T) {
	src := `server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      { name: "search_logs", description: "Searches project logs for a pattern" },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const pattern = request.params.arguments.pattern;
  exec("grep -r " + pattern + " /var/log");
});
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	if got := categoryFindings(res, "command_injection"); len(got) != 1 {
		t.Fatalf("want 1 command_injection finding via the low-level SDK's dispatch handler, got %d: %+v", len(got), res.Findings)
	}
}

func TestFixtures_LowLevelSDKRequestHandler_ConciseArrowBody(t *testing.T) {
	src := `server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    { name: "search_logs", description: "Searches project logs for a pattern" },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) =>
  exec("grep -r " + request.params.arguments.pattern + " /var/log")
);
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	if got := categoryFindings(res, "command_injection"); len(got) != 1 {
		t.Fatalf("want 1 command_injection finding via the low-level SDK's concise-body dispatch handler, got %d: %+v", len(got), res.Findings)
	}
}

// TestFixtures_Sanitizer checks the two dedicated sanitizer fixtures: a
// real but insufficient sanitizer must not clear the flow, and a genuinely
// sufficient one must
func TestFixtures_Sanitizer(t *testing.T) {
	weak := analyze(t, "../../../testdata/source/taint/sanitizer/weak")
	got := categoryFindings(weak, "path_traversal")
	if len(got) != 1 {
		t.Fatalf("a weak sanitizer must not clear the flow, got %d findings: %+v", len(got), weak.Findings)
	}
	var sawSanitizer bool
	for _, step := range got[0].Evidence[0].Path {
		if step.Kind == "sanitizer" {
			sawSanitizer = true
		}
	}
	if !sawSanitizer {
		t.Errorf("want a sanitizer step recorded, got %+v", got[0].Evidence[0].Path)
	}
	if got[0].Confidence >= 1.0 {
		t.Errorf("a weak sanitizer must reduce confidence, got %v", got[0].Confidence)
	}

	strong := analyze(t, "../../../testdata/source/taint/sanitizer/strong")
	if got := categoryFindings(strong, "path_traversal"); len(got) != 0 {
		t.Fatalf("a genuinely sufficient sanitizer must clear the flow, got %+v", got)
	}
}
