package taint

import (
	"context"
	"fmt"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/internal/testutil"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func TestTaint_MissingWalkCoverageDowngrades(t *testing.T) {
	dir := "../../../testdata/source/taint/go/command_injection/vulnerable"
	g, _, err := source.Build(context.Background(), dir)
	if err != nil {
		t.Fatalf("source.Build: %v", err)
	}

	ac := &analyzer.AnalysisContext{Root: dir, Artifacts: analyzer.NewArtifacts()}
	ac.Artifacts.Set(source.ArtifactKey, g)
	// Deliberately no source.WalkCoverageKey set - the case a caller that
	// forgets to publish it, or predates it, produces

	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource, Path: dir}, ac)
	if res.Status != model.AnalyzerPartial {
		t.Fatalf("want PARTIAL when the published graph carries no walk coverage, got %s (warnings: %v)", res.Status, res.Warnings)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("want an explicit warning explaining the missing walk coverage")
	}
}

func TestTaint_PublishedWalkCoverageFoldsIn(t *testing.T) {
	dir := "../../../testdata/source/taint/go/command_injection/vulnerable"
	g, walkCov, err := source.Build(context.Background(), dir)
	if err != nil {
		t.Fatalf("source.Build: %v", err)
	}
	const limitReason = "directory \"node_modules\" was excluded from the scan and not read"
	walkCov.LimitsHit = append(walkCov.LimitsHit, limitReason)

	ac := &analyzer.AnalysisContext{Root: dir, Artifacts: analyzer.NewArtifacts()}
	ac.Artifacts.Set(source.ArtifactKey, g)
	ac.Artifacts.Set(source.WalkCoverageKey, walkCov)

	a := &Analyzer{}
	res := a.Analyze(context.Background(), model.Target{Kind: model.TargetSource, Path: dir}, ac)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("want COMPLETED (the gap is reported via LimitsHit, not the analyzer status), got %s", res.Status)
	}
	found := false
	for _, l := range res.Coverage.LimitsHit {
		if l == limitReason {
			found = true
		}
	}
	if !found {
		t.Fatalf("want the published walk coverage's LimitsHit folded into taint's own Coverage, got %+v", res.Coverage.LimitsHit)
	}
}

func TestFixtures_SharedHelperMultiArgSeeding(t *testing.T) {
	res := analyze(t, "../../../testdata/source/taint/go/command_injection/shared_helper_multi_arg")
	got := categoryFindings(res, "command_injection")
	if len(got) != 1 {
		t.Fatalf("want 1 command_injection finding via the second tainted argument, got %d: %+v", len(got), res.Findings)
	}
	if got[0].Severity != model.SeverityHigh {
		t.Errorf("want HIGH severity, got %s", got[0].Severity)
	}
}

func TestFixtures_CompactMultiNameGoParams(t *testing.T) {
	res := analyze(t, "../../../testdata/source/taint/go/command_injection/compact_multi_name_params")
	got := categoryFindings(res, "command_injection")
	if len(got) != 1 {
		t.Fatalf("want 1 command_injection finding via runIn's second, compact-form parameter, got %d: %+v", len(got), res.Findings)
	}
	if got[0].Severity != model.SeverityHigh {
		t.Errorf("want HIGH severity, got %s", got[0].Severity)
	}
}

func TestTaint_SharedHelperSeededDeterministically(t *testing.T) {
	dir := "../../../testdata/source/taint/go/command_injection/shared_helper_nondeterministic"
	for i := range 30 {
		res := analyze(t, dir)
		got := categoryFindings(res, "command_injection")
		if len(got) != 2 {
			t.Fatalf("iteration %d: want both tools' flows into the shared helper found regardless of scan order, got %d: %+v", i, len(got), res.Findings)
		}
	}
}

func TestTaint_ShellClassification(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"bare_sh", `exec.Command("sh", "-c", "make "+args.Target)`},
		{"path_to_sh", `exec.Command("/bin/sh", "-c", "make "+args.Target)`},
		{"clustered_login_flag", `exec.Command("bash", "-lc", "make "+args.Target)`},
		{"env_prefix", `exec.Command("env", "sh", "-c", "make "+args.Target)`},
		{"flag_not_first", `exec.Command("sh", "-e", "-c", "make "+args.Target)`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := testutil.WriteTree(t, map[string]string{
				"handler.go": fmt.Sprintf(`package main

import "os/exec"

func runHandler(ctx Context, args RunArgs) (string, error) {
	out, _ := %s.Output()
	return string(out), nil
}
`, c.call),
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
			if got[0].Severity != model.SeverityHigh {
				t.Errorf("want HIGH severity, got %s", got[0].Severity)
			}
		})
	}
}

func TestTaint_GoExecCommandContext(t *testing.T) {
	dir := testutil.WriteTree(t, map[string]string{
		"handler.go": `package main

import (
	"context"
	"os/exec"
)

func runHandler(ctx Context, args RunArgs) (string, error) {
	out, _ := exec.CommandContext(context.Background(), "sh", "-c", "make "+args.Target).Output()
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
		t.Fatalf("want 1 command_injection finding via exec.CommandContext, got %d: %+v", len(got), res.Findings)
	}
	if got[0].Severity != model.SeverityHigh {
		t.Errorf("want HIGH severity, got %s", got[0].Severity)
	}
}

func TestTaint_NodeAsyncProcessAPIs(t *testing.T) {
	t.Run("spawn_argv_shell", func(t *testing.T) {
		src := `const { spawn } = require("child_process");

function runHandler(ctx, args) {
  return spawn("/bin/sh", ["-c", "run " + args.name]);
}

module.exports.register = function (server) {
  server.registerTool("run", { description: "Runs a named script" }, runHandler);
};
`
		res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": src}))
		if got := categoryFindings(res, "command_injection"); len(got) != 1 {
			t.Fatalf(`want 1 command_injection finding for spawn("/bin/sh", ["-c", ...]), got %d: %+v`, len(got), res.Findings)
		}
	})

	t.Run("spawn_shell_option", func(t *testing.T) {
		src := `const { spawn } = require("child_process");

function runHandler(ctx, args) {
  return spawn("/opt/scripts/" + args.name + ".sh", { shell: true });
}

module.exports.register = function (server) {
  server.registerTool("run", { description: "Runs a named script" }, runHandler);
};
`
		res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": src}))
		if got := categoryFindings(res, "command_injection"); len(got) != 1 {
			t.Fatalf("want 1 command_injection finding for spawn's shell:true option, got %d: %+v", len(got), res.Findings)
		}
	})

	t.Run("execFile_argv_shell", func(t *testing.T) {
		src := `const { execFile } = require("child_process");

function runHandler(ctx, args) {
  return execFile("/bin/sh", ["-c", "run " + args.name]);
}

module.exports.register = function (server) {
  server.registerTool("run", { description: "Runs a named script" }, runHandler);
};
`
		res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": src}))
		if got := categoryFindings(res, "command_injection"); len(got) != 1 {
			t.Fatalf("want 1 command_injection finding for execFile, got %d: %+v", len(got), res.Findings)
		}
	})

	t.Run("fork_program_tainted", func(t *testing.T) {
		src := `const { fork } = require("child_process");

function runHandler(ctx, args) {
  return fork("/opt/scripts/" + args.name + ".js");
}

module.exports.register = function (server) {
  server.registerTool("run", { description: "Runs a named script" }, runHandler);
};
`
		res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": src}))
		if got := categoryFindings(res, "command_injection"); len(got) != 1 {
			t.Fatalf("want 1 command_injection finding for fork, got %d: %+v", len(got), res.Findings)
		}
	})
}

func TestTaint_PythonProcessCatalogueAdditions(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"subprocess_check_call", `subprocess.check_call(["sh", "-c", "run " + name])`},
		{"os_execv", `os.execv("/bin/sh", ["-c", "run " + name])`},
		{"os_spawnv", `os.spawnv(os.P_WAIT, "/bin/sh", ["-c", "run " + name])`},
		{"commands_getoutput", `commands.getoutput("run " + name)`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := fmt.Sprintf(`import subprocess
import os
import commands


def run_handler(name: str) -> str:
    return %s


def register(mcp):
    mcp.add_tool(run_handler, name="run", description="Runs a named script")
`, c.call)
			res := analyze(t, mustWriteDir(t, map[string]string{"handler.py": src}))
			if got := categoryFindings(res, "command_injection"); len(got) != 1 {
				t.Fatalf("want 1 command_injection finding, got %d: %+v", len(got), res.Findings)
			}
		})
	}
}

func TestFixtures_ShorthandDestructuringAssignment(t *testing.T) {
	src := `import { readFileSync } from "fs";

async function readHandler(ctx, args) {
  const { target } = args;
  return readFileSync("/notes/" + target, "utf8");
}

module.exports.register = function (server) {
  server.registerTool("read", { description: "Reads a note by name" }, readHandler);
};
`
	res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": src}))
	if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
		t.Fatalf("want 1 path_traversal finding via shorthand destructuring, got %d: %+v", len(got), res.Findings)
	}
}

func TestTaint_LoopBindingCarriesTaint(t *testing.T) {
	t.Run("js_for_of", func(t *testing.T) {
		src := `const { exec } = require("child_process");

async function buildHandler(ctx, args) {
  for (const t of args.targets) {
    exec("make " + t);
  }
}

module.exports.register = function (server) {
  server.registerTool("build", { description: "Builds a list of targets" }, buildHandler);
};
`
		res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": src}))
		if got := categoryFindings(res, "command_injection"); len(got) != 1 {
			t.Fatalf("want 1 command_injection finding via a for-of loop binding, got %d: %+v", len(got), res.Findings)
		}
	})

	t.Run("js_foreach_callback", func(t *testing.T) {
		src := `const { execSync } = require("child_process");

async function buildHandler(ctx, args) {
  args.targets.forEach((t) => {
    execSync("make " + t);
  });
}

module.exports.register = function (server) {
  server.registerTool("build", { description: "Builds a list of targets" }, buildHandler);
};
`
		res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": src}))
		if got := categoryFindings(res, "command_injection"); len(got) != 1 {
			t.Fatalf("want 1 command_injection finding via a forEach callback binding, got %d: %+v", len(got), res.Findings)
		}
	})

	t.Run("python_for_in", func(t *testing.T) {
		src := `import os


def build_handler(targets: list) -> None:
    for t in targets:
        os.system("make " + t)


def register(mcp):
    mcp.add_tool(build_handler, name="build", description="Builds a list of targets")
`
		res := analyze(t, mustWriteDir(t, map[string]string{"handler.py": src}))
		if got := categoryFindings(res, "command_injection"); len(got) != 1 {
			t.Fatalf("want 1 command_injection finding via a Python for-in loop binding, got %d: %+v", len(got), res.Findings)
		}
	})

	t.Run("go_range", func(t *testing.T) {
		dir := testutil.WriteTree(t, map[string]string{
			"handler.go": `package main

import "os/exec"

func buildHandler(ctx Context, args BuildArgs) (string, error) {
	for _, t := range args.Targets {
		exec.Command("sh", "-c", "make "+t).Output()
	}
	return "", nil
}
`,
			"register.go": fmtRegister("buildHandler"),
		})
		res := run(t, dir)
		got := categoryFindings(res, "command_injection")
		if len(got) != 1 {
			t.Fatalf("want 1 command_injection finding via a Go range loop binding, got %d: %+v", len(got), res.Findings)
		}
	})
}

func TestTaint_AsyncioSubprocessShell(t *testing.T) {
	base := "../../../testdata/source/taint/python/command_injection/asyncio_shell"
	t.Run("vulnerable", func(t *testing.T) {
		res := analyze(t, base+"/vulnerable")
		if got := categoryFindings(res, "command_injection"); len(got) == 0 {
			t.Fatalf("want a command_injection finding, got none among %+v", res.Findings)
		}
	})
	t.Run("fixed", func(t *testing.T) {
		res := analyze(t, base+"/fixed")
		if got := categoryFindings(res, "command_injection"); len(got) != 0 {
			t.Fatalf("want no command_injection finding once shlex.quote is applied, got %+v", got)
		}
	})
	t.Run("benign", func(t *testing.T) {
		res := analyze(t, base+"/benign")
		if got := categoryFindings(res, "command_injection"); len(got) != 0 {
			t.Fatalf("want no command_injection finding when no tainted value reaches the shell call, got %+v", got)
		}
	})
}

func TestTaint_AsyncioSubprocessExec(t *testing.T) {
	base := "../../../testdata/source/taint/python/command_injection/asyncio_exec_argv"
	t.Run("vulnerable", func(t *testing.T) {
		res := analyze(t, base+"/vulnerable")
		if got := categoryFindings(res, "command_injection"); len(got) == 0 {
			t.Fatalf("want a command_injection finding via sh -c, got none among %+v", res.Findings)
		}
	})
	t.Run("fixed", func(t *testing.T) {
		res := analyze(t, base+"/fixed")
		if got := categoryFindings(res, "command_injection"); len(got) != 0 {
			t.Fatalf("want no command_injection finding once shlex.quote is applied, got %+v", got)
		}
	})
	t.Run("benign", func(t *testing.T) {
		res := analyze(t, base+"/benign")
		if got := categoryFindings(res, "command_injection"); len(got) != 0 {
			t.Fatalf("want no command_injection finding for a non-shell program with a terminated argv, got %+v", got)
		}
		if got := categoryFindings(res, "argument_injection"); len(got) != 0 {
			t.Fatalf("want no argument_injection finding either - the literal -- terminator covers that too, got %+v", got)
		}
	})
}

func TestTaint_Execa(t *testing.T) {
	base := "../../../testdata/source/taint/javascript/command_injection/execa_shell"
	t.Run("vulnerable", func(t *testing.T) {
		res := analyze(t, base+"/vulnerable")
		if got := categoryFindings(res, "command_injection"); len(got) == 0 {
			t.Fatalf("want a command_injection finding, got none among %+v", res.Findings)
		}
	})
	t.Run("fixed", func(t *testing.T) {
		res := analyze(t, base+"/fixed")
		if got := categoryFindings(res, "command_injection"); len(got) != 0 {
			t.Fatalf("want no command_injection finding once the target is checked against an allowlist, got %+v", got)
		}
	})
	t.Run("benign", func(t *testing.T) {
		res := analyze(t, base+"/benign")
		if got := categoryFindings(res, "command_injection"); len(got) != 0 {
			t.Fatalf("want no command_injection finding when no tainted value reaches execa, got %+v", got)
		}
	})
}

func TestTaint_ExecaCommand(t *testing.T) {
	base := "../../../testdata/source/taint/javascript/command_injection/execa_command"
	t.Run("vulnerable", func(t *testing.T) {
		res := analyze(t, base+"/vulnerable")
		if got := categoryFindings(res, "command_injection"); len(got) == 0 {
			t.Fatalf("want a command_injection finding, got none among %+v", res.Findings)
		}
	})
	t.Run("fixed", func(t *testing.T) {
		res := analyze(t, base+"/fixed")
		if got := categoryFindings(res, "command_injection"); len(got) != 0 {
			t.Fatalf("want no command_injection finding once the target is checked against an allowlist, got %+v", got)
		}
	})
	t.Run("benign", func(t *testing.T) {
		res := analyze(t, base+"/benign")
		if got := categoryFindings(res, "command_injection"); len(got) != 0 {
			t.Fatalf("want no command_injection finding when no tainted value reaches execaCommand, got %+v", got)
		}
	})
}

func TestFixtures_ModuleVariantExtensionDiscovered(t *testing.T) {
	dir := mustWriteDir(t, map[string]string{
		"server.ts": `export function register(server: any): void {
  server.tool("ping", "Replies pong", async () => "pong");
}
`,
		"handler.mts": `import { exec } from "child_process";

export async function runHandler({ command }: { command: string }) {
  exec("run " + command);
}

export function register(server: any): void {
  server.tool("run", "Runs a named script", runHandler);
}
`,
	})
	res := analyze(t, dir)
	if got := categoryFindings(res, "command_injection"); len(got) != 1 {
		t.Fatalf("want 1 command_injection finding from the .mts handler, got %d: %+v", len(got), res.Findings)
	}
	if res.Coverage.FilesDiscovered != 2 {
		t.Fatalf("want both server.ts and handler.mts discovered, got %d", res.Coverage.FilesDiscovered)
	}
}
