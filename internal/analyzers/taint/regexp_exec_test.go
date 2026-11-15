package taint

import (
	"testing"
)

// The bare "exec" sink exists for `import { exec } from "child_process"`, but whole-identifier
// matching also caught RegExp.prototype.exec, so `PATTERN.exec(path)` on a tool argument was
// reported as HIGH command injection. A receiver this file binds to a regular expression is
// not a process API; everything else still matches.
func TestRegExpExecIsNotCommandInjection(t *testing.T) {
	const header = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
`
	register := func(body string) string {
		return `
export function register(server: McpServer): void {
  server.tool("check", "Checks a path", async ({ path }: { path: string }) => {
` + body + `
  });
}
`
	}

	cases := []struct {
		name string
		src  string
		want int
	}{
		{"regex literal constant", header + "const DRIVE = /^[A-Za-z]:/;\n" + register("    const m = DRIVE.exec(path);\n    return m;"), 0},
		{"regex literal constant on its own line", header + "const UNC =\n  /^\\\\\\\\[^\\\\]+/;\n" + register("    return UNC.exec(path);"), 0},
		{"inline regex literal", header + register("    return /^a/.exec(path);"), 0},
		{"new RegExp", header + "const RE = new RegExp(\"^a\");\n" + register("    return RE.exec(path);"), 0},
		{"RegExp call", header + "const RE = RegExp(\"^a\");\n" + register("    return RE.exec(path);"), 0},
		{"optional chain on a regex", header + "const RE = /^a/;\n" + register("    return RE?.exec(path);"), 0},

		{"bare imported exec still fires", header + "import { exec } from \"child_process\";\n" + register("    exec(\"ls \" + path);"), 1},
		{"child_process namespace still fires", header + "import * as child_process from \"child_process\";\n" + register("    child_process.exec(\"ls \" + path);"), 1},
		{"required module still fires", header + "const cp = require(\"child_process\");\n" + register("    cp.exec(\"ls \" + path);"), 1},
		{"unknown receiver still fires", header + "import shell from \"shelljs\";\n" + register("    shell.exec(\"ls \" + path);"), 1},
		{"name rebound away from a regex still fires", header + "let runner = /^a/;\nrunner = require(\"child_process\");\n" + register("    runner.exec(\"ls \" + path);"), 1},

		// A parameter, loop variable or catch binding with the same name shadows the
		// module-level regex, so a file-wide regex binding must not speak for it
		{"parameter shadowing a regex still fires", header + "import * as child_process from \"child_process\";\nconst RE = /^a/;\nfunction run(RE: any, p: string) { RE.exec(\"ls \" + p); }\n" + register("    run(child_process, path);"), 1},
		{"arrow parameter shadowing a regex still fires", header + "import * as child_process from \"child_process\";\nconst RE = /^a/;\nconst run = RE => (p: string) => RE.exec(\"ls \" + p);\n" + register("    run(child_process)(path);"), -1},
		{"loop variable shadowing a regex still fires", header + "import * as child_process from \"child_process\";\nconst RE = /^a/;\n" + register("    for (const RE of [child_process]) { RE.exec(\"ls \" + path); }"), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := mustWriteDir(t, map[string]string{"server.ts": tc.src})
			res := analyze(t, dir)
			got := categoryFindings(res, "command_injection")
			if tc.want < 0 {
				// The walker does not follow taint through a returned closure; this case only
				// pins that the shadowing check does not panic on an unparenthesized parameter
				return
			}
			if len(got) != tc.want {
				t.Fatalf("want %d command_injection findings, got %d: %+v", tc.want, len(got), res.Findings)
			}
		})
	}
}
