package taint

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
)

// ---- Python: os.execl and its l-variant siblings (argv) ----

func TestTaint_PythonExeclFamily(t *testing.T) {
	for _, name := range []string{"os.execl", "os.execle", "os.execlp", "os.execlpe"} {
		t.Run(name, func(t *testing.T) {
			extra := ""
			if strings.HasSuffix(name, "e") {
				extra = `, {"PATH": "/usr/bin"}`
			}
			src := func(program, arg0, flagOrArg, tail string) string {
				return fmt.Sprintf(`def run_handler(name: str) -> str:
    %s(%s, %s, %s, %s%s)
    return "done"


def register(mcp):
    mcp.add_tool(run_handler, name="run", description="Runs a named script")
`, name, program, arg0, flagOrArg, tail, extra)
			}

			vulnerable := src(`"/bin/sh"`, `"sh"`, `"-c"`, `"run " + name`)
			res := analyze(t, mustWriteDir(t, map[string]string{"handler.py": vulnerable}))
			if got := categoryFindings(res, "command_injection"); len(got) != 1 {
				t.Fatalf("want 1 command_injection finding via %s, got %d: %+v", name, len(got), res.Findings)
			}

			fixed := src(`"/usr/bin/printenv"`, `"printenv"`, `"--"`, `name`)
			res = analyze(t, mustWriteDir(t, map[string]string{"handler.py": fixed}))
			if got := categoryFindings(res, "command_injection"); len(got) != 0 {
				t.Fatalf("%s: want no command_injection finding once the program is a non-shell literal with a -- terminator, got %+v", name, got)
			}
			if got := categoryFindings(res, "argument_injection"); len(got) != 0 {
				t.Fatalf("%s: want no argument_injection finding either - the literal -- covers that too, got %+v", name, got)
			}

			benign := src(`"/usr/bin/printenv"`, `"printenv"`, `"HOME"`, `"unused"`)
			res = analyze(t, mustWriteDir(t, map[string]string{"handler.py": benign}))
			if got := categoryFindings(res, "command_injection"); len(got) != 0 {
				t.Fatalf("%s: want no command_injection finding when no tainted value reaches it, got %+v", name, got)
			}
		})
	}
}

// ---- Python: urllib.request.urlopen (ssrf) ----

func TestTaint_UrllibUrlopen(t *testing.T) {
	vulnerable := `import urllib.request


def fetch_handler(target: str) -> str:
    resp = urllib.request.urlopen("https://" + target)
    return resp.read().decode()


def register(mcp):
    mcp.add_tool(fetch_handler, name="fetch", description="Fetches a URL")
`
	res := analyze(t, mustWriteDir(t, map[string]string{"handler.py": vulnerable}))
	if got := categoryFindings(res, "ssrf"); len(got) != 1 {
		t.Fatalf("want 1 ssrf finding, got %d: %+v", len(got), res.Findings)
	}

	fixed := `import urllib.request


def fetch_handler(city: str) -> str:
    if city == "london":
        resp = urllib.request.urlopen("https://api.weather.example/v1/london")
    elif city == "paris":
        resp = urllib.request.urlopen("https://api.weather.example/v1/paris")
    else:
        return ""
    return resp.read().decode()


def register(mcp):
    mcp.add_tool(fetch_handler, name="fetch", description="Fetches the weather for one of a fixed set of cities")
`
	res = analyze(t, mustWriteDir(t, map[string]string{"handler.py": fixed}))
	if got := categoryFindings(res, "ssrf"); len(got) != 0 {
		t.Fatalf("want no ssrf finding once the URL is one of a fixed set of literals, got %+v", got)
	}

	benign := `import urllib.request


def status_handler(label: str) -> str:
    resp = urllib.request.urlopen("https://status.example.com/health")
    return label + ": " + resp.read().decode()


def register(mcp):
    mcp.add_tool(status_handler, name="status", description="Reports status with a caller-supplied label")
`
	res = analyze(t, mustWriteDir(t, map[string]string{"handler.py": benign}))
	if got := categoryFindings(res, "ssrf"); len(got) != 0 {
		t.Fatalf("want no ssrf finding when no tainted value reaches urlopen, got %+v", got)
	}
}

// ---- Python: archive extraction (zipfile, tarfile, shutil) ----

func TestTaint_ArchiveExtraction(t *testing.T) {
	cases := []struct {
		name       string
		vulnerable string
		fixed      string
		benign     string
	}{
		{
			name: "zipfile",
			vulnerable: `import zipfile


def extract_handler(name: str) -> str:
    zipfile.ZipFile("/srv/archives/upload.zip").extractall("/srv/extracted/" + name)
    return "done"


def register(mcp):
    mcp.add_tool(extract_handler, name="extract", description="Extracts an uploaded archive")
`,
			fixed: `import os
import zipfile


def extract_handler(name: str) -> str:
    zipfile.ZipFile("/srv/archives/upload.zip").extractall("/srv/extracted/" + os.path.basename(name))
    return "done"


def register(mcp):
    mcp.add_tool(extract_handler, name="extract", description="Extracts an uploaded archive")
`,
			benign: `import zipfile


def status_handler(label: str) -> str:
    zipfile.ZipFile("/srv/archives/upload.zip").extractall("/srv/extracted")
    return label


def register(mcp):
    mcp.add_tool(status_handler, name="status", description="Reports status with a caller-supplied label")
`,
		},
		{
			name: "tarfile",
			vulnerable: `import tarfile


def extract_handler(name: str) -> str:
    tarfile.open("/srv/archives/upload.tar.gz").extractall("/srv/extracted/" + name)
    return "done"


def register(mcp):
    mcp.add_tool(extract_handler, name="extract", description="Extracts an uploaded archive")
`,
			fixed: `import os
import tarfile


def extract_handler(name: str) -> str:
    tarfile.open("/srv/archives/upload.tar.gz").extractall("/srv/extracted/" + os.path.basename(name))
    return "done"


def register(mcp):
    mcp.add_tool(extract_handler, name="extract", description="Extracts an uploaded archive")
`,
			benign: `import tarfile


def status_handler(label: str) -> str:
    tarfile.open("/srv/archives/upload.tar.gz").extractall("/srv/extracted")
    return label


def register(mcp):
    mcp.add_tool(status_handler, name="status", description="Reports status with a caller-supplied label")
`,
		},
		{
			name: "shutil.unpack_archive",
			vulnerable: `import shutil


def extract_handler(name: str) -> str:
    shutil.unpack_archive("/srv/archives/upload.zip", "/srv/extracted/" + name)
    return "done"


def register(mcp):
    mcp.add_tool(extract_handler, name="extract", description="Extracts an uploaded archive")
`,
			fixed: `import os
import shutil


def extract_handler(name: str) -> str:
    shutil.unpack_archive("/srv/archives/upload.zip", "/srv/extracted/" + os.path.basename(name))
    return "done"


def register(mcp):
    mcp.add_tool(extract_handler, name="extract", description="Extracts an uploaded archive")
`,
			benign: `import shutil


def status_handler(label: str) -> str:
    shutil.unpack_archive("/srv/archives/upload.zip", "/srv/extracted")
    return label


def register(mcp):
    mcp.add_tool(status_handler, name="status", description="Reports status with a caller-supplied label")
`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"handler.py": c.vulnerable}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
				t.Fatalf("want 1 path_traversal finding, got %d: %+v", len(got), res.Findings)
			}
			res = analyze(t, mustWriteDir(t, map[string]string{"handler.py": c.fixed}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
				t.Fatalf("want no path_traversal finding once os.path.basename is applied, got %+v", got)
			}
			res = analyze(t, mustWriteDir(t, map[string]string{"handler.py": c.benign}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
				t.Fatalf("want no path_traversal finding when no tainted value reaches the destination, got %+v", got)
			}
		})
	}
}

// ---- Python: os.scandir, os.makedirs ----

func TestTaint_PythonScandirAndMakedirs(t *testing.T) {
	for _, call := range []string{"os.scandir", "os.makedirs"} {
		t.Run(call, func(t *testing.T) {
			vulnerable := fmt.Sprintf(`import os


def run_handler(name: str) -> str:
    %s("/srv/docs/" + name)
    return "done"


def register(mcp):
    mcp.add_tool(run_handler, name="run", description="Operates on a named directory")
`, call)
			res := analyze(t, mustWriteDir(t, map[string]string{"handler.py": vulnerable}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
				t.Fatalf("%s: want 1 path_traversal finding, got %d: %+v", call, len(got), res.Findings)
			}

			fixed := fmt.Sprintf(`import os


def run_handler(name: str) -> str:
    %s("/srv/docs/" + os.path.basename(name))
    return "done"


def register(mcp):
    mcp.add_tool(run_handler, name="run", description="Operates on a named directory")
`, call)
			res = analyze(t, mustWriteDir(t, map[string]string{"handler.py": fixed}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
				t.Fatalf("%s: want no path_traversal finding once os.path.basename is applied, got %+v", call, got)
			}

			benign := fmt.Sprintf(`import os


def status_handler(label: str) -> str:
    %s("/srv/docs")
    return label


def register(mcp):
    mcp.add_tool(status_handler, name="status", description="Reports status with a caller-supplied label")
`, call)
			res = analyze(t, mustWriteDir(t, map[string]string{"handler.py": benign}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
				t.Fatalf("%s: want no path_traversal finding when no tainted value reaches it, got %+v", call, got)
			}
		})
	}
}

// ---- Go: os.ReadDir, os.Rename, os.Symlink, os.Mkdir, os.Chmod,
// os.Truncate, filepath.Walk(Dir) ----

func goHandlerSrc(imports []string, pathExpr, call string) string {
	return fmt.Sprintf(`package main

import (
	%s
)

func runHandler(ctx Context, args RunArgs) (string, error) {
	target := %s
	%s
	return "", nil
}
`, strings.Join(imports, "\n\t"), pathExpr, call)
}

func TestTaint_GoFilesystemAdditions(t *testing.T) {
	cases := []struct {
		name string
		call string // %s is replaced with the tainted path variable
	}{
		{"os.ReadDir", `_, _ = os.ReadDir(%s)`},
		{"os.Rename", `_ = os.Rename(%s, "/tmp/out")`},
		{"os.Symlink", `_ = os.Symlink(%s, "/tmp/link")`},
		{"os.Mkdir", `_ = os.Mkdir(%s, 0o755)`},
		{"os.Chmod", `_ = os.Chmod(%s, 0o600)`},
		{"os.Truncate", `_ = os.Truncate(%s, 0)`},
		{"filepath.Walk", `_ = filepath.Walk(%s, nil)`},
		{"filepath.WalkDir", `_ = filepath.WalkDir(%s, nil)`},
	}
	imports := []string{`"os"`, `"path/filepath"`}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vuln := goHandlerSrc(imports, `"/srv/docs/" + args.Name`, fmt.Sprintf(c.call, "target"))
			dir := testutil.WriteTree(t, map[string]string{"handler.go": vuln, "register.go": fmtRegister("runHandler")})
			res := run(t, dir)
			if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
				t.Fatalf("want 1 path_traversal finding, got %d: %+v", len(got), res.Findings)
			}

			fixed := goHandlerSrc(imports, `"/srv/docs/" + filepath.Base(args.Name)`, fmt.Sprintf(c.call, "target"))
			dir = testutil.WriteTree(t, map[string]string{"handler.go": fixed, "register.go": fmtRegister("runHandler")})
			res = run(t, dir)
			if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
				t.Fatalf("want no path_traversal finding once filepath.Base is applied, got %+v", got)
			}

			benign := goHandlerSrc(imports, `"/srv/docs/fixed.txt"`, fmt.Sprintf(c.call, "target"))
			dir = testutil.WriteTree(t, map[string]string{"handler.go": benign, "register.go": fmtRegister("runHandler")})
			res = run(t, dir)
			if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
				t.Fatalf("want no path_traversal finding when no tainted value reaches it, got %+v", got)
			}
		})
	}
}

// ---- TypeScript/JavaScript: readdir, readdirSync, appendFileSync, cp,
// opendir, createWriteStream ----

// TestTaint_NodeFilesystemAdditions follows the same shape
// TestFixtures_FsPromisesMethodSinks already established for
// readFile/writeFile/... : vulnerable when the path is built by
// concatenation, clean once path.basename is applied
func TestTaint_NodeFilesystemAdditions(t *testing.T) {
	ops := []struct {
		name string
		call string // %s replaced with the path expression
	}{
		{"readdir", `fs.promises.readdir(%s)`},
		{"cp", `fs.promises.cp(%s, "/srv/backup/copy")`},
		{"opendir", `fs.promises.opendir(%s)`},
		{"createWriteStream", `fs.createWriteStream(%s)`},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			vulnerable := "const fs = require(\"fs\");\n\n" +
				"async function readHandler(ctx, args) {\n" +
				"  return " + fmt.Sprintf(op.call, `"/srv/project/" + args.name`) + ";\n" +
				"}\n\n" +
				"module.exports.register = function (server) {\n" +
				"  server.registerTool(\"read\", { description: \"Operates on a file in the project directory\" }, readHandler);\n" +
				"};\n"
			res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": vulnerable}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
				t.Fatalf("%s: want 1 path_traversal finding, got %d: %+v", op.name, len(got), res.Findings)
			}

			fixed := "const fs = require(\"fs\");\n" +
				"const path = require(\"path\");\n\n" +
				"async function readHandler(ctx, args) {\n" +
				"  const safe = path.basename(args.name);\n" +
				"  return " + fmt.Sprintf(op.call, `"/srv/project/" + safe`) + ";\n" +
				"}\n\n" +
				"module.exports.register = function (server) {\n" +
				"  server.registerTool(\"read\", { description: \"Operates on a file in the project directory\" }, readHandler);\n" +
				"};\n"
			res = analyze(t, mustWriteDir(t, map[string]string{"handler.js": fixed}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
				t.Fatalf("%s: a path.basename'd argument must not fire, got %+v", op.name, got)
			}

			benign := "const fs = require(\"fs\");\n\n" +
				"async function statusHandler(ctx, args) {\n" +
				"  " + fmt.Sprintf(op.call, `"/srv/project/fixed"`) + ";\n" +
				"  return args.label;\n" +
				"}\n\n" +
				"module.exports.register = function (server) {\n" +
				"  server.registerTool(\"status\", { description: \"Reports status with a caller-supplied label\" }, statusHandler);\n" +
				"};\n"
			res = analyze(t, mustWriteDir(t, map[string]string{"handler.js": benign}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
				t.Fatalf("%s: want no path_traversal finding when no tainted value reaches it, got %+v", op.name, got)
			}
		})
	}
}

// TestTaint_NodeSyncFilesystemAdditions is readdirSync/appendFileSync -
// Node's synchronous fs API, imported bare the way readFileSync/
// writeFileSync already were, rather than through fs.promises
func TestTaint_NodeSyncFilesystemAdditions(t *testing.T) {
	ops := []struct {
		name string
		call string
	}{
		{"readdirSync", `readdirSync(%s)`},
		{"appendFileSync", `appendFileSync(%s, "logged")`},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			vulnerable := fmt.Sprintf(`const { %s } = require("fs");

function readHandler(ctx, args) {
  return %s;
}

module.exports.register = function (server) {
  server.registerTool("read", { description: "Operates on a file in the project directory" }, readHandler);
};
`, op.name, fmt.Sprintf(op.call, `"/srv/project/" + args.name`))
			res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": vulnerable}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
				t.Fatalf("%s: want 1 path_traversal finding, got %d: %+v", op.name, len(got), res.Findings)
			}

			fixed := fmt.Sprintf(`const { %s } = require("fs");
const path = require("path");

function readHandler(ctx, args) {
  const safe = path.basename(args.name);
  return %s;
}

module.exports.register = function (server) {
  server.registerTool("read", { description: "Operates on a file in the project directory" }, readHandler);
};
`, op.name, fmt.Sprintf(op.call, `"/srv/project/" + safe`))
			res = analyze(t, mustWriteDir(t, map[string]string{"handler.js": fixed}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
				t.Fatalf("%s: a path.basename'd argument must not fire, got %+v", op.name, got)
			}

			benign := fmt.Sprintf(`const { %s } = require("fs");

function statusHandler(ctx, args) {
  %s;
  return args.label;
}

module.exports.register = function (server) {
  server.registerTool("status", { description: "Reports status with a caller-supplied label" }, statusHandler);
};
`, op.name, fmt.Sprintf(op.call, `"/srv/project/fixed"`))
			res = analyze(t, mustWriteDir(t, map[string]string{"handler.js": benign}))
			if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
				t.Fatalf("%s: want no path_traversal finding when no tainted value reaches it, got %+v", op.name, got)
			}
		})
	}
}

// ---- Parity-driven additions: lighter, vulnerable-only verification ----

func TestTaint_ParityAdditionsFire(t *testing.T) {
	t.Run("python", func(t *testing.T) {
		for _, call := range []string{"os.chmod", "os.symlink"} {
			t.Run(call, func(t *testing.T) {
				src := fmt.Sprintf(`import os


def run_handler(name: str) -> str:
    %s("/srv/docs/" + name, "/tmp/x")
    return "done"


def register(mcp):
    mcp.add_tool(run_handler, name="run", description="Operates on a named path")
`, call)
				res := analyze(t, mustWriteDir(t, map[string]string{"handler.py": src}))
				if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
					t.Fatalf("%s: want 1 path_traversal finding, got %d: %+v", call, len(got), res.Findings)
				}
			})
		}
	})

	t.Run("node", func(t *testing.T) {
		for _, call := range []string{"chmod", "symlink"} {
			t.Run(call, func(t *testing.T) {
				src := fmt.Sprintf(`const fs = require("fs");

async function runHandler(ctx, args) {
  return fs.promises.%s("/srv/docs/" + args.name, "/tmp/x");
}

module.exports.register = function (server) {
  server.registerTool("run", { description: "Operates on a named path" }, runHandler);
};
`, call)
				res := analyze(t, mustWriteDir(t, map[string]string{"handler.js": src}))
				if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
					t.Fatalf("%s: want 1 path_traversal finding, got %d: %+v", call, len(got), res.Findings)
				}
			})
		}
	})

	t.Run("java", func(t *testing.T) {
		cases := []struct {
			name string
			call string // %s replaced with Path.of("/srv/project/" + name)
		}{
			{"Files.list", `Files.list(%s)`},
			{"Files.move", `Files.move(%s, Path.of("/srv/archive/out"))`},
			{"Files.createDirectory", `Files.createDirectory(%s)`},
			{"Files.createDirectories", `Files.createDirectories(%s)`},
			{"Files.setPosixFilePermissions", `Files.setPosixFilePermissions(%s, Set.of(PosixFilePermission.OWNER_READ))`},
			{"Files.createSymbolicLink", `Files.createSymbolicLink(%s, Path.of("/srv/real"))`},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				src := fmt.Sprintf(`package taintfixture;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

public class FsTool {

    @Tool(name = "run", description = "Operates on a named path")
    public void run(String name) throws Exception {
        %s;
    }
}
`, fmt.Sprintf(c.call, `Path.of("/srv/project/" + name)`))
				res := analyze(t, mustWriteDir(t, map[string]string{"FsTool.java": src}))
				if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
					t.Fatalf("%s: want 1 path_traversal finding, got %d: %+v", c.name, len(got), res.Findings)
				}
			})
		}
	})

	t.Run("rust", func(t *testing.T) {
		cases := []struct {
			name string
			call string // %s replaced with the tainted path expression
		}{
			{"std::fs::read_dir", `std::fs::read_dir(%s)`},
			{"std::fs::rename", `std::fs::rename(%s, "/srv/out")`},
			{"std::fs::create_dir", `std::fs::create_dir(%s)`},
			{"std::fs::create_dir_all", `std::fs::create_dir_all(%s)`},
			{"std::fs::set_permissions", `std::fs::set_permissions(%s, perms)`},
			{"std::os::unix::fs::symlink", `std::os::unix::fs::symlink(%s, "/srv/link")`},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				src := fmt.Sprintf(`#[tool(name = "run", description = "Operates on a named path")]
fn run(name: String) -> String {
    let path = "/srv/project/".to_string() + &name;
    let _ = %s;
    String::new()
}
`, fmt.Sprintf(c.call, "path"))
				res := analyze(t, mustWriteDir(t, map[string]string{"tool.rs": src}))
				if got := categoryFindings(res, "path_traversal"); len(got) != 1 {
					t.Fatalf("%s: want 1 path_traversal finding, got %d: %+v", c.name, len(got), res.Findings)
				}
			})
		}
	})
}
