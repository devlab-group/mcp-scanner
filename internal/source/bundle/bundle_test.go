package bundle

import (
	"bytes"
	"strings"
	"testing"
)

const sample = `#!/usr/bin/env node
var __defProp = Object.defineProperty;

// ../../node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js
var McpServer = class {
  registerTool(name, config, cb) {}
};

// node_modules/zod/v3/types.js
function stringType() { return "é"; }

// src/tools/notes.ts
import { readFile } from "fs/promises";
async function readNote(name) {
  return readFile(name);
}

// package.json
var version = "1.0.0";
`

func TestSplitBlanksDependencyModules(t *testing.T) {
	res, ok := Split([]byte(sample))
	if !ok {
		t.Fatal("want a bundle")
	}
	if len(res.Masked) != len(sample) {
		t.Fatalf("masked length %d, want %d", len(res.Masked), len(sample))
	}
	if bytes.Count(res.Masked, []byte("\n")) != strings.Count(sample, "\n") {
		t.Fatal("line count changed")
	}
	masked := string(res.Masked)
	for _, gone := range []string{"McpServer", "registerTool", "stringType", "node_modules"} {
		if strings.Contains(masked, gone) {
			t.Errorf("dependency text %q kept", gone)
		}
	}
	for _, kept := range []string{"__defProp", "// src/tools/notes.ts", "readFile(name)", `var version = "1.0.0"`} {
		if !strings.Contains(masked, kept) {
			t.Errorf("own text %q blanked", kept)
		}
	}
	// the server's own code stays at the same byte offset
	if i, j := strings.Index(sample, "readFile(name)"), strings.Index(masked, "readFile(name)"); i != j {
		t.Errorf("own code moved from %d to %d", i, j)
	}
	if res.ThirdParty != 2 || res.Own != 2 {
		t.Errorf("modules: %d third-party, %d own; want 2, 2", res.ThirdParty, res.Own)
	}
	if got := strings.Join(res.Packages, ","); got != "@modelcontextprotocol/sdk,zod" {
		t.Errorf("packages %q", got)
	}
	if want := int64(len(masked) - strings.Count(masked, " ")); res.OwnBytes < want {
		t.Errorf("own bytes %d less than the unblanked text %d", res.OwnBytes, want)
	}
}

func TestSplitNotABundle(t *testing.T) {
	for _, src := range []string{
		"// src/index.ts\nconst a = 1;\n",                                        // no dependency module
		"const a = 1; // node_modules/zod/index.js\n",                            // not at column 0
		"//  node_modules/zod/index.js\n",                                        // not esbuild's spacing
		"// node_modules/zod/index.js is where the parser lives\nconst a = 1;\n", // prose, not a path
		"/* node_modules/zod/index.js */\n",
	} {
		if _, ok := Split([]byte(src)); ok {
			t.Errorf("%q: want not a bundle", src)
		}
	}
}

func TestPackageOf(t *testing.T) {
	for path, want := range map[string]string{
		"node_modules/zod/v3/types.js":                                         "zod",
		"../../node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js":  "@modelcontextprotocol/sdk",
		"node_modules/@modelcontextprotocol/sdk/node_modules/ajv/dist/core.js": "ajv",
		"src/index.ts": "",
	} {
		if got, _ := packageOf(path); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}

func TestRead(t *testing.T) {
	big := strings.Repeat("// node_modules/zod/index.js\nvar a = 1;\n", 4000) + "// src/index.ts\nrun();\n"
	t.Run("a bundle whose own code fits is read whole and blanked", func(t *testing.T) {
		src, pkgs, ok, err := Read(strings.NewReader(big), 1024)
		if err != nil || !ok || len(src) != len(big) || strings.Contains(string(src), "var a") || !strings.Contains(string(src), "run();") {
			t.Fatalf("ok %v err %v len %d pkgs %v", ok, err, len(src), pkgs)
		}
	})
	t.Run("own code over the limit is truncated", func(t *testing.T) {
		src, _, ok, err := Read(strings.NewReader(big), 10)
		if err != nil || ok || len(src) != 10 {
			t.Fatalf("ok %v err %v len %d", ok, err, len(src))
		}
	})
	t.Run("a file that is no bundle any more is truncated", func(t *testing.T) {
		src, _, ok, err := Read(strings.NewReader(strings.Repeat("x", 5000)), 100)
		if err != nil || ok || len(src) != 100 {
			t.Fatalf("ok %v err %v len %d", ok, err, len(src))
		}
	})
	t.Run("more than MaxSize is never read whole", func(t *testing.T) {
		huge := big + strings.Repeat("\n", MaxSize)
		src, _, ok, err := Read(strings.NewReader(huge), 1024)
		if err != nil || ok || len(src) != 1024 {
			t.Fatalf("ok %v err %v len %d", ok, err, len(src))
		}
	})
}
