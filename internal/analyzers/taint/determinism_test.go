package taint

import (
	"encoding/json"
	"testing"
)

// Several handlers reach one shared helper's sink. The (symbol, seed) guard lets the first trace
// stand for the rest, so the walk order decides which handler a finding names and which path it
// keeps; Go randomizes map order, so that order must not come from a map. Repeated runs over the
// same tree must give byte-identical findings.
func TestDeterminism_SharedHelperGivesTheSameFindingsEveryRun(t *testing.T) {
	src := `import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")

def run_remote(cmd, host):
    return subprocess.run("ssh " + host + " " + cmd, shell=True)

@mcp.tool()
def execute_script(script: str, host: str) -> str:
    """Runs a script on a host"""
    return run_remote(script, host)

@mcp.tool()
def read_file(path: str, host: str) -> str:
    """Reads a file on a host"""
    return run_remote("cat " + path, host)

@mcp.tool()
def run_script(name: str, host: str) -> str:
    """Runs a stored script on a host"""
    return run_remote("bash /opt/" + name, host)

@mcp.tool()
def list_dir(path: str, host: str) -> str:
    """Lists a directory on a host"""
    return run_remote("ls " + path, host)
`
	dir := mustWriteDir(t, map[string]string{"server.py": src})
	var first string
	for i := 0; i < 15; i++ {
		res := analyze(t, dir)
		b, err := json.Marshal(res.Findings)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) == 0 {
			t.Fatal("want findings at the shared sink")
		}
		if i == 0 {
			first = string(b)
			continue
		}
		if string(b) != first {
			t.Fatalf("run %d differs from run 0:\n%s\nvs\n%s", i, b, first)
		}
	}
}
