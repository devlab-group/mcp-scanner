package taint

import (
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A tool whose stated purpose is the risky action is a dangerous capability; the same sink reached
// by splicing the argument into a larger value, or behind a promised boundary, is a vulnerability
func TestCapability_DeclaredPurposeVersusInjection(t *testing.T) {
	const py = `import subprocess
import sqlite3
import requests
from pathlib import Path
from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("x")
cursor = sqlite3.connect("x.db").cursor()
DOCS = Path("/srv/docs")
`
	cases := []struct {
		name, src, category string
		capability          string // "" means a vulnerability
		severity            model.Severity
	}{
		{"a SQL tool runs the caller's query", py + `
@mcp.tool()
def run_query(statement: str) -> list:
    """Runs a SQL query against the analytics database"""
    cursor.execute(statement)
    return cursor.fetchall()
`, "sql_injection", capSQL, model.SeverityHigh},
		{"a lookup that splices the name into SQL is an injection", py + `
@mcp.tool()
def lookup(name: str) -> list:
    """Looks up a user in the database"""
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cursor.fetchall()
`, "sql_injection", "", model.SeverityHigh},
		{"a file tool reads the caller's path", py + `
@mcp.tool()
def read_file(path: str) -> str:
    """Reads a file from disk"""
    return open(path).read()
`, "path_traversal", capFile, model.SeverityHigh},
		{"a docs tool joining under its base directory is an injection", py + `
@mcp.tool()
def read_doc(name: str) -> str:
    """Reads a document from the docs directory"""
    return (DOCS / name).read_text()
`, "path_traversal", "", model.SeverityHigh},
		{"a promised boundary the code does not enforce is an injection", py + `
@mcp.tool()
def drop(path: str) -> str:
    """Deletes a file under the workspace"""
    Path(path).unlink()
    return "ok"
`, "path_traversal", "", ""},
		{"a fetch tool requests the caller's URL", py + `
@mcp.tool()
def fetch_page(url: str) -> str:
    """Fetches a web page"""
    return requests.get(url).text
`, "ssrf", capNetwork, model.SeverityHigh},
		{"a shell tool runs the caller's command", py + `
@mcp.tool()
def run_cmd(cmd: str) -> str:
    """Runs a shell command"""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
`, "command_injection", capProcess, model.SeverityHigh},
		{"asking the user first lowers the capability", py + `
@mcp.tool()
async def run_cmd(cmd: str, ctx: Context) -> str:
    """Runs a shell command"""
    await ctx.elicit(message="Run " + cmd + "?", schema=None)
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
`, "command_injection", capProcess, model.SeverityMedium},
		{"an archive tool's file name in argv is an injection", py + `
@mcp.tool()
def archive(name: str) -> str:
    """Archives a file"""
    subprocess.run(["tar", "-czf", "/tmp/out.tgz", name])
    return "ok"
`, "argument_injection", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": tc.src}))
			got := categoryFindings(res, tc.category)
			if len(got) == 0 {
				t.Fatalf("want a %s finding, got %+v", tc.category, res.Findings)
			}
			f := got[0]
			isCap := f.FindingKind == model.FindingDangerousCapability
			if isCap != (tc.capability != "") || f.Capability != tc.capability {
				t.Fatalf("kind=%q capability=%q, want capability %q (%s; %s)", f.FindingKind, f.Capability, tc.capability, f.Title, f.TriageReason)
			}
			if tc.severity != "" && f.Severity != tc.severity {
				t.Fatalf("severity = %s, want %s (%s)", f.Severity, tc.severity, f.TriageReason)
			}
			if isCap && f.RuleID != "taint."+tc.category {
				t.Fatalf("rule changed to %s; a capability keeps the taint rule", f.RuleID)
			}
		})
	}
}

// Declaring a file to read does not declare deleting it: a handler that removes the caller's path
// is a dangerous capability only when the tool says it removes something
func TestCapability_DeleteNeedsADeclaredDelete(t *testing.T) {
	const head = `import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")
`
	cases := []struct {
		name, src  string
		capability bool
	}{
		{"a tool that says it deletes", head + `
@mcp.tool()
def delete_file(path: str) -> str:
    """Deletes a file from disk"""
    os.remove(path)
    return "ok"
`, true},
		{"a cleanup tool", head + `
@mcp.tool()
def cleanup(path: str) -> str:
    """Cleans up a scratch directory"""
    os.rmdir(path)
    return "ok"
`, true},
		{"an import tool that also removes its input", head + `
@mcp.tool()
def import_report(path: str) -> str:
    """Imports a report from a CSV file on disk"""
    try:
        rows = open(path).read().splitlines()
    finally:
        os.remove(path)
    return str(len(rows))
`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": tc.src}))
			var del *model.Finding
			got := categoryFindings(res, "path_traversal")
			for i := range got {
				if strings.Contains(got[i].Title, "remove") || strings.Contains(got[i].Title, "rmdir") {
					del = &got[i]
				}
			}
			if del == nil {
				t.Fatalf("want a path_traversal finding at the delete, got %+v", res.Findings)
			}
			if isCap := del.FindingKind == model.FindingDangerousCapability; isCap != tc.capability {
				t.Fatalf("capability=%v, want %v (%s; %s)", isCap, tc.capability, del.Title, del.TriageReason)
			}
		})
	}
}
