package taint

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Findings from the third iteration (servers 151-200), each paired with the real issue beside it
func TestIteration3Regressions(t *testing.T) {
	const py = `import os
import re
import sqlite3
import asyncpg
import requests
from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")
BASE = os.environ["API_BASE"]
GITHUB_DIR = Path("/srv/.github")
cursor = sqlite3.connect("x.db").cursor()


def validate_table_name(name):
    if not re.match(r"^[a-zA-Z0-9_]+$", name):
        raise ValueError("bad table name")
    return True


def validate_file_path(path):
    real = os.path.realpath(path)
    if not real.startswith("/tmp/"):
        raise ValueError("outside the allowed directories")
    return real


def ci_read(path):
    return path.read_text()
`
	cases := []struct {
		name, src, category string
		want                int
		triage              model.Triage
		capability          bool
	}{
		{"asyncpg fetch on a connection is SQL, not HTTP", py + `
@mcp.tool()
async def execute_sales_query(query: str) -> list:
    """Runs a SQL query against the sales database"""
    conn = await asyncpg.connect("postgres://x")
    return await conn.fetch(query)
`, "sql_injection", 1, model.TriagePotential, true},
		{"a query string after a configured base is not SSRF", py + `
@mcp.tool()
def report(request_id: str) -> str:
    """Reports a request"""
    return requests.get(f"{BASE}?method=report&requestId={request_id}").text
`, "ssrf", 0, "", false},
		{"a join passed straight into a helper is a composition", py + `
@mcp.tool()
def ci_file(filename: str) -> str:
    """Reads a CI configuration file"""
    return ci_read(GITHUB_DIR / filename)
`, "path_traversal", 1, "", false},
		{"a guard-statement validator sends the finding to review", py + `
@mcp.tool()
def count(table: str) -> int:
    """Counts rows in a table"""
    validate_table_name(table)
    cursor.execute(f"SELECT COUNT(*) FROM {table}")
    return cursor.fetchone()[0]
`, "sql_injection", 1, model.TriageNeedsReview, false},
		{"a returning validator sends the finding to review", py + `
@mcp.tool()
def upload_theme(file_path: str) -> bytes:
    """Uploads a theme image"""
    safe_path = validate_file_path(file_path)
    with open(safe_path, "rb") as fh:
        return fh.read()
`, "path_traversal", 1, model.TriageNeedsReview, false},
		// An in-repo query() function makes client.query resolve in the tree; a generic client
		// receiver keeps the SQL check when the path built a SQL string, as in a ClickHouse
		// server inside a large monorepo
		{"client.query with a built SQL string stays SQL beside an in-repo query function", py + `
import clickhouse_connect


def query(q):
    return q


@mcp.tool()
def list_tables(database: str) -> list:
    """Lists the tables of a database"""
    client = clickhouse_connect.get_client()
    sql = f"SELECT name FROM system.tables WHERE database = '{database}'"
    return client.query(sql).result_rows
`, "sql_injection", 1, model.TriagePotential, false},
		{"without a validator the same SQL is potential", py + `
@mcp.tool()
def count(table: str) -> int:
    """Counts rows in a table"""
    cursor.execute(f"SELECT COUNT(*) FROM {table}")
    return cursor.fetchone()[0]
`, "sql_injection", 1, model.TriagePotential, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze(t, mustWriteDir(t, map[string]string{"server.py": tc.src}))
			got := categoryFindings(res, tc.category)
			if len(got) != tc.want {
				t.Fatalf("want %d %s findings, got %d: %+v", tc.want, tc.category, len(got), res.Findings)
			}
			if tc.want == 0 {
				return
			}
			f := got[0]
			tri := f.Triage
			if tri == "" {
				tri, _ = model.DefaultTriage(f)
			}
			if tc.triage != "" && tri != tc.triage {
				t.Fatalf("triage = %s (%s), want %s", tri, f.TriageReason, tc.triage)
			}
			if (f.FindingKind == model.FindingDangerousCapability) != tc.capability {
				t.Fatalf("kind = %q (%s), want capability %v", f.FindingKind, f.Title, tc.capability)
			}
		})
	}
}
