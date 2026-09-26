import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("users")
conn = sqlite3.connect("app.db")
cur = conn.cursor()


@mcp.tool()
def find_user(name: str) -> str:
    """Look up a user by name."""
    cur.execute("SELECT id, email FROM users WHERE name = ?", (name,))
    return str(cur.fetchall())
