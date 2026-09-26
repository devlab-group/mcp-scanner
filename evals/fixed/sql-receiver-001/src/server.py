import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def search(term: str) -> str:
    """Search notes by keyword."""
    conn = sqlite3.connect("notes.db")
    cur = conn.cursor()
    cur.execute("SELECT body FROM notes WHERE body LIKE ?", ("%" + term + "%",))
    return "\n".join(row[0] for row in cur.fetchall())
