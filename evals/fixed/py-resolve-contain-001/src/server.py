from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
NOTES = Path("/srv/notes")


@mcp.tool()
def read_note(name: str) -> str:
    """Read a note from the notes directory."""
    p = (NOTES / name).resolve()
    if not p.is_relative_to(NOTES):
        raise ValueError("name escapes the notes directory")
    return p.read_text()
