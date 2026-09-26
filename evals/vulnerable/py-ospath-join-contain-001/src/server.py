import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
NOTES = "/srv/notes"


@mcp.tool()
def read_note(name: str) -> str:
    """Read a note from the notes directory."""
    full = os.path.join(NOTES, name)
    p = Path(full)
    if not p.is_relative_to(NOTES):
        raise ValueError("name escapes the notes directory")
    return p.read_text()
