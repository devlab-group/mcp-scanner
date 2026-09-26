from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
NOTES = Path("/srv/notes")


@mcp.tool()
def read_note(name: str) -> str:
    """Read a note from the notes directory."""
    if not Path(NOTES / name).resolve().is_relative_to(NOTES):
        raise ValueError("name escapes the notes directory")
    return (NOTES / name).read_text()
