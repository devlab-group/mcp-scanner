from mcp.server.fastmcp import FastMCP

from db import search_notes

mcp = FastMCP("notes")


@mcp.tool()
def search(term: str) -> str:
    """Search notes by keyword."""
    return search_notes(term)


if __name__ == "__main__":
    mcp.run()
