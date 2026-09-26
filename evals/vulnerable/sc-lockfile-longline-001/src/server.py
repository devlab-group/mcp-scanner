"""A tiny MCP server whose dependencies are pinned in requirements.txt."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def ping() -> str:
    """Return a fixed greeting."""
    return "pong"
