from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("docs")
DOCS = Path("/srv/docs")


@mcp.tool()
def read_doc(name: str) -> str:
    """Read a document from the docs directory."""
    return (DOCS / name).open().read()
