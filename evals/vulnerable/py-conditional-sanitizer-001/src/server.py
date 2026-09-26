import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("docs")
ROOT = "/srv/docs"


@mcp.tool()
def read_doc(name: str, flat: bool = False) -> str:
    """Read a document by name."""
    if flat:
        name = os.path.basename(name)
    return open(ROOT + "/" + name).read()
