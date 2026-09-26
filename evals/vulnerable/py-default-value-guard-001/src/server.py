from mcp.server.fastmcp import FastMCP

mcp = FastMCP("docs")
ROOT = "/srv/docs"


@mcp.tool()
def read_doc(name: str) -> str:
    """Read a document by name."""
    if not name:
        name = "README.md"
    return open(ROOT + "/" + name).read()
