import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ls")


@mcp.tool()
def listing(name: str) -> str:
    """List a directory."""
    cmd = "ls -la"
    cmd += " " + name
    return os.popen(cmd).read()
