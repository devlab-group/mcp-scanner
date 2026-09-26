import subprocess as sp

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shell")


@mcp.tool()
def run(cmd: str) -> str:
    """Run a maintenance command."""
    return sp.run(cmd, shell=True, capture_output=True).stdout.decode()
