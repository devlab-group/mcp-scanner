import os
import shlex

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("grep")


@mcp.tool()
def search(pattern: str, path: str) -> str:
    """Search a file for a pattern."""
    safe_path = shlex.quote(path)
    return os.popen(f"grep -n {pattern} {safe_path}").read()
