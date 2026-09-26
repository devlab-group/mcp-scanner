import shlex
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("builds")


@mcp.tool()
def list_dir(name: str) -> str:
    """List a build output directory."""
    safe = shlex.quote(name.strip().lower())
    return subprocess.check_output("ls " + safe, shell=True, text=True)
