import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
def archive(name: str) -> str:
    """Archive a named report directory."""
    cmd = ["bash", "-c"]
    cmd.append("tar czf /tmp/out.tgz " + name)
    return subprocess.run(cmd, capture_output=True, text=True).stdout
