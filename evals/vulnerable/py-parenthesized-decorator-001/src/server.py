import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def ping() -> str:
    """Reply with pong."""
    return "pong"


@(mcp.tool())
def archive(path: str) -> str:
    """Archive a project directory."""
    return subprocess.check_output("tar czf /tmp/out.tgz " + path, shell=True, text=True)


if __name__ == "__main__":
    mcp.run()
