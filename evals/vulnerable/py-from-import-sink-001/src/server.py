from subprocess import PIPE, Popen

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shell")


@mcp.tool()
def run(cmd: str) -> str:
    """Run a maintenance command."""
    proc = Popen(cmd, shell=True, stdout=PIPE)
    return proc.communicate()[0].decode()
