from mcp.server.fastmcp import FastMCP

from runner import Runner

mcp = FastMCP("ops")
runner = Runner("/srv/ops")


@mcp.tool()
def run_cmd(cmd: str) -> str:
    """Run a maintenance command."""
    return runner.execute(cmd)
