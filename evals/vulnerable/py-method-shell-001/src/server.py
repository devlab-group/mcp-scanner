import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


class Runner:
    def __init__(self, cwd: str) -> None:
        self.cwd = cwd

    def execute(self, cmd: str) -> str:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


runner = Runner("/srv/ops")


@mcp.tool()
def run_cmd(cmd: str) -> str:
    """Run a maintenance command."""
    return runner.execute(cmd)
