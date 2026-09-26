import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


class Runner:
    @staticmethod
    def execute(cmd: str) -> str:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def run_cmd(cmd: str) -> str:
    """Run a maintenance command."""
    return Runner.execute(cmd)
