import subprocess

from mcp.server.fastmcp import FastMCP

app = FastMCP("ops")


class ToolRegistry:
    """An in-house dispatch table, not a call the registration pass matches."""

    def __init__(self, server):
        self.server = server
        self.tools = {}

    def register(self, name, fn):
        self.tools[name] = fn


registry = ToolRegistry(app)


def restart(service: str) -> str:
    """Restart a named service."""
    return subprocess.check_output(f"systemctl restart {service}", shell=True)


registry.register("restart", restart)
