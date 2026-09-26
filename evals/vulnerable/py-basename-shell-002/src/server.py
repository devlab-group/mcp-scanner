import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reports")


@mcp.tool()
def render(report: str) -> str:
    """Renders a report."""
    safe_path = "/reports/" + os.path.basename(report)
    return os.popen("pandoc " + safe_path).read()
