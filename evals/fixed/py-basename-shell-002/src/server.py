import os
import shlex

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reports")


@mcp.tool()
def render(report: str) -> str:
    """Renders a report."""
    safe_name = os.path.basename(report)
    safe_path = "/reports/" + shlex.quote(safe_name)
    return os.popen("pandoc " + safe_path).read()
