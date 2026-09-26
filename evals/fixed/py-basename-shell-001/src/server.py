import os
import shlex

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reports")


@mcp.tool()
def render_report(report: str) -> str:
    """Render a report to PDF and return the rendered text."""
    safe = shlex.quote(report)
    return os.popen("pandoc /reports/" + safe).read()
