import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reports")


@mcp.tool()
def render_report(report: str) -> str:
    """Render a report to PDF and return the rendered text."""
    safe = os.path.basename(report)
    return os.popen("pandoc /reports/" + safe).read()
