import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reports")


@mcp.tool()
def read_report(report: str) -> str:
    """Read a report file's contents."""
    safe = os.path.basename(report)
    with open("/reports/" + safe) as fh:
        return fh.read()
