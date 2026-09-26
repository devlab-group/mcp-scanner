import shlex

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reports")


@mcp.tool()
def read_report(report: str) -> str:
    """Read a report file's contents."""
    safe = shlex.quote(report)
    with open("/reports/" + safe) as fh:
        return fh.read()
