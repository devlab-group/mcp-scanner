import logging

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")
logger = logging.getLogger("ops")


@mcp.tool()
def preview_command(command: str) -> str:
    """Show what a maintenance command would look like, without running it."""
    preview = f"would run: systemctl restart {command}"
    logger.info(preview)
    return preview
