import asyncio
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
async def restart(service: str) -> str:
    """Restart a named service."""
    await asyncio.to_thread(subprocess.run, ["systemctl", "restart", "--", service])
    return "restarted"
