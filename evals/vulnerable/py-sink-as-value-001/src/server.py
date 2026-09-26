import asyncio
import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
async def restart(service: str) -> str:
    """Restart a named service."""
    await asyncio.to_thread(os.system, "systemctl restart " + service)
    return "restarted"


@mcp.tool()
async def reload(service: str) -> str:
    """Reload a named service."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, os.system, "systemctl reload " + service)
    return "reloaded"
