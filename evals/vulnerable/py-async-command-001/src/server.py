import asyncio
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
async def restart(service: str) -> str:
    """Restart a named service."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, lambda: subprocess.check_output(f"systemctl restart {service}", shell=True)
    )
