"""The caller's label never reaches the fixed shell command."""

import asyncio


async def status_handler(label: str) -> str:
    proc = await asyncio.create_subprocess_shell("uptime", stdout=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    return f"{label}: {out.decode()}"


def register(mcp):
    mcp.add_tool(status_handler, name="status", description="Reports system uptime with a caller-supplied label")
