"""Caller input follows -- in a non-shell argv list."""

import asyncio


async def archive_handler(name: str) -> str:
    proc = await asyncio.create_subprocess_exec("tar", "czf", "/tmp/out.tgz", "--", name, stdout=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    return out.decode()


def register(mcp):
    mcp.add_tool(archive_handler, name="archive", description="Archive a project directory")
