"""Caller input reaches an asynchronous shell command."""

import asyncio


async def run_handler(command: str) -> str:
    proc = await asyncio.create_subprocess_shell(f"ls {command}", stdout=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    return out.decode()


def register(mcp):
    mcp.add_tool(run_handler, name="run", description="Lists files matching a caller-supplied pattern")
