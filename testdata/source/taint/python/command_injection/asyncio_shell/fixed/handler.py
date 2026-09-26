"""shlex quotes caller input before it reaches the shell."""

import asyncio
import shlex


async def run_handler(command: str) -> str:
    quoted = shlex.quote(command)
    proc = await asyncio.create_subprocess_shell(f"ls {quoted}", stdout=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    return out.decode()


def register(mcp):
    mcp.add_tool(run_handler, name="run", description="Lists files matching a caller-supplied pattern")
