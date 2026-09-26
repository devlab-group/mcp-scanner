"""shlex quotes caller input before it reaches sh -c."""

import asyncio
import shlex


async def run_handler(command: str) -> str:
    quoted = shlex.quote(command)
    proc = await asyncio.create_subprocess_exec("sh", "-c", "ls " + quoted, stdout=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    return out.decode()


def register(mcp):
    mcp.add_tool(run_handler, name="run", description="Lists files matching a caller-supplied pattern")
