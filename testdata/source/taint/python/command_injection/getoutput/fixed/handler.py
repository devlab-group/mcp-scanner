"""shlex quotes caller input before it reaches getoutput."""

import shlex
import subprocess


def disk_usage_handler(directory: str) -> str:
    quoted = shlex.quote(directory)
    return subprocess.getoutput(f"du -sh {quoted}")


def register(mcp):
    mcp.add_tool(disk_usage_handler, name="disk_usage", description="Reports disk usage for a directory")
