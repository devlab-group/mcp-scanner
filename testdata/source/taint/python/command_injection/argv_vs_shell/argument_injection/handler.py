"""Caller input can become a tar flag because argv omits --."""

import subprocess


def archive_handler(name: str) -> str:
    result = subprocess.run(["tar", "czf", "/tmp/out.tgz", name], capture_output=True)
    return result.stdout


def register(mcp):
    mcp.add_tool(archive_handler, name="archive", description="Archive a project directory")
