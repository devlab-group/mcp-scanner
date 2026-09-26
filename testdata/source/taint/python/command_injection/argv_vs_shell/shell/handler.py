"""shell=True interprets caller input as shell text."""

import subprocess


def archive_handler(name: str) -> str:
    result = subprocess.run(f"tar czf /tmp/out.tgz {name}", shell=True, capture_output=True)
    return result.stdout


def register(mcp):
    mcp.add_tool(archive_handler, name="archive", description="Archive a project directory")
