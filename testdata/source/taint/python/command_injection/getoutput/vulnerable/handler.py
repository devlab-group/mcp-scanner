"""Caller input reaches the shell through subprocess.getoutput."""

import subprocess


def disk_usage_handler(directory: str) -> str:
    return subprocess.getoutput(f"du -sh {directory}")


def register(mcp):
    mcp.add_tool(disk_usage_handler, name="disk_usage", description="Reports disk usage for a directory")
