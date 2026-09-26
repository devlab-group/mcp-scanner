"""The caller's label never reaches the fixed shell command."""

import subprocess


def uptime_handler(label: str) -> str:
    out = subprocess.getoutput("uptime")
    return f"{label}: {out}"


def register(mcp):
    mcp.add_tool(uptime_handler, name="uptime", description="Reports system uptime with a caller-supplied label")
