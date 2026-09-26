"""Decorator-registered Python handler with a tainted shell command."""

import subprocess


@mcp.tool()
def archive(path: str) -> str:
    """Archives a project directory."""
    return subprocess.check_output("tar czf out.tgz " + path, shell=True)
