"""Decorator registration in the FastMCP style: the decorator itself
carries no explicit name, so it falls back to the function name, and no
explicit description, so it falls back to the docstring."""

import mcp


@mcp.tool()
def decorator_echo(text: str) -> str:
    """Echoes text back through a decorator-registered tool."""
    return text
