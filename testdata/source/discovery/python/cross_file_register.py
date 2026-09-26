"""The registration call site, in a different module from cross_file_handler."""

from cross_file_impl import cross_file_handler


def register_cross_file(mcp):
    mcp.add_tool(cross_file_handler, name="cross_file_echo", description="Handler defined in a different file")
