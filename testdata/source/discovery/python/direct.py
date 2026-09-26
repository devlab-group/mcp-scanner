"""Direct SDK registration via a low-level add_tool call."""


def direct_handler(text: str) -> str:
    return text


def register_direct(mcp):
    mcp.add_tool(direct_handler, name="direct_echo", description="Echoes text back unchanged")
