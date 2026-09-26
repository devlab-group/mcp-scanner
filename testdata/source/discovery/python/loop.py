"""Registration inside a loop over a list of names supplied by the caller,
rather than a module-level table."""


def loop_handler(text: str) -> str:
    return text


def register_loop(mcp, names):
    for name in names:
        mcp.add_tool(loop_handler, name=name, description="One of several dynamically named tools")
