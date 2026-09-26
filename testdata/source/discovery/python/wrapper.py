"""A helper function that forwards its own arguments into the SDK call."""


def wrapper_handler(text: str) -> str:
    return text


def register_wrapper_tool(mcp, name, description, fn):
    mcp.add_tool(fn, name=name, description=description)


def setup_wrapper(mcp):
    register_wrapper_tool(mcp, "wrapper_echo", "Echoes text back through a wrapper", wrapper_handler)
