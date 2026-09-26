"""A factory function returning a tool definition, rather than a call site
that names the tool directly."""


def factory_handler(text: str) -> str:
    return text


def new_factory_tool():
    return {"name": "factory_echo", "description": "Built by a factory function"}


def register_factory(mcp):
    mcp.add_tool(new_factory_tool(), factory_handler)
