"""dict.get stays benign because this file imports no recognized HTTP client."""

SETTINGS = {"greeting": "hello"}


def lookup_handler(key: str) -> str:
    return SETTINGS.get(key, "")


def register(mcp):
    mcp.add_tool(lookup_handler, name="lookup", description="Looks up a setting by key")
