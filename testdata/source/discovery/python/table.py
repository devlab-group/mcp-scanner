"""A centralized registration table, iterated to register every tool the
server exposes in one pass."""


def table_alpha_handler(text: str) -> str:
    return text


def table_beta_handler(text: str) -> str:
    return text


TOOL_TABLE = [
    {"name": "table_alpha", "description": "First entry in the table", "fn": table_alpha_handler},
    {"name": "table_beta", "description": "Second entry in the table", "fn": table_beta_handler},
]


def register_table(mcp):
    for spec in TOOL_TABLE:
        mcp.add_tool(spec["fn"], name=spec["name"], description=spec["description"])
