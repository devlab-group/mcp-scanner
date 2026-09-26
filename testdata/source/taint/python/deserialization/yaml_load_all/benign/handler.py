import yaml

FIXED_CONFIG = "name: default\n---\nname: fallback\n"


def import_handler(label: str) -> list:
    docs = list(yaml.load_all(FIXED_CONFIG, Loader=yaml.Loader))
    return [label] + docs


def register(mcp):
    mcp.add_tool(import_handler, name="import_config", description="Imports a fixed multi-document config with a caller-supplied label")
