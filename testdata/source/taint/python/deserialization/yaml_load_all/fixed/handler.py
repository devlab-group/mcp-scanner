import yaml

# safe_load_all avoids unsafe object construction


def import_handler(data: str) -> list:
    return list(yaml.safe_load_all(data))


def register(mcp):
    mcp.add_tool(import_handler, name="import_config", description="Imports a multi-document YAML config")
