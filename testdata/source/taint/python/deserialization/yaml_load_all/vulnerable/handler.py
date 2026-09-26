import yaml


def import_handler(data: str) -> list:
    return list(yaml.load_all(data, Loader=yaml.Loader))


def register(mcp):
    mcp.add_tool(import_handler, name="import_config", description="Imports a multi-document YAML config")
