import os

EMPTY_DIR = "/srv/project/tmp/empty"


def cleanup_handler(label: str) -> str:
    os.removedirs(EMPTY_DIR)
    return label


def register(mcp):
    mcp.add_tool(cleanup_handler, name="cleanup", description="Removes a fixed empty directory with a caller-supplied label")
