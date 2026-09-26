import os

BASE_DIR = "/srv/project"


def cleanup_handler(name: str) -> str:
    path = os.path.join(BASE_DIR, name)
    os.removedirs(path)
    return path


def register(mcp):
    mcp.add_tool(cleanup_handler, name="cleanup", description="Removes an empty directory and its empty parents")
