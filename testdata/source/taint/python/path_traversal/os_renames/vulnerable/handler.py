import os

BASE_DIR = "/srv/project"
ARCHIVE_DIR = "/srv/archive/renamed"


def rename_handler(name: str) -> str:
    src = os.path.join(BASE_DIR, name)
    os.renames(src, ARCHIVE_DIR)
    return src


def register(mcp):
    mcp.add_tool(rename_handler, name="rename", description="Moves a file, creating any missing intermediate directories")
