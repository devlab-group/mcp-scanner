import os

BASE_DIR = "/srv/project"
ARCHIVE_DIR = "/srv/archive/renamed"


def rename_handler(name: str) -> str:
    safe = os.path.basename(name)
    src = os.path.join(BASE_DIR, safe)
    os.renames(src, ARCHIVE_DIR)
    return src


def register(mcp):
    mcp.add_tool(rename_handler, name="rename", description="Moves a file, creating any missing intermediate directories")
