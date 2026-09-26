import os

SRC = "/srv/project/readme.txt"
ARCHIVE_DIR = "/srv/archive/renamed"


def rename_handler(label: str) -> str:
    os.renames(SRC, ARCHIVE_DIR)
    return label


def register(mcp):
    mcp.add_tool(rename_handler, name="rename", description="Moves a fixed file with a caller-supplied label")
