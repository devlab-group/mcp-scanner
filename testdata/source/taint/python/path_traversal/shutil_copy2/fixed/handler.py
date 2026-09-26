import os
import shutil

BASE_DIR = "/srv/project"
DEST_DIR = "/srv/archive"


def archive_handler(name: str) -> str:
    safe = os.path.basename(name)
    src = os.path.join(BASE_DIR, safe)
    shutil.copy2(src, DEST_DIR)
    return src


def register(mcp):
    mcp.add_tool(archive_handler, name="archive", description="Archives a file, preserving metadata")
