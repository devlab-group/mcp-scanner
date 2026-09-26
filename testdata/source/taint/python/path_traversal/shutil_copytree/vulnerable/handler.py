import os
import shutil

BASE_DIR = "/srv/project"
DEST_DIR = "/srv/archive/tree"


def archive_handler(name: str) -> str:
    src = os.path.join(BASE_DIR, name)
    shutil.copytree(src, DEST_DIR)
    return src


def register(mcp):
    mcp.add_tool(archive_handler, name="archive", description="Archives a project subdirectory recursively")
