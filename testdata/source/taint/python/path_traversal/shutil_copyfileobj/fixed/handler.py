import os
import shutil
import tempfile

BASE_DIR = "/srv/project"
DEST_PATH = "/srv/archive/copy.bin"


def archive_handler(name: str) -> str:
    safe = os.path.basename(name)
    src = tempfile.NamedTemporaryFile(dir=BASE_DIR + "/" + safe)
    with open(DEST_PATH, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return safe


def register(mcp):
    mcp.add_tool(archive_handler, name="archive", description="Copies a staged temporary file's contents")
