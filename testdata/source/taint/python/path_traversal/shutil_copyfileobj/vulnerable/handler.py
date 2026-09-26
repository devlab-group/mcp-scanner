import shutil
import tempfile

BASE_DIR = "/srv/project"
DEST_PATH = "/srv/archive/copy.bin"

# Taint reaches copyfileobj through the file object returned by a call


def archive_handler(name: str) -> str:
    src = tempfile.NamedTemporaryFile(dir=BASE_DIR + "/" + name)
    with open(DEST_PATH, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return name


def register(mcp):
    mcp.add_tool(archive_handler, name="archive", description="Copies a staged temporary file's contents")
