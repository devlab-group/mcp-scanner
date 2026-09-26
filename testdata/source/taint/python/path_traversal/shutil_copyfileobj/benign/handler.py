import shutil
import tempfile

STAGE_DIR = "/srv/project/stage"
DEST_PATH = "/srv/archive/copy.bin"


def archive_handler(label: str) -> str:
    src = tempfile.NamedTemporaryFile(dir=STAGE_DIR)
    with open(DEST_PATH, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return label


def register(mcp):
    mcp.add_tool(archive_handler, name="archive", description="Copies a fixed staged file with a caller-supplied label")
