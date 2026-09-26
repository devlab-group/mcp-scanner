import shutil

# The caller's label never reaches the fixed source path
SRC = "/srv/project/readme.txt"
DEST_DIR = "/srv/archive"


def archive_handler(label: str) -> str:
    shutil.copy2(SRC, DEST_DIR)
    return label


def register(mcp):
    mcp.add_tool(archive_handler, name="archive", description="Archives a fixed file with a caller-supplied label")
