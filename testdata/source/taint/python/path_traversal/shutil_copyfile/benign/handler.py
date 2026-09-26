import shutil

SRC = "/srv/project/readme.txt"
DEST = "/srv/archive/copy.txt"


def archive_handler(label: str) -> str:
    shutil.copyfile(SRC, DEST)
    return label


def register(mcp):
    mcp.add_tool(archive_handler, name="archive", description="Copies a fixed file with a caller-supplied label")
