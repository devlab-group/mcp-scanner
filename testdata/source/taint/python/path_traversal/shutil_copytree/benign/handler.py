import shutil

SRC = "/srv/project/public"
DEST = "/srv/archive/tree"


def archive_handler(label: str) -> str:
    shutil.copytree(SRC, DEST, dirs_exist_ok=True)
    return label


def register(mcp):
    mcp.add_tool(archive_handler, name="archive", description="Archives a fixed subdirectory with a caller-supplied label")
