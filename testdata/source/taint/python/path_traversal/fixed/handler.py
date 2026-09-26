import os

BASE_DIR = "/srv/project"


def read_handler(name: str) -> str:
    safe = os.path.basename(name)
    path = os.path.join(BASE_DIR, safe)
    with open(path) as f:
        return f.read()


def register(mcp):
    mcp.add_tool(read_handler, name="read", description="Reads a file from the project directory")
