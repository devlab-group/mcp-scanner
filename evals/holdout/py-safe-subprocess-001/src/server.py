import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def count_lines(file: str) -> str:
    """Count the lines in a project file."""
    return subprocess.check_output(["wc", "-l", "--", file], text=True)


if __name__ == "__main__":
    mcp.run()
