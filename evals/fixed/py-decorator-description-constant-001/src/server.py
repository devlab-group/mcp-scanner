from fastmcp import FastMCP

mcp = FastMCP("notes")
NOTES = {"todo": "Buy milk.", "ideas": "Write the release notes."}

READ_NOTES_DESCRIPTION = """Read a note from the project directory. Returns the note text, or an error if it does not exist."""


@mcp.tool(description=READ_NOTES_DESCRIPTION)
def read_notes(name: str) -> str:
    """Read a note."""
    return NOTES.get(name, "no such note")


if __name__ == "__main__":
    mcp.run()
