from mcp.server.fastmcp import FastMCP

mcp = FastMCP("docs")


@mcp.resource("docs://readme")
def readme() -> str:
    """The project readme."""
    return "hello"


@mcp.prompt()
def summarize(topic: str) -> str:
    """Summarize a topic in one paragraph."""
    return f"Summarize {topic} in one paragraph."


@mcp.tool()
def echo(text: str) -> str:
    """Echo the text back."""
    return text


if __name__ == "__main__":
    mcp.run()
