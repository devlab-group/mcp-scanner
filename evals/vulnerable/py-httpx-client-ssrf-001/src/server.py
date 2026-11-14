import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pages")


@mcp.tool()
async def fetch_page(url: str) -> str:
    """Fetch a web page and return its text."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.text


if __name__ == "__main__":
    mcp.run()
