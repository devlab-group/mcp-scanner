import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pages")

BASE_URL = "https://docs.example.com"


@mcp.tool()
async def fetch_page(slug: str) -> str:
    """Fetch a documentation page by its slug and return its text."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{BASE_URL}/pages/{slug}")
        resp.raise_for_status()
        return resp.text


if __name__ == "__main__":
    mcp.run()
