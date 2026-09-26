"""Caller input reaches a shared httpx.AsyncClient."""

import httpx

client = httpx.AsyncClient()


async def fetch_handler(url: str) -> str:
    resp = await client.get(url)
    return resp.text


def register(mcp):
    mcp.add_tool(fetch_handler, name="fetch", description="Fetches a URL")
