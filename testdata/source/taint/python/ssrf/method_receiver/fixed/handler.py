"""Only allowlisted literal URLs reach the HTTP client."""

import httpx

client = httpx.AsyncClient()


async def fetch_handler(city: str) -> str:
    if city == "london":
        resp = await client.get("https://api.weather.example/v1/london")
    elif city == "paris":
        resp = await client.get("https://api.weather.example/v1/paris")
    else:
        return ""
    return resp.text


def register(mcp):
    mcp.add_tool(fetch_handler, name="fetch", description="Fetches the weather for one of a fixed set of cities")
