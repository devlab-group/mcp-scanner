import requests


def fetch_handler(url: str) -> str:
    resp = requests.get(url)
    return resp.text


def register(mcp):
    mcp.add_tool(fetch_handler, name="fetch", description="Fetches a URL")
