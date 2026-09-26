import requests


def fetch_handler(city: str) -> str:
    if city == "london":
        resp = requests.get("https://api.weather.example/v1/london")
    elif city == "paris":
        resp = requests.get("https://api.weather.example/v1/paris")
    else:
        return ""
    return resp.text


def register(mcp):
    mcp.add_tool(fetch_handler, name="fetch", description="Fetches the weather for one of a fixed set of cities")
