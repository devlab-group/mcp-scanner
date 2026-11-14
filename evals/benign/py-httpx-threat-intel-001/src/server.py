import ipaddress
import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("threat-intel")

INTERNETDB = "https://internetdb.shodan.io"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
SEVERITY = {"low": 1, "medium": 2, "high": 3}
client = httpx.AsyncClient(timeout=15)


def _public_ip(value: str) -> str:
    addr = ipaddress.ip_address(value)
    if not addr.is_global:
        raise ValueError("only public addresses can be looked up")
    return str(addr)


@mcp.tool()
async def ip_ports(ip: str) -> dict:
    """List the open ports and known vulnerabilities for a public IP address."""
    addr = _public_ip(ip)
    resp = await client.get(f"{INTERNETDB}/{addr}")
    data = resp.json()
    return {"ports": data.get("ports", []), "vulns": data.get("vulns", [])}


@mcp.tool()
async def ip_reputation(ip: str, max_age_days: int = 90) -> dict:
    """Report the AbuseIPDB confidence score for an IP address, using the AbuseIPDB API key from the environment."""
    resp = await client.get(
        ABUSE_URL,
        params={"ipAddress": ip, "maxAgeInDays": max_age_days},
        headers={"Key": os.environ.get("ABUSEIPDB_KEY", "")},
    )
    report = resp.json().get("data", {})
    return {"score": report.get("abuseConfidenceScore"), "country": report.get("countryCode")}


@mcp.tool()
async def url_status(url: str) -> dict:
    """Ask URLhaus whether a URL is known to serve malware."""
    resp = await client.post(URLHAUS_URL, data={"url": url})
    return {"status": resp.json().get("query_status")}


@mcp.tool()
def severity_rank(level: str) -> int:
    """Convert a severity name to its rank."""
    return SEVERITY.get(level.lower(), 0)


if __name__ == "__main__":
    mcp.run()
