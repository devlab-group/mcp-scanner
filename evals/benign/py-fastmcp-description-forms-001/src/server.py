from datetime import datetime, timezone

from fastmcp import FastMCP

mcp = FastMCP("clock")

NOW_DESCRIPTION = "Return the current UTC time in ISO 8601 format."
ADD_DESCRIPTION = """Add two integers and return the sum.

Use this for exact integer arithmetic.
"""


@mcp.tool(description=NOW_DESCRIPTION)
def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@mcp.tool(description=ADD_DESCRIPTION)
def add(a: int, b: int) -> int:
    return a + b


@mcp.tool(
    description=(
        "Convert a temperature from Celsius to Fahrenheit. "
        "Returns the value rounded to one decimal place."
    )
)
def c_to_f(celsius: float) -> float:
    return round(celsius * 9 / 5 + 32, 1)


@mcp.tool
def weekday(date: str) -> str:
    """Return the weekday name for an ISO 8601 date such as 2026-11-13."""
    return datetime.fromisoformat(date).strftime("%A")


@mcp.tool(description=None)
def days_between(start: str, end: str) -> int:
    """Return the number of days from start to end, both ISO 8601 dates."""
    return (datetime.fromisoformat(end) - datetime.fromisoformat(start)).days


if __name__ == "__main__":
    mcp.run()
