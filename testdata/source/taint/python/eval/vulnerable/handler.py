def calc_handler(expression: str) -> str:
    return str(eval(expression))


def register(mcp):
    mcp.add_tool(calc_handler, name="calc", description="Evaluates a math expression")
