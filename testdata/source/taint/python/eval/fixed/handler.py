import ast


def calc_handler(expression: str) -> str:
    # literal_eval parses literals without executing code
    return str(ast.literal_eval(expression))


def register(mcp):
    mcp.add_tool(calc_handler, name="calc", description="Parses a literal value")
