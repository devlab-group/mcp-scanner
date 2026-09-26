def lookup_handler(user_id: str) -> str:
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()


def register(mcp):
    mcp.add_tool(lookup_handler, name="lookup", description="Looks up a user by id")
