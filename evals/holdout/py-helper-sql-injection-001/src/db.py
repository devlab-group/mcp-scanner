import sqlite3


def search_notes(term: str) -> str:
    conn = sqlite3.connect("notes.db")
    cur = conn.cursor()
    query = "SELECT body FROM notes WHERE body LIKE '%{}%'".format(term)
    cur.execute(query)
    return "\n".join(row[0] for row in cur.fetchall())
