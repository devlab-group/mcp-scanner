from mywrapper import expose


@expose(category="tooling")
def harmless() -> str:
    """Says hello."""
    return "ok"
