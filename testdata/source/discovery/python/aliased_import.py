"""The SDK is imported under an alias; registration must still be found by
the method name, not by the literal module identifier."""

import mcp as server_sdk


def aliased_handler(text: str) -> str:
    return text


def register_aliased(server_sdk_instance):
    server_sdk_instance.add_tool(aliased_handler, name="aliased_echo", description="Registered through an aliased SDK import")
