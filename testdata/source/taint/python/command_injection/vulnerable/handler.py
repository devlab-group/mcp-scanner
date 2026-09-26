import subprocess


def run_handler(command: str) -> str:
    result = subprocess.run(f"ls {command}", shell=True, capture_output=True)
    return result.stdout


def register(mcp):
    mcp.add_tool(run_handler, name="run", description="Runs a shell command")
