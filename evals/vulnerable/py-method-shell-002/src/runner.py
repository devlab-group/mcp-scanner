import subprocess


class Runner:
    def __init__(self, cwd: str) -> None:
        self.cwd = cwd

    def execute(self, cmd: str) -> str:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
